import logging
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import List
import math

import pandas as pd
import requests

from lru_cache import LRUCache
from bulk_data import BulkData
from client_configuration import ClientConfiguration
from kmip_decrypt import create_decrypt_request, \
    parse_decrypt_response
from kmip_encrypt import create_encrypt_request, \
    parse_encrypt_response
from kmip_post import kmip_post
from shared import Algorithm, split_list


#
# This is the main entry point of the library
#

logger = logging.getLogger("comsian_kms")
slog = logging.LoggerAdapter(logger, {
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})

#
# This data needs to be adjusted to your requirements
#
CONFIGURATION = '{"kms_server_url": "http://localhost:9998"}'
# the heuristic is 5 times the number of cores for 64 bytes plaintexts
NUM_THREADS = 40
THRESHOLD = 100000
session = requests.Session()

# The LRU cach is useful for deterministic encryption (AES GCM SIV)
LRU_CACHE_SIZE = 10
LRU_CACHE_ENCRYPT = LRUCache(LRU_CACHE_SIZE)
LRU_CACHE_DECRYPT = LRUCache(LRU_CACHE_SIZE)


def set_configuration(configuration: str):
    global CONFIGURATION
    CONFIGURATION = configuration


# The following fonctions expect to work on dataframes with the following structure:
# For AES-GCM, AES-XTS, CHACHA20_POLY1305: 
#   0: key_id
#   1: plaintext (for encrypt) or ciphertext (for decrypt)
# For AES-GCM-SIV:
#   0: key_id
#   1: nonce
#   2: plaintext (for encrypt) or ciphertext (for decrypt)


def encrypt_aes_gcm(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_GCM)


def encrypt_aes_gcm_siv(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_GCM_SIV)


def encrypt_aes_xts(data: pd.DataFrame):
    return encrypt(data, Algorithm.AES_XTS)


def encrypt_chacha20_poly1305(data: pd.DataFrame):
    return encrypt(data, Algorithm.CHACHA20_POLY1305)


def encrypt(df: pd.DataFrame, algorithm: Algorithm):
    """
    python udf to encrypt data using symmetric encryption
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

    # This is a Pandas Series
    # same key for everyone
    key_id = df[0][0]
    key_id_bytes = key_id.encode('utf-8')
    if df.shape[1] > 2:
        nonce = to_padded_nonce(df[1][0], algorithm)
        plaintexts = df[2]
    else:
        nonce = None
        plaintexts = df[1]

    # Check if the ciphertext is in the cache for AES GCM SIV
    if algorithm == Algorithm.AES_GCM_SIV:
        result: list[bytes] = []
        for pt in plaintexts:
            plaintext = LRU_CACHE_ENCRYPT.get([key_id_bytes, nonce, pt])
            if plaintext is None:
                # not in cache, run the query
                break
            result.append(plaintext)
        if len(result) == len(plaintexts):
            slog.debug(f"encrypt cache hit")
            return pd.Series(result)

    slog.debug("encrypt cache miss")
    # We do not u®se the bulk data encoding if there is only one plaintext
    no_bulk_data_encoding = len(plaintexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        encrypt_requests = [
            create_encrypt_request(
                key_id=key_id,
                plaintext=plaintexts[0],
                algorithm=algorithm,
                nonce=nonce
            )
        ]
    else:
        if len(plaintexts) <= THRESHOLD:
            encrypt_requests = [
                create_encrypt_request(
                    key_id=key_id,
                    plaintext=BulkData(plaintexts).serialize(),
                    algorithm=algorithm,
                    nonce=nonce
                )
            ]
        else:
            # Split the plaintexts into chunks
            splits = math.floor(len(plaintexts) / THRESHOLD) + 1
            split_series = split_list(plaintexts, splits)
            encrypt_requests = [
                create_encrypt_request(
                    key_id=key_id,
                    plaintext=BulkData(chunk).serialize(), 
                    algorithm=algorithm,
                    nonce=nonce
                ) for chunk in
                split_series]
    t_prepare_requests = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    if len(encrypt_requests) == 1:
        slog.debug(f"encrypt: no threadpool")
        results: List[dict] = [kmip_post(configuration, session, encrypt_requests[0])]
    else:
        # Post the operations in parallel
        slog.debug(f"encrypt: threadpool with {NUM_THREADS} threads")
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: List[dict] = list(executor.map(partial(kmip_post, configuration, session), encrypt_requests))
    t_post_operations = time.perf_counter() - t_start

    # Parse the response
    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        ciphertexts = [parse_encrypt_response(results[0])]
    else:
        ciphertexts = [ct for r in results for ct in BulkData.deserialize(parse_encrypt_response(r)).data]
    # For AES GCM SIV, remove the nonce from the ciphertext
    if algorithm == Algorithm.AES_GCM_SIV:
        ciphertexts = [ct[12:] for ct in ciphertexts]

    # for AES GCM SIV, store the ciphertexts in the cache
    if algorithm == Algorithm.AES_GCM_SIV:
        for ct, pt in zip(ciphertexts, plaintexts):
            LRU_CACHE_ENCRYPT.put([key_id_bytes, nonce, pt], ct)

    data_frame = pd.Series(ciphertexts)
    t_parse_encrypt_response_payload = time.perf_counter() - t_start

    logger.info(
        "encrypt_aes",
        extra={
            "size": len(plaintexts),
            "request": t_prepare_requests,
            "post": t_post_operations,
            "response": t_parse_encrypt_response_payload
        }
    )
    return data_frame


def decrypt_aes_gcm(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_GCM)


def decrypt_aes_gcm_siv(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_GCM_SIV)


def decrypt_aes_xts(data: pd.DataFrame):
    return decrypt(data, Algorithm.AES_XTS)


def decrypt_chacha20_poly1305(data: pd.DataFrame):
    return decrypt(data, Algorithm.CHACHA20_POLY1305)


def decrypt(df: pd.DataFrame, algorithm: Algorithm):
    """
    python udf to decrypt data using symmetric encryption
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)

    key_id = df[0][0]
    key_id_bytes = key_id.encode('utf-8')
    if df.shape[1] > 2:
        nonce = to_padded_nonce(df[1][0], algorithm)
        ciphertexts = df[2]
    else:
        nonce = None
        ciphertexts = df[1]

    # Check if the plaintext is in the cache for AES GCM SIV
    if algorithm == Algorithm.AES_GCM_SIV:
        result: list[bytes] = []
        for ct in ciphertexts:
            plaintext = LRU_CACHE_DECRYPT.get([key_id_bytes, nonce, ct])
            if plaintext is None:
                # not in cache, run the query
                break
            result.append(plaintext)
        if len(result) == len(ciphertexts):
            slog.debug(f"decrypt cache hit")
            return pd.Series(result)

    slog.debug("decrypt cache miss")

    # We do not use the bulk data encoding if there is only one ciphertext
    no_bulk_data_encoding = len(ciphertexts) == 1

    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        decrypt_requests = [
            create_decrypt_request(
                key_id=key_id,
                ciphertext=ciphertexts[0],
                algorithm=algorithm,
                nonce=nonce
            )
        ]
    else:
        # got AES GCM SIV, prepend all ciphertexts with the nonce
        if algorithm == Algorithm.AES_GCM_SIV:
            ciphertexts = [nonce + ct for ct in ciphertexts]
        if len(ciphertexts) <= THRESHOLD:
            slog.debug(f"decrypt: no threadpool")
            decrypt_requests = [
                create_decrypt_request(
                    key_id=key_id,
                    ciphertext=BulkData(ciphertexts),
                    algorithm=algorithm,
                    nonce=None
                )
            ]
        else:
            slog.debug(f"decrypt: threadpool with {NUM_THREADS} threads")
            # Split the ciphertexts into chunks
            splits = math.floor(len(ciphertexts) / THRESHOLD) + 1
            split_series = split_list(ciphertexts, splits)
            decrypt_requests = [create_decrypt_request(
                key_id=key_id,
                ciphertext=BulkData(chunk),
                algorithm=algorithm,
                nonce=None
            ) for chunk in split_series]
    t_prepare_requests = time.perf_counter() - t_start

    # Post the operations
    t_start = time.perf_counter()
    if len(decrypt_requests) == 1:
        results: List[dict] = [kmip_post(configuration, session, decrypt_requests[0])]
    else:
        # Post the operations in parallel
        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            results: List[dict] = list(executor.map(partial(kmip_post, configuration, session), decrypt_requests))
    t_post_operations = time.perf_counter() - t_start

    # Parse the response
    t_start = time.perf_counter()
    if no_bulk_data_encoding:
        plaintexts = [parse_decrypt_response(results[0])]
    else:
        plaintexts = [ct for r in results for ct in BulkData.deserialize(parse_decrypt_response(r)).data]

    # for AES GCM SIV, store the plaintext in the cache
    if algorithm == Algorithm.AES_GCM_SIV:
        for ct, pt in zip(ciphertexts, plaintexts):
            # nonce is prepended in ciphertext; do not repeat it in the cache key
            LRU_CACHE_DECRYPT.put([key_id_bytes, ct], pt)

    data_frame = pd.Series(plaintexts)
    t_parse_decrypt_response_payload = time.perf_counter() - t_start

    logger.info(
        "decrypt_aes",
        extra={
            "size": len(df[1]),
            "request": t_prepare_requests,
            "post": t_post_operations,
            "response": t_parse_decrypt_response_payload
        }
    )
    return data_frame


def to_padded_nonce(input_string: str, algorithm: Algorithm) -> bytes:
    """
    Convert a string to a padded bytes nonce for symmetric encryption
    Args:
        input_string: the string that will be used as a nonce
        algorithm: the algorithm used for encryption 

    Returns:
        bytes: the padded nonce
    """
    # Convert string to bytes
    byte_array = input_string.encode('utf-8')

    if algorithm == Algorithm.AES_XTS:
        if len(byte_array) > 16:
            raise ValueError("AES XTS requires a nonce of 16 bytes maximum")
        padded_byte_array = byte_array.ljust(16, b'\0')
    else:
        if len(byte_array) > 12:
            raise ValueError(f"The nonce should be less than 12 bytes for {algorithm}")
        padded_byte_array = byte_array.ljust(12, b'\0')

    return padded_byte_array

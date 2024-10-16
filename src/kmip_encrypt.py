from typing import Optional

import orjson
from shared import nonce_block, Algorithm


def create_encrypt_request(key_id: str, plaintext: bytes, algorithm=Algorithm, nonce=Optional[bytes]) -> dict:
    """
    Create a symmetric Encrypt request

    Args:
        key_id (str): AES key ID
        plaintext (bytes): data to encrypt
        algorithm (Algorithm): the algorithm to use
        nonce (bytes): the nonce to use or None for a random nonce

    Returns:
      str: the encrypt request
    """

    # Check https://docs.cosmian.com/cosmian_key_management_system/kmip_2_1/json_ttlv_api/ for details
    # to see how to generate the JSON payload

    if nonce is None and algorithm == Algorithm.AES_GCM_SIV:
        raise ValueError("You should supply a nonce for AES_GCM_SIV")

    if nonce is not None:
        nonce_b = nonce_block(nonce)
    else:
        nonce_b = ""

    if algorithm == Algorithm.AES_GCM:
        alg = "AES"
        block_cipher_mode = "GCM"
    elif algorithm == Algorithm.AES_GCM_SIV:
        alg = "AES"
        block_cipher_mode = "GCMSIV"
    elif algorithm == Algorithm.AES_XTS:
        alg = "AES"
        block_cipher_mode = "XTS"
    elif algorithm == Algorithm.CHACHA20_POLY1305:
        alg = "ChaCha20"
        block_cipher_mode = "Poly1305"
    else:
        raise ValueError(f"Unsupported algorithm {algorithm}")

    
    r = f"""
        {{
            "tag": "Encrypt",
            "type": "Structure",
            "value": [
                {{
                    "tag": "UniqueIdentifier",
                    "type": "TextString",
                    "value": "{key_id}"
                }},
                {{
                    "tag": "CryptographicParameters",
                    "type": "Structure",
                    "value": [
                        {{
                            "tag": "BlockCipherMode",
                            "type": "Enumeration",
                            "value": "{block_cipher_mode}"
                        }},
                        {{
                            "tag": "CryptographicAlgorithm",
                            "type": "Enumeration",
                            "value": "{alg}"
                        }}
                    ]
                }},
                {{
                    "tag": "Data",
                    "type": "ByteString",
                    "value": "{plaintext.hex().upper()}"
                }}
            {nonce_b}
            ]
        }}
        """
    request = orjson.loads(r)
    return request


def parse_encrypt_response(response: dict) -> bytes:
    """
    Parse an AES encrypt response JSON payload
    Args:
        response: the AES GCM encrypt response

    Returns:
        a tuple with the (nonce, ciphertext and tag) as hex strings

    """
    values = response['value']
    nonce = ''
    ciphertext = ''
    tag = ''
    for value in values:
        if value['tag'] == 'Data':
            ciphertext = value['value']
        elif value['tag'] == 'IvCounterNonce':
            nonce = value['value']
        elif value['tag'] == 'AuthenticatedEncryptionTag':
            tag = value['value']
    return bytes.fromhex(nonce + ciphertext + tag)

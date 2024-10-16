import pandas as pd
import random
import logging

from cosmian_kms import encrypt_aes_gcm, decrypt_aes_gcm, encrypt_aes_gcm_siv, decrypt_aes_gcm_siv

# 
logger = logging.getLogger(__name__)
slog = logging.LoggerAdapter(logger, {
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})


def test_performance_aes_gcm_udf():
    _performance_aes_gcm_udf(1)
    _performance_aes_gcm_udf(2)
    _performance_aes_gcm_udf(100001)


def _performance_aes_gcm_udf(batch_size: int):
    plaintext_size = 64
    slog.info(f"Testing AES GCM performance with batch size {batch_size}")
    key_id = '0d319307-f766-4869-b90a-02096edb9431'

    # Generate a random batch of data
    keys: list[str] = [key_id for _ in range(batch_size)]
    plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
    for plaintext in plaintexts:
        assert len(plaintext) == plaintext_size
    data_frame = pd.DataFrame({0: keys, 1: plaintexts})
    slog.info(f"Generated random data")

    # Encrypt the data
    encryptions = encrypt_aes_gcm(data_frame)
    # do some verifications
    assert len(encryptions) == batch_size
    for v in encryptions.values:
        assert len(v) == plaintext_size + 12 + 16

    # decrypt the data
    data_frame = pd.DataFrame({0: keys, 1: encryptions.values})
    recovered = decrypt_aes_gcm(data_frame)

    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert plaintexts[i] == recovered[i]


def test_performance_aes_gcm_siv_udf():
    _performance_aes_gcm_siv_udf(1)
    _performance_aes_gcm_siv_udf(2)
    _performance_aes_gcm_siv_udf(100001)


def _performance_aes_gcm_siv_udf(batch_size: int):
    plaintext_size = 64
    slog.info(f"Testing AES GCM SIV performance with batch size {batch_size}")
    key_id = '0d319307-f766-4869-b90a-02096edb9431'
    nonce_str = 'abcde'

    # Generate a random batch of data
    keys: list[str] = [key_id for _ in range(batch_size)]
    nonces: list[str] = [nonce_str for _ in range(batch_size)]
    plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
    for plaintext in plaintexts:
        assert len(plaintext) == plaintext_size
    data_frame = pd.DataFrame({0: keys, 1: nonces, 2: plaintexts})
    slog.info(f"Generated random data")

    # Encrypt the data
    encryptions = encrypt_aes_gcm_siv(data_frame)
    # do some verifications
    assert len(encryptions) == batch_size
    for v in encryptions.values:
        assert len(v) == plaintext_size + 16

    # decrypt the data
    data_frame = pd.DataFrame({0: keys, 1: nonces, 2: encryptions.values})
    recovered = decrypt_aes_gcm_siv(data_frame)

    # Check that the decrypted data is the same as the original data
    for i in range(batch_size):
        assert plaintexts[i] == recovered[i]


def test_aes_gcm_siv_cache():
    """
    Test the cache for AES GCM SIV
    The logs should show that two cache hits at the end of the test
    """
    key_id = '0d319307-f766-4869-b90a-02096edb9431'
    nonce_str = 'abcde'
    plaintexts = [b'1234567890', b'abcdefghijk']

    # Generate a random batch of data
    keys: list[str] = [key_id for _ in range(len(plaintexts))]
    nonces: list[str] = [nonce_str for _ in range(len(plaintexts))]
    enc_data_frame = pd.DataFrame({0: keys, 1: nonces, 2: plaintexts})
    slog.info(f"Generated random data")

    # Encrypt the data
    encryptions = encrypt_aes_gcm_siv(enc_data_frame)

    # decrypt the data
    dec_data_frame = pd.DataFrame({0: keys, 1: nonces, 2: encryptions.values})
    _recovered = decrypt_aes_gcm_siv(dec_data_frame)
    
    # encrypt again
    _encryptions = encrypt_aes_gcm_siv(enc_data_frame)

    # decrypt the data again
    _recovered = decrypt_aes_gcm_siv(dec_data_frame)


# def test_single_encrypt_decrypt():
#     plaintext_size = 64
#     slog.info(f"Testing single encryption")
#     key_id = '0d319307-f766-4869-b90a-02096edb9431'
#     nonce_str = 'abcde'
# 
#     key_id = '0d319307-f766-4869-b90a-02096edb9431'
# 
#     # Generate a random batch of data
#     keys: list[str] = [key_id for _ in range(batch_size)]
#     plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
#     for plaintext in plaintexts:
#         assert len(plaintext) == plaintext_size
#     data_frame = pd.DataFrame({0: keys, 1: plaintexts})

#     plaintext_size = 64
#     batch_size = 1000000
#     slog.info(f"Testing performance with batch size {batch_size}")
#     key_id = '0d319307-f766-4869-b90a-02096edb9431'
# 
#     # Generate a random batch of data
#     keys: list[str] = [key_id for _ in range(batch_size)]
#     plaintexts: list[bytes] = [random.randbytes(plaintext_size) for _ in range(batch_size)]
#     data_frame = pd.DataFrame({0: keys, 1: plaintexts})
#     slog.info(f"Generated random data")
# 
#     # Encrypt the data
#     encryptions_1 = encrypt_aes(data_frame)
#     encryptions_2 = encryptions_1.copy()
# 
#     # decrypt the data
#     data_frame = pd.DataFrame({0: keys, 1: encryptions_1.values, 2:encryptions_2.values})
#     decrypter = DecryptAES()
#     decryptions = decrypter.end_partition(data_frame)
#     
#     # print(decryptions)
# 
#     # Check that the decrypted data is the same as the original data
#     for i in range(batch_size):
#         assert plaintexts[i] == decryptions[0][i]
#         assert plaintexts[i] == decryptions[1][i]


if __name__ == '__main__':
    test_performance_aes_gcm_udf()
    test_performance_aes_gcm_siv_udf()

from typing import Optional

import orjson

from bulk_data import BulkData
from shared import nonce_block, mac_block, Algorithm


def create_decrypt_request(
        key_id: str,
        ciphertext: bytes | BulkData,
        algorithm: Algorithm,
        nonce: Optional[bytes],
) -> dict:
    """
    Create a symmetric Decrypt request

    Args:
        key_id (str): AES key ID
        ciphertext (bytes): data to decrypt
        algorithm (Algorithm): the algorithm to use
        nonce (bytes): the nonce to use for AES_GCM_SIV (the nonce is expected to be in the cipher text otherwise)

    Returns:
      str: the encrypt request
    """
    
    is_bulk_data = isinstance(ciphertext, BulkData)

    if algorithm == Algorithm.AES_GCM:
        alg = "AES"
        block_cipher_mode = "GCM"
        if is_bulk_data:
            data = ciphertext.serialize()
            nonce_b = ""
            mac_b = ""
        else:
            nonce_b = nonce_block(ciphertext[:12])
            data = ciphertext[12:-16]
            mac_b = mac_block(ciphertext[-16:])
    elif algorithm == Algorithm.AES_GCM_SIV:
        alg = "AES"
        block_cipher_mode = "GCMSIV"
        if is_bulk_data:
            data = ciphertext.serialize()
            nonce_b = ""
            mac_b = ""
        else:
            if nonce is None:
                raise ValueError("You should supply a nonce for AES_GCM_SIV")
            nonce_b = nonce_block(nonce)
            data = ciphertext[:-16]
            mac_b = mac_block(ciphertext[-16:])
    elif algorithm == Algorithm.AES_XTS:
        alg = "AES"
        block_cipher_mode = "XTS"
        mac_b = ""
        if is_bulk_data:
            data = ciphertext.serialize()
            nonce_b = ""
        else:
            data = ciphertext[12:]
            nonce_b = nonce_block(ciphertext[:12])
    elif algorithm == Algorithm.CHACHA20_POLY1305:
        alg = "ChaCha20"
        block_cipher_mode = "Poly1305"
        if is_bulk_data:
            data = ciphertext.serialize()
            nonce_b = ""
            mac_b = ""
        else:
            nonce_b = nonce_block(ciphertext[:12])
            data = ciphertext[12:-16]
            mac_b = mac_block(ciphertext[-16:])
    else:
        raise ValueError(f"Unsupported algorithm {algorithm}")
    
    r=f"""
        {{
            "tag": "Decrypt",
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
                    "value": "{data.hex().upper()}"
                }}
            {nonce_b}
            {mac_b}
            ]
        }}
        """
    request = orjson.loads(r)
    return request


def parse_decrypt_response(response: dict) -> bytes:
    """
        Parse a decrypt response JSON

    Args:
      response (dict): the decrypt JSON response

    Returns:
      bytes: the cleartext data
    """
    values = response['value']
    plaintext = ''
    for value in values:
        if value['tag'] == 'Data':
            plaintext = value['value']
    return bytes.fromhex(plaintext)



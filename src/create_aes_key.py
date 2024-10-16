import json
from typing import List

import requests
from jsonpath_ng import ext
from client_configuration import ClientConfiguration
from cosmian_kms import CONFIGURATION
from kmip_post import kmip_post

# 
# A KMIP Call to create a symmetric key on the KMS
#

# This JSON was generated using the following CLI command:
# ckms --json sym keys create -a aes -l 256 --tag aes_key
CREATE_AES_KEY = json.loads("""
{
  "tag": "Create",
  "type": "Structure",
  "value": [
    {
      "tag": "ObjectType",
      "type": "Enumeration",
      "value": "SymmetricKey"
    },
    {
      "tag": "Attributes",
      "type": "Structure",
      "value": [
        {
          "tag": "CryptographicAlgorithm",
          "type": "Enumeration",
          "value": "AES"
        },
        {
          "tag": "CryptographicLength",
          "type": "Integer",
          "value": 256
        },
        {
          "tag": "CryptographicUsageMask",
          "type": "Integer",
          "value": 2108
        },
        {
          "tag": "KeyFormatType",
          "type": "Enumeration",
          "value": "TransparentSymmetricKey"
        },
        {
          "tag": "ObjectType",
          "type": "Enumeration",
          "value": "SymmetricKey"
        },
        {
          "tag": "VendorAttributes",
          "type": "Structure",
          "value": [
            {
              "tag": "VendorAttributes",
              "type": "Structure",
              "value": [
                {
                  "tag": "VendorIdentification",
                  "type": "TextString",
                  "value": "cosmian"
                },
                {
                  "tag": "AttributeName",
                  "type": "TextString",
                  "value": "tag"
                },
                {
                  "tag": "AttributeValue",
                  "type": "ByteString",
                  "value": "5B226165735F6B6579225D"
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
""")

# request
KEY_SIZE_PATH = ext.parse('$..value[?tag = "CryptographicLength"]')
TAGS_PATH = ext.parse('$..value[?tag = "VendorAttributes"]')
# response



def create_aes_key_request(key_size: int = 2048, tags: list = None) -> dict:
    req = CREATE_AES_KEY.copy()

    # Set the  key size path
    if key_size != 256:
        ks_path = KEY_SIZE_PATH.find(req)
        ks_path[0].value['value'] = key_size

    # Set the tags
    if tags is not None:
        # Convert list to JSON string
        json_str = json.dumps(tags)
        # Convert JSON string to hex bytes
        hex_str = json_str.encode('utf-8').hex().upper()
        # Set the tags path
        tags_path = TAGS_PATH.find(req)
        tags_path[0].value['value'][0]['value'][2]['value'] = hex_str
    else:
        # remove the VendorAttributes path
        TAGS_PATH.filter(lambda d: True, req)

    return req


def parse_aes_key_response(response: dict) -> str:
    # {
    #   "tag": "CreateResponse",
    #   "type": "Structure",
    #   "value": [
    #     {
    #       "tag": "ObjectType",
    #       "type": "Enumeration",
    #       "value": "SymmetricKey"
    #     },
    #     {
    #       "tag": "UniqueIdentifier",
    #       "type": "TextString",
    #       "value": "365d78dd-6da4-4396-b63a-3ad793db2ab0"
    #     }
    #   ]
    # }
    return response['value'][1]['value']


def create_aes_key(session: requests.Session, size: int = 256, tags: List[str] = None ) -> str:
    """Create an AES key

    Returns:
        an hex string of the AES key
    """
    configuration: ClientConfiguration = ClientConfiguration.from_json(CONFIGURATION)
    req = create_aes_key_request(size, tags)
    response = kmip_post(configuration, session, req)
    keypair = parse_aes_key_response(response)
    return keypair

from dataclasses import dataclass
import json


# This class is used to store the configuration of the client
# It is very basic, see: https://docs.cosmian.com/cosmian_key_management_system/cli/cli/#configuring-the-clients
# for more configuration options

@dataclass
class ClientConfiguration:
    """
    Configuration for the client posting to the KMS server
    """
    kms_server_url: str
    kms_access_token: str = None

    @staticmethod
    def from_json(json_str: str):
        data = json.loads(json_str)
        return ClientConfiguration(**data)

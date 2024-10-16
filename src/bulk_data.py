from dataclasses import dataclass
from leb128 import u
import io


@dataclass
class BulkData:
    """
    This class is used to aggregate multiple data items into a single serialized object
    See https://docs.cosmian.com/cosmian_key_management_system/encrypting_and_decrypting_at_scale/#encoding-scheme
    for more details
    """
    data: list[bytes]

    def __init__(self, data: list[bytes]):
        self.data = data

    @staticmethod
    def is_serialized_bulk_data(serialized: bytes) -> bool:
        return len(serialized) > 2 and serialized[0] == 0x87 and serialized[1] == 0x87

    def serialize(self) -> bytes:
        result = io.BytesIO()
        # Write the header  
        result.write(bytes([0x87, 0x87]))
        # Write the number of items using leb128 encoding        
        result.write(u.encode(len(self.data)))
        # Gather all encoded items
        encoded_items = [u.encode(len(item)) + item for item in self.data]
        # Write all items at once
        result.write(b''.join(encoded_items))
        return result.getvalue()

    @classmethod
    def deserialize(cls, serialized: bytes) -> 'BulkData':
        data = io.BytesIO(serialized)
        # read the first two bytes 0x87
        _header = data.read(2)
        # read the number of items
        num_items, _num_bytes = u.decode_reader(data)
        # Preallocate the list for the result
        result = [None] * num_items
        for i in range(num_items):
            item_length, _ = u.decode_reader(data)
            result[i] = data.read(item_length)
        return cls(result)

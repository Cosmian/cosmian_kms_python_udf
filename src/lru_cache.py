import logging
from collections import deque
import threading
from xxhash import xxh64

logger = logging.getLogger("kms_decrypt")
slog = logging.LoggerAdapter(logger, {
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})


def key_hash(key: bytes | list[bytes]) -> int:
    h = xxh64()
    if isinstance(key, list):
        for k in key:
            h.update(k)
    else:
        h.update(key)
    return h.intdigest()


class LRUCache:
    # A simple LRU cache
    # To use with deterministic encryption like AES_GCM_SIV
    # and void doing unnecessary round trips to the server

    def __init__(self, capacity):
        self.cache = dict()
        self.capacity = capacity
        self.access = deque()
        self.lock = threading.Lock()

    def get(self, key: bytes | list[bytes]) -> bytes | None:
        key = key_hash(key)
        if key not in self.cache:
            return None
        else:
            # small race condition here with the test on self.cache
            # but we do not want to delay self.cache
            with self.lock:
                if self.access[-1] != key:
                    self.access.remove(key)
                    self.access.append(key)
                return self.cache[key]

    def put(self, key: bytes | list[bytes], value: bytes):
        key = key_hash(key)
        with self.lock:
            if key in self.cache:
                self.access.remove(key)
            elif len(self.cache) == self.capacity:
                oldest = self.access.popleft()
                del self.cache[oldest]
            self.cache[key] = value
            self.access.append(key)

    def print(self):
        for key in self.access:
            print(f"{key}: {self.cache[key]}")

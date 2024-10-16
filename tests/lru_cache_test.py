from lru_cache import LRUCache


def test_lru_cache_eviction():
    cache = LRUCache(3)
    cache.put(b"key1", 1)
    cache.put(b"key2", 2)
    cache.put(b"key3", 3)
    cache.put(b"key4", 4)
    assert cache.get(b"key1") == -1
    assert cache.get(b"key2") == 2
    assert cache.get(b"key3") == 3
    assert cache.get(b"key4") == 4


def test_lru_cache_array():
    cache = LRUCache(3)
    cache.put([b"key1", b"key2", b"key3"], 1)
    assert cache.get([b"key1", b"key2", b"key3"]) == 1
    cache.put([b"key1", b"key2"], -1)
    assert cache.get([b"key2", b"key3"]) == -1
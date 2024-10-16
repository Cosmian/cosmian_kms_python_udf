import numpy as np
import numpy.testing as npt
from bulk_data import BulkData
import logging
import time
import random

logger = logging.getLogger(__name__)
slog = logging.LoggerAdapter(logger, {
    "id": "",
    "size": 0,
    "request": 0,
    "post": 0,
    "response": 0
})


def test_bulk_data_test_vector():
    data = np.array([
        bytes([0x01, 0x02, 0x03]),
        bytes([0x04, 0x05, 0x06]),
        bytes([0x07] * 10)
    ])
    bulk_data = BulkData(data)
    serialized = bulk_data.serialize()
    assert list(serialized) == [
        0x87, 0x87, 0x03, 0x03, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x06, 0x0A, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07
    ]
    deserialized = BulkData.deserialize(serialized)
    npt.assert_array_equal(data, deserialized.data)


def benchmark_bulk_data(bulk_data) -> BulkData:
    t_start = time.perf_counter()
    serialized = bulk_data.serialize()
    t_serialize = time.perf_counter() - t_start
    slog.info(f"Serialize: {t_serialize}s")

    t_start = time.perf_counter()
    deserialized = BulkData.deserialize(serialized)
    t_deserialize = time.perf_counter() - t_start
    slog.info(f"deserialize: {t_deserialize}s")
    return deserialized


def random_bytes() -> bytes:
    return bytes(random.getrandbits(8) for _ in range(64))


def test_bulk_data_benchmark():
    num_samples = 5000000
    slog.info(f"Testing performance with bulk data of {num_samples} samples")
    t_start = time.perf_counter()
    data = np.array([
        random.randbytes(64) for _ in range(num_samples)
    ], dtype=np.object_)
    # check all samples have 64 bytes
    for item in data:
        assert len(item) == 64
    bulk_data = BulkData(data)
    t_generate = time.perf_counter() - t_start
    slog.info(f"Generate: {t_generate}s")

    t_start = time.perf_counter()
    recovered = benchmark_bulk_data(bulk_data)
    t_all = time.perf_counter() - t_start
    slog.info(f"serialize+deserialize: {t_all}s, i.e. {t_all / num_samples * 1000000:.6f}µs per item")

    assert np.array_equal(bulk_data.data, recovered.data)

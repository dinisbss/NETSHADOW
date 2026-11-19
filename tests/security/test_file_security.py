
import hashlib
import pytest

from pathlib import Path
from security.secure_storage import (
    SecureStorage,
    SecureStorageError,
)


@pytest.fixture
def storage(tmp_path):
    return SecureStorage(base_directory=tmp_path)


def test_storage_initialization(storage):
    assert storage is not None


def test_write_and_read_file(storage):
    content = b"NETSHADOW security test"

    storage.write_bytes("test.txt", content)

    assert storage.read_bytes("test.txt") == content


def test_file_integrity(storage):
    content = b"Integrity verification"

    storage.write_bytes("integrity.txt", content)

    file_path = Path(storage.base_directory) / "integrity.txt"

    expected = hashlib.sha256(content).hexdigest()
    actual = hashlib.sha256(file_path.read_bytes()).hexdigest()

    assert actual == expected


def test_missing_file_is_handled(storage):
    with pytest.raises(SecureStorageError):
        storage.read_bytes("missing.txt")


def test_path_traversal_is_rejected(storage):
    with pytest.raises(SecureStorageError):
        storage.write_bytes(
            "../outside.txt",
            b"Unauthorized",
        )


def test_nested_directory_storage(storage):
    storage.write_bytes(
        "reports/test.txt",
        b"Test report",
    )

    assert storage.read_bytes(
        "reports/test.txt"
    ) == b"Test report"

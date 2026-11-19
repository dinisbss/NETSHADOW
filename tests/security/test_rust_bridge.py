
import pytest

from engines.rust_bridge.adapter import (
    RustAdapter,
    RustBridgeError,
    RustBridgeStatus,
)


def test_rust_adapter_initialization():
    adapter = RustAdapter()

    assert adapter is not None
    assert adapter.is_available() is False


def test_rust_adapter_fallback():
    adapter = RustAdapter()

    info = adapter.get_info()

    assert info.backend == "PYTHON"
    assert info.status == RustBridgeStatus.UNAVAILABLE


def test_rust_adapter_initialize_without_extension():
    adapter = RustAdapter()

    info = adapter.initialize()

    assert info.status in {
        RustBridgeStatus.AVAILABLE,
        RustBridgeStatus.UNAVAILABLE,
        RustBridgeStatus.INCOMPATIBLE,
        RustBridgeStatus.ERROR,
    }

    assert info.backend in {"RUST", "PYTHON"}


def test_rust_adapter_unavailable_module():
    adapter = RustAdapter()

    assert adapter.get_module() is None


def test_rust_adapter_execute_when_unavailable():
    adapter = RustAdapter()

    with pytest.raises(RustBridgeError):
        adapter.execute("example_function")


def test_rust_adapter_rejects_invalid_function_name():
    adapter = RustAdapter()

    with pytest.raises(RustBridgeError):
        adapter.execute("../invalid")


def test_rust_adapter_rejects_private_function():
    adapter = RustAdapter()

    with pytest.raises(RustBridgeError):
        adapter.execute("_private_function")


def test_rust_adapter_reset():
    adapter = RustAdapter()

    adapter.initialize()
    adapter.reset()

    assert adapter.is_available() is False
    assert adapter.get_module() is None
    assert adapter.get_info().status == RustBridgeStatus.UNAVAILABLE

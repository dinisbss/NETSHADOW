
import pytest

from core.permissions import PermissionManager, PermissionMode


def test_network_selection_does_not_grant_authorization():
    permissions = PermissionManager()

    with pytest.raises(PermissionError):
        permissions.authorize_network("192.168.1.0/24")

    assert not permissions.is_network_authorized("192.168.1.0/24")


def test_device_selection_does_not_grant_authorization():
    permissions = PermissionManager()

    with pytest.raises(PermissionError):
        permissions.authorize_device("192.168.1.100")

    assert not permissions.is_device_authorized("192.168.1.100")


def test_explicit_network_authorization():
    permissions = PermissionManager()

    authorization = permissions.create_authorization(
        scope="192.168.1.0/24",
        reason="Authorized local security audit",
        confirmation=True,
    )

    assert permissions.is_network_authorized(
        "192.168.1.0/24",
        authorization.reference,
    )


def test_device_inside_authorized_network():
    permissions = PermissionManager()

    authorization = permissions.create_authorization(
        scope="192.168.1.0/24",
        reason="Authorized local security audit",
        confirmation=True,
    )

    assert permissions.is_device_authorized(
        "192.168.1.100",
        authorization.reference,
    )


def test_device_outside_authorized_network():
    permissions = PermissionManager()

    authorization = permissions.create_authorization(
        scope="192.168.1.0/24",
        reason="Authorized local security audit",
        confirmation=True,
    )

    assert not permissions.is_device_authorized(
        "10.0.0.1",
        authorization.reference,
    )


def test_invalid_device():
    permissions = PermissionManager()

    assert not permissions.is_device_authorized("invalid-address")


def test_unauthorized_operation():
    permissions = PermissionManager()

    result = permissions.check_operation("unknown_operation")

    assert result.allowed is False


def test_authorized_read_only_operation():
    permissions = PermissionManager()

    result = permissions.check_operation("network_info")

    assert result.allowed is True


def test_invalid_mode():
    permissions = PermissionManager()

    with pytest.raises(ValueError):
        permissions.set_mode("INVALID")


def test_authorization_requires_confirmation():
    permissions = PermissionManager()

    with pytest.raises(PermissionError):
        permissions.create_authorization(
            scope="192.168.1.0/24",
            reason="Test",
            confirmation=False,
        )


def test_revoked_authorization():
    permissions = PermissionManager()

    authorization = permissions.create_authorization(
        scope="192.168.1.0/24",
        reason="Authorized local security audit",
        confirmation=True,
    )

    assert permissions.revoke_authorization(authorization.reference)

    assert not permissions.is_device_authorized(
        "192.168.1.100",
        authorization.reference,
    )


def test_invalid_authorization_scope():
    permissions = PermissionManager()

    with pytest.raises(ValueError):
        permissions.create_authorization(
            scope="not-a-network",
            reason="Test",
            confirmation=True,
        )


def test_invalid_authorization_duration():
    permissions = PermissionManager()

    with pytest.raises(ValueError):
        permissions.create_authorization(
            scope="192.168.1.0/24",
            reason="Test",
            confirmation=True,
            validity_minutes=0,
        )

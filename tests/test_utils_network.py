from __future__ import annotations

import errno
import socket
from unittest.mock import Mock, call

import pytest

from aia_chaser import NonGlobalAddressError
from aia_chaser.utils.network import (
    create_pinned_socket,
    is_global_unicast_address,
    resolve_global_host,
)
from tests.conftest import make_addrinfo


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "::ffff:10.0.0.1",
        "2002:0a00:0001::",
        "64:ff9b::a00:1",
        "2001::a9fe:a9fe",
    ],
)
def test_non_global_addresses_are_rejected(address: str) -> None:
    assert is_global_unicast_address(address) is False


@pytest.mark.parametrize(
    "address",
    [
        "224.0.0.1",
        "239.1.2.3",
        "ff02::1",
        "ff0e::1",
        "::ffff:239.1.2.3",
    ],
)
def test_global_multicast_addresses_are_rejected(address: str) -> None:
    """The address policy should reject multicast destinations."""
    assert is_global_unicast_address(address) is False


def test_public_addresses_are_allowed() -> None:
    assert is_global_unicast_address("8.8.8.8") is True
    assert is_global_unicast_address("2001:4860:4860::8888") is True


def test_resolve_global_host_raises_typed_error_for_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[make_addrinfo("10.0.0.1")]),
    )

    with pytest.raises(NonGlobalAddressError) as exc_info:
        resolve_global_host("internal.example", 443)

    assert exc_info.value.host == "internal.example"
    assert exc_info.value.address == "10.0.0.1"


def test_resolve_global_host_allows_public_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[make_addrinfo("8.8.8.8")]),
    )

    assert resolve_global_host("public.example", 443)[0][4][0] == "8.8.8.8"


def test_create_pinned_socket_fails_over_and_closes_failed_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connector should try the next address after a connection error."""
    failed_socket = Mock()
    failed_socket.connect.side_effect = OSError("connection refused")
    connected_socket = Mock()
    socket_factory = Mock(side_effect=[failed_socket, connected_socket])
    monkeypatch.setattr(socket, "socket", socket_factory)
    addresses = [make_addrinfo("8.8.8.8"), make_addrinfo("1.1.1.1")]

    result = create_pinned_socket(addresses, timeout=3, source_address=None)

    assert result is connected_socket
    failed_socket.close.assert_called_once_with()
    failed_socket.connect.assert_called_once_with(addresses[0][4])
    connected_socket.connect.assert_called_once_with(addresses[1][4])


def test_create_pinned_socket_binds_source_address_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connector should bind the requested local address first."""
    fake_socket = Mock()
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake_socket))
    address = make_addrinfo("8.8.8.8")
    source_address = ("192.0.2.10", 0)

    result = create_pinned_socket([address], timeout=3, source_address=source_address)

    assert result is fake_socket
    fake_socket.bind.assert_called_once_with(source_address)
    assert fake_socket.mock_calls.index(call.bind(source_address)) < (
        fake_socket.mock_calls.index(call.connect(address[4]))
    )


def test_create_pinned_socket_ignores_unsupported_tcp_nodelay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connector should keep a socket when TCP_NODELAY is unsupported."""
    fake_socket = Mock()
    fake_socket.setsockopt.side_effect = OSError(errno.ENOPROTOOPT, "unsupported")
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake_socket))

    result = create_pinned_socket(
        [make_addrinfo("8.8.8.8")],
        timeout=3,
        source_address=None,
    )

    assert result is fake_socket
    fake_socket.close.assert_not_called()


def test_create_pinned_socket_propagates_other_socket_option_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The connector should propagate TCP_NODELAY errors other than ENOPROTOOPT."""
    fake_socket = Mock()
    socket_error = OSError(errno.EPERM, "permission denied")
    fake_socket.setsockopt.side_effect = socket_error
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake_socket))

    with pytest.raises(OSError, match="permission denied") as exc_info:
        create_pinned_socket(
            [make_addrinfo("8.8.8.8")],
            timeout=3,
            source_address=None,
        )

    assert exc_info.value is socket_error
    fake_socket.close.assert_called_once_with()


def test_create_pinned_socket_raises_gaierror_for_empty_addresses() -> None:
    """The connector should report when resolution supplied no addresses."""
    with pytest.raises(socket.gaierror) as exc_info:
        create_pinned_socket([], timeout=None, source_address=None)

    assert exc_info.value.errno == socket.EAI_NONAME


def test_resolve_global_host_rejects_unexpected_address_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The resolver should reject address records with an unsupported shape."""
    address_info = (socket.AF_UNIX, socket.SOCK_STREAM, 0, "", ("8.8.8.8",))
    monkeypatch.setattr(socket, "getaddrinfo", Mock(return_value=[address_info]))

    with pytest.raises(socket.gaierror) as exc_info:
        resolve_global_host("unexpected.example", 443)

    assert exc_info.value.errno == socket.EAI_FAMILY


def test_resolve_global_host_raises_gaierror_for_empty_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The resolver should report an empty address result."""
    monkeypatch.setattr(socket, "getaddrinfo", Mock(return_value=[]))

    with pytest.raises(socket.gaierror) as exc_info:
        resolve_global_host("missing.example", 443)

    assert exc_info.value.errno == socket.EAI_NONAME

from __future__ import annotations

import socket
from unittest.mock import Mock

import pytest

from aia_chaser import NonGlobalAddressError
from aia_chaser.utils.network import is_global_unicast_address, resolve_global_host
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

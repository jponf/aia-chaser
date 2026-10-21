from __future__ import annotations

import socket
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock

import pytest

from aia_chaser import AiaChaser, NonGlobalAddressError, chaser
from tests.conftest import AIA_CA_ISSUER_URL, make_addrinfo


if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography import x509


def test_aia_chaser_allows_private_ips_by_default() -> None:
    assert AiaChaser().allow_private_ip is True


def test_initial_host_rejects_private_ip_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[make_addrinfo("127.0.0.1")]),
    )
    monkeypatch.setattr(
        socket,
        "socket",
        Mock(side_effect=AssertionError("private destination must not connect")),
    )
    chaser = AiaChaser(allow_private_ip=False)

    with pytest.raises(NonGlobalAddressError):
        chaser.fetch_host_cert("internal.example")


def test_chaser_passes_private_ip_option_to_issuer_fetch(
    monkeypatch: pytest.MonkeyPatch,
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    leaf_cert, trusted_cert = host_and_ca_chain
    chaser_instance = AiaChaser(
        trusted_cas=[trusted_cert],
        allow_private_ip=False,
    )

    def fetch_issuer(
        urls: list[str],
        *,
        allow_private_ip: bool = True,
    ) -> list[x509.Certificate]:
        assert urls == [AIA_CA_ISSUER_URL]
        assert allow_private_ip is False
        return [trusted_cert]

    monkeypatch.setattr(chaser, "_try_download_certificate", fetch_issuer)
    assert list(chaser_instance.aia_chase_cert(leaf_cert)) == [leaf_cert, trusted_cert]


def test_dns_rebinding_toctou_prevention_on_fetch_host_cert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure DNS rebinding (TOCTOU) cannot bypass host cert fetching."""
    public_addr = make_addrinfo("8.8.8.8")
    private_addr = make_addrinfo("127.0.0.1")

    getaddrinfo_mock = Mock(side_effect=[[public_addr], [private_addr]])
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo_mock)

    fake_socket = MagicMock()
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake_socket))

    chaser_obj = AiaChaser(allow_private_ip=False)
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.__enter__.return_value = mock_ssl_sock
    mock_ssl_sock.getpeercert.return_value = None
    chaser_obj._context = MagicMock(  # noqa: SLF001
        wrap_socket=Mock(return_value=mock_ssl_sock),
    )

    with pytest.raises(chaser.MissingPeerCertificateError):
        chaser_obj.fetch_host_cert("rebind.example", 443)

    assert getaddrinfo_mock.call_count == 1
    fake_socket.connect.assert_called_once_with(public_addr[4])
    assert fake_socket.connect.call_args.args[0] != private_addr[4]

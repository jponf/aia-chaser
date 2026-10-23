from __future__ import annotations

import socket
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock

import pytest

from aia_chaser import AiaChaser, NonGlobalAddressError, chaser
from aia_chaser.verify import VerifyCertificatesConfig
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
    chaser_instance = AiaChaser(allow_private_ip=False)

    with pytest.raises(NonGlobalAddressError):
        chaser_instance.fetch_host_cert("internal.example")


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

    monkeypatch.setattr(chaser, "try_download_certificate", fetch_issuer)
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

    chaser_instance = AiaChaser(allow_private_ip=False)
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.__enter__.return_value = mock_ssl_sock
    mock_ssl_sock.getpeercert.return_value = None
    chaser_instance._context = MagicMock(  # noqa: SLF001
        wrap_socket=Mock(return_value=mock_ssl_sock),
    )

    with pytest.raises(chaser.MissingPeerCertificateError):
        chaser_instance.fetch_host_cert("rebind.example", 443)

    assert getaddrinfo_mock.call_count == 1
    fake_socket.connect.assert_called_once_with(public_addr[4])
    assert fake_socket.connect.call_args.args[0] != private_addr[4]


def test_chaser_propagates_private_ip_to_verify_when_config_is_none(
    monkeypatch: pytest.MonkeyPatch,
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    """Default VerifyCertificatesConfig inherits chaser's allow_private_ip."""
    chaser_instance = AiaChaser(allow_private_ip=False)
    monkeypatch.setattr(
        chaser_instance,
        "aia_chase",
        Mock(return_value=iter(host_and_ca_chain)),
    )

    mock_verify = Mock()
    monkeypatch.setattr(chaser, "verify_certificate_chain", mock_verify)

    chaser_instance.fetch_cert_chain_for_host("public.example")

    assert mock_verify.call_count == 1
    config = mock_verify.call_args.kwargs["config"]
    assert config.allow_private_ip is False


def test_chaser_forces_private_ip_false_on_passed_verify_config(
    monkeypatch: pytest.MonkeyPatch,
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    """Strict chaser forces allow_private_ip=False on verify_config."""
    chaser_instance = AiaChaser(allow_private_ip=False)
    monkeypatch.setattr(
        chaser_instance,
        "aia_chase",
        Mock(return_value=iter(host_and_ca_chain)),
    )

    mock_verify = Mock()
    monkeypatch.setattr(chaser, "verify_certificate_chain", mock_verify)

    user_config = VerifyCertificatesConfig(ocsp_enabled=True)
    chaser_instance.fetch_cert_chain_for_host(
        "public.example",
        verify_config=user_config,
    )

    assert mock_verify.call_count == 1
    config = mock_verify.call_args.kwargs["config"]
    assert config.allow_private_ip is False
    assert config.ocsp_enabled is True


def test_chaser_respects_explicit_verify_config_when_chaser_allows_private_ip(
    monkeypatch: pytest.MonkeyPatch,
    host_and_ca_chain: Sequence[x509.Certificate],
) -> None:
    """Explicit allow_private_ip=False on verify_config is respected."""
    chaser_instance = AiaChaser(allow_private_ip=True)
    monkeypatch.setattr(
        chaser_instance,
        "aia_chase",
        Mock(return_value=iter(host_and_ca_chain)),
    )

    mock_verify = Mock()
    monkeypatch.setattr(chaser, "verify_certificate_chain", mock_verify)

    user_config = VerifyCertificatesConfig(allow_private_ip=False)
    chaser_instance.fetch_cert_chain_for_host(
        "public.example",
        verify_config=user_config,
    )

    assert mock_verify.call_count == 1
    config = mock_verify.call_args.kwargs["config"]
    assert config.allow_private_ip is False

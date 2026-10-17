from __future__ import annotations

import socket
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from aia_chaser import AiaChaser, NonGlobalAddressError, chaser
from aia_chaser.chaser import _AiaRedirectHandler, _validate_url_destination
from aia_chaser.utils.url import is_global_address, resolve_global_host


def _addrinfo(
    address: str,
) -> tuple[int, int, int, str, tuple[str, int] | tuple[str, int, int, int]]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr


def test_aia_chaser_allows_private_ips_by_default() -> None:
    assert AiaChaser().allow_private_ip is True


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
    assert is_global_address(address) is False


def test_public_addresses_are_allowed() -> None:
    assert is_global_address("8.8.8.8") is True
    assert is_global_address("2001:4860:4860::8888") is True


def test_resolve_global_host_raises_typed_error_for_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[_addrinfo("10.0.0.1")]),
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
        Mock(return_value=[_addrinfo("8.8.8.8")]),
    )

    assert resolve_global_host("public.example", 443)[0][4][0] == "8.8.8.8"


def test_initial_host_rejects_private_ip_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[_addrinfo("127.0.0.1")]),
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        Mock(side_effect=AssertionError("private destination must not connect")),
    )
    chaser = object.__new__(AiaChaser)
    chaser.allow_private_ip = False
    chaser._context = SimpleNamespace(wrap_socket=Mock())

    with pytest.raises(NonGlobalAddressError):
        chaser.fetch_host_cert("internal.example")


def test_chaser_passes_private_ip_option_to_issuer_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    leaf_cert = object()
    issuer_cert = object()
    trusted_cert = object()
    info_by_cert = {
        leaf_cert: SimpleNamespace(
            subject="leaf",
            issuer="issuer",
            aia_ca_issuers=["http://ca.example/issuer.crt"],
        ),
        issuer_cert: SimpleNamespace(
            subject="issuer",
            issuer="root",
            aia_ca_issuers=[],
        ),
    }
    chaser_instance = object.__new__(AiaChaser)
    chaser_instance.allow_private_ip = False
    chaser_instance._trusted = {"issuer": trusted_cert}
    monkeypatch.setattr(
        chaser,
        "_extract_aia_info",
        lambda certificate: info_by_cert[certificate],
    )

    def fetch_issuer(urls: list[str], *, allow_private_ip: bool = True) -> list[object]:
        assert urls == ["http://ca.example/issuer.crt"]
        assert allow_private_ip is False
        return [issuer_cert]

    monkeypatch.setattr(chaser, "_try_download_certificate", fetch_issuer)

    assert list(chaser_instance.aia_chase_cert(leaf_cert)) == [leaf_cert, trusted_cert]


def test_default_private_ip_option_preserves_aia_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(chaser, "build_opener", Mock(return_value=opener))
    monkeypatch.setattr(
        chaser,
        "_try_parse_certificate",
        Mock(return_value=[object()]),
    )
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(side_effect=AssertionError("default behavior must not resolve-check")),
    )
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    assert chaser._download_certificate(
        "http://internal.example/issuer.crt"
    )  # noqa: SLF001
    opener.open.assert_called_once()

    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_aia_url_validation_rejects_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[_addrinfo("127.0.0.1")]),
    )

    with pytest.raises(NonGlobalAddressError):
        _validate_url_destination("http://internal.example/issuer.crt")


def test_download_rejects_private_issuer_before_opening_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[_addrinfo("10.0.0.1")]),
    )
    monkeypatch.setattr(
        chaser,
        "build_opener",
        Mock(side_effect=AssertionError("private destination must not be opened")),
    )
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    with pytest.raises(NonGlobalAddressError):
        chaser._download_certificate(  # noqa: SLF001
            "http://internal.example/issuer.crt",
            allow_private_ip=False,
        )

    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_redirect_handler_rejects_private_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[_addrinfo("127.0.0.1")]),
    )
    handler = _AiaRedirectHandler(allow_private_ip=False)

    with pytest.raises(NonGlobalAddressError):
        handler.redirect_request(
            SimpleNamespace(),
            None,
            302,
            "Found",
            {},
            "http://internal.example/",
        )

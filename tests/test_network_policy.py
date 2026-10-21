from __future__ import annotations

import socket
from http.client import HTTPMessage
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock
from urllib.error import URLError
from urllib.request import ProxyHandler, Request

import pytest

from aia_chaser import AiaChaser, NonGlobalAddressError, chaser
from aia_chaser.exceptions import CertificateDownloadError
from aia_chaser.utils import http_pinning
from aia_chaser.utils.http_pinning import (
    AiaHTTPHandler,
    AiaHTTPSHandler,
    AiaRedirectHandler,
)
from aia_chaser.utils.http_utils import validate_and_get_http_host_port
from aia_chaser.utils.network import is_global_unicast_address, resolve_global_host
from tests.conftest import AIA_CA_ISSUER_URL


if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography import x509


def _addrinfo(
    address: str,
) -> tuple[int, int, int, str, tuple[str, int] | tuple[str, int, int, int]]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr


def test_validate_http_host_port_accepts_uppercase_scheme() -> None:
    """The HTTP validator should accept uppercase URL schemes."""
    assert validate_and_get_http_host_port("HTTPS://Example.com/path") == (
        "example.com",
        443,
    )


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


def test_default_private_ip_option_preserves_aia_downloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
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

    assert chaser._download_certificate(  # noqa: SLF001
        "http://internal.example/issuer.crt",
    )
    opener.open.assert_called_once()

    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_http_handler_rejects_private_ip_before_opening_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[_addrinfo("127.0.0.1")]),
    )

    handler = AiaHTTPHandler()
    monkeypatch.setattr(
        handler,
        "do_open",
        Mock(side_effect=AssertionError("private destination connected")),
    )

    with pytest.raises(NonGlobalAddressError):
        handler.http_open(Request("http://internal.example/issuer.crt"))


@pytest.mark.parametrize(
    ("handler_type", "method_name", "url", "expected_port"),
    [
        (AiaHTTPHandler, "http_open", "http://public.example/file", 80),
        (AiaHTTPSHandler, "https_open", "https://public.example/file", 443),
    ],
)
def test_http_handlers_pin_connection_to_validated_address(
    monkeypatch: pytest.MonkeyPatch,
    handler_type: type[AiaHTTPHandler | AiaHTTPSHandler],
    method_name: str,
    url: str,
    expected_port: int,
) -> None:
    address = _addrinfo("8.8.8.8")
    getaddrinfo = Mock(return_value=[address])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        getaddrinfo,
    )
    fake_socket = MagicMock()
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake_socket))

    handler = handler_type()
    do_open_mock = Mock()
    monkeypatch.setattr(handler, "do_open", do_open_mock)

    request = Request(url)  # noqa: S310
    request.timeout = None

    getattr(handler, method_name)(request)

    connection_class = do_open_mock.call_args.args[0]
    connection_kwargs: dict[str, object] = {"timeout": request.timeout}
    connection_kwargs.update(do_open_mock.call_args.kwargs)

    fake_context = None
    if method_name == "https_open":
        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_socket
        connection_kwargs["context"] = fake_context
    connection = connection_class(request.host, **connection_kwargs)
    connection.connect()

    getaddrinfo.assert_called_once_with(
        "public.example",
        expected_port,
        type=socket.SOCK_STREAM,
    )
    fake_socket.connect.assert_called_once_with(address[4])
    fake_socket.setsockopt.assert_called_once_with(
        socket.IPPROTO_TCP,
        socket.TCP_NODELAY,
        1,
    )
    if method_name == "https_open":
        assert fake_context is not None
        fake_context.wrap_socket.assert_called_once_with(
            fake_socket,
            server_hostname="public.example",
        )


def test_download_uses_pinned_handlers_and_disables_proxy_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"
    opener = Mock()
    opener.open.return_value = response
    build_opener = Mock(return_value=opener)
    monkeypatch.setattr(http_pinning, "build_opener", build_opener)
    monkeypatch.setattr(chaser, "_try_parse_certificate", Mock(return_value=[object()]))
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    assert chaser._download_certificate(  # noqa: SLF001
        "http://public.example/issuer.crt",
        allow_private_ip=False,
    )

    handlers = build_opener.call_args.args
    assert any(isinstance(handler, AiaHTTPHandler) for handler in handlers)
    assert any(isinstance(handler, AiaHTTPSHandler) for handler in handlers)
    proxy_handler = next(
        handler for handler in handlers if isinstance(handler, ProxyHandler)
    )
    assert proxy_handler.proxies == {}  # type: ignore[attr-defined]
    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_strict_redirect_rejects_non_http_scheme() -> None:
    handler = AiaRedirectHandler(allow_private_ip=False)

    with pytest.raises(CertificateDownloadError):
        handler.redirect_request(
            Request("http://public.example/original"),
            BytesIO(),
            302,
            "Found",
            HTTPMessage(),
            "ftp://internal.example/",
        )


def test_strict_redirect_is_checked_when_its_protocol_handler_opens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    getaddrinfo = Mock(return_value=[_addrinfo("127.0.0.1")])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        getaddrinfo,
    )
    handler = AiaRedirectHandler(allow_private_ip=False)
    redirect = handler.redirect_request(
        Request("http://public.example/original"),
        BytesIO(),
        302,
        "Found",
        HTTPMessage(),
        "http://internal.example/",
    )
    assert redirect is not None
    getaddrinfo.assert_not_called()

    with pytest.raises(NonGlobalAddressError):
        AiaHTTPHandler().http_open(redirect)


def test_proxy_handler_consults_environment_when_private_ips_are_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default opener should honor proxies from the environment."""
    environment_proxies = {"http": "http://proxy.example:8080"}
    monkeypatch.setattr(
        "urllib.request.getproxies",
        Mock(return_value=environment_proxies),
    )
    build_opener = Mock()
    monkeypatch.setattr(http_pinning, "build_opener", build_opener)

    http_pinning.build_certificate_opener(allow_private_ip=True)
    proxy_handler = next(
        handler
        for handler in build_opener.call_args.args
        if isinstance(handler, ProxyHandler)
    )

    assert proxy_handler.proxies == environment_proxies  # type: ignore[attr-defined]


def test_proxy_handler_ignores_environment_when_private_ips_are_disallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The strict opener should ignore proxies from the environment."""
    monkeypatch.setattr(
        "urllib.request.getproxies",
        Mock(return_value={"http": "http://proxy.example:8080"}),
    )
    build_opener = Mock()
    monkeypatch.setattr(http_pinning, "build_opener", build_opener)

    http_pinning.build_certificate_opener(allow_private_ip=False)
    proxy_handler = next(
        handler
        for handler in build_opener.call_args.args
        if isinstance(handler, ProxyHandler)
    )
    assert proxy_handler.proxies == {}  # type: ignore[attr-defined]


def test_download_certificate_warns_on_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    monkeypatch.setattr(chaser, "_try_parse_certificate", Mock(return_value=[object()]))
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    with pytest.warns(
        UserWarning,
        match="Trying to download an intermediate CA certificate using HTTPS",
    ):
        chaser._download_certificate("https://secure.example/cert.crt")  # noqa: SLF001

    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_try_download_certificate_accepts_uppercase_scheme(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=200)
    response.__enter__.return_value = response
    response.read.return_value = b"certificate"
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    certificate = object()
    monkeypatch.setattr(
        chaser,
        "_try_parse_certificate",
        Mock(return_value=[certificate]),
    )
    chaser._download_certificate.cache_clear()  # noqa: SLF001
    url = "HTTP://Example.com/CaseSensitivePath"

    assert chaser._try_download_certificate([url]) == [certificate]  # noqa: SLF001
    assert opener.open.call_args.args[0] == url

    chaser._download_certificate.cache_clear()  # noqa: SLF001


@pytest.mark.parametrize("url", ["ftp://example.com/cert.crt", "http"])
def test_download_certificate_raises_on_invalid_scheme(url: str) -> None:
    """The downloader should reject unsupported or missing schemes."""
    chaser._download_certificate.cache_clear()  # noqa: SLF001
    with pytest.raises(
        CertificateDownloadError,
        match="URL scheme must be http or https",
    ):
        chaser._download_certificate(url)  # noqa: SLF001
    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_download_certificate_wraps_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opener = Mock()
    opener.open.side_effect = URLError("connection refused")
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    with pytest.raises(CertificateDownloadError, match="could not download"):
        chaser._download_certificate("http://failing.example/cert.crt")  # noqa: SLF001

    chaser._download_certificate.cache_clear()  # noqa: SLF001


def test_download_certificate_raises_on_non_ok_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = MagicMock(status=404)
    response.__enter__.return_value = response
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr(http_pinning, "build_opener", Mock(return_value=opener))
    chaser._download_certificate.cache_clear()  # noqa: SLF001

    with pytest.raises(CertificateDownloadError, match="could not download"):
        chaser._download_certificate("http://notfound.example/cert.crt")  # noqa: SLF001

    chaser._download_certificate.cache_clear()  # noqa: SLF001


@pytest.mark.parametrize(
    ("handler_type", "method_name", "url", "expected_port"),
    [
        (AiaHTTPHandler, "http_open", "http://rebind.example/cert.crt", 80),
        (AiaHTTPSHandler, "https_open", "https://rebind.example/cert.crt", 443),
    ],
)
def test_dns_rebinding_toctou_prevention_on_handlers(
    monkeypatch: pytest.MonkeyPatch,
    handler_type: type[AiaHTTPHandler | AiaHTTPSHandler],
    method_name: str,
    url: str,
    expected_port: int,
) -> None:
    """Ensure DNS rebinding (TOCTOU) cannot bypass SSRF protection.

    Simulates a DNS rebinding where the first resolution is public
    and subsequent resolutions return a private IP.
    """
    public_addr = _addrinfo("8.8.8.8")
    private_addr = _addrinfo("127.0.0.1")

    # Mock side_effect iterates across responses on successive calls
    getaddrinfo_mock = Mock(side_effect=[[public_addr], [private_addr]])
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo_mock)

    fake_socket = MagicMock()
    monkeypatch.setattr(socket, "socket", Mock(return_value=fake_socket))

    handler = handler_type()
    do_open_mock = Mock()
    monkeypatch.setattr(handler, "do_open", do_open_mock)

    request = Request(url)  # noqa: S310
    request.timeout = None

    getattr(handler, method_name)(request)

    connection_class = do_open_mock.call_args.args[0]
    connection_kwargs: dict[str, object] = {"timeout": request.timeout}
    connection_kwargs.update(do_open_mock.call_args.kwargs)

    if method_name == "https_open":
        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_socket
        connection_kwargs["context"] = fake_context

    connection = connection_class(request.host, **connection_kwargs)
    connection.connect()

    # getaddrinfo must only be called once at validation time (no TOCTOU re-resolution)
    assert getaddrinfo_mock.call_count == 1
    getaddrinfo_mock.assert_called_once_with(
        "rebind.example",
        expected_port,
        type=socket.SOCK_STREAM,
    )
    # The socket must connect to the pre-validated public IP, never the private IP
    fake_socket.connect.assert_called_once_with(public_addr[4])
    assert fake_socket.connect.call_args.args[0] != private_addr[4]


def test_dns_rebinding_toctou_prevention_on_fetch_host_cert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure DNS rebinding (TOCTOU) cannot bypass host cert fetching."""
    public_addr = _addrinfo("8.8.8.8")
    private_addr = _addrinfo("127.0.0.1")

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

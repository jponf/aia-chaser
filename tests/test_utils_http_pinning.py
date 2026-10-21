from __future__ import annotations

import socket
from http.client import HTTPMessage
from io import BytesIO
from unittest.mock import MagicMock, Mock
from urllib.request import ProxyHandler, Request

import pytest

from aia_chaser import NonGlobalAddressError
from aia_chaser.exceptions import CertificateDownloadError
from aia_chaser.utils import http_pinning
from aia_chaser.utils.http_pinning import (
    AiaHTTPHandler,
    AiaHTTPSHandler,
    AiaRedirectHandler,
)
from tests.conftest import make_addrinfo


def test_http_handler_rejects_private_ip_before_opening_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[make_addrinfo("127.0.0.1")]),
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
    address = make_addrinfo("8.8.8.8")
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
    getaddrinfo = Mock(return_value=[make_addrinfo("127.0.0.1")])
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
    public_addr = make_addrinfo("8.8.8.8")
    private_addr = make_addrinfo("127.0.0.1")

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

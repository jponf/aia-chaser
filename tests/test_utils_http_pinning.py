from __future__ import annotations

import socket
from io import BytesIO
from unittest.mock import MagicMock, Mock
from urllib.error import URLError
from urllib.request import HTTPHandler, HTTPSHandler, ProxyHandler, Request

import pytest

from aia_chaser import NonGlobalAddressError
from aia_chaser.exceptions import InvalidUrlError
from aia_chaser.utils import http_pinning
from aia_chaser.utils.http_pinning import AiaHTTPHandler, AiaHTTPSHandler
from tests.conftest import make_addrinfo


def test_http_handler_rejects_url_without_hostname() -> None:
    """The handler should reject an HTTP URL without a hostname."""
    handler = AiaHTTPHandler(allow_private_ip=False)

    with pytest.raises(InvalidUrlError, match="invalid HTTP URL:"):
        handler.http_open(Request("http:///issuer.crt"))


def test_http_handler_rejects_private_ip_before_opening_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        Mock(return_value=[make_addrinfo("127.0.0.1")]),
    )

    handler = AiaHTTPHandler(allow_private_ip=False)
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

    handler = handler_type(allow_private_ip=False)
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
        assert isinstance(handler, AiaHTTPSHandler)
        assert (
            do_open_mock.call_args.kwargs["context"] is handler._context  # noqa: SLF001
        )
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


@pytest.mark.parametrize(
    ("handler_type", "method_name", "url", "expected_port"),
    [
        (AiaHTTPHandler, "http_open", "http://rebind.example/cert.crt", 80),
        (AiaHTTPSHandler, "https_open", "https://rebind.example/cert.crt", 443),
    ],
)
def test_http_handler_dns_rebinding_toctou_prevention(
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

    handler = handler_type(allow_private_ip=False)
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


@pytest.mark.parametrize(
    ("handler_type", "stock_handler_type", "method_name", "url"),
    [
        (AiaHTTPHandler, HTTPHandler, "http_open", "http://public.example/file"),
        (AiaHTTPSHandler, HTTPSHandler, "https_open", "https://public.example/file"),
    ],
)
def test_http_handler_skips_pinning_when_private_ips_are_allowed(
    monkeypatch: pytest.MonkeyPatch,
    handler_type: type[AiaHTTPHandler | AiaHTTPSHandler],
    stock_handler_type: type[HTTPHandler | HTTPSHandler],
    method_name: str,
    url: str,
) -> None:
    """The handler should delegate without pinning when private IPs are allowed."""
    # Mock open (http_open/https_open) on stock handlers
    stock_open = Mock()
    monkeypatch.setattr(stock_handler_type, method_name, stock_open)

    # Mock with resolve global host and getaddrinfo (should not be called)
    resolve_global_host = Mock(
        side_effect=AssertionError("Host validation should not run"),
    )
    getaddrinfo = Mock(
        side_effect=AssertionError("Address resolution should not run"),
    )
    monkeypatch.setattr(http_pinning, "resolve_global_host", resolve_global_host)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)

    # Instantiate handler and run http_open/https_open
    handler = handler_type(allow_private_ip=True)
    request = Request(url)  # noqa: S310
    response = getattr(handler, method_name)(request)

    # Assert response comes from mocked stock open
    assert response is stock_open.return_value
    stock_open.assert_called_once_with(request)

    # Assert resolve global and address info have not been called
    resolve_global_host.assert_not_called()
    getaddrinfo.assert_not_called()


def test_proxy_handler_consults_environment_when_private_ips_are_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default opener should honor proxies from the environment."""
    # Mock getting proxies from environment
    environment_proxies = {"http": "http://proxy.example:8080"}
    monkeypatch.setattr(
        "urllib.request.getproxies",
        Mock(return_value=environment_proxies),
    )
    # Mock build_opener from http_pinning
    build_opener = Mock()
    monkeypatch.setattr(http_pinning, "build_opener", build_opener)

    http_pinning.build_certificate_opener(allow_private_ip=True)

    # Verify build_opener is build with custom HTTP handlers
    handlers = build_opener.call_args.args
    assert any(isinstance(handler, AiaHTTPHandler) for handler in handlers)
    assert any(isinstance(handler, AiaHTTPSHandler) for handler in handlers)

    # Get proxy handler from call to build_opener
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
    handlers = build_opener.call_args.args
    assert any(isinstance(handler, AiaHTTPHandler) for handler in handlers)
    assert any(isinstance(handler, AiaHTTPSHandler) for handler in handlers)
    proxy_handler = next(
        handler for handler in handlers if isinstance(handler, ProxyHandler)
    )
    assert proxy_handler.proxies == {}  # type: ignore[attr-defined]


@pytest.mark.parametrize("allow_private_ip", [True, False])
def test_opener_rejects_ftp_schema(*, allow_private_ip: bool) -> None:
    opener = http_pinning.build_certificate_opener(allow_private_ip=allow_private_ip)
    with pytest.raises(URLError, match=r"'ftp' scheme is not supported:"):
        opener.open("ftp://hostname.net/")


@pytest.mark.parametrize("allow_private_ip", [True, False])
def test_opener_rejects_file_schema(*, allow_private_ip: bool) -> None:
    opener = http_pinning.build_certificate_opener(allow_private_ip=allow_private_ip)

    with pytest.raises(URLError, match=r"'file' scheme is not supported: file://\w+"):
        opener.open("file://hostname/path")

    with pytest.raises(URLError, match=r"'file' scheme is not supported: file:///\w+"):
        opener.open("file:///path")  # empty hostname

    with pytest.raises(URLError, match=r"'file' scheme is not supported: file:/\w+"):
        opener.open("file:/path")  # no hostname


@pytest.mark.parametrize("allow_private_ip", [True, False])
def test_opener_rejects_data_schema(*, allow_private_ip: bool) -> None:
    opener = http_pinning.build_certificate_opener(allow_private_ip=allow_private_ip)

    uris = [
        "data:text/vnd-example+xyz;foo=bar;base64,R0lGODdh",
        "data:text/plain;charset=UTF-8;page=21,the%20data:1234,5678",
        "data:image/jpeg;base64,/9j/4AAQSkZJRgABAgAAZABkAAD",
    ]
    for uri in uris:
        with pytest.raises(
            URLError,
            match=r"'data' scheme is not supported: data:",
        ):
            opener.open(uri)


def test_opener_rejects_ftp_redirect_even_when_private_ips_are_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opener should reject FTP redirects even when private IPs are allowed."""
    # Set up fake socket that returns 302 redirect to ftp address
    monkeypatch.setattr("urllib.request.getproxies", Mock(return_value={}))
    fake_socket = MagicMock()
    fake_socket.makefile.return_value = BytesIO(
        b"HTTP/1.1 302 Found\r\n"
        b"Location: ftp://public.example/issuer.crt\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n",
    )
    create_connection = Mock(return_value=fake_socket)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(
        "urllib.request.FTPHandler.ftp_open",
        Mock(side_effect=AssertionError("FTP redirect was followed")),
    )

    # Simulate opener + redirect
    opener = http_pinning.build_certificate_opener(allow_private_ip=True)
    with pytest.raises(URLError, match="ftp"):
        opener.open("http://public.example/issuer.crt")

    create_connection.assert_called_once()


def test_opener_rejects_redirect_to_private_ip_when_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The strict opener should reject redirects to private IP addresses."""
    # Mock address resolution first 8.8.8.8 then 127.0.0.1
    public_address = make_addrinfo("8.8.8.8")
    getaddrinfo = Mock(
        side_effect=[[public_address], [make_addrinfo("127.0.0.1")]],
    )
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)

    # Set up fake socket that returns 302 redirect to private address
    fake_socket = MagicMock()
    fake_socket.makefile.return_value = BytesIO(
        b"HTTP/1.1 302 Found\r\n"
        b"Location: http://internal.example/issuer.crt\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n",
    )
    socket_factory = Mock(return_value=fake_socket)
    monkeypatch.setattr(socket, "socket", socket_factory)

    # Run opener with redirect to private
    opener = http_pinning.build_certificate_opener(allow_private_ip=False)
    with pytest.raises(NonGlobalAddressError):
        opener.open("http://public.example/issuer.crt")

    # Verify public and internal hostname have been resolved
    getaddrinfo.assert_any_call("public.example", 80, type=socket.SOCK_STREAM)
    getaddrinfo.assert_any_call("internal.example", 80, type=socket.SOCK_STREAM)

    # Opener did open a connection to public address
    socket_factory.assert_called_once()
    fake_socket.connect.assert_called_once_with(public_address[4])


def test_opener_follows_legitimate_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opener should follow a redirect to a public host and return its response."""
    # Mock address resolution first 8.8.8.8 then 1.1.1.1
    initial_address = make_addrinfo("8.8.8.8")
    final_address = make_addrinfo("1.1.1.1")
    getaddrinfo = Mock(side_effect=[[initial_address], [final_address]])
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)

    # Set up fake socket that returns 302 redirect to public address
    redirect_socket = MagicMock()
    redirect_socket.makefile.return_value = BytesIO(
        b"HTTP/1.1 302 Found\r\n"
        b"Location: http://redirect.example/issuer.crt\r\n"
        b"Content-Length: 0\r\n"
        b"Connection: close\r\n"
        b"\r\n",
    )
    # Set up fake socket that returns legitimate redirect data
    final_socket = MagicMock()
    final_socket.makefile.return_value = BytesIO(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 11\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"certificate",
    )
    monkeypatch.setattr(
        socket,
        "socket",
        Mock(side_effect=[redirect_socket, final_socket]),
    )

    # Run opener with redirect to legitimate (public) address
    opener = http_pinning.build_certificate_opener(allow_private_ip=False)

    # Assert response is from final legitimate connection
    with opener.open("http://public.example/issuer.crt") as response:
        assert response.status == 200  # noqa: PLR2004
        assert response.geturl() == "http://redirect.example/issuer.crt"
        assert response.read() == b"certificate"

    # Verify redirect and public hostname have been resolved
    getaddrinfo.assert_any_call("public.example", 80, type=socket.SOCK_STREAM)
    getaddrinfo.assert_any_call("redirect.example", 80, type=socket.SOCK_STREAM)

    # Verify both sockets have been connected to
    redirect_socket.connect.assert_called_once_with(initial_address[4])
    final_socket.connect.assert_called_once_with(final_address[4])


def test_cached_certificate_opener_should_cache_by_private_ip_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The opener cache should reuse one opener per private-IP policy."""
    http_pinning.get_cached_certificate_opener.cache_clear()
    default_opener = Mock()
    strict_opener = Mock()
    expected_build_count = 2
    build_opener = Mock(side_effect=[default_opener, strict_opener])
    monkeypatch.setattr(http_pinning, "build_certificate_opener", build_opener)

    assert (
        http_pinning.get_cached_certificate_opener(allow_private_ip=True)
        is default_opener
    )
    assert (
        http_pinning.get_cached_certificate_opener(allow_private_ip=True)
        is default_opener
    )
    assert (
        http_pinning.get_cached_certificate_opener(allow_private_ip=False)
        is strict_opener
    )
    assert build_opener.call_count == expected_build_count
    http_pinning.get_cached_certificate_opener.cache_clear()

from __future__ import annotations

import functools
import http.client
import ssl
from typing import TYPE_CHECKING
from urllib.request import (
    BaseHandler,
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    OpenerDirector,
    ProxyHandler,
    build_opener,
)

from aia_chaser.utils.http_utils import validate_and_get_http_host_port
from aia_chaser.utils.network import (
    SocketAddressInfo,
    create_pinned_socket,
    resolve_global_host,
)


if TYPE_CHECKING:
    import socket
    from collections.abc import Sequence
    from http.client import HTTPMessage, HTTPResponse
    from typing import IO
    from urllib.request import Request


class AiaRedirectHandler(HTTPRedirectHandler):
    """Validate redirect destinations when private addresses are disallowed."""

    def __init__(self, *, allow_private_ip: bool) -> None:
        self.allow_private_ip = allow_private_ip
        super().__init__()

    def redirect_request(  # noqa: PLR0913, PLR0917
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        """Create a redirect request after validating its destination."""
        if not self.allow_private_ip:
            validate_and_get_http_host_port(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class PinnedConnectionMixin:
    """Use pre-resolved addresses with the standard HTTP connect lifecycle."""

    _addresses: Sequence[SocketAddressInfo]

    def _init_pinned(
        self,
        addresses: Sequence[SocketAddressInfo],
    ) -> None:
        self._addresses = addresses
        self._create_connection = functools.partial(
            _create_pinned_connection,
            addresses=self._addresses,
        )


def _create_pinned_connection(
    address: tuple[str, int],
    timeout: float | None = None,
    source_address: tuple[str, int] | None = None,
    *,
    addresses: Sequence[SocketAddressInfo],
) -> socket.socket:
    """Create a socket using a connection's pre-resolved addresses."""
    # Keep the callback parameter, HTTPConnection.connect() calls
    # _create_connection(address, timeout, source_address)  # noqa: ERA001
    # pinning uses the validated address list.
    del address

    return create_pinned_socket(
        addresses,
        timeout,
        source_address,
        set_nodelay=False,
    )


class PinnedHTTPConnection(PinnedConnectionMixin, http.client.HTTPConnection):
    """HTTP connection pinned to a previously validated address list."""

    def __init__(
        self,
        host: str,
        *,
        addresses: Sequence[SocketAddressInfo],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
    ) -> None:
        super().__init__(
            host,
            timeout=timeout,
            source_address=source_address,
        )
        self._init_pinned(addresses)


class PinnedHTTPSConnection(PinnedConnectionMixin, http.client.HTTPSConnection):
    """HTTPS connection pinned to validated addresses and an SSL context."""

    def __init__(
        self,
        host: str,
        *,
        addresses: Sequence[SocketAddressInfo],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            host,
            timeout=timeout,
            source_address=source_address,
            context=context,
        )
        self._init_pinned(addresses)


class AiaHTTPHandler(HTTPHandler):
    """Open HTTP requests using globally reachable, pinned addresses."""

    def http_open(self, req: Request) -> HTTPResponse:
        """Resolve and pin the request host before opening the connection."""
        host, port = validate_and_get_http_host_port(req.full_url)
        addresses = resolve_global_host(host, port)
        http_class = functools.partial(
            PinnedHTTPConnection,
            addresses=addresses,
        )
        return self.do_open(http_class, req)  # pyright: ignore[reportArgumentType]


class AiaHTTPSHandler(HTTPSHandler):
    """Open HTTPS requests using globally reachable, pinned addresses."""

    def __init__(self) -> None:
        context = ssl._create_default_https_context()  # noqa: SLF001
        super().__init__(context=context)
        self._aia_context = context

    def https_open(self, req: Request) -> HTTPResponse:
        """Resolve and pin the request host before opening the TLS connection."""
        host, port = validate_and_get_http_host_port(req.full_url)
        addresses = resolve_global_host(host, port)
        http_class = functools.partial(
            PinnedHTTPSConnection,
            addresses=addresses,
        )
        return self.do_open(
            http_class,  # pyright: ignore[reportArgumentType]
            req,
            context=self._aia_context,
        )


def build_certificate_opener(
    *,
    allow_private_ip: bool = True,
) -> OpenerDirector:
    """Build a urllib opener configured for AIA certificate downloads.

    When private addresses are disallowed, redirects are restricted to valid
    HTTP(S) URLs and connections use pinned global addresses. Environment
    proxies are disabled in this mode because they could bypass address
    pinning. When private addresses are allowed, urllib's default redirect
    behavior and environment proxies are used for backwards compatibility.

    Args:
        allow_private_ip: Whether non-global IP addresses may be used.

    Returns:
        An opener configured for AIA certificate downloads.
    """
    handlers: list[BaseHandler] = [
        AiaRedirectHandler(allow_private_ip=allow_private_ip),
    ]
    if allow_private_ip:
        handlers.append(ProxyHandler())
    else:
        handlers.append(ProxyHandler({}))
        handlers.extend((AiaHTTPHandler(), AiaHTTPSHandler()))
    return build_opener(*handlers)

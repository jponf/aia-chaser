from __future__ import annotations

import functools
import http.client
from typing import TYPE_CHECKING
from urllib.error import URLError
from urllib.request import (
    BaseHandler,
    DataHandler,
    FileHandler,
    FTPHandler,
    HTTPHandler,
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
    import ssl
    from collections.abc import Sequence
    from http.client import HTTPResponse
    from typing import NoReturn
    from urllib.request import Request


class _DisabledFileHandler(FileHandler):
    """Reject file:// requests; AIA, CRL, and OCSP are HTTP(S)-only."""

    def file_open(self, req: Request) -> NoReturn:
        msg = f"'file' scheme is not supported: {req.full_url}"
        raise URLError(msg)


class _DisabledFTPHandler(FTPHandler):
    """Reject ftp:// requests; AIA, CRL, and OCSP are HTTP(S)-only."""

    def ftp_open(self, req: Request) -> NoReturn:
        msg = f"'ftp' scheme is not supported: {req.full_url}"
        raise URLError(msg)


class _DisabledDataHandler(DataHandler):
    """Reject data: requests; AIA, CRL, and OCSP are HTTP(S)-only."""

    def data_open(self, req: Request) -> NoReturn:
        msg = f"'data' scheme is not supported: {req.full_url}"
        raise URLError(msg)


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
    """Validate the request URL, pinning the connection when strict."""

    def __init__(self, *, allow_private_ip: bool) -> None:
        self.allow_private_ip = allow_private_ip
        super().__init__()

    def http_open(self, req: Request) -> HTTPResponse:
        """Validate the URL, then connect directly or via a pinned address."""
        host, port = validate_and_get_http_host_port(req.full_url)

        # Original handler behaviour
        if self.allow_private_ip:
            return super().http_open(req)

        # Pinned connection to global host
        addresses = resolve_global_host(host, port)
        http_class = functools.partial(
            PinnedHTTPConnection,
            addresses=addresses,
        )
        return self.do_open(http_class, req)  # pyright: ignore[reportArgumentType]


class AiaHTTPSHandler(HTTPSHandler):
    """Validate the request URL, pinning the connection when strict."""

    _context: ssl.SSLContext

    def __init__(self, *, allow_private_ip: bool) -> None:
        self.allow_private_ip = allow_private_ip
        super().__init__()

    def https_open(self, req: Request) -> HTTPResponse:
        """Validate the URL, then connect directly or via a pinned address."""
        host, port = validate_and_get_http_host_port(req.full_url)

        # Original handler behaviour
        if self.allow_private_ip:
            return super().https_open(req)

        # Pinned connection to global host
        addresses = resolve_global_host(host, port)
        http_class = functools.partial(
            PinnedHTTPSConnection,
            addresses=addresses,
        )
        return self.do_open(
            http_class,  # pyright: ignore[reportArgumentType]
            req,
            context=self._context,  # pyright: ignore[reportAttributeAccessIssue]
        )


def build_certificate_opener(
    *,
    allow_private_ip: bool = True,
) -> OpenerDirector:
    """Build a urllib opener configured for AIA certificate downloads.

    The opener only ever serves HTTP(S) requests: `file://`, `ftp://`, and
    `data:` handlers are excluded, and redirects are restricted to valid
    HTTP(S) URLs. Both restrictions apply regardless of `allow_private_ip`,
    because CPython's default handlers would otherwise serve `file://`
    directly and follow redirects to `ftp://` even in permissive mode.

    When private addresses are disallowed, connections are additionally
    pinned to a validated global address, and environment proxies are
    ignored because they could bypass address pinning. When private
    addresses are allowed, environment proxies are honored for backwards
    compatibility.

    Args:
        allow_private_ip: Whether non-global IP addresses may be used.

    Returns:
        An opener configured for AIA certificate downloads.
    """
    handlers: list[BaseHandler] = [
        AiaHTTPHandler(allow_private_ip=allow_private_ip),
        AiaHTTPSHandler(allow_private_ip=allow_private_ip),
        _DisabledFileHandler(),
        _DisabledFTPHandler(),
        _DisabledDataHandler(),
        ProxyHandler() if allow_private_ip else ProxyHandler({}),
    ]
    return build_opener(*handlers)


@functools.lru_cache(maxsize=2)
def get_cached_certificate_opener(
    *,
    allow_private_ip: bool = True,
) -> OpenerDirector:
    """Return the cached opener configured for the requested IP policy."""
    return build_certificate_opener(allow_private_ip=allow_private_ip)

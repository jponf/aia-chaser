from __future__ import annotations

import ipaddress
import socket
from typing import cast
from urllib.parse import urlsplit

from aia_chaser.constants import DEFAULT_SCHEME_PORT, SocketAddressInfo
from aia_chaser.exceptions import NonGlobalAddressError


_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_DISCOVERY = ipaddress.IPv6Network("64:ff9b:1::/48")


def extract_host_port_from_url(url_string: str) -> tuple[str, int]:
    """Extract host and port from a URL string.

    If the port is not explicitly specified it will be inferred from the
    scheme.

    Args:
        url_string: URL from which to extract the host.

    Returns:
        The hostname of `url_string` and the explicit or inferred port.

    Raises:
        ValueError: If the host or port cannot be extracted from the given
            URL. It may happen with a seemingly correct URL if
            it is missing the scheme component.
    """
    url_split = urlsplit(url_string)
    host = url_split.hostname
    if not host:
        raise ValueError("cannot split host from URL, missing scheme?")

    scheme = url_split.scheme.lower()
    port = url_split.port

    if port is None:
        if not scheme:
            raise ValueError("URL has no port nor scheme to infer it")
        if scheme not in DEFAULT_SCHEME_PORT:
            raise ValueError(f"default port for scheme '{scheme}' is not known")

        port = DEFAULT_SCHEME_PORT[scheme]

    return host, port


def is_global_address(value: str | int) -> bool:
    """Return whether an IP address is globally routable.

    IPv4 addresses embedded in IPv6 transition or NAT64 addresses are checked
    directly, and Teredo addresses are rejected.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv6Address):
        if address.teredo is not None:
            return False
        embedded_ipv4 = address.ipv4_mapped or address.sixtofour
        if embedded_ipv4 is None and (
            address in _NAT64_WELL_KNOWN or address in _NAT64_DISCOVERY
        ):
            embedded_ipv4 = ipaddress.IPv4Address(address.packed[-4:])
        if embedded_ipv4 is not None:
            address = embedded_ipv4

    return address.is_global


def resolve_global_host(
    host: str,
    port: int | None = None,
) -> list[SocketAddressInfo]:
    """Resolve a host and ensure every returned address is globally routable.

    Args:
        host: Hostname or IP address to resolve.
        port: Optional port passed to the address resolver.

    Returns:
        The resolved socket address records.

    Raises:
        socket.gaierror: If the host does not resolve to any addresses.
        NonGlobalAddressError: If any resolved address is not globally
            routable.
    """
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise socket.gaierror(socket.EAI_NONAME, host)

    global_addresses: list[SocketAddressInfo] = []
    for address_info in addresses:
        address = address_info[4][0]
        if not isinstance(address, str) or len(address_info[4]) not in (2, 4):
            raise socket.gaierror(socket.EAI_FAMILY, host)
        if not is_global_address(address):
            raise NonGlobalAddressError(
                host=host,
                address=address,
            )
        global_addresses.append(cast("SocketAddressInfo", address_info))
    return global_addresses

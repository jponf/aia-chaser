from __future__ import annotations

import ipaddress
import socket
import sys
from typing import cast

from aia_chaser.exceptions import NonGlobalAddressError


if sys.version_info < (3, 10):
    from typing import Tuple, Union

    SocketAddressInfo = Tuple[
        int,
        int,
        int,
        str,
        Union[Tuple[str, int], Tuple[str, int, int, int]],
    ]
else:
    SocketAddressInfo = tuple[
        int,
        int,
        int,
        str,
        tuple[str, int] | tuple[str, int, int, int],
    ]

_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_DISCOVERY = ipaddress.IPv6Network("64:ff9b:1::/48")


def is_global_address(value: str | int) -> bool:
    """Return whether an IP address is globally routable.

    IPv4 addresses embedded in IPv6 transition or NAT64 addresses are checked
    directly, and Teredo addresses are rejected.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    # Do not replace this normalization with a raw IPv6Address.is_global check:
    # Python 3.9 reports 2002:0a00:0001:: (6to4 for 10.0.0.1) as global and
    # ::ffff:8.8.8.8 as non-global; Python 3.12/3.14 report the opposite.
    # Unwrap embedded IPv4 so the address policy stays consistent.
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

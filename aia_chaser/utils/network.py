from __future__ import annotations

import errno
import ipaddress
import socket
from typing import TYPE_CHECKING, cast

from aia_chaser.exceptions import NonGlobalAddressError


if TYPE_CHECKING:
    from collections.abc import Sequence


SocketAddressInfo = tuple[
    int,
    int,
    int,
    str,
    tuple[str, int] | tuple[str, int, int, int],
]

_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_DISCOVERY = ipaddress.IPv6Network("64:ff9b:1::/48")


def create_pinned_socket(
    addresses: Sequence[SocketAddressInfo],
    timeout: float | None,
    source_address: tuple[str, int] | None,
    *,
    set_nodelay: bool = True,
) -> socket.socket:
    """Connect to the first successful pre-resolved socket address.

    This connects directly to each supplied socket address without resolving a
    hostname, preserving the caller's address pinning.

    Args:
        addresses: Socket addresses to try in order.
        timeout: Timeout applied to each socket before connecting.
        source_address: Optional local address to bind before connecting.
        set_nodelay: Whether to enable TCP_NODELAY on the connected socket.

    Returns:
        The first successfully connected socket.

    Raises:
        OSError: If all supplied addresses fail to connect.
        socket.gaierror: If no addresses are supplied.
    """
    connection_errors: list[OSError] = []
    for family, socktype, protocol, _, sockaddr in addresses:
        sock = socket.socket(family, socktype, protocol)
        try:
            sock.settimeout(timeout)
            if source_address is not None:
                sock.bind(source_address)
            sock.connect(sockaddr)
            if set_nodelay:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError as err:
                    if err.errno != errno.ENOPROTOOPT:
                        raise
        except OSError as err:
            sock.close()
            connection_errors.append(err)
        else:
            return sock

    if connection_errors:
        raise connection_errors[-1]
    raise socket.gaierror(socket.EAI_NONAME, "no addresses to connect to")


def is_global_unicast_address(value: str | int) -> bool:
    """Return whether an IP address is a globally routable unicast destination.

    This check is intended for TCP peer addresses, so multicast is rejected
    even when it has global scope. IPv4 addresses embedded in IPv6 transition
    or NAT64 addresses are checked directly, and Teredo addresses are rejected.

    Args:
        value: IP address as a string or an integer representing an
            IPv4 or IPv6 address.
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
        elif address.is_site_local or address.is_reserved:
            # fec0::/10 (RFC 3879) and ::/96 (RFC 4291) are deprecated and
            # not globally routable, but is_global doesn't know that; these
            # stdlib properties exist specifically to cover the gap.
            return False

    if address.is_multicast:
        return False

    return address.is_global


def resolve_global_host(
    host: str,
    port: int | None = None,
) -> list[SocketAddressInfo]:
    """Resolve a host and retain only globally routable addresses.

    Args:
        host: Hostname or IP address to resolve.
        port: Optional port passed to the address resolver.

    Returns:
        Only the resolved socket address records that are globally routable.

    Raises:
        socket.gaierror: If the host does not resolve to any addresses.
        NonGlobalAddressError: If no resolved address is globally routable.
    """
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise socket.gaierror(socket.EAI_NONAME, host)

    global_addresses: list[SocketAddressInfo] = []
    first_non_global_address: str | None = None
    for address_info in addresses:
        address = address_info[4][0]
        if not isinstance(address, str) or len(address_info[4]) not in (2, 4):
            raise socket.gaierror(socket.EAI_FAMILY, host)
        if not is_global_unicast_address(address):
            if first_non_global_address is None:
                first_non_global_address = address
            continue
        global_addresses.append(cast("SocketAddressInfo", address_info))

    if not global_addresses:
        if first_non_global_address is None:
            raise socket.gaierror(socket.EAI_NONAME, host)
        raise NonGlobalAddressError(
            host=host,
            address=first_non_global_address,
        )

    return global_addresses


def create_global_unicast_connection(host: str, port: int) -> socket.socket:
    """Resolve, validate, and connect to a globally routable unicast host.

    The returned socket connects to one of the validated address records
    directly, without a second hostname resolution.

    Args:
        host: Hostname or IP address to resolve and connect to.
        port: Remote port to connect to.

    Returns:
        A connected socket to a validated global unicast address.

    Raises:
        socket.gaierror: If the host does not resolve to usable addresses.
        NonGlobalAddressError: If no resolved address is globally routable
            unicast.
        OSError: If connections to all validated addresses fail.
    """
    addresses = resolve_global_host(host, port)
    return create_pinned_socket(addresses, timeout=None, source_address=None)

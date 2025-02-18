from __future__ import annotations

from urllib.parse import urlsplit

from aia_chaser.constants import DEFAULT_SCHEME_PORT


def extract_host_port_from_url(url_string: str) -> tuple[str, int]:
    """Extract host and port from a URL string.

    If the port is not explicitly specified it will be inferred from the
    scheme.

    Args:
        url_string: URL from which to extract the host.

    Returns:
        The host (netloc) of `url_string` and, if present, the port.

    Raises:
        ValueError: If the host or port cannot be extracted from the given
            URL. It may happen with a seemingly correct URL if
            it is missing the scheme component.
    """
    url_split = urlsplit(url_string)
    if not url_split.netloc:
        raise ValueError("cannot split host from URL, missing scheme?")

    scheme = url_split.scheme.lower()
    port = url_split.port

    if port is None:
        if not scheme:
            raise ValueError("URL has no port nor scheme to infer it")
        if scheme not in DEFAULT_SCHEME_PORT:
            raise ValueError(f"default port for scheme '{scheme}' is not known")

        port = DEFAULT_SCHEME_PORT[scheme]

    return url_split.netloc, port

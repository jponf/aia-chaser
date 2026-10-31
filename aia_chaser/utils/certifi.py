"""Utilities for using certifi's CA bundle."""

from __future__ import annotations

import ssl


def create_certifi_context(*, for_chaser: bool = True) -> ssl.SSLContext:
    """Create an SSL context using certifi's CA bundle.

    Args:
        for_chaser: Disable hostname and certificate verification for the
            initial connection when `True`. The chaser performs certificate
            verification after retrieving the chain. When `False`, retain
            the standard TLS verification settings.

    Returns:
        An SSL context loaded with certifi's CA certificates.

    Raises:
        ImportError: If certifi is not installed. Install the extra with
            `pip install aia-chaser[certifi]`.
    """
    try:
        import certifi  # noqa: PLC0415
    except ImportError as exc:
        msg = "certifi is required, install it with `pip install aia-chaser[certifi]`."
        raise ImportError(msg) from exc

    context = ssl.create_default_context(cafile=certifi.where())
    if for_chaser:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context

from __future__ import annotations

import pytest

from aia_chaser.utils.url import (
    extract_host_port_from_url,
    extract_scheme_from_url,
    extract_scheme_host_port_from_url,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/path", ("example.com", 443)),
        ("http://example.com:8080/path", ("example.com", 8080)),
        ("https://[2001:4860:4860::8888]/", ("2001:4860:4860::8888", 443)),
    ],
)
def test_extract_host_port_from_url_returns_hostname_and_port(
    url: str,
    expected: tuple[str, int],
) -> None:
    """The host-port extractor should infer defaults and retain explicit ports."""
    assert extract_host_port_from_url(url) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("HTTPS://example.com/path", "https"),
        ("http://example.com/path", "http"),
        ("example.com/path", ""),
    ],
)
def test_extract_scheme_from_url_returns_lowercase_scheme(
    url: str,
    expected: str,
) -> None:
    """The scheme extractor should lowercase schemes and allow missing ones."""
    assert extract_scheme_from_url(url) == expected


def test_extract_scheme_host_port_from_url_returns_components() -> None:
    """The combined extractor should return a normalized scheme and endpoint."""
    assert extract_scheme_host_port_from_url("HTTPS://Example.com/path") == (
        "https",
        "example.com",
        443,
    )


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("example.com/path", "cannot split host from URL, missing scheme?"),
        ("//example.com/path", "URL has no port nor scheme to infer it"),
        ("custom://example.com/path", "default port for scheme 'custom' is not known"),
    ],
)
def test_extract_scheme_host_port_from_url_rejects_unresolvable_endpoints(
    url: str,
    message: str,
) -> None:
    """The endpoint extractor should explain why a URL cannot provide a port."""
    with pytest.raises(ValueError, match=message):
        extract_scheme_host_port_from_url(url)

from __future__ import annotations

from aia_chaser.utils.http_utils import validate_and_get_http_host_port


def test_validate_http_host_port_accepts_uppercase_scheme() -> None:
    """The HTTP validator should accept uppercase URL schemes."""
    assert validate_and_get_http_host_port("HTTPS://Example.com/path") == (
        "example.com",
        443,
    )

"""Tests for aia_chaser.utils.cert_utils."""

from __future__ import annotations

import ssl
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning

from aia_chaser.exceptions import AiaChaserWarning
from aia_chaser.utils.cert_utils import load_ssl_ca_certificates


DATA_DIR = Path(__file__).parent / "data"


@pytest.fixture
def negative_serial_cert() -> x509.Certificate:
    """Certificate with a negative serial number (RFC 5280 violation)."""
    pem = (DATA_DIR / "negative_serial.pem").read_bytes()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        return x509.load_pem_x509_certificate(pem)


def test_negative_serial_cert_has_non_positive_serial(
    negative_serial_cert: x509.Certificate,
) -> None:
    """Should confirm the test fixture has a non-positive serial number."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        assert negative_serial_cert.serial_number <= 0


def test_load_ssl_ca_certificates_skips_unparseable_cert() -> None:
    """Should skip a cert that raises on parse and return only the valid ones."""
    good_cert = object()

    def patched_load(der: bytes) -> x509.Certificate:
        if der == b"bad":
            raise ValueError(  # noqa: TRY003
                "simulated future cryptography exception",  # noqa: EM101
            )
        return good_cert  # type: ignore[return-value]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with (
        patch.object(ctx, "get_ca_certs", return_value=[b"good", b"bad"]),
        patch(
            "aia_chaser.utils.cert_utils.x509.load_der_x509_certificate",
            patched_load,
        ),
        pytest.warns(AiaChaserWarning),
    ):
        result = load_ssl_ca_certificates(ctx, force_load=False)

    assert result == [good_cert]

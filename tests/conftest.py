"""Integration tests configuration file for pytest."""

from __future__ import annotations

import datetime as dt
import socket
from typing import TYPE_CHECKING

import faker
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID

from aia_chaser import AiaChaser
from aia_chaser.utils.cert_utils import load_ssl_ca_certificates
from aia_chaser.utils.certifi import create_certifi_context


if TYPE_CHECKING:
    import ssl
    from collections.abc import Mapping, Sequence

    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey,
        RSAPublicKey,
    )

    from aia_chaser.utils.network import SocketAddressInfo

# Fake AIA CA issuer url for tests
AIA_CA_ISSUER_URL = "http://ca.example/issuer.crt"

# Smaller subset for HTTP library integration tests
TEST_URLS_SUBSET = (
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.github.com",
    "https://www.kernel.org",
)

# Full test URLs used for AIA chase tests
TEST_URLS = (
    # Companies
    "https://aliexpress.com",
    "https://www.baidu.com",
    "https://www.siemens.com",
    "https://www.microsoft.com",
    "https://www.amazon.com",
    "https://www.google.com",
    # News
    "https://www.elperiodico.com",
    "https://segre.com",
    "https://www.nytimes.com",
    # Governments
    "https://administracion.gob.es",
    "https://www.bundesregierung.de",
    "https://www.elysee.fr",
    "https://www.gov.uk",
    "https://www.japan.go.jp",
    "https://www.usa.gov",
    # Universities
    "https://udl.cat",
    "https://www.upc.edu",
    "https://www.mit.edu",
    "https://www.berkeley.edu",
    "https://en.snu.ac.kr",
    # NGOs
    "https://www.redcross.org",
    "https://www2.cruzroja.es",
    # Other
    "https://www.kernel.org",
    "https://www.fbi.gov",
    "https://policia.es",
    "https://mossos.gencat.cat",
)

EXPIRED_URLS = (
    "https://expired.badssl.com/",
    "https://expired-rsa-dv.ssl.com/",
    "https://expired-rsa-ev.ssl.com/",
    "https://expired-ecc-dv.ssl.com/",
    "https://expired-ecc-ev.ssl.com/",
)

REVOKED_CRL_URLS = ("https://revoked.badssl.com/",)

REVOKED_OCSP_URLS = (
    # "https://revoked.grc.com/",  # started failing with unauthorized response  # noqa: ERA001
    "https://revoked-rsa-dv.ssl.com/",
    "https://revoked-ecc-dv.ssl.com/",
    "https://revoked-ecc-ev.ssl.com/",
)


def make_addrinfo(
    address: str,
) -> SocketAddressInfo:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr


def make_certificate(
    cert_key: RSAPublicKey,
    issuer_name: x509.Name,
    issuer_key: RSAPrivateKey,
    aia_ca_issuer_url: str | None = None,
) -> x509.Certificate:
    fake = faker.Faker(locale=["en_US"])
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, fake.country_code()),
            x509.NameAttribute(NameOID.LOCALITY_NAME, fake.city()),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, fake.company()),
            x509.NameAttribute(NameOID.COMMON_NAME, fake.hostname()),
        ],
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(cert_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10),
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(fake.domain_name())]),
            critical=False,
        )
    )
    if aia_ca_issuer_url is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.CA_ISSUERS,  # pyright: ignore[reportPrivateImportUsage]
                        x509.UniformResourceIdentifier(aia_ca_issuer_url),
                    ),
                ],
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture(scope="session")
def root_ca_key() -> RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


@pytest.fixture(scope="session")
def root_ca(root_ca_key: RSAPrivateKey) -> x509.Certificate:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "myca.com"),
        ],
    )

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(root_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10),
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(root_ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def host_and_ca_chain(
    root_ca_key: RSAPrivateKey,
    root_ca: x509.Certificate,
) -> Sequence[x509.Certificate]:
    leaf_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return [
        make_certificate(
            cert_key=leaf_key.public_key(),
            issuer_name=root_ca.subject,
            issuer_key=root_ca_key,
        ),
        root_ca,
    ]


@pytest.fixture(scope="session")
def certifi_context() -> ssl.SSLContext:
    return create_certifi_context(for_chaser=True)


@pytest.fixture
def chaser_certifi(certifi_context: ssl.SSLContext) -> AiaChaser:
    return AiaChaser(context=certifi_context)


@pytest.fixture(scope="session")
def certifi_certificates(
    certifi_context: ssl.SSLContext,
) -> Mapping[x509.Name, x509.Certificate]:
    certs = load_ssl_ca_certificates(certifi_context, force_load=False)
    return {cert.subject: cert for cert in certs}

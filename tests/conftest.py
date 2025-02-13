"""Integration tests configuration file for pytest."""

import datetime
from collections.abc import Sequence

import faker
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509 import NameOID


def make_certificate(
    cert_key: RSAPublicKey,
    issuer_name: x509.Name,
    issuer_key: RSAPrivateKey,
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

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(cert_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10),
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(fake.domain_name())]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )


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
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10),
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(root_ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def host_and_ca(
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

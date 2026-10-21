from types import MappingProxyType

from aia_chaser.utils.type_utils import StrEnum


DOWNLOAD_CACHE_SIZE = 1024

DEFAULT_URLOPEN_TIMEOUT = 30

DEFAULT_SCHEME_PORT = MappingProxyType(
    {
        "dns": 53,
        "ftp": 21,
        "http": 80,
        "https": 443,
        "ipp": 631,
        "nfs": 111,
        "ssh": 22,
        "telnet": 23,
    },
)

X509_CERTIFICATE_MIME = (
    "application/x-x509-ca-cert",
    "application/pkix-cert",
    "application/octet-stream",
    "binary/octet-stream",
)


class HttpHeader(StrEnum):
    """HTTP header name."""

    CONTENT_TYPE = "Content-Type"


class SSLReason(StrEnum):
    """SSL error reasons."""

    NO_CERTIFICATE_FOUND = "NO_CERTIFICATE_OR_CRL_FOUND"

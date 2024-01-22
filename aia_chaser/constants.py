from types import MappingProxyType

from aia_chaser.utils.type_utils import StrEnum


DOWNLOAD_CACHE_SIZE = 1024

DEFAULT_URLOPEN_TIMEOUT = 30

DEFAULT_SCHEME_PORT = MappingProxyType(
    {
        "ftp": 21,
        "http": 80,
        "https": 443,
    },
)

X509_CERTIFICATE_DER_MIME = (
    "application/pkix-cert",
    "application/x-x509-ca-cert",
)


class HttpHeader(StrEnum):
    """HTTP header name."""

    CONTENT_TYPE = "Content-Type"

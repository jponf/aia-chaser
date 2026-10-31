from __future__ import annotations

import collections
import contextlib
import dataclasses
import http
import http.client
import socket
import ssl
import warnings
from threading import RLock
from types import MappingProxyType
from typing import TYPE_CHECKING, NamedTuple
from urllib.error import URLError

from cachetools import TTLCache, cached
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from aia_chaser.constants import DEFAULT_URLOPEN_TIMEOUT, DOWNLOAD_CACHE_SIZE
from aia_chaser.exceptions import (
    AiaChaseExhaustedError,
    CertificateDownloadError,
    CertificateParseError,
    InvalidUrlError,
    MissingPeerCertificateError,
    NonGlobalAddressError,
    NoValidAiaCaUrlError,
    RootCertificateNotFoundError,
)
from aia_chaser.utils.cert_utils import (
    certificates_to_der,
    extract_aia_information,
    load_ssl_ca_certificates,
)
from aia_chaser.utils.http_pinning import get_cached_certificate_opener
from aia_chaser.utils.http_utils import RetryConfig, http_urlopen_with_retry
from aia_chaser.utils.network import create_global_unicast_connection
from aia_chaser.utils.url import extract_host_port_from_url, extract_scheme_from_url
from aia_chaser.verify import VerifyCertificatesConfig, verify_certificate_chain


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence


__all__ = ["AiaChaser"]


class AiaChaser:
    """Authority Information Access (AIA) Chaser.

    AIA is part of the X509 standard in RFC 5280. It's objective
    is pointing the client towards an endpoint from which the
    signing certificate can be obtained even if the server does
    not provide the intermediate certificates as part of the
    TLS handshake.

    The chaser object can be later used to generate SSL context
    to access specific hosts after all the intermediate certificates
    have been resolved.

    Args:
        context: Context used internally to request the host's certificate
            during AIA chasing operations. Its loaded CA certificates at
            the time of crating the `AiaChaser` are considered the trusted
            root CAs. If not given a new SSLContext is created with the
            default certificates.
        trusted_cas: Additional trusted CA certificates.
        retry_config: Retry settings for AIA downloads on cache misses. None
            uses defaults (see
            [`RetryConfig`][aia_chaser.utils.http_utils.RetryConfig]).
        allow_private_ip: Whether non-global IP addresses may be used for
            the initial connection, AIA certificate downloads, and OCSP/CRL
            revocation checks. Defaults to True for backwards compatibility;
            this will default to False in v4. When False, non-global DNS
            answers are discarded and the hostname fails only if no global
            addresses remain.
    """

    def __init__(
        self,
        context: ssl.SSLContext | None = None,
        trusted_cas: Sequence[x509.Certificate] | None = None,
        *,
        allow_private_ip: bool = True,
        retry_config: RetryConfig | None = None,
    ) -> None:
        self.allow_private_ip = allow_private_ip
        self.retry_config = retry_config
        trusted_cas = trusted_cas or []

        if context is None:
            # Create context with disabled verification during handshake.
            # This mirrors the old ssl.SSLContext() default behavior.
            # Verification is done separately by aia-chaser after fetching.
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self._context.check_hostname = False
            self._context.verify_mode = ssl.CERT_NONE
        else:
            self._context = context

        # Load trusted certificates
        ssl_trusted_cert = load_ssl_ca_certificates(
            self._context,
            force_load=context is None,
        )

        self._trusted = {ca_cert.subject: ca_cert for ca_cert in ssl_trusted_cert}
        for cert in trusted_cas:
            self.add_trusted_cert(cert)  # self._context and self._trusted must exist

    @property
    def trusted_certificates(self) -> Mapping[x509.Name, x509.Certificate]:
        """Trusted CA certificates indexed by subject name.

        The mapping includes certificates loaded from the SSL context and
        certificates provided through `trusted_cas` or `add_trusted_cert`.

        Returns:
            A mapping from each trusted certificate's subject to the
                certificate.
        """
        return MappingProxyType(self._trusted)

    def add_trusted_cert(self, cert: x509.Certificate) -> None:
        """Trust the provided certificate.

        If the certificate subject already exists in the trusted mapping
        it will not be overwritten.

        Args:
            cert: Certificate to trust.
        """
        if cert.subject not in self._trusted:
            self._context.load_verify_locations(
                cadata=cert.public_bytes(Encoding.DER),
            )
            self._trusted[cert.subject] = cert

    def aia_chase_cert(
        self,
        certificate: x509.Certificate,
    ) -> Iterator[x509.Certificate]:
        """Chase AIA CA information from the provided certificate.

        Args:
            certificate: Start AIA chasing from this certificate.

        Yields:
            The certificates from the certificate chain of
                `certificate`. The first is the provided
                certificate and the last is the root or a
                trusted CA.

        Raises:
            AiaChaseExhaustedError: If all HTTP(S) AIA URLs fail to download,
                parse, or resolve to a usable globally routable address. This
                may happen during iteration, after certificates have already
                been yielded.
        """
        to_process = collections.deque([certificate])
        while True:
            cert = to_process.popleft()
            cert_info = _extract_aia_info(cert)

            # Already trusted & self-signed
            #
            # Running until the end of some chains end up in "ValiCert Class 2
            # Policy Validation Authority", which are not in the system's
            # trusted database:
            # https://security.stackexchange.com/questions/65508/what-is-the-deal-with-valicert-ssl-root-certificates
            #
            # This may happen with other certificate chains thereby we stop
            # the chasing once we find a certificate that we already trust.
            if cert_info.subject in self._trusted:
                yield self._trusted[cert_info.subject]
                break
            if cert_info.subject == cert_info.issuer:
                if cert_info.issuer not in self._trusted:
                    raise RootCertificateNotFoundError(
                        subject=cert_info.issuer.rfc4514_string(),
                    )
                yield self._trusted[cert_info.issuer]
                break

            # Yield and continue AIA chasing
            yield cert

            # Current cert does not have more intermediate CAs
            if not cert_info.aia_ca_issuers:
                # If there are not more certificates the issuer is expected to
                # be in the trusted set.
                if not to_process and cert_info.issuer not in self._trusted:
                    raise RootCertificateNotFoundError(
                        subject=cert_info.issuer.rfc4514_string(),
                    )
                yield self._trusted[cert_info.issuer]
                break

            to_process.extend(
                try_download_certificate(
                    cert_info.aia_ca_issuers,
                    allow_private_ip=self.allow_private_ip,
                    retry_config=self.retry_config,
                ),
            )

    def aia_chase(
        self,
        host: str,
        port: int = 443,
    ) -> Iterator[x509.Certificate]:
        """Chase AIA CA information starting from the `host`'s certificate.

        Args:
            host: Host to get the initial certificate.
            port: Port on host to connect and retrieve the initial
                certificate.

        Yields:
            The certificates from the certificate chain of the
                host's certificate. The first is the host's
                certificate and the last is the root or a
                trusted CA.

        Raises:
            NonGlobalAddressError: If private IP addresses are disallowed and
                the initial host has no globally routable address.
            AiaChaseExhaustedError: If all HTTP(S) AIA URLs fail to download,
                parse, or resolve to a usable globally routable address.
                AIA URLs are tried in order until one succeeds or all fail.
        """
        cert = self.fetch_host_cert(host=host, port=port)
        yield from self.aia_chase_cert(certificate=cert)

    def fetch_host_cert(self, host: str, port: int = 443) -> x509.Certificate:
        """Get the host, port pair certificate.

        Args:
            host: Host to retrieve the certificate for.
            port: Port on host to connect and retrieve the certificate.

        Returns:
            The certificate of the (host, port) pair.

        Raises:
            MissingPeerCertificateError: If it is not possible to retrieve
                the certificate of the `host`.
            NonGlobalAddressError: If `allow_private_ip` is False and the host
                has no globally routable IP addresses.
        """
        with contextlib.ExitStack() as ctx:
            if self.allow_private_ip:
                sock = socket.create_connection((host, port))
            else:
                sock = create_global_unicast_connection(host, port)
            sock = ctx.enter_context(sock)
            s_sock = ctx.enter_context(
                self._context.wrap_socket(
                    sock,
                    server_hostname=host,
                ),
            )

            # Get initial, possibly incomplete, chain from peer once the
            # functionality is supported by ssl module
            # https://www.openssl.org/docs/man1.0.2/man3/SSL_get_peer_cert_chain.html
            der_cert = s_sock.getpeercert(True)  # noqa: FBT003
            if der_cert is not None:
                return x509.load_der_x509_certificate(der_cert)

        raise MissingPeerCertificateError(host=host, port=port)

    def fetch_cert_chain_for_host(
        self,
        host: str,
        port: int = 443,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> list[x509.Certificate]:
        """Fetch the certificate chain for a given host.

        Retrieves the certificate chain for a specified host and port.
        Optionally verifies the chain against a trusted certificate store.

        Args:
            host: The hostname to fetch the certificate chain for.
            port: The port to connect to. Defaults to 443.
            verify_config: Configuration for verifying the certificate chain.
                If None, a default configuration inherits the chaser's IP
                policy. A chaser with allow_private_ip=False always enforces
                that policy, even if this configuration explicitly sets
                allow_private_ip=True. The supplied configuration is not mutated.
            verify: Whether to verify the certificate chain. Defaults to True.

        Returns:
            The fetched certificate chain, optionally verified.

        Raises:
            exceptions.CertificateChainError: If the certificate chain fails
                verification.
            exceptions.MissingPeerCertificateError: If it is not possible to
                retrieve the certificate of the `host`.
        """
        certificates = list(self.aia_chase(host, port))
        if verify:
            config = verify_config or VerifyCertificatesConfig(
                allow_private_ip=self.allow_private_ip,
            )
            # Enforce strict policy: if the chaser disallows private IPs,
            # verification must not silently permit them via a config default.
            if not self.allow_private_ip and config.allow_private_ip:
                config = dataclasses.replace(config, allow_private_ip=False)
            verify_certificate_chain(
                certificates=certificates,
                trusted=self._trusted,
                config=config,
            )
        return certificates

    def fetch_ca_chain_for_host(
        self,
        host: str,
        port: int = 443,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> list[x509.Certificate]:
        """Fetch the CA certificate chain for a given host.

        Same as
        [`fetch_cert_chain_for_host`][aia_chaser.AiaChaser.fetch_cert_chain_for_host]
        excluding the host's certificate.

        Args:
            host: The hostname to fetch the CA certificate chain for.
            port: The port to connect to. Defaults to 443.
            verify_config: Configuration for verifying the certificate chain.
                If None, a default configuration inherits the chaser's IP
                policy. A chaser with allow_private_ip=False always enforces
                that policy, even if this configuration explicitly sets
                allow_private_ip=True. The supplied configuration is not mutated.
            verify: Whether to verify the CA certificate chain. Defaults to True.

        Returns:
            The fetched CA certificate chain (host excluded), optionally verified.

        Raises:
            exceptions.CertificateChainError: If the certificate chain fails
                verification.
            exceptions.MissingPeerCertificateError: If it is not possible to
                retrieve the certificate of the `host`.
        """
        return self.fetch_cert_chain_for_host(
            host,
            port,
            verify_config=verify_config,
            verify=verify,
        )[:1]

    def fetch_cert_chain_for_url(
        self,
        url_string: str,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> list[x509.Certificate]:
        """Fetch the certificate chain for a given host.

        Same as `fetch_cert_chain_for_host` but the host name and port
        are obtained from the `url_string`

        Args:
            url_string: URL to fetch the certificate chain for.
            verify_config: Configuration for verifying the certificate chain.
                If None, a default configuration inherits the chaser's IP
                policy. A chaser with allow_private_ip=False always enforces
                that policy, even if this configuration explicitly sets
                allow_private_ip=True. The supplied configuration is not mutated.
            verify: Whether to verify the certificate chain. Defaults to True.

        Returns:
            The fetched certificate chain, optionally verified.

        Raises:
            exceptions.CertificateChainError: If the certificate chain fails
                verification.
            exceptions.MissingPeerCertificateError: If it is not possible to
                retrieve the certificate of the host.
        """
        host, port = extract_host_port_from_url(url_string)
        return self.fetch_cert_chain_for_host(
            host=host,
            port=port,
            verify_config=verify_config,
            verify=verify,
        )

    def fetch_ca_chain_for_url(
        self,
        url_string: str,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> list[x509.Certificate]:
        """Fetch the CA certificate chain for a given host.

        Same as `fetch_cert_chain_for_url` excluding the host's
        certificate.

        Args:
            url_string: URL to fetch the CA certificate chain for.
            verify_config: Configuration for verifying the certificate chain.
                If None, a default configuration inherits the chaser's IP
                policy. A chaser with allow_private_ip=False always enforces
                that policy, even if this configuration explicitly sets
                allow_private_ip=True. The supplied configuration is not mutated.
            verify: Whether to verify the CA certificate chain. Defaults to True.

        Returns:
            The fetched CA certificate chain, optionally verified.

        Raises:
            exceptions.CertificateChainError: If the certificate chain fails
                verification.
            exceptions.MissingPeerCertificateError: If it is not possible to
                retrieve the certificate of the host.
        """
        return self.fetch_cert_chain_for_url(
            url_string=url_string,
            verify_config=verify_config,
            verify=verify,
        )

    def make_ssl_context_for_host(
        self,
        host: str,
        port: int = 443,
        purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> ssl.SSLContext:
        """Create a new SSL context and add certificate chain for host.

        See Also:
            fetch_ca_chain_for_host: Method used to retrieve and optionally
                verify the CA chain to add to the SSL context.
        """
        context = ssl.create_default_context(purpose=purpose)
        self.add_host_ca_chain_to_context(
            context,
            host,
            port,
            verify_config=verify_config,
            verify=verify,
        )
        return context

    def make_ssl_context_for_url(
        self,
        url_string: str,
        purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> ssl.SSLContext:
        """Create a new SSL context and add certificate chain for URL.

        See Also:
            fetch_ca_chain_for_url: Method used to retrieve and optionally
                verify the CA chain to add to the SSL context.
        """
        context = ssl.create_default_context(purpose=purpose)
        self.add_url_ca_chain_to_context(
            context,
            url_string=url_string,
            verify_config=verify_config,
            verify=verify,
        )
        return context

    def add_host_ca_chain_to_context(
        self,
        context: ssl.SSLContext,
        host: str,
        port: int = 443,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> None:
        """Add host CA chain to SSL context.

        See Also:
            fetch_ca_chain_for_host: Method used to retrieve and optionally
                verify the CA chain to add to the SSL context.
        """
        certificates = self.fetch_ca_chain_for_host(
            host,
            port,
            verify_config=verify_config,
            verify=verify,
        )
        context.load_verify_locations(cadata=certificates_to_der(certificates))

    def add_url_ca_chain_to_context(
        self,
        context: ssl.SSLContext,
        url_string: str,
        verify_config: VerifyCertificatesConfig | None = None,
        *,
        verify: bool = True,
    ) -> None:
        """Add CA chain to URL's host to SSL context.

        See Also:
            fetch_ca_chain_for_host: Method used to retrieve and optionally
                verify the CA chain to add to the SSL context.
        """
        certificates = self.fetch_ca_chain_for_url(
            url_string,
            verify_config=verify_config,
            verify=verify,
        )
        context.load_verify_locations(cadata=certificates_to_der(certificates))


def try_download_certificate(
    urls: Sequence[str],
    *,
    allow_private_ip: bool = True,
    retry_config: RetryConfig | None = None,
) -> list[x509.Certificate]:
    """Try AIA URLs until one downloads and parses successfully.

    Non-global DNS answers are filtered out. If a URL has no globally
    routable answers, its address-policy error is recorded and the next URL
    is tried.

    Args:
        urls: AIA certificate URLs to try in order.
        retry_config: Retry settings for cache misses. None uses defaults (see
            [`RetryConfig`][aia_chaser.utils.http_utils.RetryConfig]).
        allow_private_ip: Whether downloads may connect to non-global IP
            addresses. If False, non-global DNS answers are skipped.
    """
    http_urls = [url for url in urls if url.lower().startswith(("http:", "https:"))]
    if not http_urls:
        raise NoValidAiaCaUrlError(urls=urls)

    errors = []
    for http_url in http_urls:
        try:
            return _download_certificate(
                http_url,
                allow_private_ip=allow_private_ip,
                retry_config=retry_config,
            )
        except (  # noqa: PERF203
            CertificateDownloadError,
            CertificateParseError,
            NonGlobalAddressError,
            InvalidUrlError,
        ) as err:
            errors.append(err)

    raise AiaChaseExhaustedError(errors=errors)


@cached(
    cache=TTLCache(
        maxsize=DOWNLOAD_CACHE_SIZE,
        ttl=12 * 60 * 60,
    ),
    key=lambda url_string, *, allow_private_ip=True, **_kwargs: (
        url_string,
        allow_private_ip,
    ),
    lock=RLock(),
)
def _download_certificate(
    url_string: str,
    *,
    allow_private_ip: bool = True,
    retry_config: RetryConfig | None = None,
) -> list[x509.Certificate]:
    """Download and parse X.509 certificates from an AIA URL.

    Successful results are cached by URL and private IP policy for 12 hours.
    Cache hits do not perform network requests or reapply the address policy.

    Args:
        url_string: URL pointing to the certificate to download.
        retry_config: Retry settings for cache misses, excluded from the cache
            key.
        allow_private_ip: Whether non-global IP addresses may be used.
            Also partitions the cache by address policy.

    Returns:
        A list of parsed X.509 certificates.

    Raises:
        CertificateDownloadError: If the download fails, or the certificate
            data cannot be parsed.
        InvalidUrlError: If the URL scheme is unsupported or the URL is
            malformed.
        NonGlobalAddressError: If the configured opener rejects the URL host
            because it resolves to a non-global address.
    """
    opener = get_cached_certificate_opener(allow_private_ip=allow_private_ip)
    scheme = extract_scheme_from_url(url_string)
    if scheme == "https":
        warnings.warn(
            "Trying to download an intermediate CA certificate using HTTPS",
            category=UserWarning,
            stacklevel=2,
        )

    try:
        with http_urlopen_with_retry(
            url_string,
            timeout=DEFAULT_URLOPEN_TIMEOUT,
            opener=opener,
            retry_config=retry_config,
        ) as response:
            if response.status != http.HTTPStatus.OK:
                raise CertificateDownloadError(
                    message=f"could not download {url_string}",
                    url_string=url_string,
                )
            content = response.read()
    except (URLError, http.client.HTTPException, OSError) as err:
        raise CertificateDownloadError(
            message=f"could not download {url_string}: {err}",
            url_string=url_string,
        ) from err

    try:
        return _try_parse_certificate(content)
    except CertificateParseError as err:
        raise CertificateDownloadError(
            message=str(err),
            url_string=url_string,
        ) from None


def _wrap_single_cert_parser(
    parser_func: Callable[[bytes], x509.Certificate],
) -> Callable[[bytes], list[x509.Certificate]]:
    def wrapper(data: bytes) -> list[x509.Certificate]:
        return [parser_func(data)]

    return wrapper


_CERT_PARSE_FNS = (
    _wrap_single_cert_parser(x509.load_der_x509_certificate),
    _wrap_single_cert_parser(x509.load_pem_x509_certificate),
    pkcs7.load_der_pkcs7_certificates,
    pkcs7.load_pem_pkcs7_certificates,
)


def _try_parse_certificate(data: bytes) -> list[x509.Certificate]:
    exceptions = []
    for parse_fn in _CERT_PARSE_FNS:
        try:
            return parse_fn(data)
        except (ValueError, TypeError) as err:  # noqa: PERF203
            exceptions.append(err)

    raise CertificateParseError(reasons=[str(err) for err in exceptions])


class _CertificateAiaInfo(NamedTuple):
    """Simpler format to work with  certificate info."""

    subject: x509.Name
    issuer: x509.Name
    aia_ca_issuers: list[str]
    aia_ocsp_urls: list[str]


def _extract_aia_info(x509_certificate: x509.Certificate) -> _CertificateAiaInfo:
    aia_info = extract_aia_information(x509_certificate)
    return _CertificateAiaInfo(
        subject=x509_certificate.subject,
        issuer=x509_certificate.issuer,
        aia_ca_issuers=aia_info.ca_issuers,
        aia_ocsp_urls=aia_info.ocsp_urls,
    )

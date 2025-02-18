import pytest

from aia_chaser import AiaChaser, VerifyCertificatesConfig
from aia_chaser.exceptions import (
    CertificateChainError,
    CertificateExpiredError,
    OcspRevokedStatusError,
)


@pytest.mark.parametrize(
    "url_string",
    [
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
    ],
)
def test_aia_chase_url_ok(url_string: str) -> None:
    chaser = AiaChaser()
    chain = chaser.fetch_cert_chain_for_url(url_string=url_string)
    # on Windows microsoft.com certificate is trusted resulting
    # in a chain of length 1 ¯\_(ツ)_/¯
    assert len(chain) >= 1


@pytest.mark.parametrize(
    "url_string",
    [
        "www.siemens.com",
        "www.microsoft.com",
        "www.amazon.com",
        "www.google.com",
        "www.segre.com",
        "www.nytimes.com",
    ],
)
def test_aia_chase_url_no_scheme(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(ValueError):  # noqa: PT011
        chaser.fetch_ca_chain_for_url(url_string=url_string)


EXPIRED_URLS = (
    "https://expired.badssl.com/",
    "https://expired-rsa-dv.ssl.com/",
    "https://expired-rsa-ev.ssl.com/",
    "https://expired-ecc-dv.ssl.com/",
    "https://expired-ecc-ev.ssl.com/",
)


@pytest.mark.parametrize(
    "url_string",
    EXPIRED_URLS,
)
def test_aia_chase_url_expired(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(CertificateChainError) as exc_info:
        chaser.fetch_ca_chain_for_url(url_string=url_string)
    assert type(exc_info.value.reason) is CertificateExpiredError


@pytest.mark.parametrize(
    "url_string",
    EXPIRED_URLS,
)
def test_aia_chase_url_ignore_expired(url_string: str) -> None:
    chaser = AiaChaser()
    chain = chaser.fetch_ca_chain_for_url(url_string=url_string, verify=False)
    assert len(chain) >= 1


REVOKED_URLS = (
    "https://revoked.badssl.com/",
    "https://revoked.grc.com/",
    "https://revoked-rsa-dv.ssl.com/",
    "https://revoked-rsa-ev.ssl.com/",
    "https://revoked-ecc-dv.ssl.com/",
    "https://revoked-ecc-ev.ssl.com/",
)


@pytest.mark.parametrize(
    "url_string",
    REVOKED_URLS,
)
def test_aia_chase_url_ocsp_revoked(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(CertificateChainError) as exc_info:
        chaser.fetch_ca_chain_for_url(url_string=url_string)
    assert type(exc_info.value.reason) is OcspRevokedStatusError


@pytest.mark.parametrize(
    "url_string",
    REVOKED_URLS,
)
def test_aia_chase_url_ignore_ocsp_revoked(url_string: str) -> None:
    chaser = AiaChaser()
    chain = chaser.fetch_ca_chain_for_url(
        url_string=url_string,
        verify_config=VerifyCertificatesConfig(
            ocsp_enabled=False,
        ),
    )
    assert len(chain) >= 1

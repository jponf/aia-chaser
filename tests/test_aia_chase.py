import pytest

from aia_chaser import AiaChaser


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
def test_aia_chase_url(url_string: str) -> None:
    chaser = AiaChaser()
    chain = chaser.fetch_ca_chain_for_url(url_string=url_string)
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

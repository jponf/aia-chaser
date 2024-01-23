import pytest

from aia_chaser import AiaChaser


@pytest.mark.parametrize(
    "url_string",
    [
        "https://www.siemens.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://www.google.com",
    ],
)
def test_aia_chase_url(url_string: str) -> None:
    chaser = AiaChaser()
    chain = chaser.fetch_ca_chain_for_url(url_string=url_string)
    assert len(chain) > 1


@pytest.mark.parametrize(
    "url_string",
    [
        "www.siemens.com",
        "www.microsoft.com",
        "www.amazon.com",
        "www.google.com",
    ],
)
def test_aia_chase_url_no_scheme(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(ValueError):
        chaser.fetch_ca_chain_for_url(url_string=url_string)

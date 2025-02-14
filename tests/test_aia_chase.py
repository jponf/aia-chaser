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
    ],
)
def test_aia_chase_url_no_scheme(url_string: str) -> None:
    chaser = AiaChaser()
    with pytest.raises(ValueError):  # noqa: PT011
        chaser.fetch_ca_chain_for_url(url_string=url_string)

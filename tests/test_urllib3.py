"""Tests for urllib3 library integration."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING

import pytest
import urllib3

from .conftest import TEST_URLS_SUBSET


if TYPE_CHECKING:
    from aia_chaser import AiaChaser


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_urllib3_with_ssl_context(url_string: str, chaser: AiaChaser) -> None:
    context = chaser.make_ssl_context_for_url(url_string)

    with urllib3.PoolManager(ssl_context=context) as pool:
        response = pool.request("GET", url_string)

    assert response.status == HTTPStatus.OK

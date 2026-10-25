"""Tests for urllib (standard library) integration."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING
from urllib.request import urlopen

import pytest

from .conftest import TEST_URLS_SUBSET


if TYPE_CHECKING:
    from aia_chaser import AiaChaser


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
def test_urlopen_with_ssl_context(url_string: str, chaser: AiaChaser) -> None:
    context = chaser.make_ssl_context_for_url(url_string)
    response = urlopen(url_string, context=context)  # noqa: S310

    assert response.status == HTTPStatus.OK

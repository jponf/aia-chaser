"""Tests for aiohttp library integration."""

from http import HTTPStatus

import aiohttp
import pytest

from aia_chaser import AiaChaser

from .conftest import TEST_URLS_SUBSET


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
@pytest.mark.asyncio
async def test_aiohttp_with_ssl_context(url_string: str) -> None:
    chaser = AiaChaser()
    context = chaser.make_ssl_context_for_url(url_string)

    async with (
        aiohttp.ClientSession() as session,
        session.get(url_string, ssl=context) as response,
    ):
        assert response.status == HTTPStatus.OK

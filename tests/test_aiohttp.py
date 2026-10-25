"""Tests for aiohttp library integration."""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING

import aiohttp
import pytest

from .conftest import TEST_URLS_SUBSET


if TYPE_CHECKING:
    from aia_chaser import AiaChaser


@pytest.mark.parametrize("url_string", TEST_URLS_SUBSET)
@pytest.mark.asyncio
async def test_aiohttp_with_ssl_context(url_string: str, chaser: AiaChaser) -> None:
    context = chaser.make_ssl_context_for_url(url_string)

    async with (
        aiohttp.ClientSession(max_line_size=65536, max_field_size=65536) as session,
        session.get(url_string, ssl=context) as response,
    ):
        assert response.status == HTTPStatus.OK

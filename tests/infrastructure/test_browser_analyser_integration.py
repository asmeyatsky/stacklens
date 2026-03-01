"""Integration test — requires real Playwright + Chromium."""

import pytest

from stacklens.domain.models.browser import BrowserResult
from stacklens.domain.models.target import AnalysisTarget
from stacklens.infrastructure.analysers.browser_analyser import BrowserAnalyser


@pytest.mark.slow
@pytest.mark.asyncio
async def test_browser_analyser_against_example_com():
    analyser = BrowserAnalyser()
    target = AnalysisTarget.from_url("https://example.com")
    result = await analyser.analyse(target)

    assert isinstance(result, BrowserResult)
    assert result.final_url  # should have navigated somewhere
    assert result.elapsed_ms > 0
    assert result.dom.total_elements > 0
    assert result.page_title  # example.com has a title
    assert result.network.total_requests >= 1  # at least the document itself

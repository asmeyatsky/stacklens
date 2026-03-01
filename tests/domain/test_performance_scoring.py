"""Tests for the performance scoring service."""

from __future__ import annotations

from stacklens.domain.models.browser import (
    BrowserResult,
    NetworkSummary,
    PerformanceMetrics,
)
from stacklens.domain.services.performance_scoring import (
    _grade_from_score,
    score_performance,
)


def _browser(
    ttfb_ms: float | None = None,
    fcp_ms: float | None = None,
    lcp_ms: float | None = None,
    cls: float | None = None,
    tbt_ms: float | None = None,
    total_requests: int = 0,
    third_party_requests: int = 0,
    total_transfer_bytes: int = 0,
    resource_breakdown: dict[str, int] | None = None,
    render_blocking_count: int = 0,
    total_page_weight_bytes: int = 0,
) -> BrowserResult:
    return BrowserResult(
        network=NetworkSummary(
            total_requests=total_requests,
            third_party_requests=third_party_requests,
            total_transfer_bytes=total_transfer_bytes,
        ),
        performance=PerformanceMetrics(
            ttfb_ms=ttfb_ms,
            fcp_ms=fcp_ms,
            lcp_ms=lcp_ms,
            cls=cls,
            tbt_ms=tbt_ms,
            render_blocking_count=render_blocking_count,
            resource_breakdown=resource_breakdown or {},
            total_page_weight_bytes=total_page_weight_bytes,
        ),
    )


class TestGradeFromScore:
    def test_a_grade(self) -> None:
        assert _grade_from_score(90) == "A"
        assert _grade_from_score(100) == "A"

    def test_b_grade(self) -> None:
        assert _grade_from_score(75) == "B"
        assert _grade_from_score(89) == "B"

    def test_c_grade(self) -> None:
        assert _grade_from_score(50) == "C"
        assert _grade_from_score(74) == "C"

    def test_d_grade(self) -> None:
        assert _grade_from_score(25) == "D"
        assert _grade_from_score(49) == "D"

    def test_f_grade(self) -> None:
        assert _grade_from_score(0) == "F"
        assert _grade_from_score(24) == "F"


class TestAllGoodMetrics:
    def test_score_at_least_90(self) -> None:
        result = score_performance(_browser(
            ttfb_ms=200, fcp_ms=500, lcp_ms=1000, cls=0.02, tbt_ms=50,
        ))
        assert result.overall_score >= 90
        assert result.grade == "A"

    def test_all_metrics_rated_good(self) -> None:
        result = score_performance(_browser(
            ttfb_ms=200, fcp_ms=500, lcp_ms=1000, cls=0.02, tbt_ms=50,
        ))
        for m in result.metrics:
            assert m.rating == "good"
            assert m.score == 100


class TestAllPoorMetrics:
    def test_score_below_30(self) -> None:
        result = score_performance(_browser(
            ttfb_ms=5000, fcp_ms=8000, lcp_ms=10000, cls=0.8, tbt_ms=2000,
        ))
        assert result.overall_score < 30
        assert result.grade in ("D", "F")

    def test_all_metrics_rated_poor(self) -> None:
        result = score_performance(_browser(
            ttfb_ms=5000, fcp_ms=8000, lcp_ms=10000, cls=0.8, tbt_ms=2000,
        ))
        for m in result.metrics:
            assert m.rating == "poor"


class TestMissingMetrics:
    def test_partial_metrics_scored_on_available(self) -> None:
        # Only LCP and FCP provided, both good
        result = score_performance(_browser(lcp_ms=1000, fcp_ms=500))
        assert result.overall_score >= 90
        assert result.grade == "A"

    def test_missing_metrics_rated_unknown(self) -> None:
        result = score_performance(_browser(lcp_ms=1000))
        unknown = [m for m in result.metrics if m.rating == "unknown"]
        assert len(unknown) == 4  # CLS, TBT, FCP, TTFB

    def test_no_metrics_at_all(self) -> None:
        result = score_performance(_browser())
        assert result.overall_score == 0
        assert result.grade == "F"


class TestThirdPartyRatio:
    def test_ratio_calculated(self) -> None:
        result = score_performance(_browser(
            lcp_ms=1000,
            total_requests=100,
            third_party_requests=40,
        ))
        assert abs(result.third_party_ratio - 0.4) < 0.01

    def test_zero_requests(self) -> None:
        result = score_performance(_browser(lcp_ms=1000))
        assert result.third_party_ratio == 0.0


class TestResourceBreakdown:
    def test_passthrough(self) -> None:
        breakdown = {"script": 150000, "image": 80000}
        result = score_performance(_browser(
            lcp_ms=1000,
            resource_breakdown=breakdown,
        ))
        assert result.resource_breakdown == breakdown


class TestNetworkStats:
    def test_transfer_bytes_and_requests(self) -> None:
        result = score_performance(_browser(
            lcp_ms=1000,
            total_requests=50,
            total_transfer_bytes=2_000_000,
            render_blocking_count=3,
            total_page_weight_bytes=3_000_000,
        ))
        assert result.total_requests == 50
        assert result.total_transfer_bytes == 2_000_000
        assert result.render_blocking_count == 3
        assert result.page_weight_bytes == 3_000_000


class TestMetricDisplay:
    def test_ms_format(self) -> None:
        result = score_performance(_browser(lcp_ms=2500))
        lcp = next(m for m in result.metrics if m.name == "LCP")
        assert lcp.display == "2500ms"

    def test_cls_format(self) -> None:
        result = score_performance(_browser(cls=0.08))
        cls_metric = next(m for m in result.metrics if m.name == "CLS")
        assert cls_metric.display == "0.080"

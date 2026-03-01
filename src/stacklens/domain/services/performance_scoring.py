from __future__ import annotations

from stacklens.domain.models.browser import BrowserResult
from stacklens.domain.models.performance import MetricScore, PerformanceScore

# Thresholds: (good_upper, needs_improvement_upper)
# Score: good → 100, linearly down to needs-improvement → 50, linearly down to poor → 0
_THRESHOLDS: dict[str, tuple[float, float, float]] = {
    # name: (good, needs_improvement, weight)
    "LCP": (2500.0, 4000.0, 0.25),
    "CLS": (0.10, 0.25, 0.25),
    "TBT": (200.0, 600.0, 0.30),
    "FCP": (1800.0, 3000.0, 0.10),
    "TTFB": (800.0, 1800.0, 0.10),
}


def _score_metric(value: float, good: float, needs_imp: float) -> tuple[int, str]:
    """Return (score 0-100, rating) for a single metric value."""
    if value <= good:
        score = 100
        rating = "good"
    elif value <= needs_imp:
        # Linear interpolation from 100 at good to 50 at needs_imp
        ratio = (value - good) / (needs_imp - good)
        score = int(100 - ratio * 50)
        rating = "needs-improvement"
    else:
        # Linear interpolation from 50 at needs_imp toward 0
        # Use same range width for the poor zone
        poor_range = needs_imp - good
        if poor_range > 0:
            ratio = min((value - needs_imp) / poor_range, 1.0)
        else:
            ratio = 1.0
        score = int(50 - ratio * 50)
        rating = "poor"
    return max(0, min(100, score)), rating


def _format_metric(name: str, value: float) -> str:
    if name == "CLS":
        return f"{value:.3f}"
    return f"{value:.0f}ms"


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "F"


def score_performance(browser: BrowserResult) -> PerformanceScore:
    perf = browser.performance
    net = browser.network

    # Map metric names to their values
    raw_values: dict[str, float | None] = {
        "LCP": perf.lcp_ms,
        "CLS": perf.cls,
        "TBT": perf.tbt_ms,
        "FCP": perf.fcp_ms,
        "TTFB": perf.ttfb_ms,
    }

    metric_scores: list[MetricScore] = []
    weighted_sum = 0.0
    total_weight = 0.0

    for name, (good, needs_imp, weight) in _THRESHOLDS.items():
        value = raw_values.get(name)
        if value is None:
            metric_scores.append(MetricScore(
                name=name,
                value=None,
                score=0,
                rating="unknown",
                display="—",
            ))
            continue

        score, rating = _score_metric(value, good, needs_imp)
        metric_scores.append(MetricScore(
            name=name,
            value=value,
            score=score,
            rating=rating,
            display=_format_metric(name, value),
        ))
        weighted_sum += score * weight
        total_weight += weight

    overall = int(weighted_sum / total_weight) if total_weight > 0 else 0
    grade = _grade_from_score(overall)

    # Third-party ratio
    total_req = net.total_requests
    third_party_ratio = (
        net.third_party_requests / total_req if total_req > 0 else 0.0
    )

    return PerformanceScore(
        overall_score=overall,
        grade=grade,
        metrics=metric_scores,
        resource_breakdown=dict(perf.resource_breakdown),
        third_party_ratio=third_party_ratio,
        total_requests=net.total_requests,
        total_transfer_bytes=net.total_transfer_bytes,
        render_blocking_count=perf.render_blocking_count,
        page_weight_bytes=perf.total_page_weight_bytes,
    )

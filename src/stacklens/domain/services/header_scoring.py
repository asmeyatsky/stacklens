from __future__ import annotations

from stacklens.domain.models.headers import SecurityHeader

RATING_WEIGHTS: dict[str, float] = {
    "good": 1.0,
    "warning": 0.5,
    "missing": 0.0,
}


def score_security_headers(headers: list[SecurityHeader]) -> float:
    """Pure function: average score across all checked security headers."""
    if not headers:
        return 0.0
    total = sum(RATING_WEIGHTS.get(h.rating, 0.0) for h in headers)
    return round(total / len(headers), 2)

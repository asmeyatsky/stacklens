from __future__ import annotations

from urllib.parse import urlparse

from pydantic import BaseModel, model_validator


class AnalysisTarget(BaseModel, frozen=True):
    """Value object representing the URL to analyse."""

    url: str
    scheme: str
    hostname: str
    port: int

    @model_validator(mode="before")
    @classmethod
    def _parse_url(cls, values: dict) -> dict:
        if "hostname" in values:
            return values
        raw = values.get("url", "")
        if not raw.startswith(("http://", "https://")):
            raw = f"https://{raw}"
        parsed = urlparse(raw)
        if not parsed.hostname:
            raise ValueError(f"Cannot parse hostname from URL: {values.get('url')}")
        scheme = parsed.scheme or "https"
        port = parsed.port or (443 if scheme == "https" else 80)
        return {
            "url": raw,
            "scheme": scheme,
            "hostname": parsed.hostname,
            "port": port,
        }

    @classmethod
    def from_url(cls, url: str) -> AnalysisTarget:
        return cls(url=url)

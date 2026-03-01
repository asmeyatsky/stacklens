from __future__ import annotations

from pydantic import BaseModel, Field


class DnsRecord(BaseModel, frozen=True):
    record_type: str
    name: str
    value: str
    ttl: int | None = None


class DnsResult(BaseModel, frozen=True):
    records: list[DnsRecord] = Field(default_factory=list)
    nameservers: list[str] = Field(default_factory=list)
    resolved_ips: list[str] = Field(default_factory=list)
    cdn_detected: str | None = None

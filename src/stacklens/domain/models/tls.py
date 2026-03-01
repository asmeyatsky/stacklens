from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class TlsCertificate(BaseModel, frozen=True):
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    san: list[str] = []


class TlsResult(BaseModel, frozen=True):
    protocol: str
    cipher: str
    certificate: TlsCertificate | None = None
    days_until_expiry: int | None = None
    hsts: bool = False

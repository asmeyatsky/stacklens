from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone

from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.models.tls import TlsCertificate, TlsResult


class TlsAnalyser:
    @property
    def name(self) -> str:
        return "tls"

    @property
    def depends_on(self) -> list[str]:
        return []

    async def analyse(self, target: AnalysisTarget) -> TlsResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._connect, target)

    def _connect(self, target: AnalysisTarget) -> TlsResult:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            __import__("socket").create_connection((target.hostname, target.port), timeout=10),
            server_hostname=target.hostname,
        ) as sock:
            cert = sock.getpeercert()
            cipher_info = sock.cipher()
            version = sock.version() or "unknown"

        certificate = self._parse_cert(cert) if cert else None
        days_until_expiry = None
        if certificate:
            delta = certificate.not_after - datetime.now(timezone.utc)
            days_until_expiry = delta.days

        return TlsResult(
            protocol=version,
            cipher=cipher_info[0] if cipher_info else "unknown",
            certificate=certificate,
            days_until_expiry=days_until_expiry,
        )

    @staticmethod
    def _parse_cert(cert: dict) -> TlsCertificate:
        def _field(tuples: tuple, key: str) -> str:
            for item in tuples:
                for k, v in item:
                    if k == key:
                        return v
            return "unknown"

        subject = _field(cert.get("subject", ()), "commonName")
        issuer = _field(cert.get("issuer", ()), "organizationName")

        not_before = datetime.strptime(
            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        san = [
            value
            for typ, value in cert.get("subjectAltName", ())
            if typ == "DNS"
        ]

        return TlsCertificate(
            subject=subject,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            serial_number=cert.get("serialNumber", "unknown"),
            san=san,
        )

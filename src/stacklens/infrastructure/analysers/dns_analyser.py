from __future__ import annotations

import asyncio

import dns.resolver

from stacklens.domain.models.dns import DnsRecord, DnsResult
from stacklens.domain.models.target import AnalysisTarget

CDN_CNAME_PATTERNS: dict[str, str] = {
    "cloudfront.net": "Amazon CloudFront",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "edgecastcdn": "Edgecast",
    "azureedge.net": "Azure CDN",
    "googleapis.com": "Google Cloud CDN",
}

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]


class DnsAnalyser:
    @property
    def name(self) -> str:
        return "dns"

    @property
    def depends_on(self) -> list[str]:
        return []

    async def analyse(self, target: AnalysisTarget) -> DnsResult:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10

        tasks = [self._query(resolver, target.hostname, rt) for rt in RECORD_TYPES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_records: list[DnsRecord] = []
        resolved_ips: list[str] = []
        nameservers: list[str] = []
        cdn_detected: str | None = None

        for rt, result in zip(RECORD_TYPES, results):
            if isinstance(result, Exception):
                continue
            for record in result:
                all_records.append(record)
                if rt in ("A", "AAAA"):
                    resolved_ips.append(record.value)
                elif rt == "NS":
                    nameservers.append(record.value)
                elif rt == "CNAME" and not cdn_detected:
                    cdn_detected = self._detect_cdn(record.value)

        return DnsResult(
            records=all_records,
            nameservers=nameservers,
            resolved_ips=resolved_ips,
            cdn_detected=cdn_detected,
        )

    async def _query(
        self,
        resolver: dns.resolver.Resolver,
        hostname: str,
        record_type: str,
    ) -> list[DnsRecord]:
        loop = asyncio.get_running_loop()
        try:
            answer = await loop.run_in_executor(
                None, lambda: resolver.resolve(hostname, record_type)
            )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return []
        return [
            DnsRecord(
                record_type=record_type,
                name=hostname,
                value=str(rdata),
                ttl=answer.rrset.ttl if answer.rrset else None,
            )
            for rdata in answer
        ]

    @staticmethod
    def _detect_cdn(cname_value: str) -> str | None:
        lower = cname_value.lower()
        for pattern, cdn_name in CDN_CNAME_PATTERNS.items():
            if pattern in lower:
                return cdn_name
        return None

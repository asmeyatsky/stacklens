from __future__ import annotations

import asyncio
import re
import socket

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

# ── NS pattern → DNS hosting provider ────────────────────────────────
_NS_PROVIDERS: list[tuple[str, str]] = [
    ("awsdns", "AWS Route53"),
    ("googledomains", "Google Domains"),
    ("google", "Google Cloud DNS"),
    ("azure-dns", "Azure DNS"),
    ("ns.cloudflare", "Cloudflare DNS"),
    ("cloudflare", "Cloudflare DNS"),
    ("domaincontrol.com", "GoDaddy"),
    ("registrar-servers.com", "Namecheap"),
    ("nsone.net", "NS1"),
    ("dnsimple.com", "DNSimple"),
]

# ── SPF include → service name ────────────────────────────────────────
_SPF_SERVICES: dict[str, str] = {
    "amazonses.com": "AWS SES",
    "_spf.google.com": "Google",
    "google.com": "Google",
    "spf.protection.outlook.com": "Microsoft 365",
    "sendgrid.net": "SendGrid",
    "servers.mcsv.net": "Mailchimp",
    "spf.mandrillapp.com": "Mandrill",
    "mail.zendesk.com": "Zendesk",
    "salesforce.com": "Salesforce",
    "spf.messagelabs.com": "Symantec",
    "mailgun.org": "Mailgun",
    "spf1.hubspot.com": "HubSpot",
    "freshdesk.com": "Freshdesk",
}

# ── MX pattern → email provider ──────────────────────────────────────
_MX_PROVIDERS: list[tuple[str, str]] = [
    ("aspmx.l.google.com", "Google Workspace"),
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("mailgun.org", "Mailgun"),
    ("messagelabs.com", "Symantec"),
    ("zoho.com", "Zoho Mail"),
]

# ── TXT record service verifications ─────────────────────────────────
_TXT_SERVICES: list[tuple[str, str]] = [
    ("facebook-domain-verification", "Facebook"),
    ("apple-domain-verification", "Apple"),
    ("atlassian-domain-verification", "Atlassian"),
    ("docker-verification", "Docker"),
    ("google-site-verification", "Google"),
    ("ms=", "Microsoft"),
    ("v=DMARC", "DMARC"),
    ("stripe-verification", "Stripe"),
    ("slack-domain-verification", "Slack"),
    ("have-i-been-pwned-verification", "Have I Been Pwned"),
    ("docusign", "DocuSign"),
    ("_github-challenge", "GitHub"),
    ("adobe-idp-site-verification", "Adobe"),
    ("globalsign-domain-verification", "GlobalSign"),
    ("cisco-ci-domain-verification", "Cisco"),
    ("zuora", "Zuora"),
    ("dynatrace-site-verification", "Dynatrace"),
    ("logmein-verification-code", "LogMeIn"),
    ("sophos-domain-verification", "Sophos"),
]

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
        mx_values: list[str] = []
        txt_values: list[str] = []

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
                elif rt == "MX":
                    mx_values.append(record.value)
                elif rt == "TXT":
                    txt_values.append(record.value)

        hosting_provider = self._infer_hosting_provider(nameservers)
        email_provider = self._infer_email_provider(mx_values)
        spf_includes = self._parse_spf_includes(txt_values)
        dns_services = self._detect_txt_services(txt_values)

        # New: DMARC, CAA, PTR
        dmarc_task = self._query_dmarc(resolver, target.hostname)
        caa_task = self._query_caa(resolver, target.hostname)
        ptr_task = self._query_ptr_records(resolved_ips)

        dmarc_policy, caa_issuers, ptr_records = await asyncio.gather(
            dmarc_task, caa_task, ptr_task, return_exceptions=False,
        )

        return DnsResult(
            records=all_records,
            nameservers=nameservers,
            resolved_ips=resolved_ips,
            cdn_detected=cdn_detected,
            hosting_provider=hosting_provider,
            email_provider=email_provider,
            spf_includes=spf_includes,
            dns_services=dns_services,
            dmarc_policy=dmarc_policy,
            caa_issuers=caa_issuers,
            ptr_records=ptr_records,
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

    async def _query_dmarc(
        self, resolver: dns.resolver.Resolver, hostname: str,
    ) -> str | None:
        """Query _dmarc.{hostname} TXT record and parse p= tag."""
        loop = asyncio.get_running_loop()
        try:
            answer = await loop.run_in_executor(
                None, lambda: resolver.resolve(f"_dmarc.{hostname}", "TXT")
            )
        except Exception:
            return None

        for rdata in answer:
            txt = str(rdata).strip('"')
            m = re.search(r'\bp=(\w+)', txt)
            if m:
                return m.group(1).lower()  # none, quarantine, reject
        return None

    async def _query_caa(
        self, resolver: dns.resolver.Resolver, hostname: str,
    ) -> list[str]:
        """Query CAA records and extract issue/issuewild values."""
        loop = asyncio.get_running_loop()
        try:
            answer = await loop.run_in_executor(
                None, lambda: resolver.resolve(hostname, "CAA")
            )
        except Exception:
            return []

        issuers: list[str] = []
        for rdata in answer:
            txt = str(rdata)
            # CAA records: flag tag value, e.g. '0 issue "letsencrypt.org"'
            m = re.search(r'(?:issue|issuewild)\s+"?([^"]+)"?', txt)
            if m:
                issuer = m.group(1).strip()
                if issuer and issuer not in issuers:
                    issuers.append(issuer)
        return issuers

    async def _query_ptr_records(self, resolved_ips: list[str]) -> list[str]:
        """Reverse DNS lookup for each resolved IP."""
        if not resolved_ips:
            return []

        loop = asyncio.get_running_loop()
        ptrs: list[str] = []

        async def _ptr_lookup(ip: str) -> str | None:
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)),
                    timeout=5.0,
                )
                return result[0]
            except Exception:
                return None

        results = await asyncio.gather(*[_ptr_lookup(ip) for ip in resolved_ips])
        for r in results:
            if r and r not in ptrs:
                ptrs.append(r)
        return ptrs

    @staticmethod
    def _detect_cdn(cname_value: str) -> str | None:
        lower = cname_value.lower()
        for pattern, cdn_name in CDN_CNAME_PATTERNS.items():
            if pattern in lower:
                return cdn_name
        return None

    @staticmethod
    def _infer_hosting_provider(nameservers: list[str]) -> str | None:
        for ns in nameservers:
            ns_lower = ns.lower()
            for pattern, provider in _NS_PROVIDERS:
                if pattern in ns_lower:
                    return provider
        return None

    @staticmethod
    def _infer_email_provider(mx_values: list[str]) -> str | None:
        for mx in mx_values:
            mx_lower = mx.lower()
            for pattern, provider in _MX_PROVIDERS:
                if pattern in mx_lower:
                    return provider
        return None

    @staticmethod
    def _parse_spf_includes(txt_values: list[str]) -> list[str]:
        includes: list[str] = []
        for txt in txt_values:
            if "v=spf1" not in txt.lower():
                continue
            for match in re.findall(r"include:(\S+)", txt):
                domain = match.lower()
                for spf_pattern, service_name in _SPF_SERVICES.items():
                    if spf_pattern in domain:
                        if service_name not in includes:
                            includes.append(service_name)
                        break
                else:
                    if domain not in includes:
                        includes.append(domain)
        return includes

    @staticmethod
    def _detect_txt_services(txt_values: list[str]) -> list[str]:
        services: list[str] = []
        for txt in txt_values:
            txt_lower = txt.lower()
            for pattern, service_name in _TXT_SERVICES:
                if pattern.lower() in txt_lower and service_name not in services:
                    services.append(service_name)
        return services

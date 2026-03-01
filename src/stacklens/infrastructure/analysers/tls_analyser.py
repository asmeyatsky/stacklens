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

        cipher_name = cipher_info[0] if cipher_info else "unknown"
        certificate = self._parse_cert(cert) if cert else None
        days_until_expiry = None
        if certificate:
            delta = certificate.not_after - datetime.now(timezone.utc)
            days_until_expiry = delta.days

        # New analysis
        cipher_strength = self._rate_cipher_strength(cipher_name)
        is_wildcard = self._is_wildcard_cert(certificate.san if certificate else [])
        is_ev = self._is_ev_cert(cert) if cert else False
        key_type = self._detect_key_type(cipher_name)

        return TlsResult(
            protocol=version,
            cipher=cipher_name,
            certificate=certificate,
            days_until_expiry=days_until_expiry,
            cipher_strength=cipher_strength,
            is_wildcard=is_wildcard,
            is_ev=is_ev,
            key_type=key_type,
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

    @staticmethod
    def _rate_cipher_strength(cipher: str) -> str:
        cipher_upper = cipher.upper()
        # Weak ciphers
        if any(w in cipher_upper for w in ("RC4", "DES", "3DES", "NULL", "EXPORT")):
            return "weak"
        # Strong ciphers
        if any(s in cipher_upper for s in ("AES_256", "AES-256", "CHACHA20")):
            return "strong"
        # Medium
        if any(m in cipher_upper for m in ("AES_128", "AES-128")):
            return "medium"
        # Default for modern cipher suites
        if "GCM" in cipher_upper or "POLY1305" in cipher_upper:
            return "strong"
        return "unknown"

    @staticmethod
    def _is_wildcard_cert(san_list: list[str]) -> bool:
        return any(s.startswith("*.") for s in san_list)

    @staticmethod
    def _is_ev_cert(cert: dict) -> bool:
        """EV certs require organizationName in subject."""
        subject = cert.get("subject", ())
        for item in subject:
            for k, _v in item:
                if k == "organizationName":
                    return True
        return False

    @staticmethod
    def _detect_key_type(cipher_name: str) -> str | None:
        cipher_upper = cipher_name.upper()
        if "ECDSA" in cipher_upper:
            return "ECDSA"
        if "RSA" in cipher_upper:
            return "RSA"
        # TLS 1.3 cipher suites don't include key exchange in name
        if cipher_upper.startswith("TLS_"):
            return None
        return None

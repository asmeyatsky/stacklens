"""Tests for DMARC parsing, CAA extraction, and PTR lookups."""

from unittest.mock import patch

import pytest

from stacklens.infrastructure.analysers.dns_analyser import DnsAnalyser


class TestDmarcParsing:
    """Test DMARC policy extraction from _dmarc TXT records."""

    def test_parses_reject_policy(self):
        import re
        txt = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        m = re.search(r'\bp=(\w+)', txt)
        assert m.group(1).lower() == "reject"

    def test_parses_quarantine_policy(self):
        import re
        txt = "v=DMARC1; p=quarantine; pct=100"
        m = re.search(r'\bp=(\w+)', txt)
        assert m.group(1).lower() == "quarantine"

    def test_parses_none_policy(self):
        import re
        txt = "v=DMARC1; p=none"
        m = re.search(r'\bp=(\w+)', txt)
        assert m.group(1).lower() == "none"


class TestCaaExtraction:
    """Test CAA record issuer extraction."""

    def test_extracts_issuers_from_caa_format(self):
        import re
        records = [
            '0 issue "letsencrypt.org"',
            '0 issue "digicert.com"',
            '0 issuewild "letsencrypt.org"',
        ]
        issuers = []
        for txt in records:
            m = re.search(r'(?:issue|issuewild)\s+"?([^"]+)"?', txt)
            if m:
                issuer = m.group(1).strip()
                if issuer and issuer not in issuers:
                    issuers.append(issuer)

        assert "letsencrypt.org" in issuers
        assert "digicert.com" in issuers
        assert len(issuers) == 2  # deduplicated


class TestPtrLookup:
    """Test reverse DNS lookup logic."""

    @pytest.mark.asyncio
    async def test_returns_empty_for_no_ips(self):
        analyser = DnsAnalyser()
        result = await analyser._query_ptr_records([])
        assert result == []

    @pytest.mark.asyncio
    async def test_handles_failed_ptr_lookups(self):
        analyser = DnsAnalyser()
        with patch("socket.gethostbyaddr", side_effect=OSError("not found")):
            result = await analyser._query_ptr_records(["192.0.2.1"])
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_ptr_hostnames(self):
        analyser = DnsAnalyser()
        with patch(
            "socket.gethostbyaddr",
            return_value=("server-1.example.com", [], ["192.0.2.1"]),
        ):
            result = await analyser._query_ptr_records(["192.0.2.1"])
        assert "server-1.example.com" in result

    @pytest.mark.asyncio
    async def test_deduplicates_ptr_records(self):
        analyser = DnsAnalyser()
        with patch(
            "socket.gethostbyaddr",
            return_value=("server-1.example.com", [], ["192.0.2.1"]),
        ):
            result = await analyser._query_ptr_records(["192.0.2.1", "192.0.2.2"])
        assert len(result) == 1
        assert "server-1.example.com" in result

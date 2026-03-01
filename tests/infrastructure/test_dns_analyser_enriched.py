"""Tests for enriched DNS analysis: NS inference, SPF parsing, MX analysis, TXT services."""

from stacklens.infrastructure.analysers.dns_analyser import DnsAnalyser


class TestNsInference:
    def test_detects_aws_route53(self):
        analyser = DnsAnalyser()
        result = analyser._infer_hosting_provider(["ns-1234.awsdns-56.com", "ns-5678.awsdns-78.net"])
        assert result == "AWS Route53"

    def test_detects_cloudflare_dns(self):
        analyser = DnsAnalyser()
        result = analyser._infer_hosting_provider(["ns.cloudflare.com", "ns2.cloudflare.com"])
        assert result == "Cloudflare DNS"

    def test_detects_google_dns(self):
        analyser = DnsAnalyser()
        result = analyser._infer_hosting_provider(["ns-cloud-a1.googledomains.com"])
        assert result == "Google Domains"

    def test_detects_azure_dns(self):
        analyser = DnsAnalyser()
        result = analyser._infer_hosting_provider(["ns1-01.azure-dns.com"])
        assert result == "Azure DNS"

    def test_returns_none_for_unknown(self):
        analyser = DnsAnalyser()
        result = analyser._infer_hosting_provider(["ns1.unknownprovider.com"])
        assert result is None

    def test_empty_nameservers(self):
        analyser = DnsAnalyser()
        result = analyser._infer_hosting_provider([])
        assert result is None


class TestSpfParsing:
    def test_extracts_aws_ses(self):
        analyser = DnsAnalyser()
        result = analyser._parse_spf_includes([
            '"v=spf1 include:amazonses.com include:_spf.google.com ~all"'
        ])
        assert "AWS SES" in result
        assert "Google" in result

    def test_extracts_sendgrid(self):
        analyser = DnsAnalyser()
        result = analyser._parse_spf_includes(['"v=spf1 include:sendgrid.net ~all"'])
        assert "SendGrid" in result

    def test_extracts_microsoft_365(self):
        analyser = DnsAnalyser()
        result = analyser._parse_spf_includes([
            '"v=spf1 include:spf.protection.outlook.com -all"'
        ])
        assert "Microsoft 365" in result

    def test_ignores_non_spf_records(self):
        analyser = DnsAnalyser()
        result = analyser._parse_spf_includes([
            '"google-site-verification=abc123"',
            '"v=DMARC1; p=reject"',
        ])
        assert result == []

    def test_includes_unknown_domains(self):
        analyser = DnsAnalyser()
        result = analyser._parse_spf_includes([
            '"v=spf1 include:custom-mail.example.com ~all"'
        ])
        assert "custom-mail.example.com" in result


class TestMxInference:
    def test_detects_google_workspace(self):
        analyser = DnsAnalyser()
        result = analyser._infer_email_provider(["10 aspmx.l.google.com."])
        assert result == "Google Workspace"

    def test_detects_microsoft_365(self):
        analyser = DnsAnalyser()
        result = analyser._infer_email_provider([
            "10 example-com.mail.protection.outlook.com."
        ])
        assert result == "Microsoft 365"

    def test_detects_proofpoint(self):
        analyser = DnsAnalyser()
        result = analyser._infer_email_provider(["10 mx1.example.pphosted.com."])
        assert result == "Proofpoint"

    def test_returns_none_for_unknown(self):
        analyser = DnsAnalyser()
        result = analyser._infer_email_provider(["10 mail.example.com."])
        assert result is None


class TestTxtServices:
    def test_detects_facebook_verification(self):
        analyser = DnsAnalyser()
        result = analyser._detect_txt_services([
            '"facebook-domain-verification=abc123"'
        ])
        assert "Facebook" in result

    def test_detects_google_verification(self):
        analyser = DnsAnalyser()
        result = analyser._detect_txt_services([
            '"google-site-verification=abc123def456"'
        ])
        assert "Google" in result

    def test_detects_multiple_services(self):
        analyser = DnsAnalyser()
        result = analyser._detect_txt_services([
            '"google-site-verification=abc"',
            '"facebook-domain-verification=def"',
            '"apple-domain-verification=123"',
            '"v=DMARC1; p=reject"',
        ])
        assert "Google" in result
        assert "Facebook" in result
        assert "Apple" in result
        assert "DMARC" in result

    def test_empty_txt_records(self):
        analyser = DnsAnalyser()
        result = analyser._detect_txt_services([])
        assert result == []

    def test_detects_atlassian_verification(self):
        analyser = DnsAnalyser()
        result = analyser._detect_txt_services([
            '"atlassian-domain-verification=abc123"'
        ])
        assert "Atlassian" in result

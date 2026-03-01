import pytest
from pydantic import ValidationError

from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.models.dns import DnsResult


class TestAnalysisTarget:
    def test_from_url_with_https(self):
        target = AnalysisTarget.from_url("https://example.com")
        assert target.hostname == "example.com"
        assert target.scheme == "https"
        assert target.port == 443

    def test_from_url_with_http(self):
        target = AnalysisTarget.from_url("http://example.com")
        assert target.scheme == "http"
        assert target.port == 80

    def test_from_url_adds_scheme(self):
        target = AnalysisTarget.from_url("example.com")
        assert target.scheme == "https"
        assert target.hostname == "example.com"

    def test_from_url_with_custom_port(self):
        target = AnalysisTarget.from_url("https://example.com:8443")
        assert target.port == 8443

    def test_invalid_url_raises(self):
        with pytest.raises(ValidationError):
            AnalysisTarget.from_url("")


class TestAnalysisReport:
    def test_with_layer_result_returns_new_instance(self):
        target = AnalysisTarget.from_url("https://example.com")
        report = AnalysisReport(target=target)
        dns = DnsResult()
        new_report = report.with_layer_result("dns", dns)

        assert "dns" not in report.layers
        assert "dns" in new_report.layers

    def test_finalize_sets_completed_at(self):
        target = AnalysisTarget.from_url("https://example.com")
        report = AnalysisReport(target=target)
        report = report.with_layer_result("dns", DnsResult())
        final = report.finalize()

        assert final.meta.completed_at is not None
        assert final.meta.layers == ["dns"]

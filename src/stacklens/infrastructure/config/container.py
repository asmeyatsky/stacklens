from __future__ import annotations

from stacklens.application.commands.run_analysis import RunAnalysisCommand
from stacklens.application.orchestration.pipeline import AnalysisPipeline
from stacklens.domain.services.ethics import EthicsPolicy
from stacklens.infrastructure.adapters.httpx_client import HttpxClientAdapter
from stacklens.infrastructure.analysers.backend_analyser import BackendAnalyser
from stacklens.infrastructure.analysers.dns_analyser import DnsAnalyser
from stacklens.infrastructure.analysers.frontend_analyser import FrontendAnalyser
from stacklens.infrastructure.analysers.headers_analyser import HeadersAnalyser
from stacklens.infrastructure.analysers.tls_analyser import TlsAnalyser
from stacklens.infrastructure.writers.html_writer import HtmlReportWriter
from stacklens.infrastructure.writers.json_writer import JsonReportWriter


class Container:
    """Composition root: wires all concrete implementations."""

    def __init__(self) -> None:
        self.http_client = HttpxClientAdapter()
        self.dns_analyser = DnsAnalyser()
        self.tls_analyser = TlsAnalyser()
        self.headers_analyser = HeadersAnalyser(self.http_client)
        self.frontend_analyser = FrontendAnalyser(self.http_client)
        self.backend_analyser = BackendAnalyser(self.http_client)
        self.json_writer = JsonReportWriter()
        self.html_writer = HtmlReportWriter()
        self.ethics = EthicsPolicy(self.http_client)

        self._all_analysers = {
            "dns": self.dns_analyser,
            "tls": self.tls_analyser,
            "headers": self.headers_analyser,
            "frontend": self.frontend_analyser,
            "backend": self.backend_analyser,
        }

        try:
            from stacklens.infrastructure.analysers.browser_analyser import BrowserAnalyser
            self.browser_analyser = BrowserAnalyser()
            self._all_analysers["browser"] = self.browser_analyser
        except ImportError:
            self.browser_analyser = None

    def pipeline(self, layers: list[str]) -> AnalysisPipeline:
        selected = [self._all_analysers[l] for l in layers if l in self._all_analysers]
        return AnalysisPipeline(selected)

    def run_analysis_command(self, layers: list[str]) -> RunAnalysisCommand:
        return RunAnalysisCommand(
            pipeline=self.pipeline(layers),
            writers={"json": self.json_writer, "html": self.html_writer},
            ethics=self.ethics,
        )

    @property
    def available_layers(self) -> list[str]:
        return list(self._all_analysers.keys())

    async def close(self) -> None:
        await self.http_client.close()

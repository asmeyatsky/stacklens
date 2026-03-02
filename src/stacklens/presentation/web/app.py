from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from stacklens.application.dtos.analysis_config import AnalysisConfig
from stacklens.application.orchestration.pipeline import AnalysisPipeline
from stacklens.application.services.summary_builder import build_summary
from stacklens.domain.models.browser import BrowserResult
from stacklens.domain.models.report import AnalysisReport
from stacklens.domain.models.target import AnalysisTarget
from stacklens.domain.services.ethics import EthicsPolicy
from stacklens.domain.services.performance_scoring import score_performance
from stacklens.domain.services.recommendation_builder import build_recommendations
from stacklens.infrastructure.config.container import Container
from stacklens.infrastructure.writers.html_writer import HtmlReportWriter

_HERE = Path(__file__).parent
_TEMPLATES = _HERE / "templates"

_container: Container | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _container
    _container = Container()
    yield
    if _container:
        await _container.close()
        _container = None


webapp = FastAPI(title="StackLens", lifespan=lifespan)
webapp.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")

VALID_LAYERS = ["dns", "tls", "headers", "frontend", "backend", "browser"]
DEFAULT_LAYERS = ["dns", "tls", "headers", "frontend", "backend"]


# ── Routes ──────────────────────────────────────────────────


@webapp.get("/", response_class=HTMLResponse)
async def index():
    return (_TEMPLATES / "index.html").read_text()


class AnalyzeRequest(BaseModel):
    url: str
    layers: list[str] = DEFAULT_LAYERS
    perf: bool = False


@webapp.post("/api/analyze")
async def analyze(body: AnalyzeRequest):
    report = await _run_analysis(body.url, body.layers, body.perf)
    return report.model_dump(mode="json")


@webapp.get("/api/analyze/stream")
async def analyze_stream(url: str, layers: str = "", perf: str = "0"):
    layer_list = [l.strip() for l in layers.split(",") if l.strip()] or DEFAULT_LAYERS
    layer_list = [l for l in layer_list if l in VALID_LAYERS]
    enable_perf = perf == "1"

    if enable_perf and "browser" not in layer_list:
        layer_list.append("browser")

    async def event_stream():
        try:
            assert _container is not None
            target = AnalysisTarget.from_url(url)

            await _container.ethics.check_robots_txt(
                f"{target.scheme}://{target.hostname}",
                strict=False,
            )

            report = AnalysisReport(target=target)
            resolved_order = _resolve_dag(_container, layer_list)

            for batch in resolved_order:
                for name in batch:
                    yield _sse("layer_start", {"layer": name})

                tasks = [_run_layer(_container, name, target) for name in batch]
                results = await asyncio.gather(*tasks)

                for name, result in zip(batch, results):
                    if isinstance(result, dict) and "error" in result:
                        yield _sse("layer_error", {"layer": name, "error": result["error"]})
                    else:
                        yield _sse("layer_done", {"layer": name})
                    report = report.with_layer_result(name, result)

            report = report.finalize()
            summary = build_summary(report)
            report = report.with_summary(summary)

            browser_data = report.layers.get("browser")
            if isinstance(browser_data, BrowserResult):
                perf_score = score_performance(browser_data)
                report = report.with_performance_score(perf_score)

            recs = build_recommendations(report)
            report = report.with_recommendations(recs)

            yield _sse("complete", report.model_dump(mode="json"))
        except Exception as exc:
            yield _sse("error_msg", {"error": str(exc)})

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@webapp.post("/api/export/html", response_class=HTMLResponse)
async def export_html(request: Request):
    body = await request.json()
    report = AnalysisReport.model_validate(body)
    writer = HtmlReportWriter()
    html_str = writer._render(report)
    return HTMLResponse(content=html_str)


# ── Helpers ─────────────────────────────────────────────────


def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


async def _run_analysis(url: str, layers: list[str], perf: bool) -> AnalysisReport:
    assert _container is not None
    layer_list = [l for l in layers if l in VALID_LAYERS]
    if perf and "browser" not in layer_list:
        layer_list.append("browser")

    config = AnalysisConfig(
        target_url=url,
        layers=layer_list,
        output_formats=[],
        perf=perf,
    )
    command = _container.run_analysis_command(config.layers)
    return await command.execute(config)


def _resolve_dag(container: Container, layers: list[str]) -> list[list[str]]:
    pipeline = container.pipeline(layers)
    return pipeline._resolve_dag(layers)


async def _run_layer(container: Container, name: str, target: AnalysisTarget) -> Any:
    analyser = container._all_analysers.get(name)
    if not analyser:
        return {"error": f"Unknown analyser: {name}"}
    try:
        timeout = getattr(analyser, "timeout", 30.0)
        return await asyncio.wait_for(analyser.analyse(target), timeout=timeout)
    except asyncio.TimeoutError:
        timeout = getattr(analyser, "timeout", 30.0)
        return {"error": f"Analyser '{name}' timed out after {timeout}s"}
    except Exception as exc:
        return {"error": f"Analyser '{name}' failed: {exc}"}

import pytest

from stacklens.application.orchestration.pipeline import AnalysisPipeline
from stacklens.domain.models.target import AnalysisTarget


class FakeAnalyser:
    def __init__(self, name: str, result, depends: list[str] | None = None):
        self._name = name
        self._result = result
        self._depends = depends or []

    @property
    def name(self) -> str:
        return self._name

    @property
    def depends_on(self) -> list[str]:
        return self._depends

    async def analyse(self, target):
        return self._result


class FailingAnalyser:
    @property
    def name(self) -> str:
        return "failing"

    @property
    def depends_on(self) -> list[str]:
        return []

    async def analyse(self, target):
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_pipeline_runs_all_layers():
    analysers = [
        FakeAnalyser("a", {"data": 1}),
        FakeAnalyser("b", {"data": 2}),
    ]
    pipeline = AnalysisPipeline(analysers)
    target = AnalysisTarget.from_url("https://example.com")
    report = await pipeline.run(target, ["a", "b"])

    assert "a" in report.layers
    assert "b" in report.layers
    assert report.layers["a"] == {"data": 1}


@pytest.mark.asyncio
async def test_pipeline_error_isolation():
    analysers = [
        FakeAnalyser("good", {"ok": True}),
        FailingAnalyser(),
    ]
    pipeline = AnalysisPipeline(analysers)
    target = AnalysisTarget.from_url("https://example.com")
    report = await pipeline.run(target, ["good", "failing"])

    assert report.layers["good"] == {"ok": True}
    assert "error" in report.layers["failing"]


@pytest.mark.asyncio
async def test_pipeline_dependency_ordering():
    analysers = [
        FakeAnalyser("base", "base_result"),
        FakeAnalyser("dependent", "dep_result", depends=["base"]),
    ]
    pipeline = AnalysisPipeline(analysers)
    target = AnalysisTarget.from_url("https://example.com")
    report = await pipeline.run(target, ["dependent", "base"])

    assert list(report.layers.keys()) == ["base", "dependent"]

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


class FakeAnalyserWithTimeout:
    def __init__(self, name: str, result, timeout: float):
        self._name = name
        self._result = result
        self._timeout = timeout

    @property
    def name(self) -> str:
        return self._name

    @property
    def depends_on(self) -> list[str]:
        return []

    @property
    def timeout(self) -> float:
        return self._timeout

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


@pytest.mark.asyncio
async def test_pipeline_per_analyser_timeout():
    """Analyser with custom timeout property uses that instead of pipeline default."""
    import asyncio

    class SlowAnalyser:
        @property
        def name(self) -> str:
            return "slow"

        @property
        def depends_on(self) -> list[str]:
            return []

        @property
        def timeout(self) -> float:
            return 0.1  # very short timeout

        async def analyse(self, target):
            await asyncio.sleep(5)  # will exceed the 0.1s timeout
            return {"data": "never"}

    analysers = [
        SlowAnalyser(),
        FakeAnalyser("fast", {"ok": True}),
    ]
    pipeline = AnalysisPipeline(analysers, timeout=30.0)
    target = AnalysisTarget.from_url("https://example.com")
    report = await pipeline.run(target, ["slow", "fast"])

    # slow should timeout with its own 0.1s, not pipeline's 30s
    assert "error" in report.layers["slow"]
    assert "0.1s" in report.layers["slow"]["error"]
    # fast should succeed
    assert report.layers["fast"] == {"ok": True}


@pytest.mark.asyncio
async def test_pipeline_default_timeout_when_no_property():
    """Analyser without timeout property uses pipeline default."""
    analysers = [FakeAnalyser("a", {"data": 1})]
    pipeline = AnalysisPipeline(analysers, timeout=30.0)
    target = AnalysisTarget.from_url("https://example.com")
    report = await pipeline.run(target, ["a"])
    assert report.layers["a"] == {"data": 1}

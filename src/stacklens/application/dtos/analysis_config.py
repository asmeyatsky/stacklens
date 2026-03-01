from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class AnalysisConfig:
    target_url: str
    layers: list[str] = field(default_factory=lambda: ["dns", "tls", "headers", "frontend", "backend"])
    output_formats: list[str] = field(default_factory=lambda: ["json"])
    output_dir: Path = field(default_factory=lambda: Path("stacklens_output"))
    no_ai: bool = True
    ethical_strict: bool = False

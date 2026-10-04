from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

CheckStatus = Literal["passed", "failed", "blocked", "skipped", "error"]


@dataclass
class DetectedProject:
    languages: list[str] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    file_count: int = 0
    has_python: bool = False
    has_node: bool = False
    has_typescript: bool = False
    python_files_present: bool = False
    javascript_files_present: bool = False
    typescript_files_present: bool = False
    package_scripts: list[str] = field(default_factory=list)
    python_tests_present: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlannedCheck:
    check_id: str
    title: str
    selected: bool
    reason: str
    execution: Literal["static", "sandbox"]
    test_category: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckResult:
    check_id: str
    title: str
    status: CheckStatus
    summary: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    output_excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

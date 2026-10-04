from __future__ import annotations

from collections import Counter
from typing import Any

from saferun.models import CheckResult


def make_report(project: dict[str, Any], plan: list[dict[str, Any]], checks: list[CheckResult]) -> dict[str, Any]:
    safe_checks = [item.to_dict() for item in checks]
    counts = Counter(item.status for item in checks)
    selected_ids = {item["check_id"] for item in plan if item.get("selected")}
    selected_skips = [item.check_id for item in checks if item.status == "skipped" and item.check_id in selected_ids]
    if counts["failed"]:
        summary = f"{counts['failed']} check(s) need attention. Review the evidence and blocked coverage below."
    elif counts["error"] or counts["blocked"] or selected_skips:
        summary = "The run is partial: some checks could not complete in this environment."
    else:
        summary = "All selected checks completed. This is a bounded audit, not proof the project is defect-free."
    languages = project.get("languages", [])
    unsupported_languages = [
        language for language in languages
        if language not in {"Python", "JavaScript", "TypeScript", "Unknown / configuration-only"}
    ]
    coverage_note = "SafeRun reports only registered checks that ran. It does not query external vulnerability feeds or guarantee exhaustive coverage."
    if unsupported_languages:
        coverage_note += " Detected " + ", ".join(unsupported_languages) + " received the shared archive, dependency-manifest, and secret checks; language-specific test runners for those ecosystems are not built in yet."
    elif languages == ["Unknown / configuration-only"]:
        coverage_note += " No language-specific project runner matched this upload; the shared checks still ran."
    return {
        "summary": summary,
        "project": project,
        "plan": plan,
        "checks": safe_checks,
        "counts": {key: int(counts.get(key, 0)) for key in ("passed", "failed", "blocked", "skipped", "error")},
        "coverage_note": coverage_note,
    }

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from saferun.checks.static import run_static_check
from saferun.config import Settings
from saferun.db import connection, update_scan_status
from saferun.detection import detect_project
from saferun.models import CheckResult, DetectedProject, PlannedCheck
from saferun.planner import validate_plan
from saferun.reports import make_report
from saferun.runner.docker import run_sandbox_check
from saferun.runner.session import close_sandbox_session, start_sandbox_session
from saferun.storage import remove_job_directory

_scan_lock = threading.Lock()

def run_scan(settings: Settings, scan_id: str) -> None:
    # This MVP has one in-process worker: queue subsequent scans instead of
    # allowing multiple uploaded repositories to run at once.
    with _scan_lock:
        _run_scan(settings, scan_id)


def _run_scan(settings: Settings, scan_id: str) -> None:
    update_scan_status(settings, scan_id, "running")
    checks: list[CheckResult] = []
    plan_dict: list[dict[str, Any]] = []
    project_dict: dict[str, Any] = {}
    report: dict[str, Any] | None = None
    final_status = "completed"
    sandbox_sessions = {}
    try:
        with connection(settings) as db:
            scan = db.execute("SELECT project_json,plan_json FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            return
        project_dict = json.loads(scan["project_json"])
        plan_dict = json.loads(scan["plan_json"])
        project = DetectedProject(**project_dict)
        plan = [PlannedCheck(**item) for item in plan_dict]
        validate_plan(plan)
        root = _locate_root(settings.jobs_dir / scan_id)
        # Re-detect immediately before scanning; the uploaded files remain untrusted.
        project = detect_project(root)
        project_dict = project.to_dict()
        for check in plan:
            try:
                if check.execution == "static":
                    checks.append(run_static_check(check, root, project))
                else:
                    ecosystem = "python" if check.check_id.startswith("python.") else "node"
                    if check.selected and ecosystem not in sandbox_sessions:
                        selected_ids = {
                            item.check_id for item in plan
                            if item.selected and item.execution == "sandbox" and item.check_id.startswith(ecosystem + ".")
                        }
                        sandbox_sessions[ecosystem] = start_sandbox_session(root, project, settings, scan_id, ecosystem, selected_ids)
                    checks.append(run_sandbox_check(check, root, project, settings, scan_id, sandbox_sessions.get(ecosystem)))
            except Exception as exc:
                checks.append(CheckResult(
                    check_id=check.check_id, title=check.title, status="error",
                    summary=f"SafeRun hit an internal {type(exc).__name__} while starting this check. Source and raw error details were not saved.",
                ))
        report = make_report(project_dict, plan_dict, checks)
    except Exception:
        report = make_report(project_dict, plan_dict, checks)
        report["summary"] = "The scan stopped because SafeRun encountered an internal error. Available completed results are shown below."
        report["checks"].append({
            "check_id": "runner.internal", "title": "SafeRun scan lifecycle", "status": "error",
            "summary": "The scan could not finish. No project source or raw error log was saved.",
            "evidence": [], "duration_ms": 0, "output_excerpt": "",
        })
        final_status = "failed"
    finally:
        sandboxes_removed = True
        for session in sandbox_sessions.values():
            if not close_sandbox_session(session, settings):
                sandboxes_removed = False
        removed = remove_job_directory(settings.jobs_dir, scan_id)
        if report is None:
            report = make_report(project_dict, plan_dict, checks)
            final_status = "failed"
        report["source_cleanup"] = "removed" if removed else "pending"
        report["sandbox_cleanup"] = "removed" if sandboxes_removed else "pending"
        if not removed:
            report["summary"] += " SafeRun could not confirm removal of the temporary source; cleanup will be retried at next startup."
        if not sandboxes_removed:
            report["summary"] += " SafeRun could not confirm the temporary sandbox was removed; cleanup will be retried at next startup."
        update_scan_status(settings, scan_id, final_status, report=report)


def _locate_root(job_dir: Path) -> Path:
    from saferun.archive import locate_project_root
    return locate_project_root(job_dir)

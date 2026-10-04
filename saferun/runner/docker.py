from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from saferun.config import Settings
from saferun.models import CheckResult, DetectedProject, PlannedCheck
from saferun.planner import CATALOG
from saferun.runner.session import SandboxSession, run_in_sandbox

_COMMANDS = {
    "python.tests", "python.ruff", "python.mypy", "node.test",
    "node.lint", "node.typecheck", "node.build",
    "python.tests.unit", "python.tests.integration", "python.tests.system", "python.tests.e2e",
    "node.test.unit", "node.test.integration", "node.test.system", "node.test.e2e",
}


def docker_executable() -> str | None:
    found = shutil.which("docker")
    if found:
        return found
    if os.name == "nt":
        roots = [os.environ.get("ProgramFiles", r"C:\Program Files"), os.environ.get("LOCALAPPDATA", "")]
        for root in roots:
            if root:
                candidate = Path(root) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe" if "Program Files" in root else Path(root) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe"
                try:
                    if candidate.is_file():
                        return str(candidate)
                except OSError:
                    continue
    return None


def _sandbox_user() -> str | None:
    if os.name == "nt":
        return "65534:65534"
    uid = os.getuid()
    if uid == 0:
        return None
    return f"{uid}:{os.getgid()}"


def _result(check: PlannedCheck, status: str, summary: str, *, started: float | None = None, output: str = "") -> CheckResult:
    duration = int((time.monotonic() - started) * 1000) if started is not None else 0
    return CheckResult(check.check_id, check.title, status, summary, [], duration, _sanitize_output(output))  # type: ignore[arg-type]


def _sanitize_output(output: str, max_chars: int = 3000) -> str:
    value = output.replace("\r", "")
    value = value.replace("/workspace", "<project>")
    value = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED]", value)
    value = re.sub(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b", "[REDACTED]", value)
    value = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,})\b", "[REDACTED]", value)
    value = re.sub(r"(?i)((?:api[_-]?key|secret|secret[_-]?key|password|access[_-]?token|database[_-]?url|connection[_-]?string)\s*[:=]\s*)\S+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{12,}", r"\1[REDACTED]", value)
    value = re.sub(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", value, flags=re.DOTALL)
    return value[:max_chars]


def run_sandbox_check(
    check: PlannedCheck,
    root: Path,
    project: DetectedProject,
    settings: Settings,
    scan_id: str,
    session: SandboxSession | None = None,
) -> CheckResult:
    if not check.selected:
        return _result(check, "skipped", check.reason)
    if check.check_id not in _COMMANDS:
        return _result(check, "skipped", "No sandbox adapter is registered for this check.")
    started = time.monotonic()
    if session is None:
        return _result(check, "blocked", "SafeRun could not prepare the isolated runner. No project command ran.", started=started)
    return_code, output, timed_out, reason = run_in_sandbox(check, root, project, session, settings)
    if reason:
        return _result(check, "blocked", reason, started=started)
    lower = output.casefold()
    if timed_out:
        return _result(check, "error", "The sandbox check exceeded its time limit. SafeRun stopped the isolated container.", started=started, output=output)
    if check.check_id.startswith("python.tests") and ("ran 0 tests" in lower or "no tests ran" in lower):
        return _result(check, "skipped", "The configured Python test command discovered no runnable tests.", started=started, output=output)
    if check.check_id.startswith("node.test") and any(marker in lower for marker in ("# tests 0", "ℹ tests 0", "test suites: 0", "no tests found")):
        return _result(check, "skipped", "The configured Node test script discovered no tests.", started=started, output=output)
    if return_code == 0:
        return _result(check, "passed", "The registered command completed successfully inside an isolated, network-disconnected container.", started=started, output=output)
    if return_code is None or return_code in {125, 126}:
        return _result(check, "blocked", "Docker could not invoke the registered command in the isolated container. This is a runner issue, not a confirmed project failure.", started=started, output=output)
    if return_code in {137, 143}:
        return _result(check, "error", "The sandbox process was terminated, possibly after reaching its resource limit.", started=started, output=output)
    if any(marker in lower for marker in ("modulenotfounderror:", "no module named", "cannot find module", "err_module_not_found")):
        has_actual_test_failure = (
            "assertionerror" in lower
            or re.search(r"(?m)^\s*(?:fail:|not ok\b)", lower) is not None
            or re.search(r"(?m)^\s*failed\s+\S+::", lower) is not None
        )
        if has_actual_test_failure:
            return _result(check, "failed", "At least one test reported a failure, and another check could not load because a dependency is missing.", started=started, output=output)
        missing = re.search(r"no module named ['\"]([a-z0-9_.-]+)['\"]|cannot find module ['\"]([a-z0-9@._/-]+)['\"]", lower)
        if missing:
            module = next(value for value in missing.groups() if value)
            guidance = f"The check could not import {module!r}. SafeRun prepares declared packages only; add the missing package (or its matching distribution) to the project manifest and rescan. No test assertion failure was confirmed."
        else:
            guidance = "The check could not fully load because a dependency is missing. SafeRun prepares declared packages only; add the missing package to the project manifest and rescan. No test assertion failure was confirmed."
        return _result(check, "blocked", guidance, started=started, output=output)
    if check.check_id.startswith("node.test") and "missing script:" in lower:
        return _result(check, "skipped", "The declared package test script is unavailable in this package directory.", started=started, output=output)
    return _result(check, "failed", "The registered project check returned a non-zero exit code.", started=started, output=output)


def sandbox_capability() -> dict[str, object]:
    if _sandbox_user() is None:
        return {"available": False, "message": "SafeRun is running as root; command checks stay blocked until it runs as a regular user."}
    binary = docker_executable()
    if not binary:
        return {"available": False, "message": "Docker CLI was not found; command checks stay blocked."}
    try:
        result = subprocess.run([binary, "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0 and result.stdout.strip():
            return {"available": True, "message": "Docker is reachable. SafeRun can fetch free runner images and supported packages into temporary containers when needed."}
    except (OSError, subprocess.TimeoutExpired):
        pass
    return {"available": False, "message": "Docker is installed but its daemon is not reachable."}

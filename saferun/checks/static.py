from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import time
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from saferun.models import CheckResult, DetectedProject, PlannedCheck
from saferun.planner import CATALOG

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\b(?P<value>AKIA[0-9A-Z]{16})\b"), "high"),
    ("AWS secret key", re.compile(r"(?i)(?:['\"])?\baws[_-]?secret[_-]?access[_-]?key\b['\"]?\s*[:=]\s*['\"](?P<value>[^'\"\r\n]{30,})['\"]"), "high"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "high"),
    ("API token pattern", re.compile(r"\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{20,})\b"), "high"),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "high"),
    ("Database URL credentials", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:(?P<value>[^@\s/?#]{6,})@[^/\s]+"), "medium"),
    (
        "Credential assignment",
        re.compile(
            r"(?i)(?:['\"])?\b(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)['\"]?\s*[:=]\s*(?P<quote>['\"])(?P<value>[^'\"\r\n]{8,})(?P=quote)"
        ),
        "medium",
    ),
]
_PLACEHOLDER_SECRET = re.compile(r"(?i)^(?:your(?:[-_ ]?(?:api[-_ ]?)?(?:key|secret|token|password))?|example|sample|test|demo|dummy|placeholder|replace[-_ ]?me|change[-_ ]?me|insert[-_ ]?here|redacted|not[-_ ]?a[-_ ]?secret|none|null|xxx+|0+|x+)$")
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", "target", "vendor", "coverage", ".next", ".nuxt", ".gradle", ".terraform"}
_DEPENDENCY_FILES = {
    "requirements.txt", "requirements-dev.txt", "package.json", "pyproject.toml", "Cargo.toml", "go.mod",
    "composer.json", "Gemfile", "pom.xml", "pubspec.yaml", "build.gradle", "build.gradle.kts",
    "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "package-lock.json", "npm-shrinkwrap.json",
    "pnpm-lock.yaml", "yarn.lock", "bun.lock", "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock",
    "pubspec.lock", "mix.exs", "mix.lock", "Package.swift", "Package.resolved", "CMakeLists.txt", "meson.build",
}


def _dependency_name(value: str) -> str:
    value = value.strip()
    if re.match(r"(?i)^(?:git\+|https?://|file:)", value):
        return "direct-url dependency (value hidden)"
    match = re.match(r"(@[A-Za-z0-9_.-]+/)?([A-Za-z0-9_.-]+)", value)
    return (match.group(1) or "") + match.group(2) if match else "declared dependency (unparsed)"


def _source_files(root: Path):
    count = 0
    for path in root.rglob("*"):
        try:
            if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
                continue
            if path.is_symlink() or not path.is_file():
                continue
        except OSError:
            continue
        count += 1
        if count > 5000:
            return
        yield path


def _dep_entry(path: Path, name: str, version: object = None) -> dict[str, str]:
    label = _dependency_name(name)
    if label == "declared dependency (unparsed)":
        return {"file": "", "name": label}
    if version is not None:
        version_text = str(version).strip()
        if re.match(r"(?i)^(?:git\+|https?://|file:|workspace:|link:)", version_text):
            version_text = "<direct reference hidden>"
        label += "@" + version_text
    return {"file": "", "name": label[:180]}


def _is_placeholder_secret(value: str | None) -> bool:
    if value is None:
        return False
    candidate = value.strip().strip("`$ ")
    compact = re.sub(r"[^a-z0-9]", "", candidate.casefold())
    return (
        not candidate
        or _PLACEHOLDER_SECRET.fullmatch(candidate) is not None
        or compact in {"akiaiosfodnn7example", "wjalrxutnfmixkmdengbpxrficyexamplekey"}
        or compact.endswith(("examplekey", "examplestring", "exampletoken"))
        or compact.startswith(("yourapikey", "yoursecret", "yourtoken", "yourpassword", "example", "sample", "placeholder", "changeme", "replaceme", "inserthere", "redacted"))
        or len(set(compact)) <= 2
    )


def _parse_dependency_manifest(path: Path, root: Path) -> tuple[list[dict[str, str]], bool]:
    """Extract a bounded list of package names without evaluating project config."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], True
    entries: list[dict[str, str]] = []
    parsed = True

    def add(name: object, version: object = None) -> None:
        if not isinstance(name, str) or not name.strip():
            return
        item = _dep_entry(path, name, version)
        item["file"] = path.relative_to(root).as_posix()
        entries.append(item)

    try:
        if path.name.casefold().startswith("requirements") and path.name.casefold().endswith(".txt"):
            for line in text.splitlines():
                value = line.split("#", 1)[0].strip()
                if value and not value.startswith("-"):
                    add(_dependency_name(value))
                elif value.startswith(("-r", "--requirement", "-c", "--constraint")):
                    parsed = False
        elif path.name == "package.json":
            data = json.loads(text)
            if not isinstance(data, dict):
                return [], True
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                packages = data.get(section, {})
                if isinstance(packages, dict):
                    for name, version in list(packages.items())[:500]:
                        add(name, version)
        elif path.name == "pyproject.toml":
            data = tomllib.loads(text)
            project = data.get("project", {})
            if isinstance(project, dict):
                for value in project.get("dependencies", [])[:500]:
                    add(_dependency_name(str(value)))
                groups = project.get("optional-dependencies", {})
                if isinstance(groups, dict):
                    for values in groups.values():
                        if isinstance(values, list):
                            for value in values[:500]:
                                add(_dependency_name(str(value)))
            cargo = data.get("dependencies", {})
            if isinstance(cargo, dict):
                for name, value in cargo.items():
                    add(value.get("package", name) if isinstance(value, dict) else name, value.get("version") if isinstance(value, dict) else value)
            for table in ("dev-dependencies", "build-dependencies"):
                cargo = data.get(table, {})
                if isinstance(cargo, dict):
                    for name, value in cargo.items():
                        add(value.get("package", name) if isinstance(value, dict) else name, value.get("version") if isinstance(value, dict) else value)
        elif path.name == "Cargo.toml":
            data = tomllib.loads(text)
            for table in ("dependencies", "dev-dependencies", "build-dependencies"):
                packages = data.get(table, {})
                if isinstance(packages, dict):
                    for name, value in packages.items():
                        add(value.get("package", name) if isinstance(value, dict) else name, value.get("version") if isinstance(value, dict) else value)
        elif path.name == "go.mod":
            in_block = False
            for line in text.splitlines():
                line = line.split("//", 1)[0].strip()
                if line.startswith("require ("):
                    in_block = True
                    continue
                if in_block and line == ")":
                    in_block = False
                    continue
                value = line[8:].strip() if line.startswith("require ") else line if in_block else ""
                match = re.match(r"([A-Za-z0-9._~/-]+)\s+(v[0-9][A-Za-z0-9.+-]*)", value)
                if match:
                    add(match.group(1), match.group(2))
        elif path.name == "composer.json":
            data = json.loads(text)
            if isinstance(data, dict):
                for section in ("require", "require-dev"):
                    packages = data.get(section, {})
                    if isinstance(packages, dict):
                        for name, version in packages.items():
                            if name.casefold() != "php":
                                add(name, version)
        elif path.name == "Gemfile":
            for match in re.finditer(r"(?m)^\s*gem\s+['\"]([A-Za-z0-9_.-]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", text):
                add(match.group(1), match.group(2))
        elif path.name == "pom.xml":
            if re.search(r"(?is)<!DOCTYPE|<!ENTITY", text):
                return [], True
            xml_root = ET.fromstring(text)
            for element in xml_root.iter():
                if element.tag.rsplit("}", 1)[-1] != "dependency":
                    continue
                values = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in element}
                if values.get("artifactId"):
                    add(f"{values.get('groupId', 'maven')}/{values['artifactId']}", values.get("version"))
        elif path.name in {"build.gradle", "build.gradle.kts"}:
            pattern = re.compile(r"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*\(?\s*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]")
            for match in pattern.finditer(text):
                add(match.group(1) + "/" + match.group(2), match.group(3))
        elif path.name == "pubspec.yaml":
            section = ""
            for line in text.splitlines():
                if line and not line[0].isspace() and line.rstrip().endswith(":"):
                    section = line.rstrip()[:-1]
                    continue
                if section in {"dependencies", "dev_dependencies", "dependency_overrides"}:
                    match = re.match(r"\s{2}([A-Za-z0-9_.-]+):\s*([^#]+)?", line)
                    if match and match.group(1) != "sdk":
                        add(match.group(1), (match.group(2) or "").strip())
        elif path.suffix.casefold() in {".csproj", ".fsproj", ".vbproj"}:
            for match in re.finditer(r"(?i)<PackageReference\s+[^>]*Include=['\"]([^'\"]+)['\"][^>]*Version=['\"]([^'\"]+)['\"]", text):
                add(match.group(1), match.group(2))
            if not entries and "PackageReference" in text:
                parsed = False
        else:
            # Recognized lockfiles/build manifests are disclosed, but not
            # represented as if SafeRun parsed their full dependency graph.
            return [{"file": path.relative_to(root).as_posix(), "name": "manifest detected; dependency graph not parsed by this scanner"}], False
    except (ValueError, OSError, UnicodeError, TypeError, AttributeError, ET.ParseError, RecursionError):
        return [], True
    return entries, parsed


def _result(check_id: str, status: str, summary: str, evidence: list[dict[str, Any]] | None = None, started: float | None = None, output: str = "") -> CheckResult:
    title = CATALOG[check_id][0]
    ms = int((time.monotonic() - started) * 1000) if started else 0
    return CheckResult(check_id, title, status, summary, evidence or [], ms, output[:3000])  # type: ignore[arg-type]


def run_static_check(check: PlannedCheck, root: Path, project: DetectedProject) -> CheckResult:
    if not check.selected:
        return _result(check.check_id, "skipped", check.reason)
    started = time.monotonic()
    if check.check_id == "archive.validate":
        return _result(check.check_id, "passed", "Uploaded paths, file count, link handling, and size limits passed validation.", started=started)
    if check.check_id == "project.detect":
        langs = ", ".join(project.languages)
        manifests = ", ".join(project.manifests) or "none found"
        ecosystems = ", ".join(project.ecosystems) or "no known ecosystem manifest"
        return _result(check.check_id, "passed", f"Detected {langs} across {project.file_count} files. Ecosystems: {ecosystems}. Manifests: {manifests}.", started=started)
    if check.check_id == "dependencies.inventory":
        dependencies: list[dict[str, str]] = []
        manifest_bytes = 0
        truncated = False
        manifests_seen = 0

        def add_entries(entries) -> bool:
            nonlocal truncated
            for entry in entries:
                if len(dependencies) >= 500:
                    truncated = True
                    return False
                dependencies.append(entry)
            return True

        for path in _source_files(root):
            is_requirements = path.name.casefold().startswith("requirements") and path.name.casefold().endswith(".txt")
            if path.name not in _DEPENDENCY_FILES and not is_requirements and path.suffix.casefold() not in {".csproj", ".fsproj", ".vbproj"}:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > 1024 * 1024 or manifest_bytes + size > 20 * 1024 * 1024:
                truncated = True
                continue
            manifest_bytes += size
            manifests_seen += 1
            entries, parsed = _parse_dependency_manifest(path, root)
            if not parsed:
                truncated = True
            if not add_entries(entries):
                break
        status = "blocked" if truncated else "passed"
        summary = f"Inspected {manifests_seen} common dependency manifest(s) and listed {len(dependencies)} dependency entries."
        if truncated:
            summary += " Some files could not be fully parsed or the 500-entry / 20 MiB budget was reached; results are partial."
        summary += " Dependency setup, when needed, happens later in the temporary sandbox."
        return _result(check.check_id, status, summary, dependencies, started)
    if check.check_id == "secrets.scan":
        findings: list[dict[str, Any]] = []
        scanned_bytes = 0
        truncated = False
        for path in _source_files(root):
            if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".pyc", ".woff", ".woff2", ".ico"}:
                continue
            try:
                size = path.stat().st_size
                if size > 2 * 1024 * 1024 or scanned_bytes + size > 20 * 1024 * 1024:
                    truncated = True
                    continue
                scanned_bytes += size
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(content.splitlines(), 1):
                for label, pattern, confidence in _SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        secret_value = match.groupdict().get("value")
                        if _is_placeholder_secret(secret_value):
                            continue
                        findings.append({"file": path.relative_to(root).as_posix(), "line": line_no, "kind": label, "confidence": confidence})
                        break
                if len(findings) >= 100:
                    truncated = True
                    break
            if len(findings) >= 100:
                break
        if findings:
            return _result(check.check_id, "failed", f"Found {len(findings)} likely secret pattern(s). Values were not stored or displayed.", findings, started)
        if truncated:
            return _result(check.check_id, "blocked", "No likely secret patterns were found in the scanned portion; the file or byte cap prevented a complete scan.", started=started)
        return _result(check.check_id, "passed", "No likely secret patterns were found in scanned text files.", started=started)
    if check.check_id == "python.syntax":
        errors: list[dict[str, Any]] = []
        skipped = 0
        parsed = 0
        inspected = 0
        parsed_bytes = 0
        deadline = time.monotonic() + 15
        for path in _source_files(root):
            if path.suffix.casefold() not in {".py", ".pyi", ".pyw"}:
                continue
            try:
                size = path.stat().st_size
                inspected += 1
                if size > 256 * 1024 or parsed_bytes + size > 12 * 1024 * 1024 or inspected > 500 or time.monotonic() > deadline:
                    skipped += 1
                    continue
                parsed_bytes += size
                ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=path.name)
                parsed += 1
            except SyntaxError as exc:
                errors.append({"file": path.relative_to(root).as_posix(), "line": exc.lineno or 1, "message": (exc.msg or "Invalid syntax")[:180]})
            except (RecursionError, MemoryError, ValueError):
                skipped += 1
            except OSError:
                skipped += 1
        if errors:
            return _result(check.check_id, "failed", f"Found {len(errors)} Python syntax error(s). Project code was not executed.", errors[:100], started)
        if skipped:
            return _result(check.check_id, "blocked", f"Parsed Python files without executing them; {skipped} large or unreadable file(s) were skipped.", started=started)
        if not parsed:
            return _result(check.check_id, "skipped", "No Python source files were found to parse.", started=started)
        return _result(check.check_id, "passed", f"Parsed {parsed} Python source file(s) without importing or executing project code.", started=started)
    if check.check_id == "node.syntax":
        node = _find_node()
        if not node:
            return _result(check.check_id, "blocked", "Node.js is unavailable here, so JavaScript syntax parsing was not run.", started=started)
        all_files = list(_source_files(root))
        files = [p for p in all_files if p.suffix in {".js", ".mjs", ".cjs"}]
        unsupported = sum(1 for p in all_files if p.suffix in {".jsx", ".ts", ".tsx", ".mts", ".cts"})
        if not files:
            return _result(check.check_id, "skipped", "No plain JavaScript source files were found; JSX and TypeScript need configured project tooling.", started=started)
        errors: list[dict[str, Any]] = []
        skipped = unsupported
        deadline = time.monotonic() + 30
        for path in files[:100]:
            if time.monotonic() >= deadline or path.stat().st_size > 1024 * 1024:
                skipped += 1
                continue
            try:
                process = subprocess.run([node, "--check", str(path)], capture_output=True, text=True, timeout=min(3, max(0.1, deadline - time.monotonic())), check=False)
            except subprocess.TimeoutExpired:
                skipped += 1
                continue
            if process.returncode:
                output = (process.stderr or process.stdout).strip().splitlines()
                errors.append({"file": path.relative_to(root).as_posix(), "line": 1, "message": (output[-1] if output else "Syntax error")[:180]})
        if len(files) > 100:
            skipped += len(files) - 100
        if errors:
            return _result(check.check_id, "failed", f"Found {len(errors)} JavaScript syntax error(s). Node syntax-only mode was used.", errors[:100], started)
        if skipped:
            return _result(check.check_id, "blocked", f"JavaScript syntax parsed, but {skipped} TypeScript, JSX, or over-limit file(s) were not checked by this parser.", started=started)
        return _result(check.check_id, "passed", f"Parsed {len(files)} JavaScript file(s) in Node syntax-only mode.", started=started)
    return _result(check.check_id, "skipped", "No static adapter is registered for this check.", started=started)


def _find_node() -> str | None:
    return shutil.which("node")

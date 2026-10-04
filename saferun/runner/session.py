from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from saferun.config import Settings
from saferun.models import DetectedProject, PlannedCheck

_IMAGES = {"python": "python:3.13-slim", "node": "node:24-alpine"}
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SAFE_TAIL = re.compile(
    r"\s*(?:(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+(?:\s*,\s*(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+)*)?"
    r"(?:\s*;\s*[A-Za-z0-9_. '\"=!<>&|()+-]+)?\s*"
)
_PYTHON_PROJECT_COPY = r"""import os, shutil
src='/workspace'; dst='/deps/project'; skips={'.git','node_modules','.venv','venv','__pycache__'}
for current, dirs, names in os.walk(src, followlinks=False):
    dirs[:] = sorted(d for d in dirs if d.casefold() not in skips and not os.path.islink(os.path.join(current,d)))
    for name in sorted(names):
        source=os.path.join(current,name)
        if os.path.islink(source) or not os.path.isfile(source): continue
        relative=os.path.relpath(source,src); target=os.path.normpath(os.path.join(dst,relative))
        if os.path.commonpath((dst,target)) != dst: raise ValueError('unsafe path')
        os.makedirs(os.path.dirname(target),exist_ok=True); shutil.copyfile(source,target)
"""
_NODE_PROJECT_COPY = r"""const fs=require('fs'),path=require('path'),src='/workspace',dst='/deps/project',skips=new Set(['.git','node_modules','.venv','venv','__pycache__']);
function copy(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){if(entry.isSymbolicLink())continue;const from=path.join(dir,entry.name),rel=path.relative(src,from),to=path.resolve(dst,rel);if(to!==dst&&!to.startsWith(dst+path.sep))throw Error('unsafe path');if(entry.isDirectory()){if(!skips.has(entry.name.toLowerCase())){fs.mkdirSync(to,{recursive:true});copy(from)}}else if(entry.isFile()){fs.mkdirSync(path.dirname(to),{recursive:true});fs.copyFileSync(from,to)}}}
fs.mkdirSync(dst,{recursive:true});copy(src);
"""


@dataclass
class SandboxSession:
    binary: str
    container: str
    ecosystem: str
    ready: bool = False
    project_dependencies_ready: bool = False
    tools_ready: bool = False
    typecheck_ready: bool = True
    frameworks: list[str] | None = None
    message: str = ""
    closed: bool = False


def _sandbox_user() -> str | None:
    if os.name == "nt":
        return "65534:65534"
    uid = os.getuid()
    if uid == 0:
        return None
    return f"{uid}:{os.getgid()}"


def _bounded_command(args: list[str], timeout: int, output_limit: int) -> tuple[int | None, str, bool]:
    """Run a fixed Docker client invocation while keeping captured output bounded."""
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, str(exc)[:1000], False
    assert process.stdout is not None and process.stderr is not None
    stdout: list[bytes] = []
    stderr: list[bytes] = []
    lock = threading.Lock()

    def read(pipe, target: list[bytes]) -> None:
        used = 0
        while chunk := pipe.read(8192):
            with lock:
                remaining = max(0, output_limit // 2 - used)
                if remaining:
                    target.append(chunk[:remaining])
                    used += min(len(chunk), remaining)

    out_thread = threading.Thread(target=read, args=(process.stdout, stdout), daemon=True)
    err_thread = threading.Thread(target=read, args=(process.stderr, stderr), daemon=True)
    out_thread.start()
    err_thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    out_thread.join(timeout=3)
    err_thread.join(timeout=3)
    output = b"".join(stdout + stderr).decode("utf-8", errors="replace")
    return process.returncode, output, timed_out


def _docker_executable() -> str | None:
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


def _ensure_image(binary: str, image: str) -> tuple[bool, str]:
    code, output, timed_out = _bounded_command([binary, "version", "--format", "{{.Server.Version}}"], 10, 4000)
    if timed_out or code != 0:
        return False, "Docker Desktop is not responding. Start Docker and retry the scan."
    code, output, timed_out = _bounded_command([binary, "image", "inspect", "--format", "{{.Id}}", image], 12, 4000)
    if not timed_out and code == 0:
        return True, ""
    code, output, timed_out = _bounded_command([binary, "pull", image], 300, 6000)
    if timed_out:
        return False, "The free local runner image download timed out. Check the connection and retry."
    if code != 0:
        return False, "SafeRun could not download the free runner image from Docker Hub. Check Docker's internet access and retry."
    return True, ""


def _collect_python_dependencies(root: Path) -> tuple[list[str], bool]:
    requirements: dict[str, str] = {}
    unsupported = False

    def add(value: object) -> None:
        nonlocal unsupported
        if not isinstance(value, str):
            unsupported = True
            return
        line = value.split("#", 1)[0].strip()
        if not line:
            return
        if line.startswith(("-", ".", "/")) or "\\" in line or "@" in line or "://" in line:
            unsupported = True
            return
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?)(.*)", line)
        if not match or not _SAFE_TAIL.fullmatch(match.group(2)):
            unsupported = True
            return
        name = match.group(1)
        if not _SAFE_NAME.fullmatch(name.split("[", 1)[0]):
            unsupported = True
            return
        requirements[name.casefold()] = line

    requirement_files_all = sorted(
        (path for path in root.glob("requirements*.txt") if path.is_file() and not path.is_symlink()),
        key=lambda path: path.name.casefold(),
    )
    if len(requirement_files_all) > 20:
        unsupported = True
    requirement_files = requirement_files_all[:20]
    for path in requirement_files:
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 1024 * 1024:
                unsupported = True
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                add(line)
        except OSError:
            unsupported = True

    pipfile = root / "Pipfile"
    if pipfile.is_file():
        try:
            import tomllib
            if pipfile.stat().st_size > 1024 * 1024:
                unsupported = True
            else:
                data = tomllib.loads(pipfile.read_text(encoding="utf-8", errors="replace"))
                for source in data.get("source", []):
                    if not isinstance(source, dict):
                        unsupported = True
                        continue
                    source_url = urlparse(str(source.get("url", "")))
                    if source_url.scheme != "https" or source_url.hostname != "pypi.org" or source_url.path.rstrip("/") != "/simple":
                        unsupported = True
                for section in ("packages", "dev-packages"):
                    packages = data.get(section, {})
                    if not isinstance(packages, dict):
                        unsupported = True
                        continue
                    for name, value in packages.items():
                        if isinstance(value, str):
                            if value == "*":
                                add(str(name))
                            elif value.startswith(("==", ">=", "<=", "!=", "~=", "<", ">")):
                                add(f"{name}{value}")
                            elif re.fullmatch(r"[0-9][A-Za-z0-9.*+_-]*", value):
                                add(f"{name}=={value}")
                            else:
                                unsupported = True
                        elif isinstance(value, dict) and value.get("version") in {None, "*"}:
                            extras = value.get("extras", [])
                            package_name = f"{name}[{','.join(extras)}]" if isinstance(extras, list) and extras else str(name)
                            add(package_name)
                        else:
                            unsupported = True
        except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
            unsupported = True
    elif (root / "Pipfile.lock").is_file():
        unsupported = True

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            import tomllib

            if pyproject.stat().st_size > 1024 * 1024:
                unsupported = True
            else:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8", errors="replace"))
                project = data.get("project", {})
                if isinstance(project, dict):
                    for dep in project.get("dependencies", []):
                        add(dep)
                    optional = project.get("optional-dependencies", {})
                    if isinstance(optional, dict):
                        for group in optional.values():
                            if isinstance(group, list):
                                for dep in group:
                                    add(dep)
                            else:
                                unsupported = True
                poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool", {}), dict) else {}
                poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
                if isinstance(poetry_deps, dict) and not (root / "poetry.lock").is_file():
                    for name, value in poetry_deps.items():
                        if str(name).casefold() == "python":
                            continue
                        if isinstance(value, str):
                            add(f"{name}{value if value.startswith(('==', '>=', '<=', '!=', '~=', '<', '>')) else ''}")
                            if value and not value.startswith(("==", ">=", "<=", "!=", "~=", "<", ">")):
                                unsupported = True
                        elif isinstance(value, dict) and isinstance(value.get("version"), str):
                            version = value["version"]
                            if version.startswith(("==", ">=", "<=", "!=", "~=", "<", ">")):
                                add(f"{name}{version}")
                            else:
                                unsupported = True
                        elif isinstance(value, dict):
                            unsupported = True
                        else:
                            unsupported = True
        except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
            unsupported = True
    poetry_lock = root / "poetry.lock"
    if poetry_lock.is_file():
        try:
            import tomllib
            if poetry_lock.stat().st_size > 5 * 1024 * 1024:
                unsupported = True
            else:
                lock_data = tomllib.loads(poetry_lock.read_text(encoding="utf-8", errors="replace"))
                packages = lock_data.get("package", [])
                if not isinstance(packages, list):
                    unsupported = True
                else:
                    for package in packages[:500]:
                        if not isinstance(package, dict) or not isinstance(package.get("name"), str) or not isinstance(package.get("version"), str):
                            unsupported = True
                            continue
                        source = package.get("source")
                        if isinstance(source, dict):
                            source_type = str(source.get("type", ""))
                            source_url = urlparse(str(source.get("url", "")))
                            if source_type not in {"legacy", "registry"} or (source_url.hostname and source_url.hostname not in {"pypi.org", "www.pypi.org"}):
                                unsupported = True
                                continue
                        add(f"{package['name']}=={package['version']}")
                    if len(packages) > 500:
                        unsupported = True
        except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
            unsupported = True
    if len(requirements) > 200:
        unsupported = True
    return list(requirements.values())[:200], unsupported


def _node_manifest_safe(root: Path) -> bool:
    manifest = root / "package.json"
    if not manifest.is_file():
        return not any((root / name).exists() for name in ("package-lock.json", "npm-shrinkwrap.json"))
    if manifest.stat().st_size > 2 * 1024 * 1024:
        return False
    try:
        package = json.loads(manifest.read_text(encoding="utf-8"))
        if not isinstance(package, dict):
            return False
        manager = str(package.get("packageManager", "")).split("@", 1)[0].casefold()
        if manager in {"pnpm", "yarn", "bun"} or any((root / name).exists() for name in ("pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")):
            return False
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            values = package.get(section, {})
            if not isinstance(values, dict):
                return False
            if any(str(value).startswith(("file:", "git+", "git:", "github:", "https:", "http:")) for value in values.values()):
                return False
            if any(str(value).startswith("workspace:") for value in values.values()):
                return False
        for section in ("overrides", "resolutions"):
            overrides = package.get(section, {})
            if isinstance(overrides, dict):
                values = json.dumps(overrides).casefold()
                if any(marker in values for marker in ("https:", "http:", "git+", "github:", "file:", "workspace:")):
                    return False
        lock = root / "package-lock.json"
        shrinkwrap = root / "npm-shrinkwrap.json"
        lock_path = lock if lock.is_file() else shrinkwrap if shrinkwrap.is_file() else None
        if lock_path and lock_path.stat().st_size <= 5 * 1024 * 1024:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
            def safe_registry_references(value: object) -> bool:
                if isinstance(value, dict):
                    for key, item in value.items():
                        if key == "resolved" and isinstance(item, str):
                            parsed = urlparse(item)
                            if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org":
                                return False
                        if key == "from" and isinstance(item, str) and re.match(r"(?i)^(?:https?|git\+|git:|ssh:|file:|github:)", item):
                            parsed = urlparse(item)
                            if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org":
                                return False
                        if not safe_registry_references(item):
                            return False
                elif isinstance(value, list):
                    return all(safe_registry_references(item) for item in value)
                return True
            return safe_registry_references(data)
        if lock_path:
            return False
        return True
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return False


def _node_declares_typescript(root: Path) -> bool:
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        return any(
            "typescript" in package.get(section, {})
            for section in ("dependencies", "devDependencies", "optionalDependencies")
            if isinstance(package.get(section, {}), dict)
        )
    except (OSError, UnicodeError, ValueError, TypeError):
        return False


def _node_has_declared_dependencies(root: Path) -> bool:
    """Whether package.json declares packages that need registry preparation."""
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        return any(
            bool(package.get(section, {}))
            for section in ("dependencies", "devDependencies", "optionalDependencies")
            if isinstance(package.get(section, {}), dict)
        )
    except (OSError, UnicodeError, ValueError, TypeError):
        return False


def start_sandbox_session(
    root: Path,
    project: DetectedProject,
    settings: Settings,
    scan_id: str,
    ecosystem: str,
    check_ids: set[str],
) -> SandboxSession:
    binary = _docker_executable()
    if not binary:
        return SandboxSession("", "", ecosystem, message="Docker CLI was not found. SafeRun did not install anything on the host or run project commands there.")
    user = _sandbox_user()
    if user is None:
        return SandboxSession(binary, "", ecosystem, message="SafeRun is running as root. Start it as a regular user so the sandbox can run as non-root.")
    image = _IMAGES[ecosystem]
    available, message = _ensure_image(binary, image)
    if not available:
        return SandboxSession(binary, "", ecosystem, message=message)
    root = root.resolve()
    if "," in str(root):
        return SandboxSession(binary, "", ecosystem, message="The temporary source path cannot be safely represented in Docker mount syntax.")
    container = "saferun-" + re.sub(r"[^a-zA-Z0-9_.-]", "", scan_id[:24]) + "-" + ecosystem
    uid, gid = user.split(":", 1)
    keepalive = ["python", "-I", "-c", "import time; time.sleep(86400)"] if ecosystem == "python" else ["node", "-e", "setInterval(()=>{}, 3600000)"]
    source = str(root).replace("\\", "/")
    args = [
        binary, "run", "--detach", "--pull=never", "--log-driver=none", "--label", "com.saferun.managed=true", "--name", container,
        "--network=bridge", "--cpus=1", "--memory=1g", "--memory-swap=1g", "--pids-limit=128",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs", f"/deps:rw,nosuid,size=512m,uid={uid},gid={gid}",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", user,
        "--env", "HOME=/tmp/home", "--env", "PIP_CONFIG_FILE=/dev/null", "--env", "PIP_NO_INPUT=1",
        "--env", "PIP_CACHE_DIR=/tmp/pip-cache", "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--env", "PYTHONPYCACHEPREFIX=/tmp/pycache",
        "--env", "npm_config_cache=/tmp/npm-cache", "--env", "npm_config_registry=https://registry.npmjs.org",
        "--mount", f"type=bind,source={source},target=/workspace,readonly", "--workdir", "/tmp",
        image, *keepalive,
    ]
    code, _, timed_out = _bounded_command(args, 30, 4000)
    session = SandboxSession(binary, container, ecosystem, frameworks=project.frameworks, message="Docker could not start the restricted container." if timed_out or code != 0 else "")
    if session.message:
        return session

    copy_project = ["python", "-I", "-c", _PYTHON_PROJECT_COPY] if ecosystem == "python" else ["node", "-e", _NODE_PROJECT_COPY]
    code, _, timed_out = _bounded_command([binary, "exec", "--workdir", "/tmp", container, *copy_project], 60, settings.output_limit)
    if timed_out or code != 0:
        session.message = "SafeRun could not create the bounded temporary project copy. No project checks ran."
        _stop_session(session, settings)
        return session

    if ecosystem == "python":
        has_python_tests = any(check_id == "python.tests" or check_id.startswith("python.tests.") for check_id in check_ids)
        tooling = ["pytest"] if has_python_tests else []
        if "python.ruff" in check_ids:
            tooling.append("ruff")
        if "python.mypy" in check_ids:
            tooling.append("mypy")
        if tooling:
            code, _, timed_out = _bounded_command(
                [binary, "exec", "--workdir", "/tmp", container, "python", "-I", "-m", "pip", "install", "--upgrade", "--disable-pip-version-check", "--no-cache-dir", "--only-binary=:all:", "--target", "/deps/python", "--index-url", "https://pypi.org/simple", *tooling],
                240, settings.output_limit,
            )
            if timed_out:
                session.message = "The checker tool download timed out. SafeRun stopped the setup container."
                _stop_session(session, settings)
                return session
            session.tools_ready = code == 0
        else:
            session.tools_ready = True
        if not (has_python_tests or "python.mypy" in check_ids):
            session.project_dependencies_ready = True
        else:
            requirements, unsupported = _collect_python_dependencies(root)
            if unsupported:
                session.project_dependencies_ready = False
                session.message = "Some Python dependency declarations use URLs, local paths, or unsupported options. SafeRun skipped those installs for safety."
            elif not requirements:
                session.project_dependencies_ready = True
            else:
                code, _, timed_out = _bounded_command(
                    [binary, "exec", "--workdir", "/tmp", container, "python", "-I", "-m", "pip", "install", "--upgrade", "--disable-pip-version-check", "--no-cache-dir", "--only-binary=:all:", "--target", "/deps/python", "--index-url", "https://pypi.org/simple", *requirements],
                    240, settings.output_limit,
                )
                if timed_out:
                    session.message = "The Python dependency download timed out. SafeRun stopped the setup container."
                    _stop_session(session, settings)
                    return session
                session.project_dependencies_ready = code == 0
                if not session.project_dependencies_ready:
                    session.message = "SafeRun could not prepare every declared Python dependency as a prebuilt wheel from public PyPI. No project check has run yet."
    else:
        safe_manifest = _node_manifest_safe(root)
        if not safe_manifest:
            session.project_dependencies_ready = False
            session.message = "The Node dependencies include a non-public URL, local path, unsupported lockfile, or invalid package manifest. SafeRun skipped installation for safety."
        elif not _node_has_declared_dependencies(root):
            # Node's built-in test runner and many project scripts need no npm
            # packages. Avoid a registry request for projects like the demo.
            session.project_dependencies_ready = True
        else:
            script = (
                "rm -f /deps/project/.npmrc && cd /deps/project && "
                "if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then "
                "npm ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org --userconfig=/dev/null --globalconfig=/dev/null; "
                "else npm install --package-lock=false --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org --userconfig=/dev/null --globalconfig=/dev/null; fi"
            )
            code, _, timed_out = _bounded_command([binary, "exec", "--workdir", "/tmp", container, "sh", "-c", script], 240, settings.output_limit)
            if timed_out:
                session.message = "The Node dependency download timed out. SafeRun stopped the setup container."
                _stop_session(session, settings)
                return session
            session.project_dependencies_ready = not timed_out and code == 0
            if not session.project_dependencies_ready:
                session.message = "SafeRun could not prepare Node dependencies from the public npm registry. No project check has run yet."
        if session.project_dependencies_ready and "node.typecheck" in check_ids and not _node_declares_typescript(root):
            code, _, timed_out = _bounded_command(
                [binary, "exec", "--workdir", "/tmp", container, "npm", "install", "--prefix", "/deps/project", "--no-save", "--package-lock=false", "--ignore-scripts", "--no-audit", "--no-fund", "--registry=https://registry.npmjs.org", "--userconfig=/dev/null", "--globalconfig=/dev/null", "typescript"],
                240, settings.output_limit,
            )
            if timed_out:
                session.message = "The TypeScript checker download timed out. SafeRun stopped the setup container."
                _stop_session(session, settings)
                return session
            session.typecheck_ready = code == 0
            if not session.typecheck_ready:
                session.message = "SafeRun could not prepare the TypeScript checker from the public npm registry."
        session.tools_ready = session.project_dependencies_ready

    # Setup is the only phase allowed to reach a package registry. Verify that
    # Docker removed every network from the disposable container before checks.
    code, _, timed_out = _bounded_command([binary, "network", "disconnect", "bridge", container], 12, 3000)
    inspect_code, networks, inspect_timeout = _bounded_command([binary, "inspect", "--format", "{{json .NetworkSettings.Networks}}", container], 12, 3000)
    if timed_out or code != 0 or inspect_timeout or inspect_code != 0 or networks.strip() not in {"{}", "null"}:
        session.message = "SafeRun could not confirm network isolation after dependency setup. Project checks were not run."
        _stop_session(session, settings)
        return session
    session.ready = True
    return session


def run_in_sandbox(
    check: PlannedCheck,
    root: Path,
    project: DetectedProject,
    session: SandboxSession,
    settings: Settings,
) -> tuple[int | None, str, bool, str]:
    if session.closed:
        return None, "", False, "The isolated container is no longer running."
    if not session.ready:
        return None, "", False, session.message or "The isolated sandbox could not be prepared."
    if session.ecosystem == "python":
        if (check.check_id.startswith("python.tests") or check.check_id in {"python.ruff", "python.mypy"}) and not session.tools_ready:
            return None, "", False, "SafeRun could not install the requested Python test/check tools as prebuilt public wheels."
        if (check.check_id == "python.mypy" or check.check_id == "python.tests" or check.check_id.startswith("python.tests.")) and not session.project_dependencies_ready:
            return None, "", False, session.message or "Project dependencies were not safely available in the offline sandbox."
    elif not session.project_dependencies_ready:
        return None, "", False, session.message or "Node dependencies were not safely available in the offline sandbox."
    if check.check_id == "node.typecheck" and not session.typecheck_ready:
        return None, "", False, session.message or "The TypeScript checker was not available in the offline sandbox."
    command = {
        "python.tests": ["python", "-m", "pytest", "-q"],
        "python.ruff": ["python", "-m", "ruff", "check", "."],
        "python.mypy": ["python", "-m", "mypy", "."],
        "node.test": ["npm", "test"],
        "node.lint": ["npm", "run", "lint"],
        "node.typecheck": ["tsc", "--noEmit"],
        "node.build": ["npm", "run", "build"],
    }.get(check.check_id)
    if check.check_id.startswith("python.tests."):
        category = check.check_id.rsplit(".", 1)[-1]
        folders = {
            "unit": ("tests/unit", "test/unit", "unit_tests", "unit-tests"),
            "integration": ("tests/integration", "test/integration", "integration_tests", "integration-tests"),
            "system": ("tests/system", "test/system", "system_tests", "system-tests"),
            "e2e": ("tests/e2e", "test/e2e", "tests/acceptance", "acceptance_tests", "e2e"),
        }.get(category, ())
        folder = next((candidate for candidate in folders if (root / candidate).is_dir()), None)
        command = ["python", "-m", "pytest", "-q", folder] if folder else None
    elif check.check_id.startswith("node.test."):
        category = check.check_id.rsplit(".", 1)[-1]
        script = f"test:{category}"
        if category == "e2e" and script not in project.package_scripts and "test:acceptance" in project.package_scripts:
            script = "test:acceptance"
        command = ["npm", "run", script] if category in {"unit", "integration", "system", "e2e"} else None
    if command is None:
        return None, "", False, "No sandbox adapter is registered for this check."
    exec_args = [session.binary, "exec", "--workdir", "/deps/project"]
    if session.ecosystem == "python":
        exec_args.extend([
            "--env", "PYTHONPATH=/deps/python:/deps/project",
            "--env", "PATH=/deps/python/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ])
    else:
        exec_args.extend([
            "--env", "NODE_PATH=/deps/project/node_modules",
            "--env", "PATH=/deps/project/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ])
    return_code, output, timed_out = _bounded_command(
        [*exec_args, session.container, *command], settings.check_timeout_seconds, settings.output_limit,
    )
    if timed_out:
        _stop_session(session, settings)
    return return_code, output, timed_out, ""


def _stop_session(session: SandboxSession, settings: Settings) -> bool:
    if not session.binary or not session.container:
        session.closed = True
        return True
    code, _, timed_out = _bounded_command([session.binary, "rm", "-f", session.container], 12, 3000)
    if not timed_out and code == 0:
        session.closed = True
        return True
    inspect, output, inspect_timeout = _bounded_command([session.binary, "inspect", session.container], 8, 3000)
    absent = inspect != 0 and any(x in output.casefold() for x in ("no such object", "no such container", "not found"))
    session.closed = absent
    return absent


def close_sandbox_session(session: SandboxSession, settings: Settings) -> bool:
    return _stop_session(session, settings)


def cleanup_managed_sandboxes() -> bool:
    """Remove SafeRun containers left behind if the app was interrupted."""
    binary = _docker_executable()
    if not binary:
        return False
    code, output, timed_out = _bounded_command(
        [binary, "ps", "--all", "--quiet", "--filter", "label=com.saferun.managed=true"], 12, 16 * 1024,
    )
    if timed_out or code != 0:
        return False
    for container in output.split():
        code, _, timed_out = _bounded_command([binary, "rm", "--force", container], 12, 3000)
        if timed_out or code != 0:
            return False
    return True

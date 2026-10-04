from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

from saferun.models import DetectedProject

_SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build",
    "target", "vendor", "coverage", ".next", ".nuxt", ".angular", ".gradle",
    ".idea", ".terraform", ".mypy_cache", ".pytest_cache", ".ruff_cache",
}
_MANIFESTS = {
    "pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "Pipfile.lock",
    "poetry.lock", "uv.lock", "setup.py", "setup.cfg", "package.json", "package-lock.json",
    "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "tsconfig.json",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts", "Gemfile", "Gemfile.lock", "composer.json",
    "composer.lock", "pubspec.yaml", "pubspec.lock", "mix.exs", "mix.lock", "Package.swift",
    "Package.resolved", "CMakeLists.txt", "Makefile", "meson.build", "Dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "compose.yml", "compose.yaml", "terraform.tf", "build.sbt", "project.clj",
    "deps.edn", "Project.toml", "environment.yml", "environment.yaml", "renv.lock", "flake.nix",
    "stack.yaml",
}
_LANGUAGE_EXTENSIONS = {
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".cs": "C#", ".csx": "C#",
    ".rb": "Ruby", ".php": "PHP", ".cpp": "C++", ".cxx": "C++", ".cc": "C++",
    ".c++": "C++", ".hpp": "C++", ".hxx": "C++", ".hh": "C++", ".h": "C/C++",
    ".c": "C", ".m": "Objective-C", ".mm": "Objective-C++", ".swift": "Swift",
    ".kt": "Kotlin", ".kts": "Kotlin", ".dart": "Dart", ".ex": "Elixir", ".exs": "Elixir",
    ".hs": "Haskell", ".lhs": "Haskell", ".lua": "Lua", ".pl": "Perl", ".pm": "Perl",
    ".r": "R", ".jl": "Julia", ".scala": "Scala", ".sc": "Scala", ".clj": "Clojure",
    ".cljs": "ClojureScript", ".cljc": "Clojure", ".sh": "Shell", ".bash": "Shell",
    ".zsh": "Shell", ".sql": "SQL", ".html": "HTML", ".htm": "HTML", ".css": "CSS",
    ".scss": "SCSS", ".vue": "Vue", ".svelte": "Svelte", ".sol": "Solidity",
    ".tf": "Terraform / HCL", ".proto": "Protocol Buffers", ".f": "Fortran", ".for": "Fortran",
    ".f90": "Fortran", ".f95": "Fortran", ".sv": "SystemVerilog", ".vhd": "VHDL",
    ".vhdl": "VHDL", ".zig": "Zig", ".nim": "Nim", ".ml": "OCaml", ".mli": "OCaml",
    ".fs": "F#", ".fsi": "F#", ".asm": "Assembly", ".s": "Assembly", ".ipynb": "Jupyter Notebook",
}
_MANIFEST_ECOSYSTEMS = {
    "pyproject.toml": "Python", "requirements.txt": "Python", "requirements-dev.txt": "Python",
    "Pipfile": "Python", "Pipfile.lock": "Python", "poetry.lock": "Python", "uv.lock": "Python",
    "setup.py": "Python", "setup.cfg": "Python", "package.json": "Node.js", "package-lock.json": "Node.js",
    "npm-shrinkwrap.json": "Node.js", "pnpm-lock.yaml": "Node.js", "yarn.lock": "Node.js", "bun.lock": "Node.js",
    "bun.lockb": "Node.js", "tsconfig.json": "TypeScript", "Cargo.toml": "Rust / Cargo", "Cargo.lock": "Rust / Cargo",
    "go.mod": "Go modules", "go.sum": "Go modules", "pom.xml": "Java / Maven", "build.gradle": "Java / Gradle",
    "build.gradle.kts": "JVM / Gradle", "settings.gradle": "JVM / Gradle", "settings.gradle.kts": "JVM / Gradle",
    "Gemfile": "Ruby / Bundler", "Gemfile.lock": "Ruby / Bundler", "composer.json": "PHP / Composer",
    "composer.lock": "PHP / Composer", "pubspec.yaml": "Dart / Flutter", "pubspec.lock": "Dart / Flutter",
    "mix.exs": "Elixir / Mix", "mix.lock": "Elixir / Mix", "Package.swift": "Swift / Swift Package Manager",
    "Package.resolved": "Swift / Swift Package Manager", "CMakeLists.txt": "C / C++ / CMake",
    "Makefile": "Make", "meson.build": "C / C++ / Meson", "Dockerfile": "Docker / containerized app",
    "docker-compose.yml": "Docker Compose", "docker-compose.yaml": "Docker Compose",
    "compose.yml": "Docker Compose", "compose.yaml": "Docker Compose", "build.sbt": "JVM / SBT",
    "project.clj": "Clojure / Leiningen", "deps.edn": "Clojure CLI", "Project.toml": "Julia",
    "environment.yml": "Conda", "environment.yaml": "Conda", "renv.lock": "R / renv", "flake.nix": "Nix",
}
_MANIFEST_LANGUAGES = {
    "pyproject.toml": "Python", "Pipfile": "Python", "Pipfile.lock": "Python", "poetry.lock": "Python",
    "uv.lock": "Python", "setup.py": "Python", "setup.cfg": "Python", "environment.yml": "Python",
    "environment.yaml": "Python", "package.json": "JavaScript", "package-lock.json": "JavaScript",
    "npm-shrinkwrap.json": "JavaScript", "pnpm-lock.yaml": "JavaScript", "yarn.lock": "JavaScript",
    "bun.lock": "JavaScript", "bun.lockb": "JavaScript", "Cargo.toml": "Rust", "Cargo.lock": "Rust",
    "go.mod": "Go", "go.sum": "Go", "pom.xml": "Java", "Gemfile": "Ruby", "Gemfile.lock": "Ruby",
    "composer.json": "PHP", "composer.lock": "PHP", "pubspec.yaml": "Dart", "pubspec.lock": "Dart",
    "mix.exs": "Elixir", "mix.lock": "Elixir", "Package.swift": "Swift", "Package.resolved": "Swift",
    "build.sbt": "Scala", "project.clj": "Clojure", "deps.edn": "Clojure", "Project.toml": "Julia",
    "CMakeLists.txt": "C/C++", "meson.build": "C/C++", "stack.yaml": "Haskell",
}


def _files(root: Path, max_files: int = 5000):
    count = 0
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d.casefold() not in _SKIP_DIRS and not (Path(current) / d).is_symlink())
        depth = len(Path(current).relative_to(root).parts)
        if depth >= 12:
            dirs[:] = []
        for name in sorted(names, key=str.casefold):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            count += 1
            if count > max_files:
                return
            yield path


def _read_manifest(path: Path) -> str:
    try:
        if path.stat().st_size <= 1024 * 1024:
            return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return ""


def detect_project(root: Path) -> DetectedProject:
    files = sorted(_files(root), key=lambda path: path.relative_to(root).as_posix().casefold())
    names = {p.name for p in files}
    rel = [p.relative_to(root).as_posix() for p in files]
    manifests = {name for name in names if name in _MANIFESTS or (name.casefold().startswith("requirements") and name.casefold().endswith(".txt"))}
    manifests.update(name for name in names if name.lower().endswith((".sln", ".csproj", ".fsproj", ".vbproj")))
    manifests.update(name for name in names if name.lower().endswith((".xcodeproj", ".xcworkspace")))
    py_files = [p for p in files if p.suffix.casefold() in {".py", ".pyi", ".pyw"}]
    js_files = [p for p in files if p.suffix.casefold() in {".js", ".mjs", ".cjs", ".jsx"}]
    ts_files = [p for p in files if p.suffix.casefold() in {".ts", ".tsx", ".mts", ".cts"}]
    has_python = bool(py_files or any(path.suffix.casefold() == ".ipynb" for path in files) or any(name.casefold().startswith("requirements") and name.casefold().endswith(".txt") for name in names) or {"pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "uv.lock", "setup.py", "setup.cfg", "environment.yml", "environment.yaml"} & names)
    has_node = bool(js_files or ts_files or {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "tsconfig.json"} & names)
    has_ts = bool(ts_files or "tsconfig.json" in names)

    languages: list[str] = []
    if has_python:
        languages.append("Python")
    if has_node:
        languages.append("TypeScript" if has_ts else "JavaScript")
    for path in files:
        label = _LANGUAGE_EXTENSIONS.get(path.suffix.casefold())
        if label and label not in languages:
            languages.append(label)
    for name in sorted(manifests, key=str.casefold):
        label = _MANIFEST_LANGUAGES.get(name)
        if label == "JavaScript" and has_ts:
            continue
        if label and label not in languages:
            languages.append(label)
    if any(name.lower().endswith((".sln", ".csproj")) for name in names) and "C#" not in languages:
        languages.append("C#")
    if any(name.lower().endswith(".fsproj") for name in names) and "F#" not in languages:
        languages.append("F#")
    if any(name.lower().endswith(".vbproj") for name in names) and "Visual Basic" not in languages:
        languages.append("Visual Basic")
    if not languages:
        languages.append("Unknown / configuration-only")

    ecosystems = {_MANIFEST_ECOSYSTEMS[name] for name in manifests if name in _MANIFEST_ECOSYSTEMS}
    if any(name.casefold().startswith("requirements") and name.casefold().endswith(".txt") for name in names):
        ecosystems.add("Python")
    if "gradlew" in names or "mvnw" in names:
        ecosystems.add("JVM build wrapper")
    if any(name.lower().endswith((".sln", ".csproj", ".fsproj", ".vbproj")) for name in names):
        ecosystems.add(".NET")
    if any(name.lower().endswith((".xcodeproj", ".xcworkspace")) for name in names):
        ecosystems.add("Apple / Xcode")
    if any(path.suffix.casefold() in {".html", ".htm"} for path in files):
        ecosystems.add("Web frontend")

    frameworks: set[str] = set()
    scripts: list[str] = []
    for path in files:
        if path.name == "package.json":
            try:
                data = json.loads(_read_manifest(path))
                if not isinstance(data, dict):
                    continue
                script_data = data.get("scripts", {})
                if path.parent == root and isinstance(script_data, dict):
                    scripts.extend(str(k) for k in script_data if isinstance(k, str))
                deps = {}
                for section in ("dependencies", "devDependencies", "peerDependencies"):
                    section_data = data.get(section, {})
                    if isinstance(section_data, dict):
                        deps.update(section_data)
                for package, framework in (("react", "React"), ("next", "Next.js"), ("vite", "Vite"), ("express", "Express"), ("typescript", "TypeScript"), ("vue", "Vue"), ("svelte", "Svelte"), ("@angular/core", "Angular")):
                    if package in deps:
                        frameworks.add(framework)
            except (ValueError, OSError, UnicodeError, AttributeError, TypeError, RecursionError):
                pass
        elif path.name == "pyproject.toml":
            try:
                data = tomllib.loads(_read_manifest(path))
                text = str(data).casefold()
                for package, framework in (("fastapi", "FastAPI"), ("django", "Django"), ("flask", "Flask"), ("pytest", "pytest"), ("django-ninja", "Django Ninja"), ("pydantic", "Pydantic")):
                    if package in text:
                        frameworks.add(framework)
            except (ValueError, OSError, UnicodeError):
                pass
        elif path.name == "Pipfile" or (path.name.casefold().startswith("requirements") and path.name.casefold().endswith(".txt")):
            text = _read_manifest(path).casefold()
            for package, framework in (("fastapi", "FastAPI"), ("django", "Django"), ("flask", "Flask"), ("pytest", "pytest")):
                if package in text:
                    frameworks.add(framework)

    test_present = any(
        Path(name).name.startswith("test_") or Path(name).name.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts"))
        or "/tests/" in f"/{name.casefold()}/" or "/test/" in f"/{name.casefold()}/"
        for name in rel
    )
    return DetectedProject(
        languages=languages,
        ecosystems=sorted(ecosystems),
        manifests=sorted(manifests, key=str.casefold),
        frameworks=sorted(frameworks),
        file_count=len(files),
        has_python=has_python,
        has_node=has_node,
        has_typescript=has_ts,
        python_files_present=bool(py_files),
        javascript_files_present=bool(js_files),
        typescript_files_present=bool(ts_files),
        package_scripts=sorted(set(scripts)),
        python_tests_present=test_present and has_python,
    )

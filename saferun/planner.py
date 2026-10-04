from __future__ import annotations

from pathlib import Path

from saferun.models import DetectedProject, PlannedCheck

CATALOG = {
    "archive.validate": ("Archive safety", "static"),
    "project.detect": ("Project detection", "static"),
    "dependencies.inventory": ("Dependency inventory", "static"),
    "secrets.scan": ("Likely secret scan", "static"),
    "python.syntax": ("Python syntax", "static"),
    "python.tests": ("Python configured test suite", "sandbox"),
    "python.ruff": ("Ruff lint", "sandbox"),
    "python.mypy": ("Mypy type check", "sandbox"),
    "node.syntax": ("JavaScript syntax", "static"),
    "node.test": ("Node test script", "sandbox"),
    "node.lint": ("Node lint script", "sandbox"),
    "node.typecheck": ("TypeScript check", "sandbox"),
    "node.build": ("Node build script", "sandbox"),
    "python.tests.unit": ("Python unit tests", "sandbox"),
    "python.tests.integration": ("Python integration tests", "sandbox"),
    "python.tests.system": ("Python system tests", "sandbox"),
    "python.tests.e2e": ("Python end-to-end tests", "sandbox"),
    "node.test.unit": ("Node unit test script", "sandbox"),
    "node.test.integration": ("Node integration test script", "sandbox"),
    "node.test.system": ("Node system test script", "sandbox"),
    "node.test.e2e": ("Node end-to-end test script", "sandbox"),
}


TEST_CATEGORIES = ("unit", "integration", "system", "e2e")
PYTHON_TEST_DIRS = {
    "unit": ("tests/unit", "test/unit", "unit_tests", "unit-tests"),
    "integration": ("tests/integration", "test/integration", "integration_tests", "integration-tests"),
    "system": ("tests/system", "test/system", "system_tests", "system-tests"),
    "e2e": ("tests/e2e", "test/e2e", "tests/acceptance", "acceptance_tests", "e2e"),
}


def build_plan(project: DetectedProject, root: Path | None = None, *, full_test_run: bool = False) -> list[PlannedCheck]:
    scripts = set(project.package_scripts)
    checks: list[PlannedCheck] = []

    def add(check_id: str, selected: bool, reason: str, test_category: str | None = None) -> None:
        title, execution = CATALOG[check_id]
        checks.append(PlannedCheck(check_id, title, selected, reason, execution, test_category))

    add("archive.validate", True, "The uploaded ZIP or folder passed path, file-count, and size validation.")
    add("project.detect", True, "SafeRun checks common source files, manifests, frameworks, and project ecosystems across languages.")
    add("dependencies.inventory", True, "Declared dependency manifests are inspected without importing or executing project code.")
    add("secrets.scan", True, "Text files are checked for common committed-secret patterns; findings are redacted.")
    add("python.syntax", project.has_python and project.python_files_present, "Python files are parsed without importing or running project code." if project.python_files_present else "No Python source files were detected." if project.has_python else "No Python project signal was detected.")
    categorized_python_tests = bool(full_test_run and root and any((root / folder).is_dir() for folders in PYTHON_TEST_DIRS.values() for folder in folders))
    python_test_reason = (
        "Full-test mode will run recognized test folders individually to keep the report separated by test type."
        if categorized_python_tests else
        "Test files were detected; dependencies will be prepared in a disposable container, then tests run with networking disabled."
        if project.python_tests_present else "No Python test files were detected." if project.has_python else "No Python project signal was detected."
    )
    add("python.tests", project.has_python and project.python_tests_present and not categorized_python_tests, python_test_reason)
    add("python.ruff", project.python_files_present, "Ruff is fetched as a prebuilt wheel into a disposable container, then runs with networking disabled." if project.python_files_present else "No Python source files were detected." if project.has_python else "No Python project signal was detected.")
    mypy_config = bool(root and any((root / name).exists() for name in ("mypy.ini", ".mypy.ini")))
    if root and (root / "pyproject.toml").is_file():
        try:
            pyproject = root / "pyproject.toml"
            if pyproject.stat().st_size <= 1024 * 1024:
                mypy_config = mypy_config or "[tool.mypy]" in pyproject.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    add("python.mypy", project.python_files_present and mypy_config, "A mypy configuration was detected; execution requires the local sandbox tool." if mypy_config else "No mypy configuration was detected." if project.has_python else "No Python project signal was detected.")
    add("node.syntax", project.javascript_files_present, "JavaScript sources can be parsed with Node's syntax-only mode; TypeScript parsing needs configured project tools." if project.javascript_files_present else "No JavaScript source files were detected." if project.has_node else "No JavaScript or TypeScript project signal was detected.")
    categorized_node_tests = bool(full_test_run and any(f"test:{category}" in scripts for category in TEST_CATEGORIES)) or bool(full_test_run and "test:acceptance" in scripts)
    node_test_reason = (
        "Full-test mode will run recognized test scripts individually to keep the report separated by test type."
        if categorized_node_tests else
        "A test script is declared in package.json; packages install with lifecycle scripts disabled in a disposable container, then tests run offline."
        if "test" in scripts else "No package.json test script was detected." if project.has_node else "No Node project signal was detected."
    )
    add("node.test", project.has_node and "test" in scripts and not categorized_node_tests, node_test_reason)
    add("node.lint", project.has_node and "lint" in scripts, "A lint script is declared in package.json; dependencies are prepared in a disposable container and the check runs offline." if "lint" in scripts else "No package.json lint script was detected." if project.has_node else "No Node project signal was detected.")
    has_tsconfig = bool(root and (root / "tsconfig.json").is_file())
    typecheck_selected = project.typescript_files_present and has_tsconfig
    typecheck_reason = (
        "TypeScript sources and a root tsconfig.json were detected; the registered tsc check runs only in Docker."
        if typecheck_selected else
        "TypeScript sources were detected, but no root tsconfig.json was found; SafeRun skips guessing compiler options."
        if project.typescript_files_present else
        "No TypeScript source files were detected." if project.has_typescript else
        "No TypeScript configuration or sources were detected."
    )
    add("node.typecheck", typecheck_selected, typecheck_reason)
    add("node.build", project.has_node and "build" in scripts, "A build script is declared in package.json and will run only in Docker." if "build" in scripts else "No package.json build script was detected." if project.has_node else "No Node project signal was detected.")

    # The optional full-test mode runs category-specific suites only when the
    # repository declares them using conventional npm script names or folders.
    # It never guesses arbitrary commands from the uploaded source.
    for category in TEST_CATEGORIES:
        py_id = f"python.tests.{category}"
        py_candidates = PYTHON_TEST_DIRS[category]
        py_path = next((candidate for candidate in py_candidates if root and (root / candidate).is_dir()), None)
        py_available = project.has_python and py_path is not None
        py_label = " / ".join(py_candidates[:2])
        py_reason = (
            f"A conventional {category} test folder ({py_path}) was detected; pytest will run only that folder in Docker."
            if py_available else
            f"No recognized Python {category} test folder was detected. SafeRun does not guess which tests belong to this category."
            if project.has_python else "No Python project signal was detected."
        )
        add(py_id, bool(full_test_run and py_available), py_reason, category)

        node_id = f"node.test.{category}"
        node_script = f"test:{category}"
        if category == "e2e" and node_script not in scripts and "test:acceptance" in scripts:
            node_script = "test:acceptance"
        node_available = project.has_node and node_script in scripts
        node_reason = (
            f"The explicit {node_script} script is declared in package.json and will run in Docker."
            if node_available else
            f"No package.json {category} test script was detected (expected {node_script})."
            if project.has_node else "No Node project signal was detected."
        )
        add(node_id, bool(full_test_run and node_available), node_reason, category)
    return checks


def validate_plan(plan: list[PlannedCheck]) -> None:
    for item in plan:
        if item.check_id not in CATALOG or item.execution != CATALOG[item.check_id][1]:
            raise ValueError("Planner produced an unregistered check.")

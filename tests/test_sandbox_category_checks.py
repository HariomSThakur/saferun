from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from saferun.config import Settings
from saferun.models import DetectedProject, PlannedCheck
from saferun.runner.session import SandboxSession, run_in_sandbox


class CategorizedSandboxCommandTests(unittest.TestCase):
    def test_python_category_check_uses_its_detected_folder(self) -> None:
        with tempfile.TemporaryDirectory(prefix="saferun-category-") as temp:
            root = Path(temp)
            (root / "tests" / "integration").mkdir(parents=True)
            check = PlannedCheck("python.tests.integration", "Python integration tests", True, "detected", "sandbox", "integration")
            session = SandboxSession("docker", "container", "python", ready=True, project_dependencies_ready=True, tools_ready=True)
            settings = Settings(root)
            with patch("saferun.runner.session._bounded_command", return_value=(0, "1 passed", False)) as command:
                result = run_in_sandbox(check, root, DetectedProject(has_python=True), session, settings)

        self.assertEqual(result[0], 0)
        self.assertEqual(command.call_args.args[0][-4:], ["-m", "pytest", "-q", "tests/integration"])

    def test_node_category_check_uses_only_the_registered_script_name(self) -> None:
        with tempfile.TemporaryDirectory(prefix="saferun-category-") as temp:
            root = Path(temp)
            check = PlannedCheck("node.test.system", "Node system tests", True, "detected", "sandbox", "system")
            project = DetectedProject(has_node=True, package_scripts=["test:system"])
            session = SandboxSession("docker", "container", "node", ready=True, project_dependencies_ready=True, tools_ready=True)
            settings = Settings(root)
            with patch("saferun.runner.session._bounded_command", return_value=(0, "tests passed", False)) as command:
                result = run_in_sandbox(check, root, project, session, settings)

        self.assertEqual(result[0], 0)
        self.assertEqual(command.call_args.args[0][-4:], ["container", "npm", "run", "test:system"])


if __name__ == "__main__":
    unittest.main()

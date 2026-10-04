import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def run_cli(ledger_file, *arguments):
    environment = os.environ.copy()
    project_root = Path(__file__).resolve().parents[2]
    existing_path = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(project_root) + (os.pathsep + existing_path if existing_path else "")
    result = subprocess.run(
        [sys.executable, "-m", "pocketledger.cli", "--file", str(ledger_file), *arguments],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
        env=environment,
        timeout=10,
    )
    return result


class LedgerSystemTests(unittest.TestCase):
    def test_cli_add_command_persists_a_valid_entry(self):
        with tempfile.TemporaryDirectory(prefix="pocketledger-") as temp:
            ledger_file = Path(temp) / "ledger.json"
            result = run_cli(ledger_file, "add", "Notebook", "-325")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Added Notebook: -325 cents", result.stdout)
            self.assertEqual(json.loads(ledger_file.read_text(encoding="utf-8")), [
                {"description": "Notebook", "amount_cents": -325},
            ])

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def invoke(project_root, ledger_file, *arguments):
    environment = os.environ.copy()
    existing_path = environment.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = str(project_root) + (os.pathsep + existing_path if existing_path else "")
    return subprocess.run(
        [sys.executable, "-m", "pocketledger.cli", "--file", str(ledger_file), *arguments],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


class LedgerEndToEndTests(unittest.TestCase):
    def test_user_can_add_list_and_check_balance(self):
        project_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="pocketledger-") as temp:
            ledger_file = Path(temp) / "ledger.json"

            first = invoke(project_root, ledger_file, "add", "Allowance", "5000")
            second = invoke(project_root, ledger_file, "add", "Lunch", "-850")
            listing = invoke(project_root, ledger_file, "list")
            total = invoke(project_root, ledger_file, "balance")

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(listing.returncode, 0, listing.stderr)
            self.assertEqual(total.returncode, 0, total.stderr)
            self.assertIn("Allowance: 5000 cents", listing.stdout)
            self.assertIn("Lunch: -850 cents", listing.stdout)
            self.assertEqual(total.stdout.strip(), "Balance: 4150 cents")

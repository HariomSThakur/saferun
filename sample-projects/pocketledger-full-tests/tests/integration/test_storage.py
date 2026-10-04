import json
import tempfile
import unittest
from pathlib import Path

from pocketledger.ledger import add_entry
from pocketledger.store import load_entries, save_entries


class LedgerIntegrationTests(unittest.TestCase):
    def test_entries_survive_save_and_reload(self):
        with tempfile.TemporaryDirectory(prefix="pocketledger-") as temp:
            ledger_file = Path(temp) / "data" / "ledger.json"
            entries = []
            add_entry(entries, "Train pass", -1200)

            save_entries(ledger_file, entries)

            self.assertEqual(load_entries(ledger_file), entries)
            self.assertEqual(json.loads(ledger_file.read_text(encoding="utf-8"))[0]["description"], "Train pass")

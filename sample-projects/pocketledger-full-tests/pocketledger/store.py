from __future__ import annotations

import json
from pathlib import Path

from .ledger import Entry


def load_entries(path: Path) -> list[Entry]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Ledger file must contain a JSON list.")
    return data


def save_entries(path: Path, entries: list[Entry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    temporary_path.replace(path)

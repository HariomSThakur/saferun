from __future__ import annotations

from typing import TypedDict


class Entry(TypedDict):
    description: str
    amount_cents: int


def normalize_description(value: str) -> str:
    description = " ".join(value.split())
    if not description:
        raise ValueError("Description cannot be empty.")
    if len(description) > 80:
        raise ValueError("Description must be 80 characters or fewer.")
    return description


def add_entry(entries: list[Entry], description: str, amount_cents: int) -> Entry:
    if isinstance(amount_cents, bool) or not isinstance(amount_cents, int) or amount_cents == 0:
        raise ValueError("Amount must be a non-zero number of cents.")
    entry: Entry = {
        "description": normalize_description(description),
        "amount_cents": amount_cents,
    }
    entries.append(entry)
    return entry


def balance(entries: list[Entry]) -> int:
    return sum(entry["amount_cents"] for entry in entries)

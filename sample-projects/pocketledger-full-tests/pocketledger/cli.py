from __future__ import annotations

import argparse
from pathlib import Path

from .ledger import add_entry, balance
from .store import load_entries, save_entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Keep a small local expense ledger.")
    parser.add_argument("--file", type=Path, default=Path("ledger.json"), help="Path to the JSON ledger file.")
    commands = parser.add_subparsers(dest="command", required=True)
    add_command = commands.add_parser("add", help="Add an income or expense in cents.")
    add_command.add_argument("description")
    add_command.add_argument("amount_cents", type=int)
    commands.add_parser("list", help="List saved ledger entries.")
    commands.add_parser("balance", help="Show the current balance in cents.")
    args = parser.parse_args(argv)

    try:
        entries = load_entries(args.file)
        if args.command == "add":
            entry = add_entry(entries, args.description, args.amount_cents)
            save_entries(args.file, entries)
            print(f"Added {entry['description']}: {entry['amount_cents']} cents")
        elif args.command == "list":
            for entry in entries:
                print(f"{entry['description']}: {entry['amount_cents']} cents")
            if not entries:
                print("No entries yet.")
        else:
            print(f"Balance: {balance(entries)} cents")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

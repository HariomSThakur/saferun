from __future__ import annotations

import argparse
import getpass

from saferun.auth import normalize_email, valid_email
from saferun.config import load_settings
from saferun.db import create_user, get_user_by_email, initialize
from saferun.security.passwords import hash_password, validate_password


def create_admin() -> int:
    settings = load_settings()
    initialize(settings)
    email = input("Administrator email: ").strip()
    if not valid_email(email):
        print("Enter a valid email address.")
        return 2
    if get_user_by_email(settings, email):
        print("That account already exists. Admin roles cannot be assigned through this command to existing accounts.")
        return 2
    password = getpass.getpass("Administrator password (12–128 characters): ")
    issue = validate_password(password)
    if issue:
        print(issue)
        return 2
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords did not match.")
        return 2
    create_user(settings, normalize_email(email), hash_password(password), role="admin")
    print("Administrator account created.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="saferun", description="Local SafeRun administration")
    parser.add_subparsers(dest="command", required=True).add_parser("create-admin", help="Create a separate administrator account")
    args = parser.parse_args()
    if args.command == "create-admin":
        raise SystemExit(create_admin())


if __name__ == "__main__":
    main()

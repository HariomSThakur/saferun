from __future__ import annotations

import re

from saferun.config import Settings
from saferun.db import create_user, get_user_by_email, record_login_attempt, too_many_login_attempts
from saferun.security.passwords import hash_password, verify_password

_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def normalize_email(value: str) -> str:
    return value.strip().casefold()


def valid_email(value: str) -> bool:
    email = normalize_email(value)
    return len(email) <= 254 and bool(_EMAIL.fullmatch(email))


def register_user(settings: Settings, email: str, password: str) -> int:
    return create_user(settings, normalize_email(email), hash_password(password), role="user")


def authenticate(settings: Settings, email: str, password: str, *, admin: bool = False):
    normalized = normalize_email(email)
    if too_many_login_attempts(settings, normalized):
        return None, "Too many attempts. Wait 15 minutes before trying again."
    if len(normalized) > 254 or len(password) > 128:
        record_login_attempt(settings, normalized, False)
        return None, "Email or password was not accepted."
    user = get_user_by_email(settings, normalized)
    correct = bool(user and verify_password(str(user["password_hash"]), password))
    allowed = correct and bool(user["active"]) and (str(user["role"]) == "admin" if admin else str(user["role"]) == "user")
    record_login_attempt(settings, normalized, bool(allowed))
    if not allowed:
        return None, "Email or password was not accepted."
    return user, None

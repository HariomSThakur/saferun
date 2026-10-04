from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

from saferun.config import Settings
from saferun.db import connection, transaction


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class Session:
    user_id: int
    email: str
    role: str
    active: bool
    csrf_token: str


def create_session(settings: Settings, user_id: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = int(time.time())
    with transaction(settings) as db:
        db.execute(
            "INSERT INTO sessions(user_id,token_hash,csrf_hash,created_at,last_seen,expires_at) VALUES(?,?,?,?,?,?)",
            (user_id, _hash(token), _hash(csrf), now, now, now + settings.session_absolute_seconds),
        )
    return token, csrf


def get_session(settings: Settings, token: str | None) -> Session | None:
    if not token or len(token) > 256:
        return None
    now = int(time.time())
    digest = _hash(token)
    with connection(settings) as db:
        row = db.execute(
            "SELECT s.*,u.email,u.role,u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
            (digest,),
        ).fetchone()
    if row is None:
        return None
    if not row["active"] or row["expires_at"] <= now or row["last_seen"] + settings.session_idle_seconds <= now:
        revoke_session(settings, token)
        return None
    if now - row["last_seen"] > 60:
        with transaction(settings) as db:
            db.execute("UPDATE sessions SET last_seen=? WHERE id=?", (now, row["id"]))
    return Session(
        user_id=int(row["user_id"]), email=str(row["email"]), role=str(row["role"]),
        active=bool(row["active"]), csrf_token="",
    )


def validate_csrf(settings: Settings, token: str | None, submitted: str | None) -> bool:
    if not token or not submitted or len(submitted) > 256:
        return False
    with connection(settings) as db:
        row = db.execute("SELECT csrf_hash FROM sessions WHERE token_hash=?", (_hash(token),)).fetchone()
        return bool(row and secrets.compare_digest(str(row["csrf_hash"]), _hash(submitted)))


def revoke_session(settings: Settings, token: str | None) -> None:
    if not token:
        return
    with transaction(settings) as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (_hash(token),))


def revoke_user_sessions(settings: Settings, user_id: int) -> None:
    with transaction(settings) as db:
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


def rotate_csrf(settings: Settings, token: str, csrf: str) -> None:
    with transaction(settings) as db:
        db.execute("UPDATE sessions SET csrf_hash=? WHERE token_hash=?", (_hash(csrf), _hash(token)))

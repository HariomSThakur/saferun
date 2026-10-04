from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from saferun.config import Settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(settings: Settings) -> sqlite3.Connection:
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    connection = sqlite3.connect(settings.database, timeout=10, isolation_level=None)
    if os.name != "nt":
        os.chmod(settings.database, 0o600)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def connection(settings: Settings) -> Iterator[sqlite3.Connection]:
    db = connect(settings)
    try:
        yield db
    finally:
        db.close()


def initialize(settings: Settings) -> None:
    schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
    with connection(settings) as db:
        version = int(db.execute("PRAGMA user_version").fetchone()[0])
        if version > 1:
            raise RuntimeError("SafeRun database was created by a newer app version.")
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript(schema)
        db.execute("PRAGMA user_version = 1")


@contextmanager
def transaction(settings: Settings) -> Iterator[sqlite3.Connection]:
    db = connect(settings)
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def create_user(settings: Settings, email: str, password_hash: str, role: str = "user") -> int:
    with transaction(settings) as db:
        cur = db.execute(
            "INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)",
            (email.strip().casefold(), password_hash, role, utc_now()),
        )
        return int(cur.lastrowid)


def get_user_by_email(settings: Settings, email: str) -> sqlite3.Row | None:
    with connection(settings) as db:
        return db.execute("SELECT * FROM users WHERE email = ?", (email.strip().casefold(),)).fetchone()


def get_user(settings: Settings, user_id: int) -> sqlite3.Row | None:
    with connection(settings) as db:
        return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def record_login_attempt(settings: Settings, email: str, succeeded: bool) -> None:
    now = int(datetime.now(timezone.utc).timestamp())
    with transaction(settings) as db:
        db.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (now - 86400,))
        db.execute(
            "INSERT INTO login_attempts(email,attempted_at,succeeded) VALUES(?,?,?)",
            (email.strip().casefold()[:254], now, int(succeeded)),
        )
        if succeeded:
            db.execute("DELETE FROM login_attempts WHERE email = ?", (email.strip().casefold()[:254],))


def too_many_login_attempts(settings: Settings, email: str) -> bool:
    now = int(datetime.now(timezone.utc).timestamp())
    with connection(settings) as db:
        row = db.execute(
            "SELECT COUNT(*) AS n FROM login_attempts WHERE email = ? AND succeeded = 0 AND attempted_at > ?",
            (email.strip().casefold()[:254], now - 900),
        ).fetchone()
        return int(row["n"]) >= 5


def create_scan(settings: Settings, scan_id: str, owner_id: int, project: dict[str, Any], plan: list[dict[str, Any]]) -> None:
    stamp = utc_now()
    with transaction(settings) as db:
        db.execute(
            "INSERT INTO scans(id,owner_id,status,project_json,plan_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (scan_id, owner_id, "planned", json.dumps(project), json.dumps(plan), stamp, stamp),
        )


def get_owned_scan(settings: Settings, scan_id: str, owner_id: int) -> sqlite3.Row | None:
    with connection(settings) as db:
        return db.execute("SELECT * FROM scans WHERE id = ? AND owner_id = ?", (scan_id, owner_id)).fetchone()


def delete_owned_scan(settings: Settings, scan_id: str, owner_id: int) -> bool:
    with transaction(settings) as db:
        cur = db.execute("DELETE FROM scans WHERE id = ? AND owner_id = ?", (scan_id, owner_id))
        return cur.rowcount == 1


def list_owned_scans(settings: Settings, owner_id: int) -> list[sqlite3.Row]:
    with connection(settings) as db:
        return list(db.execute(
            "SELECT id,status,project_json,created_at,updated_at,finished_at FROM scans WHERE owner_id=? ORDER BY created_at DESC",
            (owner_id,),
        ))


def update_scan_status(settings: Settings, scan_id: str, status: str, *, report: dict[str, Any] | None = None) -> None:
    stamp = utc_now()
    with transaction(settings) as db:
        db.execute(
            "UPDATE scans SET status=?, updated_at=?, started_at=CASE WHEN ?='running' THEN COALESCE(started_at,?) ELSE started_at END, finished_at=CASE WHEN ? IN ('completed','failed') THEN ? ELSE finished_at END, report_json=COALESCE(?,report_json) WHERE id=?",
            (status, stamp, status, stamp, status, stamp, json.dumps(report) if report is not None else None, scan_id),
        )


def queue_owned_scan(settings: Settings, scan_id: str, owner_id: int) -> bool:
    with transaction(settings) as db:
        cur = db.execute(
            "UPDATE scans SET status='queued',updated_at=? WHERE id=? AND owner_id=? AND status='planned' AND EXISTS (SELECT 1 FROM users WHERE users.id=scans.owner_id AND users.active=1 AND users.role='user')",
            (utc_now(), scan_id, owner_id),
        )
        return cur.rowcount == 1


def mark_interrupted_scans(settings: Settings, cleanup_results: dict[str, bool] | None = None) -> None:
    with transaction(settings) as db:
        rows = db.execute("SELECT id FROM scans WHERE status IN ('queued','running')").fetchall()
        for row in rows:
            removed = (cleanup_results or {}).get(str(row["id"]), True)
            db.execute(
                "UPDATE scans SET status='failed',updated_at=?,finished_at=?,report_json=? WHERE id=?",
                (utc_now(), utc_now(), json.dumps({
                    "summary": "The local app restarted before this run finished." if removed else "The local app restarted; temporary source cleanup is still pending.",
                    "source_cleanup": "removed" if removed else "pending",
                    "checks": [],
                    "counts": {"passed": 0, "failed": 0, "blocked": 0, "skipped": 0, "error": 0},
                    "coverage_note": "The interrupted scan did not finish. No checks are counted as passed.",
                }), row["id"]),
            )


def prune_sessions(settings: Settings) -> None:
    now = int(datetime.now(timezone.utc).timestamp())
    with transaction(settings) as db:
        db.execute("DELETE FROM sessions WHERE expires_at <= ? OR last_seen + ? <= ?", (now, settings.session_idle_seconds, now))


def list_user_history(settings: Settings, owner_id: int) -> list[dict[str, Any]]:
    return [dict(row) for row in list_owned_scans(settings, owner_id)]


def admin_counts(settings: Settings) -> dict[str, int]:
    with connection(settings) as db:
        users = db.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0]
        active = db.execute("SELECT COUNT(*) FROM users WHERE role='user' AND active=1").fetchone()[0]
        scans = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        running = db.execute("SELECT COUNT(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0]
    return {"users": int(users), "active_users": int(active), "scans": int(scans), "active_runs": int(running)}


def admin_accounts(settings: Settings) -> list[dict[str, Any]]:
    with connection(settings) as db:
        rows = db.execute(
            "SELECT id,email,role,active,created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]


def admin_runs(settings: Settings) -> list[dict[str, Any]]:
    with connection(settings) as db:
        rows = db.execute(
            "SELECT s.id,s.owner_id,u.email,s.status,s.created_at,s.started_at,s.finished_at,s.updated_at FROM scans s JOIN users u ON u.id=s.owner_id ORDER BY s.updated_at DESC LIMIT 200"
        ).fetchall()
        return [dict(row) for row in rows]


def set_user_active(settings: Settings, user_id: int, active: bool) -> bool:
    with transaction(settings) as db:
        cur = db.execute("UPDATE users SET active=? WHERE id=? AND role='user'", (int(active), user_id))
        if not active:
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        return cur.rowcount == 1


def delete_user(settings: Settings, user_id: int) -> list[str]:
    """Delete an idle user and return their scan IDs for source cleanup."""
    with transaction(settings) as db:
        active = db.execute(
            "SELECT 1 FROM scans WHERE owner_id=? AND status IN ('queued','running') LIMIT 1",
            (user_id,),
        ).fetchone()
        if active:
            raise ValueError("Wait for this account's active scans to finish before deleting it.")
        scan_ids = [row[0] for row in db.execute("SELECT id FROM scans WHERE owner_id=?", (user_id,))]
        cur = db.execute("DELETE FROM users WHERE id=? AND role='user'", (user_id,))
        return scan_ids if cur.rowcount == 1 else []


def prepare_user_deletion(settings: Settings, user_id: int) -> list[str]:
    """Revoke access and prevent new scans while an admin removes its data."""
    with transaction(settings) as db:
        user = db.execute("SELECT id FROM users WHERE id=? AND role='user'", (user_id,)).fetchone()
        if user is None:
            return []
        active = db.execute(
            "SELECT 1 FROM scans WHERE owner_id=? AND status IN ('queued','running') LIMIT 1",
            (user_id,),
        ).fetchone()
        if active:
            raise ValueError("Wait for this account's active scans to finish before deleting it.")
        scan_ids = [row[0] for row in db.execute("SELECT id FROM scans WHERE owner_id=?", (user_id,))]
        db.execute("UPDATE users SET active=0 WHERE id=?", (user_id,))
        db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        return scan_ids

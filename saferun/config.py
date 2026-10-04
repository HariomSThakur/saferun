from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8000
    cookie_name: str = "saferun_session"
    upload_limit: int = 25 * 1024 * 1024
    entry_limit: int = 5000
    expanded_limit: int = 100 * 1024 * 1024
    session_idle_seconds: int = 12 * 60 * 60
    session_absolute_seconds: int = 7 * 24 * 60 * 60
    check_timeout_seconds: int = 120
    output_limit: int = 1024 * 1024

    @property
    def database(self) -> Path:
        return self.data_dir / "saferun.sqlite3"

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"


def load_settings() -> Settings:
    raw_dir = os.environ.get("SAFERUN_DATA_DIR", "./data")
    data_dir = Path(raw_dir).expanduser().resolve()
    host = os.environ.get("SAFERUN_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("SafeRun must bind to loopback for this local MVP.")
    return Settings(
        data_dir=data_dir,
        host=host,
        port=int(os.environ.get("SAFERUN_PORT", "8000")),
    )

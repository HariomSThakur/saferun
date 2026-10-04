from __future__ import annotations

import re
import shutil
import stat
from pathlib import Path


_SCAN_ID = re.compile(r"^[a-f0-9]{32}$")


def remove_job_directory(jobs_dir: Path, scan_id: str) -> bool:
    """Remove a scan's temporary source and report whether it is gone."""
    if not _SCAN_ID.fullmatch(scan_id):
        return False
    base = jobs_dir.resolve()
    target = base / scan_id
    if target.parent != base or target.is_symlink():
        return False
    if not target.exists():
        return True
    try:
        shutil.rmtree(target, onerror=_make_removable)
    except OSError:
        return not target.exists()
    return not target.exists()


def _make_removable(function, path: str, _error_info) -> None:
    try:
        Path(path).chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        function(path)
    except OSError:
        raise

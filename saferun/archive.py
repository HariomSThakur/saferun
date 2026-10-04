from __future__ import annotations

import stat
import os
import time
import zipfile
from pathlib import Path

from fastapi import UploadFile

from saferun.config import Settings
from saferun.storage import remove_job_directory


class UnsafeArchive(ValueError):
    pass


async def extract_upload(upload: UploadFile, settings: Settings, scan_id: str) -> Path:
    """Stream a ZIP to a private job folder, validate every member, then extract safely."""
    job_dir = settings.jobs_dir / scan_id
    source_dir = job_dir / "project"
    job_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    archive_path = job_dir / "upload.zip"
    total = 0
    deadline = time.monotonic() + 60
    try:
        with archive_path.open("xb") as archive_file:
            while chunk := await upload.read(1024 * 1024):
                if time.monotonic() > deadline:
                    raise UnsafeArchive("The upload took too long to read.")
                total += len(chunk)
                if total > settings.upload_limit:
                    raise UnsafeArchive("ZIP exceeds the 25 MiB upload limit.")
                archive_file.write(chunk)
        if total == 0:
            raise UnsafeArchive("The uploaded ZIP is empty.")
        source_dir.mkdir(mode=0o700)
        try:
            with zipfile.ZipFile(archive_path) as archive:
                entries = archive.infolist()
                if len(entries) > settings.entry_limit:
                    raise UnsafeArchive("ZIP contains more than 5,000 entries.")
                expanded = 0
                validated: list[tuple[zipfile.ZipInfo, Path, bool]] = []
                for entry in entries:
                    path, is_dir = _validated_member(entry, source_dir)
                    if entry.flag_bits & 0x1:
                        raise UnsafeArchive("Password-protected ZIP entries are not supported.")
                    expanded += entry.file_size
                    if expanded > settings.expanded_limit:
                        raise UnsafeArchive("ZIP expands beyond the 100 MiB limit.")
                    validated.append((entry, path, is_dir))
                for entry, destination, is_dir in validated:
                    if time.monotonic() > deadline:
                        raise UnsafeArchive("Archive extraction exceeded its time limit.")
                    if is_dir:
                        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    written = 0
                    with archive.open(entry, "r") as source, destination.open("xb") as target:
                        while chunk := source.read(1024 * 128):
                            if time.monotonic() > deadline:
                                raise UnsafeArchive("Archive extraction exceeded its time limit.")
                            written += len(chunk)
                            if written > entry.file_size or written > settings.expanded_limit:
                                raise UnsafeArchive("ZIP entry expanded beyond its declared size.")
                            target.write(chunk)
                    if os.name != "nt":
                        os.chmod(destination, 0o600)
                    if written != entry.file_size:
                        raise UnsafeArchive("ZIP entry size did not match its directory record.")
        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
            if isinstance(exc, UnsafeArchive):
                raise
            raise UnsafeArchive("The uploaded file is not a valid, readable ZIP archive.") from exc
        return project_root(source_dir)
    except Exception:
        remove_job_directory(settings.jobs_dir, scan_id)
        raise
    finally:
        await upload.close()
        archive_path.unlink(missing_ok=True)


async def extract_folder_upload(uploads: list[UploadFile], settings: Settings, scan_id: str) -> Path:
    """Stream browser folder-upload files into a private workspace with ZIP-equivalent limits."""
    job_dir = settings.jobs_dir / scan_id
    source_dir = job_dir / "project"
    job_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    total = 0
    deadline = time.monotonic() + 90
    try:
        if not uploads:
            raise UnsafeArchive("Choose a project folder or ZIP archive.")
        if len(uploads) > settings.entry_limit:
            raise UnsafeArchive("Project folder contains more than 5,000 files.")
        source_dir.mkdir(mode=0o700)
        validated: list[tuple[UploadFile, tuple[str, ...], str]] = []
        seen: set[str] = set()
        file_paths: set[tuple[str, ...]] = set()
        for upload in uploads:
            relative, key = _validated_folder_filename(upload.filename or "")
            if key in seen:
                raise UnsafeArchive("Project folder contains duplicate file paths.")
            seen.add(key)
            file_paths.add(tuple(part.casefold() for part in relative))
            validated.append((upload, relative, key))
        for _, relative, _ in validated:
            for index in range(1, len(relative)):
                if tuple(part.casefold() for part in relative[:index]) in file_paths:
                    raise UnsafeArchive("Project folder has a file where another file path expects a folder.")

        for upload, relative, _ in validated:
            if time.monotonic() > deadline:
                raise UnsafeArchive("Project folder upload took too long to read.")
            destination = source_dir.joinpath(*relative)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            written = 0
            with destination.open("xb") as target:
                while chunk := await upload.read(128 * 1024):
                    if time.monotonic() > deadline:
                        raise UnsafeArchive("Project folder upload took too long to read.")
                    written += len(chunk)
                    total += len(chunk)
                    if total > settings.upload_limit:
                        raise UnsafeArchive("Project folder exceeds the 25 MiB upload limit.")
                    if written > settings.expanded_limit:
                        raise UnsafeArchive("Project folder exceeds the 100 MiB expanded-size limit.")
                    target.write(chunk)
            if os.name != "nt":
                os.chmod(destination, 0o600)
        return project_root(source_dir)
    except Exception:
        remove_job_directory(settings.jobs_dir, scan_id)
        raise
    finally:
        for upload in uploads:
            await upload.close()


def _validated_folder_filename(raw: str) -> tuple[tuple[str, ...], str]:
    if not raw or "\x00" in raw or "\\" in raw or len(raw) > 512:
        raise UnsafeArchive("Project folder contains an unsafe file path.")
    if raw.startswith("/") or (len(raw) >= 2 and raw[1] == ":"):
        raise UnsafeArchive("Project folder contains an absolute path.")
    parts = tuple(raw.split("/"))
    if not parts or any(part in {"", ".", ".."} or len(part) > 255 for part in parts):
        raise UnsafeArchive("Project folder contains a path traversal entry.")
    windows_devices = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
    for part in parts:
        stem = part.split(".", 1)[0].strip(" .").casefold()
        if any(char in part for char in '<>:"|?*') or part.endswith((".", " ")) or stem in windows_devices:
            raise UnsafeArchive("Project folder contains a path that is unsafe on Windows.")
    return parts, "/".join(part.casefold() for part in parts)


def _validated_member(entry: zipfile.ZipInfo, root: Path) -> tuple[Path, bool]:
    raw = entry.filename
    if not raw or "\x00" in raw or "\\" in raw:
        raise UnsafeArchive("ZIP contains an unsafe path.")
    if raw.startswith("/") or (len(raw) >= 2 and raw[1] == ":"):
        raise UnsafeArchive("ZIP contains an absolute path.")
    is_dir = entry.is_dir()
    raw_parts = raw.split("/")
    if is_dir and raw_parts and raw_parts[-1] == "":
        raw_parts.pop()
    parts = tuple(raw_parts)
    if not parts or any(part in {"", ".", ".."} for part in parts) or len(raw) > 512 or any(len(part) > 255 for part in parts):
        raise UnsafeArchive("ZIP contains a path traversal entry.")
    windows_devices = {"con", "prn", "aux", "nul", "conin$", "conout$"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
    for part in parts:
        stem = part.split(".", 1)[0].strip(" .").casefold()
        if any(char in part for char in '<>:"|?*') or part.endswith((".", " ")) or stem in windows_devices:
            raise UnsafeArchive("ZIP contains a path that is unsafe on Windows.")
    mode = entry.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind == stat.S_IFLNK or (kind not in {0, stat.S_IFREG, stat.S_IFDIR}):
        raise UnsafeArchive("ZIP contains a link or special file.")
    if kind == stat.S_IFDIR and not is_dir:
        raise UnsafeArchive("ZIP contains an inconsistent directory entry.")
    destination = root.joinpath(*parts).resolve()
    try:
        destination.relative_to(root.resolve())
    except ValueError as exc:
        raise UnsafeArchive("ZIP contains a path outside its extraction folder.") from exc
    return destination, is_dir


def project_root(source_dir: Path) -> Path:
    current = source_dir
    for _ in range(4):
        entries = list(current.iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            current = entries[0]
            continue
        break
    return current


def locate_project_root(job_dir: Path) -> Path:
    source_dir = job_dir / "project"
    if not source_dir.is_dir():
        raise FileNotFoundError("Temporary project workspace is missing.")
    return project_root(source_dir)

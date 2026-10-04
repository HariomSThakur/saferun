from __future__ import annotations

import hmac
import json
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.templating import Jinja2Templates

from saferun.archive import UnsafeArchive, extract_folder_upload, extract_upload
from saferun.auth import authenticate, normalize_email, register_user, valid_email
from saferun.config import Settings, load_settings
from saferun.db import (
    admin_accounts, admin_counts, admin_runs, connection, create_scan, delete_owned_scan,
    delete_user, get_owned_scan, initialize, list_user_history, mark_interrupted_scans,
    prepare_user_deletion,
    get_user_by_email, prune_sessions, queue_owned_scan, set_user_active, update_scan_status, utc_now,
)
from saferun.dependencies import current_session
from saferun.detection import detect_project
from saferun.jobs import run_scan
from saferun.planner import TEST_CATEGORIES, build_plan, validate_plan
from saferun.runner.docker import sandbox_capability
from saferun.runner.session import cleanup_managed_sandboxes
from saferun.security.passwords import validate_password
from saferun.security.sessions import create_session, revoke_session, validate_csrf
from saferun.storage import remove_job_directory


def _csrf_cookie_name(settings: Settings) -> str:
    return settings.cookie_name + "_csrf"


def _csrf_for_form(request: Request, settings: Settings) -> tuple[str, bool]:
    session_token = request.cookies.get(settings.cookie_name)
    csrf_name = _csrf_cookie_name(settings)
    csrf = request.cookies.get(csrf_name)
    session = current_session(request)
    if session and session_token and csrf and validate_csrf(settings, session_token, csrf):
        return csrf, False
    if not session and not session_token and csrf:
        return csrf, False
    csrf = secrets.token_urlsafe(24)
    if session and session_token:
        from saferun.security.sessions import rotate_csrf
        rotate_csrf(settings, session_token, csrf)
    return csrf, True


def _valid_form_csrf(request: Request, submitted: str | None, settings: Settings) -> bool:
    cookie = request.cookies.get(_csrf_cookie_name(settings))
    if not cookie or not submitted or not hmac.compare_digest(cookie, submitted):
        return False
    session_token = request.cookies.get(settings.cookie_name)
    session = current_session(request)
    if session and session_token:
        return validate_csrf(settings, session_token, submitted)
    return True


def _set_session_cookies(response: Response, request: Request, settings: Settings, token: str, csrf: str) -> None:
    secure = request.url.scheme == "https"
    response.set_cookie(settings.cookie_name, token, httponly=True, secure=secure, samesite="lax", path="/", max_age=settings.session_absolute_seconds)
    response.set_cookie(_csrf_cookie_name(settings), csrf, httponly=False, secure=secure, samesite="lax", path="/", max_age=settings.session_idle_seconds)


def _clear_session_cookies(response: Response, settings: Settings) -> None:
    response.delete_cookie(settings.cookie_name, path="/", httponly=True, samesite="lax")
    response.delete_cookie(_csrf_cookie_name(settings), path="/", samesite="lax")


def _owned_user(request: Request):
    session = current_session(request)
    if not session:
        return None
    return session


def _render(request: Request, template: str, **context: Any) -> HTMLResponse:
    response = templates.TemplateResponse(request=request, name=template, context=context)
    if "status_code" in context:
        response.status_code = int(context["status_code"])
    return response


def _render_form(request: Request, template: str, **context: Any) -> HTMLResponse:
    csrf, issue_cookie = _csrf_for_form(request, settings)
    context["csrf"] = csrf
    response = _render(request, template, **context)
    if issue_cookie:
        response.set_cookie(_csrf_cookie_name(settings), csrf, httponly=False, secure=request.url.scheme == "https", samesite="lax", path="/", max_age=settings.session_idle_seconds)
    return response


class UploadBodyLimit:
    def __init__(self, app, limit: int):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in {"POST", "DELETE"}:
            await self.app(scope, receive, send)
            return
        limit = self.limit if scope.get("path") == "/scans" else 256 * 1024
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        length = headers.get(b"content-length")
        if length:
            try:
                if int(length) > limit:
                    response = PlainTextResponse("Request body is too large.", status_code=413)
                    await response(scope, receive, send)
                    return
            except ValueError:
                response = PlainTextResponse("Invalid content length.", status_code=400)
                await response(scope, receive, send)
                return
        seen = 0

        async def limited_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise _RequestTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestTooLarge:
            response = PlainTextResponse("Request body is too large.", status_code=413)
            await response(scope, receive, send)


class _RequestTooLarge(Exception):
    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    initialize(settings)
    settings.jobs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    prune_sessions(settings)
    sandbox_cleanup_ok = cleanup_managed_sandboxes()
    cleanup_results: dict[str, bool] = {}
    # A restart invalidates planned and interrupted work, then reconciles any
    # earlier cleanup that could not be confirmed.
    with connection(settings) as db:
        startup_scans = db.execute("SELECT id,status,report_json FROM scans").fetchall()
    for row in startup_scans:
        scan_id = str(row["id"])
        removed = remove_job_directory(settings.jobs_dir, scan_id)
        cleanup_results[scan_id] = removed
        if row["report_json"]:
            try:
                report = json.loads(row["report_json"])
            except (ValueError, TypeError):
                continue
            if isinstance(report, dict):
                changed = False
                if report.get("source_cleanup") == "pending" and removed:
                    report["source_cleanup"] = "removed"
                    report["summary"] = str(report.get("summary", "")).replace(
                        " SafeRun could not confirm removal of the temporary source; cleanup will be retried at next startup.", ""
                    )
                    changed = True
                if report.get("sandbox_cleanup") == "pending" and sandbox_cleanup_ok:
                    report["sandbox_cleanup"] = "removed"
                    report["summary"] = str(report.get("summary", "")).replace(
                        " SafeRun could not confirm the temporary sandbox was removed; cleanup will be retried at next startup.", ""
                    )
                    changed = True
                if changed:
                    with connection(settings) as db:
                        db.execute("UPDATE scans SET report_json=?,updated_at=? WHERE id=?", (json.dumps(report), utc_now(), scan_id))
    for item in settings.jobs_dir.iterdir():
        if item.is_dir() and item.name not in cleanup_results:
            remove_job_directory(settings.jobs_dir, item.name)
    mark_interrupted_scans(settings, cleanup_results)
    with connection(settings) as db:
        planned = db.execute("SELECT id FROM scans WHERE status='planned'").fetchall()
        stamp = utc_now()
        for row in planned:
            removed = cleanup_results.get(str(row["id"]), True)
            db.execute(
                "UPDATE scans SET status='failed',updated_at=?,finished_at=?,report_json=? WHERE id=?",
                (stamp, stamp, json.dumps({
                    "summary": "The local app restarted and cleared the temporary upload." if removed else "The local app restarted; temporary source cleanup is still pending.",
                    "source_cleanup": "removed" if removed else "pending",
                    "checks": [], "counts": {},
                }), row["id"]),
            )
    yield


settings = load_settings()
app = FastAPI(title="SafeRun", lifespan=lifespan)
app.state.settings = settings
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]"])
app.add_middleware(UploadBodyLimit, limit=settings.upload_limit + settings.entry_limit * 1024 + 64 * 1024)
templates = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))
templates.env.filters["from_json"] = json.loads
app.mount("/static", StaticFiles(directory=str(Path(__file__).with_name("static"))), name="static")


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if exc.status_code == 303:
        return RedirectResponse("/login", status_code=303)
    if exc.status_code == 403:
        return _render(request, "error.html", title="Access denied", message=str(exc.detail), status_code=403)
    return _render(request, "error.html", title="SafeRun could not complete that request", message=str(exc.detail), status_code=exc.status_code)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/healthz", response_class=PlainTextResponse)
async def healthz():
    return "ok"


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session = current_session(request)
    if session:
        return RedirectResponse("/admin/runs" if session.role == "admin" else "/dashboard", status_code=303)
    return RedirectResponse("/login", status_code=303)


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    session = current_session(request)
    if session:
        return RedirectResponse("/dashboard", status_code=303)
    return _render_form(request, "register.html", error=None)


@app.post("/register", response_class=HTMLResponse)
async def register(request: Request):
    form = await request.form(max_files=1, max_fields=8)
    email = normalize_email(str(form.get("email", "")))
    password = str(form.get("password", ""))
    if not _valid_form_csrf(request, str(form.get("csrf", "")), settings):
        raise HTTPException(403, "The form expired. Reload the page and try again.")
    error = None
    if not valid_email(email):
        error = "Enter a valid email address."
    elif issue := validate_password(password):
        error = issue
    elif get_user_by_email(settings, email):
        error = "An account with that email already exists."
    if error:
        response = _render(request, "register.html", csrf=form.get("csrf", ""), error=error, email=email)
        return response
    try:
        user_id = register_user(settings, email, password)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with that email already exists.")
    token, csrf = create_session(settings, user_id)
    response = RedirectResponse("/dashboard", status_code=303)
    _set_session_cookies(response, request, settings, token, csrf)
    return response


async def _login_page(request: Request, *, admin: bool):
    session = current_session(request)
    if session:
        target = "/admin/runs" if session.role == "admin" else "/dashboard"
        return RedirectResponse(target, status_code=303)
    return _render_form(request, "login.html", error=None, admin=admin)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return await _login_page(request, admin=False)


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return await _login_page(request, admin=True)


async def _login(request: Request, *, admin: bool):
    form = await request.form(max_files=1, max_fields=8)
    email = normalize_email(str(form.get("email", "")))
    if not _valid_form_csrf(request, str(form.get("csrf", "")), settings):
        raise HTTPException(403, "The form expired. Reload the page and try again.")
    user, error = authenticate(settings, email, str(form.get("password", "")), admin=admin)
    if error:
        response = _render(request, "login.html", csrf=form.get("csrf", ""), error=error, admin=admin, email=email)
        return response
    token, csrf = create_session(settings, int(user["id"]))
    response = RedirectResponse("/admin/runs" if admin else "/dashboard", status_code=303)
    _set_session_cookies(response, request, settings, token, csrf)
    return response


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    return await _login(request, admin=False)


@app.post("/admin/login", response_class=HTMLResponse)
async def admin_login(request: Request):
    return await _login(request, admin=True)


@app.post("/logout")
async def logout(request: Request):
    form = await request.form(max_files=1, max_fields=5)
    token = request.cookies.get(settings.cookie_name)
    if not _valid_form_csrf(request, str(form.get("csrf", "")), settings):
        raise HTTPException(403, "The form expired. Reload the page and try again.")
    revoke_session(settings, token)
    response = RedirectResponse("/login", status_code=303)
    _clear_session_cookies(response, settings)
    return response


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = _owned_user(request)
    if not session:
        return RedirectResponse("/login", status_code=303)
    if session.role != "user":
        return RedirectResponse("/admin/runs", status_code=303)
    scans = list_user_history(settings, session.user_id)
    return _render_form(request, "dashboard.html", user=session, scans=scans, capability=sandbox_capability(), error=request.query_params.get("error"))


@app.post("/scans")
async def create_scan_route(request: Request):
    session = _owned_user(request)
    if not session or session.role != "user":
        return RedirectResponse("/login", status_code=303)
    form = await request.form(max_files=settings.entry_limit + 1, max_fields=8)
    if not _valid_form_csrf(request, str(form.get("csrf", "")), settings):
        raise HTTPException(403, "The form expired. Reload the page and try again.")
    scan_mode = str(form.get("scan_mode", "standard"))
    if scan_mode not in {"standard", "full_tests"}:
        raise HTTPException(400, "Choose a valid scan mode.")
    archive_uploads = [item for item in form.getlist("archive") if isinstance(item, StarletteUploadFile) and item.filename]
    folder_uploads = [item for item in form.getlist("project_files") if isinstance(item, StarletteUploadFile) and item.filename]
    if bool(archive_uploads) == bool(folder_uploads) or len(archive_uploads) > 1:
        for item in archive_uploads + folder_uploads:
            await item.close()
        return RedirectResponse("/dashboard?error=Choose+one+ZIP+archive+or+one+project+folder.", status_code=303)
    if archive_uploads and not archive_uploads[0].filename.casefold().endswith(".zip"):
        await archive_uploads[0].close()
        return RedirectResponse("/dashboard?error=Choose+a+ZIP+archive+or+a+project+folder.", status_code=303)
    scan_id = secrets.token_hex(16)
    try:
        root = await extract_upload(archive_uploads[0], settings, scan_id) if archive_uploads else await extract_folder_upload(folder_uploads, settings, scan_id)
        project = detect_project(root)
        plan = build_plan(project, root, full_test_run=scan_mode == "full_tests")
        validate_plan(plan)
        create_scan(settings, scan_id, session.user_id, project.to_dict(), [item.to_dict() for item in plan])
    except UnsafeArchive as exc:
        for item in archive_uploads + folder_uploads:
            await item.close()
        return RedirectResponse("/dashboard?error=" + str(exc).replace(" ", "+"), status_code=303)
    except Exception:
        for item in archive_uploads + folder_uploads:
            try:
                await item.close()
            except Exception:
                pass
        remove_job_directory(settings.jobs_dir, scan_id)
        return RedirectResponse("/dashboard?error=SafeRun+could+not+read+that+project+upload.", status_code=303)
    return RedirectResponse(f"/scans/{scan_id}/plan", status_code=303)


@app.get("/scans/{scan_id}/plan", response_class=HTMLResponse)
async def scan_plan(request: Request, scan_id: str):
    session = _owned_user(request)
    if not session or session.role != "user":
        return RedirectResponse("/login", status_code=303)
    row = get_owned_scan(settings, scan_id, session.user_id)
    if not row:
        raise HTTPException(404, "Scan not found.")
    plan = json.loads(row["plan_json"])
    project = json.loads(row["project_json"])
    labels = {"unit": "Unit", "integration": "Integration", "system": "System", "e2e": "End-to-end / acceptance"}
    test_categories = []
    for category in TEST_CATEGORIES:
        category_selected = any(item.get("selected") and item.get("test_category") == category for item in plan)
        generic_unit_suite = category == "unit" and any(item.get("selected") and item.get("check_id") in {"python.tests", "node.test"} for item in plan)
        test_categories.append({
            "key": category,
            "label": "Unit / configured suite" if category == "unit" else labels[category],
            "selected": category_selected or generic_unit_suite,
            "available": any(item.get("test_category") == category and item.get("reason", "").startswith(("A conventional", "The explicit")) for item in plan) or generic_unit_suite,
            "generic": generic_unit_suite and not category_selected,
        })
    full_test_run = any(item.get("selected") and item.get("test_category") for item in plan)
    return _render_form(request, "plan.html", user=session, scan_id=scan_id, plan=plan, project=project, status=row["status"], test_categories=test_categories, full_test_run=full_test_run)


@app.post("/scans/{scan_id}/run")
async def start_scan(request: Request, scan_id: str, background_tasks: BackgroundTasks):
    session = _owned_user(request)
    if not session or session.role != "user":
        return RedirectResponse("/login", status_code=303)
    form = await request.form(max_files=1, max_fields=5)
    if not _valid_form_csrf(request, str(form.get("csrf", "")), settings):
        raise HTTPException(403, "The form expired. Reload the page and try again.")
    row = get_owned_scan(settings, scan_id, session.user_id)
    if not row:
        raise HTTPException(404, "Scan not found.")
    if row["status"] != "planned" or not (settings.jobs_dir / scan_id / "project").is_dir():
        return RedirectResponse(f"/scans/{scan_id}", status_code=303)
    if not queue_owned_scan(settings, scan_id, session.user_id):
        return RedirectResponse(f"/scans/{scan_id}", status_code=303)
    background_tasks.add_task(run_scan, settings, scan_id)
    return RedirectResponse(f"/scans/{scan_id}", status_code=303)


def _scan_context(row) -> dict[str, Any]:
    report = json.loads(row["report_json"]) if row["report_json"] else None
    return {
        "scan_id": row["id"], "status": row["status"], "created_at": row["created_at"],
        "project": json.loads(row["project_json"]), "plan": json.loads(row["plan_json"]), "report": report,
    }


@app.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_report(request: Request, scan_id: str):
    session = _owned_user(request)
    if not session or session.role != "user":
        return RedirectResponse("/login", status_code=303)
    row = get_owned_scan(settings, scan_id, session.user_id)
    if not row:
        raise HTTPException(404, "Scan not found.")
    if row["status"] == "planned":
        return RedirectResponse(f"/scans/{scan_id}/plan", status_code=303)
    return _render_form(request, "report.html", user=session, **_scan_context(row))


@app.delete("/scans/{scan_id}")
async def delete_scan(request: Request, scan_id: str):
    session = _owned_user(request)
    if not session or session.role != "user":
        return RedirectResponse("/login", status_code=303)
    form = await request.form(max_files=1, max_fields=5)
    if not _valid_form_csrf(request, str(form.get("csrf", "")), settings):
        raise HTTPException(403, "The form expired. Reload the page and try again.")
    row = get_owned_scan(settings, scan_id, session.user_id)
    if not row:
        raise HTTPException(404, "Scan not found.")
    if row["status"] in {"queued", "running"}:
        raise HTTPException(409, "Wait for the active scan to finish before deleting it.")
    if not remove_job_directory(settings.jobs_dir, scan_id):
        return RedirectResponse("/dashboard?cleanup=pending", status_code=303)
    delete_owned_scan(settings, scan_id, session.user_id)
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/scans/{scan_id}/delete")
async def delete_scan_form(request: Request, scan_id: str):
    return await delete_scan(request, scan_id)


def _require_admin(request: Request):
    session = _owned_user(request)
    if not session:
        return None
    if session.role != "admin":
        raise HTTPException(403, "Administrator access required.")
    return session


@app.get("/admin/accounts", response_class=HTMLResponse)
async def accounts_page(request: Request):
    session = _require_admin(request)
    if not session:
        return RedirectResponse("/admin/login", status_code=303)
    return _render_form(request, "admin_accounts.html", user=session, accounts=admin_accounts(settings))


@app.post("/admin/accounts/{user_id}/{action}")
async def account_action(request: Request, user_id: int, action: str):
    admin = _require_admin(request)
    if not admin:
        return RedirectResponse("/admin/login", status_code=303)
    form = await request.form(max_files=1, max_fields=5)
    if not _valid_form_csrf(request, str(form.get("csrf", "")), settings):
        raise HTTPException(403, "The form expired. Reload the page and try again.")
    if action == "deactivate":
        set_user_active(settings, user_id, False)
    elif action == "reactivate":
        set_user_active(settings, user_id, True)
    elif action == "delete":
        try:
            scan_ids = prepare_user_deletion(settings, user_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        cleanup_ok = True
        for scan_id in scan_ids:
            if not remove_job_directory(settings.jobs_dir, scan_id):
                cleanup_ok = False
        if not cleanup_ok:
            return RedirectResponse("/admin/accounts?cleanup=pending", status_code=303)
        delete_user(settings, user_id)
    else:
        raise HTTPException(404, "Action not found.")
    return RedirectResponse("/admin/accounts", status_code=303)


@app.get("/admin/runs", response_class=HTMLResponse)
async def admin_runs_page(request: Request):
    session = _require_admin(request)
    if not session:
        return RedirectResponse("/admin/login", status_code=303)
    return _render_form(request, "admin_runs.html", user=session, counts=admin_counts(settings), runs=admin_runs(settings))

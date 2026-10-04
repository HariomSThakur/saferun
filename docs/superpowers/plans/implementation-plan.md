# SafeRun Local Repository Auditor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build SafeRun as a local, no-paid-service web app where users can upload repositories, see supported checks and results, and manage their own reports, while admins manage accounts and view run status only.

**Architecture:** A Python FastAPI app serves server-rendered pages and a JSON-backed local workflow. SQLite stores accounts, revocable sessions, and sanitized per-user reports. A deterministic planner selects registered checks; static analyzers run locally, while project test commands run only through a Docker-compatible disposable sandbox. If no sandbox is present, code-execution checks are blocked and the UI says why.

**Tech Stack:** Python 3.13; FastAPI and Uvicorn; Jinja2 templates; `python-multipart`; built-in `sqlite3`; Argon2id via `argon2-cffi`; plain HTML/CSS/JavaScript; local Docker CLI as an optional execution capability. No LLM, external API, hosted database, paid service, or API key.

**Spec:** [SafeRun repository-testing design](saferun-repository-testing-design.md)

## Global Constraints

- The core workflow must not require a paid service or an API key.
- The app binds to `127.0.0.1` by default.
- Store passwords as Argon2id hashes and session tokens as hashes; sessions are revocable and cookies are HTTP-only and SameSite.
- Admins can manage accounts and see aggregate counts and run lifecycle status only; they cannot access source, logs, findings, or reports.
- Users can view and delete only their own sanitized scan reports.
- Delete uploaded source, extracted workspaces, and raw logs when each job ends; persist no source archive in SQLite.
- Reject malformed archives and path traversal before extraction.
- The planner selects registered check IDs only; it never supplies arbitrary commands or changes source files.
- Disable network access during project code execution. Dependency preparation is separate and uses free public registries without API credentials.
- Run project code only in a disposable sandbox with resource and time limits. If the sandbox is unavailable, do static inspection only and show execution checks as blocked.
- Do not claim checks passed unless they ran and returned success; distinguish passed, failed, blocked, skipped, and error.
- Do not add an LLM or external API dependency.
- Limit uploads to 25 MiB and 5,000 archive entries; reject extracted content over 100 MiB.
- Limit each sandbox check to 120 seconds, 1 CPU, 1 GiB memory, 128 processes, and 1 MiB captured output.
- Use 12-hour idle and 7-day absolute server-session expiry; normalize email with trim plus casefold; require passwords of 12–128 characters.
- Keep raw job data only in a unique temporary directory and delete it immediately after the run ends.

## Review Focus

- Malicious or malformed ZIP contents, including traversal paths and excessive file counts, must be rejected before extraction.
- A logged-in user changing a scan ID must never reveal another user's report.
- Admin routes must not return report details, source paths, raw logs, or findings.
- Missing Docker, runtimes, test scripts, or dependencies must produce blocked/skipped states, never a false pass.
- Process timeouts, oversized logs, and secret-like strings in output must not hang the app or leak raw sensitive output.

---

## Project File Map

Project root: `outputs/saferun/` (fresh local Git repository).

- `pyproject.toml`, `requirements.txt`: Python package metadata and runtime dependencies.
- `README.md`, `.gitignore`, `.env.example`: setup, local run instructions, generated data exclusions, and non-secret configuration names.
- `saferun/config.py`: local paths and settings; bind host defaults to localhost.
- `saferun/models.py`: typed `DetectedProject`, `PlannedCheck`, `CheckResult`, `Evidence`, `ScanReport`, and `ScanStatus` records shared across services and routes.
- `saferun/db.py`, `saferun/schema.sql`: SQLite connections, schema creation/versioning, and transaction helpers.
- `saferun/security/passwords.py`, `saferun/security/sessions.py`: Argon2id password handling and revocable server sessions.
- `saferun/auth.py`, `saferun/dependencies.py`: authentication routes and user/admin authorization dependencies.
- `saferun/archive.py`: upload limits, ZIP validation, safe extraction, and temporary job cleanup.
- `saferun/detection.py`, `saferun/planner.py`: manifest/language detection and deterministic allowed-check selection.
- `saferun/checks/static.py`: archive/config checks, dependency inventory, and local secret-pattern scan.
- `saferun/runner/docker.py`: Docker capability detection, fixed runner commands, resource/time limits, network isolation, and result normalization.
- `saferun/jobs.py`, `saferun/reports.py`: scan lifecycle, sanitized report persistence, ownership checks, and retention/deletion.
- `saferun/web.py`: page and form routes composed from the domain modules.
- `saferun/templates/`: `base.html`, `login.html`, `register.html`, `dashboard.html`, `plan.html`, `report.html`, `admin_accounts.html`, `admin_runs.html`, and shared error/empty states.
- `saferun/static/app.css`, `saferun/static/app.js`: responsive interface and minimal interactions without a frontend build service.
- `saferun/cli.py`: one-time admin creation command with a hidden password prompt.
- `sample-projects/python-demo/`, `sample-projects/node-demo/`: small known fixtures for the walkthrough.
- `data/`: local SQLite DB and temporary job roots, excluded from version control.

### Shared interfaces

- `detect_project(root: Path) -> DetectedProject` inspects names/manifests only and never imports or executes project code.
- `build_plan(project: DetectedProject) -> list[PlannedCheck]` emits only catalog IDs and validated parameters.
- `run_static_check(check: PlannedCheck, root: Path) -> CheckResult` performs non-executing inspection.
- `run_sandbox_check(check: PlannedCheck, root: Path, limits: SandboxLimits) -> CheckResult` uses the Docker adapter or returns `blocked` without invoking a host shell.
- `create_scan(owner_id: int, project: DetectedProject, plan: list[PlannedCheck]) -> str` creates an opaque scan ID and queued record.
- `save_scan_result(scan_id: str, report: ScanReport) -> None` stores a sanitized report; owner-facing queries always include the owner ID.
- `get_owned_scan(scan_id: str, owner_id: int) -> ScanReport | None` enforces ownership in SQL/service code.
- `get_admin_run_statuses() -> list[AdminRunStatus]` returns scan ID, owner ID/email, lifecycle status, and timestamps only; it never selects report JSON.

Check IDs are fixed as `archive.validate`, `project.detect`, `dependencies.inventory`, `secrets.scan`, `python.syntax`, `python.tests`, `python.ruff`, `python.mypy`, `node.syntax`, `node.test`, `node.lint`, `node.typecheck`, and `node.build`. The planner may omit unsupported checks or mark them blocked, but cannot add IDs.

### HTTP route contract

- `GET, POST /register`; `GET, POST /login`; `POST /logout` for user sessions.
- `GET, POST /admin/login` for pre-provisioned admins; use the same password verifier and reject non-admin accounts before creating an admin session.
- `GET /dashboard`; `POST /scans`; `GET /scans/{scan_id}/plan`; `POST /scans/{scan_id}/run`; `GET, DELETE /scans/{scan_id}` for owner-bound workflows.
- `GET /admin/accounts`; `POST /admin/accounts/{user_id}/deactivate`; `POST /admin/accounts/{user_id}/reactivate`; `DELETE /admin/accounts/{user_id}`; `GET /admin/runs` for status-only admin operations.
- All state-changing browser requests carry a per-session CSRF token. Jinja autoescaping stays enabled for reports and captured scan output.
- `POST /scans/{scan_id}/run` queues one in-process background job and immediately redirects to the status page; a single local worker runs checks sequentially. On startup, stale queued/running records from a previous process are marked failed with an interruption reason.

## Task 1: Create the local application skeleton

**Files:** Create project root files listed above for package/configuration and app composition.

- [ ] Create `pyproject.toml` with the supported Python floor, dependencies, and `saferun` CLI entry point.
- [ ] Create package structure and a FastAPI application factory that loads config and serves a minimal health/home page.
- [ ] Add `.gitignore` rules for the SQLite DB, session data, uploads, extracted workspaces, logs, virtual environments, and secrets.
- [ ] Add README setup steps using standard package registries; state that no API key or paid account is needed.
- [ ] Initialize Git in the new project folder and keep only source, sample fixtures, and documentation tracked.

**Deliverable:** `uvicorn saferun.web:app --host 127.0.0.1 --port 8000` starts the local app and shows its home page.

## Task 2: Add SQLite persistence, user login, and admin provisioning

**Files:** `saferun/db.py`, `saferun/schema.sql`, `saferun/security/passwords.py`, `saferun/security/sessions.py`, `saferun/auth.py`, `saferun/dependencies.py`, `saferun/cli.py`.

- [ ] Define versioned SQLite tables for users, sessions, scans, and sanitized report JSON, with unique normalized email and foreign-key cascades.
- [ ] Implement Argon2id password hash/verify helpers; never store plaintext passwords.
- [ ] Implement random opaque session tokens, store only token hashes, use 12-hour idle and 7-day absolute expiry, support revocation, and set HTTP-only SameSite=Lax cookies; set Secure on HTTPS and use localhost's local-development exception.
- [ ] Add register, login, logout, and current-user routes; include CSRF protection for state changes and login throttling.
- [ ] Add `/admin/login` using the shared credential verifier and sessions, but reject non-admin accounts before establishing an admin UI session.
- [ ] Enforce per-request active-account and role checks; revoke all sessions when an account is deactivated or deleted.
- [ ] Add a CLI command that interactively creates the initial admin, never echoes the password, and refuses to create public/admin signup routes.

**Deliverable:** Users can create/sign in to ordinary accounts, and a separately provisioned admin can sign in; user/admin authorization is centralized.

## Task 3: Implement safe project upload and detection

**Files:** `saferun/archive.py`, `saferun/detection.py`, `saferun/web.py`, upload and dashboard templates.

- [ ] Accept ZIP uploads only; enforce the 25 MiB byte, 5,000-entry, and 100 MiB expanded-size limits while streaming to a temporary location.
- [ ] Validate archive entries and reject path traversal, absolute paths, symlinks, malformed members, and unsafe extraction destinations.
- [ ] Extract to a unique job directory with cleanup on every failure path.
- [ ] Detect Python, JavaScript, TypeScript, and known generic project signals from manifests, lockfiles, and layout without executing project files.
- [ ] Show the detected project type and known limitations before check selection.

**Deliverable:** A user can upload a safe archive and review detected project information; unsafe archives stop before extraction.

## Task 4: Add the deterministic check planner and local static checks

**Files:** `saferun/planner.py`, `saferun/checks/static.py`, check catalog configuration, plan and report templates.

- [ ] Define the fixed check IDs from Shared interfaces with typed arguments; reject unknown IDs and malformed parameters.
- [ ] Select checks deterministically from detected manifests and explain each selection.
- [ ] Add non-executing archive/config validation and dependency inventory from common requirements, pyproject, package, and lockfile formats.
- [ ] Add Python source syntax compilation and JavaScript/TypeScript parse checks when a local parser is available; do not import project modules.
- [ ] Add a local secret-pattern scanner that reports file/line and confidence while redacting likely secret values.
- [ ] Represent every check as `passed`, `failed`, `blocked`, `skipped`, or `error`; unrun checks cannot be passed.
- [ ] Implement fixed check selection: Python `python.syntax`, `python.tests`, `python.ruff`, and `python.mypy`; Node `node.syntax`, `node.test`, `node.lint`, `node.typecheck`, and `node.build`. Mark tool/config absence as skipped or blocked with a reason.
- [ ] Render a reviewable check plan with expected requirements before execution.

**Deliverable:** SafeRun can generate and display a reproducible, key-free static check plan and initial findings without running uploaded code.

## Task 5: Add sandbox capability detection and Python/Node test execution

**Files:** `saferun/runner/docker.py`, `saferun/jobs.py`, run status components and capability messages.

- [ ] Detect whether a supported Docker-compatible runtime is installed and usable before starting any project command.
- [ ] If unavailable, mark Python/Node test, lint, type, and build commands `blocked` with an actionable message; do not fall back to host subprocess execution.
- [ ] If available, invoke only registered adapters inside disposable containers: Python `pytest`/`unittest`, `ruff`, `mypy`; Node configured `test`/`lint`/`build` scripts and `tsc --noEmit` when installed. Use 1 CPU, 1 GiB memory, 128 processes, 120 seconds per check, a read-only source mount, writable temp storage, no network during execution, dropped capabilities, and a non-root container user.
- [ ] For Python, select only configured/recognized `pytest` or `unittest`, `ruff`, and `mypy` checks; for Node, select only configured `test`, `lint`, and `build` scripts plus `tsc --noEmit` when installed in the project dependencies.
- [ ] Keep dependency preparation separate from checks; use public registries without keys, disable npm lifecycle scripts, install Python wheels only, and keep dependency setup inside a disposable sandbox. Mark unresolved dependencies blocked.
- [ ] Normalize exit codes, timeouts, runner failures, missing commands, and captured output to structured check results; cap and redact raw output.
- [ ] Run the check list sequentially in one bounded local worker; persist `queued`, `running`, `completed`, or `failed` lifecycle updates and mark interrupted work failed at next startup.
- [ ] Delete the extracted project, container, and raw logs after job completion or failure.

**Deliverable:** Configured checks run only in a disposable sandbox; this machine currently has no Docker command, so execution checks will remain blocked until the user installs a compatible runtime.

## Task 6: Persist user-owned scan history and implement admin controls

**Files:** `saferun/jobs.py`, `saferun/reports.py`, `saferun/web.py`, user history and admin templates.

- [ ] Persist each scan's owner, status, timestamps, detected project summary, and sanitized structured report in SQLite; never persist archives or raw logs.
- [ ] Enforce ownership in the query/service layer for viewing/deleting reports and in routes; do not rely on hidden UI controls.
- [ ] Add scan history and report deletion for the signed-in owner; account deletion cascades through reports.
- [ ] Add admin account list, deactivate/reactivate/delete actions, aggregate run counts, and run lifecycle status/timestamps.
- [ ] Ensure admin queries and serializers cannot return report content, findings, source paths, or raw logs.

**Deliverable:** Users can revisit only their own reports; admins can manage accounts and see run status without opening user findings.

## Task 7: Build the product interface and end-to-end user flow

**Files:** `saferun/templates/*`, `saferun/static/app.css`, `saferun/static/app.js`, `saferun/web.py`.

- [ ] Before writing UI markup, complete the Impeccable new-surface context/init/direction workflow and get the visual direction approved; the launcher currently needs network and cache-write permission to install its engine.
- [ ] Create responsive register/login screens, including validation, empty, loading, and error states.
- [ ] Create the authenticated dashboard with upload, project detection, plan review, run progress, and history.
- [ ] Create a readable report view with summary, individual check statuses, coverage gaps, evidence locations, and bounded log excerpts.
- [ ] Create role-separated admin pages for account management and run status only.
- [ ] Make permission-denied, unavailable-sandbox, blocked dependency, timeout, and partial-run states understandable and actionable.
- [ ] Keep interactions keyboard accessible, forms labelled, focus visible, and status meaning available without color alone.

**Deliverable:** A user can register, upload, review, run available checks, and view their report; an admin can manage accounts and view run statuses only.

## Task 8: Prepare the local demo and operating guide

**Files:** `README.md`, sample project fixtures, `outputs/saferun-demo-guide.md`.

- [ ] Add one passing and one deliberately failing Python sample project plus a small Node/TypeScript sample; keep all samples harmless and self-contained.
- [ ] Document startup, admin bootstrap, login, ZIP upload, database location, and deletion behavior.
- [ ] Document the local Docker-compatible runtime prerequisite for executing uploaded project code and explain the static-only fallback when it is unavailable; SafeRun itself requires no paid API or account.
- [ ] Add a short demo path showing local registration, admin status view, static findings, blocked execution without Docker, and a completed run when the runtime is available.
- [ ] Document known limitations, including no external vulnerability feed, no email reset flow, no LLM, and no guarantee of exhaustive test coverage.

**Deliverable:** A new user can run the project without API credentials or a paid account and understand which checks this environment can perform.

## Manual acceptance walkthrough

- Register and log in as a user; create an admin only through the CLI setup flow.
- Upload safe Python and Node/TypeScript sample archives and confirm detection and deterministic plan selection.
- Upload malformed and path-traversal archives and confirm they are rejected before extraction.
- Confirm static checks work without Docker and execution checks show blocked on this current machine.
- Confirm User A cannot open or delete User B's report, including by changing the report URL.
- Confirm admin can list/deactivate/reactivate/delete accounts and see run status, but report/detail endpoints deny access.
- Confirm uploaded source and raw logs are removed after completion or failure; sanitized reports remain available only to their owner.
- Confirm the app runs without an API key, paid account, external LLM, or hosted database.

## Plan review notes

- The current host has Python 3.13.5 and Node 24.21.0; no Docker CLI was detected. The runner must fail closed and preserve static-only capability here.
- Project files do not yet exist. The plan creates the app under `outputs/saferun/` so the project and its documentation are visible as deliverables.
- The Impeccable context launcher could not install its engine because the sandbox lacks network access and write permission to its cache under the user profile. Before implementing the new UI, request the exact required permissions.
- The selected Code Review capability exposes CI diagnostics for an existing pull/merge request, not local diff review. Use the available Superpowers local review workflow for final review.

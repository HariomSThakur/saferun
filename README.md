# SafeRun

SafeRun is a local repository audit app. Upload a ZIP or choose a project folder from your computer. It detects common languages and project ecosystems, inventories supported dependency manifests, scans text files for likely committed secrets, and runs registered project checks only inside a restricted Docker container. Deep test, lint, type, and build runners currently cover Python and JavaScript/TypeScript; other recognized project types receive the shared repository scans and a clear coverage note. SafeRun stores accounts and sanitized reports in local SQLite. It does not call an AI service, require an API key, or use a paid service.

## Start locally

1. Install standard Python 3.11 or newer (the free-threaded `3.13t` build is not supported by all dependencies yet).
2. From PowerShell in this folder, use the launcher to create a local virtual environment, install the free Python dependencies, and start SafeRun:

   ```powershell
   .\start-saferun.ps1
   ```

   Or set up the environment manually:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

3. Start SafeRun on your own computer only if you used the manual setup:

   ```powershell
   uvicorn saferun.web:app --host 127.0.0.1 --port 8000
   ```

4. Visit <http://127.0.0.1:8000> and register a normal account.

The first account is not automatically an administrator. Create one from a terminal with `python -m saferun.cli create-admin`; the password prompt does not echo your password. Never expose this development server to the public internet.

## Checks and isolation

Upload a repository ZIP or select a project folder (up to 25 MiB and 5,000 files). Folder selection skips Git metadata, installed dependency folders, build outputs, and caches. SafeRun rejects unsafe paths, symlinks, duplicate paths, and oversized archives before scanning. Static checks do not import the project. When you start a check that needs a runner or declared Python/Node dependencies, SafeRun can download the free Docker image and packages from public registries into a temporary, resource-limited container. Setup commands use a clean working directory and do not add uploaded source paths to their import or executable search paths. Python packages must have prebuilt wheels; npm lifecycle scripts are disabled during dependency setup. SafeRun disconnects and verifies the container network before adding project paths to the environment and running project tests, lint, type, or build commands. Uploaded code never runs on the host, and SafeRun does not use host API keys or registry credentials. If setup cannot be completed safely or Docker is unavailable, the affected checks are marked blocked. On Linux and macOS, run SafeRun as a regular user so containers can stay non-root.

Reports are saved to the local SQLite database for the signed-in owner. Uploaded source and temporary check output are deleted after a run; planned-but-not-yet-run uploads live in the local temporary job folder until they are run, deleted, or the app restarts. Admins can manage accounts and inspect run lifecycle status, but cannot view report contents.

The upload screen offers **Inspect repository** and **Run full test suite**. Full-test mode runs the regular supported checks plus categorized tests it recognizes: Python folders such as `tests/unit`, `tests/integration`, `tests/system`, or `tests/e2e`, and Node scripts named `test:unit`, `test:integration`, `test:system`, or `test:e2e` (with `test:acceptance` accepted for end-to-end). A normal `pytest` or `npm test` command is also run when configured, but SafeRun labels it as a general project suite because the project has not identified its test levels. Missing categories are reported as not detected; SafeRun does not invent tests. Deep execution remains limited to Python and JavaScript/TypeScript.

Before sharing or publishing the SafeRun source, exclude local runtime data such as `data/`, `.venv/`, `.env`, and SQLite database files. These are ignored by Git, but manually created ZIP files should be checked separately.

For a short project walkthrough and sample upload steps, see [the local demo guide](../saferun-demo-guide.md).

## Local data

By default, SafeRun creates `data/saferun.sqlite3` and temporary workspaces under `data/jobs/`. Set `SAFERUN_DATA_DIR` to choose another private local folder. Deleting an account removes that user's sessions and scan reports. There is no email password reset in this MVP.

## Limits

SafeRun is a local MVP, not a guarantee that every defect or vulnerability will be found. Project detection is broad, but language-specific execution currently covers Python and JavaScript/TypeScript. It does not query external vulnerability feeds or auto-fix code. The sandbox reduces risk but is not a security guarantee against all hostile input. Use it only with repositories you are allowed to inspect.

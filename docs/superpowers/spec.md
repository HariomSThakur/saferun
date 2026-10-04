# SafeRun Repository Testing — Design Specification

## Status

The local MVP is implemented in this repository. It supports ZIP and browser folder uploads, broad language/ecosystem detection, shared static checks, SQLite accounts/reports, a restricted Docker runner with deeper Python and JavaScript/TypeScript checks, and a full-test upload mode with recognized unit, integration, system, and end-to-end suites. Full container execution still needs verification in a shell where Docker Desktop is reachable.

## Product summary

SafeRun is a local web app where users create accounts, upload project archives or select a local project folder, review a constrained test plan, run supported checks in a temporary isolated environment, and view evidence-based reports. An admin can manage accounts and monitor run status without reading users' reports.

The product aims to make repository testing easier to understand and safer to run. Its core workflow must not require a paid service or an API key. It does not call external APIs. Network access may be needed to fetch free dependencies when they are not already available; when dependencies cannot be prepared, affected checks are marked blocked or skipped. It must report what it actually checked and clearly mark checks it could not run. It must not claim complete coverage of every possible test for every repository.

## Target user and problem

The primary user is a student developer or software developer who has a repository and wants a quick, understandable view of its current test and code-quality status without manually figuring out every command first. A secondary user is the SafeRun administrator, who needs to handle accounts and see service/run status without accessing project contents or report details.

Problem statement: Developers lack a simple way to inspect a project, discover the checks it supports, run those checks in a controlled environment, and understand the results. Running unfamiliar repository scripts directly can also expose the user's machine to untrusted code.

## Hackathon framing

Recommended track: **Open Innovation**, under Safety and trust. The product addresses the risk and friction of checking unfamiliar code through local, understandable scans and controlled test execution. Because the core deliberately uses no AI service, this is a clearer fit than the Agentic AI track. The event requires selecting one track.

## Selected product approach

Use broad language and project detection, with deeper check support for Python and JavaScript/TypeScript. A deterministic local planner selects supported checks from a fixed catalog. Recognized but less-supported projects receive general scans and a clear account of unsupported checks.

This is preferred over generating new tests with AI or building a full hosted CI platform. Generated tests add uncertain coverage and validation work; a full hosted platform adds infrastructure and isolation work beyond a hackathon prototype.

## User flow

1. A user registers or signs in with an email and password.
2. The user uploads a ZIP archive or selects a local project folder; both inputs receive path and size validation before scanning.
3. SafeRun validates the archive and extracts it into a temporary workspace.
4. A detector identifies languages, manifests, lockfiles, test frameworks, and configured scripts.
5. A deterministic local planner selects check IDs from an allowlisted catalog and explains each choice. The user can review the proposed plan before execution.
6. A policy gate validates the plan. The runner executes allowed checks inside a disposable sandbox with resource and time limits.
7. A local results analyzer combines process output and structured test results and explains failures using templates and evidence from the run.
8. The user sees and can revisit their own sanitized report history. SafeRun deletes the extracted source and raw logs when the job ends. The admin dashboard displays account management and run status only.

## Accounts, persistence, and roles

- Use a local SQLite database for the hackathon MVP. It stores account records, roles, account active state, and per-user scan records with sanitized structured reports. No hosted database or paid service is required.
- User registration and sign-in use email and password; email is an account identifier and is not verified in the local MVP. Hash passwords with Argon2id; never store or log plaintext passwords. Use revocable server-side sessions, store only a hash of the session token in SQLite, and send the token in an HTTP-only, SameSite cookie. Require CSRF protection for state-changing actions and rate-limit login attempts.
- Users can view and delete their own scan records and reports. A user cannot access another user's scan by changing an ID or URL. Account deactivation or deletion revokes all that account's sessions.
- Create the initial admin with a one-time CLI setup command that prompts for the email and password without echoing the password. Do not provide public admin signup, hard-code credentials, or expose role promotion through the ordinary user interface.
- Admin can list, deactivate, reactivate, or delete accounts and see aggregate counts plus scan lifecycle status (queued/running/completed/failed and timestamps). Admin cannot view source archives, raw logs, findings, or report content.
- When a user deletes an account, delete their scan records and reports as well. Deactivation blocks future login and upload while retaining records until an admin deletes the account; ensure this policy is visible in the UI.
- Persist only sanitized reports needed for a user's own history. Raw source files, extracted workspaces, and raw execution logs are deleted when a run ends. Store no uploaded source in SQLite.
- Bind the local MVP to localhost by default and reject Host headers outside the loopback host allowlist to reduce DNS-rebinding risk. A deployment exposed beyond localhost requires HTTPS, stronger session configuration, and an explicit production security review; hosted multi-tenant deployment is out of scope.
- Password recovery by email and external identity providers are out of scope for the local MVP; an admin can deactivate or delete accounts, but cannot view or recover passwords.

## Check catalog and coverage

| Coverage area | Version 1 behavior | Limitations |
|---|---|---|
| Project detection | Identify known languages and ecosystems from manifests, lockfiles, and project structure. | Detection does not imply that SafeRun can execute that ecosystem's test suite. Unknown combinations are reported. |
| General checks | Inventory dependencies, scan for likely committed secrets, and validate common project configuration and archive structure. | Secret scans can have false positives. Vulnerability advisory lookup is out of scope for the offline MVP; clearly report that external advisory data was not checked. |
| Python | Run syntax/compile checks and configured lint, type, and unit-test checks when the required tools and dependencies are available. Detect unittest/pytest-style suites where possible. | Missing packages, unsupported configuration, unavailable services, or credentials produce blocked/skipped results. |
| JavaScript/TypeScript | Run configured test, lint, and build scripts; run a TypeScript check when a TypeScript configuration is present and dependencies are available. | SafeRun does not invent missing scripts. Package installation and lifecycle scripts are constrained by sandbox policy. |
| Other detected languages | Show detected language and run only generic checks that are explicitly supported. | Do not claim deep test coverage for unsupported stacks. |
| Integration/end-to-end tests | Run only when the repository declares a supported setup and the required local services can be started safely. | Tests needing real accounts, external systems, devices, or credentials are blocked or skipped. |
| Performance tests | Out of scope for the first version. | Consider as a later extension with explicit resource budgets and workload controls. |

Every report shows the checks available for the detected project, the selected checks, and why other checks were not run. A check that did not run can never be counted as passed.

## Planner and execution boundaries

- The local planner may inspect filenames and relevant project metadata, then select only check IDs from a validated catalog.
- The planner cannot provide arbitrary shell commands, change source files, or mark a result as passed. A registered test/build check may invoke a project-configured script through a fixed runner adapter, but only inside the disposable sandbox.
- Each check ID maps to a fixed runner implementation and argument schema. The policy gate rejects unknown check IDs and malformed parameters.
- The execution result from the sandbox is authoritative. Local explanation templates cite the relevant check output or file location.
- Planning and reporting use deterministic local rules and templates; no LLM, API key, or remote inference service is required.
- The MVP does not auto-apply fixes or request project credentials.

## Safe execution and privacy

- Treat every uploaded archive, folder entry, and file inside it as untrusted input.
- Limit uploads to 25 MiB and 5,000 archive entries; reject extracted content over 100 MiB. Reject path traversal, malformed archives, symlinks, and unsafe extraction paths.
- Run code only in a disposable sandbox with CPU, memory, process, and wall-clock limits. Do not expose host credentials or unrelated files to it. Each sandbox check has a 120-second timeout, 1 CPU, 1 GiB memory, 128-process limit, and 1 MiB output cap.
- Keep the read-only upload mounted separately from a temporary 512 MiB sandbox copy. When Python/Node commands are selected, SafeRun may pull free public runner images and prepare declared packages inside a disposable, resource-limited container. While networking is enabled, use `/tmp` as the working directory, isolated Python startup, and system-only command paths; do not add uploaded source paths to Python/Node import paths or `PATH`. Python dependencies are installed from PyPI using prebuilt wheels only; npm uses registry.npmjs.org with lifecycle scripts disabled and only public registry lockfile URLs accepted. No host environment credentials are passed into the container. Disconnect all container networking and verify isolation before adding project paths to the command environment and running project checks. If safe setup or network removal cannot be confirmed, do not run project commands and mark those checks blocked.
- Never mount the original archive as a writable host path. Delete the extracted workspace and raw logs after the job. Persist only the sanitized report in SQLite for its owner to revisit; the admin cannot read it.
- If the required sandbox is unavailable, allow only non-executing static inspection and state that code execution was unavailable.
- Describe the sandbox as a risk-reduction boundary, not a guarantee that all hostile code is harmless.

## Report

The report includes:

- detected languages, frameworks, manifests, and test configuration;
- the planned checks and a short reason for each;
- one status per check: passed, failed, blocked, skipped, or error;
- duration, sanitized command/check identifier, relevant file and line locations, and a concise log excerpt;
- dependency and secret-scan findings with severity and confidence where available;
- an explicit coverage summary showing unsupported or environment-dependent areas;
- deterministic explanations and suggested next steps grounded in run output.

The report must distinguish a failed test from a runner error, a missing dependency, an unsupported check, and a test that was not configured. Raw logs should be size-limited and redacted for likely secrets before display.

## Proposed 30-hour MVP

- A local web interface with user registration/login, per-user scan history, a role-protected admin area, and ZIP or project-folder upload; no remote multi-tenant service, paid subscription, or API key.
- A local SQLite schema for users and sanitized scan records, with a documented setup path for bootstrapping the first admin.
- Detection for Python, JavaScript, TypeScript, and a generic unknown/other classification.
- A fixed check catalog: safe archive validation, language/configuration detection, secret scan, dependency inventory, and configured Python/Node test, lint, type, and build checks when available.
- A deterministic local planner and a reviewable plan.
- A disposable runner with time/resource limits and no project credentials.
- A report that accurately labels passed, failed, blocked, skipped, and error outcomes.
- One deliberately failing sample project and one passing sample project for a repeatable demo.

Defer Git hosting integrations, arbitrary language-specific plugin authoring, AI-generated test files, automatic code fixes, performance testing, vulnerability lookups against external databases, LLM summaries, and remote SaaS deployment.

## Failure handling

- Invalid or unsafe archives are rejected before extraction.
- Missing runtimes, dependencies, or test commands create explicit blocked or skipped results, not silent omissions.
- A timed-out or crashed check is an error, while its output and the rest of the report are preserved when possible.
- If some checks finish and others fail to start, show a partial report with the overall run marked incomplete.
- If the local planner encounters an unknown project setup, select only safe generic checks and show which coverage is unsupported.
- If report formatting fails, retain the structured results and show a clear report-generation error.

## Acceptance criteria

1. SafeRun accepts a valid repository ZIP or browser folder upload and rejects malformed or unsafe paths before running code.
2. It recognizes the supported Python and JavaScript/TypeScript project signals and reports other detected languages without implying unsupported checks ran.
3. The planner can select only registered check IDs; invalid IDs or arguments never reach the runner.
4. Each configured, available check has an accurate status and evidence; a missing or unrun check is never shown as passed.
5. Python and JavaScript/TypeScript checks run only in the disposable environment with configured limits.
6. The report explains skipped, blocked, errored, and failed checks separately.
7. Source files remain unchanged, no project credentials are requested, and extracted source files and raw logs are deleted when the job ends.
8. The core workflow runs without a paid service, API key, or remote AI call. User passwords are only stored as strong hashes; sessions are protected; ordinary users cannot access one another's scan history.
9. The admin can manage accounts and see run status but cannot open report content or source files.
10. The demo can show one passing result and one actionable failure with the report pointing to its evidence.

## Validation plan for implementation

Validation completed so far: Python source compilation; a direct multipart folder-upload route check that preserved nested paths, wrote a scan record, detected TypeScript/Node, and produced the expected plan; ZIP upload and unsafe traversal checks at the upload-function level; three security regression tests covering secret detection/redaction, Host validation, and setup-versus-offline command environment; JavaScript syntax validation; and a rendered login page check for the dark theme. Docker command construction is checked with mocked command calls. Not verified in this shell: Docker image/package download and actual project commands, because Docker is not on the Codex command environment's PATH. The remaining fixture cases (including timeout, failing checks, and secret findings) still need a Docker-reachable run before calling the MVP fully validated.

## Open implementation decisions

- Docker availability is environment-specific. The app checks for Docker when it starts and marks execution checks blocked if the CLI or daemon is unavailable.
- FastAPI and Jinja templates provide the local web interface; no LLM provider is needed.
- Python check tools and declared Python/Node dependencies are prepared automatically inside a disposable container when a corresponding check is selected. Unsafe or unsupported package sources are blocked; no dependency is installed on the host.

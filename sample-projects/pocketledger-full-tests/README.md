# PocketLedger demo project

PocketLedger is a tiny local expense ledger used to demonstrate SafeRun's full-test upload option. It stores entries as JSON and includes both Python and Node.js command-line implementations so SafeRun can demonstrate both supported test runners.

## Upload this project to SafeRun

1. In SafeRun, choose **Browse ZIP** and select `sample-projects/pocketledger-all-tests-demo.zip`, or choose **Browse folder** and select this folder.
2. Click **Run full test suite**.
3. On the review page, look for unit, integration, system, and end-to-end/acceptance suites.
4. Start checks and review the report.

The project uses only the Python and Node.js standard libraries. SafeRun provides its Python test runner in a temporary Docker container; the Node test suites use Node's built-in test runner. No API key or external service is needed.

## Test layout

- `tests/unit/`, `tests/integration/`, `tests/system/`, `tests/e2e/`: Python unit, storage integration, CLI system, and user-flow tests.
- `tests-node/`: matching Node.js unit, integration, system, and end-to-end suites selected by `package.json` scripts.

Expected result: Python and JavaScript syntax checks pass, along with all four categorized test suites for both languages. SafeRun may also show shared repository checks such as dependency inventory and secret scanning.

Run locally with `python -m unittest discover -s tests` and `npm run test:unit`, `npm run test:integration`, `npm run test:system`, and `npm run test:e2e`.

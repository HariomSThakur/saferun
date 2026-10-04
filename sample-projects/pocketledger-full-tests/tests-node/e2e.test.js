import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const cli = resolve("pocketledger-js/cli.js");

function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 10000 });
}

test("user can add entries, list them, and check the balance", async () => {
  const directory = await mkdtemp(join(tmpdir(), "pocketledger-"));
  const filePath = join(directory, "ledger.json");
  try {
    const options = ["--file", filePath];
    const first = run("add", "Allowance", "5000", ...options);
    const second = run("add", "Lunch", "-850", ...options);
    const listing = run("list", ...options);
    const total = run("balance", ...options);
    assert.equal(first.status, 0, first.stderr);
    assert.equal(second.status, 0, second.stderr);
    assert.equal(listing.status, 0, listing.stderr);
    assert.match(listing.stdout, /Allowance: 5000 cents/);
    assert.match(listing.stdout, /Lunch: -850 cents/);
    assert.equal(total.status, 0, total.stderr);
    assert.equal(total.stdout.trim(), "Balance: 4150 cents");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

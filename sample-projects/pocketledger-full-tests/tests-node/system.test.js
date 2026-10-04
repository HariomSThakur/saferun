import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const cli = resolve("pocketledger-js/cli.js");

test("CLI add command writes an entry to disk", async () => {
  const directory = await mkdtemp(join(tmpdir(), "pocketledger-"));
  const filePath = join(directory, "ledger.json");
  try {
    const result = spawnSync(process.execPath, [cli, "add", "Notebook", "-325", "--file", filePath], { encoding: "utf8", timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Added Notebook: -325 cents/);
    assert.deepEqual(JSON.parse(await readFile(filePath, "utf8")), [{ description: "Notebook", amountCents: -325 }]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

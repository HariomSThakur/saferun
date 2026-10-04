import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { addEntry } from "../pocketledger-js/ledger.js";
import { loadEntries, saveEntries } from "../pocketledger-js/store.js";

test("entries persist through the JSON store", async () => {
  const directory = await mkdtemp(join(tmpdir(), "pocketledger-"));
  try {
    const filePath = join(directory, "ledger.json");
    const entries = [];
    addEntry(entries, "Train pass", -1200);
    await saveEntries(filePath, entries);
    assert.deepEqual(await loadEntries(filePath), entries);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

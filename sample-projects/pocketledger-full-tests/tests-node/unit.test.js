import assert from "node:assert/strict";
import test from "node:test";
import { addEntry, balance, normalizeDescription } from "../pocketledger-js/ledger.js";

test("description whitespace is normalized", () => {
  assert.equal(normalizeDescription("  bus   ticket "), "bus ticket");
});

test("blank descriptions are rejected", () => {
  assert.throws(() => normalizeDescription("  "), /cannot be empty/);
});

test("amounts must be non-zero integer cents", () => {
  assert.throws(() => addEntry([], "Coffee", 0), /non-zero/);
  assert.throws(() => addEntry([], "Coffee", 1.5), /non-zero/);
});

test("balance combines income and expenses", () => {
  assert.equal(balance([{ amountCents: 5000 }, { amountCents: -850 }]), 4150);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { formatGreeting } from "../src/format.js";

test("greeting trims surrounding whitespace", () => {
  assert.equal(formatGreeting(" Sam "), "Hello, Sam!");
});

#!/usr/bin/env node
import { addEntry, balance } from "./ledger.js";
import { loadEntries, saveEntries } from "./store.js";

const [command, ...args] = process.argv.slice(2);
const fileIndex = args.indexOf("--file");
const filePath = fileIndex >= 0 ? args[fileIndex + 1] : "ledger.json";
const values = fileIndex >= 0 ? args.filter((_, index) => index !== fileIndex && index !== fileIndex + 1) : args;

try {
  const entries = await loadEntries(filePath);
  if (command === "add") {
    const amount = Number(values.at(-1));
    const description = values.slice(0, -1).join(" ");
    const entry = addEntry(entries, description, amount);
    await saveEntries(filePath, entries);
    console.log(`Added ${entry.description}: ${entry.amountCents} cents`);
  } else if (command === "list") {
    console.log(entries.length ? entries.map((entry) => `${entry.description}: ${entry.amountCents} cents`).join("\n") : "No entries yet.");
  } else if (command === "balance") {
    console.log(`Balance: ${balance(entries)} cents`);
  } else {
    console.error("Usage: pocketledger-js <add|list|balance> [--file path]");
    process.exitCode = 2;
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}

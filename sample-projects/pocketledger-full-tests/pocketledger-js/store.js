import { readFile, rename, writeFile } from "node:fs/promises";

export async function loadEntries(filePath) {
  try {
    const text = await readFile(filePath, "utf8");
    const entries = JSON.parse(text);
    if (!Array.isArray(entries)) throw new Error("Ledger file must contain a JSON list.");
    return entries;
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

export async function saveEntries(filePath, entries) {
  const temporaryPath = `${filePath}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(entries, null, 2)}\n`, "utf8");
  await rename(temporaryPath, filePath);
}

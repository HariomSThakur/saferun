export function normalizeDescription(value) {
  const description = String(value).trim().replace(/\s+/g, " ");
  if (!description) throw new Error("Description cannot be empty.");
  if (description.length > 80) throw new Error("Description must be 80 characters or fewer.");
  return description;
}

export function addEntry(entries, description, amountCents) {
  if (!Number.isInteger(amountCents) || amountCents === 0) {
    throw new Error("Amount must be a non-zero number of cents.");
  }
  const entry = { description: normalizeDescription(description), amountCents };
  entries.push(entry);
  return entry;
}

export function balance(entries) {
  return entries.reduce((total, entry) => total + entry.amountCents, 0);
}

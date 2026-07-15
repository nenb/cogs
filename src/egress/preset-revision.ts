import { createHash } from "node:crypto";

export function canonicalPresetPolicyRevision(preset: Record<string, unknown>): string {
  return `sha256:${createHash("sha256")
    .update(canonical(presetRevisionInput(preset)))
    .digest("hex")}`;
}

function presetRevisionInput(preset: Record<string, unknown>): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...preset };
  delete copy.preset_revision;
  if (isPlainRecord(copy.auth)) {
    const auth: Record<string, unknown> = { ...copy.auth };
    delete auth.secret_handle;
    copy.auth = auth;
  }
  return copy;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isPlainRecord(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

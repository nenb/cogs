import type { JsonValue } from "../api/server.ts";

export const PERMITTED_PROJECTION = "cogs.permitted-json/v1";
const sensitive = /^(api[-_]?key|authorization|credential|secret|token|refresh[-_]?token|access[-_]?token)$/i;

export class PermittedHistoryError extends Error {
  public constructor() {
    super("permitted history unavailable");
    this.name = "PermittedHistoryError";
  }
}

// No preview clipping. Bounds are admission failures, never successful partial JSON.
// The registry owner must retain prior secrets on rotation; undefined means unavailable.
export function permittedJsonBytes(
  value: unknown,
  options: {
    secrets: readonly string[] | undefined;
    maxInputBytes: number;
    maxOutputBytes: number;
    maxNodes?: number;
  },
): Buffer {
  try {
    const suppliedSecrets = options.secrets;
    if (suppliedSecrets === undefined) throw new Error();
    const secrets = [...new Set(suppliedSecrets)];
    if (secrets.length > 256) throw new Error();
    let registryBytes = 0;
    for (const secret of secrets) {
      if (typeof secret !== "string" || secret.length === 0 || Buffer.byteLength(secret) > 16384) throw new Error();
      registryBytes += Buffer.byteLength(secret);
    }
    if (registryBytes > 65536) throw new Error();
    const maxNodes = options.maxNodes ?? 1_000_000;
    for (const n of [maxNodes, options.maxInputBytes, options.maxOutputBytes])
      if (!Number.isSafeInteger(n) || n < 1 || n > 64 * 1024 * 1024) throw new Error();
    // Validate every original node, including deliberately redacted subtrees, without
    // invoking getters/toJSON. Count keys, escapes and punctuation in input admission.
    serialize(value, [], options.maxInputBytes, maxNodes, false);
    return serialize(value, secrets, options.maxOutputBytes, maxNodes, true);
  } catch {
    throw new PermittedHistoryError();
  }
}

export function permittedJson(value: unknown, options: Parameters<typeof permittedJsonBytes>[1]): JsonValue {
  return JSON.parse(permittedJsonBytes(value, options).toString("utf8")) as JsonValue;
}

type Task = { value: unknown; depth: number } | { token: string };
function serialize(
  value: unknown,
  secrets: readonly string[],
  maximum: number,
  maxNodes: number,
  project: boolean,
): Buffer {
  const tasks: Task[] = [{ value, depth: 0 }];
  const seen = new WeakSet<object>();
  const chunks: string[] = [];
  let bytes = 0;
  let nodes = 0;
  let matchWork = 0;
  function redact(text: string): string | null {
    matchWork += text.length * secrets.length;
    if (matchWork > 32 * 1024 * 1024) throw new Error();
    const ranges: [number, number][] = [];
    for (const secret of secrets) {
      let from = 0;
      for (;;) {
        const at = text.indexOf(secret, from);
        if (at < 0) break;
        ranges.push([at, at + secret.length]);
        if (ranges.length > 1_000_000) throw new Error();
        from = at + 1; // include overlapping occurrences
      }
    }
    if (ranges.length === 0) return text;
    ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    const merged: [number, number][] = [];
    for (const range of ranges) {
      const last = merged.at(-1);
      if (last !== undefined && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]);
      else merged.push([...range]);
    }
    const result: string[] = [];
    let offset = 0;
    for (const [start, end] of merged) {
      result.push(text.slice(offset, start), "[redacted]");
      offset = end;
    }
    result.push(text.slice(offset));
    const output = result.join("");
    return secrets.some((secret) => output.includes(secret)) ? null : output;
  }
  while (tasks.length > 0) {
    const task = tasks.pop();
    if (task === undefined) throw new Error();
    if ("token" in task) {
      bytes += Buffer.byteLength(task.token);
      if (bytes > maximum) throw new Error();
      chunks.push(task.token);
      continue;
    }
    if (++nodes > maxNodes || task.depth > 4096) throw new Error();
    const entry = task.value;
    if (entry === null || typeof entry === "boolean" || typeof entry === "number" || typeof entry === "string") {
      if (typeof entry === "number" && !Number.isFinite(entry)) throw new Error();
      tasks.push({ token: JSON.stringify(typeof entry === "string" && project ? redact(entry) : entry) });
      continue;
    }
    if (typeof entry !== "object" || seen.has(entry)) throw new Error();
    seen.add(entry);
    const array = Array.isArray(entry);
    if (Object.getPrototypeOf(entry) !== (array ? Array.prototype : Object.prototype)) throw new Error();
    const keys = Reflect.ownKeys(entry);
    if (keys.length > maxNodes - nodes + 1) throw new Error();
    const children: { key: string; value: unknown }[] = [];
    for (const key of keys) {
      if (typeof key !== "string") throw new Error();
      const descriptor = Object.getOwnPropertyDescriptor(entry, key);
      if (descriptor === undefined || !("value" in descriptor)) throw new Error();
      if (array && key === "length") continue;
      if (!descriptor.enumerable) throw new Error();
      children.push({ key, value: descriptor.value });
    }
    if (array) {
      if (children.length !== entry.length || children.some((child, index) => child.key !== String(index)))
        throw new Error();
    } else children.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    const retained = project && !array ? children.filter((child) => redact(child.key) === child.key) : children;
    tasks.push({ token: array ? "]" : "}" });
    for (let i = retained.length - 1; i >= 0; i--) {
      const child = retained[i];
      if (child === undefined) throw new Error();
      tasks.push({ value: project && !array && sensitive.test(child.key) ? null : child.value, depth: task.depth + 1 });
      if (!array) tasks.push({ token: `${JSON.stringify(child.key)}:` });
      if (i > 0) tasks.push({ token: "," });
    }
    tasks.push({ token: array ? "[" : "{" });
  }
  return Buffer.from(chunks.join(""), "utf8");
}

export type CogsCommandAuditHook = Readonly<{
  mode: "disabled";
  enabled: false;
  record(): false;
}>;

const disabledHook: CogsCommandAuditHook = Object.freeze({
  mode: "disabled",
  enabled: false,
  record: () => false,
});

export function createCogsCommandAuditHook(input?: unknown): CogsCommandAuditHook {
  if (input === undefined) return disabledHook;
  return validateCogsCommandAuditHook(input);
}

export function captureCogsCommandAuditHook(input?: unknown): CogsCommandAuditHook {
  if (input === undefined) return disabledHook;
  return validateCogsCommandAuditHook(input);
}

export function validateCogsCommandAuditHook(input: unknown): CogsCommandAuditHook {
  try {
    if (input === undefined) return disabledHook;
    if (input === null || typeof input !== "object" || Array.isArray(input)) throw new Error("bad audit hook");
    if (Object.getPrototypeOf(input) !== Object.prototype) throw new Error("bad audit hook");
    if (!Object.isFrozen(input)) throw new Error("bad audit hook");
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Reflect.ownKeys(descriptors).sort();
    if (keys.join("\0") !== ["enabled", "mode", "record"].join("\0")) throw new Error("bad audit hook");
    const mode = data(descriptors, "mode");
    const enabled = data(descriptors, "enabled");
    const record = data(descriptors, "record");
    if (mode !== "disabled" || enabled !== false || typeof record !== "function") throw new Error("bad audit hook");
    return Object.freeze({ mode: "disabled", enabled: false, record: disabledRecord });
  } catch {
    throw new Error("invalid command audit hook");
  }
}

function data(descriptors: PropertyDescriptorMap, key: "mode" | "enabled" | "record"): unknown {
  const descriptor = descriptors[key];
  if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true)
    throw new Error("bad audit hook");
  return descriptor.value;
}

function disabledRecord(): false {
  return false;
}

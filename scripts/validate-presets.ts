import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;

const root = resolve(import.meta.dirname, "..");
const directory = resolve(root, "integrations/presets");
const schema = JSON.parse(readFileSync(resolve(root, "schemas/integration-v1alpha1.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

for (const filename of readdirSync(directory)
  .filter((name) => name.endsWith(".json"))
  .sort()) {
  const path = resolve(directory, filename);
  const preset = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  assert.ok(validate(preset), `${filename}: ${ajv.errorsText(validate.errors)}`);
  const revision = preset.preset_revision;
  const revisionInput = { ...preset };
  delete revisionInput.preset_revision;
  const expected = `sha256:${createHash("sha256").update(canonical(revisionInput)).digest("hex")}`;
  assert.equal(revision, expected, `${filename}: preset_revision does not bind canonical policy`);

  const rules = preset.rules as Array<Record<string, unknown>>;
  const hosts = new Map<string, Array<Record<string, unknown>>>();
  const names = new Set<string>();
  for (const rule of rules) {
    const name = rule.name as string;
    const host = rule.host as string;
    assert.equal(names.has(name), false, `${filename}: duplicate rule name ${name}`);
    names.add(name);
    assert.equal(host, host.toLowerCase(), `${filename}: host is not canonical`);
    hosts.set(host, [...(hosts.get(host) ?? []), rule]);
    for (const pathPattern of rule.path_patterns as string[]) {
      assert.doesNotMatch(pathPattern, /%|\\|\/\/|(?:^|\/)\.\.?(?:\/|$)/, `${filename}: ambiguous path pattern`);
    }
    const redirects = rule.redirects as { mode: string; max_hops: number; allowed_hosts: string[] };
    if (redirects.mode === "deny") {
      assert.equal(redirects.max_hops, 0, `${filename}: denied redirects must have zero hops`);
      assert.deepEqual(redirects.allowed_hosts, [], `${filename}: denied redirects must have no hosts`);
    } else {
      assert.ok(redirects.max_hops > 0, `${filename}: allowed redirects need a positive hop bound`);
      assert.ok(redirects.allowed_hosts.length > 0, `${filename}: allowed redirects need exact hosts`);
    }
  }
  for (const rule of rules) {
    const redirects = rule.redirects as { allowed_hosts: string[] };
    for (const host of redirects.allowed_hosts) {
      const destinations = hosts.get(host);
      assert.ok(destinations, `${filename}: redirect host ${host} has no bound rule`);
      // A redirect can carry the preset credential only when its destination rule explicitly binds it.
      assert.ok(destinations.some((destination) => typeof destination.inject_auth === "boolean"));
    }
  }
}

console.log("Validated versioned integration presets, canonical revisions, redirect bindings, and path policy.");

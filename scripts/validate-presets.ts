import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options } from "ajv";
import { canonicalPresetPolicyRevision } from "../src/egress/preset-revision.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;

const root = resolve(import.meta.dirname, "..");
const directory = resolve(root, "integrations/presets");
const schema = JSON.parse(readFileSync(resolve(root, "schemas/integration-v1alpha1.json"), "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile(schema);

for (const filename of readdirSync(directory)
  .filter((name) => name.endsWith(".json"))
  .sort()) {
  const path = resolve(directory, filename);
  const preset = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  assert.ok(validate(preset), `${filename}: ${ajv.errorsText(validate.errors)}`);
  const revision = preset.preset_revision;
  const expected = canonicalPresetPolicyRevision(preset);
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
    const query = rule.query_policy as { mode: string; values?: string[] };
    if (query.mode === "exact") {
      assert.ok((query.values?.length ?? 0) > 0, `${filename}: exact query needs values`);
      assert.equal(
        [...(query.values ?? [])].sort().join("&"),
        (query.values ?? []).join("&"),
        `${filename}: query values must be sorted`,
      );
      assert.equal(
        new Set((query.values ?? []).map((value) => value.split("=", 1)[0])).size,
        query.values?.length,
        `${filename}: query keys must be unique`,
      );
    } else {
      assert.equal(query.mode, "deny", `${filename}: unsupported query mode`);
    }
    const redirects = rule.redirects as { mode: string; max_hops: number; allowed_hosts: string[] };
    assert.equal(redirects.mode, "deny", `${filename}: shipped presets must deny redirects in Slice 2a`);
    assert.equal(redirects.max_hops, 0, `${filename}: denied redirects must have zero hops`);
    assert.deepEqual(redirects.allowed_hosts, [], `${filename}: denied redirects must have no hosts`);
  }
}

console.log("Validated versioned integration presets, canonical revisions, redirect bindings, and path policy.");

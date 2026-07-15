import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

interface Rule {
  name: string;
  host: string;
  port: number;
  methods: string[];
  path_patterns: string[];
  query_policy: { mode: "deny" } | { mode: "exact"; values: string[] };
  inject_auth: boolean;
  redirects: { mode: "deny" | "allow-declared"; max_hops: number; allowed_hosts: string[] };
}
interface Preset {
  id: string;
  dns: { mode: string; guest_resolution: boolean };
  rules: Rule[];
}

const load = (name: string): Preset =>
  JSON.parse(readFileSync(resolve(import.meta.dirname, `../integrations/presets/${name}`), "utf8")) as Preset;

test("GitHub preset is fetch-only smart HTTP with exact discovery query", () => {
  const preset = load("github-smart-http-v1.json");
  assert.deepEqual(
    preset.rules.map((rule) => rule.name),
    ["github-smart-http-refs", "github-smart-http-upload-pack"],
  );
  const refs = preset.rules[0];
  const pack = preset.rules[1];
  assert.deepEqual(refs?.methods, ["GET"]);
  assert.deepEqual(refs?.path_patterns, ["/*/*.git/info/refs"]);
  assert.deepEqual(refs?.query_policy, { mode: "exact", values: ["service=git-upload-pack"] });
  assert.deepEqual(pack?.methods, ["POST"]);
  assert.deepEqual(pack?.path_patterns, ["/*/*.git/git-upload-pack"]);
  assert.deepEqual(pack?.query_policy, { mode: "deny" });
  assert.equal(JSON.stringify(preset).includes("receive-pack"), false);
});

test("PyPI preset is GET-only with explicit query denial and no redirect fan-out", () => {
  const preset = load("pypi-v1.json");
  const index = preset.rules.find((rule) => rule.host === "pypi.org");
  const files = preset.rules.find((rule) => rule.host === "files.pythonhosted.org");
  assert.equal(index?.inject_auth, true);
  assert.deepEqual(index?.query_policy, { mode: "deny" });
  assert.equal(files?.inject_auth, false);
  assert.deepEqual(files?.methods, ["GET"]);
  assert.deepEqual(index?.path_patterns, ["/simple/*/", "/pypi/*/json"]);
  assert.deepEqual(files?.path_patterns, ["/packages"]);
  assert.deepEqual(files?.query_policy, { mode: "deny" });
});

test("npm install preset is GET-only exact-host credential binding", () => {
  const preset = load("npm-v1.json");
  assert.equal(
    preset.rules.every((rule) => rule.host === "registry.npmjs.org" && rule.port === 443),
    true,
  );
  assert.equal(
    preset.rules.every((rule) => rule.inject_auth && rule.methods.join(",") === "GET"),
    true,
  );
  assert.ok(preset.rules.some((rule) => rule.path_patterns.includes("/*/-/*.tgz")));
});

test("presets require proxy-side CONNECT authority, query policy, and denied redirects", () => {
  for (const name of ["github-smart-http-v1.json", "pypi-v1.json", "npm-v1.json"]) {
    const preset = load(name);
    assert.deepEqual(preset.dns, { mode: "proxy-connect-authority", guest_resolution: false });
    for (const rule of preset.rules) {
      assert.equal(rule.host, rule.host.toLowerCase());
      assert.equal(rule.port, 443);
      assert.ok(rule.query_policy.mode === "deny" || rule.query_policy.mode === "exact");
      assert.deepEqual(rule.redirects, { mode: "deny", max_hops: 0, allowed_hosts: [] });
    }
  }
});

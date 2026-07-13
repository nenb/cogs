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

test("GitHub preset binds smart HTTP credentials but not redirected artifact hosts", () => {
  const preset = load("github-smart-http-v1.json");
  const smart = preset.rules.find((rule) => rule.name === "github-smart-http");
  assert.deepEqual(smart?.methods, ["GET", "POST"]);
  assert.deepEqual(smart?.path_patterns, [
    "/*/*.git/info/refs",
    "/*/*.git/git-upload-pack",
    "/*/*.git/git-receive-pack",
  ]);
  assert.equal(smart?.inject_auth, true);
  for (const host of smart?.redirects.allowed_hosts ?? []) {
    const destinations = preset.rules.filter((rule) => rule.host === host);
    assert.ok(destinations.length > 0);
    assert.equal(
      destinations.every((rule) => !rule.inject_auth),
      true,
    );
  }
});

test("PyPI fan-out never receives index credentials", () => {
  const preset = load("pypi-v1.json");
  const index = preset.rules.find((rule) => rule.host === "pypi.org");
  const files = preset.rules.find((rule) => rule.host === "files.pythonhosted.org");
  assert.equal(index?.inject_auth, true);
  assert.deepEqual(index?.redirects.allowed_hosts, ["files.pythonhosted.org"]);
  assert.equal(files?.inject_auth, false);
  assert.deepEqual(files?.methods, ["GET"]);
  assert.deepEqual(files?.path_patterns, ["/packages/*"]);
});

test("npm metadata and tarballs remain exact-host credential bindings", () => {
  const preset = load("npm-v1.json");
  assert.equal(
    preset.rules.every((rule) => rule.host === "registry.npmjs.org" && rule.port === 443),
    true,
  );
  assert.equal(
    preset.rules.every((rule) => rule.inject_auth),
    true,
  );
  assert.ok(preset.rules.some((rule) => rule.path_patterns.includes("/*/-/*.tgz")));
});

test("presets require proxy-side CONNECT authority and no guest resolver", () => {
  for (const name of ["github-smart-http-v1.json", "pypi-v1.json", "npm-v1.json"]) {
    const preset = load(name);
    assert.deepEqual(preset.dns, { mode: "proxy-connect-authority", guest_resolution: false });
    for (const rule of preset.rules) {
      assert.equal(rule.host, rule.host.toLowerCase());
      assert.equal(rule.port, 443);
    }
  }
});

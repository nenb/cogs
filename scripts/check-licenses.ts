import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

interface LockPackage {
  dev?: boolean;
  license?: string;
  link?: boolean;
  resolved?: string;
  version?: string;
}

const allowed = new Set(["0BSD", "Apache-2.0", "BSD-3-Clause", "BlueOak-1.0.0", "ISC", "MIT"]);
const exactLicenseOverrides = new Map<string, { version: string; license: string; allowDisallowed?: true }>([
  ["node_modules/buildcheck", { version: "0.0.7", license: "MIT" }],
  ["node_modules/cpu-features", { version: "0.0.10", license: "MIT" }],
  ["node_modules/ssh2", { version: "1.17.0", license: "MIT" }],
  ["node_modules/tweetnacl", { version: "0.14.5", license: "Unlicense", allowDisallowed: true }],
]);
const lock = JSON.parse(readFileSync(resolve(import.meta.dirname, "../package-lock.json"), "utf8")) as {
  packages: Record<string, LockPackage>;
};
const productionPackages = Object.entries(lock.packages).filter(([path, entry]) => path && !entry.dev && !entry.link);
function licenseFor(path: string, entry: LockPackage): string | undefined {
  if (entry.license) return entry.license;
  const override = exactLicenseOverrides.get(path);
  if (override !== undefined && entry.version === override.version) return override.license;
  return undefined;
}

const missing = productionPackages.filter(([path, entry]) => !licenseFor(path, entry)).map(([path]) => path);
function isExactDisallowedException(path: string, entry: LockPackage, license: string | undefined): boolean {
  const override = exactLicenseOverrides.get(path);
  return (
    override?.allowDisallowed === true &&
    entry.version === override.version &&
    license === override.license &&
    path === "node_modules/tweetnacl" &&
    entry.version === "0.14.5" &&
    license === "Unlicense"
  );
}

const disallowed = productionPackages
  .map(([path, entry]) => [path, entry, licenseFor(path, entry)] as const)
  .filter(
    ([path, entry, license]) => license && !allowed.has(license) && !isExactDisallowedException(path, entry, license),
  )
  .map(([path, _entry, license]) => `${path}: ${license}`);

const tweetnacl = lock.packages["node_modules/tweetnacl"];
assert.equal(tweetnacl?.version, "0.14.5", "tweetnacl Unlicense exception is version-scoped");
assert.equal(
  licenseFor("node_modules/tweetnacl", tweetnacl),
  "Unlicense",
  "tweetnacl Unlicense exception is license-scoped",
);
assert.equal(
  isExactDisallowedException("node_modules/tweetnacl", { ...tweetnacl, version: "0.14.6" }, "Unlicense"),
  false,
  "tweetnacl Unlicense exception must not float to future versions",
);
assert.equal(
  isExactDisallowedException("node_modules/other", tweetnacl, "Unlicense"),
  false,
  "tweetnacl Unlicense exception must not apply to other paths",
);

assert.deepEqual(missing, [], `production dependencies without declared licenses: ${missing.join(", ")}`);
assert.deepEqual(disallowed, [], `production dependencies outside the allowlist: ${disallowed.join(", ")}`);

const counts = new Map<string, number>();
for (const [path, entry] of productionPackages) {
  const license = licenseFor(path, entry) as string;
  counts.set(license, (counts.get(license) ?? 0) + 1);
}
console.log(
  `Verified ${productionPackages.length} production dependency licenses: ${[...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([license, count]) => `${license}=${count}`)
    .join(", ")}`,
);

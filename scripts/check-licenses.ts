import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

interface LockPackage {
  dev?: boolean;
  license?: string;
  link?: boolean;
  resolved?: string;
}

const allowed = new Set(["0BSD", "Apache-2.0", "BSD-3-Clause", "BlueOak-1.0.0", "ISC", "MIT"]);
const lock = JSON.parse(readFileSync(resolve(import.meta.dirname, "../package-lock.json"), "utf8")) as {
  packages: Record<string, LockPackage>;
};
const productionPackages = Object.entries(lock.packages).filter(([path, entry]) => path && !entry.dev && !entry.link);
const missing = productionPackages.filter(([, entry]) => !entry.license).map(([path]) => path);
const disallowed = productionPackages
  .filter(([, entry]) => entry.license && !allowed.has(entry.license))
  .map(([path, entry]) => `${path}: ${entry.license}`);

assert.deepEqual(missing, [], `production dependencies without declared licenses: ${missing.join(", ")}`);
assert.deepEqual(disallowed, [], `production dependencies outside the allowlist: ${disallowed.join(", ")}`);

const counts = new Map<string, number>();
for (const [, entry] of productionPackages) {
  const license = entry.license as string;
  counts.set(license, (counts.get(license) ?? 0) + 1);
}
console.log(
  `Verified ${productionPackages.length} production dependency licenses: ${[...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([license, count]) => `${license}=${count}`)
    .join(", ")}`,
);

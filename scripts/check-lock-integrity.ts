import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

interface LockPackage {
  resolved?: string;
  integrity?: string;
  link?: boolean;
}

const lock = JSON.parse(readFileSync(resolve(import.meta.dirname, "../package-lock.json"), "utf8")) as {
  lockfileVersion: number;
  packages: Record<string, LockPackage>;
};
assert.equal(lock.lockfileVersion, 3, "package-lock.json must use lockfile version 3");

const missingIntegrity = Object.entries(lock.packages)
  .filter(([, entry]) => entry.resolved?.startsWith("https://registry.npmjs.org/") && !entry.integrity && !entry.link)
  .map(([path]) => path);
assert.deepEqual(missingIntegrity, [], `registry packages without SRI integrity: ${missingIntegrity.join(", ")}`);

console.log("Verified SRI integrity for every registry-backed package-lock entry.");

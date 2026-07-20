import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const readme = () => readFileSync(resolve(import.meta.dirname, "..", "README.md"), "utf8");

test("README states current Stage 3 development-only status without production or cloud claims", () => {
  const text = readme();
  assert.match(text, /development-only Stage 3 local vertical slice/);
  assert.match(text, /insecure-container` functional-only/);
  assert.match(text, /linux-kvm` authoritative-local/);
  assert.match(text, /next exit gate is #71/);
  assert.match(
    text,
    /no production daemon, scheduler, EKS\/cloud deployment, release, compliance, or general isolation guarantee/,
  );
  assert.match(text, /AWS feasibility work remains separate/);
  assert.doesNotMatch(text, /Stage 0 feasibility work/);
  assert.doesNotMatch(text, /AWS feasibility work is completed|AWS completion|AWS resources are/i);
});

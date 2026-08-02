import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const projectDocument = (name: string) => readFileSync(resolve(import.meta.dirname, "..", name), "utf8");

test("README states the completed, local-only Stage 3 authority", () => {
  const text = projectDocument("README.md");
  assert.match(text, /Stage 3 local vertical slice is complete/);
  assert.match(text, /Stage 3 exited through closed issue #71/);
  assert.match(text, /authoritative-local profile only/);
  assert.match(text, /insecure-container` is functional-only/);
  assert.match(text, /linux-kvm` is authoritative only for local guest-root evidence/);
  assert.doesNotMatch(text, /next exit gate is #71/);
});

test("README preserves the cloud-entry gate and disclaims current deployment authority", () => {
  const text = projectDocument("README.md");
  assert.match(text, /#42 remains the hard gate before any Stage 4 cloud campaign/);
  assert.match(
    text,
    /#42 must close before any Stage 4 cloud action, followed by a separate explicit campaign approval/,
  );
  assert.match(text, /no Stage 4 EKS\/NIC or Stage 5 release-readiness claim exists yet/);
  assert.match(
    text,
    /not production-ready and provides no production daemon, scheduler, user ingress, EKS deployment, release, compliance, or general isolation guarantee/,
  );
  assert.match(text, /no AWS resources are currently claimed/);
  assert.match(text, /Standalone EC2 evidence is not EKS, CNI, release, or production evidence/);
  assert.match(text, /Issue #356's workload-identity, proxy, network, telemetry, and audit-WAL policy contracts/);
  assert.match(text, /static expected-policy shapes only and remain pending exact EKS CNI\/runtime qualification/);
  assert.doesNotMatch(text, /Stage 0 feasibility work/);
  assert.doesNotMatch(text, /AWS feasibility work is completed|AWS completion/i);
  assert.match(text, /historical v1 assessment preserves the NIC `v0\.11\.0` capability failure/);
  assert.match(text, /Active v2 pins explicitly accepted personal-fork NIC commit/);
  assert.match(text, /resolves only external launch-template ID\/version preservation with operator attestation/);
  assert.match(text, /region-specific EKS AMI\/running kernel and runtime observation are unresolved/);
});

test("the linked implementation plan keeps Stages 4 and 5 API-key-only", () => {
  assert.match(projectDocument("README.md"), /\[`IMPLEMENTATION\.md`\]\(IMPLEMENTATION\.md\)/);

  const text = projectDocument("IMPLEMENTATION.md");
  assert.match(text, /Stages 4 and 5 are API-key-only/);
  assert.match(text, /Subscription integration remains disabled and absent from the advertised support matrix/);
  assert.match(text, /post-MVP issue #13 and is not a Stage 5 release dependency/);
  assert.match(text, /Cogs must not receive or persist refresh tokens/);
});

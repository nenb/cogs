import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

const reportPath = resolve("docs/test-reports/stage-3-s3-09-linux-kvm-exit.md");
const report = readFileSync(reportPath, "utf8");

test("accepted S3-09 exit report pins exact non-release automatic evidence", () => {
  for (const required of [
    "Issue: #71.",
    "Validation source revision: `9f6e241f4bc3a7ee32c1682d140e14c0e72489f5`.",
    "Profile: `linux-kvm`.",
    "Authority: `authoritative-local`.",
    "`release_eligible`: `false`.",
    "`29875168111`",
    "`29875168130`",
    "`29875168103`",
    "`kvm-qualification-29875168103-1`",
    "All five automatic checks passed",
    "`launcher.s3-09.integrated` passed",
    "The normal `launcher.smoke` passed",
    "The Stage 1 Envoy suite completed with applicability-aware stubbed results; those results are not relabelled pass or real.",
    "the Stage 3 real-runtime bearer report and sidecar and the integrated S3 report passed with all declared dependencies real",
    "functional-only companion evidence",
    "No AWS or other cloud resources were provisioned; GitHub Actions was used for automatic validation.",
    "No external real-provider call using a provider API key was made.",
    "No EKS, deployment, release, compliance, or production-readiness claim is made.",
  ]) {
    assert.ok(report.includes(required), required);
  }
  assert.doesNotMatch(report, /https?:\/\//u);
  assert.doesNotMatch(report, /\]\(/u);
  assert.doesNotMatch(report, /8512831390/u);
});

test("accepted S3-09 exit report covers criteria without sensitive evidence values", () => {
  for (const required of [
    "authorization, audit, revocation, identity, and network-enforcement dependency modes all real",
    "KVM acceleration was present and active; guest root and distinct guest boots were observed.",
    "read, edit, and bash tool operations and created a real Git commit",
    "Local trusted composition resolved the model API key runtime-only for the pinned Pi deterministic stream, without an external call or persistence.",
    "bound to the current fixture instance",
    "greater than 32 and at most 1000",
    "oldest cursor produced the required replay gap",
    "paged durable history remained available",
    "untrusted client observation reported the expected Git mapping",
    "OTLP evidence remained metadata-only",
    "Pinned Pi opened the validated raw export as the current session",
    "Shutdown reached zero owned resources",
    "roots were unmounted",
    "conformance guest was destroyed",
    "All 9 downloaded KVM artifact files were tied to the exact source revision and passed their applicable schema and semantic validation.",
    "Across all 9 files, sensitive-content scans passed",
    "Only the two launcher reports additionally passed scans for URLs, proxy coordinates, and digest fields.",
    "13,333 lines / ADR 0036 hard limit 13,400",
    "22,610 lines / hard limit 23,400",
    "ADR 0036 and ADR 0037 boundaries",
  ]) {
    assert.ok(report.includes(required), required);
  }

  for (const forbidden of [
    "192.0.2.1",
    "18080",
    "session.jsonl",
    "/workspace",
    "/run/cogs",
    "/usr/bin",
    "cogs-dev-egress-key",
    "x-cogs-fixture-proof",
    "launcher-v1-",
    "cogs launcher s3-09",
    "proof.txt",
    "curl_path",
    "proxy_used",
    "sk-ant-",
    "Bearer ",
    "Basic ",
    "sha256:",
    "sha512:",
  ]) {
    assert.equal(report.includes(forbidden), false, forbidden);
  }
  assert.doesNotMatch(report, /[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/iu);
  assert.doesNotMatch(report, /companion full Envoy report/u);
  assert.doesNotMatch(report, /Full egress conformance/u);
  assert.doesNotMatch(report, /Across all 9 files[^.]*(?:URLs|proxy coordinates|digest fields)/u);
});

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { renderAwsStage2CompletionReport } from "../scripts/render-aws-stage2-completion-report-v3.ts";
import {
  CompletionEvidenceValidationError,
  parseAwsStage2CompletionEvidence,
} from "../scripts/validate-aws-stage2-completion-evidence-v3.ts";

const workflow = readFileSync(".github/workflows/stage2-production-approval.yml", "utf8");

test("audit-blocked formal bytes compose through approval, production private serializers, adapter, controller and v3 evidence", () => {
  const result = spawnSync("python3", ["-I", "-B", "test/stage2-production-approval.py", "--composition-samples"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const samples = JSON.parse(result.stdout) as {
    package: string;
    approval: string;
    authentication: string;
    private_receipts: string[];
    evidence: string;
    report: string;
  };
  const sha = (raw: string) => createHash("sha256").update(raw).digest("hex");
  const prerequisite = JSON.parse(samples.package);
  const approval = JSON.parse(samples.approval);
  const authentication = JSON.parse(samples.authentication);
  assert.equal(approval.pre_aws_package_sha256, sha(samples.package));
  assert.equal(authentication.approval_sha256, sha(samples.approval));
  const validated = parseAwsStage2CompletionEvidence(samples.evidence);
  const evidence = validated.evidence;
  assert.equal(renderAwsStage2CompletionReport(validated), samples.report);
  assert.equal(evidence.bindings.pre_aws_package_commitment, sha(samples.package));
  assert.equal(evidence.bindings.approval_authentication_commitment, sha(samples.authentication));
  assert.equal(evidence.bindings.runtime_manifest_sha256, prerequisite.runtime_manifest_sha256);
  assert.equal(evidence.cycles.length, 7);
  assert.equal(evidence.inventories.length, 8);
  assert.equal(samples.private_receipts.length, 7);
  for (const [index, raw] of samples.private_receipts.entries()) {
    const receipt = JSON.parse(raw);
    const cycle = evidence.cycles[index];
    assert.ok(cycle);
    assert.equal(receipt.version, "cogs.stage2-cycle-private-owner-receipt/v2");
    assert.equal(receipt.route, index === 0 ? "full" : "readiness");
    assert.equal(receipt.cycle_grant.grant_commitment, cycle.grant_commitment);
    assert.equal(receipt.cycle_grant.batch_commitment, approval.batch_commitment);
    assert.equal(cycle.remote.host_receipt_commitment, sha(`cogs.stage2-cycle-private-owner-receipt/v2\0${raw}`));
    assert.equal(cycle.remote.instance_commitment, cycle.effects.running.identity_commitment);
    // The provider's resource-ID commitment has a different domain/preimage
    // from its running observation. Never equate these two opaque commitments.
    assert.notEqual(cycle.freshness.instance, cycle.remote.instance_commitment);
    assert.deepEqual(cycle.remote.bindings.source_bindings, prerequisite.source_bindings);
    assert.equal(cycle.remote.bindings.qemu.runtime_identity_sha256, receipt.qmp_lineage.runtime_identity_sha256);
    assert.notEqual(cycle.remote.bindings.qemu.runtime_identity_sha256, approval.runtime_manifest_sha256);
    assert.equal(cycle.workloads?.length ?? 0, index === 0 ? 21 : 0);
    if (index > 0)
      assert.notEqual(receipt.qmp_lineage.qemu_process_sha256, receipt.runtime_readiness_lineage.qemu_process_sha256);
    // Mutations start from emitted bytes, never from a repaired positive fixture.
    for (const [before, after] of [
      [approval.runtime_manifest_sha256, receipt.qmp_lineage.runtime_identity_sha256],
      [receipt.qmp_lineage.runtime_identity_sha256, approval.runtime_manifest_sha256],
    ])
      assert.throws(
        () => parseAwsStage2CompletionEvidence(samples.evidence.replaceAll(before, after)),
        CompletionEvidenceValidationError,
        "static/live substitution",
      );
  }
  assert.equal(new Set(evidence.cycles.map((cycle) => cycle.remote.bindings.qemu.runtime_identity_sha256)).size, 7);
});

test("production approval issuance is canonical, provider-free, signed, and first-created", () => {
  const Ajv2020 = createRequire(import.meta.url)("ajv/dist/2020.js");
  const ajv = new Ajv2020({ strict: true, strictRequired: false });
  for (const file of readdirSync("schemas").filter((name) => name.endsWith(".json")))
    ajv.addSchema(JSON.parse(readFileSync(`schemas/${file}`, "utf8")));
  const validate = ajv.getSchema("https://cogs.dev/schemas/aws-stage2-completion-production-approval-v5.json");
  assert.ok(validate);
  const fixture = JSON.parse(readFileSync("test/fixtures/stage2-completion/approval-v5-test-only.json", "utf8"));
  assert.equal(validate(fixture), true, ajv.errorsText(validate.errors));
  for (const version of [1, 2, 3, 4]) {
    assert.ok(ajv.getSchema(`https://cogs.dev/schemas/aws-stage2-completion-production-approval-v${version}.json`));
    assert.equal(validate({ ...fixture, version: `cogs.stage2-completion-production-approval/v${version}` }), false);
  }
  const oldKey = { ...fixture, runtime_commitment: fixture.runtime_manifest_sha256 };
  assert.equal(validate(oldKey), false, "mixed runtime contract");
  delete oldKey.runtime_manifest_sha256;
  assert.equal(validate(oldKey), false, "historical runtime contract");
  const missing = { ...fixture };
  delete missing.runtime_manifest_sha256;
  assert.equal(validate(missing), false);
  assert.match(
    readFileSync("schemas/aws-stage2-completion-production-approval-v3.json", "utf8"),
    /production-approval\/v3/u,
  );
  assert.match(
    readFileSync("schemas/aws-stage2-completion-production-approval-v4.json", "utf8"),
    /production-approval\/v4/u,
  );
  const issuer = readFileSync("scripts/stage2-production-approval.py", "utf8");
  assert.match(issuer, /production-approval\/v5/u);
  assert.match(issuer, /validate_package\(path, approval\)/u);
  assert.match(issuer, /validate_package\(approval_path, approval\)/u);
  assert.match(workflow, /stage2-production-approval\.yml\/runs/u);
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(workflow, /cosign\/cosign@sha256:/u);
  const copy = workflow.indexOf('install -m 0600 "$RUNNER_TEMP/planning/pre-aws-package-v5.json"');
  const digest = workflow.indexOf('sha256sum "$out/pre-aws-package-v5.json"', copy);
  const authenticate = workflow.indexOf("scripts/stage2-production-approval.py authenticate");
  const signing = workflow.indexOf("sign-blob --yes");
  assert.ok(copy >= 0 && digest > copy && authenticate > digest && signing > authenticate);
  assert.match(
    workflow,
    /install -m 0600 "\$RUNNER_TEMP\/planning\/pre-aws-package-v5\.json" \\\n\s+"\$out\/pre-aws-package-v5\.json"/u,
  );
  assert.match(workflow.slice(copy, authenticate), /\.pre_aws_package_sha256/u);
  assert.match(workflow, /path: \$\{\{ runner.temp \}\}\/approval/u);
  assert.match(workflow, /sign-blob --yes/u);
  assert.match(workflow, /verify-blob/u);
  assert.match(workflow, /approval-authentication\.bundle\.json/u);
  assert.match(workflow, /--network none/u);
  assert.match(workflow, /sigstore-trusted-root\.json/u);
  assert.doesNotMatch(workflow, /aws-actions|AWS_ACCESS_KEY_ID|opentofu|terraform|\bssm\b/u);
  assert.doesNotMatch(workflow, /actions\/(?:upload|download)-artifact@v[0-9]/u);
});

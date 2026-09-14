import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const runPython = (program: string) => {
  const result = spawnSync("python3", ["-I", "-B", "-c", program], { encoding: "utf8", timeout: 60_000 });
  assert.equal(result.status, 0, result.stderr);
};

test("ADR0338 through ADR0348 retain the five literal tasks and final reserve", () => {
  runPython(`
import copy,json,runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py')
b,_,paths,_,_=m['_remediation_budget']()
p=b['product_test_correction']; tasks=p['remaining_tranche']['allocations']
assert [t['name'] for t in tasks] == ['governance','product','local-tofu-ssm','readiness-ci','final-HGQ']
assert [(t['gross_lines'],t['gross_bytes']) for t in tasks] == [(5400,1100000),(5200,3200000),(4457,7400000),(1800,4300000),(5300,5500000)]
assert (p['remaining_tranche']['gross_lines'],p['remaining_tranche']['gross_bytes']) == (22157,21500000)
assert (p['global_gross_line_forecast'],p['global_gross_byte_forecast']) == (40157,29500000)
assert len(tasks[-1]['paths']) == 40
assert tasks[-1]['paths'] == sorted(tasks[-1]['paths'])
for path in ['config/stage2-retired-revisions-v2.json','docs/adr/0349-freeze-replacement-H-and-authorize-control.md','docs/adr/0350-establish-replacement-Q-and-authorize-qualification.md','scripts/stage2-prebuilt-local-qualification-guard.py','scripts/stage2-prebuilt-mixed-hg-preflight.sh','scripts/stage2-revision-retirement.py','test/stage2-prebuilt-rehearsal-grant.py']:
 assert path in tasks[-1]['paths']
assert len([p for p in tasks[-1]['paths'] if p.startswith('.github/workflows/')]) == 10
assert len([p for p in tasks[-1]['paths'] if p.startswith('deploy/aws-feasibility/remote/stage2-completion-local-control-v7/')]) == 13
assert tasks[3]['paths'] == ['.gitleaksignore','.github/workflows/ci.yml','docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json','docs/security-evidence/stage4-offline-readiness-artifacts/image-lock.json','docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json','docs/security-evidence/stage4-offline-readiness-artifacts/schema-inventory.json','docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json','docs/security-evidence/stage4-offline-readiness-package.json','docs/security-evidence/stage5-destructive-harness-report.canonical-json','scripts/stage4-offline-readiness.ts','scripts/stage4-offline-source-inventory.ts','scripts/stage4-runtime-artifact-closure.ts','test/ci-infrastructure-boundary.test.ts']
assert 'docs/adr/0339-row4-first-attempt-corrections.md' in tasks[0]['paths']
assert 'docs/adr/0340-row4-second-minimal-correction-batch.md' in tasks[0]['paths']
assert 'docs/adr/0341-row4-third-minimal-correction-batch.md' in tasks[0]['paths']
assert 'docs/adr/0342-row4-fourth-minimal-correction-batch.md' in tasks[0]['paths']
assert 'docs/adr/0343-row4-fifth-minimal-correction-batch.md' in tasks[0]['paths']
assert 'docs/adr/0344-row4-proactive-confirmed-domain-batch.md' in tasks[0]['paths']
assert 'docs/adr/0345-row4-sixth-runtime-correction.md' in tasks[0]['paths']
assert 'docs/adr/0346-row4-post-merge-product-correction.md' in tasks[0]['paths']
assert 'docs/adr/0347-add-direct-kvm-diagnostic-lane.md' in tasks[0]['paths']
assert 'docs/adr/0348-retire-transient-H-producer.md' in tasks[0]['paths']
assert tasks[1]['paths'] == ['.github/workflows/insecure-container.yml','.github/workflows/kvm-driver-diagnostic.yml','.github/workflows/kvm-qualification.yml','.github/workflows/release-images.yml','config/release-image-set-pins-v1.json','IMPLEMENTATION.md','dev/linux-kvm/driver.sh','dev/linux-kvm/bounded-command.py','dev/linux-kvm/qualification-owner.py','dev/linux-kvm/qualify.sh','dev/product-test/host-custody.py','dev/product-test/runner.ts','dev/product-test/snapshot-owner.ts','docs/adr/0337-correct-protected-product-runtime-ancestry.md','docs/operations/release-image-publication.md','docs/operations/production-runtime-foundation.md','docs/operations/stage-4-offline-readiness.md','docs/security-evidence/release-image-set-assertion-34774398155.canonical.json','docs/security-evidence/release-image-set-review-34774398155.canonical.json','docs/test-reports/stage-4-offline-readiness.md','images/sandbox/entrypoint.sh','schemas/release-image-set-assertion-v1.json','schemas/release-image-set-review-v3.json','schemas/stage4-authenticated-runtime-artifact-evidence-v4.json','schemas/stage4-offline-readiness-package-v5.json','scripts/release-image-set-review-v2.ts','scripts/release-image-set-review-v3.ts','scripts/stage4-offline-readiness-regenerate.ts','src/egress/otlp-telemetry.ts','src/egress/runtime-manager.ts','src/runtime/compose.ts','src/skills/snapshot-session-preparer.ts','src/ssh/connection.ts','src/telemetry/otlp-http.ts','src/telemetry/worker-telemetry.ts','test/egress-otlp-telemetry.test.ts','test/egress-runtime-manager.test.ts','test/launcher-smoke-evidence.test.ts','test/linux-kvm-git-tools.test.ts','test/otlp-http.test.ts','test/ssh-connection.test.ts','test/worker-telemetry.test.ts','test/dev-launcher-profiles.test.ts','test/production-compose.test.ts','test/production-sandbox-image.test.ts','test/release-image-set-assertion.test.ts','test/aws-stage2-completion-final-integration-linux.test.ts','test/aws-stage2-completion-immutable-preparation.test.ts','test/release-image-set-review-v2.test.ts','test/release-image-set-review-v3.test.ts','test/stage4-offline-readiness.test.ts','test/stage4-runtime-artifact-closure.test.ts']
assert paths['.gitleaksignore'] == 'integration'
local=tasks[2]['paths']
assert 'scripts/stage2-stage-production-approval.py' in local
assert 'test/stage2-production-workflows.test.ts' in local
assert tasks[2]['gross_lines'] == 4457 and tasks[2]['gross_bytes'] == 7400000
assert tasks[3]['gross_lines'] == 1800 and tasks[3]['gross_bytes'] == 4300000
assert tasks[-1]['pre_h_cap'] == {'gross_lines':1800,'gross_bytes':2000000}
assert tasks[-1]['post_h_reserve'] == {'gross_lines':3500,'gross_bytes':3500000}
assert b['source_limits'] == {'tracked_files':1540,'source_inventory_bytes':34000000,'serialized_source_inventory_bytes':262144}
for index in range(len(tasks)):
 bad=copy.deepcopy(b); bad['product_test_correction']['remaining_tranche']['allocations'][index]['name']='other'
 try: m['_product_test_budget'](bad,{})
 except m['LineBudgetError']: pass
 else: raise AssertionError(index)
bad=copy.deepcopy(b); bad['product_test_correction']['remaining_tranche']['allocations'][0]['paths'].append('unexpected.py')
try: m['_product_test_budget'](bad,{})
except m['LineBudgetError']: pass
else: raise AssertionError('path mutation accepted')
`);
});

test("ADR0338 records temporary runner-loss handling without effect authority", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8");
  const compact = adr.replace(/\s+/gu, " ");
  for (const phrase of [
    "Accepted as **Row 1 only**",
    "no product or KVM dispatch, no AWS, OpenTofu, or SSM effect",
    "separate local `TF_DATA_DIR`, state, and plan paths",
    "Tests use fakes only; they must not invoke OpenTofu",
    "sends exactly one command",
    "no automatic retry, success claim, or reuse",
    "destroys and confirms zero before the next cycle",
    "strict hard cap is **132,000 lines**",
    ".github/workflows/kvm-qualification.yml",
  ])
    assert.ok(compact.includes(phrase), phrase);
  for (const path of [
    "test/aws-stage2-completion-kata-mutable-bridges.test.ts",
    "test/aws-stage2-completion-kata-runtime.test.ts",
    "test/aws-stage2-completion-local-result.test.ts",
  ])
    assert.ok(compact.includes(path), path);
});

test("ADR0339 records failed first attempts and its exact post-merge authority", () => {
  const adr = readFileSync("docs/adr/0339-row4-first-attempt-corrections.md", "utf8");
  for (const phrase of [
    "34736648989",
    "34736650134",
    "09e586c2377738fabeee9d6900bf4b3f89c94372",
    "non-authoritative",
    "continue Rows 4–10 while\nstopping before AWS",
    "exact-tree\nreview, readiness and full checks, protected PR CI, and merge",
    "exactly one first-created\nattempt-one **Protected** product run and exactly one KVM qualification run for\nthe fresh replacement protected-main candidate",
    "same-byte retry, H/G/Q, AWS, OpenTofu, SSM, or network\neffects, or any other Docker or KVM execution",
    "literal product task includes `.github/workflows/kvm-qualification.yml`",
  ])
    assert.ok(adr.includes(phrase), phrase);
});

test("ADR0340 records the second failed attempts and preserves all execution stops", () => {
  const adr = readFileSync("docs/adr/0340-row4-second-minimal-correction-batch.md", "utf8");
  for (const phrase of [
    "de0c4ba3fec6f7caf51f198f3f5cea22c31f3d50",
    "34741154464",
    "34741155639",
    "non-authoritative",
    "source and focused review, full and readiness validation, protected PR CI, and merge",
    "Only after merge it authorizes exactly one fresh, first-created, attempt-one Protected product run and exactly one KVM qualification run",
    "No effect, full, or readiness execution occurs now",
    "Same-byte retry and H/G/Q remain denied",
    "AWS, OpenTofu, SSM, Docker/KVM/network effects remain denied",
    "caps, all other task caps, source-inventory bounds, and the final-HGQ reserve are unchanged",
  ])
    assert.ok(adr.includes(phrase), phrase);
  const index = readFileSync("docs/adr/README.md", "utf8");
  assert.ok(index.includes("[0340](0340-row4-second-minimal-correction-batch.md)"));
});

test("ADR0341 records third failed attempts and keeps caps and effects denied", () => {
  const adr = readFileSync("docs/adr/0341-row4-third-minimal-correction-batch.md", "utf8");
  for (const phrase of [
    "ed0263c3",
    "34747348323",
    "34747349534",
    "non-authoritative",
    "exactly one fresh first-created attempt-one replacement pair",
    "Same-byte retry and H/G/Q remain denied",
    "AWS, OpenTofu, SSM, Docker, KVM, network, and all effects remain denied now",
    "All caps and the final-HGQ reserve are unchanged",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(readFileSync("docs/adr/README.md", "utf8").includes("[0341](0341-row4-third-minimal-correction-batch.md)"));
});

test("ADR0342 records failed candidate-pass/KVM attempts and old-byte probes as non-authorizing", () => {
  const adr = readFileSync("docs/adr/0342-row4-fourth-minimal-correction-batch.md", "utf8");
  for (const phrase of [
    "ee114b7b50c34a9b9f93ea7f4248b426a90bb65f",
    "34751527567",
    "34751528484",
    "candidate-pass jobs failed",
    "eight-capability probe jobs succeeded only for old bytes",
    "non-authorizing",
    "source and focused review, full and readiness validation, protected PR CI, and merge",
    "No effects, full, or readiness execution occurs now",
    "exactly one fresh first-created attempt-one replacement pair",
    "Same-byte retry and H/G/Q remain denied",
    "RetirementUncertain",
    "All caps, allocations, source-inventory bounds, and the final-HGQ reserve are unchanged",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(
    readFileSync("docs/adr/README.md", "utf8").includes("[0342](0342-row4-fourth-minimal-correction-batch.md)"),
  );
});

test("ADR0343 records failed old-byte probes as non-authorizing and retains execution stops", () => {
  const adr = readFileSync("docs/adr/0343-row4-fifth-minimal-correction-batch.md", "utf8");
  for (const phrase of [
    "c92aaeaa",
    "34756063319",
    "34756064403",
    "Both product probe suites succeeded only for old bytes, but the candidate profiles failed; KVM failed",
    "non-authoritative and non-authorizing",
    "normal source correction, review, validation, protected PR CI, and merge",
    "No effects, full, or readiness execution occurs now",
    "exactly one fresh first-created attempt-one replacement pair",
    "Same-byte retry and H/G/Q remain denied",
    "AWS, OpenTofu, SSM, Docker, KVM, network, and all other effects remain denied",
    "All caps, allocations, source-inventory bounds, and the final-HGQ reserve are unchanged",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(readFileSync("docs/adr/README.md", "utf8").includes("[0343](0343-row4-fifth-minimal-correction-batch.md)"));
});

test("ADR0345 records sixth failures, bounded diagnosis, exact corrections, and no present effects", () => {
  const adr = readFileSync("docs/adr/0345-row4-sixth-runtime-correction.md", "utf8");
  for (const phrase of [
    "533341db2cb4601fa47cf9ad0fbc92eb3b9036dd",
    "34782632633",
    "34782634239",
    "same bytes are retired as a Product/KVM dispatch candidate",
    "non-authoritative, and non-authorizing",
    "fresh local x86_64 Lima execution used diagnostic-modified bytes",
    "diagnostic only, too slow for pass authority",
    "two-second worker/skill reply waits",
    "15-second synchronous helper-command bound",
    "complete 20-second service bound",
    "65-second initial gate-acquisition bound",
    "25-second snapshot-control acquisition bound",
    "retained exact worker/sandbox pidfds alive",
    "105-second initial receipt-publication wait",
    "four-second outer observation deadline",
    "five-second startup window",
    '`diagnostic:"status"`',
    "`application-exit` for application exit 1",
    "`skill-gate-exit` for skill-gate exits 70–74",
    "`other-exit` for every other/signal-like exit",
    "1,000-millisecond runtime operation/revocation bound",
    "20,000-millisecond manager startup-observation bound",
    "15,000-millisecond Envoy startup bound",
    "runtime-mask `ssh.socket` and `ssh.service` in one fail-fast early cloud-init transaction",
    "with no late reload/restart",
    "source implementation, focused review, full and readiness validation, protected PR CI, merge",
    "protected pair remains denied until the exact merged source and consumed image pass suitable Product and KVM diagnostics",
    "exactly one fresh first-created attempt-one pair",
    "Same-byte retry remains denied",
    "H, G, Q, AWS, OpenTofu, SSM",
    "No image definition, release pin, cap, allocation, source-inventory bound, or final-HGQ reserve changes",
    "no cap raise, transfer, deletion credit, or reserve use",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(readFileSync("docs/adr/README.md", "utf8").includes("[0345](0345-row4-sixth-runtime-correction.md)"));
});

test("ADR0346 records post-merge diagnostics, bounded corrections, and the AWS stop", () => {
  const adr = readFileSync("docs/adr/0346-row4-post-merge-product-correction.md", "utf8");
  for (const phrase of [
    "1df3426f099b9beba5e9f4864cacdad49ba0dbdc",
    "superseded before dispatch, not retired authoritative evidence",
    "selected `[::1]:18443`",
    "InvalidArgumentError: invalid content-length header",
    "dual-stack wildcard with `ipv6Only: false`",
    "do not supply a caller-owned `content-length`",
    "Transfer 200 unused governance lines to Product",
    "Only after those diagnostics converge may exactly one fresh first-created attempt-one protected Product/KVM pair",
    "AWS, provider initialization, OpenTofu, SSM, inventory, deployment, and campaign effects remain denied",
    "stop before the first AWS operation",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(readFileSync("docs/adr/README.md", "utf8").includes("[0346](0346-row4-post-merge-product-correction.md)"));
});

test("ADR0347 requires three non-authorizing KVM diagnostics before one protected pair", () => {
  const adr = readFileSync("docs/adr/0347-add-direct-kvm-diagnostic-lane.md", "utf8");
  for (const phrase of [
    "d033b9c427a8cc1f886d21bd2613036e039b71b2",
    "supersedes it before dispatch",
    "separate protected-main, manual, attempt-one-only direct KVM diagnostic workflow",
    "has `permissions: {}`, accepts no input, token, secret, artifact, provider, or caller-selected revision",
    '`authority:"diagnostic-only"`',
    "At least three fresh direct-KVM dispatches must pass",
    "Transfer 400 unused governance lines to Product",
    "No AWS, provider initialization, OpenTofu, SSM, inventory, deployment, campaign, H, G, or Q operation",
    "stops immediately before the first AWS campaign operation",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(readFileSync("docs/adr/README.md", "utf8").includes("[0347](0347-add-direct-kvm-diagnostic-lane.md)"));
});

test("ADR0348 retires the failed H producer and requires full replacement convergence", () => {
  const adr = readFileSync("docs/adr/0348-retire-transient-H-producer.md", "utf8");
  for (const phrase of [
    "34831102547",
    "34831105333",
    "34831612221",
    "failed before building at closed stage `artifact.redirect.status`",
    "Three subsequent unique local diagnostic generations each downloaded and verified all 16 fixed public artifacts",
    "Retire H `9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e` and producer run `34831612221`",
    "Make no acquisition, retry, redirect, timeout, rootfs, runtime, image, provider, or campaign behavior change",
    "repeat exact-source Product diagnostics, three fresh direct KVM diagnostics, and exactly one fresh first-created attempt-one protected Product/KVM pair",
    "Transfer 1,000,000 unused bytes from local-tofu-ssm to readiness-ci",
    "No AWS, provider initialization, OpenTofu, SSM, inventory, deployment, or campaign operation",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(adr.includes("Do not mutate the old Q-authenticated retirement parser or policy in place"));
  assert.ok(readFileSync("docs/adr/README.md", "utf8").includes("[0348](0348-retire-transient-H-producer.md)"));
});

test("ADR0349 freezes replacement H, producer, and additive retirement V2", () => {
  const adr = readFileSync("docs/adr/0349-freeze-replacement-H-and-authorize-control.md", "utf8");
  for (const phrase of [
    "1ef6aae3506fded805d8277ec4bce02e585c0650",
    "34852537897",
    "34852537647",
    "34853517895",
    "10352673587",
    "two byte-identical builds",
    "Preserve `config/stage2-retired-revisions-v1.json` byte-identically",
    "Update the closed Python selector and all nineteen pre-effect workflow mirror occurrences together",
    "sole parent is H",
    "no AWS, credentials, provider initialization, OpenTofu, SSM, inventory, deployment, campaign",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(
    readFileSync("docs/adr/README.md", "utf8").includes("[0349](0349-freeze-replacement-H-and-authorize-control.md)"),
  );
});

test("ADR0350 binds the replacement static observation and authorizes qualification only", () => {
  const adr = readFileSync("docs/adr/0350-establish-replacement-Q-and-authorize-qualification.md", "utf8");
  for (const phrase of [
    "fce64662b39b2a21e9b384eba8408ecd5311047a",
    "34872020437",
    "10359751882",
    "34876857175",
    "10361229317",
    "sha256:478275cdb16c9614a32854239d98d6f9d9ce6e5cffd466b5def69a1760108b5d",
    "exact thirteen independently read-back members",
    "byte for byte and without reserialization",
    "one commit whose sole parent is exact G",
    "final pre-effect repository-variable interlock",
    "exactly one first-created attempt-one exact H/G/Q mixed preflight",
    "exactly one first-created attempt-one seven-runner qualification run",
    "stop immediately before `.github/workflows/stage2-production-plan.yml`",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(
    readFileSync("docs/adr/README.md", "utf8").includes(
      "[0350](0350-establish-replacement-Q-and-authorize-qualification.md)",
    ),
  );
});

test("central checker accepts the current cumulative linear plan", () => {
  const result = spawnSync("python3", ["-I", "-B", "scripts/check-stage2-retained-lines.py"], {
    encoding: "utf8",
    timeout: 180_000,
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout) as { hard_satisfied: boolean; product_test_task_gross_added_lines: object };
  assert.equal(report.hard_satisfied, true);
  assert.deepEqual(Object.keys(report.product_test_task_gross_added_lines).sort(), [
    "final-HGQ",
    "governance",
    "local-tofu-ssm",
    "product",
    "readiness-ci",
  ]);
});

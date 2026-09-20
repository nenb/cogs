import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const runPython = (program: string) => {
  const result = spawnSync("python3", ["-I", "-B", "-c", program], { encoding: "utf8", timeout: 60_000 });
  assert.equal(result.status, 0, result.stderr);
};

test("ADR0338 through ADR0351 retain the five literal tasks and final reserve", () => {
  runPython(`
import copy,json,runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py')
b,_,paths,_,_=m['_remediation_budget']()
p=b['product_test_correction']; tasks=p['remaining_tranche']['allocations']
assert [t['name'] for t in tasks] == ['governance','product','local-tofu-ssm','readiness-ci','final-HGQ']
assert [(t['gross_lines'],t['gross_bytes']) for t in tasks] == [(5400,1100000),(5200,3200000),(4457,3800000),(1800,7900000),(5300,5500000)]
assert (p['remaining_tranche']['gross_lines'],p['remaining_tranche']['gross_bytes']) == (22157,21500000)
assert (p['global_gross_line_forecast'],p['global_gross_byte_forecast']) == (40157,29500000)
assert len(tasks[-1]['paths']) == 42
assert tasks[-1]['paths'] == sorted(tasks[-1]['paths'])
assert 'BUGS-TO-FIX.md' in tasks[0]['paths']
for path in ['config/stage2-retired-revisions-v2.json','deploy/aws-feasibility/remote/completion_kata_process.py','docs/adr/0349-freeze-replacement-H-and-authorize-control.md','docs/adr/0350-establish-replacement-Q-and-authorize-qualification.md','scripts/stage2-prebuilt-local-qualification-guard.py','scripts/stage2-prebuilt-mixed-hg-preflight.sh','scripts/stage2-revision-retirement.py','test/aws-stage2-completion-kata-process.py','test/stage2-prebuilt-rehearsal-grant.py']:
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
assert 'docs/adr/0351-correct-aws-host-boundaries-before-new-h.md' in tasks[0]['paths']
assert tasks[1]['paths'] == ['.github/workflows/insecure-container.yml','.github/workflows/kvm-driver-diagnostic.yml','.github/workflows/kvm-qualification.yml','.github/workflows/release-images.yml','config/release-image-set-pins-v1.json','IMPLEMENTATION.md','dev/linux-kvm/driver.sh','dev/linux-kvm/bounded-command.py','dev/linux-kvm/qualification-owner.py','dev/linux-kvm/qualify.sh','dev/product-test/host-custody.py','dev/product-test/runner.ts','dev/product-test/snapshot-owner.ts','docs/adr/0337-correct-protected-product-runtime-ancestry.md','docs/operations/release-image-publication.md','docs/operations/production-runtime-foundation.md','docs/operations/stage-4-offline-readiness.md','docs/security-evidence/release-image-set-assertion-34774398155.canonical.json','docs/security-evidence/release-image-set-review-34774398155.canonical.json','docs/test-reports/stage-4-offline-readiness.md','images/sandbox/entrypoint.sh','schemas/release-image-set-assertion-v1.json','schemas/release-image-set-review-v3.json','schemas/stage4-authenticated-runtime-artifact-evidence-v4.json','schemas/stage4-offline-readiness-package-v5.json','scripts/release-image-set-review-v2.ts','scripts/release-image-set-review-v3.ts','scripts/stage4-offline-readiness-regenerate.ts','src/egress/otlp-telemetry.ts','src/egress/runtime-manager.ts','src/runtime/compose.ts','src/skills/snapshot-session-preparer.ts','src/ssh/connection.ts','src/telemetry/otlp-http.ts','src/telemetry/worker-telemetry.ts','test/egress-otlp-telemetry.test.ts','test/egress-runtime-manager.test.ts','test/launcher-smoke-evidence.test.ts','test/linux-kvm-git-tools.test.ts','test/otlp-http.test.ts','test/ssh-connection.test.ts','test/worker-telemetry.test.ts','test/dev-launcher-profiles.test.ts','test/production-compose.test.ts','test/production-sandbox-image.test.ts','test/release-image-set-assertion.test.ts','test/aws-stage2-completion-final-integration-linux.test.ts','test/aws-stage2-completion-immutable-preparation.test.ts','test/release-image-set-review-v2.test.ts','test/release-image-set-review-v3.test.ts','test/stage4-offline-readiness.test.ts','test/stage4-runtime-artifact-closure.test.ts']
assert paths['.gitleaksignore'] == 'integration'
local=tasks[2]['paths']
assert '.github/workflows/stage2-production-approval-signing-diagnostic.yml' in local
assert '.github/workflows/stage2-r-diagnostic-campaign.yml' in local
assert '.github/workflows/stage2-r-diagnostic-preparation.yml' in local
assert 'scripts/stage2-cosign-keyless-sign.sh' in local
assert 'scripts/stage2-stage-production-approval.py' in local
assert 'test/stage2-production-approval.test.ts' in local
assert 'test/stage2-production-workflows.test.ts' in local
assert tasks[2]['gross_lines'] == 4457 and tasks[2]['gross_bytes'] == 3800000
assert tasks[3]['gross_lines'] == 1800 and tasks[3]['gross_bytes'] == 7900000
assert tasks[-1]['pre_h_cap'] == {'gross_lines':1800,'gross_bytes':2000000}
assert tasks[-1]['post_h_reserve'] == {'gross_lines':3500,'gross_bytes':3500000}
assert b['source_limits'] == {'tracked_files':1546,'source_inventory_bytes':34000000,'serialized_source_inventory_bytes':262144}
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

test("ADR0338 and the bug register retire failed R2 approval authority", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "89b0a5b5843373ab92710ce92008fe1b4e6ca658",
      "35114827724",
      "35118929555",
      "mode-`0700`",
      "terminal",
      "non-authorizing",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(bugs.includes("produced no approval artifact"));
  assert.ok(bugs.includes("No campaign was dispatched"));
  assert.ok(adr.includes("exact positive numeric UID/GID"));
  assert.ok(adr.includes("grants no retry, planning, approval, provider, or AWS-effect authority"));
});

test("ADR0338 and the bug register retire failed R3 approval and gate R4 on diagnostics", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "cb30f534ce8801f605a5c021656d7569ff35306c",
      "35148506458",
      "10468186158",
      "35150577796",
      "mkdir /.sigstore",
      "terminal",
      "non-authorizing",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(bugs.includes("It produced no approval artifact"));
  assert.ok(adr.includes("live TUF initialization, GitHub OIDC"));
  assert.ok(adr.includes("raise the tracked-file source limit from 1,541 to 1,543"));
  assert.ok(adr.includes("Neither R4 nor its diagnostic grants a retry"));
});

test("ADR0338 and the bug register retire the successful unused R4 generation", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "1116692df81f40c9f3f60c0a7448bcb46167cc61",
      "35170392903",
      "10476681104",
      "35172329037",
      "10476784540",
      "447f6e4a73aab1911bb66f07e4b86f92501592dd58e9e341c4ddb1cbb337e4a8",
      "2026-09-17T08:24:18Z",
      "expired unused",
      "terminal",
      "permanently non-authorizing",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(adr.includes("successful R4 signing diagnostic"));
  assert.ok(adr.includes("all signer, approval, planning, campaign, provider, and executable bytes"));
  assert.ok(adr.includes("active byte highs 6,100,000 and 5,600,000"));
  assert.ok(bugs.includes("No campaign was dispatched"));
  assert.ok(bugs.includes("independent inventory found zero campaign resources"));
  assert.ok(bugs.includes("R5 grants no IAM setup, planning, approval, campaign, retry, or AWS authority"));
});

test("ADR0338 retires R5 planning and authorizes only the bounded R6 window correction", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "87be0712de3889721b7c4ed3194c32646f823356",
      "35225324388",
      "10498263515",
      "1df0a4f015d225464929b1dece0b4a2d24fe75bf3cddf5ecb8ea9c0360101350",
      "5a29a9601d008640d7789adef3b0a7914b1bff5e71b520d5ea07a0eb0db4f931",
      "2026-09-17T14:35:23Z",
      "5,140 seconds",
      "terminal and permanently non-authorizing",
      "16,500 seconds",
      "14,700-second effect-and-cleanup envelope",
      "2h24m",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(adr.includes("expressly supersedes the earlier no-production-control-plane-redesign constraint"));
  assert.ok(adr.includes("preserve exact H/G/Q"));
  assert.ok(adr.includes("campaign's minimum derived credential duration from 20,000 to 16,500 seconds"));
  assert.ok(adr.includes("active byte highs 5,900,000 and 5,800,000"));
  assert.ok(adr.includes("authorize-seven-stage2-production-cycles"));
  assert.ok(bugs.includes("No approval or campaign run exists at R5"));
  assert.ok(bugs.includes("campaign spend was zero"));
});

test("ADR0338 retires failed exact-head R6 CI and authorizes governance-only R7", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "2975deffaf20f518d6611f5757fc2778f7e53d50",
      "48c379d2027df7016f7aca5a1eca09b45cdb9cd3",
      "35259074785",
      "35259074947",
      "attempt 1",
      "TooManyRequests 503 No healthy backends",
      "terminal",
      "governance-only successor",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(adr.includes("active byte highs 5,600,000 and 6,100,000"));
  assert.ok(adr.includes("must not change H/G/Q, the 16,500-second campaign guard"));
  assert.ok(
    bugs.includes(
      "No R6 IAM setup, planning, approval, campaign, provider, OpenTofu, SSM, or resource operation occurred",
    ),
  );
  assert.ok(bugs.includes("cannot be retried into authority"));
});

test("ADR0338 retires the failed R7 campaign and authorizes only the tag-read guard", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "6a28492a70ee3b0eaffa57e8355070ee865492b9",
      "e52a42a82456182d5a0e5cb618b2430d3550d74f",
      "35275965649",
      "10519889589",
      "22948dfcc672cd9ec2c15457d205fde5f8a79e6784d9e295d2f63e3f50a9acb5",
      "35278527916",
      "10521084322",
      "43e775acd96f7994612c6db70370d97e921fe42e2039586731647ad911ef9fe7",
      "35281016121",
      "budgets:ListTagsForResource",
      "AccessDenied",
      "NotFoundException",
      "2026-09-17T22:23:06Z",
      "terminal and permanently non-authorizing",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(adr.includes("before a provider apply receipt, SSM command, workload, or measurement"));
  assert.ok(adr.includes("recovery could not reach destroy"));
  assert.ok(adr.includes("GetInstanceUefiData"));
  assert.ok(adr.includes("Repeated independent inventory returned total zero"));
  assert.ok(adr.includes("must preserve exact H/G/Q, the 16,500-second campaign guard"));
  assert.ok(adr.includes("active byte highs 5,300,000 and 6,400,000"));
  assert.ok(bugs.includes("Fresh IAM bootstrap must add and simulate `budgets:ListTagsForResource`"));
  assert.ok(bugs.includes("protected CI, fresh IAM setup, fresh read-only planning authorization"));
});

test("ADR0338 retires R8 and permits only a non-authoritative end-to-end diagnostic", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "fff2b20f89b1aae26158376104ada8425f8a0d19",
      "35293994076",
      "10526314592",
      "6d4c5deb521734dcde4ecbca203fdf1b94f7d945fe586a7e110ee9214c29130d",
      "35295519831",
      "10527701595",
      "7b1ecc45c2818c884ae112d8ca28b7431585612bc909100d05a90f87ba163b5f",
      "35297082154",
      "06a3f62c-20b4-4bfa-9f75-b45e2196bacc",
      "immutable Stage 2 preparation failed at entry",
      "/usr/bin/env -i",
      "authorize-seven-stage2-non-authoritative-diagnostic-cycles",
      "1,543 to 1,545",
      "terminal",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(adr.includes("No Kata launch, workload, measurement, successful cycle, or evidence"));
  assert.ok(adr.includes("publish no accepted production evidence"));
  assert.ok(adr.includes("grants no H, G, Q, R, production"));
  assert.ok(bugs.includes("publish only a digest manifest"));
  assert.ok(bugs.includes("Only a seven-cycle pass"));
  assert.ok(adr.includes("active byte highs 5,000,000 and 6,700,000"));
});

test("ADR0338 retires the first diagnostic planning export without retry authority", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "8f1bf3032668c6f986fa31145911a42c0ece7925",
      "a9d3635aa67be3d047f97dc57a9e2c7242d1b140",
      "35354704622",
      "35354704494",
      "35369019149",
      "10557980075",
      "3cd400242d442cbb741d50a3e737c4e1cce87cbcf61dcf41612755c91c5fc862",
      "plans/.provider-tf-data",
      "start-stage2-r-diagnostic-window",
      "terminal and permanently non-authorizing",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(adr.includes("zero active resources in all 17 enabled regions"));
  assert.ok(adr.includes("No approval was issued or signed"));
  assert.ok(bugs.includes("No signing, approval artifact, campaign dispatch, resource creation"));
  assert.ok(adr.includes("active byte highs 4,700,000 and 7,000,000"));
});

test("ADR0338 retires the approval-environment diagnostic failure without campaign authority", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "ce4b5895e16e882067cd01bc258394e25bc42048",
      "bb324ac7763caca746e734353d7b60257f2c5ec7",
      "35377483991",
      "35377483993",
      "35390352878",
      "10566006682",
      "65ed5766f877e3302a2d3f0c96c685269827305bf54d1586b96971c94526ea18",
      "COGS_STAGE2_CONTROL_REVISION",
      "terminal and permanently non-authorizing",
      "active byte highs 4,400,000 and 7,300,000",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(adr.includes("passed exact artifact readback"));
  assert.ok(adr.includes("No approval or signature was produced"));
  assert.ok(bugs.includes("No approval artifact, campaign dispatch, resource creation"));
});

test("ADR0338 batches cancelled checks and the complete no-cloud diagnostic audit", () => {
  const adr = readFileSync("docs/adr/0338-plan-pre-h-final-corrections.md", "utf8").replace(/\s+/gu, " ");
  const bugs = readFileSync("BUGS-TO-FIX.md", "utf8").replace(/\s+/gu, " ");
  for (const source of [adr, bugs]) {
    for (const phrase of [
      "3be83879c87b552f7cdb07480ceda5e843add905",
      "570b8f4c527d8156ca14d4db389a999f060be70a",
      "35392818607",
      "35392818603",
      "35397053515",
      "35397053474",
      "explicitly cancelled",
      "Forty-one focused",
      "additional diagnostic defect was found",
      "authorize-complete-stage2-r-non-authoritative-diagnostic",
      "active byte highs 4,100,000 and 7,600,000",
    ])
      assert.ok(source.includes(phrase), phrase);
  }
  assert.ok(adr.includes("All seven plan binaries matched the draft"));
  assert.ok(adr.includes("No workflow or AWS operation occurred"));
  assert.ok(bugs.includes("Complete local validation must precede"));
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

test("ADR0351 authorizes only bounded AWS host corrections before a new H", () => {
  const adr = readFileSync("docs/adr/0351-correct-aws-host-boundaries-before-new-h.md", "utf8").replace(/\s+/gu, " ");
  for (const phrase of [
    "umask 022",
    "fwupd-refresh.timer",
    "/proc/sys/net/ipv4/ip_forward",
    "Preserve the cgroup implementation byte-for-byte",
    "non-authoritative static observation/control package",
    "complete seven-cycle AWS rehearsal",
    "clean rehearsal cannot itself authorize or produce H",
    "G must then have that exact H as its sole parent",
    "Q must have that exact fresh G as its sole parent",
  ])
    assert.ok(adr.includes(phrase), phrase);
  assert.ok(
    readFileSync("docs/adr/README.md", "utf8").includes("[0351](0351-correct-aws-host-boundaries-before-new-h.md)"),
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

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const runPython = (program: string) => {
  const result = spawnSync("python3", ["-I", "-B", "-c", program], { encoding: "utf8", timeout: 60_000 });
  assert.equal(result.status, 0, result.stderr);
};

test("ADR0338/ADR0339 retain the five literal tasks and final reserve", () => {
  runPython(`
import copy,json,runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py')
b,_,paths,_,_=m['_remediation_budget']()
p=b['product_test_correction']; tasks=p['remaining_tranche']['allocations']
assert [t['name'] for t in tasks] == ['governance','product','local-tofu-ssm','readiness-ci','final-HGQ']
assert [(t['gross_lines'],t['gross_bytes']) for t in tasks] == [(6000,1100000),(4000,3200000),(4457,8400000),(1800,2000000),(5300,5500000)]
assert (p['remaining_tranche']['gross_lines'],p['remaining_tranche']['gross_bytes']) == (21557,20200000)
assert (p['global_gross_line_forecast'],p['global_gross_byte_forecast']) == (39557,28200000)
assert tasks[-1]['paths'] == ['test/aws-stage2-completion-kata-mutable-bridges.test.ts','test/aws-stage2-completion-kata-runtime.py','test/aws-stage2-completion-kata-runtime.test.ts','test/aws-stage2-completion-local-result.test.ts','test/stage2-prebuilt-local-kata-workflow.test.ts']
assert tasks[3]['paths'] == ['.gitleaksignore','.github/workflows/ci.yml','docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json','docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json','docs/security-evidence/stage4-offline-readiness-package.json','scripts/stage4-offline-readiness.ts','scripts/stage4-offline-source-inventory.ts','test/ci-infrastructure-boundary.test.ts']
assert 'docs/adr/0339-row4-first-attempt-corrections.md' in tasks[0]['paths']
assert {'dev/linux-kvm/driver.sh','test/linux-kvm-git-tools.test.ts','dev/product-test/host-custody.py','dev/product-test/runner.ts','dev/product-test/snapshot-owner.ts','test/production-compose.test.ts'} <= set(tasks[1]['paths'])
assert paths['.gitleaksignore'] == 'integration'
local=tasks[2]['paths']
assert 'scripts/stage2-stage-production-approval.py' in local
assert 'test/stage2-production-workflows.test.ts' in local
assert tasks[2]['gross_lines'] == 4457 and tasks[2]['gross_bytes'] == 8400000
assert tasks[-1]['pre_h_cap'] == {'gross_lines':1800,'gross_bytes':2000000}
assert tasks[-1]['post_h_reserve'] == {'gross_lines':3500,'gross_bytes':3500000}
assert b['source_limits'] == {'tracked_files':1530,'source_inventory_bytes':34000000,'serialized_source_inventory_bytes':262144}
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
  ])
    assert.ok(adr.includes(phrase), phrase);
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

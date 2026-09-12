import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const runPython = (program: string) => {
  const result = spawnSync("python3", ["-I", "-B", "-c", program], { encoding: "utf8", timeout: 60_000 });
  assert.equal(result.status, 0, result.stderr);
};

test("ADR0338 has the five literal Row 1 tasks and preserves its final reserve", () => {
  runPython(`
import copy,json,runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py')
b,_,_,_,_=m['_remediation_budget']()
p=b['product_test_correction']; tasks=p['remaining_tranche']['allocations']
assert [t['name'] for t in tasks] == ['governance','product','local-tofu-ssm','readiness-ci','final-HGQ']
assert [(t['gross_lines'],t['gross_bytes']) for t in tasks] == [(6000,1100000),(4000,3200000),(4457,8400000),(1800,2000000),(5300,5500000)]
assert (p['remaining_tranche']['gross_lines'],p['remaining_tranche']['gross_bytes']) == (21557,20200000)
assert (p['global_gross_line_forecast'],p['global_gross_byte_forecast']) == (39557,28200000)
assert tasks[-1]['paths'] == []
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

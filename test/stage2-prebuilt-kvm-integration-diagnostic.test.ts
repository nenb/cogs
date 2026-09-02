import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflowPath = ".github/workflows/stage2-prebuilt-kvm-integration-diagnostic.yml";
const workflow = readFileSync(workflowPath, "utf8");
const lock = readFileSync("config/stage2-prebuilt-kvm-diagnostic-lock-v1.json", "utf8");
const occurrences = (source: string, value: string) => source.split(value).length - 1;

test("reusable KVM diagnostic has a distinct repeatable non-authorizing workflow identity", () => {
  assert.match(workflow, /^name: Stage 2 reusable prebuilt KVM integration diagnostic$/mu);
  assert.match(workflow, /^\s{2}workflow_dispatch:\s*$/mu);
  assert.doesNotMatch(workflow, /workflow_dispatch:\s*\n\s+inputs:/u);
  assert.equal(occurrences(workflow, 'test "$GITHUB_REF_PROTECTED" = true'), 2);
  assert.equal(occurrences(workflow, 'test "$GITHUB_RUN_ATTEMPT" = 1'), 4);
  assert.doesNotMatch(workflow, /gh api|GH_TOKEN|workflow_runs|first-created|concurrency:/u);
  assert.doesNotMatch(
    workflow,
    /actions\/(?:upload|download)-artifact|aws-actions|configure-aws|opentofu|terraform|packages:\s*write|id-token:\s*write/u,
  );
  assert.match(workflow, /permissions:\n\s{2}contents: read/u);
  assert.equal(occurrences(workflow, "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"), 2);
  assert.equal(occurrences(workflow, "persist-credentials: false"), 2);
});

test("full and readiness run in independent fresh jobs with complete no-mint settlement", () => {
  assert.match(workflow, /^ {2}full:\n/mu);
  assert.match(workflow, /^ {2}readiness:\n/mu);
  assert.equal(occurrences(workflow, "completion_kata_immutable_preparation.py"), 2);
  assert.equal(occurrences(workflow, "stage2-prebuilt-kvm-diagnostic-lock.py descriptor"), 2);
  assert.equal(occurrences(workflow, "stage2-prebuilt-kvm-diagnostic-lock.py adjuncts"), 2);
  assert.equal(occurrences(workflow, "run-stage2-completion-full-rehearsal.sh"), 1);
  assert.equal(occurrences(workflow, "run-stage2-completion-readiness-rehearsal.sh"), 1);
  assert.equal(occurrences(workflow, "recover-stage2-completion-remote.sh"), 2);
  assert.equal(occurrences(workflow, "stage2-local-settlement.py cleanup"), 2);
  assert.equal(occurrences(workflow, "stage2-local-settlement.py residue"), 2);
  assert.doesNotMatch(workflow, /completion_local_full|stage2-local-publication|stage2-local-upload-receipt/u);
  const aggregate = workflow.slice(workflow.indexOf("  aggregate:"));
  assert.doesNotMatch(aggregate, /checkout|artifact|REPORT_|sudo/u);
  assert.match(aggregate, /FULL: \$\{\{ needs\.full\.result \}\}/u);
  assert.match(aggregate, /READINESS: \$\{\{ needs\.readiness\.result \}\}/u);
});

test("diagnostic lock pins the prior authenticated immutable publication and failed rehearsal", () => {
  const value = JSON.parse(lock) as Record<string, unknown>;
  assert.equal(value.authority, "diagnostic-only-non-authorizing");
  assert.equal(value.profile, "reusable-no-mint-kvm-integration");
  assert.match(lock, /33615572679/u);
  assert.match(lock, /9840794063/u);
  assert.match(lock, /662bdd78f5b3088a37e226c54847cd19d3bb6ac044dc23f800046111d9983c45/u);
  assert.match(lock, /f80a3eafb00a184fa0899014c91401d7d5f06d757b29f38562070d0b5dab2a67/u);
  assert.match(lock, /41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397/u);
  assert.match(lock, /33615698328/u);
  assert.match(lock, /failed-non-authorizing/u);
});

test("hostile lock or custody changes fail and formal control, grant, and mint reject the profile", () => {
  const program = `
import copy,importlib.util,json,sys
from pathlib import Path
root=Path.cwd()
spec=importlib.util.spec_from_file_location('diagnostic_lock',root/'scripts/stage2-prebuilt-kvm-diagnostic-lock.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
value,raws=m.load_lock(); lock=json.loads((root/'config/stage2-prebuilt-kvm-diagnostic-lock-v1.json').read_bytes())
def rejected(call):
 try:call()
 except Exception:pass
 else:raise AssertionError('hostile diagnostic input accepted')
for mutate in (
 lambda x:x.update(profile='formal'),
 lambda x:x['publication'].update(run_id=1),
 lambda x:x['publication'].update(oci_digest='sha256:'+'0'*64),
 lambda x:x['historical_rehearsal'].update(authority='pass'),
 lambda x:x['custody'][0].update(size=1),
 lambda x:x.update(extra=True),
):
 hostile=copy.deepcopy(lock);mutate(hostile)
 rejected(lambda:m.load_lock(m.canonical(hostile),raws))
for name in sorted(raws):
 hostile=dict(raws);hostile[name]=raws[name][:-1]+bytes([raws[name][-1]^1])
 rejected(lambda hostile=hostile:m.load_lock(custody=hostile))
sys.path.insert(0,str(root/'deploy/aws-feasibility/remote'))
sys.path.insert(0,str(root/'deploy/aws-feasibility'))
import completion_cycle_authority as authority
import completion_cycle_evidence as evidence
import completion_kata_preparation as preparation
lock_raw=(root/'config/stage2-prebuilt-kvm-diagnostic-lock-v1.json').read_bytes()
rejected(lambda:authority.decode(lock_raw))
rejected(lambda:preparation.load_control(lock_raw))
rejected(lambda:evidence._issue_cycle_receipt(value,object()))
print('diagnostic separation checks passed')
`;
  for (const optimization of [[], ["-O"]]) {
    const result = spawnSync("python3", [...optimization, "-B", "-c", program], {
      encoding: "utf8",
      timeout: 20_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "diagnostic separation checks passed\n");
  }
});

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflowPath = ".github/workflows/stage2-prebuilt-kvm-integration-diagnostic.yml";
const workflow = readFileSync(workflowPath, "utf8");
const lock = readFileSync("config/stage2-prebuilt-kvm-diagnostic-lock-v1.json", "utf8");
const occurrences = (source: string, value: string) => source.split(value).length - 1;
const oldImplementation = "5bced6bdc54756761f28a393970301b9b24341cc";
const profile = "cogs.stage2-current-source-prebuilt-diagnostic-control/v1";

test("reusable diagnostic is protected, repeatable, read-only, and independently fresh", () => {
  assert.match(workflow, /^name: Stage 2 reusable prebuilt KVM integration diagnostic$/mu);
  assert.match(workflow, /^\s{2}workflow_dispatch:\s*$/mu);
  assert.doesNotMatch(workflow, /workflow_dispatch:\s*\n\s+inputs:|concurrency:|workflow_runs|first-created/u);
  assert.equal(occurrences(workflow, 'test "$GITHUB_REF_PROTECTED" = true'), 2);
  assert.equal(occurrences(workflow, 'test "$GITHUB_RUN_ATTEMPT" = 1'), 4);
  assert.equal(occurrences(workflow, "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"), 2);
  assert.equal(occurrences(workflow, "persist-credentials: false"), 2);
  assert.match(workflow, /permissions:\n\s{2}contents: read/u);
  assert.doesNotMatch(
    workflow,
    /actions\/(?:upload|download)-artifact|aws-actions|configure-aws|opentofu|terraform|packages:\s*write|id-token:\s*write/u,
  );
});

test("both jobs materialize and execute GITHUB_SHA, never the prior producer implementation", () => {
  assert.match(workflow, /^ {2}full:\n/mu);
  assert.match(workflow, /^ {2}readiness:\n/mu);
  assert.equal(occurrences(workflow, "scripts/prepare-stage2-fixed-source.py"), 2);
  assert.equal(occurrences(workflow, ')["revision"])\')" = "$GITHUB_SHA"'), 2);
  assert.equal(occurrences(workflow, "completion_kata_diagnostic_control.py"), 2);
  assert.equal(occurrences(workflow, "completion_cycle_full_diagnostic.py"), 1);
  assert.equal(occurrences(workflow, "completion_cycle_readiness_diagnostic.py"), 1);
  assert.equal(occurrences(workflow, `provisional "$DIAGNOSTIC_CONTROL_VERSION"`), 2);
  assert.equal(occurrences(workflow, profile), 1);
  assert.doesNotMatch(workflow, new RegExp(oldImplementation, "u"));
  assert.doesNotMatch(
    workflow,
    /stage2-implementation|git (?:fetch|init)|rehearsal-grant|full-rehearsal|readiness-rehearsal/u,
  );
});

test("fixed rootfs custody is acquired twice while mint, report, and publication stay absent", () => {
  assert.equal(occurrences(workflow, "completion_kata_immutable_preparation.py"), 2);
  assert.equal(occurrences(workflow, "stage2-prebuilt-kvm-diagnostic-lock.py descriptor"), 2);
  assert.equal(occurrences(workflow, "stage2-prebuilt-kvm-diagnostic-lock.py adjuncts"), 2);
  assert.equal(occurrences(workflow, "recover-stage2-completion-remote.sh"), 2);
  assert.equal(occurrences(workflow, "stage2-local-settlement.py cleanup"), 2);
  assert.equal(occurrences(workflow, "stage2-local-settlement.py residue"), 2);
  assert.doesNotMatch(workflow, /completion_local_full|stage2-local-publication|stage2-local-upload-receipt/u);
  const aggregate = workflow.slice(workflow.indexOf("  aggregate:"));
  assert.match(aggregate, /^ {4}permissions: \{\}$/mu);
  assert.doesNotMatch(aggregate, /checkout|artifact|REPORT_|sudo/u);
  assert.match(
    aggregate,
    /FULL: \$\{\{ needs\.full\.result \}\}[\s\S]*READINESS: \$\{\{ needs\.readiness\.result \}\}/u,
  );
});

test("lock separates current runtime source from the unchanged prior H/G publication", () => {
  const value = JSON.parse(lock);
  assert.equal(value.authority, "diagnostic-only-non-authorizing");
  assert.deepEqual(value.runtime_source, {
    manifest: "exact-materialized-source-manifest",
    must_differ_from_publication_producer: true,
    revision: "github-sha",
  });
  assert.equal(value.publication_producer.implementation_revision, oldImplementation);
  assert.equal(value.publication_producer.control_revision, "3a3499f0f452bf0fe893a0214cf0c0bbd0cd0e99");
  for (const fixed of [
    "33615572679",
    "9840794063",
    "662bdd78f5b3088a37e226c54847cd19d3bb6ac044dc23f800046111d9983c45",
    "f80a3eafb00a184fa0899014c91401d7d5f06d757b29f38562070d0b5dab2a67",
    "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397",
  ])
    assert.match(lock, new RegExp(fixed, "u"));
});

test("hostile lineage/custody fails; formal codecs and every mint route refuse diagnostics", () => {
  const program = `
import copy,importlib.util,json,sys
from pathlib import Path
root=Path.cwd(); remote=root/'deploy/aws-feasibility/remote'; sys.path.insert(0,str(remote)); sys.path.insert(0,str(root/'deploy/aws-feasibility'))
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('diagnostic_lock',root/'scripts/stage2-prebuilt-kvm-diagnostic-lock.py')
value,raws=m.load_lock(); lock=json.loads((root/'config/stage2-prebuilt-kvm-diagnostic-lock-v1.json').read_bytes())
def rejected(call):
 try:call()
 except Exception:pass
 else:raise AssertionError('hostile diagnostic input accepted')
for mutate in (lambda x:x.update(profile='formal'),lambda x:x['runtime_source'].update(revision='fallback'),lambda x:x['publication_producer'].update(implementation_revision='0'*40),lambda x:x['publication'].update(oci_digest='sha256:'+'0'*64),lambda x:x['custody'][0].update(size=1),lambda x:x.update(extra=True)):
 hostile=copy.deepcopy(lock);mutate(hostile);rejected(lambda hostile=hostile:m.load_lock(m.canonical(hostile),raws))
for name in sorted(raws):
 hostile=dict(raws);hostile[name]=raws[name][:-1]+bytes([raws[name][-1]^1]);rejected(lambda hostile=hostile:m.load_lock(custody=hostile))
import completion_cycle_authority as authority,completion_cycle_evidence as evidence
import completion_kata_coordinator as coordinator,completion_kata_diagnostic_control as diagnostic
import completion_kata_preparation as preparation
rejected(lambda:diagnostic._runtime_revision(diagnostic.PRODUCER_IMPLEMENTATION))
assert diagnostic._runtime_revision('a'*40)=='a'*40
raw=diagnostic.preparation.canonical_bytes({'version':diagnostic.VERSION})
rejected(lambda:preparation.load_control(raw));rejected(lambda:authority.decode(raw))
full=evidence._diagnostic_full_route();ready=evidence._diagnostic_readiness_route()
assert evidence._is_diagnostic_route(full) and evidence._is_diagnostic_route(ready)
assert not evidence._is_diagnostic_route(evidence._fixed_full_route())
rejected(lambda:coordinator._run_cycle(full,None,True));rejected(lambda:coordinator._run_cycle(ready,object(),False))
rejected(lambda:evidence._issue_cycle_receipt(full,object()))
print('diagnostic separation checks passed')
`;
  for (const optimization of [[], ["-O"]]) {
    const result = spawnSync("python3", [...optimization, "-B", "-c", program], { encoding: "utf8", timeout: 20_000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "diagnostic separation checks passed\n");
  }
});

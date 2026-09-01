import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

const producer = readFileSync(".github/workflows/stage2-prebuilt-rootfs-diagnostic-producer.yml", "utf8");
const publisher = readFileSync(".github/workflows/stage2-prebuilt-rootfs-diagnostic-publisher.yml", "utf8");
const rehearsal = readFileSync(".github/workflows/stage2-prebuilt-kvm-rehearsal.yml", "utf8");
const coordinator = readFileSync("deploy/aws-feasibility/remote/completion_kata_coordinator.py", "utf8");
const occurrences = (source: string, value: string) => source.split(value).length - 1;

test("diagnostic supply-chain identities cannot consume final first-created authority", () => {
  assert.match(producer, /stage2-prebuilt-rootfs-diagnostic-producer\.yml\/runs/u);
  assert.match(producer, /\.path == "\.github\/workflows\/stage2-prebuilt-rootfs-diagnostic-producer\.yml"/u);
  assert.doesNotMatch(producer, /actions\/workflows\/stage2-prebuilt-rootfs-producer\.yml\/runs/u);
  assert.doesNotMatch(producer, /packages:\s*write|id-token:\s*write|cosign sign|oras push/u);
  assert.match(publisher, /\.path == "\.github\/workflows\/stage2-prebuilt-rootfs-diagnostic-producer\.yml"/u);
  assert.match(publisher, /stage2-prebuilt-rootfs-diagnostic-publisher\.yml\/runs/u);
  assert.doesNotMatch(publisher, /actions\/workflows\/stage2-prebuilt-rootfs-publisher\.yml\/runs/u);
  assert.match(publisher, /test "\$\(git rev-parse HEAD\^\)" = "\$EXACT_H"/u);
  assert.match(publisher, /fetch-depth: 2/u);
  assert.match(publisher, /stage2-prebuilt-rootfs-diagnostic-publisher\.yml@refs\/heads\/main/u);
});

test("diagnostic publisher separately signs, verifies, and reads back immutable bytes", () => {
  assert.match(publisher, /packages: write/u);
  assert.match(publisher, /id-token: write/u);
  assert.match(publisher, /cosign sign --yes --new-bundle-format=true "\$SUBJECT"/u);
  assert.match(publisher, /--user "\$\(id -u\):\$\(id -g\)"/u);
  assert.match(publisher, /-e HOME=\/cosign-home/u);
  assert.match(publisher, /rm -rf -- "\$RUNNER_TEMP\/docker-config" "\$RUNNER_TEMP\/cosign-home"/u);
  assert.match(publisher, /cosign verify --new-bundle-format=true/u);
  assert.match(publisher, /subject="\$REPOSITORY:diagnostic-\$EXACT_H-\$GITHUB_RUN_ID"/u);
  assert.match(
    publisher,
    /for name in accepted\/rootfs\.tar accepted\/rootfs\.manifest\.json accepted\/rootfs\.metadata\.json rootfs\.package\.json rootfs\.provenance\.json/u,
  );
  assert.match(publisher, /stage2-prebuilt-rootfs-diagnostic-control-input-/u);
  assert.match(publisher, /map\(\.id\)\) == \[\$current\]/u);
  assert.doesNotMatch(publisher, /latest|continue-on-error:\s*true/u);
});

test("one first-created rehearsal uses each authentic route once and mints nothing", () => {
  assert.match(rehearsal, /stage2-prebuilt-kvm-rehearsal\.yml\/runs/u);
  assert.match(rehearsal, /map\(\.id\) == \[\$current\]/u);
  assert.match(rehearsal, /\.run_attempt == 1/u);
  assert.match(rehearsal, /stage2-prebuilt-rootfs-diagnostic-publisher\.yml/u);
  assert.equal(occurrences(rehearsal, "run-stage2-completion-full-rehearsal.sh"), 1);
  assert.equal(occurrences(rehearsal, "run-stage2-completion-readiness-rehearsal.sh"), 1);
  assert.equal(occurrences(rehearsal, "stage2-prebuilt-rehearsal-grant.py full"), 1);
  assert.equal(occurrences(rehearsal, "stage2-prebuilt-rehearsal-grant.py readiness"), 1);
  assert.equal(occurrences(rehearsal, "recover-stage2-completion-remote.sh"), 2);
  assert.match(rehearsal, /steps\.preparation\.outcome != 'skipped'/u);
  assert.doesNotMatch(rehearsal, /steps\.preparation\.outcome == 'success'/u);
  assert.match(rehearsal, /stage2-stage-prebuilt-control\.py provisional/u);
  assert.match(rehearsal, /Independently prove final zero lifecycle residue/u);
  assert.doesNotMatch(
    rehearsal,
    /completion_local_full|upload-artifact|stage2-local-publication|stage2-local-upload-receipt|_issue_cycle_receipt|_issue_owner_receipt/u,
  );
  assert.match(coordinator, /def _run_fixed_full_rehearsal\(\):[\s\S]*?claim_full\(\), False\)/u);
  assert.match(coordinator, /def _run_fixed_readiness_rehearsal\(\):[\s\S]*?claim_readiness\(\), False\)/u);
});

test("rehearsal descriptor custody is directional and publication adjuncts follow acquisition", () => {
  const descriptor = rehearsal.indexOf("descriptor-v1/descriptor.json");
  const immutable = rehearsal.indexOf("completion_kata_immutable_preparation.py");
  const adjuncts = rehearsal.indexOf("for name in publication-receipt.json", immutable);
  const control = rehearsal.indexOf("Generate and stage provisional directional G control");
  assert.ok(descriptor > 0 && immutable > descriptor && adjuncts > immutable && control > adjuncts);
  assert.match(rehearsal, /test "\$\(git rev-parse HEAD\^\)" = "\$EXACT_H"/u);
  assert.match(rehearsal, /fetch-depth: 2/u);
  assert.match(rehearsal, /COGS_STAGE2_CONTROL_REVISION="\$GITHUB_SHA"/u);
  assert.match(rehearsal, /rootfs_artifact_count/u);
  assert.doesNotMatch(rehearsal, /aws-actions|opentofu|terraform|\bssm\b/u);
});

test("hostile rehearsal grant values are closed, directional, and route-distinct", () => {
  const program = String.raw`
import hashlib,importlib.util,json,sys
from pathlib import Path
root=Path.cwd(); sys.path.insert(0,str(root/'deploy/aws-feasibility/remote'))
spec=importlib.util.spec_from_file_location('rehearsal_grant',root/'scripts/stage2-prebuilt-rehearsal-grant.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
fixed={'implementation_revision':'1'*40,'control_revision':'2'*40,'static_control_sha256':'3'*64,'rootfs_descriptor_sha256':'4'*64}
full=m.grant_value('full','19',fixed); ready=m.grant_value('readiness','19',fixed)
assert full['ordinal']==1 and ready['ordinal']==2 and full['mode']=='full' and ready['mode']=='readiness'
assert full['batch_commitment']==ready['batch_commitment'] and full['ami_commitment']==ready['ami_commitment']
assert full['plan_sha256']!=ready['plan_sha256']
for value in (full,ready):
 fields={key:item for key,item in value.items() if key not in {'version','grant_commitment'}}
 expected=hashlib.sha256(b'cogs.stage2-cycle-launch-grant/v1\0'+m.canonical(fields)[:-1]).hexdigest()
 assert value['grant_commitment']==expected and m.canonical(value).endswith(b'\n')
for args in [('other','19',fixed),('full','0',fixed),('full','19',{**fixed,'extra':'5'*64}),('full','19',{**fixed,'static_control_sha256':'x'*64})]:
 try:m.grant_value(*args)
 except m.RehearsalGrantError:pass
 else:raise AssertionError(args)
print('closed rehearsal grants passed')
`;
  for (const optimization of [[], ["-O"]]) {
    const result = spawnSync("python3", [...optimization, "-B", "-c", program], {
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /closed rehearsal grants passed/u);
  }
});

/* biome-ignore-all lint/suspicious/noExplicitAny: closed descriptor fixture */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const root = join(import.meta.dirname, "..");
const workflow = readFileSync(join(root, ".github/workflows/stage2-prebuilt-rootfs-publisher.yml"), "utf8");
const script = join(root, "scripts/stage2-prebuilt-rootfs-publisher.py");

test("trusted publisher is directional, numeric-artifact-bound, signed, and byte-read-back", () => {
  assert.match(workflow, /test "\$\(git rev-parse HEAD\^\)" = "\$EXACT_H"/u);
  assert.match(workflow, /fetch-depth: 2/u);
  assert.match(workflow, /\.sha == \$g and \(\.parents \| map\(\.sha\)\) == \[\$h\]/u);
  assert.match(workflow, /Step bounds total 40 minutes with a ten-minute cleanup\/runner reserve/u);
  assert.match(workflow, /^ {4}timeout-minutes: 50$/mu);
  assert.match(workflow, /artifact-ids: \$\{\{ inputs\.producer_artifact_id \}\}/u);
  assert.match(workflow, /\.digest == \$digest and \.workflow_run\.id == \$run/u);
  assert.match(workflow, /packages: write/u);
  assert.match(workflow, /id-token: write/u);
  assert.match(workflow, /cosign sign --yes --new-bundle-format=true "\$SUBJECT"/u);
  assert.match(workflow, /--user "\$\(id -u\):\$\(id -g\)"/u);
  assert.match(workflow, /-e HOME=\/cosign-home/u);
  assert.match(workflow, /install -m 0600 "\$RUNNER_TEMP\/docker-config\/config\.json"/u);
  assert.match(workflow, /rm -rf -- "\$RUNNER_TEMP\/docker-config" "\$RUNNER_TEMP\/cosign-home"/u);
  assert.match(workflow, /cosign verify --new-bundle-format=true/u);
  assert.match(
    workflow,
    /for name in accepted\/rootfs\.tar accepted\/rootfs\.manifest\.json accepted\/rootfs\.metadata\.json rootfs\.package\.json rootfs\.provenance\.json/u,
  );
  assert.match(workflow, /map\(\.id\) == \[\$current\]/u);
  assert.match(
    workflow,
    /select\(\.head_sha == \$g and\s*\.path == "\.github\/workflows\/stage2-prebuilt-rootfs-publisher\.yml"\)/u,
  );
  assert.doesNotMatch(workflow, /\.head_sha == \$g and \.display_title/u);
  assert.doesNotMatch(workflow, /stage2-prebuilt-rootfs-publisher\.yml\/runs\?event=workflow_dispatch&branch=/u);
  assert.match(workflow, /\.path == "\.github\/workflows\/stage2-prebuilt-rootfs-producer\.yml"/u);
  assert.doesNotMatch(workflow, /latest|continue-on-error:\s*true/u);
});

test("publisher refuses authenticated retired provenance despite matching archive hashes, before output", () => {
  const program = String.raw`
import copy,importlib.util,io,json,os,tempfile
from pathlib import Path
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
s=importlib.util.spec_from_file_location('publisher','scripts/stage2-prebuilt-rootfs-publisher.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with tempfile.TemporaryDirectory() as directory:
 m.CANDIDATE=Path(directory); (m.CANDIDATE/'accepted').mkdir()
 blobs={'rootfs.manifest.json':b'manifest','rootfs.metadata.json':b'metadata','rootfs.tar':b'archive'}
 for name,raw in blobs.items(): (m.CANDIDATE/'accepted'/name).write_bytes(raw)
 (m.CANDIDATE/'accepted/.cogs-rootfs-publication-v1').write_bytes(b'cogs-rootfs-publication-v1\n')
 for prefix,name in [('MANIFEST','rootfs.manifest.json'),('METADATA','rootfs.metadata.json'),('USTAR','rootfs.tar')]:
  setattr(m.prebuilt,prefix+'_SIZE',len(blobs[name]));setattr(m.prebuilt,prefix+'_SHA256',m.sha(blobs[name]))
 base=Path('config/stage2-prebuilt-kvm-diagnostic-custody-v1')
 for revision in [*m.retirement['REVISIONS'],'a'*40]:
  provenance=json.loads((base/'rootfs.provenance.json').read_bytes())
  receipt=json.loads((base/'producer-receipt.json').read_bytes())
  package=json.loads((base/'rootfs.package.json').read_bytes())
  members=[dict(name=name,size=len(raw),sha256=m.sha(raw)) for name,raw in blobs.items()]
  provenance['builder'].update(implementation_revision=revision,run_id=123)
  provenance['subject']=members; provenance_raw=m.canonical(provenance)
  package['members']=[*members,dict(name='rootfs.provenance.json',size=len(provenance_raw),sha256=m.sha(provenance_raw))]
  package_raw=m.canonical(package)
  receipt.update(implementation_revision=revision,run_id=123,package_manifest_sha256=m.sha(package_raw),provenance_sha256=m.sha(provenance_raw),
   manifest_sha256=m.prebuilt.MANIFEST_SHA256,manifest_size=m.prebuilt.MANIFEST_SIZE,ustar_sha256=m.prebuilt.USTAR_SHA256,ustar_size=m.prebuilt.USTAR_SIZE)
  for name,raw in [('rootfs.provenance.json',provenance_raw),('rootfs.package.json',package_raw),('producer-receipt.json',m.canonical(receipt))]:
   (m.CANDIDATE/name).write_bytes(raw)
  out=io.BytesIO()
  with patch.dict(os.environ,dict(EXACT_H='a'*40,GITHUB_SHA='b'*40,PRODUCER_RUN_ID='123',PRODUCER_ARTIFACT_ID='124'),clear=True), redirect_stdout(SimpleNamespace(buffer=out)):
   try:m.validate_candidate()
   except ValueError as error:
    assert type(error).__name__=='RetirementError' and revision in m.retirement['REVISIONS']
   else:assert revision=='a'*40
  assert bool(out.getvalue())==(revision=='a'*40)
`;
  const result = spawnSync("python3", ["-I", "-B", "-c", program], { encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr);
});

test("trusted descriptor issuer emits the closed fixed descriptor", () => {
  const digest = "1".repeat(64);
  const result = spawnSync("python3", ["-I", "-B", script, "issue-descriptor"], {
    cwd: root,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      COGS_PREBUILT_H: "2".repeat(40),
      GITHUB_SHA: "8".repeat(40),
      PRODUCER_RUN_ID: "123",
      PRODUCER_ARTIFACT_ID: "124",
      COGS_PREBUILT_SOURCE_MANIFEST_SHA256: digest,
      COGS_PREBUILT_PACKAGE_MANIFEST_SHA256: "3".repeat(64),
      COGS_PREBUILT_PROVENANCE_SHA256: "4".repeat(64),
      COGS_PREBUILT_QUALIFICATION_RECEIPT_SHA256: "5".repeat(64),
      COGS_PREBUILT_PUBLICATION_RECEIPT_SHA256: "6".repeat(64),
      COGS_PREBUILT_OCI_MANIFEST_DIGEST: "7".repeat(64),
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const value = JSON.parse(result.stdout) as Record<string, any>;
  assert.equal(value.authority, "authenticated-static-control-only");
  assert.equal(value.registry.manifest_digest, "7".repeat(64));
  assert.equal(value.registry.layer_digest, "41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397");
  assert.equal(value.producer.publication_receipt_sha256, "6".repeat(64));
});

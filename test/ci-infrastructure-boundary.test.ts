import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import {
  admitProfile,
  admitRestrictions,
  BASELINE,
  deterministicStream,
  FINDINGS,
  launchDocument,
  PROFILE,
  PROXY_CLIENT,
  RestrictionCounters,
  runtimeDocument,
  WORKER_DOCKERFILE,
  WORKER_GATE,
} from "../dev/product-test/runner.ts";
import {
  type ContainerSpec,
  type CustodyPort,
  canonical,
  containerArguments,
  LocalSkillSnapshotOwner,
  SANDBOX_CAPABILITIES,
  SANDBOX_CAPABILITY_MASK,
} from "../dev/product-test/snapshot-owner.ts";

const require = createRequire(import.meta.url);
const parseYaml = (require("yaml") as { parse(source: string): unknown }).parse;
const root = resolve(import.meta.dirname, "..");
const workflowDirectory = resolve(root, ".github/workflows");
const forbiddenRuns = [
  ["legacy validation entry", /validate\.sh/iu],
  ["installer entry", /install-opentofu/iu],
  ["infrastructure tool reference", /\b(?:opentofu|tofu|terraform)\b/iu],
  ["AWS CLI command", /(?:^|[\s;&|()])(?:command\s+)?(?:\.{0,2}\/|\/[\w./-]*\/)?aws(?=$|[\s;&|()])/iu],
  ["infrastructure fixture path", /(?:^|[\s"'`])(?:\.\/)?deploy\/aws-feasibility(?:\/|$|[\s"'`])/iu],
] as const;

type WorkflowStep = { name?: unknown; run?: unknown };
type WorkflowJob = { steps?: unknown };
type Workflow = { jobs?: unknown };

function workflowRuns(path: string): Array<{ job: string; step: string; run: string }> {
  const parsed = parseYaml(readFileSync(path, "utf8")) as Workflow;
  assert.ok(parsed.jobs && typeof parsed.jobs === "object" && !Array.isArray(parsed.jobs), `${path}: parsed jobs`);
  const runs: Array<{ job: string; step: string; run: string }> = [];
  for (const [jobName, value] of Object.entries(parsed.jobs as Record<string, WorkflowJob>)) {
    assert.ok(Array.isArray(value.steps), `${path}: parsed steps for ${jobName}`);
    for (const [index, rawStep] of value.steps.entries()) {
      assert.ok(
        rawStep && typeof rawStep === "object" && !Array.isArray(rawStep),
        `${path}: parsed step ${jobName}/${index}`,
      );
      const step = rawStep as WorkflowStep;
      if (step.run === undefined) continue;
      assert.ok(typeof step.run === "string", `${path}: string run command ${jobName}/${index}`);
      runs.push({ job: jobName, step: typeof step.name === "string" ? step.name : String(index), run: step.run });
    }
  }
  return runs;
}

test("parsed workflow run commands cannot invoke infrastructure validation", () => {
  const dormantProduction = new Set([
    "stage2-production-plan.yml",
    "stage2-production-approval.yml",
    "stage2-production-campaign.yml",
  ]);
  const workflowPaths = readdirSync(workflowDirectory)
    .filter((name) => name.endsWith(".yml") || name.endsWith(".yaml"))
    .sort()
    .map((name) => resolve(workflowDirectory, name));
  assert.ok(workflowPaths.length > 0, "workflow inventory");

  for (const path of workflowPaths) {
    if (dormantProduction.has(path.split("/").at(-1) ?? "")) continue;
    for (const { job, step, run } of workflowRuns(path)) {
      for (const [label, pattern] of forbiddenRuns) {
        assert.doesNotMatch(run, pattern, `${path}: ${job}/${step} must not invoke ${label}`);
      }
    }
  }
});

test("forbidden run-command guards reject direct, wrapped, and path-based invocations", () => {
  for (const command of [
    "./deploy/aws-feasibility/validate.sh",
    "bash deploy/aws-feasibility/plan.sh",
    "./scripts/install-opentofu.sh",
    "./tofu validate",
    "/usr/bin/terraform init",
    "command aws sts get-caller-identity",
  ]) {
    assert.ok(
      forbiddenRuns.some(([, pattern]) => pattern.test(command)),
      `guarded command: ${command}`,
    );
  }
});

test("parsed Quality job selects only the bounded static feasibility source checker", () => {
  const path = resolve(workflowDirectory, "ci.yml");
  const runs = workflowRuns(path);
  const selected = runs.filter(({ run }) => run.includes("feasibility-source:check"));
  assert.deepEqual(
    selected.map(({ job, run }) => ({ job, run })),
    [{ job: "quality", run: "npm run feasibility-source:check" }],
  );

  const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
    scripts?: Record<string, unknown>;
  };
  assert.equal(packageJson.scripts?.["feasibility-source:check"], "tsx scripts/check-feasibility-source.ts");
});

test("bounded feasibility checker performs static parsing only", () => {
  const result = spawnSync(resolve(root, "node_modules/.bin/tsx"), ["scripts/check-feasibility-source.ts"], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, PI_OFFLINE: "1" },
    timeout: 15_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(
    result.stdout,
    /^Statically checked 33 bounded feasibility fixture sources without infrastructure execution\.\n$/u,
  );
});

const productGeneration = "a".repeat(32);
const image = (letter: string) => `sha256:${letter.repeat(64)}`;
const restrictions = () => ({
  version: "cogs.product-restrictions/v1",
  baseline: BASELINE,
  candidate: "a".repeat(40),
  owner: "repository-owner",
  expires: 200000,
  profile: PROFILE,
  breach: "fail-and-settle-exact",
  findings: FINDINGS,
  seconds: 60,
  skills: "empty",
  fresh_protected_runner: true,
  sandbox_image: image("a"),
  worker_image: image("b"),
  stock_worker_image: image("c"),
});
const noEffects: CustodyPort = Object.freeze({
  root: `/var/lib/cogs-product-test/${productGeneration}`,
  generation: productGeneration,
  request: async () => {
    throw new Error("effect before admission");
  },
});

test("product restrictions are canonical, closed, expiring and identity/profile-bound before effects", () => {
  const good = restrictions();
  const admitted = admitRestrictions(Buffer.from(canonical(good)), good.candidate, 1000);
  assert.ok(Object.isFrozen(admitted) && Object.isFrozen(admitted.findings));
  for (const patch of [
    { findings: [4, 5, 6, 8, 9, 10] },
    { findings: [...FINDINGS, 3] },
    { expires: 0 },
    { baseline: "b".repeat(40) },
    { candidate: "b".repeat(40) },
    { profile: "production" },
    { owner: "developer" },
    { breach: "ignore" },
    { extra: true },
    { seconds: 601 },
    { worker_image: "worker:latest" },
    { sandbox_image: good.worker_image },
    { fresh_protected_runner: false },
  ])
    assert.throws(() => admitRestrictions(Buffer.from(canonical({ ...good, ...patch })), good.candidate, 1000));
  assert.throws(() => admitRestrictions(Buffer.from(JSON.stringify(good)), good.candidate, 1000));
  const skills = new LocalSkillSnapshotOwner(noEffects, false);
  const launch = launchDocument(skills.sharedRevision, skills.user.digest);
  admitProfile(runtimeDocument(), launch);
  assert.throws(() => admitProfile(runtimeDocument(), { ...launch, integrations: [] }));
  assert.throws(() =>
    admitProfile(runtimeDocument(), { ...launch, integrations: [...launch.integrations, ...launch.integrations] }),
  );
  assert.throws(() =>
    admitProfile(runtimeDocument(), { ...launch, limits: { ...launch.limits, max_tool_output_bytes: 32768 } }),
  );
});

test("product pre-publication, causal headers, turn, history and disconnect restrictions latch failure", () => {
  const counters = new RestrictionCounters();
  assert.throws(() => counters.admit("turn"));
  counters.headers = true;
  assert.throws(() => counters.admit("event"));
  for (const [kind, maximum] of [
    ["event", 48],
    ["turn", 16],
  ] as const) {
    const c = new RestrictionCounters();
    c.headers = true;
    for (let i = 0; i < maximum; i++) c.admit(kind);
    assert.throws(() => c.admit(kind));
    assert.equal(c.failed, true);
  }
  for (const [entries, nodes] of [
    [26, 1],
    [1, 2049],
    [-1, 1],
  ]) {
    const c = new RestrictionCounters();
    assert.throws(() => c.admit("history", entries, nodes));
  }
  const c = new RestrictionCounters();
  c.admit("history", 25, 2048);
  assert.throws(() => c.disconnect());
  const settled = new RestrictionCounters();
  settled.shutdown = true;
  settled.disconnect();
});

test("product mount and capability plans forbid aliases, mutable tags, host networking and missing capabilities", () => {
  const spec: ContainerSpec = {
    image: image("a"),
    network: "none",
    caps: SANDBOX_CAPABILITIES,
    mask: SANDBOX_CAPABILITY_MASK,
    mounts: [{ source: `${noEffects.root}/publication/a`, target: "/shared/skills/a", ro: true }],
    tmpfs: {},
  };
  const args = containerArguments(noEffects, spec, [], "0:0");
  for (const word of [
    "never",
    "--read-only",
    "none",
    "--memory=4g",
    "--memory-swap=4g",
    "--memory-swappiness=0",
    "--cpus=2",
    "--pids-limit=128",
    "no-new-privileges",
  ])
    assert.ok(args.includes(word));
  assert.ok(args.some((a) => a.includes("bind-propagation=rprivate,readonly")));
  for (const cap of SANDBOX_CAPABILITIES)
    assert.throws(() =>
      containerArguments(noEffects, { ...spec, caps: spec.caps.filter((v) => v !== cap) }, [], "0:0"),
    );
  for (const caps of [[...spec.caps, "SYS_ADMIN"], ["NET_ADMIN"], ["NET_RAW"], ["MKNOD"], ["SETPCAP"]])
    assert.throws(() => containerArguments(noEffects, { ...spec, caps }, [], "0:0"));
  for (const network of ["host", "bridge", "container:foreign"])
    assert.throws(() => containerArguments(noEffects, { ...spec, network }, [], "0:0"));
  for (const source of ["/var/run/docker.sock", "/home/developer", `${noEffects.root}/../foreign`])
    assert.throws(() =>
      containerArguments(noEffects, { ...spec, mounts: [{ source, target: "/alias", ro: true }] }, [], "0:0"),
    );
  for (const source of [spec.mounts[0]?.source, `${noEffects.root}/publication`])
    assert.throws(() =>
      containerArguments(
        noEffects,
        { ...spec, mounts: [...spec.mounts, { source: source ?? "", target: "/alias", ro: false }] },
        [],
        "0:0",
      ),
    );
  assert.throws(() => containerArguments(noEffects, { ...spec, image: "latest" }, [], "0:0"));
});

test("product empty/nonempty paired snapshots resolve and discover the same retained canonical bytes (fake host)", async () => {
  for (const nonempty of [false, true]) {
    const root = await mkdtemp(join(tmpdir(), "cogs-product-contract-"));
    const log: Array<{ op: string; fields: Record<string, unknown> }> = [];
    const host: CustodyPort = {
      root,
      generation: productGeneration,
      request: async <T>(op: string, fields: Record<string, unknown> = {}): Promise<T> => {
        log.push({ op, fields });
        if (op === "storage") await mkdir(join(root, String(fields.name)));
        if (op === "mkdir") await mkdir(join(root, String(fields.path)), { mode: 0o700 }); // fake root writes
        if (op === "file")
          await writeFile(join(root, String(fields.path)), Buffer.from(String(fields.data), "base64"), {
            mode: Number(fields.mode),
            flag: "wx",
          });
        return (
          op === "pair"
            ? { shared: { source_device: "1", source_inode: "11" }, user: { source_device: "1", source_inode: "12" } }
            : undefined
        ) as T;
      },
    };
    try {
      await mkdir(join(root, "state/host-private"), { recursive: true, mode: 0o700 });
      const owner = new LocalSkillSnapshotOwner(host, nonempty);
      const launch = launchDocument(owner.sharedRevision, owner.user.digest);
      await owner.publish(launch);
      assert.equal(owner.shared.fileCount, Number(nonempty));
      assert.equal(owner.user.fileCount, Number(nonempty));
      assert.ok(owner.mounts().every((m) => m.ro && m.source.includes(`/publication/${productGeneration}/`)));
      assert.equal(log.filter((e) => e.op === "pair").length, 1);
      const spec: ContainerSpec = { image: image("a"), network: "none", caps: [], mask: 0, mounts: [], tmpfs: {} };
      const receipt = await owner.lease(
        launch,
        { id: "b".repeat(64), pid: 42, namespace: "mnt:[1]", spec },
        { id: "a".repeat(64), pid: 41, namespace: "mnt:[2]", spec },
      );
      assert.equal(receipt.shared.bundle_digest, owner.shared.digest);
      assert.equal(receipt.user.bundle_digest, owner.user.digest);
      assert.equal(receipt.generation, productGeneration);
      assert.equal(log.at(-1)?.op, "lease");
      assert.ok((await readFile(join(root, "inputs/shared-oci/index.json"))).length > 0);
      await assert.rejects(owner.publish(launch));
    } finally {
      await rm(root, { recursive: true, force: true });
    } // fake fixture disposal, NOT product retirement
  }
});

test("product host descriptor, nonce, acquisition and live lease contracts use portable syscall/Docker fakes", () => {
  const python = String.raw`
import importlib.util,os,tempfile,types
s=importlib.util.spec_from_file_location('custody','dev/product-test/host-custody.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with tempfile.TemporaryDirectory() as root:
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 original=m.os.fchown;m.os.fchown=lambda *args: None
 try:
  m.exclusive(fd,'ordinary',b'abc',0o400)
  assert m.capture(fd,'ordinary')==b'abc'
  try: m.exclusive(fd,'ordinary',b'foreign')
  except FileExistsError: pass
  else: raise AssertionError('replace')
  assert m.capture(fd,'ordinary')==b'abc'
  os.symlink('ordinary',root+'/alias')
  try: m.capture(fd,'alias')
  except OSError: pass
  else: raise AssertionError('symlink')
  os.link(root+'/ordinary',root+'/hardlink')
  try: m.capture(fd,'ordinary')
  except RuntimeError: pass
  else: raise AssertionError('hardlink')
 finally: m.os.fchown=original;os.close(fd)
with tempfile.TemporaryDirectory() as root:
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 os.mkdir(root+'/source');os.mkdir(root+'/competitor')
 class Kernel:
  def __call__(self,a,source,b,destination,flags):
   assert a==b==fd and source==b'source' and destination==b'competitor' and flags==1
   return -1
 original=m.ctypes.CDLL;m.ctypes.CDLL=lambda *args,**kwargs: types.SimpleNamespace(renameat2=Kernel())
 try:
  try: m.no_replace(fd,'source','competitor')
  except RuntimeError: pass
  else: raise AssertionError('no-replace failure ignored')
  assert sorted(os.listdir(root))==['competitor','source']
 finally: m.ctypes.CDLL=original;os.close(fd)
owner=m.Custody.__new__(m.Custody)
owner.generation='a'*32;owner.ids={};owner.control=0
log=[];journal={}
m.exclusive=lambda fd,name,data,*args: journal.setdefault(name,data)
def docker(*args):
 log.append(args)
 if args[0]=='create': return ('b'*64+'\n').encode()
 if args[0]=='start': raise RuntimeError('lost start response')
owner.docker=docker
spec={'image':'sha256:'+'c'*64}
try: owner.dispatch({'op':'create','generation':'d'*32,'role':'worker','spec':spec,'argv':[]})
except RuntimeError: pass
else: raise AssertionError('foreign generation')
assert not log and not journal
try: owner.dispatch({'op':'create','generation':'a'*32,'role':'worker','spec':spec,'argv':[]})
except RuntimeError: pass
else: raise AssertionError('lost start accepted')
assert owner.ids['worker']['id']=='b'*64 and 'worker-receipt' in journal
assert all(row[0] not in ('rm','prune') for row in log)
owner.receipt={'consumer_id':'e'*32};owner.peers={};owner.events=0;owner.turns=0;owner.headers=False;owner.released=False
owner.authenticate=lambda role: None
class Conn:
 def __init__(self): self.sent=[];self.fd=None
 def fileno(self): return self.fd
 def sendall(self,data): self.sent.append(data)
c=Conn();owner.peers[c]={'kind':'gate.sock','nonce':None,'sequence':0,'last':0}
def message(op,sequence):
 q={'version':'cogs.skill-snapshot-control/v1','op':op,'nonce':'f'*32,'sequence':sequence,'receipt_digest':m.digest(m.canonical(owner.receipt)),'consumer_id':'e'*32,'pid':1}
 r,w=os.pipe();os.write(w,m.canonical(q));os.close(w);c.fd=r
 try: owner.message(c)
 finally: os.close(r)
message('acquire',1)
try: message('acquire',1)
except RuntimeError: pass
else: raise AssertionError('replay')
for n in range(2,50): message('event',n)
try: message('event',50)
except RuntimeError: pass
else: raise AssertionError('event overflow')
assert len(c.sent)==49
print('portable custody contracts passed')
`;
  const result = spawnSync("python3", ["-I", "-B", "-c", python], { cwd: root, encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "portable custody contracts passed");
});

test("product worker gate is inert before lease; deterministic model and missing-proxy negative need no network", async () => {
  assert.ok(WORKER_GATE.indexOf("op:'leased'") < WORKER_GATE.indexOf("import('/opt/cogs/dev/product-test/runner.ts')"));
  assert.match(WORKER_GATE, /O_NOFOLLOW/);
  assert.match(WORKER_GATE, /socket\.pause/);
  assert.doesNotMatch(WORKER_DOCKERFILE, /RUN|curl|apt|npm|openbao/i);
  for (const endpoint of [runtimeDocument().otlp.traces_endpoint, runtimeDocument().otlp.metrics_endpoint])
    assert.match(endpoint, /^https:\/\/127\.0\.0\.1:18444\//);
  const missing = spawnSync("python3", ["-I", "-B", "-c", PROXY_CLIENT], {
    env: { PATH: process.env.PATH },
    encoding: "utf8",
    timeout: 3000,
  });
  assert.equal(missing.status, 20);
  assert.equal(missing.stdout, "");
  const model = { provider: "anthropic", id: "claude-sonnet-4-5" } as never;
  const stream = deterministicStream();
  for (let stage = 0; stage < 4; stage++) {
    const result = await (
      await stream(model, { messages: [] }, { apiKey: "synthetic-model-key-not-a-provider-credential" })
    ).result();
    assert.equal(result.stopReason, stage === 0 ? "toolUse" : "stop");
    if (stage === 2) assert.ok(JSON.stringify(result).length > 32768);
  }
  assert.throws(() => stream(model, { messages: [] }, { apiKey: "synthetic-model-key-not-a-provider-credential" }));
  assert.throws(() => deterministicStream()(model, { messages: [] }, { apiKey: "real-provider-key" }));
});

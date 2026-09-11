import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import fs, { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire, syncBuiltinESMExports } from "node:module";
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
  ProductToolResults,
  RestrictionCounters,
  runtimeDocument,
  WORKER_DOCKERFILE,
  WORKER_GATE,
  withProductCustody,
} from "../dev/product-test/runner.ts";
import {
  type ContainerSpec,
  type CustodyPort,
  canonical,
  containerArguments,
  hash,
  LocalSkillSnapshotOwner,
  SANDBOX_CAPABILITIES,
  SANDBOX_CAPABILITY_MASK,
} from "../dev/product-test/snapshot-owner.ts";
import { createCogsPiSession } from "../src/pi/session.ts";
import { createSshBashToolPort } from "../src/ssh/bash-tool.ts";
import type { CogsExecPort, SshConnectionManager } from "../src/ssh/connection.ts";

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

test("ADR0335 closes the complete package execution inventory and whole insecure workflow job", async () => {
  const fixed = `sh -c 'printf "%s\\n" "legacy launcher/insecure execution is disabled by ADR0335" >&2; exit 2' --`;
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const workflow = parseYaml(await readFile(join(workflowDirectory, "insecure-container.yml"), "utf8"));
  const checkPackage = (value: typeof pkg) => {
    assert.equal(value.scripts.launcher, fixed);
    assert.equal(value.exports, undefined);
    assert.equal(value.bin, undefined);
    const { launcher: _, ...other } = value.scripts;
    assert.equal(
      require("node:crypto").createHash("sha256").update(JSON.stringify(other)).digest("hex"),
      "26f0f275aa7a04855c8bd6265b6fe47a051d5c73efa697b152856d7e1547e640",
    );
  };
  const checkWorkflow = (value: unknown) => {
    const jobs = (value as { jobs: Record<string, { if: string; uses?: string; steps: unknown[] }> }).jobs;
    assert.deepEqual(Object.keys(jobs), ["insecure-container"]);
    assert.equal(jobs["insecure-container"]?.if, "${{ false }}");
    assert.equal(jobs["insecure-container"]?.uses, undefined);
    assert(Array.isArray(jobs["insecure-container"]?.steps));
  };
  checkPackage(pkg);
  checkWorkflow(workflow);
  for (const name of ["launcher", "prelauncher", "postlauncher", "insecure", "alias"])
    assert.throws(() => checkPackage({ ...pkg, scripts: { ...pkg.scripts, [name]: "tsx dev/launcher/main.ts" } }));
  for (const key of ["exports", "bin"]) assert.throws(() => checkPackage({ ...pkg, [key]: "./dev/launcher/main.ts" }));
  for (const job of [
    {},
    { if: "env.ALLOW" },
    { steps: [{ if: "${{ false }}" }] },
    { if: "${{ false }}", uses: "./other.yml" },
  ])
    assert.throws(() => checkWorkflow({ jobs: { "insecure-container": job } }));
  assert.throws(() => checkWorkflow({ jobs: { ...(workflow as { jobs: object }).jobs, escape: {} } }));
  // Exact builtin-only command + closed hook/alias inventory: no Node/tsx/application can start.
  for (const profile of ["insecure-container", "linux-kvm", "macos-vm", "invalid", "--help"])
    for (const op of [
      "create",
      "verify",
      "reset",
      "destroy",
      "start",
      "run",
      "smoke",
      "s3-09",
      "; node --eval throw",
    ]) {
      const result = spawnSync("/bin/sh", ["-c", `${pkg.scripts.launcher} "$@"`, "npm", "--profile", profile, op], {
        env: { PATH: "/bin" },
        encoding: "utf8",
        timeout: 2000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, 2);
      assert.equal(result.stdout, "");
      assert.equal(result.stderr, "legacy launcher/insecure execution is disabled by ADR0335\n");
    }
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

test("product empty/nonempty paired snapshots discover journaled publication without external staging (fake host)", async (t) => {
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
        if (op === "pair")
          for (const [scope, entries] of Object.entries(
            fields.pair as Record<string, Record<string, { data: string }>>,
          ))
            for (const [path, entry] of Object.entries(entries)) {
              const target = join(root, "publication", productGeneration, scope, path);
              await mkdir(resolve(target, ".."), { recursive: true, mode: 0o700 });
              await writeFile(target, Buffer.from(entry.data, "base64"), { flag: "wx", mode: 0o444 });
            }
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
      const temp = t.mock.method(fs, "mkdtemp", () => assert.fail("unjournaled staging forbidden"));
      syncBuiltinESMExports();
      try {
        await owner.publish(launch);
      } finally {
        temp.mock.restore();
        syncBuiltinESMExports();
      }
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

test("product actual Bash/Pi adapter projection binds success and rejects failures after effects", async () => {
  const root = await mkdtemp(join(tmpdir(), "cogs-tool-failure-"));
  try {
    for (const code of [0, 91]) {
      const effect = join(root, `effect-${code}`);
      const child = spawnSync(process.execPath, [
        "-e",
        `require('node:fs').writeFileSync(${JSON.stringify(effect)},'effect'); process.exit(${code})`,
      ]);
      const tools = new ProductToolResults(),
        settlements: unknown[] = [],
        observed: unknown[] = [];
      const manager = {
        withBashExec: async (_: unknown, use: (port: CogsExecPort) => Promise<unknown>) =>
          use({
            onStdout: (listener) => listener(Buffer.from("proxy-controls-passed\n")),
            onStderr: () => {},
            signal: async () => {},
            terminal: async () => ({ code: child.status ?? assert.fail("child did not exit"), signal: null }),
          }),
      } as unknown as SshConnectionManager;
      const cwd = join(root, `cwd-${code}`),
        agentDir = join(root, `agent-${code}`);
      await mkdir(cwd);
      await mkdir(agentDir);
      const adapter = await createCogsPiSession({
        cwd,
        agentDir,
        sessionRoot: join(root, `sessions-${code}`),
        sessionId: "product-session",
        userId: "synthetic",
        model: { provider: "anthropic", id: "claude-sonnet-4-5" },
        apiKey: "synthetic-model-key-not-a-provider-credential",
        toolPorts: {
          read: async () => ({}),
          write: async () => ({}),
          edit: async () => ({}),
          ...createSshBashToolPort({ manager }),
        },
        streamFn: deterministicStream(),
        emit: () => true,
        onFatal: () => {},
        turnTimeoutMs: 10000,
        historyAdmission: (entry) => {
          if ((entry as { message?: { role: string } }).message?.role === "toolResult") observed.push(entry);
          tools.admit(entry);
        },
      });
      const host: CustodyPort = {
        ...noEffects,
        request: async <T>(op: string, fields?: Record<string, unknown>) => {
          assert.equal(op, "settle");
          settlements.push(fields);
          return { retired: true, failed: fields?.passed !== true } as T;
        },
      };
      try {
        const run = withProductCustody(host, async () => {
          await adapter.input({ requestId: "tool", correlationId: "tool", kind: "prompt", content: "synthetic" });
          const deadline = Date.now() + 5000;
          while (!tools.failed && (await adapter.state()).runState !== "settled") {
            assert(Date.now() < deadline);
            await new Promise((r) => setTimeout(r, 10));
          }
          tools.evidence();
          return true;
        });
        if (code) {
          await assert.rejects(run);
          assert.throws(() => tools.admit(observed[0]));
        } else await run;
        assert.equal(observed.length, 1);
        const raw = observed[0] as { message: Record<string, unknown> };
        assert.equal(raw.message.isError, false); // Pi marks resolved {ok:false} as non-error.
        assert(Object.hasOwn(raw.message, "usage") && raw.message.usage === undefined);
        const projection = JSON.parse(JSON.stringify(raw));
        const cases = [projection];
        if (!code) {
          const text = projection.message.content[0].text,
            good = JSON.parse(text);
          for (const [key, value] of [
            ["ok", false],
            ["ok", 1],
            ["exitCode", 91],
            ["exitCode", false],
            ["stdout", "x".repeat(4097)],
            ["stderr", {}],
            ["stderrBytes", 1],
            ["error", "failed"],
            ["timedOut", true],
            ["signal", "TERM"],
            ["elapsedMs", -1],
          ]) {
            const bad = structuredClone(projection);
            bad.message.content[0].text = JSON.stringify({ ...good, [key as string]: value });
            cases.push(bad);
          }
          for (const content of [
            [],
            [{ type: "text", text: "success" }],
            [{ type: "text", text: text.replace('"ok":true', '"ok":false,"ok":true') }],
          ]) {
            const bad = structuredClone(projection);
            bad.message.content = content;
            cases.push(bad);
          }
          for (const entry of cases.slice(1)) assert.throws(() => new ProductToolResults().admit(entry));
          assert.deepEqual(tools.evidence(), [hash(canonical(projection.message))]);
          const entries = (await readFile(adapter.sessionFile() as string, "utf8"))
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
          assert.deepEqual(
            entries.find((e) => e.message?.role === "toolResult"),
            projection,
          );
        }
        const independent = spawnSync(
          "python3",
          [
            "-I",
            "-c",
            `
import importlib.util,json,sys
s=importlib.util.spec_from_file_location('custody','dev/product-test/host-custody.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
out=[]
for entry in json.load(sys.stdin):
 try: out.append(m.tool_result(entry))
 except Exception: out.append(None)
print(json.dumps(out))`,
          ],
          { input: JSON.stringify(cases), encoding: "utf8", timeout: 5000 },
        );
        assert.equal(independent.status, 0, independent.stderr);
        assert.deepEqual(
          JSON.parse(independent.stdout),
          cases.map((_, i) => (!code && i === 0 ? hash(canonical(projection.message)) : null)),
        );
        if (code) assert(!(await readFile(adapter.sessionFile() as string, "utf8")).includes('"role":"toolResult"'));
      } finally {
        await adapter.dispose().catch(() => undefined);
      }
      assert.deepEqual(settlements, [{ passed: code === 0 }]);
      assert.equal(await readFile(effect, "utf8"), "effect");
    }
    const missing = new ProductToolResults();
    assert.throws(() => missing.evidence());
    assert.throws(() => missing.admit({ message: { role: "toolResult", isError: false, toolCallId: "foreign" } }));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("product host descriptor, nonce, acquisition and live lease contracts use portable syscall/Docker fakes", () => {
  const python = String.raw`
import importlib.util,os,tempfile,types,time,signal,selectors,json
from unittest.mock import patch
s=importlib.util.spec_from_file_location('custody','dev/product-test/host-custody.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def veto(call,label,errors=RuntimeError):
 try: call()
 except errors: return
 raise AssertionError(label)
m.Custody.probe=False  # __new__ syscall fixtures model the default authorizing run
with tempfile.TemporaryDirectory() as root:
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 original=m.os.fchown;m.os.fchown=lambda *args: None
 try:
  m.exclusive(fd,'ordinary',b'abc',0o400)
  assert m.capture(fd,'ordinary')==b'abc'
  veto(lambda:m.exclusive(fd,'ordinary',b'foreign'),'replace',FileExistsError)
  assert m.capture(fd,'ordinary')==b'abc'
  os.symlink('ordinary',root+'/alias')
  veto(lambda:m.capture(fd,'alias'),'symlink',OSError)
  os.link(root+'/ordinary',root+'/hardlink')
  veto(lambda:m.capture(fd,'ordinary'),'hardlink')
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
  veto(lambda:m.no_replace(fd,'source','competitor'),'no-replace failure ignored')
  assert sorted(os.listdir(root))==['competitor','source']
 finally: m.ctypes.CDLL=original;os.close(fd)
# Kill during each publication acquisition boundary; durable storage custody owns every stage byte.
for boundary in ['intent','mkdir','tree','publish']:
 with tempfile.TemporaryDirectory() as root:
  os.mkdir(root+'/control');os.mkdir(root+'/publication');generation='a'*32
  owner=m.Custody.__new__(m.Custody);owner.root=root;owner.generation=generation;owner.recovery=False;owner.publication=None
  owner.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);owner.control=m.directory(owner.fd,'control');owner.records=set();owner.mounts=['publication']
  def record(n,v):
   with open(root+'/control/'+n,'wb') as f:f.write(m.canonical(v));f.flush();os.fsync(f.fileno())
  owner.record=record;owner.saved=lambda n:json.loads(open(root+'/control/'+n,'rb').read())
  record('intent',{'generation':generation});record('root',list(m.identity(os.fstat(owner.fd))[:2]));record('cgroup',[1,2])
  record('publication-storage',{});record('publication-backing',[3,4])
  r,w=os.pipe();pid=os.fork()
  if pid==0:
   def stop(at):
    if boundary==at:os.write(w,b'1');os.kill(os.getpid(),signal.SIGSTOP)
   real_directory=m.directory
   def directory(fd,n,mode=None):
    if n.startswith('.stage-'):
     assert 'publication-intent' in os.listdir(owner.control);stop('intent')
    child=real_directory(fd,n,mode)
    if n.startswith('.stage-'):stop('mkdir')
    return child
   def tree(fd,entries,verify=False):
    if not verify:
     os.mkdir('b'*64,dir_fd=fd);stop('tree')
   def rename(fd,source,destination):
    os.chmod(source,0o700,dir_fd=fd)  # unprivileged macOS rename double, production owner is root
    os.rename(source,destination,src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd);stop('publish')
   m.directory=directory;m.tree=tree;m.no_replace=rename
   owner.dispatch({'op':'pair','generation':generation,'pair':{'shared':{},'user':{}}});os._exit(99)
  os.close(w)
  assert m.select.select([r],[],[],3)[0] and os.read(r,1)==b'1'
  os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);os.close(r)
  intent=owner.saved('publication-intent');assert intent['generation']==generation and intent['parent']==list(m.identity(os.stat(root+'/publication'))[:2])
  # Actual cleanup-only reopen consumes the storage journal, never adopts an external temp by name.
  owner.recovery=True;owner.cg=root+'/cgroup';owner.disk=None;owner.ids={};owner.peers={};owner.sealed=[];owner.selector=selectors.DefaultSelector();owner.mounts=[]
  live=[{'name':'/dev/loop9'},['exact-mount']];calls=[];owner.storage_observation=lambda n:tuple(live)
  def command(argv):
   calls.append(argv[0]);live[1 if argv[0]=='umount' else 0]=None;return b''
  owner.command=command;real_open=open
  with patch.object(m.os.path,'exists',side_effect=lambda p:p==owner.cg),patch.object(m.os,'stat',return_value=types.SimpleNamespace(st_dev=1,st_ino=2)),patch.object(m,'identity',side_effect=lambda s:(s.st_dev,s.st_ino)),patch('builtins.open',wraps=open) as opened,patch.object(m.os,'rmdir'):
   # cgroup pseudo-file is the sole kernel double; journals and staging are real files.
   opened.side_effect=lambda p,*a,**kw:m.io.StringIO('populated 0') if p==owner.cg+'/cgroup.events' else real_open(p,*a,**kw)
   owner.reopen()
  assert calls==['umount','losetup'] and owner.saved('retired')['failed'] is True
  owner.selector.close();os.close(owner.control);os.close(owner.fd)
owner=m.Custody.__new__(m.Custody)
owner.generation='a'*32;owner.ids={};owner.control=0;owner.recovery=False;owner.deadline=time.monotonic()+60
owner.images={'sha256:'+'c'*64:{'Config':{'Env':[]}}}
owner.inspect=lambda cid:{'Image':'sha256:'+'c'*64,'State':{'Running':False},'Config':{'Env':['NODE_EXTRA_CA_CERTS=/run/cogs/pki/telemetry-ca.crt']}}
owner.verify_candidate=lambda cid:None
log=[];journal={}
m.exclusive=lambda fd,name,data,*args: journal.setdefault(name,data)
owner.record=lambda name,value:journal.setdefault(name,m.canonical(value))
def docker(*args):
 log.append(args)
 if args[0]=='create': return ('b'*64+'\n').encode()
 if args[0]=='start': raise RuntimeError('lost start response')
owner.docker=docker
spec={'image':'sha256:'+'c'*64,'mounts':[],'caps':[],'mask':0}
veto(lambda:owner.dispatch({'op':'create','generation':'d'*32,'role':'worker','spec':spec,'argv':[]}),'foreign generation')
assert not log and not journal
veto(lambda:owner.dispatch({'op':'create','generation':'a'*32,'role':'worker','spec':spec,'argv':[]}),'lost start accepted')
assert owner.ids['worker']['id']=='b'*64 and 'worker-receipt' in journal
assert all(row[0] not in ('rm','prune') for row in log)
owner.receipt={'consumer_id':'e'*32};owner.peers={};owner.events=0;owner.turns=0;owner.headers=False;owner.released=False;owner.shutdown=False;owner.publications=[]
owner.bind_receipt=lambda: None
class Conn:
 def __init__(self): self.sent=[];self.fd=None
 def fileno(self): return self.fd
 def sendall(self,data): self.sent.append(data)
c=Conn();owner.peers[c]={'kind':'gate.sock','nonce':None,'sequence':0,'last':0}
def message(op,sequence):
 q={'version':'cogs.skill-snapshot-control/v1','op':op,'nonce':'f'*32,'sequence':sequence,'receipt_digest':m.digest(m.canonical(owner.receipt)),'consumer_id':'e'*32,'pid':1}
 if op=='event': q['event']={'kind':'status','correlation_id':'test','request_id':None}
 if op=='persist': q['entry']={'message':{'role':'toolResult','isError':True,'toolCallId':'product-proxy','toolName':'bash'}}
 r,w=os.pipe();os.write(w,m.canonical(q));os.close(w);c.fd=r
 try: owner.message(c)
 finally: os.close(r)
message('acquire',1)
veto(lambda:message('acquire',1),'replay')
veto(lambda:message('persist',2),'failed effect admitted for persistence')
for n in range(2,50): message('event',n)
veto(lambda:message('event',50),'event overflow')
assert len(c.sent)==49
# Each image hook/credential/TLS override and duplicate is rejected, including created containers.
for env in [['NODE_OPTIONS=--import=/evil'],['AWS_SECRET_ACCESS_KEY=x'],['NODE_TLS_REJECT_UNAUTHORIZED=0'],['LD_PRELOAD=/evil'],['PATH=x'],['HOME=/root'],['NODE_ENV=production']*2]:
 veto(lambda:m.environment({'Env':env}),env)
assert m.environment({'Env':['HOME=/tmp','NODE_ENV=production']})==['HOME=/tmp','NODE_ENV=production']
for env in [['NODE_OPTIONS=--import=/evil'],['NODE_TLS_REJECT_UNAUTHORIZED=0']]:
 owner.ids={};log.clear();owner.inspect=lambda cid:{'Image':spec['image'],'State':{'Running':False},'Config':{'Env':env}}
 veto(lambda:owner.dispatch({'op':'create','generation':owner.generation,'role':'worker','spec':spec,'argv':[]}),'started inherited code')
 assert not any(row[0]=='start' for row in log)
# Acquisition ownership precedes pidfd; stop handshake never reaps or blocks.
class Stream:
 def close(self): pass
class Process:
 pid=12345;stdout=Stream();stderr=Stream()
 def poll(self): return 0  # exited leader must NOT suppress descendant settlement
 def wait(self,**kw): return 0
for failure in ('pidfd','handshake'):
 owner.cg='/no-such-cgroup';owner.deadline=time.monotonic()+.02;signals=[]
 with patch.object(m.subprocess,'Popen',return_value=Process()),patch.object(m.os,'pidfd_open',create=True,side_effect=OSError() if failure=='pidfd' else lambda pid:77),patch.object(m.os,'waitid',create=True,return_value=None) as waiting,patch.object(m.os,'P_PIDFD',create=True,new=3),patch.object(m.os,'killpg',side_effect=lambda *a:signals.append(a)),patch.object(m.os,'close'),patch.object(m.os.path,'exists',return_value=False):
  veto(lambda:owner.command(['never-executed']),'unbounded handshake',(OSError,RuntimeError))
  assert signals==[(12345,signal.SIGKILL)]
  assert all(call.args[2]&os.WNOHANG and call.args[2]&os.WNOWAIT for call in waiting.call_args_list)
# Lost mount observation is reconciled from durable intent; unmount/detach must precede retired.
with tempfile.TemporaryDirectory() as root:
 owner=m.Custody.__new__(m.Custody);owner.root=root;owner.generation='a'*32;owner.cg=root+'/absent'
 owner.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);os.mkdir(root+'/control');owner.control=os.open(root+'/control',os.O_RDONLY|os.O_DIRECTORY)
 owner.ids={};owner.peers={};owner.sealed=[];owner.selector=selectors.DefaultSelector();owner.disk=None;owner.failed=True;owner.mounts=['state']
 journal={};owner.record=lambda n,v:journal.setdefault(n,v);owner.saved=lambda n:journal[n]
 for n,v in [('state-storage',{}),('state-backing',[1,2]),('state-loop',{'name':'/dev/loop9'}),('state-mount-intent',True)]:
  journal[n]=v;open(root+'/control/'+n,'w').close()
 live=[{'name':'/dev/loop9'},['exact-mount']];calls=[]
 owner.storage_observation=lambda n:tuple(live)
 def command(argv):
  calls.append(argv)
  if argv[0]=='umount': live[1]=None
  if argv[0]=='losetup': live[0]=None
  return b''
 owner.command=command
 owner.settle()
 assert [a[0] for a in calls]==['umount','losetup'] and live==[None,None] and 'retired' in journal
 # A foreign mount/loop observation never permits retirement.
 owner.mounts=['state'];live[:]=[{'name':'/dev/loop8'},['foreign']];journal.pop('retired')
 veto(lambda:owner.settle(),'foreign mount adopted')
 assert 'retired' not in journal
 os.close(owner.control);os.close(owner.fd);owner.selector.close()
# Full authenticate() consumes live proc/mount/cgroup observations, not an authentication stub.
owner=m.Custody.__new__(m.Custody);owner.generation='a'*32;owner.cg='/sys/fs/cgroup/cogs-product-'+owner.generation
spec={'image':'sha256:'+'c'*64,'caps':[],'mask':0,'network':'none','tmpfs':{},'mounts':[{'source':'/source','target':'/skills','ro':True}]}
held={'id':'b'*64,'spec':spec,'environment':[],'sources':{'/skills':(7,8)}};owner.ids={'sandbox':held};owner.images={spec['image']:{'Config':{'Labels':{}}}}
h={'ReadonlyRootfs':True,'Privileged':False,'PidMode':'','LogConfig':{'Type':'none'},'CapDrop':['ALL'],'CapAdd':[], 'SecurityOpt':['no-new-privileges'],'CgroupParent':owner.cg[14:],'Memory':4294967296,'MemorySwap':4294967296,'MemorySwappiness':0,'PidsLimit':128,'NanoCpus':2000000000,'PortBindings':{},'ShmSize':16777216,'NetworkMode':'none','Devices':[],'Binds':[],'Tmpfs':{}}
v={'State':{'Pid':42,'Running':True},'Image':spec['image'],'Config':{'Labels':{'cogs.product.generation':owner.generation},'Env':[]},'HostConfig':h,'Mounts':[{'Destination':'/skills','Type':'bind','Source':'/source','RW':False,'Propagation':'rprivate'}]};owner.inspect=lambda cid:v
proc={'/proc/42/mountinfo':'17 16 7:0 / /skills ro - ext4 /dev/loop9 ro\n','/proc/42/cgroup':'0::'+owner.cg[14:]+'/'+held['id']+'\n','/proc/42/status':'CapEff: 0\nCapPrm: 0\nCapBnd: 0\nNoNewPrivs: 1\nSeccomp: 2\n'}
for k,value in m.LIMITS.items():proc[owner.cg+'/'+held['id']+'/'+k]=value
with patch('builtins.open',side_effect=lambda p,**kw:m.io.StringIO(proc[p])),patch.object(m.os,'stat',return_value=types.SimpleNamespace(st_dev=7,st_ino=8)),patch.object(m.os,'readlink',return_value='mnt:[2]'),patch.object(m.os,'pidfd_open',create=True,return_value=77),patch.object(m.select,'select',return_value=([],[],[])):
 for swappiness in (None,0):
  h['MemorySwappiness']=swappiness;owner.authenticate('sandbox')
 for swappiness,swap in [(1,'0'),(-1,'0'),('0','0'),(False,'0'),(0.0,'0'),(None,'max'),(0,'1')]:
  h['MemorySwappiness']=swappiness;proc[owner.cg+'/'+held['id']+'/memory.swap.max']=swap
  veto(lambda:owner.authenticate('sandbox'),('swap admission',swappiness,swap))
 h['MemorySwappiness']=0;proc[owner.cg+'/'+held['id']+'/memory.swap.max']='0'
 held['sources']['/skills']=(7,9)
 veto(lambda:owner.authenticate('sandbox'),'live source was not bound to acquisition')
 held['sources']['/skills']=(7,8);v['Config']['Env']=['NODE_OPTIONS=--import=/evil']
 veto(lambda:owner.authenticate('sandbox'),'live environment changed')
# Live receipt identity uses retained publication, not a newly substituted source inode.
with tempfile.TemporaryDirectory() as root:
 owner=m.Custody.__new__(m.Custody);owner.root=root;owner.generation='a'*32;owner.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 os.mkdir(root+'/documents');launch={'session_id':'product-session'};open(root+'/documents/launch.json','wb').write(m.canonical(launch))
 bundle=m.digest(b'{}');pair={};sources={};mounts=[]
 for scope in ('shared','user'):
  path=f'{root}/publication/{owner.generation}/{scope}/{bundle[7:]}';os.makedirs(path)
  s=os.stat(path);sources[scope]={'source_device':str(s.st_dev),'source_inode':str(s.st_ino)}
  pair[scope]={bundle[7:]+'/.cogs-skills-bundle.json':{'data':'e30=','mode':292}}
  mounts.append({'source':path,'target':f'/{scope}/skills/{bundle[7:]}','ro':True})
 owner.publication={'pair':pair,'sources':sources};owner.saved=lambda n:owner.publication
 owner.authenticate=lambda role:{'id':('b' if role=='worker' else 'c')*64,'namespace':'mnt:[2]','spec':{'mounts':mounts}}
 owner.receipt={'version':'cogs.skill-snapshot-receipt/v1','generation':owner.generation,'consumer_id':'d'*32,'session_id':'product-session','launch_digest':m.digest(m.canonical(launch)),'worker_id':'b'*64,'sandbox_id':'c'*64,'sandbox_mount_namespace':'mnt:[2]'}
 for scope in ('shared','user'): owner.receipt[scope]={**sources[scope],'destination':f'/{scope}/skills/{bundle[7:]}','read_only':True,'bundle_digest':bundle}
 with patch.object(m,'tree'),patch.object(m,'capture',side_effect=lambda fd,n,*a:b'{}' if n=='.cogs-skills-bundle.json' else m.canonical(launch)):
  owner.bind_receipt()
  for scope in ('shared','user'):
   for key in owner.receipt[scope]:
    before=owner.receipt[scope][key];owner.receipt[scope][key]='wrong'
    veto(lambda:owner.bind_receipt(),key)
    owner.receipt[scope][key]=before
  os.rename(mounts[0]['source'],mounts[0]['source']+'.old');os.mkdir(mounts[0]['source'])
  veto(lambda:owner.bind_receipt(),'replaced publication')
 os.close(owner.fd)
veto(lambda:m.source_nodes({'nested':{'__proto__':1}}),'persisted proto')
# Full retained-evidence admission: real runner Git commands/workspace inventory, other artifacts doubled.
fixture=tempfile.TemporaryDirectory();owner=m.Custody.__new__(m.Custody);owner.root=fixture.name;owner.generation='a'*32
for name in ['control','publication','workspace','state','inputs','authority','sandbox-input','documents','lease']:os.mkdir(owner.root+'/'+name)
workspace=owner.root+'/workspace';owner.fd=os.open(owner.root,os.O_RDONLY|os.O_DIRECTORY);owner.command=lambda a:m.subprocess.check_output(a,env=m.ENV,timeout=2);open(workspace+'/proof.txt','wb').write(b'alpha\n')
for args in [('init','-q','--template=','--initial-branch=master'),('config','user.email','synthetic@example.invalid'),('config','user.name','Synthetic'),('add','proof.txt'),('commit','-q','-m','synthetic-baseline')]:owner.command(['git','-C',workspace,*args])
for key in ('core.ignorecase','core.precomposeunicode'):assert m.subprocess.run(['git','-C',workspace,'config','--unset',key],env=m.ENV,timeout=2).returncode in (0,5)  # macOS-only init settings, absent on Linux
owner.shutdown=owner.released=owner.headers=True;owner.peers={};owner.turns=3;owner.events=4;owner.publication={'pair':{}}
owner.publications=[{'kind':k} for k in ['run_settled']*3+['shutdown_ready']]
bundle=m.digest(b'{}');owner.receipt={'consumer_id':'d'*32,'user':{'bundle_digest':bundle}}
owner.launch={'skills':{'shared_revision':bundle,'user_revision':bundle}};provenance={'candidate':'e'*40}
result=dict(ok=True,exitCode=0,signal=None,elapsedMs=1,stdout='proxy-controls-passed\n',stderr='',stdoutBytes=22,stderrBytes=0)
result.update(dict.fromkeys('timedOut idleTimedOut cancelled stdoutTruncated stderrTruncated stdoutLossyUtf8 stderrLossyUtf8'.split(),False))
result.update(dict.fromkeys('stdoutDroppedBytes stderrDroppedBytes stdoutResultOmittedUtf8Bytes stderrResultOmittedUtf8Bytes updateDropped'.split(),0))
tool={'role':'toolResult','toolCallId':'product-proxy','toolName':'bash','isError':False,'details':{'cogsTool':'bash'},'content':[{'type':'text','text':json.dumps(result)}]}
entries=[{'id':'entry1','type':'message','message':tool}];native='product-session/native.jsonl';native_bytes=b''.join(m.canonical(v) for v in entries)
commit=owner.command(['git','-C',workspace,'rev-parse','HEAD']).decode().strip();mapping={'version':'cogs.git-mapping/v1alpha1','repo':'product-workspace','commit':commit,'session':'product-session','entry':'entry1','turn':'turn1','observed_at':'2026-01-01T00:00:00.000Z','confidence':'exact'}
files={native:native_bytes,'product-session/git-map.jsonl':m.canonical(mapping)}
r={'version':'cogs.egress-intent/v1alpha1','sequence':0,'intent_id':'intent1','timestamp_ms':10,'session_id':'product-session','integration_id':'synthetic-local','route_id':'route1','method':'GET','credential_required':True}
c={'intentId':'intent1','sequence':0,'routeId':'route1','responseCode':200,'durationMs':1,'completedAtMs':11}
def export(kind,items):
 scope={'scope':{'name':'cogs.worker.telemetry','version':'v1alpha1'},'spans' if kind=='Spans' else 'metrics':items}
 return {'path':'/v1/traces' if kind=='Spans' else '/v1/metrics','body':{'resource'+kind:[{'resource':{'attributes':[{'key':'service.name','value':{'stringValue':'cogs-worker'}}]},'scope'+kind:[scope]}]}}
exports=[export('Spans',[{'name':'lifecycle.start','traceId':'a'*32,'spanId':'b'*16,'kind':1,'startTimeUnixNano':'0','endTimeUnixNano':'1','attributes':[]}]),export('Metrics',[{'name':'lifecycle.starts','sum':{'dataPoints':[{'asInt':'1'}]}}])]
attrs={'cogs.'+k:r[k] for k in ['intent_id','session_id','integration_id','route_id','method','credential_required']}
attrs.update({'cogs.event':'egress.complete','cogs.intent_sequence':'0','cogs.status_class':'2','cogs.duration_ms':'1','cogs.completed_lag_ms':'1'})
exports.append({'path':'/v1/logs','body':{'resourceLogs':[{'resource':{'attributes':[{'key':'service.name','value':{'stringValue':'cogs-egress'}}]},'scopeLogs':[{'scope':{'name':'cogs.egress.telemetry','version':'v1alpha1'},'logRecords':[{'body':{'stringValue':'cogs.egress.complete'},'severityText':'INFO','timeUnixNano':'11000000','attributes':[{'key':k,'value':{'boolValue' if isinstance(v,bool) else 'intValue' if k in ['cogs.intent_sequence','cogs.status_class','cogs.duration_ms','cogs.completed_lag_ms'] else 'stringValue':v}} for k,v in attrs.items()]}]}]}]}})
e={'outcome':'pass','generation':owner.generation,'consumer':'d'*32,'events':4,'turns':3,'omitted':True,'observedEvents':owner.publications,'provenance':provenance,'audit':1,'upstream':1,'upstreamRequests':[{'method':'GET','path':'/credential','credential':True}],'egress':{'records':[r],'completions':[c],'retired':True,'uncorrelated':0,'accounting':{'accepted':1,'drained':1,'retained':0,'dropped':0,'failed':False}},'exports':exports,'traces':1,'metrics':1,'telemetry':{'ready':False,'exported':2,'queued':0,'failed':0,'dropped':0,'lag_ms':0}}
retained={'session/egress-audit.wal':m.canonical(r),**{'session/sessions/'+p:b for p,b in files.items()}}
for scope in ['host-private','private-store']: retained[scope+'/'+m.hashlib.sha256(b'synthetic').hexdigest()+'/blobs/sha256/'+bundle[7:]]=b'{}'
export_root='session/sessions/product-session/exports/cogs-session-product-session/'
for name,value in {'session.jsonl':native_bytes,'git-map.json':m.canonical({'records':[mapping]}),'skills.json':m.canonical(owner.launch['skills']),'warnings.json':m.canonical({'warnings':[]}),'transform-report.json':m.canonical({'transform':'identity','transformations':0,'sanitized':False})}.items():retained[export_root+name]=value
manifest={'version':'cogs.export/v1alpha2','session_id':'product-session','skills':owner.launch['skills'],'files':[{'path':p.removeprefix(export_root),'bytes':len(b),'sha256':m.digest(b)[7:]} for p,b in retained.items() if p.startswith(export_root)]}
retained[export_root+'manifest.json']=m.canonical(manifest)
e['exported']={'sensitive':True,'bundle':{'mode':'raw','file_count':6,'bundle':'cogs-session-product-session','manifest_sha256':m.digest(m.canonical(manifest))[7:],'total_bytes':sum(len(b) for p,b in retained.items() if p.startswith(export_root))}}
e['toolResults']=[m.tool_result(entries[0])]
retained['session/product-evidence.json']=m.canonical(e)
for p in list(retained):
 for i,ch in enumerate(p):
  if ch=='/': retained[p[:i+1]]=None
retained['session/agent/']=None
state_inode=os.stat(owner.root+'/state').st_ino;real_inventory=m.inventory;override={}
owner.retained_history=lambda:(files,native,entries);owner.history={};owner.saved=lambda n:provenance;owner.record=lambda *a:None
note=f"cogs git mapping: trusted record of untrusted Git observation; session=product-session; entry=entry1; turn=turn1; commit={commit}; observed_at={mapping['observed_at']}; confidence=exact\n".encode()
owner.command(['git','-C',workspace,'notes','--ref=refs/notes/cogs','append','-m',note.decode().strip(),commit])
with m.closing_fd(m.directory(owner.fd,'workspace')) as fd:assert m.inventory(fd)['.git/refs/tags/'] is None
with patch.object(m,'inventory',side_effect=lambda fd,*a,**kw:dict(retained) if os.fstat(fd).st_ino==state_inode else real_inventory(fd,*a,**kw) | (override if not a else {})),patch.object(m,'tree'):
 owner.evidence()
 for path,kind in [('.git/refs/tags/v1','file'),('.git/refs/tags/nested','dir'),('.git/refs/tags/nested/child','nested'),('.git/refs/tags','file'),('.git/refs/tags','symlink'),('.git/refs/unexpected','dir'),('.git/refs/heads/unexpected','file'),('.git/refs/notes/unexpected','file')]:
  target=workspace+'/'+path;tags=path=='.git/refs/tags';os.rmdir(target) if tags else None;os.makedirs(os.path.dirname(target),exist_ok=True)
  os.mkdir(target) if kind=='dir' else os.symlink('heads',target) if kind=='symlink' else open(target,'wb').write((commit+'\n').encode())
  veto(lambda:owner.evidence(),'unexpected Git inventory '+path,(OSError,RuntimeError))
  os.rmdir(target) if kind=='dir' else os.unlink(target);os.mkdir(target) if tags else os.rmdir(workspace+'/.git/refs/tags/nested') if kind=='nested' else None
 for value in (b'',b'not-a-directory'):
  override['.git/refs/tags/']=value;veto(lambda:owner.evidence(),'wrong tags inventory value');override.clear()
 for key,value in [('events',3),('upstream',2),('provenance',{}),('observedEvents',[]),('toolResults',[]),('toolResults',['sha256:'+'0'*64])]:
  bad={**e,key:value};retained['session/product-evidence.json']=m.canonical(bad)
  veto(lambda:owner.evidence(),'false pass '+key)
 retained['session/product-evidence.json']=m.canonical(e)
 for value in [True,None,0,'false']:
  tool['isError']=value
  veto(lambda:owner.evidence(),'failed tool after retained effects passed')
 tool['isError']=False
 for path in ['session/extra','session/egress-audit.wal',export_root+'session.jsonl']:
  previous=retained.get(path);retained[path]=b'corrupt\n'
  veto(lambda:owner.evidence(),'corrupt retained '+path,(RuntimeError,ValueError))
  if previous is None: del retained[path]
  else: retained[path]=previous
os.close(owner.fd);fixture.cleanup()
# Candidate source verification reads stopped-container tar bytes, checks ownership/modes and exact inventory.
owner=m.Custody.__new__(m.Custody);owner.source={};archives={}
for path in ['src','schemas','dev/product-test','dev/launcher/api-client.ts','third_party']:
 name=path if path.endswith('.ts') else path+'/fixture.ts';owner.source[name]={'digest':m.digest(b'candidate'),'mode':0o644}
 stream=m.io.BytesIO()
 with m.tarfile.open(fileobj=stream,mode='w') as archive:
  entry=m.tarfile.TarInfo(name if '/' not in path else name[len(path.rsplit('/',1)[0])+1:]);entry.size=9;entry.mode=0o644;archive.addfile(entry,m.io.BytesIO(b'candidate'))
 archives[path]=stream.getvalue()
owner.docker=lambda op,source,dest:archives[source.split(':/opt/cogs/')[1]]
owner.verify_candidate('b'*64)
for key in ['digest','mode']:
 prior=owner.source['src/fixture.ts'][key];owner.source['src/fixture.ts'][key]='foreign'
 veto(lambda:owner.verify_candidate('b'*64),'candidate '+key)
 owner.source['src/fixture.ts'][key]=prior
# Constructor failures enter rollback even after allocation; recovery is cleanup-only.
with tempfile.TemporaryDirectory() as root:
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);made=[];settled=[];locks=set()
 def opened(path,*a,**kw):
  new=os.dup(fd)
  if path.endswith('.lock'): locks.add(new)
  return new
 def stats(fd): return types.SimpleNamespace(st_uid=0,st_mode=0o100600 if fd in locks else 0o40700,st_nlink=1,st_dev=1,st_ino=2)
 def alloc(parent,name,mode=None):
  if len(made)>=2: assert mode is None
  made.append(name);return os.dup(fd)
 def fail(*a): raise RuntimeError('unsupported driver')
 with patch.object(m.sys,'platform','linux'),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'uname',return_value=types.SimpleNamespace(machine='x86_64')),patch.object(m.os,'open',side_effect=opened),patch.object(m.os,'fstat',side_effect=stats),patch.object(m.os,'write',side_effect=lambda fd,b:len(b)),patch.object(m.os,'pread',return_value=m.canonical({'generation':'a'*32,'seconds':60})),patch.object(m,'identity',return_value=(1,2)),patch.object(m,'directory',side_effect=alloc),patch.object(m.os,'mkdir'),patch.object(m.os,'stat',return_value=types.SimpleNamespace()),patch.object(m.Custody,'cwrite'),patch.object(m.Custody,'record',side_effect=lambda *a:None),patch.object(m.Custody,'docker',side_effect=fail),patch.object(m.Custody,'settle',side_effect=lambda:settled.append(True)):
  veto(lambda:m.Custody({'generation':'a'*32,'seconds':60}),'constructor passed')
  records={'intent':{'generation':'a'*32},'root':[1,2],'cgroup':[1,2]}
  with patch.object(m.Custody,'saved',side_effect=lambda n:records[n]),patch.object(m.os.path,'exists',return_value=True):
   recovered=m.Custody({'generation':'a'*32,'seconds':60,'cleanup_only':True})
   assert recovered.recovery and recovered.failed
 assert made==['a'*32,'control']*2 and settled==[True,True]
 os.close(fd)
owner=m.Custody.__new__(m.Custody);owner.recovery=True
veto(lambda:owner.dispatch({'generation':'a'*32,'op':'storage','name':'state'}),'recovery acquired storage')
# Stable descriptor inventories reject unknown sockets/symlinks/hardlinks, not merely nonempty history.
with tempfile.TemporaryDirectory() as root:
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);sock=m.socket.socket(m.socket.AF_UNIX);sock.bind(root+'/unexpected.sock')
 veto(lambda:m.inventory(fd),'socket retained',(OSError,RuntimeError))
 sock.close();os.unlink(root+'/unexpected.sock');os.mkdir(root+'/extra')
 assert m.inventory(fd)=={'extra/':None}
 os.close(fd)
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

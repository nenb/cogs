import assert from "node:assert/strict";
import childProcess, { spawnSync } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ENVOY_IMAGE } from "../dev/launcher/envoy-egress.ts";
import { OPENBAO_IMAGE } from "../dev/openbao-model-auth/image.ts";
import { WORKER_DOCKERFILE } from "../dev/product-test/runner.ts";
import {
  LAUNCHER_DOCKER,
  LAUNCHER_IMAGE_ENV,
  LAUNCHER_REQUIRED_IMAGES,
  prepareLauncherImages,
  verifyImageInspect,
} from "../scripts/prepare-launcher-images.ts";
import {
  cleanupSensitiveExport,
  expectedReportPath,
  isTmpfsType,
  launcherCommandDescriptor,
  reportFor,
  s3FailureStageFromLauncherExitCode,
  validateReportPath,
  validateS309Json,
  validateSmokeJson,
} from "../scripts/run-launcher-smoke-evidence.ts";

const sourceRevision = "a".repeat(40);

test("launcher smoke evidence renderer is applicability-aware and non-release", () => {
  const insecure = reportFor({
    profile: "insecure-container",
    sourceRevision,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    outcome: "pass",
    diagnostics: "metadata-only launcher smoke passed",
  });
  assert.equal(insecure.authority, "functional-only");
  assert.equal(insecure.environment.metadata.external_tmpfs_roots, true);
  assert.equal(insecure.tests[0]?.release_eligible, false);
  assert.equal(insecure.tests[0]?.dependency_modes.network_enforcement, "not-applicable");
  assert(!JSON.stringify(insecure).includes("launcher-smoke.json"));

  const kvm = reportFor({
    profile: "linux-kvm",
    sourceRevision,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    outcome: "pass",
    diagnostics: "metadata-only launcher smoke passed",
  });
  assert.equal(kvm.authority, "authoritative-local");
  assert.equal((kvm.environment.metadata as Record<string, unknown>).guest_root, true);
  assert.equal((kvm.environment.metadata as Record<string, unknown>).distinct_boot_ids, true);
  assert(kvm.known_limitations.some((item) => item.includes("same workflow's validated qualification")));
  assert.equal(kvm.tests[0]?.release_eligible, false);
  assert.equal(kvm.tests[0]?.dependency_modes.network_enforcement, "real");
});

test("s3-09 launcher evidence report and command are fixed and metadata-only", () => {
  const descriptor = launcherCommandDescriptor("linux-kvm", "s309", 600000, "s3-09");
  assert.deepEqual(descriptor.args.slice(-3), ["s3-09", "--timeout-ms", "600000"]);
  const report = reportFor({
    profile: "linux-kvm",
    scenario: "s3-09",
    sourceRevision,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    outcome: "pass",
    diagnostics: "metadata-only s3-09 passed",
  });
  assert.equal(report.authority, "authoritative-local");
  assert.equal(report.tests[0]?.id, "launcher.s3-09.integrated");
  assert.equal(report.tests[0]?.release_eligible, false);
  assert(report.known_limitations.some((item) => item.includes("blocked/not-run")));
  const serialized = JSON.stringify(report);
  for (const forbidden of ["session.jsonl", "credential", "/workspace", "sk-ant", "prompt"]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.equal(
    expectedReportPath("linux-kvm", "s3-09"),
    join(process.cwd(), "docs/security-evidence/generated/launcher-s3-09-linux-kvm.json"),
  );
  assert.equal(
    validateReportPath("linux-kvm", "docs/security-evidence/generated/launcher-s3-09-linux-kvm.json", "s3-09"),
    join(process.cwd(), "docs/security-evidence/generated/launcher-s3-09-linux-kvm.json"),
  );
  assert.throws(() =>
    validateReportPath("linux-kvm", "docs/security-evidence/generated/launcher-linux-kvm.json", "s3-09"),
  );
});

test("s3-09 evidence maps only exact bounded launcher exit codes to metadata stages", () => {
  assert.equal(s3FailureStageFromLauncherExitCode(40), "s3-create");
  assert.equal(s3FailureStageFromLauncherExitCode(46), "s3-terminal-kind");
  assert.equal(s3FailureStageFromLauncherExitCode(47), "s3-git-mapping");
  assert.equal(s3FailureStageFromLauncherExitCode(48), "s3-live-count");
  assert.equal(s3FailureStageFromLauncherExitCode(49), "s3-proof-run");
  assert.equal(s3FailureStageFromLauncherExitCode(50), "s3-proof-terminal");
  assert.equal(s3FailureStageFromLauncherExitCode(51), "s3-egress-shape");
  assert.equal(s3FailureStageFromLauncherExitCode(52), "s3-egress-state");
  assert.equal(s3FailureStageFromLauncherExitCode(53), "s3-egress-credential");
  assert.equal(s3FailureStageFromLauncherExitCode(54), "s3-egress-denied");
  assert.equal(s3FailureStageFromLauncherExitCode(55), "s3-egress-total");
  assert.equal(s3FailureStageFromLauncherExitCode(58), "s3-export");
  assert.equal(s3FailureStageFromLauncherExitCode(62), "s3-cleanup");
  assert.equal(s3FailureStageFromLauncherExitCode(63), "s3-trusted-relay-zero-wal-zero");
  assert.equal(s3FailureStageFromLauncherExitCode(64), "s3-trusted-relay-zero-wal-pass");
  assert.equal(s3FailureStageFromLauncherExitCode(65), "s3-trusted-relay-one-wal-zero");
  assert.equal(s3FailureStageFromLauncherExitCode(66), "s3-trusted-relay-one-wal-pass");
  for (const forged of [1, 39, 67, "40", { valueOf: () => 40 }, new Proxy({}, { get: () => 40 })]) {
    assert.equal(s3FailureStageFromLauncherExitCode(forged), undefined);
  }
  const report = reportFor({
    profile: "linux-kvm",
    scenario: "s3-09",
    sourceRevision,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    outcome: "fail",
    diagnostics: "launcher smoke failed at s3-trusted-relay-one-wal-pass",
  });
  assert.equal(report.tests[0]?.diagnostics_redacted, "launcher smoke failed at s3-trusted-relay-one-wal-pass");
});

test("launcher command descriptor uses exact node and minimal env with deadline", () => {
  const descriptor = launcherCommandDescriptor("insecure-container", "state", 600000);
  assert.equal(descriptor.executable, process.execPath);
  assert.deepEqual(descriptor.env, { HOME: process.cwd(), NO_COLOR: "1" });
  assert.equal(descriptor.cwd, process.cwd());
  assert.equal(descriptor.timeoutMs, 720000);
  assert.equal(descriptor.killGraceMs, 120000);
  assert.equal(descriptor.args.at(-1), "600000");
  assert.deepEqual(descriptor.args.slice(1), [
    join(process.cwd(), "dev", "launcher", "main.ts"),
    "--profile",
    "insecure-container",
    "--state",
    "state",
    "smoke",
    "--timeout-ms",
    "600000",
  ]);
  assert.equal(descriptor.args[0], join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs"));
});

test("launcher smoke metadata validator requires exact cleanup and abort terminal without getters", () => {
  const valid = {
    op: "smoke",
    complete: true,
    aborted: { terminal: "run_aborted", lastEventId: 9, eventCount: 3 },
    inventory: {
      profile: "linux-kvm",
      authority: "authoritative-local",
      phase: "sandbox-ready",
      descriptor: "none",
      workerLive: false,
      recovery: "absent",
      acquisitionUncertainty: "absent",
      retirement: "absent",
      cleanupRequired: false,
      driverState: "absent",
    },
  };
  validateSmokeJson(valid, "linux-kvm");
  for (const key of ["acquisitionUncertainty", "retirement"]) {
    for (const value of ["present", "unknown", undefined])
      assert.throws(() =>
        validateSmokeJson({ ...valid, inventory: { ...valid.inventory, [key]: value } }, "linux-kvm"),
      );
  }

  let invoked = false;
  assert.throws(() =>
    validateSmokeJson(
      Object.freeze(
        Object.defineProperty({}, "op", {
          enumerable: true,
          get() {
            invoked = true;
            return "smoke";
          },
        }),
      ),
      "insecure-container",
    ),
  );
  assert.equal(invoked, false);

  for (const aborted of [
    { terminal: "run_aborted" },
    { terminal: "run_settled", lastEventId: 9, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 0, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 9, eventCount: 0 },
    { terminal: "run_aborted", lastEventId: 1001, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 2, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 9.5, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 9, eventCount: 3, extra: true },
    Object.assign(Object.create(null), { terminal: "run_aborted", lastEventId: 9, eventCount: 3 }),
  ]) {
    assert.throws(() => validateSmokeJson({ ...valid, aborted }, "linux-kvm"));
  }

  const symbolAborted = { terminal: "run_aborted", lastEventId: 9, eventCount: 3, [Symbol("x")]: true };
  assert.throws(() => validateSmokeJson({ ...valid, aborted: symbolAborted }, "linux-kvm"));

  let abortedGetterInvoked = false;
  const getterAborted = Object.defineProperty({ terminal: "run_aborted", eventCount: 3 }, "lastEventId", {
    enumerable: true,
    get() {
      abortedGetterInvoked = true;
      return 9;
    },
  });
  assert.throws(() => validateSmokeJson({ ...valid, aborted: getterAborted }, "linux-kvm"));
  assert.equal(abortedGetterInvoked, false);
});

test("s3-09 metadata validator requires raw export opening proof", () => {
  const valid = {
    op: "s3-09",
    complete: true,
    terminal: "run_settled",
    lastEventId: 40,
    liveEventCount: 33,
    egressProof: true,
    history: { pages: 2, entries: 4 },
    rawExport: { descriptorValidated: true, mode: "raw", sensitive: true, rawExportOpened: true },
    inventory: {
      profile: "linux-kvm",
      authority: "authoritative-local",
      phase: "sandbox-ready",
      descriptor: "none",
      workerLive: false,
      recovery: "absent",
      acquisitionUncertainty: "absent",
      retirement: "absent",
      cleanupRequired: false,
      driverState: "absent",
    },
  };
  validateS309Json(valid);
  for (const key of ["acquisitionUncertainty", "retirement"]) {
    for (const value of ["present", "unknown", undefined])
      assert.throws(() => validateS309Json({ ...valid, inventory: { ...valid.inventory, [key]: value } }));
  }
  assert.throws(() => validateS309Json({ ...valid, liveEventCount: 32 }));
  assert.throws(() =>
    validateS309Json({ ...valid, rawExport: { descriptorValidated: true, mode: "raw", sensitive: true } }),
  );
  let invoked = false;
  assert.throws(() =>
    validateS309Json(
      Object.freeze(
        Object.defineProperty({}, "op", {
          enumerable: true,
          get() {
            invoked = true;
            return "s3-09";
          },
        }),
      ),
    ),
  );
  assert.equal(invoked, false);
});

test("launcher evidence helpers reject non-tmpfs and constrain report filename", () => {
  assert.equal(isTmpfsType(0x01021994), true);
  assert.equal(isTmpfsType(0x6969), false);
  assert.equal(
    expectedReportPath("linux-kvm"),
    join(process.cwd(), "docs/security-evidence/generated/launcher-linux-kvm.json"),
  );
  assert.equal(
    validateReportPath("insecure-container", "docs/security-evidence/generated/launcher-insecure-container.json"),
    join(process.cwd(), "docs/security-evidence/generated/launcher-insecure-container.json"),
  );
  assert.throws(() => validateReportPath("insecure-container", "/tmp/launcher-insecure-container.json"));
});

test("supported legacy and retired OpenBao entries refuse before target effects, including failure paths", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-retired-smoke-"));
  try {
    const effects = join(dir, "effects");
    const commands = [
      "docker",
      "timeout",
      "gtimeout",
      "dirname",
      "mktemp",
      "git",
      "date",
      "shasum",
      "sha256sum",
      "cut",
      "mkdir",
      "chmod",
      "sudo",
      "node",
      "python3",
      "rm",
      "seq",
      "openssl",
      "ssh",
      "sftp",
      "mv",
      "tsx",
    ];
    for (const command of commands) {
      const path = join(dir, command);
      await writeFile(path, '#!/bin/bash\nprintf EFFECT >> "$EFFECT_LOG"\nexit 97\n');
      await chmod(path, 0o700);
    }
    const receipt =
      '{"version":"cogs.dev-driver/v1alpha1","profile":"insecure-container","authority":"functional-only","command":"create","result":"pass","generation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n';
    for (const name of [
      "receipt",
      "state",
      "state.lock",
      ".cogs-retire-state-held",
      "authority",
      "quarantine",
      "export",
      "tmp",
      "report",
    ]) {
      await mkdir(join(dir, name));
      await writeFile(join(dir, name, "sentinel"), name === "receipt" ? receipt : "FOREIGN\0\n", { mode: 0o600 });
    }
    const snapshot = async () =>
      Promise.all(
        (await readdir(dir, { recursive: true })).sort().map(async (name) => {
          const s = await lstat(join(dir, name));
          return [
            name,
            s.dev,
            s.ino,
            s.mode,
            s.uid,
            s.gid,
            s.nlink,
            s.isFile() ? await readFile(join(dir, name)) : null,
          ];
        }),
      );
    const before = await snapshot();
    for (const script of [
      "dev/openbao-model-auth/ci-smoke.sh",
      "test/egress-conformance/stage3-real-runtime/ci-smoke.sh",
      "dev/insecure-sandbox/ci-smoke.sh",
      "scripts/run-launcher-smoke-evidence.ts",
    ]) {
      const cli = script.endsWith(".ts"),
        legacy = script.includes("insecure-sandbox") || cli;
      const source = await readFile(script, "utf8");
      const gate = "legacy launcher/insecure execution is disabled by ADR0335";
      if (legacy && !cli) {
        const prefix = `#!/usr/bin/env bash\n# Refusal is not cleanup or evidence; leave all uncertain legacy state untouched.\nprintf '%s\\n' '${gate}' >&2\nreturn 2 2>/dev/null || exit 2\n`;
        const check = (text: string) => assert(text.startsWith(prefix));
        check(source);
        for (const effect of ['mkdir "$report"', 'rm "$report"', "trap cleanup EXIT"])
          assert.throws(() => check(source.replace("printf", `${effect}\nprintf`)));
      }
      for (const profile of ["insecure-container", "linux-kvm", "macos-vm", "invalid", "--help"])
        for (const scenario of ["smoke", "s3-09", "invalid"])
          for (const entry of ["direct", "sourced", "missing", "initialize", "catch", "finally"] as const) {
            const path = join(process.cwd(), script),
              report = join(dir, entry === "missing" ? "absent" : "report");
            const preload = `import {registerHooks,syncBuiltinESMExports} from 'node:module';
import fs from 'node:fs'; import promises from 'node:fs/promises'; import cp from 'node:child_process';
import net from 'node:net'; import http from 'node:http'; import timers from 'node:timers';
const stderr=process.stderr; const effect=()=>{stderr.write('FORBIDDEN EFFECT\\n');process.exit(97)};
process.getuid=process.geteuid=()=>${entry === "direct" ? 0 : 65534};
registerHooks({load(url,context,next){const result=next(url,context);if(url===${JSON.stringify(`file://${path}`)}){
for(const api of [fs,promises,cp,net,http,timers])for(const key of Object.keys(api))if(typeof api[key]==='function')Object.defineProperty(api,key,{value:effect});
for(const key of ['setTimeout','setInterval','setImmediate'])globalThis[key]=effect;
process.on=process.once=effect;syncBuiltinESMExports();
const mutation=${JSON.stringify(entry)};
const first=mutation==='initialize'?'await mkdir("target");':mutation==='catch'?'try {throw Error()} catch {await unlink("target")}':mutation==='finally'?'try {throw Error()} finally {await unlink("target")}':'';
result.source=first+'\\n'+result.source;
}else if(url.includes('/dev/launcher/'))effect();return result;}});`;
            const args = cli
              ? [
                  "--import",
                  `data:text/javascript,${encodeURIComponent(preload)}`,
                  path,
                  "--profile",
                  profile,
                  "--scenario",
                  scenario,
                  "--state",
                  "state",
                  "--report",
                  report,
                ]
              : entry === "sourced"
                ? ["-c", 'source "$1" "$2"', "source", path, report]
                : [path, report];
            if (cli && scenario === "invalid") args.splice(3, args.length, ...(profile === "--help" ? ["--help"] : []));
            const mutated = cli && ["initialize", "catch", "finally"].includes(entry);
            const result = spawnSync(cli ? process.execPath : "/bin/bash", args, {
              input: entry === "direct" ? receipt : "invalid\0\n",
              env: {
                PATH: dir,
                EFFECT_LOG: effects,
                COGS_STAGE3_REAL_RUNTIME_PROFILE: profile,
                COGS_PROFILE: profile,
                COGS_ALLOW_INSECURE: "1",
                COGS_INSECURE_STATE_DIR: join(dir, "state"),
                COGS_INSECURE_GENERATION: entry === "direct" ? "a".repeat(32) : entry === "missing" ? "" : "invalid",
                HOME: dir,
                TMPDIR: join(dir, "tmp"),
                OPENBAO_IMAGE: "caller-selected:replacement",
                COGS_SOURCE_REVISION: sourceRevision,
              },
              encoding: "utf8",
              timeout: 2000,
            });
            assert.equal(result.status, mutated ? 97 : 2, `${script}:${profile}:${entry}:${result.stderr}`);
            assert.equal(result.stdout, "");
            assert.equal(result.error, undefined);
            if (legacy) assert.equal(result.stderr, mutated ? "FORBIDDEN EFFECT\n" : `${gate}\n`);
            else assert.match(result.stderr, /OpenBao 2\.6\.1 is retired; no admitted replacement/u);
            assert.deepEqual(await snapshot(), before, "refusal must precede command/report effects");
          }
      if (!legacy) assert.ok(source.includes(OPENBAO_IMAGE), "retain historical pin bytes");
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("sensitive export cleanup treats post-acquisition removal as uncertain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-export-"));
  try {
    const path = join(dir, "launcher-smoke.json");
    await writeFile(path, "{}\n", { mode: 0o600 });
    await assert.rejects(() => cleanupSensitiveExport(path, async () => unlink(path)));
    await cleanupSensitiveExport(join(dir, "absent.json"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher preparation excludes retired OpenBao and remains outside active workflows", async (t) => {
  assert.equal(LAUNCHER_DOCKER, "/usr/bin/docker");
  assert.deepEqual(LAUNCHER_IMAGE_ENV, { HOME: "/tmp" });
  assert.deepEqual(LAUNCHER_REQUIRED_IMAGES, [ENVOY_IMAGE]);
  assert.ok(Object.isFrozen(LAUNCHER_REQUIRED_IMAGES));
  const inspect = JSON.stringify([{ RepoDigests: [ENVOY_IMAGE.replace(":v1.38.3@", "@")] }]);
  assert.throws(() => verifyImageInspect(ENVOY_IMAGE, JSON.stringify([{ RepoDigests: [] }])));
  verifyImageInspect(ENVOY_IMAGE, inspect);
  const calls: unknown[][] = [];
  const exec = t.mock.method(childProcess, "execFileSync", (...args: unknown[]) => {
    calls.push(args);
    return inspect;
  });
  syncBuiltinESMExports();
  try {
    prepareLauncherImages(); // Only the injected recorder runs; never Docker.
    assert.deepEqual(
      calls.map((args) => args.slice(0, 2)),
      [
        [LAUNCHER_DOCKER, ["pull", ENVOY_IMAGE]],
        [LAUNCHER_DOCKER, ["image", "inspect", ENVOY_IMAGE]],
      ],
    );
    assert.ok(!JSON.stringify(calls).includes(OPENBAO_IMAGE));
  } finally {
    exec.mock.restore();
    syncBuiltinESMExports();
  }

  const insecure = await readFile(join(process.cwd(), ".github/workflows/insecure-container.yml"), "utf8");
  const kvm = await readFile(join(process.cwd(), ".github/workflows/kvm-qualification.yml"), "utf8");
  for (const workflow of [insecure, kvm]) {
    assert.doesNotMatch(
      workflow,
      /prepare-launcher-images|run-launcher-smoke-evidence|stage3-real-runtime|openbao-model-auth/,
    );
  }
  assert.match(insecure, /CANDIDATE: \$\{\{ needs\.admission\.outputs\.candidate \}\}/);
  assert.match(kvm, /COGS_SOURCE_REVISION: \$\{\{ needs\.admission\.outputs\.candidate \}\}/);
  assert.match(insecure, /EXECUTE_PROTECTED_PRODUCT/u);
  assert.match(insecure, /docker build --pull=false --network=none/u);
  assert.doesNotMatch(insecure, /envoy_response|COGS_ENVOY_RESPONSE_TEST/u);
  assert.match(kvm, /id: smoke/);
  assert.match(kvm, /id: domain_cleanup\n {8}if: always\(\) && env\.COGS_KVM_NETNS != ''/);
  assert.match(kvm, /id: evidence\n {8}if: always\(\)/);
  for (const [variable, step] of [
    ["SMOKE_OUTCOME", "smoke"],
    ["DOMAIN_OUTCOME", "domain_cleanup"],
    ["EVIDENCE_OUTCOME", "evidence"],
  ] as const) {
    assert(kvm.includes(`${variable}: \${{ steps.${step}.outcome }}`));
  }
  assert.match(kvm, /test "\$SMOKE_OUTCOME" = success/u);
  assert.doesNotMatch(kvm, /envoy_suite|steps\.guest|driver\.sh create|driver\.sh destroy|suite-smoke/u);
  assert.match(kvm, /ref: \$\{\{ needs\.admission\.outputs\.candidate \}\}/);
});

test("protected Docker context is an exact root-owned COPY closure and preserves digest provenance", async () => {
  const source = await readFile(join(process.cwd(), ".github/workflows/insecure-container.yml"), "utf8");
  const expected = `**
!.dockerignore
!src/
!src/**
!schemas/
!schemas/**
!dev/
!dev/product-test/
!dev/product-test/**
!dev/launcher/
!dev/launcher/api-client.ts
!third_party/
!third_party/**
`;
  const copyClosure = ["src", "schemas", "dev/product-test", "dev/launcher/api-client.ts", "third_party"];
  const assertContext = (candidate: string) => {
    const literal = /dockerignore=b"""([\s\S]*?)"""/u.exec(candidate)?.[1]?.replaceAll("\n          ", "\n");
    assert.equal(literal, expected, "deny-all context has only the product closure");
    assert.match(candidate, /os\.replace\(temporary,'\.dockerignore'/u);
    assert.match(candidate, /stat\.S_IMODE\(info\.st_mode\)!=0o400/u);
    assert.match(candidate, /'dockerignore':'sha256:'\+hashlib\.sha256\(dockerignore\)\.hexdigest\(\)/u);
    assert.match(candidate, /--build-arg PINNED_WORKER="\$STOCK_WORKER"/u);
    assert.doesNotMatch(candidate, /--build-arg PINNED_WORKER="\$STOCK_WORKER_ID"/u);
    assert.match(candidate, /'stock_worker_image':os\.environ\['STOCK_WORKER_ID'\]/u);
  };
  assertContext(source);
  const copies = [...WORKER_DOCKERFILE.matchAll(/^COPY --chown=0:0 (\S+) \/opt\/cogs\/\1$/gmu)].map(
    (match) => match[1],
  );
  assert.deepEqual(copies, copyClosure, "Docker COPY and .dockerignore closures are equal");
  for (const mutation of [
    source.replace("!schemas/**", "!schemas/runtime-v1alpha1.json"),
    source.replace("!dev/launcher/api-client.ts", "!dev/launcher/"),
    source.replace('PINNED_WORKER="$STOCK_WORKER"', 'PINNED_WORKER="$STOCK_WORKER_ID"'),
    source.replace("stat.S_IMODE(info.st_mode)!=0o400", "stat.S_IMODE(info.st_mode)!=0o644"),
  ])
    assert.throws(() => assertContext(mutation), "context or provenance mutation was accepted");
});

test("production cgroup descriptor syscalls close on veto and recover only durable exact absence", () => {
  const python = String.raw`
import importlib.util,os,tempfile
from unittest.mock import patch
s=importlib.util.spec_from_file_location('custody','dev/product-test/host-custody.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
g='a'*32
def fixture(root):
 control=root+'/control';cg=root+'/cogs-product-'+g;os.mkdir(control);os.mkdir(cg);os.mkdir(cg+'/helpers');open(cg+'/cgroup.events','w').write('populated 0\n')
 o=m.Custody.__new__(m.Custody);o.generation=g;o.cg='/sys/fs/cgroup/cogs-product-'+g;o.cgroup_name='cogs-product-'+g;o.cgroup_parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY);o.cgroup_fd=os.open(cg,os.O_RDONLY|os.O_DIRECTORY);o.helpers_fd=os.open(cg+'/helpers',os.O_RDONLY|os.O_DIRECTORY);o.cgroup_veto=False
 o.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);o.control=os.open(control,os.O_RDONLY|os.O_DIRECTORY);o.records=set();o.failed=True;o.ids={};o.peers={};o.sealed=[];o.mounts=[];o.disk=None
 journal={}
 def record(n,v):
  journal[n]=v;o.records.add(n);open(control+'/'+n,'w').write('x')
 o.record=record;o.saved=lambda n:journal[n];o.settle_children=lambda:None
 record('cgroup',list(m.identity(os.fstat(o.cgroup_fd))[:2]));record('helpers-cgroup',list(m.identity(os.fstat(o.helpers_fd))[:2]));record('cgroup-retire-intent',True)
 return o,journal,cg,control
with tempfile.TemporaryDirectory() as root:
 o,journal,cg,control=fixture(root);fds=(o.cgroup_parent,o.cgroup_fd,o.helpers_fd);real_rmdir=os.rmdir
 def rmdir(name,*,dir_fd=None):
  if name==o.cgroup_name: os.unlink(cg+'/cgroup.events')
  return real_rmdir(name,dir_fd=dir_fd)
 with patch.object(m.os,'rmdir',side_effect=rmdir):o.settle()
 assert not os.path.exists(cg) and journal['cgroup-rmdir-pending'] is True and journal['cgroup-retired'] is True and 'retired' in journal
 for fd in fds:
  try: os.fstat(fd)
  except OSError: pass
  else: raise AssertionError('retained production cgroup descriptor leaked')
with tempfile.TemporaryDirectory() as root:
 o,journal,cg,control=fixture(root);journal['cgroup']=[0,0]
 try:o.verify_cgroups()
 except RuntimeError:pass
 else:raise AssertionError('foreign production cgroup accepted')
 assert o.cgroup_veto and o.cgroup_parent is o.cgroup_fd is o.helpers_fd is None
 try:o.cgroup_fds()
 except RuntimeError:pass
 else:raise AssertionError('veto reopened a cgroup pathname')
 os.close(o.control);os.close(o.fd)
with tempfile.TemporaryDirectory() as root:
 o,journal,cg,control=fixture(root);o.failed=False;parent=o.cgroup_parent;os.close(o.helpers_fd);os.close(o.cgroup_fd);os.rmdir(cg+'/helpers');os.unlink(cg+'/cgroup.events');os.rmdir(cg);o.helpers_fd=o.cgroup_fd=o.cgroup_parent=None
 journal['cgroup-rmdir-pending']=True;open(control+'/cgroup-rmdir-pending','w').write('x');o.command=lambda *a:(_ for _ in ()).throw(AssertionError('recovery command'))
 real_open=os.open
 def opened(path,*args,**kwargs): return os.dup(parent) if path=='/sys/fs/cgroup' else real_open(path,*args,**kwargs)
 with patch.object(m.os,'open',side_effect=opened): assert o.recover_cgroup_rmdir({'cgroup-rmdir-pending'})
 assert journal['cgroup-retired'] is True and journal['retired']=={'generation':g,'failed':True}
 os.close(parent);os.close(o.control);os.close(o.fd)
print('production cgroup syscall contracts passed')
`;
  const result = spawnSync("python3", ["-I", "-B", "-c", python], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "production cgroup syscall contracts passed");
});

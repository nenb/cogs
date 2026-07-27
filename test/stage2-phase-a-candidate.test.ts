import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";

const root = process.cwd();
const workflowPath = join(root, ".github/workflows/stage2-phase-a-candidate.yml");
const runnerPath = join(root, "scripts/run-stage2-phase-a-candidate.py");
const budgetPath = join(root, "scripts/stage2-phase-a-budget.py");
const schemaV1Path = join(root, "schemas/stage2-phase-a-candidate-v1.json");
const schemaV2Path = join(root, "schemas/stage2-phase-a-candidate-v2.json");
const runtimeSchemaPath = join(root, "schemas/stage2-phase-b-qualification-v1.json");
const historicalReportPath = join(root, "docs/test-reports/stage-2-phase-a-candidate-30180567797.canonical-json");
const phaseGraphFixturePath = join(root, "test/fixtures/stage2-phase-a-v2-phase-graphs.json");
const pythonTest = join(root, "test/stage2-phase-a-candidate.py");
const ciPath = join(root, ".github/workflows/ci.yml");
const nativeSelector = "COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;

test("Phase A pure downloader, KVM ioctl, and non-authority policies", () => {
  const env: NodeJS.ProcessEnv = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
  delete env[nativeSelector];
  const result = spawnSync("python3", [pythonTest], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 20_000,
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.equal(result.stdout.match(/stage2 phase-a candidate portable tests passed/gu)?.length, 1);
  const nonExact = spawnSync("python3", [pythonTest], {
    cwd: root,
    env: { ...env, [nativeSelector]: "true" },
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.notEqual(nonExact.status, 0);
  assert.equal(nonExact.stdout, "");
  const produced = result.stdout
    .split("\n")
    .filter((line) => line.startsWith("producer-boundary-report "))
    .map(
      (line) =>
        JSON.parse(line.slice("producer-boundary-report ".length)) as {
          boundary: string;
          report: unknown;
        },
    );
  assert.equal(produced.length, 14);
  assert.equal(new Set(produced.map(({ boundary }) => boundary)).size, 14);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(JSON.parse(readFileSync(schemaV2Path, "utf8")));
  for (const { boundary, report } of produced) {
    assert.equal(validate(report), true, `${boundary}: ${ajv.errorsText(validate.errors)}`);
  }
});

test("runtime-discovery workflow has the exact PR 230 one-shot guard and cleanup order", async () => {
  const workflow = await readFile(workflowPath, "utf8");
  assert.match(workflow, /^run-name: phase-b-runtime-discovery$/mu);
  assert.match(
    workflow,
    /^on:\n {2}pull_request:\n {4}branches: \[feat\/issue42-deterministic-rootfs\]\n {4}types: \[labeled\]$/mu,
  );
  for (const gate of [
    "github.event_name == 'pull_request'",
    "github.event.action == 'labeled'",
    "github.event.label.name == 'security'",
    "github.event.pull_request.head.repo.full_name == github.repository",
    "github.event.pull_request.base.sha == '8caab23bb4277121a77d80dc043b3c2c43b07ced'",
    "github.event.pull_request.number == 230",
    "github.run_attempt == 1",
  ])
    assert.ok(workflow.includes(gate), gate);
  assert.match(workflow, /permissions:\n {2}contents: read\n {2}actions: read/u);
  assert.match(workflow, /EXACT_RUN_NAME: phase-b-runtime-discovery/u);
  assert.match(workflow, /current != min\(row\["id"\] for row in marker\)/u);
  assert.match(workflow, /len\(records\) != total/u);
  assert.doesNotMatch(workflow, /"head_sha": head/u);
  assert.equal(workflow.match(/\$\{\{ github\.token \}\}/gu)?.length, 1);
  assert.doesNotMatch(workflow, /actions\/checkout|persist-credentials|contains\(|reopened|synchronize/u);
  assert.match(workflow, /credential\.helper= -c core\.askPass=[\s\S]*GIT_TERMINAL_PROMPT=0/u);
  assert.match(workflow, /download-2-fixed-public-runtime-assets/u);
  assert.match(workflow, /COGS_REQUIRE_LINUX_PROCESS_TESTS_V1=1[\s\S]*test\/aws-stage2-completion-kata-process\.py/u);
  assert.match(workflow, /COGS_REQUIRE_ROOT_RUNTIME_CRASH_MATRIX_V1=1[\s\S]*test\/stage2-phase-a-candidate\.py/u);
  assert.equal(workflow.match(/COGS_STAGE2_BUDGET_PROFILE=phase-b-runtime-discovery/gu)?.length, 1);
  assert.doesNotMatch(workflow, /check post-export-residue-start/u);
  assert.doesNotMatch(workflow, /download-16-fixed-public-stage2-artifacts/u);
  const commands = ["observe", "cleanup", "residue", "validate", "export", "cleanup-export", "post-export-residue"];
  for (const command of commands) assert.match(workflow, new RegExp(`phase-b-runtime-discovery ${command}`, "u"));
  const positions = commands.map((command) => workflow.indexOf(`phase-b-runtime-discovery ${command}`));
  assert.deepEqual(
    positions,
    [...positions].sort((left, right) => left - right),
  );
  assert.match(workflow, /path: \/var\/tmp\/cogs-stage2-phase-b-runtime-discovery-v1\.qualification\.json/u);
  assert.equal(
    workflow.match(/^ {10}path: \/var\/tmp\/cogs-stage2-phase-b-runtime-discovery-v1\.qualification\.json$/gmu)?.length,
    1,
  );
  assert.match(workflow, /timeout-minutes: 1[\s\S]*actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/u);
  assert.match(workflow, /cancel-in-progress: false/u);
  assert.match(workflow, /elapsed < 5_280_000_000_000/u);
  assert.doesNotMatch(workflow, /apt(?:-get)?|dnf|yum|apk|brew|snap|dpkg|systemctl|\/dev\/kvm|ssh\s|aws\s/u);
  const [runner, companion, ci] = await Promise.all([
    readFile(runnerPath, "utf8"),
    readFile(pythonTest, "utf8"),
    readFile(ciPath, "utf8"),
  ]);
  const runtimeRoute = runner.slice(runner.indexOf("def _runtime_open_anonymous"), runner.indexOf("def main"));
  assert.match(runtimeRoute, /os\.O_TMPFILE \| os\.O_RDWR/u);
  assert.match(runtimeRoute, /_read_regular\(RUNTIME_REPORT, MAX_JSON, 0o400\)/u);
  assert.match(
    runner,
    /RUNTIME_EXPORT = Path\("\/var\/tmp\/cogs-stage2-phase-b-runtime-discovery-v1\.qualification\.json"\)/u,
  );
  assert.match(runtimeRoute, /def _runtime_export\(\):[\s\S]*os\.fchmod\(descriptor, 0o444\)/u);
  assert.match(runtimeRoute, /collector = qualification\.bind_runtime_discovery\(\)/u);
  assert.match(runtimeRoute, /tuple\(descriptors\), journal\.intent, journal\.started, journal\.settled, deadline_ns/u);
  assert.doesNotMatch(runtimeRoute, /\.partial|asset-final-owned/u);
  assert.match(runner, /_recover_runtime_discovery_children/u);
  assert.doesNotMatch(
    runtimeRoute,
    /_prove_kvm|_rootfs_candidates|_recover_rootfs|completion_kata_coordinator|extractall|tarfile|subprocess|killpg|\/dev\/kvm/u,
  );

  assert.match(
    workflow,
    /\/usr\/bin\/python3 -I - <<'PY'[\s\S]*urllib\.request\.urlopen\(request, timeout=min\(20, remaining\)\)/u,
  );

  assert.match(companion, /value = os\.getenv\(_NATIVE_SELECTOR\)/u);
  assert.match(companion, /selected != \[\(_NATIVE_SELECTOR \+ "=1"\)\.encode\(\)\]/u);
  assert.match(companion, /CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb/u);
  assert.match(companion, /_runtime_open_anonymous\(parent, 0o600\)[\s\S]*os\.fchmod\(descriptor, 0o400\)/u);
  assert.match(companion, /_runtime_link_anonymous\(parent, descriptor, name\)[\s\S]*_owned_file[\s\S]*_unlink_exact/u);
  assert.match(companion, /st_nlink, initial\.st_size\) == \(0, 0, 0o600, 0, 0\)/u);
  assert.match(companion, /named\.st_nlink, named\.st_size\) == \(0, 0, 0o400, 1, len\(fixture\)\)/u);
  assert.ok(companion.indexOf("if _native_selected():") < companion.indexOf("BUDGET ="));
  assert.equal(companion.match(/print\(_NATIVE_MARKER/gu)?.length, 1);

  const nativeJob = ci.slice(ci.indexOf("  native-runtime-preflight:"));
  assert.match(nativeJob, /mount -t tmpfs[\s\S]*mount -t proc[\s\S]*exec \/usr\/sbin\/chroot/u);
  const sandbox = nativeJob.slice(nativeJob.indexOf("SANDBOX'"), nativeJob.indexOf("          SANDBOX"));
  const rootLauncherStart = nativeJob.indexOf("descriptor_launcher = r'''");
  const rootLauncher = nativeJob.slice(rootLauncherStart, nativeJob.indexOf("          '''", rootLauncherStart));
  const outer = nativeJob.slice(nativeJob.indexOf("<<'OUTER'"), rootLauncherStart);
  assert.ok(rootLauncherStart > 0 && rootLauncher.length > 0);
  assert.match(
    outer,
    /os\.stat\(checkout, follow_symlinks=False\)[\s\S]*checkout != checkout_root[\s\S]*os\.path\.realpath\(os\.fsencode\(checkout\)\)[\s\S]*checkout_captured = tuple\(str\(value\) for value in authenticated\)/u,
  );
  assert.doesNotMatch(outer, /os\.open\(checkout|dup2\([^\n]*3|set_inheritable\(3|pass_fds/u);
  assert.ok(outer.indexOf("path_identity = os.stat(checkout") < nativeJob.indexOf("temp_fd = os.open"));
  assert.match(
    nativeJob,
    /\["\/usr\/bin\/sudo","-n","--close-from=3","\/usr\/bin\/python3","-I","-c",descriptor_launcher,checkout,\*checkout_captured,test_path,sandbox\]/u,
  );
  assert.match(
    nativeJob,
    /stdin=subprocess\.DEVNULL, stdout=output_fd, stderr=subprocess\.STDOUT, close_fds=True, env=\{\}, check=False/u,
  );
  assert.match(rootLauncher, /len\(sys\.argv\) != 8[\s\S]*str\(int\(raw\)\) != raw[\s\S]*int\(raw\) > 2\*\*64-1/u);
  assert.match(
    rootLauncher,
    /os\.path\.realpath\(encoded\) != encoded[\s\S]*expected\[2\] == 0[\s\S]*expected\[3\] == 0/u,
  );
  assert.match(
    rootLauncher,
    /os\.open\(checkout,os\.O_PATH\|os\.O_DIRECTORY\|os\.O_NOFOLLOW\|os\.O_CLOEXEC\)[\s\S]*identity\(os\.stat\(checkout,follow_symlinks=False\)\) != wanted/u,
  );
  assert.match(
    rootLauncher,
    /os\.dup2\(checkout_fd,3,inheritable=True\)\n {14}os\.close\(checkout_fd\)[\s\S]*os\.set_inheritable\(3,True\)[\s\S]*fcntl\.FD_CLOEXEC/u,
  );
  assert.match(
    rootLauncher,
    /set\(map\(int,os\.listdir\("\/proc\/self\/fd"\)\)\)-\{0,1,2,3\}[\s\S]*\{"0","1","2","3","4"\}[\s\S]*os\.path\.exists\("\/proc\/self\/fd\/4"\)/u,
  );
  assert.match(
    rootLauncher,
    /"\/usr\/bin\/setpriv","--reuid","0","--regid","0","--clear-groups","--no-new-privs","\/usr\/bin\/unshare","--user","--map-users=0:0:1","--map-groups=0:0:1","--net","--pid","--fork","--mount","\/usr\/bin\/env","-i","\/usr\/bin\/bash","--noprofile","--norc","-c",sandbox,"--",\*raw_identity,test_path/u,
  );
  assert.match(rootLauncher, /os\.execve\("\/usr\/bin\/setpriv",command,\{\}\)/u);
  assert.equal(rootLauncher.match(/os\.execve/gu)?.length, 1);
  assert.doesNotMatch(rootLauncher, /os\.environ|os\.getenv|importlib|runpy|__import__|SourceFileLoader|pass_fds/u);
  assert.match(sandbox, /parent = os\.getppid\(\)[\s\S]*parent != 1[\s\S]*\{"0","1","2","3"\}/u);
  assert.match(sandbox, /fdinfo\/3[\s\S]*flags & required != required[\s\S]*fcntl\.FD_CLOEXEC/u);
  assert.match(sandbox, /\/proc\/sys\/kernel\/overflow[\s\S]*stat\.S_IFDIR/u);
  assert.equal(
    sandbox.match(/^ {10}\/usr\/bin\/mount --no-canonicalize --bind \/proc\/self\/fd\/3 "\$root\/src"$/gmu)?.length,
    1,
  );
  assert.equal(sandbox.match(/\/proc\/self\/fd\/3/gu)?.length, 1);
  assert.match(
    sandbox,
    /source = one\([\s\S]*bound = one\([\s\S]*target_stat = os\.stat\(target, follow_symlinks=False\)/u,
  );
  assert.equal(sandbox.match(/\/usr\/bin\/python3 -I -c "\$verify_checkout_bind"/gu)?.length, 2);
  assert.match(
    sandbox,
    / {10}VERIFY\n {10}exec 3>&-\n {10}IFS= read -r -d '' closed_observer <<'CLOSED'[\s\S]*parent != 1[\s\S]*\{"0","1","2"\}[\s\S]* {10}CLOSED\n {10}\/usr\/bin\/python3 -I -c "\$closed_observer"\n {10}COGS_NATIVE_TEST_PATH=\$test_path exec \/usr\/sbin\/chroot/u,
  );
  assert.equal(nativeJob.match(/--close-from=/gu)?.length, 1);
  assert.doesNotMatch(nativeJob, /preexec_fn|stdin=None|--close-from=4|-C 4|"-C"|--preserve-env/u);
  assert.doesNotMatch(
    sandbox,
    /close_inherited_fds|\/proc\/\$\$\/fd\/\*|mount --bind "\$checkout"|\/home\/runner\/work|readlink[^\n]*checkout|realpath[^\n]*checkout/u,
  );
  assert.doesNotMatch(
    nativeJob,
    /map-root-user|str\(uid\)|str\(gid\)|newuidmap|newgidmap|chown|chmod|setfacl|RootView|copyfile/u,
  );
  assert.match(nativeJob, /raw\.count\("\\n"\) != 1 or raw\.split\(\) != \["0", "0", "1"\]/u);
  assert.match(
    nativeJob,
    /"\/usr\/bin\/python3", "\/usr\/bin\/zstd", "\/usr\/bin\/gzip", "\/dev\/null", "\/dev\/urandom"[\s\S]*st_uid,value\.st_gid\) != \(0,0\)[\s\S]*target_stat\.st_uid,target_stat\.st_gid[\s\S]*!= \(0,0\)/u,
  );
  assert.match(
    nativeJob,
    /--securebits \+noroot,\+noroot_locked[\s\S]*--bounding-set=-all --inh-caps=-all --ambient-caps=-all[\s\S]*--clear-groups --no-new-privs[\s\S]*\/usr\/bin\/timeout --signal=KILL 240 \/usr\/bin\/python3 -I -B -c/u,
  );
  const launcherMatch = nativeJob.match(/<<'SECCOMP'[\s\S]*?\n {10}SECCOMP/u);
  assert.ok(launcherMatch);
  const launcher = launcherMatch[0];
  const direct = launcher.slice(launcher.indexOf("ins=("), launcher.indexOf("F(0x15,0,3,157)"));
  assert.deepEqual(
    [...direct.matchAll(/F\(0x15,0,1,([0-9]+)\),F\(0x06,0,0,0x00050001\)/gu)].map((row) => Number(row[1])),
    [41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307, 425, 426, 427, 272, 308, 317],
  );
  assert.match(
    launcher,
    /F\(0x20,0,0,4\),F\(0x15,1,0,0xc000003e\),F\(0x06,0,0,0x80000000\),F\(0x20,0,0,0\),F\(0x45,0,1,0x40000000\),F\(0x06,0,0,0x80000000\)/u,
  );
  assert.match(
    launcher,
    /F\(0x15,0,3,157\),F\(0x20,0,0,16\),F\(0x15,0,1,22\),F\(0x06,0,0,0x00050001\),F\(0x06,0,0,0x7fff0000\)/u,
  );
  assert.match(
    launcher,
    /"Uid","Gid","Groups","CapInh","CapPrm","CapEff","CapBnd","CapAmb","NoNewPrivs","Seccomp"[\s\S]*rows\["Seccomp"\] != \("2" if filtered else "0"\)/u,
  );
  assert.match(launcher, /if len\(ins\)!=59: raise RuntimeError\("filter length"\)/u);
  assert.ok(
    launcher.indexOf("status(False)") < launcher.indexOf("libc.prctl(38,1,0,0,0)") &&
      launcher.indexOf("libc.prctl(38,1,0,0,0)") < launcher.indexOf("libc.prctl(22,2,ctypes.addressof(program),0,0)") &&
      launcher.indexOf("libc.prctl(22,2,ctypes.addressof(program),0,0)") < launcher.indexOf("status(True)") &&
      launcher.indexOf("status(True)") < launcher.indexOf("os.execve"),
  );
  assert.match(
    launcher,
    /path not in \("\/src\/test\/aws-stage2-completion-kata-process\.py","\/src\/test\/stage2-phase-a-candidate\.py"\)/u,
  );
  assert.match(
    launcher,
    /os\.execve\("\/usr\/bin\/python3",\("\/usr\/bin\/python3","-I","-B",path\),\{"COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1":"1","PYTHONDONTWRITEBYTECODE":"1"\}\)/u,
  );
  assert.match(launcher, /except BaseException:[\s\S]*native seccomp launcher failed[\s\S]*os\._exit\(126\)/u);
  assert.doesNotMatch(launcher, /libseccomp|subprocess|platform|uname|importlib|compile\(/u);
  assert.match(
    nativeJob,
    /run_preflight \/src\/test\/stage2-phase-a-candidate\.py 'stage2 phase-a candidate portable tests passed'/u,
  );
  assert.match(nativeJob, /os\.ftruncate\(expected_fd, 0\)[\s\S]*\/usr\/bin\/cmp[\s\S]*print\(marker, flush=True\)/u);
  assert.doesNotMatch(nativeJob, /\b(?:apt-get|apt|dnf|yum|apk|brew|curl|wget)\b/u);
});

test("runtime-discovery schema is structurally exact and codec separately enforces semantics", async () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictTuples: false });
  const validate = ajv.compile(JSON.parse(await readFile(runtimeSchemaPath, "utf8")));
  const digest = "a".repeat(64);
  const canonical = (value: unknown): string => {
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
    if (value !== null && typeof value === "object") {
      const row = value as Record<string, unknown>;
      return `{${Object.keys(row)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonical(row[key])}`)
        .join(",")}}`;
    }
    return JSON.stringify(value);
  };
  const first = <T>(values: T[]): T => {
    const value = values[0];
    assert.ok(value);
    return value;
  };
  const members: Record<string, string> = {
    "kata-runtime": "opt/kata/bin/kata-runtime",
    "kata-shim": "opt/kata/bin/containerd-shim-kata-v2",
    qemu: "opt/kata/bin/qemu-system-x86_64",
    virtiofsd: "opt/kata/libexec/virtiofsd",
    "kata-config": "opt/kata/share/defaults/kata-containers/configuration-qemu.toml",
    containerd: "bin/containerd",
    ctr: "bin/ctr",
  };
  const roles = (names: string[]) =>
    names.map((role) => {
      const member = members[role];
      assert.ok(member);
      return { role, member, kind: "file" };
    });
  const archive = (roleNames: string[]) => ({
    stream_bytes: 1024,
    member_count: 1,
    member_bytes: 1,
    type_counts: { directory: 0, file: 1, hardlink: 0, symlink: 0 },
    rejected_type_count: 0,
    manifest_sha256: digest,
    links: {
      counts: {
        "symlink-relative-in-root": 0,
        "symlink-absolute": 0,
        "symlink-escape": 0,
        "hardlink-member": 0,
        "hardlink-missing": 0,
        "hardlink-absolute": 0,
        "hardlink-escape": 0,
      },
      sha256: digest,
    },
    roles: roles(roleNames),
    blockers: [],
  });
  const objects = [
    { role: "executable", soname: null, size: 1, sha256: "1".repeat(64), needed: ["libfixed.so"] },
    { role: "library", soname: "libfixed.so", size: 1, sha256: "2".repeat(64), needed: [] },
    { role: "loader", soname: "ld-fixed.so", size: 1, sha256: "3".repeat(64), needed: [] },
  ];
  const closureDigest = createHash("sha256")
    .update(`${canonical(objects)}\n`)
    .digest("hex");
  const supervision = { direct_children: 1, helper_descendants: 0, status: 0, reaped: true };
  const report = {
    version: "cogs.stage2-phase-b-runtime-discovery/v1",
    stage: "phase-b-runtime-discovery",
    authority: "candidate",
    qualified: false,
    promotion: false,
    source: { revision: "b".repeat(40), manifest_sha256: digest },
    duration_ms: 1,
    checks: {
      assets: "pass",
      archive_enumeration: "pass",
      host_elf_closures: "pass",
      supervision: "pass",
      cleanup: "pass",
      residue: "pass",
    },
    assets: [
      {
        component: "kata",
        release: "3.32.0",
        name: "kata-static-3.32.0-amd64.tar.zst",
        compression: "zstd",
        size: 1547940938,
        sha256: "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01",
        archive: archive(["kata-runtime", "kata-shim", "qemu", "virtiofsd", "kata-config"]),
        supervision,
      },
      {
        component: "containerd",
        release: "2.2.1",
        name: "containerd-static-2.2.1-linux-amd64.tar.gz",
        compression: "gzip",
        size: 33645699,
        sha256: "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883",
        archive: archive(["containerd", "ctr"]),
        supervision,
      },
    ],
    host_elf_closures: ["python3-parser", "zstd", "gzip"].map((tool) => ({
      tool,
      objects,
      total_bytes: 3,
      closure_sha256: closureDigest,
    })),
    claims: { rootfs: false, kvm: false, lifecycle: false, extraction: false, publication: false, production: false },
    blockers: ["candidate-non-authoritative", "runtime-layout-uncommitted"],
  };
  const strictAccepts = (value: unknown) =>
    spawnSync(
      "python3",
      [
        "-I",
        "-c",
        "import sys;sys.path.insert(0,sys.argv[1]);import completion_kata_qualification as q;q.load_runtime_discovery_report(sys.stdin.buffer.read())",
        join(root, "deploy/aws-feasibility/remote"),
      ],
      { input: `${canonical(value)}\n`, encoding: "utf8" },
    ).status === 0;
  assert.equal(validate(report), true, ajv.errorsText(validate.errors));
  assert.equal(strictAccepts(report), true);

  const hostileValues = [
    { ...structuredClone(report), qualified: true },
    { ...structuredClone(report), path: "/host" },
    { ...structuredClone(report), blockers: ["candidate-non-authoritative"] },
    { ...structuredClone(report), assets: [...report.assets].reverse() },
    { ...structuredClone(report), claims: { ...report.claims, extraction: true } },
  ];
  const wrongKind = structuredClone(report);
  first(first(wrongKind.assets).archive.roles).kind = "symlink";
  hostileValues.push(wrongKind);
  const missingRole = structuredClone(report);
  first(missingRole.assets).archive.roles.pop();
  hostileValues.push(missingRole);
  const missingLoader = structuredClone(report);
  const missingLoaderClosure = first(missingLoader.host_elf_closures);
  missingLoaderClosure.objects = missingLoaderClosure.objects.slice(0, 2);
  hostileValues.push(missingLoader);
  for (const hostile of hostileValues) {
    assert.equal(validate(hostile), false, "schema accepted structurally hostile report");
  }
  for (const hostile of hostileValues) {
    assert.equal(strictAccepts(hostile), false, "codec accepted structurally hostile report");
  }

  const reversedBlockers = structuredClone(report);
  reversedBlockers.blockers.reverse();
  assert.equal(validate(reversedBlockers), false, "schema accepted reversed fixed blocker prefix");
  assert.equal(strictAccepts(reversedBlockers), false, "production validation accepted reversed blocker prefix");
  const maximumDuration = structuredClone(report);
  maximumDuration.duration_ms = 5_280_000;
  assert.equal(validate(maximumDuration), true, ajv.errorsText(validate.errors));
  assert.equal(strictAccepts(maximumDuration), true);
  const excessiveDuration = structuredClone(report);
  excessiveDuration.duration_ms = 5_280_001;
  assert.equal(validate(excessiveDuration), false, "schema accepted excessive duration");
  assert.equal(strictAccepts(excessiveDuration), false, "production validation accepted excessive duration");
  const unresolvedNeeded = structuredClone(report);
  first(first(unresolvedNeeded.host_elf_closures).objects).needed = ["missing.so"];
  const wrongDigest = structuredClone(report);
  first(wrongDigest.host_elf_closures).closure_sha256 = digest;
  const wrongTotal = structuredClone(report);
  first(wrongTotal.host_elf_closures).total_bytes = 4;
  const wrongOrder = structuredClone(report);
  first(wrongOrder.host_elf_closures).objects.reverse();
  const wrongTypeArithmetic = structuredClone(report);
  first(wrongTypeArithmetic.assets).archive.member_count = 2;
  const wrongLinkArithmetic = structuredClone(report);
  first(wrongLinkArithmetic.assets).archive.links.counts["hardlink-member"] = 1;
  const wrongAggregate = structuredClone(report);
  for (const closure of wrongAggregate.host_elf_closures) {
    for (const object of closure.objects) object.size = 100_000_000;
    closure.total_bytes = 300_000_000;
    closure.closure_sha256 = createHash("sha256")
      .update(`${canonical(closure.objects)}\n`)
      .digest("hex");
  }
  const codecSemanticValues = [
    unresolvedNeeded,
    wrongDigest,
    wrongTotal,
    wrongOrder,
    wrongTypeArithmetic,
    wrongLinkArithmetic,
    wrongAggregate,
  ];
  for (const hostile of codecSemanticValues) {
    assert.equal(validate(hostile), true, ajv.errorsText(validate.errors));
    assert.equal(strictAccepts(hostile), false, "codec accepted semantically hostile report");
  }
});

test("historical Phase A v1 schema remains immutable and validates v1 reports only", async () => {
  const v1Raw = await readFile(schemaV1Path, "utf8");
  const committed = spawnSync("git", ["show", "HEAD:schemas/stage2-phase-a-candidate-v1.json"], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(committed.status, 0, committed.stderr);
  assert.equal(v1Raw, committed.stdout);
  assert.equal(
    createHash("sha256").update(v1Raw).digest("hex"),
    "7fb0d1e29f3e3789dcfc4a17e5f753fd7ad88c227f04d15c8003d870d4b72286",
  );
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validateV1 = ajv.compile(JSON.parse(v1Raw));
  const v1 = {
    version: "cogs.stage2-phase-a-candidate/v1",
    authority: "candidate",
    qualified: false,
    source_revision: null,
    source_manifest_sha256: null,
    duration_ms: 0,
    blockers: ["observe-uncertainty"],
    checks: {
      platform: "fail",
      root: "fail",
      source: "fail",
      kvm: "unknown",
      artifact_cache: "unknown",
      rootfs_candidates: "unknown",
      runtime_assets: "unknown",
      host_tools: "unknown",
      cleanup: "unknown",
      residue: "unknown",
    },
    rootfs: null,
    rootfs_builds: {
      first: { outcome: "blocked", work_outcome: "blocked", total_elapsed_ms: 0 },
      second: { outcome: "blocked", work_outcome: "blocked", total_elapsed_ms: 0 },
    },
    recovery_attempts: [],
    runtime_assets: [],
    host_tools: [],
    kvm: { device_present: false, device_accessible: false, api_version: null },
    claims: { runtime: false, network: false, ssh: false, coordinator_invoked: false },
    diagnostic_codes: [],
  };
  assert.equal(validateV1(v1), true, ajv.errorsText(validateV1.errors));
});

test("candidate output schema enforces metadata-only non-authority", async () => {
  const schema = JSON.parse(await readFile(schemaV2Path, "utf8"));
  const historical = await readFile(historicalReportPath);
  assert.equal(historical.byteLength, 3255);
  assert.equal(
    createHash("sha256").update(historical).digest("hex"),
    "d54c4c08dc3388f7d25426cc3294fed483f8c14438d1daa942053f26816f637e",
  );
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  assert.equal(validate(JSON.parse(historical.toString("utf8"))), false);
  const report = {
    version: "cogs.stage2-phase-a-candidate/v2",
    authority: "candidate",
    qualified: false,
    source_revision: "a".repeat(40),
    source_manifest_sha256: "b".repeat(64),
    duration_ms: 1,
    blockers: ["runtime-extraction-unsafe-or-unknown"],
    checks: {
      platform: "pass",
      root: "pass",
      source: "pass",
      kvm: "pass",
      artifact_cache: "pass",
      rootfs_candidates: "pass",
      runtime_assets: "fail",
      host_tools: "blocked",
      cleanup: "pass",
      residue: "pass",
    },
    rootfs: {
      candidate_count: 2,
      cache_count: 16,
      entry_count: 4353,
      manifest_size: 1049443,
      manifest_sha256: "8783c292f232842a3d1d2d35e7ac2268d591fa6e947d3984868fe33ca006e691",
      ustar_size: 136905728,
      ustar_sha256: "47b0ab5752ae50da6bc9840345aa9ba6285bde3e5ae186c0c548acbaa83768d3",
      equal: true,
      pins_match: true,
    },
    rootfs_phases: [
      "first-build-work",
      "first-inline-cleanup",
      "second-build-work",
      "second-inline-cleanup",
      "recovery-attempt-1",
      "equality",
      "pin",
      "post-verification",
      "settlement",
    ].map((phase) => ({
      phase,
      status: "success",
      outcome: "success",
      elapsed_ms: 1,
      structural_counters: {
        record_reference_copies: 0,
        byte_names_returned: 1,
        parent_snapshots: 2,
        complete_legal_record_folds: 3,
        complete_filesystem_walks: 4,
        incrementally_advanced_ledger_records: 5,
      },
    })),
    stage_evidence: {
      artifact_cache: { status: "success", elapsed_ms: 1 },
      runtime_assets: { status: "failure", elapsed_ms: 1 },
    },
    first_build_setup: "complete",
    runtime_assets: [],
    host_tools: [],
    kvm: { device_present: true, device_accessible: true, api_version: 12 },
    claims: { runtime: false, network: false, ssh: false, coordinator_invoked: false },
    diagnostic_codes: [],
  };
  assert.equal(validate(report), true, ajv.errorsText(validate.errors));
  type PhaseRow = (typeof report.rootfs_phases)[number];
  const mutableReport = () => JSON.parse(JSON.stringify(report));
  const allNotReached = Array<string>(9).fill("not-reached");
  const firstBuildFailed = [
    "failure",
    "blocked",
    "blocked",
    "blocked",
    "not-reached",
    ...Array<string>(4).fill("blocked"),
  ];
  const observerEndedAfterFirst = ["success", "success", ...Array<string>(7).fill("not-reached")];
  const allSettled = ["success", "success", "success", "success", "not-reached", ...Array<string>(4).fill("success")];
  const stageCases = [
    ["success", "success", "complete", "pass", "pass", allSettled],
    ["success", "failure", "complete", "pass", "fail", allSettled],
    ["success", "blocked", "rootfs-bootstrap", "pass", "blocked", allNotReached],
    ["success", "blocked", "operation-establishment", "pass", "blocked", allNotReached],
    ["success", "blocked", "materializer-dispatch", "pass", "blocked", allNotReached],
    ["success", "blocked", "complete", "pass", "blocked", firstBuildFailed],
    ["success", "not-reached", "complete", "pass", "unknown", observerEndedAfterFirst],
    ["failure", "blocked", "fixed-input", "fail", "blocked", allNotReached],
    ["blocked", "blocked", "not-reached", "blocked", "blocked", allNotReached],
    ["not-reached", "not-reached", "not-reached", "unknown", "unknown", allNotReached],
  ] as const;
  const assetRows = [
    {
      component: "kata",
      release: "3.32.0",
      name: "kata-static-3.32.0-amd64.tar.zst",
      size: 1547940938,
      sha256: "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01",
      downloaded: true,
      extracted: false,
    },
    {
      component: "containerd",
      release: "2.2.1",
      name: "containerd-static-2.2.1-linux-amd64.tar.gz",
      size: 33645699,
      sha256: "af3e82bac6abed58d45956c653244aa2be583359a9753614278ef652012f2883",
      downloaded: true,
      extracted: false,
    },
  ];
  for (const [cache, runtime, setup, cacheCheck, runtimeCheck, statuses] of stageCases) {
    const candidate = mutableReport();
    candidate.stage_evidence = {
      artifact_cache: { status: cache, elapsed_ms: cache === "success" || cache === "failure" ? 1 : 0 },
      runtime_assets: { status: runtime, elapsed_ms: runtime === "success" || runtime === "failure" ? 1 : 0 },
    };
    candidate.first_build_setup = setup;
    candidate.checks.artifact_cache = cacheCheck;
    candidate.checks.runtime_assets = runtimeCheck;
    candidate.rootfs_phases = candidate.rootfs_phases.map((row: PhaseRow, index: number) => {
      const status = statuses[index];
      assert.ok(status);
      return {
        ...row,
        status,
        outcome:
          status === "success"
            ? "success"
            : status === "failure"
              ? "failed"
              : status === "blocked"
                ? "prerequisite-failed"
                : "observer-ended",
        elapsed_ms: status === "success" || status === "failure" ? 1 : 0,
        structural_counters: status === "success" || status === "failure" ? row.structural_counters : null,
      };
    });
    candidate.rootfs = statuses[8] === "success" ? report.rootfs : null;
    (candidate as { runtime_assets: unknown[] }).runtime_assets = runtime === "success" ? assetRows : [];
    assert.equal(validate(candidate), true, `${cache}/${runtime}/${setup}: ${ajv.errorsText(validate.errors)}`);
    if (statuses === allNotReached && cache === "success") {
      const unresolvedRuntime = structuredClone(candidate);
      unresolvedRuntime.stage_evidence.runtime_assets = { status: "not-reached", elapsed_ms: 0 };
      unresolvedRuntime.checks.runtime_assets = "unknown";
      assert.equal(validate(unresolvedRuntime), false, `${setup} accepted unresolved runtime`);
    }
    for (const wrong of ["pass", "fail", "blocked", "unknown"].filter((value) => value !== cacheCheck)) {
      const hostile = structuredClone(candidate);
      hostile.checks.artifact_cache = wrong;
      assert.equal(validate(hostile), false, `cache ${cache} incorrectly mapped to ${wrong}`);
    }
    for (const wrong of ["pass", "fail", "blocked", "unknown"].filter((value) => value !== runtimeCheck)) {
      const hostile = structuredClone(candidate);
      hostile.checks.runtime_assets = wrong;
      assert.equal(validate(hostile), false, `runtime ${runtime} incorrectly mapped to ${wrong}`);
    }
    const allowedSetups = new Set(
      allNotReached === statuses && cache === "success"
        ? ["rootfs-bootstrap", "operation-establishment", "materializer-dispatch"]
        : [setup],
    );
    for (const setupValue of [
      "not-reached",
      "fixed-input",
      "rootfs-bootstrap",
      "operation-establishment",
      "materializer-dispatch",
      "complete",
    ]) {
      const setupCandidate = structuredClone(candidate);
      setupCandidate.first_build_setup = setupValue;
      assert.equal(validate(setupCandidate), allowedSetups.has(setupValue), `${cache}/${runtime}/${setupValue}`);
    }
  }
  const statusCheck = { success: "pass", failure: "fail", blocked: "blocked", "not-reached": "unknown" } as const;
  const allowedRuntime = {
    success: new Set(["success", "failure", "blocked", "not-reached"]),
    failure: new Set(["blocked"]),
    blocked: new Set(["blocked"]),
    "not-reached": new Set(["not-reached"]),
  } as const;
  for (const cache of Object.keys(statusCheck) as Array<keyof typeof statusCheck>) {
    for (const runtime of Object.keys(statusCheck) as Array<keyof typeof statusCheck>) {
      const candidate = mutableReport();
      const statuses =
        cache !== "success"
          ? allNotReached
          : runtime === "not-reached"
            ? observerEndedAfterFirst
            : runtime === "blocked"
              ? firstBuildFailed
              : allSettled;
      candidate.stage_evidence = {
        artifact_cache: { status: cache, elapsed_ms: cache === "success" || cache === "failure" ? 1 : 0 },
        runtime_assets: { status: runtime, elapsed_ms: runtime === "success" || runtime === "failure" ? 1 : 0 },
      };
      candidate.checks.artifact_cache = statusCheck[cache];
      candidate.checks.runtime_assets = statusCheck[runtime];
      candidate.first_build_setup =
        cache === "success"
          ? statuses === allNotReached
            ? "rootfs-bootstrap"
            : "complete"
          : cache === "failure"
            ? "fixed-input"
            : "not-reached";
      candidate.rootfs = statuses === allSettled ? report.rootfs : null;
      candidate.rootfs_phases = candidate.rootfs_phases.map((row: PhaseRow, index: number) => {
        const status = statuses[index];
        assert.ok(status);
        return {
          ...row,
          status,
          outcome:
            status === "success"
              ? "success"
              : status === "failure"
                ? "failed"
                : status === "blocked"
                  ? "prerequisite-failed"
                  : "observer-ended",
          elapsed_ms: status === "success" || status === "failure" ? 1 : 0,
          structural_counters: status === "success" || status === "failure" ? row.structural_counters : null,
        };
      });
      candidate.runtime_assets = runtime === "success" ? assetRows : [];
      assert.equal(validate(candidate), allowedRuntime[cache].has(runtime), `${cache}/${runtime}`);
    }
  }
  const blockedWithAttemptedRootfs = mutableReport();
  blockedWithAttemptedRootfs.stage_evidence = {
    artifact_cache: { status: "blocked", elapsed_ms: 0 },
    runtime_assets: { status: "blocked", elapsed_ms: 0 },
  };
  blockedWithAttemptedRootfs.checks.artifact_cache = "blocked";
  blockedWithAttemptedRootfs.checks.runtime_assets = "blocked";
  blockedWithAttemptedRootfs.first_build_setup = "not-reached";
  blockedWithAttemptedRootfs.rootfs = null;
  assert.equal(validate(blockedWithAttemptedRootfs), false);

  for (const hostile of [
    { ...structuredClone(report), stage_evidence: { artifact_cache: { status: "success", elapsed_ms: 1 } } },
    {
      ...structuredClone(report),
      stage_evidence: { ...report.stage_evidence, runtime_assets: { status: "blocked", elapsed_ms: 1 } },
    },
    { ...structuredClone(report), stage_evidence: { ...report.stage_evidence, unexpected: true } },
    {
      ...structuredClone(report),
      stage_evidence: {
        artifact_cache: { status: "failure", elapsed_ms: 1 },
        runtime_assets: { status: "failure", elapsed_ms: 1 },
      },
      first_build_setup: "fixed-input",
    },
    {
      ...structuredClone(report),
      stage_evidence: {
        artifact_cache: { status: "success", elapsed_ms: 1 },
        runtime_assets: { status: "blocked", elapsed_ms: 0 },
      },
      checks: { ...report.checks, artifact_cache: "fail", runtime_assets: "pass" },
      first_build_setup: "operation-establishment",
    },
    {
      ...structuredClone(report),
      stage_evidence: {
        artifact_cache: { status: "failure", elapsed_ms: 1 },
        runtime_assets: { status: "blocked", elapsed_ms: 0 },
      },
      checks: { ...report.checks, artifact_cache: "fail", runtime_assets: "blocked" },
      first_build_setup: "complete",
    },
    {
      ...structuredClone(report),
      stage_evidence: {
        artifact_cache: { status: "success", elapsed_ms: 1 },
        runtime_assets: { status: "blocked", elapsed_ms: 0 },
      },
      checks: { ...report.checks, artifact_cache: "pass", runtime_assets: "blocked" },
      first_build_setup: "operation-establishment",
      runtime_assets: assetRows,
    },
  ])
    assert.equal(validate(hostile), false);
  const fixture = JSON.parse(await readFile(phaseGraphFixturePath, "utf8")) as {
    version: string;
    valid: Array<{ statuses: string[]; rootfs: boolean }>;
  };
  assert.equal(fixture.version, "cogs.stage2-phase-a-phase-graph-fixtures/v1");
  const validGraphs = new Set(fixture.valid.map((item) => JSON.stringify([item.statuses, item.rootfs])));
  const counters = report.rootfs_phases[0]?.structural_counters;
  assert.ok(counters);
  const allowedOutcomes: Record<string, ReadonlySet<string>> = {
    success: new Set(["success"]),
    failure: new Set(["failed", "cancelled", "deadline", "not-started", "postwork", "over-bound"]),
    blocked: new Set(["prerequisite-failed"]),
    "not-reached": new Set(["observer-ended"]),
  };
  const allOutcomes = new Set(Object.values(allowedOutcomes).flatMap((values) => [...values]));
  const outcomes = Object.fromEntries(
    Object.entries(allowedOutcomes).map(([status, values]) => [status, [...values][0]]),
  ) as Record<string, string>;
  const graphReport = (statuses: string[], hasRootfs: boolean) => {
    const runtimeStatus = hasRootfs
      ? "failure"
      : statuses[0] === "not-reached" || statuses.some((status) => status === "failure" || status === "blocked")
        ? "blocked"
        : "not-reached";
    return {
      ...report,
      rootfs: hasRootfs ? report.rootfs : null,
      stage_evidence: {
        artifact_cache: { status: "success", elapsed_ms: 1 },
        runtime_assets: { status: runtimeStatus, elapsed_ms: hasRootfs ? 1 : 0 },
      },
      first_build_setup: statuses[0] === "not-reached" ? "rootfs-bootstrap" : "complete",
      checks: { ...report.checks, artifact_cache: "pass", runtime_assets: statusCheck[runtimeStatus] },
      rootfs_phases: report.rootfs_phases.map((row, index) => ({
        ...row,
        status: statuses[index],
        outcome: outcomes[statuses[index] ?? ""] ?? "invalid",
        elapsed_ms: statuses[index] === "success" || statuses[index] === "failure" ? 1 : 0,
        structural_counters: statuses[index] === "success" || statuses[index] === "failure" ? counters : null,
      })),
    };
  };
  const resolvedRootfsBlock = graphReport(firstBuildFailed, false);
  for (const [status, elapsed_ms, check] of [
    ["not-reached", 0, "unknown"],
    ["failure", 1, "fail"],
  ] as const) {
    const hostile = structuredClone(resolvedRootfsBlock);
    hostile.stage_evidence.runtime_assets = { status, elapsed_ms };
    hostile.checks.runtime_assets = check;
    assert.equal(validate(hostile), false, `unsettled rootfs accepted runtime ${status}`);
  }
  for (const item of fixture.valid) {
    assert.equal(validate(graphReport(item.statuses, item.rootfs)), true, ajv.errorsText(validate.errors));
    for (const [index, current] of item.statuses.entries()) {
      for (const replacement of ["success", "failure", "blocked", "not-reached"]) {
        if (replacement === current) continue;
        const changed = item.statuses.with(index, replacement);
        const expected = validGraphs.has(JSON.stringify([changed, item.rootfs]));
        assert.equal(validate(graphReport(changed, item.rootfs)), expected, `${changed.join(",")}/${item.rootfs}`);
      }
    }
    assert.equal(validate(graphReport(item.statuses, !item.rootfs)), false);
    for (const [index, status] of item.statuses.entries()) {
      for (const outcome of allOutcomes) {
        const candidate = graphReport(item.statuses, item.rootfs);
        const row = candidate.rootfs_phases[index];
        assert.ok(row);
        candidate.rootfs_phases[index] = { ...row, outcome };
        assert.equal(
          validate(candidate),
          allowedOutcomes[status]?.has(outcome) === true,
          `${status}/${outcome}/${item.statuses.join(",")}`,
        );
      }
    }
  }
  assert.equal(validate({ ...report, qualified: true }), false);
  assert.equal(validate({ ...report, claims: { ...report.claims, runtime: true } }), false);
  const hostilePhases = [
    report.rootfs_phases.slice(0, 8),
    report.rootfs_phases.map((row, index) => (index === 0 ? { ...row, phase: "second-build-work" } : row)),
    report.rootfs_phases.map((row, index) => (index === 0 ? { ...row, status: "failure", outcome: "success" } : row)),
    report.rootfs_phases.map((row, index) =>
      index === 1 ? { ...row, status: "blocked", outcome: "prerequisite-failed", elapsed_ms: 1 } : row,
    ),
    report.rootfs_phases.map((row, index) => (index === 0 ? { ...row, status: "failure", outcome: "deadline" } : row)),
    report.rootfs_phases.map((row, index) => (index === 0 ? { ...row, structural_counters: null } : row)),
    report.rootfs_phases.map((row, index) =>
      index === 1 ? { ...row, status: "blocked", outcome: "prerequisite-failed", elapsed_ms: 0 } : row,
    ),
    report.rootfs_phases.map((row, index) =>
      index === 2
        ? {
            ...row,
            structural_counters: {
              record_reference_copies: 0,
              byte_names_returned: true,
              parent_snapshots: 0,
              complete_legal_record_folds: 0,
              complete_filesystem_walks: 0,
              incrementally_advanced_ledger_records: 0,
            },
          }
        : row,
    ),
  ];
  for (const rootfs_phases of hostilePhases) assert.equal(validate({ ...report, rootfs_phases }), false);
  assert.equal(validate({ ...report, archive_bytes: "forbidden" }), false);

  const [runner, budget] = await Promise.all([readFile(runnerPath, "utf8"), readFile(budgetPath, "utf8")]);
  assert.doesNotMatch(runner, /\b(?:apt-get|apt|dnf|yum|apk|brew|systemctl)\b/u);
  assert.doesNotMatch(runner, /completion_kata_coordinator|extractall|\.extract\(/u);
  assert.doesNotMatch(runner, /subprocess\.run\([^)]*PIPE/su);
  assert.match(
    runner,
    /first_token = _rootfs_call\("rootfs-build-token", lambda: secrets\.token_hex\(32\)\)[\s\S]*second_token = _rootfs_call\("rootfs-build-token", lambda: secrets\.token_hex\(32\)\)[\s\S]*first_token != second_token[\s\S]*first = _candidate_build\(build, approval, control, "first", first_token, phases, setup\)[\s\S]*second = _candidate_build\(build, approval, control, "second", second_token, phases\)/u,
  );
  assert.doesNotMatch(runner, /build\._two_build_outputs/u);
  assert.match(runner, /build\._require_equal_builds\(first, second\)/u);
  assert.match(runner, /type\(token\) is str and HEX\.fullmatch\(token\) is not None/u);
  assert.doesNotMatch(runner, /elapsed_ms >= build\.BUILD_SECONDS \* 1000|time\.monotonic\(\)/u);
  assert.match(runner, /total_elapsed_ns - cleanup_span_ns/u);
  const candidateBuild = runner.slice(
    runner.indexOf("def _candidate_build"),
    runner.indexOf("def _timed_rootfs_phase"),
  );
  const timedCleanup = candidateBuild.slice(candidateBuild.indexOf("def timed_cleanup"));
  assert.match(
    timedCleanup,
    /span_started = time\.monotonic_ns\(\)[\s\S]*ticket = _counter_start\(build, cleanup_name\)[\s\S]*callback\(\*args\)[\s\S]*_counter_read\(ticket\)[\s\S]*span_elapsed = _elapsed_ns\(span_started\)/u,
  );
  assert.match(candidateBuild, /work_counters = _subtract_counters\(work_total, cleanup_counters\)/u);
  assert.match(runner, /all\(subtrahend\[name\] <= minuend\[name\] for name in STRUCTURAL_COUNTERS\)/u);
  assert.doesNotMatch(
    candidateBuild.slice(0, candidateBuild.indexOf("def timed_cleanup")),
    /_counter_start\(build, cleanup_name\)/u,
  );
  assert.match(runner, /ROOTFS_PHASES = \([\s\S]*"settlement"/u);
  assert.match(runner, /_start_phase_structural_counters/u);
  assert.match(runner, /_read_phase_structural_counters/u);
  assert.match(runner, /type\(provider\) is type\(sys\)/u);
  assert.match(runner, /type\(item\) is int and 0 <= item <= 1_000_000_000/u);
  const finalResidue = runner.slice(
    runner.indexOf("def _post_export_residue"),
    runner.indexOf("def _use_runtime_paths", runner.indexOf("def _post_export_residue")),
  );
  for (const path of ["ROOTFS_STATE", "ARTIFACT_ROOT", "ASSETS", "STATE", "ANCHOR", "EXPORT_ROOT"]) {
    assert.match(finalResidue, new RegExp(`\\(${path},`, "u"));
  }
  assert.doesNotMatch(
    finalResidue,
    /os\.(?:unlink|rmdir|mkdir|write)|_cleanup|_write|lexists|_fixed_preflight|_source_approval|_verify_fixed_source/u,
  );
  assert.match(finalResidue, /_held_path_absent/u);
  assert.match(runner, /remaining_ns \/\/ NS_PER_SECOND/u);
  const assetGeneration = runner.slice(runner.indexOf("def _asset_generation"), runner.indexOf("def _same_identity"));
  assert.match(assetGeneration, /F_DUPFD_CLOEXEC[\s\S]*\/proc\/self\/fdinfo\/[{]duplicate[}][\s\S]*mnt_id/u);
  assert.doesNotMatch(assetGeneration, /completion_rootfs_fs|_raw_generation|mount_id=None/u);
  assert.match(runner, /_asset_generation\(descriptor, deadline_ns\) == held/u);
  assert.doesNotMatch(runner, /_asset_generation\(descriptor, deadline_ns, held\["mount_id"\]\)/u);
  assert.doesNotMatch(runner, /outer_deadline_ns \/ 1_000_000_000/u);
  assert.match(runner, /OBSERVE_SECONDS = 3300/u);
  assert.match(runner, /ROOTFS_RECOVERY_ATTEMPTS = 1/u);
  assert.match(runner, /rootfs-recovery-exhausted/u);
  assert.match(runner, /rootfs-foundation-uncertainty/u);
  assert.match(runner, /asset-cleanup-uncertainty/u);
  assert.match(runner, /cache-cleanup-uncertainty/u);
  assert.match(runner, /import completion_rootfs_publish\n/u);
  assert.doesNotMatch(runner, /import completion_rootfs_publication/u);
  assert.match(runner, /ownership\.jsonl/u);
  assert.match(runner, /\.cogs-stage2-phase-a-anchor-v2\.json/u);
  assert.match(runner, /include_size=False, include_nlink=False/u);
  assert.match(runner, /_same_rootfs_lifecycle\(_snapshot_rootfs_lifecycle\(\), rootfs_owned\)/u);
  assert.match(runner, /_same_directory_authority\(os\.fstat\(root\), lifecycle\["root"\]\)/u);
  assert.match(runner, /_verify_fixed_source\(anchor\["source_revision"\], anchor\["source_manifest_sha256"\]\)/u);
  assert.match(runner, /VERSION = "cogs\.stage2-phase-a-candidate\/v2"/u);
  assert.doesNotMatch(runner, /cogs\.stage2-phase-a-candidate\/v1|phase-a-candidate-v1/u);
  assert.match(runner, /authority": "candidate"/u);
  assert.match(runner, /"qualified": False/u);
  assert.doesNotMatch(runner, /COGS_STAGE2_PHASE_A_BUDGET_ANCHOR_NS/u);
  assert.match(
    budget,
    /"cleanup": 5100,[\s\S]*"residue": 5160,[\s\S]*"upload": 5290,[\s\S]*"export-cleanup": 5380,[\s\S]*"post-export-residue-start": 5380,[\s\S]*"post-export-residue": 5400,[\s\S]*"final": 5400/u,
  );
  assert.match(
    budget,
    /RUNTIME_PROFILE = "phase-b-runtime-discovery"[\s\S]*"cleanup": 4980,[\s\S]*"residue": 5040,[\s\S]*"export": 5160,[\s\S]*"upload": 5170,[\s\S]*"export-cleanup": 5260,[\s\S]*"post-export-residue": 5275,[\s\S]*"final": 5280/u,
  );
  assert.match(budget, /Scheduling-only monotonic guards/u);
});

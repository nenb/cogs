import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const root = process.cwd();
const probePath = join(root, "scripts/runner-capability-probe.py");
const schemaPath = join(root, "schemas/runner-capability-probe-v1alpha1.json");
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;

const ok = () => ({ errno: null, state: "ok" });
const unsupported = () => ({ errno: null, state: "unsupported" });
const nullableCase = () => ({
  cleanup: unsupported(),
  filesystem: "unknown",
  initial_mode_0600: null,
  initial_nlink_zero: null,
  linkat_empty_path: unsupported(),
  linked_identity_matches: null,
  open_otmpfile: unsupported(),
  owner_is_probe_identity: null,
});
const opathCase = () => ({
  bind_mount_from_proc_fd: unsupported(),
  bind_target_identity_matches: null,
  cleanup: unsupported(),
  fstat_stable: null,
  open_opath_directory: unsupported(),
});
const mapFilesCase = (proc_mount_created_in: "host" | "parent-userns" | "child-userns") => ({
  all_opened_descriptors_closed: true,
  capability_sets_zero: true,
  executable_mappings_selected: 0,
  first_open_failure: null,
  map_files_opened: 0,
  maps_read: unsupported(),
  proc_mount_created_in,
});
const toolIdentity = (path: string, present = false) => ({
  mode: present ? "0755" : null,
  observation: present ? ok() : unsupported(),
  path,
  present,
  regular_file: present ? true : null,
  root_owned: present ? true : null,
  sha256: present ? "9".repeat(64) : null,
  size: present ? 123_456 : null,
});

function validReport(): Record<string, unknown> {
  return {
    authority: "none",
    cleanup: {
      children_reaped: true,
      descriptors_restored: true,
      mounts_gone: true,
      namespace_handles_retained: false,
      temporary_names_gone: true,
      uncertainty: false,
    },
    descriptors: {
      close_range_high: {
        first: 4096,
        flags: 0,
        invocation: { errno: null, state: "blocked" },
        known_fd_closed: null,
        last: 4096,
        syscall_number_amd64: 436,
      },
      close_range_low: {
        first: 198,
        flags: 0,
        invocation: ok(),
        known_fd_closed: true,
        last: 198,
        syscall_number_amd64: 436,
      },
      exec_cloexec: {
        cloexec_fd_199_closed: true,
        invocation: ok(),
        non_cloexec_fd_198_survived: true,
      },
      inherited_baseline_restored: true,
    },
    envelope: {
      action: "labeled",
      base_sha: "d".repeat(40),
      event: "pull_request",
      event_merge_sha: "e".repeat(40),
      github_sha: "e".repeat(40),
      github_workflow_sha: "f".repeat(40),
      job: "runner-capability-probe",
      pull_request_number: 230,
      repository: "nenb/cogs",
      run_attempt: 1,
      run_id: "0",
      workflow: ".github/workflows/outcome-two-runner-capability.yml",
    },
    kernel: {
      machine: "x86_64",
      release: "6.8.0-test",
      sysname: "Linux",
      uname_status: ok(),
    },
    kvm: {
      api_version: null,
      character_device: null,
      check_extension_user_memory: unsupported(),
      device_present: false,
      get_api_version: unsupported(),
      open_read_write: unsupported(),
      user_memory_extension: null,
    },
    namespaces: {
      combined_user_mount_pid_fork: {
        child_is_namespace_pid_1: null,
        cleanup: unsupported(),
        create: unsupported(),
        proc_mount: unsupported(),
      },
      mount: { create: unsupported(), distinct_from_parent: null },
      network: { create: unsupported(), distinct_from_parent: null },
      pid: {
        child_is_namespace_pid_1: null,
        create: unsupported(),
        nspid_final_component_is_1: null,
      },
      user_direct_root: {
        create: unsupported(),
        gid_map: null,
        gid_map_status: unsupported(),
        setgroups: "absent",
        uid_map: null,
        uid_map_status: unsupported(),
      },
    },
    opath: {
      across_mount_namespace: opathCase(),
      same_mount_namespace: opathCase(),
    },
    outcome: "complete",
    procfs: {
      child_owned_proc_after_cap_drop: mapFilesCase("child-userns"),
      child_owned_proc_before_cap_drop: mapFilesCase("child-userns"),
      child_proc_distinct_from_parent: null,
      child_proc_read_only: null,
      child_proc_view_has_pid_1: null,
      child_userns_parent_proc_after_cap_drop: mapFilesCase("parent-userns"),
      child_userns_parent_proc_before_cap_drop: mapFilesCase("parent-userns"),
      host_runner: mapFilesCase("host"),
      host_sudo_root: mapFilesCase("host"),
      parent_proc_read_only: null,
    },
    qualified: false,
    rlimit_nofile: { hard: 1024, high_fd_4096_possible: false, soft: 1024 },
    runner: {
      environment: "github-hosted",
      image_metadata_status: ok(),
      image_os: "ubuntu24",
      image_version: "20260720.247.2",
      requested_label: "ubuntu-24.04",
      runner_arch: "X64",
    },
    schema: "cogs.runner-capability-probe/v1alpha1",
    seccomp: {
      final_mode: 2,
      initial_mode: 2,
      initial_no_new_privs: 0,
      install_filter: ok(),
      network_syscalls_policy: "fixed-eperm-filter-installed",
      set_no_new_privs: ok(),
    },
    source: {
      checkout_sha: "a".repeat(40),
      driver_sha256: "b".repeat(64),
      pr_head_sha: "a".repeat(40),
      schema_sha256: "c".repeat(64),
      source_head_workflow_blob_sha256: "d".repeat(64),
    },
    sudo: {
      close_from_3: { exit_code: null, fd3_closed: null, fd4_closed: null, invocation: unsupported() },
      close_from_4: { exit_code: null, fd3_preserved: null, fd4_closed: null, invocation: unsupported() },
      executable: toolIdentity("/usr/bin/sudo"),
      noninteractive: unsupported(),
    },
    temporary_files: { private_tmpfs: nullableCase(), runner_temp: nullableCase() },
    tools: {
      gzip: toolIdentity("/usr/bin/gzip"),
      python3: toolIdentity("/usr/bin/python3", true),
      unshare: toolIdentity("/usr/bin/unshare"),
      zstd: toolIdentity("/usr/bin/zstd"),
    },
  };
}

function compileSchema(): { ajv: AjvCore; validate: ValidateFunction } {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  return { ajv, validate: ajv.compile(JSON.parse(readFileSync(schemaPath, "utf8"))) };
}

function assertInvalid(validate: ValidateFunction, candidate: unknown, message: string): void {
  assert.equal(validate(candidate), false, message);
}

function setPath(candidate: Record<string, unknown>, path: string[], value: unknown): void {
  const field = path.at(-1);
  assert.ok(field);
  let cursor = candidate;
  for (const segment of path.slice(0, -1)) cursor = cursor[segment] as Record<string, unknown>;
  cursor[field] = value;
}

function statusSemantics(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Object.keys(value).sort().join(",") !== "errno,state") return false;
  const { errno, state } = value as { errno: number | null; state: string };
  if (state === "ok" || state === "blocked" || state === "mismatch") return errno === null;
  if (state === "unsupported") return errno === null || errno === 38 || errno === 95;
  if (state === "denied") return errno === 1 || errno === 13;
  return state === "error" && Number.isInteger(errno) && errno! >= 1 && errno! <= 4095 && ![1, 13, 38, 95].includes(errno!);
}

function reportSemantics(candidate: Record<string, unknown>): boolean {
  const cleanup = candidate.cleanup as Record<string, unknown>;
  const source = candidate.source as Record<string, unknown>;
  const envelope = candidate.envelope as Record<string, unknown>;
  const python = (candidate.tools as Record<string, Record<string, unknown>>).python3!;
  const low = (candidate.descriptors as Record<string, Record<string, unknown>>).close_range_low!;
  const exactCleanup =
    ["children_reaped", "descriptors_restored", "mounts_gone", "temporary_names_gone"].every(
      (field) => cleanup[field] === true,
    ) && cleanup.namespace_handles_retained === false && cleanup.uncertainty === false;
  return (
    candidate.outcome === (exactCleanup ? "complete" : "incomplete") &&
    source.pr_head_sha === source.checkout_sha &&
    envelope.github_sha === envelope.event_merge_sha &&
    python.present === true &&
    (python.observation as { state: string }).state === "ok" &&
    ((low.invocation as { state: string }).state !== "ok" || low.known_fd_closed === true)
  );
}

test("runner capability schema is closed, bounded, and permanently non-authoritative", () => {
  const { ajv, validate } = compileSchema();
  const report = validReport();
  assert.equal(validate(report), true, ajv.errorsText(validate.errors));

  for (const [field, value] of [
    ["authority", "attestation"],
    ["qualified", true],
    ["schema", "cogs.runner-capability-probe/v1"],
    ["outcome", "pass"],
  ] as const) {
    assertInvalid(validate, { ...structuredClone(report), [field]: value }, `${field} must remain fixed`);
  }

  for (const field of ["version_line", "version_output_sha256"]) {
    const versioned = structuredClone(report);
    setPath(versioned, ["tools", "gzip", field], field === "version_line" ? "gzip 1.12" : "f".repeat(64));
    assertInvalid(validate, versioned, `${field} was removed from ToolIdentity`);
  }

  const objectPaths: Array<Array<string | number>> = [];
  const visit = (value: unknown, path: Array<string | number>): void => {
    if (value === null || typeof value !== "object") return;
    if (!Array.isArray(value)) objectPaths.push(path);
    for (const [key, child] of Object.entries(value)) visit(child, [...path, key]);
  };
  visit(report, []);
  for (const path of objectPaths) {
    const candidate = structuredClone(report);
    let cursor = candidate as Record<string, unknown>;
    for (const segment of path) cursor = cursor[segment] as Record<string, unknown>;
    cursor.raw_stderr_or_attestation = "forbidden";
    assertInvalid(validate, candidate, `object at ${path.join(".") || "<root>"} was not closed`);
  }

  const mutations: Array<[string, string[], unknown]> = [
    ["noncanonical run ID", ["envelope", "run_id"], "01"],
    ["run attempt bound", ["envelope", "run_attempt"], 256],
    ["lowercase source hashes", ["source", "pr_head_sha"], "A".repeat(40)],
    ["lowercase envelope hashes", ["envelope", "github_sha"], "A".repeat(40)],
    ["printable kernel release", ["kernel", "release"], "bad\nrelease"],
    ["kernel release byte bound", ["kernel", "release"], "x".repeat(129)],
    ["rlimit bound", ["rlimit_nofile", "hard"], 1e20],
    ["fixed syscall number", ["descriptors", "close_range_low", "syscall_number_amd64"], 435],
    ["uint32 maps", ["namespaces", "user_direct_root", "uid_map"], [[0, 0, 4294967296]]],
    ["five map rows", ["namespaces", "user_direct_root", "uid_map"], Array(6).fill([0, 0, 1])],
    ["map triple shape", ["namespaces", "user_direct_root", "uid_map"], [[0, 0]]],
    ["selected mappings bound", ["procfs", "host_runner", "executable_mappings_selected"], 9],
    ["tool byte bound", ["tools", "gzip", "size"], 134217729],
    ["tool path substitution", ["tools", "gzip", "path"], "/bin/gzip"],
    ["mode canonicality", ["tools", "gzip", "mode"], "600"],
    ["KVM extension bound", ["kvm", "user_memory_extension"], 2147483648],
    ["retained namespace authority", ["cleanup", "namespace_handles_retained"], true],
  ];
  for (const [name, path, value] of mutations) {
    const candidate = structuredClone(report);
    setPath(candidate, path, value);
    assertInvalid(validate, candidate, name);
  }

  const statusCases: Array<[unknown, boolean]> = [
    [{ errno: null, state: "ok" }, true],
    [{ errno: 38, state: "unsupported" }, true],
    [{ errno: 95, state: "unsupported" }, true],
    [{ errno: null, state: "unsupported" }, true],
    [{ errno: 1, state: "denied" }, true],
    [{ errno: 13, state: "denied" }, true],
    [{ errno: null, state: "blocked" }, true],
    [{ errno: null, state: "mismatch" }, true],
    [{ errno: 22, state: "error" }, true],
    [{ errno: 1, state: "ok" }, false],
    [{ errno: 2, state: "denied" }, false],
    [{ errno: 22, state: "unsupported" }, false],
    [{ errno: 1, state: "error" }, false],
    [{ errno: 4096, state: "error" }, false],
    [{ errno: null, state: "error" }, false],
    [{ errno: 22, state: "unknown" }, false],
    [{ errno: null, state: "ok", detail: "raw failure text" }, false],
  ];
  for (const [status, expected] of statusCases) {
    const candidate = structuredClone(report);
    setPath(candidate, ["kernel", "uname_status"], status);
    assert.equal(validate(candidate), expected, `ProbeStatus schema accepted invalid semantics: ${JSON.stringify(status)}`);
    assert.equal(statusSemantics(status), expected, `independent status semantics disagreed: ${JSON.stringify(status)}`);
  }

  assert.equal(reportSemantics(report), true);
  for (const [path, value] of [
    [["outcome"], "incomplete"],
    [["cleanup", "uncertainty"], true],
    [["source", "checkout_sha"], "7".repeat(40)],
    [["envelope", "event_merge_sha"], "8".repeat(40)],
    [["tools", "python3", "present"], false],
    [["descriptors", "close_range_low", "known_fd_closed"], false],
  ] as Array<[string[], unknown]>) {
    const candidate = structuredClone(report);
    setPath(candidate, path, value);
    assert.equal(reportSemantics(candidate), false, `independent semantics accepted ${path.join(".")}`);
  }
});

test("runner capability probe source keeps the metadata-only execution boundary", () => {
  const source = readFileSync(probePath, "utf8");
  assert.match(source, /cogs\.runner-capability-probe\/v1alpha1/u);
  assert.match(source, /["']authority["']\s*:\s*["']none["']/u);
  assert.match(source, /["']qualified["']\s*:\s*False/u);
  for (const executable of ["python3", "sudo", "unshare", "gzip", "zstd"]) {
    assert.match(source, new RegExp(`/usr/bin/${executable}`, "u"));
  }
  assert.doesNotMatch(source, /https?:\/\//u);
  assert.doesNotMatch(source, /GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN/u);
  assert.doesNotMatch(source, /\/bin\/(?:ba)?sh|shell\s*=\s*True|os\.system\s*\(/u);
  assert.doesNotMatch(source, /\b(?:curl|wget|git|ssh|scp|docker|podman|containerd|qemu|terraform|tofu)\b/u);
  assert.doesNotMatch(source, /\b(?:apt|apt-get|dnf|yum|apk|brew|snap|dpkg)\b/u);
  assert.doesNotMatch(source, /socket\.socket\s*\(|urllib|requests|http\.client|ftplib/u);
  assert.doesNotMatch(source, /rm\s+-rf|MNT_DETACH|killall|pkill/u);
  assert.match(source, /--workflow-bound/u);
  assert.doesNotMatch(source, /\b__file__\b/u, "root and namespace helpers must not reopen the checkout driver");
  assert.doesNotMatch(source, /version_line|version_output_sha256|["']--version["']/u);
  assert.doesNotMatch(
    source,
    /except (?:BaseException|\(Exception, KeyboardInterrupt\)):[\s\S]{0,400}(?:fake_report|report\s*=|output\s*=\s*canonical_bytes)/u,
    "an exception must not fabricate or emit a report",
  );
});

test("runner capability probe exposes only bounded self-test and workflow modes", () => {
  const run = (argv: string[]) =>
    spawnSync("/usr/bin/python3", ["-I", "-B", probePath, ...argv], {
      cwd: root,
      env: { LC_ALL: "C", PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 30_000,
    });
  const selfTest = run(["--self-test"]);
  assert.equal(selfTest.status, 0, `${selfTest.stdout}\n${selfTest.stderr}`);
  assert.equal(selfTest.stderr, "");
  assert.ok(Buffer.byteLength(selfTest.stdout) <= 4096);

  assert.match(readFileSync(probePath, "utf8"), /(?:arguments|argv) (?:==|!=) \["--workflow-bound"\]/u);
  for (const argv of [[], ["unknown-mode"], ["--workflow-bound", "extra"], ["--workflow-bound"]]) {
    const rejected = run(argv);
    assert.notEqual(rejected.status, 0, `${argv.join(" ") || "default"} invalid invocation was accepted`);
    assert.equal(rejected.stdout, "", "invalid invocations must not fabricate an exception report");
  }
});

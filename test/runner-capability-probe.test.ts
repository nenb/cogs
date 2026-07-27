// biome-ignore-all lint/suspicious/noExplicitAny: hostile JSON mutations intentionally use dynamic records.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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

type JsonObject = Record<string, any>;
type ProbeStatus = { blocked_by: string | null; errno: number | null; state: string };
const ok = (): ProbeStatus => ({ blocked_by: null, errno: null, state: "ok" });
const denied = (): ProbeStatus => ({ blocked_by: null, errno: 1, state: "denied" });
const unsupported = (): ProbeStatus => ({ blocked_by: null, errno: null, state: "unsupported" });
const blocked = (blockedBy: string): ProbeStatus => ({
  blocked_by: blockedBy,
  errno: null,
  state: "blocked",
});

const toolIdentity = (path: string, present = true): JsonObject => ({
  mode: present ? "0755" : null,
  observation: present ? ok() : unsupported(),
  path,
  present,
  regular_file: present ? true : null,
  root_owned: present ? true : null,
  sha256: present ? "9".repeat(64) : null,
  size: present ? 123_456 : null,
});

const mapFilesCase = (
  procMountCreatedIn: "host" | "parent-userns" | "child-userns",
  capabilitySetsZero: boolean,
): JsonObject => ({
  all_opened_descriptors_closed: true,
  capability_sets_zero: capabilitySetsZero,
  executable_mappings_selected: 1,
  first_open_failure: null,
  map_files_opened: 1,
  maps_read: ok(),
  proc_mount_created_in: procMountCreatedIn,
  setup: ok(),
});

const tmpfileCase = (): JsonObject => ({
  cleanup: ok(),
  filesystem: "tmpfs",
  initial_mode_0600: true,
  initial_nlink_zero: true,
  linkat_empty_path: ok(),
  linked_identity_matches: true,
  open_otmpfile: ok(),
  owner_is_probe_identity: true,
});

const opathCase = (): JsonObject => ({
  bind_mount_from_proc_fd: ok(),
  bind_target_identity_matches: true,
  cleanup: ok(),
  fstat_stable: true,
  open_opath_directory: ok(),
});

function validReport(): JsonObject {
  const closeRange = (target: number): JsonObject => ({
    first: target,
    flags: 0,
    invocation: ok(),
    known_fd_closed: true,
    last: target,
    syscall_number_amd64: 436,
  });
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
      close_range_high: closeRange(4096),
      close_range_low: closeRange(198),
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
      github_sha: "7".repeat(40),
      github_workflow_sha: "f".repeat(40),
      job: "runner-capability-probe",
      pull_request_number: 230,
      repository: "nenb/cogs",
      run_attempt: 1,
      run_id: "1",
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
      check_extension_user_memory: blocked("kvm.open_read_write"),
      device_present: false,
      get_api_version: blocked("kvm.open_read_write"),
      open_read_write: unsupported(),
      user_memory_extension: null,
    },
    namespaces: {
      combined_user_mount_pid_fork: {
        child_is_namespace_pid_1: true,
        cleanup: ok(),
        create: ok(),
        proc_mount: ok(),
      },
      mount: { create: ok(), distinct_from_parent: true },
      network: { create: ok(), distinct_from_parent: true },
      pid: {
        child_is_namespace_pid_1: true,
        create: ok(),
        nspid_final_component_is_1: true,
      },
      user_direct_root: {
        create: ok(),
        exact_root_mapping: true,
        gid_map_status: ok(),
        setgroups: "deny",
        uid_map_status: ok(),
      },
    },
    opath: {
      across_mount_namespace: opathCase(),
      same_mount_namespace: opathCase(),
    },
    outcome: "complete",
    procfs: {
      child_owned_proc_after_cap_drop: mapFilesCase("child-userns", true),
      child_owned_proc_before_cap_drop: mapFilesCase("child-userns", false),
      child_proc_distinct_from_parent: true,
      child_proc_distinct_from_parent_status: ok(),
      child_proc_read_only: true,
      child_proc_view_has_pid_1: true,
      child_userns_parent_proc_after_cap_drop: mapFilesCase("parent-userns", true),
      child_userns_parent_proc_before_cap_drop: mapFilesCase("parent-userns", false),
      host_runner: mapFilesCase("host", false),
      host_sudo_root: mapFilesCase("host", false),
      parent_proc_read_only: false,
    },
    qualified: false,
    rlimit_nofile: { hard: 8192, high_fd_4096_possible: true, high_fd_4096_status: ok(), soft: 1024 },
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
      initial_mode_status: ok(),
      initial_no_new_privs: 0,
      initial_no_new_privs_status: ok(),
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
      close_from_3: {
        exit_code: 40,
        fd3_closed: true,
        fd4_closed: true,
        invocation: ok(),
      },
      close_from_4: {
        exit_code: 41,
        fd3_preserved: true,
        fd4_closed: true,
        invocation: ok(),
      },
      executable: toolIdentity("/usr/bin/sudo"),
      noninteractive: ok(),
    },
    temporary_files: { private_tmpfs: tmpfileCase(), runner_temp: tmpfileCase() },
    tools: {
      gzip: toolIdentity("/usr/bin/gzip"),
      python3: toolIdentity("/usr/bin/python3"),
      unshare: toolIdentity("/usr/bin/unshare"),
      zstd: toolIdentity("/usr/bin/zstd"),
    },
  };
}

function mixedReport(): JsonObject {
  const report = validReport();
  report.tools.gzip = toolIdentity("/usr/bin/gzip", false);
  report.sudo.noninteractive = denied();
  report.sudo.close_from_3 = {
    exit_code: null,
    fd3_closed: null,
    fd4_closed: null,
    invocation: blocked("sudo.noninteractive"),
  };
  report.sudo.close_from_4 = {
    exit_code: null,
    fd3_preserved: null,
    fd4_closed: null,
    invocation: blocked("sudo.noninteractive"),
  };
  report.procfs.host_sudo_root = {
    ...mapFilesCase("host", false),
    executable_mappings_selected: 0,
    map_files_opened: 0,
    maps_read: blocked("procfs.host_sudo_root.setup"),
    setup: blocked("sudo.noninteractive"),
  };
  return report;
}

function compileSchema(): { ajv: AjvCore; validate: ValidateFunction } {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  return { ajv, validate: ajv.compile(JSON.parse(readFileSync(schemaPath, "utf8"))) };
}

function valueAt(candidate: JsonObject, path: string): unknown {
  return path.split(".").reduce((value: any, segment) => value?.[segment], candidate);
}

function setPath(candidate: JsonObject, path: string, value: unknown): void {
  const segments = path.split(".");
  const field = segments.pop();
  assert.ok(field);
  const parent = segments.reduce((value: any, segment) => value[segment], candidate);
  parent[field] = value;
}

function assertInvalid(validate: ValidateFunction, candidate: unknown, message: string): void {
  assert.equal(validate(candidate), false, message);
}

function statusSemantics(value: unknown, report?: JsonObject, path?: string): boolean {
  if (value === null || typeof value !== "object" || Object.keys(value).sort().join(",") !== "blocked_by,errno,state")
    return false;
  const { blocked_by: blockedBy, errno, state } = value as ProbeStatus;
  if (state === "blocked") {
    const prerequisite = typeof blockedBy === "string" && report ? valueAt(report, blockedBy) : null;
    return (
      errno === null &&
      typeof blockedBy === "string" &&
      prerequisite !== null &&
      typeof prerequisite === "object" &&
      (prerequisite as ProbeStatus).state !== "ok" &&
      statusSemantics(prerequisite, report, blockedBy)
    );
  }
  if (blockedBy !== null) return false;
  if (state === "ok" || state === "mismatch") return errno === null;
  if (state === "unsupported") {
    if (errno === 38 || errno === 95) return true;
    if (errno !== null || !report || !path) return false;
    if (path === "kvm.open_read_write") return report.kvm.device_present === false;
    if (/^(?:sudo\.executable|tools\.[^.]+)\.observation$/u.test(path)) {
      const identityPath = path.slice(0, -".observation".length);
      return (valueAt(report, identityPath) as JsonObject).present === false;
    }
    return false;
  }
  if (state === "denied") return errno === 1 || errno === 13;
  return (
    state === "error" &&
    typeof errno === "number" &&
    Number.isInteger(errno) &&
    errno >= 1 &&
    errno <= 4095 &&
    ![1, 13, 38, 95].includes(errno)
  );
}

function semanticAssert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function booleanObservation(operation: ProbeStatus, fields: unknown[]): void {
  const observed = fields.every((field) => typeof field === "boolean");
  if (operation.state === "ok")
    semanticAssert(
      fields.every((field) => field === true),
      "false ok result",
    );
  else if (operation.state === "mismatch")
    semanticAssert(observed && fields.some((field) => field === false), "mismatch without false result");
  else
    semanticAssert(
      fields.every((field) => field === null),
      "unattempted result disclosed",
    );
}

function valueObservation(operation: ProbeStatus, value: unknown): void {
  if (operation.state === "ok") semanticAssert(value !== null, "ok value absent");
  else if (operation.state !== "mismatch") semanticAssert(value === null, "unobserved value disclosed");
}

function independentSemantics(report: JsonObject): boolean {
  try {
    const visit = (value: unknown, path = ""): void => {
      if (value === null || typeof value !== "object") return;
      if (Object.keys(value).sort().join(",") === "blocked_by,errno,state") {
        semanticAssert(statusSemantics(value, report, path), `invalid status at ${path}`);
        return;
      }
      for (const [key, child] of Object.entries(value)) visit(child, path ? `${path}.${key}` : key);
    };
    visit(report);

    semanticAssert(report.authority === "none" && report.qualified === false, "authority expansion");
    semanticAssert(report.source.pr_head_sha === report.source.checkout_sha, "checkout/source mismatch");
    semanticAssert(
      report.envelope.run_attempt === 1 &&
        Number.isInteger(report.envelope.pull_request_number) &&
        report.envelope.pull_request_number >= 1 &&
        report.envelope.pull_request_number <= 2_147_483_647,
      "envelope numeric domain",
    );
    if (report.runner.image_metadata_status.state === "ok")
      semanticAssert(report.runner.image_os !== null && report.runner.image_version !== null, "runner metadata absent");
    else
      semanticAssert(
        report.runner.image_os === null && report.runner.image_version === null,
        "runner metadata fabricated",
      );
    if (report.kernel.uname_status.state === "ok")
      semanticAssert(report.kernel.sysname === "Linux" && report.kernel.machine === "x86_64", "kernel mismatch hidden");
    const hard = report.rlimit_nofile.hard;
    const highFdPossible = hard === "infinity" || hard >= 4097;
    semanticAssert(report.rlimit_nofile.high_fd_4096_possible === highFdPossible, "hard-limit derivation");
    booleanObservation(report.rlimit_nofile.high_fd_4096_status, [highFdPossible]);

    for (const identity of [report.sudo.executable, ...Object.values(report.tools)] as JsonObject[]) {
      const metadata = [identity.regular_file, identity.root_owned, identity.mode, identity.size, identity.sha256];
      if (identity.observation.state === "ok") {
        semanticAssert(identity.present && identity.regular_file && identity.root_owned, "bad tool policy");
        semanticAssert((Number.parseInt(identity.mode, 8) & 0o22) === 0, "writable tool generation");
        semanticAssert(
          metadata.every((field) => field !== null),
          "missing tool metadata",
        );
      } else if (identity.observation.state === "unsupported" && identity.observation.errno === null) {
        semanticAssert(!identity.present && metadata.every((field) => field === null), "fake absent tool");
      }
    }
    semanticAssert(report.tools.python3.observation.state === "ok", "Python bootstrap not authenticated");

    const sudo3 = report.sudo.close_from_3;
    const sudo4 = report.sudo.close_from_4;
    booleanObservation(sudo3.invocation, [sudo3.fd3_closed, sudo3.fd4_closed]);
    booleanObservation(sudo4.invocation, [sudo4.fd3_preserved, sudo4.fd4_closed]);
    if (sudo3.invocation.state === "ok") semanticAssert(sudo3.exit_code === 40, "sudo close-from-3 exit");
    else if (!["mismatch"].includes(sudo3.invocation.state))
      semanticAssert(sudo3.exit_code === null, "sudo3 exit disclosed");
    if (sudo4.invocation.state === "ok") semanticAssert(sudo4.exit_code === 41, "sudo close-from-4 exit");
    else if (!["mismatch"].includes(sudo4.invocation.state))
      semanticAssert(sudo4.exit_code === null, "sudo4 exit disclosed");

    for (const name of ["close_range_low", "close_range_high"]) {
      const operation = report.descriptors[name];
      booleanObservation(operation.invocation, [operation.known_fd_closed]);
    }
    const exec = report.descriptors.exec_cloexec;
    booleanObservation(exec.invocation, [exec.non_cloexec_fd_198_survived, exec.cloexec_fd_199_closed]);

    for (const name of ["network", "mount"]) {
      const operation = report.namespaces[name];
      booleanObservation(operation.create, [operation.distinct_from_parent]);
    }
    const pid = report.namespaces.pid;
    booleanObservation(pid.create, [pid.child_is_namespace_pid_1, pid.nspid_final_component_is_1]);
    const user = report.namespaces.user_direct_root;
    if (user.uid_map_status.state === "ok" && user.gid_map_status.state === "ok")
      semanticAssert(user.create.state === "ok" && user.exact_root_mapping === true, "root map not exact");
    else if ([user.uid_map_status.state, user.gid_map_status.state].includes("mismatch"))
      semanticAssert(user.exact_root_mapping === false, "map mismatch hidden");
    else semanticAssert(user.exact_root_mapping === null, "unobserved root map disclosed");
    const combined = report.namespaces.combined_user_mount_pid_fork;
    booleanObservation(combined.create, [combined.child_is_namespace_pid_1]);
    if (combined.proc_mount.state === "blocked")
      semanticAssert(combined.create.state !== "ok", "unnamed proc prerequisite");

    const mapLocations = {
      child_owned_proc_after_cap_drop: "child-userns",
      child_owned_proc_before_cap_drop: "child-userns",
      child_userns_parent_proc_after_cap_drop: "parent-userns",
      child_userns_parent_proc_before_cap_drop: "parent-userns",
      host_runner: "host",
      host_sudo_root: "host",
    } as const;
    for (const [name, expectedMount] of Object.entries(mapLocations)) {
      const mapCase = report.procfs[name];
      semanticAssert(mapCase.proc_mount_created_in === expectedMount, "proc ownership category mismatch");
      const selected = mapCase.executable_mappings_selected;
      const opened = mapCase.map_files_opened;
      if (mapCase.maps_read.state === "ok") {
        semanticAssert(mapCase.setup.state === "ok", "maps read without setup");
        semanticAssert(opened <= selected, "opened unselected map");
        semanticAssert((opened === selected) === (mapCase.first_open_failure === null), "map failure/count mismatch");
        if (mapCase.first_open_failure !== null)
          semanticAssert(
            statusSemantics(mapCase.first_open_failure, report) &&
              !["ok", "blocked", "mismatch"].includes(mapCase.first_open_failure.state),
            "invalid first map failure",
          );
      } else {
        semanticAssert(selected === 0 && opened === 0 && mapCase.first_open_failure === null, "unread maps counted");
      }
      if (mapCase.setup.state !== "ok")
        semanticAssert(
          mapCase.maps_read.state === "blocked" && mapCase.maps_read.blocked_by?.endsWith(".setup"),
          "map setup failure copied downstream",
        );
    }
    semanticAssert(report.procfs.child_userns_parent_proc_after_cap_drop.capability_sets_zero, "user caps retained");
    semanticAssert(report.procfs.child_owned_proc_after_cap_drop.capability_sets_zero, "child caps retained");
    valueObservation(
      report.procfs.child_proc_distinct_from_parent_status,
      report.procfs.child_proc_distinct_from_parent,
    );
    if (combined.proc_mount.state === "ok") {
      semanticAssert(
        typeof report.procfs.child_proc_read_only === "boolean" &&
          report.procfs.child_proc_view_has_pid_1 === combined.child_is_namespace_pid_1,
        "combined proc postcondition absent",
      );
    } else {
      semanticAssert(
        report.procfs.child_proc_read_only === null && report.procfs.child_proc_view_has_pid_1 === null,
        "blocked proc postcondition disclosed",
      );
    }

    const seccomp = report.seccomp;
    valueObservation(seccomp.initial_mode_status, seccomp.initial_mode);
    valueObservation(seccomp.initial_no_new_privs_status, seccomp.initial_no_new_privs);
    if (seccomp.install_filter.state === "ok")
      semanticAssert(
        seccomp.set_no_new_privs.state === "ok" &&
          seccomp.final_mode === 2 &&
          seccomp.network_syscalls_policy === "fixed-eperm-filter-installed",
        "seccomp success without prerequisites",
      );
    else semanticAssert(seccomp.network_syscalls_policy === "filter-unavailable", "false seccomp policy");
    if (seccomp.install_filter.state === "blocked")
      semanticAssert(seccomp.set_no_new_privs.state !== "ok", "unnamed filter prerequisite");

    const kvm = report.kvm;
    if (!kvm.device_present) semanticAssert(kvm.character_device === null, "absent KVM metadata");
    if (kvm.open_read_write.state === "ok")
      semanticAssert(kvm.device_present && kvm.character_device === true, "KVM open without device");
    valueObservation(kvm.get_api_version, kvm.api_version);
    valueObservation(kvm.check_extension_user_memory, kvm.user_memory_extension);
    if (kvm.open_read_write.state !== "ok")
      semanticAssert(
        kvm.get_api_version.state === "blocked" && kvm.check_extension_user_memory.state === "blocked",
        "KVM ioctl attempted without fd",
      );

    for (const tmp of Object.values(report.temporary_files) as JsonObject[]) {
      booleanObservation(tmp.open_otmpfile, [
        tmp.initial_nlink_zero,
        tmp.owner_is_probe_identity,
        tmp.initial_mode_0600,
      ]);
      booleanObservation(tmp.linkat_empty_path, [tmp.linked_identity_matches]);
    }
    for (const opath of Object.values(report.opath) as JsonObject[]) {
      booleanObservation(opath.open_opath_directory, [opath.fstat_stable]);
      booleanObservation(opath.bind_mount_from_proc_fd, [opath.bind_target_identity_matches]);
    }

    const cleanupStatuses = [
      ...Object.values(report.temporary_files).map((value: any) => value.cleanup),
      ...Object.values(report.opath).map((value: any) => value.cleanup),
      combined.cleanup,
    ];
    const cleanup = report.cleanup;
    const exactCleanup =
      cleanup.children_reaped === true &&
      cleanup.descriptors_restored === true &&
      cleanup.mounts_gone === true &&
      cleanup.namespace_handles_retained === false &&
      cleanup.temporary_names_gone === true &&
      cleanup.uncertainty === false &&
      report.descriptors.inherited_baseline_restored === true &&
      cleanupStatuses.every((status: ProbeStatus) => status.state === "ok") &&
      Object.values(report.procfs)
        .filter((value: any) => value && typeof value === "object" && "maps_read" in value)
        .every((value: any) => value.all_opened_descriptors_closed === true);
    semanticAssert(report.outcome === (exactCleanup ? "complete" : "incomplete"), "cleanup/outcome mismatch");
    return true;
  } catch {
    return false;
  }
}

function mutated(report: JsonObject, path: string, value: unknown): JsonObject {
  const candidate = structuredClone(report);
  setPath(candidate, path, value);
  return candidate;
}

test("runner capability schema is closed, bounded, redacted, and keeps envelope identities separate", () => {
  const { ajv, validate } = compileSchema();
  const report = validReport();
  assert.equal(validate(report), true, ajv.errorsText(validate.errors));
  assert.equal(independentSemantics(report), true);
  const mixed = mixedReport();
  assert.equal(validate(mixed), true, ajv.errorsText(validate.errors));
  assert.equal(independentSemantics(mixed), true, "complete unsupported/denied/blocked report rejected");
  assert.notEqual(report.envelope.github_sha, report.envelope.event_merge_sha);

  for (const [field, value] of [
    ["authority", "attestation"],
    ["qualified", true],
    ["schema", "cogs.runner-capability-probe/v1"],
    ["outcome", "pass"],
  ] as const)
    assertInvalid(validate, mutated(report, field, value), `${field} must remain fixed`);

  for (const [path, value] of [
    ["envelope.run_id", "0"],
    ["envelope.run_id", "01"],
    ["envelope.run_attempt", 256],
    ["envelope.pull_request_number", 10_000_000_000],
    ["source.pr_head_sha", "A".repeat(40)],
    ["kernel.release", "bad\nrelease"],
    ["kernel.release", "x".repeat(129)],
    ["rlimit_nofile.hard", 1e20],
    ["descriptors.close_range_low.syscall_number_amd64", 435],
    ["procfs.host_runner.executable_mappings_selected", 9],
    ["tools.gzip.size", 134_217_729],
    ["tools.gzip.path", "/bin/gzip"],
    ["tools.gzip.mode", "600"],
    ["kvm.user_memory_extension", 2_147_483_648],
    ["cleanup.namespace_handles_retained", true],
  ] as Array<[string, unknown]>)
    assertInvalid(validate, mutated(report, path, value), path);

  for (const field of ["uid_map", "gid_map"])
    assertInvalid(
      validate,
      mutated(report, `namespaces.user_direct_root.${field}`, [[0, 1000, 1]]),
      `numeric ${field} disclosure was accepted`,
    );
  for (const field of ["version_line", "version_output_sha256"])
    assertInvalid(validate, mutated(report, `tools.gzip.${field}`, "CANARY"), `${field} was accepted`);

  const objectPaths: string[] = [];
  const visit = (value: unknown, path: string): void => {
    if (value === null || typeof value !== "object") return;
    if (!Array.isArray(value)) objectPaths.push(path);
    for (const [key, child] of Object.entries(value)) visit(child, path ? `${path}.${key}` : key);
  };
  visit(report, "");
  for (const path of objectPaths) {
    const candidate = structuredClone(report);
    const target = path ? (valueAt(candidate, path) as JsonObject) : candidate;
    target.raw_stderr_or_attestation = "DISCLOSURE-CANARY";
    assertInvalid(validate, candidate, `object at ${path || "<root>"} was not closed`);
  }

  assert.doesNotMatch(
    JSON.stringify(report),
    /uid_map"|gid_map"|DISCLOSURE-CANARY|GITHUB_TOKEN|https?_proxy|raw_stderr|diagnostic|attestation/u,
  );
});

test("independent semantics reject adjacent status, postcondition, and prerequisite mutations", () => {
  const report = validReport();
  const statusCases: Array<[ProbeStatus, boolean]> = [
    [ok(), true],
    [{ blocked_by: null, errno: 38, state: "unsupported" }, true],
    [{ blocked_by: null, errno: 95, state: "unsupported" }, true],
    [denied(), true],
    [{ blocked_by: null, errno: 13, state: "denied" }, true],
    [{ blocked_by: null, errno: null, state: "mismatch" }, true],
    [{ blocked_by: null, errno: 22, state: "error" }, true],
    [{ blocked_by: null, errno: 1, state: "ok" }, false],
    [{ blocked_by: null, errno: 2, state: "denied" }, false],
    [{ blocked_by: null, errno: 22, state: "unsupported" }, false],
    [{ blocked_by: null, errno: 1, state: "error" }, false],
    [{ blocked_by: null, errno: 4096, state: "error" }, false],
    [{ blocked_by: null, errno: null, state: "error" }, false],
    [{ blocked_by: "tools.python3.observation", errno: null, state: "ok" }, false],
  ];
  for (const [status, expected] of statusCases) assert.equal(statusSemantics(status), expected, JSON.stringify(status));

  const statusPaths: string[] = [];
  const collectStatuses = (value: unknown, path = ""): void => {
    if (value === null || typeof value !== "object") return;
    if (Object.keys(value).sort().join(",") === "blocked_by,errno,state") {
      statusPaths.push(path);
      return;
    }
    for (const [key, child] of Object.entries(value)) collectStatuses(child, path ? `${path}.${key}` : key);
  };
  collectStatuses(report);
  assert.ok(statusPaths.length >= 50, "status inventory unexpectedly shrank");
  for (const path of statusPaths)
    assert.equal(
      independentSemantics(mutated(report, path, { blocked_by: null, errno: 1, state: "ok" })),
      false,
      `invalid local status accepted at ${path}`,
    );

  const mutations: Array<[string, string, unknown]> = [
    ["envelope attempt", "envelope.run_attempt", 2],
    ["envelope PR", "envelope.pull_request_number", 2_147_483_648],
    ["runner", "runner.image_version", null],
    ["kernel", "kernel.machine", "unexpected"],
    ["rlimit", "rlimit_nofile.high_fd_4096_possible", false],
    ["sudo", "sudo.close_from_3.fd3_closed", false],
    ["map files", "procfs.host_runner.map_files_opened", 0],
    ["namespaces", "namespaces.pid.child_is_namespace_pid_1", false],
    ["user map", "namespaces.user_direct_root.exact_root_mapping", false],
    ["proc", "procfs.child_proc_distinct_from_parent", null],
    ["seccomp", "seccomp.network_syscalls_policy", "filter-unavailable"],
    ["seccomp prerequisite", "seccomp.set_no_new_privs", denied()],
    ["KVM", "kvm.api_version", 12],
    ["tools", "tools.gzip.root_owned", false],
    ["cleanup", "cleanup.uncertainty", true],
    ["case cleanup", "temporary_files.runner_temp.cleanup", denied()],
    ["descriptor cleanup", "procfs.host_runner.all_opened_descriptors_closed", false],
  ];
  for (const [family, path, value] of mutations)
    assert.equal(independentSemantics(mutated(report, path, value)), false, `${family}: ${path}`);

  const prerequisiteCases: Array<[string, ProbeStatus, string]> = [
    ["sudo", denied(), "sudo.noninteractive"],
    ["map files", denied(), "procfs.child_userns_parent_proc_before_cap_drop.maps_read"],
    ["namespaces", { blocked_by: null, errno: 38, state: "unsupported" }, "tools.unshare.observation"],
    ["proc", denied(), "namespaces.combined_user_mount_pid_fork.proc_mount"],
    ["seccomp", denied(), "seccomp.set_no_new_privs"],
    ["KVM", unsupported(), "kvm.open_read_write"],
    ["tools", { blocked_by: null, errno: 38, state: "unsupported" }, "tools.python3.observation"],
    ["cleanup", denied(), "temporary_files.runner_temp.linkat_empty_path"],
  ];
  for (const [family, prerequisite, path] of prerequisiteCases) {
    const candidate = structuredClone(report);
    setPath(candidate, path, prerequisite);
    const operation = blocked(path);
    assert.equal(statusSemantics(operation, candidate), true, `${family} blocker rejected`);
    setPath(candidate, path, ok());
    assert.equal(statusSemantics(operation, candidate), false, `${family} blocker accepted an ok prerequisite`);
  }

  const distinctEnvelope = structuredClone(report);
  distinctEnvelope.envelope.github_sha = "1".repeat(40);
  distinctEnvelope.envelope.event_merge_sha = "2".repeat(40);
  distinctEnvelope.envelope.github_workflow_sha = "3".repeat(40);
  assert.equal(independentSemantics(distinctEnvelope), true, "separate envelope identities were equated");
});

test("driver boundary is fixed, redacted, and self-test-only fixtures cannot reach workflow mode", () => {
  const source = readFileSync(probePath, "utf8");
  assert.match(source, /cogs\.runner-capability-probe\/v1alpha1/u);
  assert.match(source, /["']authority["']\s*:\s*["']none["']/u);
  assert.match(source, /["']qualified["']\s*:\s*False/u);
  for (const executable of ["python3", "sudo", "unshare", "gzip", "zstd"])
    assert.match(source, new RegExp(`/usr/bin/${executable}`, "u"));

  assert.doesNotMatch(source, /https?:\/\//u);
  assert.doesNotMatch(source, /GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN/u);
  assert.doesNotMatch(source, /\/bin\/(?:ba)?sh|shell\s*=\s*True|os\.system\s*\(/u);
  assert.doesNotMatch(source, /\b(?:curl|wget|git|ssh|scp|docker|podman|containerd|qemu|terraform|tofu)\b/u);
  assert.doesNotMatch(source, /\b(?:apt|apt-get|dnf|yum|apk|brew|snap|dpkg)\b/u);
  assert.doesNotMatch(source, /socket\.socket\s*\(|urllib|requests|http\.client|ftplib/u);
  assert.doesNotMatch(source, /rm\s+-rf|MNT_DETACH|killall|pkill/u);
  assert.doesNotMatch(source, /version_line|version_output_sha256|["']--version["']/u);
  assert.doesNotMatch(
    source,
    /github_sha\s*(?:==|!=)\s*(?:merge_sha|event_merge_sha)|(?:merge_sha|event_merge_sha)\s*(?:==|!=)\s*github_sha/u,
  );
  assert.match(source, /--self-test/u);
  assert.match(source, /--workflow-bound/u);
  assert.doesNotMatch(
    source,
    /except (?:BaseException|\(Exception, KeyboardInterrupt\)):[\s\S]{0,400}(?:fake_report|report\s*=|output\s*=\s*canonical_bytes)/u,
  );
  const schema = JSON.parse(readFileSync(schemaPath, "utf8")) as JsonObject;
  const allowedBlockers = new Set(schema.$defs.blockedBy.enum as string[]);
  const literalBlockers = [...source.matchAll(/blocked_by\s*=\s*["']([^"']+)["']/gu)].flatMap((match) =>
    match[1] ? [match[1]] : [],
  );
  const blockerTable = source.match(/BLOCKED_BY\s*=\s*frozenset\(\{([\s\S]*?)\}\)/u)?.[1];
  assert.ok(blockerTable, "driver has no closed prerequisite table");
  const tableBlockers = [...blockerTable.matchAll(/["']([^"']+)["']/gu)].flatMap((match) =>
    match[1] ? [match[1]] : [],
  );
  assert.ok(literalBlockers.length > 0 && tableBlockers.length > 0, "driver has no named prerequisite records");
  for (const blocker of [...literalBlockers, ...tableBlockers])
    assert.ok(allowedBlockers.has(blocker), `driver emits prerequisite outside the closed schema: ${blocker}`);
});

function runProbe(argv: string[], optimized = false, extraEnv: NodeJS.ProcessEnv = {}) {
  return spawnSync("/usr/bin/python3", ["-I", "-B", ...(optimized ? ["-O"] : []), probePath, ...argv], {
    cwd: root,
    encoding: "utf8",
    env: { LC_ALL: "C", PYTHONDONTWRITEBYTECODE: "1", ...extraEnv },
    timeout: 30_000,
  });
}

test("self-test exercises the scripted fault matrix with no real effects and canonical disclosure-safe output", () => {
  const canary = "CAPABILITY-DISCLOSURE-CANARY-7f31";
  const environment = {
    GITHUB_TOKEN: canary,
    HOME: `/tmp/${canary}`,
    HTTPS_PROXY: `https://${canary}.invalid`,
    RUNNER_TEMP: `/tmp/${canary}`,
  };
  const first = runProbe(["--self-test"], false, environment);
  const second = runProbe(["--self-test"], false, { ...environment, GITHUB_TOKEN: `${canary}-changed` });
  assert.equal(first.status, 0, `${first.stdout}\n${first.stderr}`);
  assert.equal(first.stderr, "");
  assert.equal(second.status, 0, `${second.stdout}\n${second.stderr}`);
  assert.equal(second.stderr, "");
  assert.equal(first.stdout, second.stdout, "self-test output was not repeatable or read ambient values");
  assert.ok(Buffer.byteLength(first.stdout) <= 4096);
  assert.ok(first.stdout.endsWith("\n"));
  assert.equal(first.stdout.split("\n").length, 2, "self-test must emit exactly one bounded line");
  assert.doesNotMatch(`${first.stdout}${first.stderr}${second.stdout}${second.stderr}`, new RegExp(canary, "u"));
  assert.match(first.stdout, /runner-capability-probe self-test: ok/u);
  assert.match(first.stdout, /acquisition=12/u);
  assert.match(first.stdout, /cleanup=6/u);
  assert.match(first.stdout, /real.effects=0/u);
  assert.match(first.stdout, /repeatability=2/u);
  const summaryText = first.stdout.trimEnd().split(" summary=")[1];
  assert.ok(summaryText, "self-test omitted its scripted matrix summary");
  const summary = JSON.parse(summaryText) as JsonObject;
  assert.deepEqual(summary.acquisition_faults, [
    "acquire.descriptor",
    "after.descriptor",
    "acquire.pipe",
    "after.pipe",
    "acquire.child",
    "after.child",
    "acquire.name",
    "after.name",
    "acquire.mount",
    "after.mount",
    "acquire.limit",
    "after.limit",
  ]);
  assert.deepEqual(summary.cleanup_faults, [
    "cleanup.descriptor",
    "cleanup.pipe",
    "cleanup.child",
    "cleanup.name",
    "cleanup.mount",
    "cleanup.limit",
  ]);
  assert.deepEqual(summary.disclosure_canaries, ["old-id-map-keys", "numeric-id-row", "secret", "child-output"]);
  assert.equal(summary.real_effects, 0);
  assert.equal(summary.repeatability, 2);
  assert.ok(summary.fake_report_bytes > 0 && summary.fake_report_bytes <= 32_768);
  assert.match(summary.fake_report_sha256, /^[0-9a-f]{64}$/u);

  const fakeScript =
    'import runpy,sys\nv=runpy.run_path(sys.argv[1],run_name="capability_fake_module")\nsys.stdout.buffer.write(v["canonical_bytes"](v["fake_report"]()))';
  const fakeRun = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", fakeScript, probePath], {
    cwd: root,
    encoding: null,
    env: { LC_ALL: "C", PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(fakeRun.status, 0, `${fakeRun.stdout.toString()}\n${fakeRun.stderr.toString()}`);
  assert.equal(fakeRun.stderr.length, 0);
  const fakeBytes = Buffer.from(fakeRun.stdout);
  assert.equal(fakeBytes.length, summary.fake_report_bytes);
  assert.equal(fakeBytes.at(-1), 0x0a);
  assert.equal(createHash("sha256").update(fakeBytes).digest("hex"), summary.fake_report_sha256);
  const fakeReport = JSON.parse(fakeBytes.toString("utf8")) as JsonObject;
  const { ajv, validate } = compileSchema();
  assert.equal(validate(fakeReport), true, ajv.errorsText(validate.errors));
  assert.equal(independentSemantics(fakeReport), true, "scripted fake report violates independent semantics");

  const guard = `
import runpy,sys
values=runpy.run_path(sys.argv[1],run_name="capability_test_module")
g=values["self_test"].__globals__
def forbidden(*args,**kwargs): raise AssertionError("real effect from self-test")
class Guard:
 def __init__(self,base,names): self.base,self.names=base,names
 def __getattr__(self,name): return forbidden if name in self.names else getattr(self.base,name)
g["os"]=Guard(g["os"],{"open","fork","pipe","pipe2","execve","kill","killpg","waitpid","unlink","rmdir","mkdir","setuid","setgid","setrlimit"})
g["subprocess"]=Guard(g["subprocess"],{"Popen","run","call","check_call","check_output"})
g["resource"]=Guard(g["resource"],{"setrlimit","prlimit"})
for name in ("MOUNT","UMOUNT2","UNSHARE_CALL","PRCTL","SYSCALL","LINKAT"): g[name]=forbidden
values["self_test"]()
`;
  const guarded = spawnSync("/usr/bin/python3", ["-I", "-B", "-c", guard, probePath], {
    cwd: root,
    encoding: "utf8",
    env: { LC_ALL: "C", PYTHONDONTWRITEBYTECODE: "1" },
    timeout: 30_000,
  });
  assert.equal(guarded.status, 0, `${guarded.stdout}\n${guarded.stderr}`);
  assert.equal(guarded.stderr, "");
  assert.equal(guarded.stdout, first.stdout);
});

test("optimized, default, unknown, and malformed modes are rejected without output", () => {
  for (const [name, result] of [
    ["optimized", runProbe(["--self-test"], true)],
    ["default", runProbe([])],
    ["unknown", runProbe(["unknown-mode"])],
    ["extra", runProbe(["--self-test", "extra"])],
  ] as const) {
    assert.notEqual(result.status, 0, `${name} mode was accepted`);
    assert.equal(result.stdout, "", `${name} mode fabricated output`);
    assert.equal(result.stderr, "", `${name} mode disclosed diagnostics`);
  }
});

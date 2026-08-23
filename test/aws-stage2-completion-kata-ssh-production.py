#!/usr/bin/env python3
"""Optimization-safe hostile checks for corrected ADR0099 B3; no execution."""
import hashlib
import inspect
import json
import os
from pathlib import Path
import platform
import runpy
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))
sys.path.insert(0, str(ROOT / "test"))
from stage2_attested_fixture import SHA256 as SYNTHETIC_ELF_SHA256, ensure_attested_static_fixture
import completion_guest_workloads_v2 as historical_guest
import completion_guest_workloads_v3 as guest
import completion_kata_command_policy as policy
import completion_kata_fdmap as fdmap
import completion_kata_inputs as inputs
import completion_kata_operation as operation
import completion_kata_process as process
import completion_kata_ssh as ssh
import completion_kata_runtime as kata_runtime
import completion_runtime_contract as runtime_contract
import completion_workload_owner as workload_owner


def check(value, message):
    if not value:
        raise AssertionError(message)


def reject(call, message="hostile B3 value accepted"):
    try:
        call()
    except BaseException:
        return
    raise AssertionError(message)


runtime_contract._verify_source_bindings()
v3_source_sha = hashlib.sha256((REMOTE / "completion_guest_workloads_v3.py").read_bytes()).hexdigest()
check(v3_source_sha == operation.SSH_PARSER_SHA256, "V3 parser source binding drift")
v3_contract = json.loads((ROOT / "config/stage2-completion-ssh-workload-v3.json").read_bytes())
check(v3_contract["source_sha256"] == v3_source_sha
      and v3_contract["guest_program_sha256"] == guest.GUEST_PROGRAM_SHA256
      and v3_contract["final_deb_sha256"] == guest.FINAL_DEB_SHA256
      and v3_contract["final_deb_bytes"] == guest.FINAL_DEB_BYTES
      and v3_contract["final_installed_tree_sha256"] == guest.FINAL_INSTALLED_TREE_SHA256
      and v3_contract["total_deadline_ns"] == policy.SSH_TOTAL_NS
      and v3_contract["cleanup_reserve_ns"] == policy.SSH_CLEANUP_RESERVE_NS,
      "V3 workload contract drift")
for role, descriptor in policy.REVIEWED_SYNTHETIC_HOST_TOOL_CONTRACTS.items():
    contract_raw = (ROOT / f"test/fixtures/stage2-completion/attested-{role}-contract-v1.json").read_bytes()
    contract = process._parse_contract(contract_raw, descriptor["contract_sha256"])
    check(contract.executable.sha256 == SYNTHETIC_ELF_SHA256,
          "synthetic contract artifact drift")
native_supported = sys.platform == "linux" and platform.machine() == "x86_64" and hasattr(os, "memfd_create")

# No production composition accepts behavior, program, parser, key material,
# paths, commands, or outcomes.
ssh_parameters = tuple(inspect.signature(ssh._compose_production_ssh).parameters)
input_parameters = tuple(inspect.signature(inputs._compose_production_inputs).parameters)
check(ssh_parameters == ("journal", "input_owner", "executable_owner"), "SSH injection seam")
check(input_parameters == ("journal", "completion", "control", "executable_owner"),
      "key injection seam")
source = (REMOTE / "completion_kata_inputs.py").read_text()
for forbidden in ("key_source", "_KeyCommandBatch", "_KeyCommandOutput"):
    check(forbidden not in source, "caller key seam remains: " + forbidden)
reject(ssh.open_fixed_ssh_owner)
reject(lambda: ssh._ProductionSsh())
reject(lambda: inputs._ProductionInputs())

# The registered process table itself carries exact guest stdin and four exact
# key policies. Named bridges can release only those table identities.
ssh_fixed = process._FIXED_COMMANDS[process.CommandId.SSH_READY]
check(ssh_fixed.stdin == guest.guest_program_bytes(), "SSH stdin is not exact guest program")
check(hashlib.sha256(ssh_fixed.stdin).hexdigest() == guest.GUEST_PROGRAM_SHA256,
      "guest program pin")
check(ssh_fixed.argv == ssh.ARGV and ssh_fixed.output_grammar == "ssh-plan", "SSH fixed spec")
check(ssh_fixed.stdout_limit == guest.GUEST_OUTPUT_LIMIT, "SSH output bound")
check(ssh_fixed.duration_ns == policy.SSH_TOTAL_NS == 1_200_000_000_000
      == int(workload_owner.LIFECYCLE_SECONDS * 1_000_000_000)
      and process._cleanup_reserve_ns(ssh_fixed) == policy.SSH_CLEANUP_RESERVE_NS
      and policy.SSH_CLEANUP_RESERVE_NS < policy.SSH_TOTAL_NS,
      "reviewed SSH lifecycle deadline")
check(policy.KEY_COMMAND_ORDER == tuple(policy.KEY_COMMANDS), "key command order")
for left in range(len(policy.KEY_COMMAND_ORDER)):
    for right in range(left + 1, len(policy.KEY_COMMAND_ORDER)):
        hostile = list(policy.KEY_COMMAND_ORDER)
        hostile[left], hostile[right] = hostile[right], hostile[left]
        check(tuple(hostile) != policy.KEY_COMMAND_ORDER, "key swap accepted")
for omitted in range(len(policy.KEY_COMMAND_ORDER)):
    check(policy.KEY_COMMAND_ORDER[:omitted] + policy.KEY_COMMAND_ORDER[omitted + 1:]
          != policy.KEY_COMMAND_ORDER, "key omission accepted")
check(policy.ATTESTED_COMMANDS == {"SSH_READY", *policy.KEY_COMMANDS}
      and not policy.ATTESTED_EXECUTABLES, "unattested SSH execution was enabled")
for name, argv in policy.KEY_COMMANDS.items():
    fixed = process._FIXED_COMMANDS[process.CommandId[name]]
    check(any("{operation_token}" in item for item in fixed.argv)
          and not any("kata-key-stage-v1" in item and "{operation_token}" not in item
                      for item in fixed.argv), "non-unique key stage policy")
    check(fixed.argv == argv and fixed.executable_path == "/usr/bin/ssh-keygen", name)
    check(name in policy.POLICY_SHA256 and name not in policy.DEFERRED_COMMANDS, name + " policy")
for fixed in (ssh_fixed, *(process._FIXED_COMMANDS[process.CommandId[name]]
                            for name in policy.KEY_COMMANDS)):
    spec = process._spec(fixed.command_id)
    value = {"command_id": fixed.command_id.value, "executable_role": fixed.executable_role,
             "executable_path": fixed.executable_path, "argv": list(fixed.argv),
             "stdin_hex": fixed.stdin.hex(), "policy_version": policy.POLICY_VERSION,
             "deadline_class": spec.deadline_class, "duration_ns": fixed.duration_ns,
             "cleanup_reserve_ns": process._cleanup_reserve_ns(fixed),
             "output_grammar": fixed.output_grammar,
             "stdout_limit": fixed.stdout_limit, "stderr_limit": fixed.stderr_limit,
             "inherited_fds": [["CLIENT_KEY", 200], ["KNOWN_HOSTS", 201]]
             if fixed.command_id is process.CommandId.SSH_READY else []}
    check(hashlib.sha256(operation._canonical(value)).hexdigest()
          == policy.POLICY_SHA256[fixed.command_id.value], "policy digest drift")

# Caller-created journals/executables and direct attestation owners are denied.
reject(lambda: operation._claim_production_operation(object()))
reject(lambda: operation._input_cleanup_token(object()))
active_layout_name = b"kata-key-stage-v1-" + b"a" * 64
reject(lambda: operation._stage_candidates(
    set(operation.COMPLETION_NAMES) | {b"kata-key-stage-v1"}))
check(operation._stage_candidates(set(operation.COMPLETION_NAMES) | {active_layout_name})
      == {active_layout_name}, "tokenized stage candidate rejected")
reject(lambda: operation._stage_candidates(
    set(operation.COMPLETION_NAMES) | {active_layout_name, active_layout_name + b".quarantine"}))
reject(lambda: operation._stage_candidates(
    set(operation.COMPLETION_NAMES) | {b"kata-key-stage-v1-foreign"}))
layout_names = tuple(sorted(set(operation.COMPLETION_NAMES) |
                            {operation.RUNTIME_NAME.raw, active_layout_name}))
layout_parent_key = {"mount_id": 1, "device": 2, "inode": 3, "kind": "directory"}
layout_names_sha256 = hashlib.sha256(operation._canonical([
    name.decode() for name in layout_names if name != active_layout_name])).hexdigest()
layout_records = [
    type("LayoutRecord", (), {"record_type": "GENESIS",
         "body": {"operation_token": "a" * 64}})(),
    type("LayoutRecord", (), {"record_type": "PRODUCTION_ADMISSION_V2", "body": {}})(),
    type("LayoutRecord", (), {"record_type": "INPUT_GRANT",
         "body": {"path": "@key-stage", "action": "intent",
                  "name": active_layout_name.decode(),
                  "parent_generation": layout_parent_key, "expected_kind": "directory",
                  "expected_mode": 0o700, "expected_uid": 0, "expected_gid": 0}})(),
    type("LayoutRecord", (), {"record_type": "INPUT_WA",
         "body": {"path": "@key-stage", "action": "mkdir",
                  "parent_key": layout_parent_key, "names_sha256": layout_names_sha256,
                  "target_mode": 0o700}})(),
]
reject(lambda: operation._validate_stage_layout(
    layout_names, layout_records[:-1], "ROOTFS_LEASED", layout_parent_key))
for reachable_phase in operation.KEY_INPUT_PHASES:
    operation._validate_stage_layout(layout_names, layout_records, reachable_phase, layout_parent_key)
for field, bad in (("names_sha256", "0" * 64), ("target_mode", 0o777)):
    saved = layout_records[-1].body[field]; layout_records[-1].body[field] = bad
    reject(lambda: operation._validate_stage_layout(
        layout_names, layout_records, "ROOTFS_LEASED", layout_parent_key))
    layout_records[-1].body[field] = saved
reject(lambda: operation._validate_stage_layout(
    layout_names, layout_records, "ROOTFS_LEASED", {**layout_parent_key, "inode": 4}))
for forbidden_phase in {"GENESIS", "GENESIS_SETTLED", "FS_ABSENT", "FS_OBSERVED", "FS_SETTLED",
                        "BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY", "SSH_READY",
                        "READINESS_REVOKED", "FIREWALL_ABSENT", "INPUT_REMOVED",
                        "ROOTFS_ABSENT", "RETIRED"}:
    reject(lambda forbidden_phase=forbidden_phase: operation._validate_stage_layout(
        layout_names, layout_records, forbidden_phase, layout_parent_key))
quarantine_records = layout_records + [type("LayoutRecord", (), {
    "record_type": "INPUT_WA", "body": {"path": "@key-stage", "action": "remove"}})()]
quarantine_names = tuple(active_layout_name + b".quarantine" if name == active_layout_name else name
                         for name in layout_names)
operation._validate_stage_layout(
    quarantine_names, quarantine_records, "UNCERTAIN", layout_parent_key)
runtime_intent = type("LayoutRecord", (), {
    "record_type": "RUNTIME_STAGE_INTENT_V4", "body": {}})()
runtime_staged = type("LayoutRecord", (), {
    "record_type": "RUNTIME_STAGED_V3", "body": {}})()
operation._validate_runtime_layout(
    {operation.RUNTIME_NAME.raw}, [runtime_intent], "NETWORK_READY")
reject(lambda: operation._validate_runtime_layout(
    {operation.RUNTIME_STAGING_NAME.raw}, [runtime_intent], "NETWORK_READY"))
reject(lambda: operation._validate_runtime_layout(
    set(operation.RUNTIME_NAMES), [runtime_intent], "NETWORK_READY"))
operation._validate_runtime_layout(
    {operation.RUNTIME_NAME.raw}, [runtime_intent, runtime_staged], "NETWORK_READY")
reject(lambda: operation._validate_runtime_layout(
    {operation.RUNTIME_STAGING_NAME.raw}, [runtime_intent, runtime_staged], "NETWORK_READY"))
for terminal_phase in {"INPUT_REMOVED", "ROOTFS_ABSENT", "RETIRED"}:
    for runtime_name in operation.RUNTIME_NAMES:
        reject(lambda runtime_name=runtime_name, terminal_phase=terminal_phase:
               operation._validate_runtime_layout(
                   {runtime_name}, [runtime_intent, runtime_staged], terminal_phase))
root_temporary = (b".cogs-grant-" + b"a" * 32 + b"-"
                  + hashlib.sha256(b".").hexdigest()[:16].encode())
root_intent = type("LayoutRecord", (), {"record_type": "INPUT_GRANT", "body": {
    "path": ".", "action": "intent", "name": root_temporary.decode()}})()
root_settled = type("LayoutRecord", (), {"record_type": "INPUT_GRANT", "body": {
    "path": ".", "action": "settled", "name": root_temporary.decode()}})()
root_published = type("LayoutRecord", (), {"record_type": "INPUT_WA", "body": {
    "path": ".", "action": "mkdir-settled"}})()
root_records = [layout_records[0], root_intent]
prepublication_names = tuple(
    (operation.COMPLETION_NAMES - {operation.INPUT_NAME.raw}) |
    {operation.RUNTIME_NAME.raw})
operation._validate_stage_layout(
    prepublication_names + (root_temporary,), root_records, "FS_INTENT", layout_parent_key)
operation._validate_stage_layout(
    prepublication_names + (root_temporary,), root_records + [root_settled],
    "FS_INTENT", layout_parent_key)
reject(lambda: operation._validate_stage_layout(
    prepublication_names + (root_temporary,),
    root_records + [root_settled, root_published], "FS_INTENT", layout_parent_key))
reject(lambda: operation._validate_stage_layout(
    prepublication_names + (root_temporary, operation.INPUT_NAME.raw),
    root_records, "FS_INTENT", layout_parent_key))
for terminal_phase in {"FIREWALL_ABSENT", "INPUT_REMOVED", "RETIRED"}:
    reject(lambda terminal_phase=terminal_phase: operation._validate_stage_layout(
        prepublication_names + (root_temporary,), root_records,
        terminal_phase, layout_parent_key))
reject(lambda: operation.RuntimeMountIssuance())
reject(lambda: kata_runtime.RuntimeMountOwner())
reject(lambda: kata_runtime.RuntimeMountGrant())
reject(lambda: kata_runtime._make_synthetic_runtime_mount_owner_for_tests(
    "a" * 64, object(), object()))
reject(lambda: operation._issue_runtime_mount_v2(object(), object()))
reject(lambda: operation._record_runtime_mount_v2(object(), object()))
check(tuple(inspect.signature(operation._issue_runtime_mount_v2).parameters)
      == ("authority", "runtime_grant")
      and not hasattr(operation, "_record_runtime_mount_body_v2"),
      "generic HeldNode runtime issuance")
reject(lambda: process.AttestedExecutableOwner())
reject(process._open_attested_executable_owner)
reject(lambda: process._issue_attested_executable_owner({}))
reject(lambda: process._issue_attested_executable_owner(policy.REVIEWED_HOST_TOOL_CONTRACTS))
check(not hasattr(policy, "_install_attested_executable"), "caller policy insertion route")
reject(policy._take_attested_policy_inserter)
caller_executable = process.RetainedExecutable(
    "ssh", "/usr/bin/ssh", 0, "a" * 64, "b" * 64, {})
reject(lambda: process._require_attested_executable(caller_executable))
reject(lambda: ssh._compose_production_ssh(object(), object(), object()))
reject(lambda: ssh._recover_production_ssh(object(), object()))

# Recovery claims only cleanup authority, so lifecycle expiry cannot reject
# before pending-process, revocation, and input settlement run.
class FakeCleanup:
    def __init__(self): self.called = False
    def continue_cleanup(self): self.called = True
recovery_journal, cleanup_journal, recovery_calls = object(), object(), []
cleanup = FakeCleanup()
with patch.object(inputs, "_ProductionInputCleanup", FakeCleanup), \
     patch.object(operation, "_claim_production_operation", side_effect=AssertionError("live claim")), \
     patch.object(operation, "_claim_production_cleanup_operation", return_value=cleanup_journal), \
     patch.object(operation, "_has_recovery_command", return_value=False), \
     patch.object(operation, "_revoke_or_require_terminal", side_effect=lambda value: recovery_calls.append(value)), \
     patch.object(operation, "_durable_phase", return_value="INPUT_REMOVED"):
    check(ssh._recover_production_ssh(recovery_journal, cleanup) == "INPUT_REMOVED",
          "cleanup SSH recovery result")
check(cleanup.called and recovery_calls == [cleanup_journal], "cleanup SSH recovery ordering")

# Exact guest parser and canonical typed result: marker plus all 21 fixed rows.
lines = [guest.GUEST_READY_MARKER]
for ordinal, marker in enumerate(guest.GUEST_NETWORK_MARKERS, 1):
    suffix = "|route_sha256=" + "9" * 64 if ordinal in {1, 8} else ""
    lines.append(f"{guest.GUEST_NETWORK_PREFIX}|{ordinal:02d}|{marker}{suffix}\n".encode())
for ordinal, (label, digest) in enumerate(guest.GUEST_WORKLOAD_PLAN, 1):
    lines.append(
        f"{guest.GUEST_RESULT_PREFIX}|{ordinal:02d}|{label}|1|{digest}|deleted=true\n".encode())
stdout = b"".join(lines)
parsed = guest.parse_guest_workload_output(stdout)
canonical = ssh._canonical_result(parsed)
check(type(parsed) is guest.GuestWorkloadResult and len(parsed.samples) == 21, "fixed result type")
check(canonical == ssh._canonical_result(parsed), "canonical result instability")
result_body = {"operation_token": "a" * 64, "command_serial": 0,
               "binding_sha256": "b" * 64, "manifest_sha256": "c" * 64,
               "runtime_mount_sha256": "d" * 64,
               "runtime_mount_generation": {"mount_id": 1, "device": 2, "inode": 4,
                                             "kind": "directory", "mode": 0o700,
                                             "uid": 0, "gid": 0, "nlink": 2, "size": 0,
                                             "mtime_ns": 1, "ctime_ns": 1},
               "program_sha256": guest.GUEST_PROGRAM_SHA256,
               "parser_sha256": operation.SSH_PARSER_SHA256,
               "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stdout_hex": stdout.hex(),
               "result_sha256": hashlib.sha256(canonical).hexdigest(),
               "canonical_result_hex": canonical.hex(), "proof_sha256": operation.ZERO}
result_body["proof_sha256"] = operation._ssh_result_proof(result_body)
operation._validate_body("SSH_RESULT_V2", result_body)
for field in ("manifest_sha256", "runtime_mount_sha256", "program_sha256",
              "parser_sha256", "stdout_sha256", "result_sha256", "proof_sha256"):
    hostile_body = {**result_body, field: "f" * 64}
    reject(lambda hostile_body=hostile_body: operation._validate_body("SSH_RESULT_V2", hostile_body))
check(tuple(inspect.signature(operation._record_ssh_ready).parameters) == ("authority",),
      "arbitrary readiness proof API")
for hostile in (stdout[:-1], stdout + b"extra\n", stdout.replace(b"|01|GIT_01|", b"|02|GIT_01|", 1),
                stdout.replace(b"deleted=true", b"deleted=false", 1), stdout.replace(b"|1|", b"|01|", 1)):
    reject(lambda hostile=hostile: guest.parse_guest_workload_output(hostile))

# SSH options remain one private authenticated /bin/sh stdin session.
argv = ssh.ARGV
check(argv[:4] == ("/usr/bin/ssh", "-F", "/dev/null", "-T"), "SSH prefix")
check(argv[-4:] == ("-i", "/proc/self/fd/200", "root@192.0.2.2", "/bin/sh -s"), "SSH tail")
for option in ("BatchMode=yes", "StdinNull=no", "IdentitiesOnly=yes", "IdentityAgent=none",
               "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
               "StrictHostKeyChecking=yes", "UserKnownHostsFile=/proc/self/fd/201",
               "ConnectionAttempts=1", "ProxyCommand=none", "ProxyJump=none",
               "ControlMaster=no", "ClearAllForwardings=yes", "ForwardAgent=no"):
    check(argv.count(option) == 1, option)
check("-n" not in argv and all("StrictHostKeyChecking=no" not in value for value in argv),
      "stdin/TOFU fallback")

# Historical fd observations cannot claim the distinct production owner; the
# latter remains exact-lineage and one-use.
with tempfile.TemporaryDirectory(prefix="cogs-b3-fd-") as root:
    paths = (Path(root) / "client", Path(root) / "known")
    paths[0].write_bytes(b"private\n"); paths[1].write_bytes(b"known\n")
    descriptors = tuple(os.open(path, os.O_RDONLY) for path in paths)
    try:
        identities = tuple(fdmap.identity(fd) for fd in descriptors)
        historical = fdmap.bind_inputs(*descriptors, *identities)
        reject(lambda: fdmap._claim_production_inputs(historical, "a" * 64, "b" * 64))
        owner = fdmap._bind_production_inputs(*descriptors, *identities, "a" * 64, "b" * 64)
        claimed = fdmap._claim_production_inputs(owner, "a" * 64, "b" * 64)
        rows = fdmap._consume_production_inputs((200, 201), claimed)
        check(tuple(row.target_fd for row in rows) == (200, 201), "fd targets")
        reject(lambda: fdmap._consume_production_inputs((200, 201), claimed))
        reject(lambda: fdmap._claim_production_inputs(owner, "a" * 64, "b" * 64))
    finally:
        for descriptor in descriptors: os.close(descriptor)

# Durable creation grants bind unpredictable operation names, exact exclusive
# parents, child authority bounds, and command serial before mutation.
grant = {"operation_token": "a" * 64, "action": "intent", "grant_id": "b" * 64,
         "path": "@key-stage/client", "name": "client", "parent_generation": {
             "mount_id": 1, "device": 2, "inode": 2, "kind": "directory",
             "mode": 0o700, "uid": 0, "gid": 0, "nlink": 2, "size": 0,
             "mtime_ns": 1, "ctime_ns": 1}, "parent_inode_version": 7,
         "expected_kind": "file", "expected_mode": 0o600, "expected_uid": 0,
         "expected_gid": 0, "command_serial": 0, "birth_min_ns": 10,
         "birth_max_ns": 20, "mount_id": 1, "inode_version_min": 0,
         "inode_version_max": 0xffffffff, "child_generation": None,
         "child_birth_ns": None, "child_inode_version": None}
operation._validate_body("INPUT_GRANT", grant)
operation._validate_body("INPUT_GRANT", {**grant, "action": "settled",
    "child_generation": {"mount_id": 1, "device": 2, "inode": 3, "kind": "file",
                         "mode": 0o600, "uid": 0, "gid": 0, "nlink": 1,
                         "size": 1, "mtime_ns": 11, "ctime_ns": 11},
    "child_birth_ns": 11, "child_inode_version": 8})

# Durable per-entry state accepts write-ahead metadata plus only
# intent->settled->remove-intent->absence.
# cleanup composition has no behavior callback.
wa = {"operation_token": "a" * 64, "action": "mkdir", "path": ".",
      "parent_key": {"mount_id": 1, "device": 2, "inode": 2, "kind": "directory"},
      "names_sha256": "c" * 64, "child_key": None, "before_mode": None,
      "target_mode": 0o700}
operation._validate_body("INPUT_WA", wa)
operation._validate_body("INPUT_WA", {
    **wa, "action": "mkdir-settled",
    "child_key": {"mount_id": 1, "device": 2, "inode": 3, "kind": "directory"}})
operation._validate_body("INPUT_WA", {
    **wa, "action": "remove", "path": "@key-stage/client",
    "child_key": {"mount_id": 1, "device": 2, "inode": 3, "kind": "file"},
    "before_mode": 0o600, "target_mode": 0})
for action in ("create-intent", "create", "remove-intent", "absent"):
    body = {"operation_token": "a" * 64, "action": action, "path": "private/key",
            "kind": "file", "key": None if action == "absent" else
            {"mount_id": 1, "device": 2, "inode": 3, "kind": "file"},
            "sha256": "b" * 64}
    operation._validate_body("INPUT_STEP", body)
check(tuple(inspect.signature(inputs._compose_production_input_cleanup).parameters)
      == ("journal", "completion", "control"), "cleanup injection seam")

# The reviewed synthetic static ELF crosses the real contract parser, artifact
# verifier, sealed-memfd issuer, and a fresh exec interpreter. Stable replay
# identities match while the retained kernel generations differ.
if native_supported:
    model = runpy.run_path(str(ROOT / "test/aws-stage2-completion-kata-slice-a.py"))
    fixture_elf = ensure_attested_static_fixture()
    staged = ((fixture_elf, fixture_elf, 0o500),
              (ROOT / "test/fixtures/stage2-completion/attested-ssh-contract-v1.json",
               Path("/tmp/cogs-stage2-attested-ssh-contract-v1.json"), 0o600),
              (ROOT / "test/fixtures/stage2-completion/attested-ssh-keygen-contract-v1.json",
               Path("/tmp/cogs-stage2-attested-ssh-keygen-contract-v1.json"), 0o600))
    try:
        for source_path, target_path, mode in staged:
            if source_path == target_path:
                continue
            descriptor = os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
            try:
                raw = source_path.read_bytes(); offset = 0
                while offset < len(raw): offset += os.write(descriptor, raw[offset:])
                os.fsync(descriptor)
            finally: os.close(descriptor)
        executable_path = str(staged[0][1])
        executed_ssh = subprocess.run((executable_path, "-F"), check=True, capture_output=True)
        historical_lines = [historical_guest.GUEST_READY_MARKER]
        for ordinal, (label, digest) in enumerate(historical_guest.GUEST_WORKLOAD_PLAN, 1):
            historical_lines.append(
                f"COGS_STAGE2_RESULT_V1|{ordinal:02d}|{label}|1|{digest}|deleted=true\n".encode())
        check(executed_ssh.stdout == b"".join(historical_lines),
              "historical synthetic static SSH effect drift")
        with tempfile.TemporaryDirectory(prefix="cogs-static-key-") as key_dir:
            for key_name in ("client", "server"):
                key_path = str(Path(key_dir) / key_name)
                subprocess.run((executable_path, "-q", "-f", key_path), check=True)
                check(Path(key_path).is_file() and Path(key_path + ".pub").is_file(),
                      "synthetic static key effect absent")
                public = subprocess.run((executable_path, "-y", "-f", key_path),
                                        check=True, capture_output=True).stdout
                check(public.startswith(b"ssh-ed25519 ") and public.endswith(b"\n"),
                      "synthetic static public-key effect drift")
        child_code = '''import json,os,sys\nsys.path.insert(0,sys.argv[1])\nimport completion_kata_process as p, completion_kata_command_policy as c\nos.environ["COGS_KATA_SYNTHETIC_ATTESTATION_V1"]="1"\no=p._open_synthetic_attested_executable_owner_for_tests()\na=p._claim_attested_executable(o,"ssh"); b=p._claim_attested_executable(o,"ssh-keygen")\nprint(json.dumps({"policy":{k:dict(v) for k,v in c.ATTESTED_EXECUTABLES.items()},"generations":[a.generation,b.generation]},sort_keys=True))\np._release_attested_executable(a);p._release_attested_executable(b)'''
        child = subprocess.run((sys.executable, "-c", child_code, str(REMOTE)),
                               check=True, capture_output=True, text=True,
                               env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        child_value = json.loads(child.stdout)
        os.environ["COGS_KATA_SYNTHETIC_ATTESTATION_V1"] = "1"
        synthetic_owner = process._open_synthetic_attested_executable_owner_for_tests()
        live_ssh = process._claim_attested_executable(synthetic_owner, "ssh")
        live_key = process._claim_attested_executable(synthetic_owner, "ssh-keygen")
        stable = {name: dict(value) for name, value in policy.ATTESTED_EXECUTABLES.items()}
        check(stable == child_value["policy"]
              and all("executable_generation" not in value for value in stable.values()),
              "attestation replay policy was kernel-generation-bound")
        check([live_ssh.generation, live_key.generation] != child_value["generations"],
              "fresh issuer unexpectedly recreated memfd generation")
        # Build every durable attested cut with the real issued identities,
        # then have another exec interpreter issue new memfds and replay them.
        add, prefix = model["add"], model["prefix"]
        make_intent, make_preexec, make_outcome = model["intent"], model["preexec"], model["outcome"]
        rebound, generation = model["rebound"], model["generation"]
        admitted = operation._boottime_ns()
        raw = add(prefix(), "LIFECYCLE_DEADLINE_V1", {
            "operation_token": "a" * 64,
            "admission_boottime_ns": admitted,
            "ssh_start_deadline_boottime_ns": admitted + operation.JOURNAL_SETUP_MARGIN_NS,
            "journal_deadline_boottime_ns": admitted + operation.JOURNAL_TOTAL_NS})
        raw = add(raw, "PRODUCTION_ADMISSION_V2", {
            "operation_token": "a" * 64,
            "admission_version": operation.PRODUCTION_ADMISSION_VERSION,
            "policy_version": policy.POLICY_VERSION,
            "parser_source_sha256": operation.SSH_PARSER_SHA256})
        cuts = {}
        def append_grant(value, path, name, kind, mode, serial, settled=False):
            grant_id = hashlib.sha256(f"{path}:{serial}".encode()).hexdigest()
            body = {"operation_token": "a" * 64,
                    "action": "settled" if settled else "intent", "grant_id": grant_id,
                    "path": path, "name": name, "parent_generation": generation(60),
                    "parent_inode_version": 1, "expected_kind": kind,
                    "expected_mode": mode, "expected_uid": 0, "expected_gid": 0,
                    "command_serial": serial, "birth_min_ns": 10, "birth_max_ns": 20,
                    "mount_id": 1, "inode_version_min": 0,
                    "inode_version_max": 0xffffffff,
                    "child_generation": generation(61 + serial, kind, mode) if settled else None,
                    "child_birth_ns": 11 if settled else None,
                    "child_inode_version": 2 if settled else None}
            return add(value, "INPUT_GRANT", body)
        raw = append_grant(raw, "@key-stage", "kata-key-stage-v1-" + "a" * 64,
                           "directory", 0o700, 0)
        raw = append_grant(raw, "@key-stage", "kata-key-stage-v1-" + "a" * 64,
                           "directory", 0o700, 0, True)
        serial = 0
        for command_name in policy.KEY_COMMAND_ORDER:
            if "KEYGEN" in command_name:
                names = ("client", "client.pub") if "CLIENT" in command_name else ("server", "server.pub")
                for key_name in names:
                    raw = append_grant(raw, "@key-stage/" + key_name, key_name, "file",
                                       0o600 if "." not in key_name else 0o644, serial)
            command = make_intent(serial, command_name, "ROOTFS_LEASED")
            command = make_intent(serial, command_name, "ROOTFS_LEASED")
            command = rebound({**command, "executable_sha256": live_key.sha256,
                               "tool_closure_sha256": live_key.closure_sha256,
                               "executable_generation": live_key.generation})
            raw = add(raw, "COMMAND_INTENT_V2", command); cuts[f"{command_name}-intent"] = raw
            before_exec = make_preexec(command)
            raw = add(raw, "COMMAND_PREEXEC_V2", before_exec); cuts[f"{command_name}-preexec"] = raw
            expected = b"" if "KEYGEN" in command_name else (
                b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea\n" if "CLIENT" in command_name else
                b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID1AF8PoQ4lakrcKp00bfrycmCzPLsSWjMDNVfEq9GYM\n")
            raw = add(raw, "COMMAND_OUTCOME_V2", make_outcome(command, expected))
            cuts[f"{command_name}-outcome"] = raw
            if "KEYGEN" in command_name:
                cuts[f"{command_name}-effect-before-settlement"] = raw
                for key_name in names:
                    raw = append_grant(raw, "@key-stage/" + key_name, key_name, "file",
                                       0o600 if "." not in key_name else 0o644, serial, True)
                    cuts[f"{command_name}-{key_name}-settled"] = raw
            serial += 1
        parent_generation = generation(50)
        intent_body = {"operation_token": "a" * 64, "resource_id": "input-root",
                       "action": "create", "expected_parent_generation": parent_generation,
                       "names_sha256": hashlib.sha256(operation._canonical([])).hexdigest()}
        raw = add(raw, "FS_INTENT", intent_body)
        raw = append_grant(raw, ".", ".cogs-grant-" + "a" * 32 + "-root",
                           "directory", 0o700, serial)
        cuts["mkdir-intent"] = raw
        cuts["mkdir-effect-before-settlement"] = raw
        raw = append_grant(raw, ".", ".cogs-grant-" + "a" * 32 + "-root",
                           "directory", 0o700, serial, True)
        cuts["mkdir-grant-settled"] = raw
        input_root_key = {"mount_id": 1, "device": 2, "inode": 65, "kind": "directory"}
        raw = add(raw, "INPUT_STEP", {"operation_token": "a" * 64,
            "action": "create-intent", "path": ".", "kind": "directory",
            "key": input_root_key, "sha256": None})
        raw = add(raw, "INPUT_STEP", {"operation_token": "a" * 64,
            "action": "create", "path": ".", "kind": "directory",
            "key": input_root_key, "sha256": None})
        manifest_key = {"mount_id": 1, "device": 2, "inode": 51, "kind": "file"}
        raw = add(raw, "INPUT_STEP", {"operation_token": "a" * 64,
            "action": "create-intent", "path": "@manifest", "kind": "file",
            "key": manifest_key, "sha256": "c" * 64})
        raw = add(raw, "INPUT_STEP", {"operation_token": "a" * 64,
            "action": "create", "path": "@manifest", "kind": "file",
            "key": manifest_key, "sha256": "c" * 64})
        after_parent = {**parent_generation,
                        "mtime_ns": parent_generation["mtime_ns"] + 1,
                        "ctime_ns": parent_generation["ctime_ns"] + 1}
        observed = {**intent_body, "before_parent": parent_generation,
                    "after_parent": after_parent, "before_child": None,
                    "after_child": generation(65)}
        raw = add(add(raw, "FS_OBSERVED", observed), "FS_SETTLED", observed)
        for kind in ("BASELINES_CAPTURED", "NETWORK_READY", "RUNTIME_READY"):
            raw = add(raw, kind, {"operation_token": "a" * 64, "proof_sha256": "9" * 64})
        mount = {"operation_token": "a" * 64, "manifest_sha256": "c" * 64,
                 "mount_generation": generation(52), "issuance_sha256": operation.ZERO}
        mount["issuance_sha256"] = hashlib.sha256(operation._canonical({
            name: mount[name] for name in mount if name != "issuance_sha256"})).hexdigest()
        raw = add(raw, "RUNTIME_MOUNT_V2", mount)
        ssh_command = make_intent(serial, "SSH_READY", "RUNTIME_READY")
        ssh_command = rebound({**ssh_command, "executable_sha256": live_ssh.sha256,
                               "tool_closure_sha256": live_ssh.closure_sha256,
                               "executable_generation": live_ssh.generation})
        raw = add(raw, "COMMAND_INTENT_V2", ssh_command); cuts["ssh-intent"] = raw
        raw = add(raw, "COMMAND_PREEXEC_V2", make_preexec(ssh_command)); cuts["ssh-preexec"] = raw
        raw = add(raw, "COMMAND_OUTCOME_V2", make_outcome(ssh_command, stdout)); cuts["ssh-outcome"] = raw
        result = {"operation_token": "a" * 64, "command_serial": serial,
                  "binding_sha256": ssh_command["binding_sha256"], "manifest_sha256": "c" * 64,
                  "runtime_mount_sha256": mount["issuance_sha256"],
                  "runtime_mount_generation": mount["mount_generation"],
                  "program_sha256": guest.GUEST_PROGRAM_SHA256,
                  "parser_sha256": operation.SSH_PARSER_SHA256,
                  "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stdout_hex": stdout.hex(),
                  "result_sha256": hashlib.sha256(canonical).hexdigest(),
                  "canonical_result_hex": canonical.hex(), "proof_sha256": operation.ZERO}
        result["proof_sha256"] = operation._ssh_result_proof(result)
        raw = add(raw, "SSH_RESULT_V2", result); cuts["ssh-result"] = raw
        result_record = operation._parse(raw)[-1]
        raw = add(raw, "SSH_READY_V2", {"operation_token": "a" * 64,
            "result_record_sha256": result_record.line_sha256,
            "proof_sha256": result["proof_sha256"]}); cuts["ssh-ready"] = raw
        raw = add(raw, "READINESS_REVOKED", {"operation_token": "a" * 64}); cuts["ssh-revoke"] = raw
        with tempfile.TemporaryDirectory(prefix="cogs-attested-cuts-") as cuts_dir:
            for name, value in cuts.items(): (Path(cuts_dir) / name).write_bytes(value)
            replay_code = '''import os,sys\nsys.path.insert(0,sys.argv[1])\nimport completion_kata_process as p,completion_kata_operation as o\nos.environ["COGS_KATA_SYNTHETIC_ATTESTATION_V1"]="1"\np._open_synthetic_attested_executable_owner_for_tests()\nfrom pathlib import Path\nrows=list(Path(sys.argv[2]).iterdir())\nfor row in rows:o._parse(row.read_bytes())\nprint(len(rows))'''
            replay = subprocess.run((sys.executable, "-c", replay_code, str(REMOTE), cuts_dir),
                                    check=True, capture_output=True, text=True,
                                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            check(int(replay.stdout) == len(cuts), "fresh interpreter missed attested cuts")
        process._release_attested_executable(live_ssh)
        process._release_attested_executable(live_key)
    finally:
        os.environ.pop("COGS_KATA_SYNTHETIC_ATTESTATION_V1", None)
        for _source, target_path, _mode in reversed(staged):
            try: target_path.unlink()
            except FileNotFoundError: pass

print("completion Kata corrected production SSH/input B3 hostile matrix passed")

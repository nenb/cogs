#!/usr/bin/env python3
"""Production-shaped hostile aggregation tests for seven local formal cycles."""
import copy
import hashlib
import importlib.util
import json
import io
import inspect
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module); return module


formal = load("stage2_formal_workflow_test", "scripts/stage2-formal-local-qualification.py")
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_formal_cycle_authority as authority
import completion_formal_cycle_full as formal_full_entry
import completion_formal_cycle_readiness as formal_readiness_entry
import completion_cycle_evidence as cycle_evidence
import completion_kata_admission as admission
import completion_kata_execution_bridge as execution
import completion_kata_operation as operation
import completion_kata_ssh as ssh
import completion_local_evidence as owners
import completion_local_full as local

guard = load("stage2_formal_guard_test", "scripts/stage2-prebuilt-local-qualification-guard.py")

def d(value): return hashlib.sha256(value.encode()).hexdigest()

expected = {
    "EXPECTED_IMPLEMENTATION_HEAD": "1" * 40,
    "EXPECTED_CONTROL_HEAD": "2" * 40,
    "EXPECTED_QUALIFICATION_HEAD": "3" * 40,
    "EXPECTED_SOURCE_MANIFEST_SHA256": d("source"),
    "EXPECTED_CONTROL_SHA256": d("control"),
    "EXPECTED_WORKFLOW_SHA256": hashlib.sha256((ROOT /
        ".github/workflows/stage2-prebuilt-local-kata-qualification.yml").read_bytes()).hexdigest(),
    "EXPECTED_RESULT_SCHEMA_SHA256": hashlib.sha256(formal.RESULT_SCHEMA.read_bytes()).hexdigest(),
    "EXPECTED_ROOTFS_DESCRIPTOR_SHA256": d("descriptor"),
    "EXPECTED_STATIC_CONTROL_RUN_ID": "61",
    "EXPECTED_STATIC_CONTROL_ARTIFACT_ID": "62",
    "EXPECTED_STATIC_CONTROL_ARTIFACT_DIGEST": "sha256:" + d("static-archive"),
    "EXPECTED_MIXED_PREFLIGHT_RUN_ID": "63",
    "GITHUB_RUN_ID": "71", "GITHUB_RUN_ATTEMPT": "1",
}


def rejected(action):
    try: action()
    except (formal.FormalQualificationError, authority.FormalCycleAuthorityError,
            guard.GuardError, owners.LocalEvidenceError, admission.AdmissionError, OSError, ValueError): return
    raise AssertionError("hostile formal qualification input was accepted")


# Synthetic authenticated control uses real static shapes, never consumer key
# constants. Only lineage is replaced; no held custody or real lifecycle is acquired.
control_fixture = tempfile.TemporaryDirectory()
# Historical bytes are fixture inputs only. No successor package is populated.
historical = ROOT / "deploy/aws-feasibility/remote/stage2-completion-local-control-v5"
assert formal.CONTROL_PACKAGE == guard.CONTROL_PACKAGE
assert formal.CONTROL_PACKAGE.name == "stage2-completion-local-control-v7"
control = json.loads((historical / formal.CONTROL_MEMBER).read_bytes())
envelope = json.loads((historical / formal.ENVELOPE_MEMBER).read_bytes())
runtime_raw = (historical / formal.RUNTIME_MEMBER).read_bytes()
selected = [{"path": path, "size": len((ROOT / path).read_bytes()),
             "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}
            for path in sorted(admission.preparation.MANDATORY_SECURITY_SOURCES)]
assert guard.REQUIRED_CONSUMERS <= admission.preparation.MANDATORY_SECURITY_SOURCES
control["implementation"].update(selected_sources=selected,
    selected_sources_sha256=hashlib.sha256(formal.canonical(selected)).hexdigest())
runtime = admission.preparation.StaticDescription(
    runtime_raw, hashlib.sha256(runtime_raw).hexdigest(), json.loads(runtime_raw))
control["implementation"]["revision"] = expected["EXPECTED_IMPLEMENTATION_HEAD"]
control["implementation"]["source_manifest_sha256"] = expected["EXPECTED_SOURCE_MANIFEST_SHA256"]
control["producer"].update(control_revision=expected["EXPECTED_CONTROL_HEAD"],
    implementation_revision=expected["EXPECTED_IMPLEMENTATION_HEAD"],
    source_manifest_sha256=expected["EXPECTED_SOURCE_MANIFEST_SHA256"])
envelope["implementation"] = copy.deepcopy(control["implementation"])
envelope["control_revision"] = expected["EXPECTED_CONTROL_HEAD"]
base = envelope["result_binding_base"]
base["source_head"] = expected["EXPECTED_IMPLEMENTATION_HEAD"]
base["source_manifest_sha256"] = expected["EXPECTED_SOURCE_MANIFEST_SHA256"]
expected["EXPECTED_ROOTFS_DESCRIPTOR_SHA256"] = base["rootfs_descriptor_sha256"]
formal.CONTROL_PACKAGE = Path(control_fixture.name)
for name, raw in ((formal.ENVELOPE_MEMBER, formal.canonical(envelope)),
                  (formal.RUNTIME_MEMBER, runtime_raw)):
    (formal.CONTROL_PACKAGE / name).write_bytes(raw)
    row = next(row for row in control["members"] if row["name"] == name)
    row.update(sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
control_raw = formal.canonical(control)
(formal.CONTROL_PACKAGE / formal.CONTROL_MEMBER).write_bytes(control_raw)
expected["EXPECTED_CONTROL_SHA256"] = hashlib.sha256(control_raw).hexdigest()

class FixtureCustody:
    def __init__(self): self.close_attempts = 0

def project_custody(custody):
    assert type(custody) is FixtureCustody and custody.close_attempts == 0
    return admission._static_manifest_binding(base, runtime)

def close_custody(custody):
    assert type(custody) is FixtureCustody and custody.close_attempts == 0
    custody.close_attempts += 1

def reject_diagnostic(_custody):
    raise ValueError("diagnostic custody cannot enter formal composition")

fixture_records = {}
_, _, issue, discard, consume = cycle_evidence._new_cycle_receipt_routes(
    parse_journal=lambda raw: fixture_records[raw], formal_custody_binding=project_custody,
    diagnostic_custody_lineage=reject_diagnostic, close_custody=close_custody)

def terminal(ordinal, production_grant=None):
    route = ((cycle_evidence._fixed_full_route() if ordinal == 1
              else cycle_evidence._fixed_readiness_route()) if production_grant else
             (cycle_evidence._formal_full_route() if ordinal == 1
              else cycle_evidence._formal_readiness_route()))
    mode, capability, program, marker = cycle_evidence._describe_route(route)
    grant = production_grant or formal.issue_grant(ordinal, expected, authority)
    assert grant.ordinal == ordinal and grant.mode == mode
    grant_value = authority.asdict(grant)
    grant_value["cycle_ordinal"] = grant_value.pop("ordinal"); grant_value.pop("mode")
    # Production has fresh owners, never the seven qualification identities.
    if production_grant: ordinal += 7
    token, rootfs = f"{ordinal:x}" * 64, d(f"rootfs-{ordinal}")
    boot = f"{ordinal:08x}-0000-4000-8000-{ordinal:012x}"
    parser = operation.SSH_PARSER_SHA256 if mode == "full" else cycle_evidence.readiness_guest.PARSER_SHA256
    route_body = {"operation_token": token, "route": mode,
        "cycle_capability_sha256": capability, "program_sha256": program,
        "parser_source_sha256": parser, "marker_sha256": marker,
        "grant_authority": "production" if production_grant else authority.AUTHORITY, **grant_value}
    operation._validate_body("CYCLE_ROUTE_V1", route_body)
    rows = []
    def rec(kind, body):
        sequence = len(rows)
        line_sha = hashlib.sha256(formal.canonical([ordinal, sequence, kind, body])).hexdigest()
        rows.append(operation.Record(sequence, sequence * 10, (sequence + 1) * 10, line_sha, kind, body))
    rec("GENESIS", {"operation_token": token, "rootfs_token": rootfs, "host_boot_id": boot})
    rec("CYCLE_ROUTE_V1", route_body)
    rec("ROOTFS_LEASED", {"operation_token": token})
    rec("RUNTIME_STAGED_V3", {"operation_token": token})
    rec("CTR_LAUNCH_ISSUED_V1", {"kata_launch_started_boottime_ns": 100, "host_boot_id": boot})
    rec("SSH_MARKER_OBSERVED_V1", {"ssh_marker_observed_boottime_ns": 200, "host_boot_id": boot})
    rec("SSH_COMMAND_SETTLED_V1", {"ssh_command_settled_boottime_ns": 300,
                                   "host_boot_id": boot, "parser_sha256": parser})
    rec("COMMAND_INTENT_V2", {"command_id": "CTR_RUN"})
    rec("COMMAND_INTENT_V2", {"command_id": "SSH_READY" if mode == "full" else "SSH_READINESS"})
    for index, role in enumerate(("client", "server")):
        parent = {"mount_id": 1, "device": 250, "inode": 1000 + ordinal,
            "kind": "directory", "mode": 0o700, "uid": 0, "gid": 0, "nlink": 1,
            "size": 0, "mtime_ns": 10, "ctime_ns": 10}
        child = {**parent, "inode": 2000 + ordinal * 2 + index, "kind": "file",
                 "mode": 0o600, "size": 64}
        key_grant = {"operation_token": token, "action": "settled",
            "grant_id": d(f"key-generation-{role}-{ordinal}"), "path": f"@key-stage/{role}",
            "name": role, "parent_generation": parent, "parent_inode_version": 1,
            "expected_kind": "file", "expected_mode": 0o600, "expected_uid": 0,
            "expected_gid": 0, "command_serial": 1, "birth_min_ns": 1, "birth_max_ns": 20,
            "mount_id": 1, "inode_version_min": 1, "inode_version_max": 1,
            "child_generation": child, "child_birth_ns": 10, "child_inode_version": 1}
        operation._validate_body("INPUT_GRANT", key_grant)
        rec("INPUT_GRANT", key_grant)
    rec("NETWORK_SNAPSHOT_V2", {"snapshot_kind": "runtime", "proof_sha256": d(f"network-{ordinal}")})
    rec("RUNTIME_MOUNT_V2", {"operation_token": token,
                             "issuance_sha256": d(f"mount-{ordinal}")})
    qmp = {"qemu_argv_sha256": d(f"argv-{ordinal}"), "qemu_pid": 100 + ordinal,
        "qemu_starttime": 200 + ordinal, "qemu_executable_device": 250,
        "qemu_executable_inode": 260 + ordinal, "observer_qmp_device": 300,
        "observer_qmp_inode": 400 + ordinal, "kvm_device": 500,
        "kvm_inode": 600 + ordinal, "kvm_rdev": 700,
        "kvm_api": 12, "qmp_present": True, "qmp_enabled": True}
    for kind in cycle_evidence.PRIVATE_TEARDOWN_RECORDS:
        body = {"operation_token": token}
        if kind == "RUNTIME_ROLE_IDENTITIES_V1":
            body["roles"] = [{"role": "qemu", "pid": qmp["qemu_pid"],
                "starttime": qmp["qemu_starttime"],
                "executable_device": qmp["qemu_executable_device"],
                "executable_inode": qmp["qemu_executable_inode"]}]
        rec(kind, body)
    raw = formal.canonical([authority.asdict(row) for row in rows])
    fixture_records[raw] = rows
    runtime_identity = execution._runtime_identity({**qmp, "kvm_present": True, "kvm_enabled": True})
    assert runtime_identity == cycle_evidence._runtime_identity_sha256(SimpleNamespace(**qmp))
    observed = owners._PlatformOwnerResult(operation_token=token,
        live_mapping_sha256=d(f"mapping-{ordinal}"), runtime_identity_sha256=runtime_identity,
        qemu_process_sha256=d(f"runtime-pre-ssh-{ordinal}"), **qmp)
    if mode == "full":
        parsed = cycle_evidence.full_guest.GuestWorkloadResult(d("transcript"), tuple(
            cycle_evidence.full_guest.GuestSampleResult(index, label, 1000 + index, result, True)
            for index, (label, result) in enumerate(cycle_evidence.full_guest.GUEST_WORKLOAD_PLAN, 1)),
            cycle_evidence.full_guest.GUEST_NETWORK_MARKERS, d("route"), d("route"))
        session = ssh.AuthenticatedSession(1, d("command"), program, marker, d("session"), parsed)
        proof = owners._RuntimeOwnerResult(operation_token=token,
            runtime_mount_record_sha256=d(f"mount-{ordinal}"), network_causal_proof_sha256=d("causal"),
            live_mapping_sha256=observed.live_mapping_sha256, runtime_identity_sha256=runtime_identity,
            qemu_process_sha256=d(f"runtime-post-ssh-{ordinal}"), **qmp)
    else:
        session = ssh.ReadinessAuthenticatedSession(1, d("command"), program, marker, marker)
        proof = cycle_evidence._issue_runtime_readiness_owner_result(operation_token=token,
            runtime_mount_record_sha256=d(f"mount-{ordinal}"), runtime_network_sha256=d(f"network-{ordinal}"),
            live_mapping_sha256=observed.live_mapping_sha256, runtime_identity_sha256=runtime_identity,
            qemu_process_sha256=d(f"runtime-post-ssh-{ordinal}"),
            qmp_identity=tuple(qmp[name] for name in ("qemu_pid", "qemu_starttime",
                "qemu_executable_device", "qemu_executable_inode", "observer_qmp_device",
                "observer_qmp_inode", "kvm_device", "kvm_inode", "kvm_rdev", "kvm_api")))
    lifecycle = SimpleNamespace(retired=owners._RetiredJournalOwnerResult(raw),
        residue=owners._ResidueOwnerResult(token, d(f"baseline-{ordinal}"), local.RESIDUE_FACTS),
        runtime_observation=observed, runtime_proof=proof, session=session, static_custody=FixtureCustody())
    return route, lifecycle

def receipt_bytes(ordinal):
    route, lifecycle = terminal(ordinal)
    result = issue(route, lifecycle)
    assert lifecycle.static_custody.close_attempts == 1
    rejected(lambda: cycle_evidence._consume_cycle_receipt(result))
    raw = consume(result)
    rejected(lambda: consume(result))
    assert result.receipt_commitment == hashlib.sha256(
        b"cogs.stage2-formal-local-cycle-receipt/v2\0" + raw).hexdigest()
    formal.validate_receipt(raw, expected, ordinal)
    return raw

def receipt(ordinal):
    # Hostile mutations below start from genuine serializer output, never repaired JSON.
    return json.loads(receipt_bytes(ordinal))


def write_cycle(root, ordinal, value=None):
    raw = receipt_bytes(ordinal) if value is None else formal.canonical(value)
    status = formal.status_value(raw, expected, ordinal,
        f"stage2-formal-cycle-{ordinal}-{expected['EXPECTED_IMPLEMENTATION_HEAD']}-{expected['EXPECTED_CONTROL_HEAD']}-71-1")
    path = Path(root) / f"cycle-{ordinal}"; path.mkdir()
    (path / "receipt.json").write_bytes(raw); (path / "status.json").write_bytes(formal.canonical(status))


def artifact_api():
    return {"total_count": 7, "artifacts": [{
        "id": 700 + ordinal, "name": formal.expected_artifact_name(expected, ordinal),
        "digest": "sha256:" + d(f"archive-{ordinal}"), "expired": False,
        "workflow_run": {"id": 71, "head_sha": expected["EXPECTED_QUALIFICATION_HEAD"]},
    } for ordinal in range(1, 8)]}


def custody(api=None):
    source = api or artifact_api()
    return formal.canonical(formal.custody_from_api(json.dumps(source).encode(), expected))


def aggregate(root, outcome="success", expected_value=expected, custody_raw=None):
    return formal.aggregate(root, custody_raw or custody(), expected_value, outcome)


# Grant domains are non-cloud, batch shared, ordinal/mode unique, canonical and one-attempt.
grants = [formal.issue_grant(index, expected, authority) for index in range(1, 8)]
assert len({item.batch_commitment for item in grants}) == 1
assert len({item.grant_commitment for item in grants}) == 7
assert [item.mode for item in grants] == list(formal.CYCLE_MODES)
encoded = authority.encode(grants[0]); assert authority.decode(encoded) == grants[0]
assert b"aws" not in encoded.lower() and b"provider" not in encoded.lower()
for hostile in (encoded[:-1], encoded + b" ", encoded.replace(b'"ordinal":1', b'"ordinal":2')):
    rejected(lambda hostile=hostile: authority.decode(hostile))
for impostor in (True, 1.0):
    fields = authority.asdict(grants[0])
    for name in ("authority", "batch_commitment", "grant_commitment"): fields.pop(name)
    fields["workflow_run_attempt"] = impostor
    rejected(lambda fields=fields: authority.issue(fields))

# The owner route and durable journal accept only the separate formal grant type.
canonical_grant = formal.issue_grant(1, expected, authority)
route = cycle_evidence._formal_full_route()
assert cycle_evidence._cycle_launch_authorized(route, canonical_grant)
assert not cycle_evidence._cycle_launch_authorized(route, None)
route_name, capability, program, marker = cycle_evidence._describe_route(route)
journal_grant = authority.asdict(canonical_grant)
journal_grant["cycle_ordinal"] = journal_grant.pop("ordinal"); journal_grant.pop("mode")
body = {"operation_token": d("operation"), "route": route_name,
    "cycle_capability_sha256": capability, "program_sha256": program,
    "parser_source_sha256": operation.SSH_PARSER_SHA256, "marker_sha256": marker,
    "grant_authority": authority.AUTHORITY, **journal_grant}
operation._validate_body("CYCLE_ROUTE_V1", body)
hostile_body = {**body, "grant_authority": "production"}
try: operation._validate_body("CYCLE_ROUTE_V1", hostile_body)
except operation.OperationError: pass
else: raise AssertionError("cloud authority relabeling was accepted")

# Action output and API digests have distinct closed formats.
assert formal.upload_digest(d("upload")) == d("upload")
rejected(lambda: formal.upload_digest("sha256:" + d("upload")))
rejected(lambda: formal.archive_digest(d("archive")))

# API custody is exact-ID, sha256-prefixed, run-bound, complete, and canonical.
valid_custody = formal.validate_custody(custody(), expected)
assert [row["artifact_id"] for row in valid_custody["artifacts"]] == list(range(701, 708))
for mutation in ("id", "digest", "name", "expired", "run", "head", "missing", "extra"):
    hostile = artifact_api()
    if mutation == "id": hostile["artifacts"][1]["id"] = hostile["artifacts"][0]["id"]
    elif mutation == "digest": hostile["artifacts"][1]["digest"] = d("unprefixed")
    elif mutation == "name": hostile["artifacts"][1]["name"] = "wildcard-substitute"
    elif mutation == "expired": hostile["artifacts"][1]["expired"] = True
    elif mutation == "run": hostile["artifacts"][1]["workflow_run"]["id"] = 72
    elif mutation == "head": hostile["artifacts"][1]["workflow_run"]["head_sha"] = "4" * 40
    elif mutation == "missing": hostile["artifacts"].pop(); hostile["total_count"] = 6
    else: hostile["artifacts"].append(copy.deepcopy(hostile["artifacts"][-1])); hostile["total_count"] = 8
    rejected(lambda hostile=hostile: formal.custody_from_api(json.dumps(hostile).encode(), expected))
for mutation in ("attempt-bool", "ordinal-bool"):
    hostile = json.loads(custody())
    if mutation == "attempt-bool": hostile["workflow_run"]["attempt"] = True
    else: hostile["artifacts"][0]["ordinal"] = True
    rejected(lambda hostile=hostile: formal.validate_custody(formal.canonical(hostile), expected))

with tempfile.TemporaryDirectory() as cycle_parent:
    write_cycle(cycle_parent, 1)
    formal.validate_cycle_artifact_root(cycle_parent, expected, 1)
    write_cycle(cycle_parent, 2)
    rejected(lambda: formal.validate_cycle_artifact_root(cycle_parent, expected, 1))

with tempfile.TemporaryDirectory() as temporary:
    for ordinal in range(1, 8): write_cycle(temporary, ordinal)
    package_raw = aggregate(temporary)
    package = formal.decode(package_raw, 96 * 1024)
    assert package["version"] == "cogs.stage2-pre-aws-qualification-package/v5"
    assert "runtime_commitment" not in package
    assert package["runtime_manifest_sha256"] == runtime.sha256
    assert package["cycle_count"] == 7 and package["workload_measurements"] == 21
    schema_samples = {"package": package, "receipts": [json.loads(
        (Path(temporary) / f"cycle-{ordinal}/receipt.json").read_bytes()) for ordinal in range(1, 8)]}
    assert len({row["qmp_lineage"]["runtime_identity_sha256"] for row in schema_samples["receipts"]}) == 7
    assert len({row["qmp_lineage"]["qemu_process_sha256"] for row in schema_samples["receipts"]}) == 7
    assert package["qualification_revision"] == expected["EXPECTED_QUALIFICATION_HEAD"]
    assert package["source_bindings"] == receipt(1)["source_bindings"]
    assert package["cycle_artifact_custody"] == valid_custody
    assert package["mixed_preflight_run_id"] == 63
    assert package["static_control_observation"] == {
        "run_id": 61, "artifact_id": 62,
        "artifact_archive_digest": "sha256:" + d("static-archive")}
    assert package["cycle_artifact_custody_sha256"] == hashlib.sha256(custody()).hexdigest()
    assert [row["mode"] for row in package["cycles"]] == list(formal.CYCLE_MODES)
    assert [row["artifact_id"] for row in package["cycles"]] == list(range(701, 708))
    assert all(row["artifact_archive_digest"].startswith("sha256:") for row in package["cycles"])
    assert package["claims"] == {"formal_non_aws_qualification_passed": True,
        "aws_authorized": False, "aws_executed": False, "provider_executed": False,
        "promotion_authorized": False}
    for outcome in ("failure", "cancelled", "skipped", ""):
        rejected(lambda outcome=outcome: aggregate(temporary, outcome))
    rejected(lambda: aggregate(temporary, expected_value={**expected, "GITHUB_RUN_ATTEMPT": "2"}))

    # The actual package command owns exclusive storage, completes short writes,
    # fsyncs both files and both directories, and emits no upload-eligible success
    # on any write/persistence failure. No root/provider/KVM operation is used.
    with tempfile.TemporaryDirectory() as publication_root:
        parent = Path(publication_root); custody_path = parent / "custody.json"
        custody_path.write_bytes(custody())
        real_fsync, real_write = formal.os.fsync, formal.os.write
        for fault in (None, "zero-write", "write-error", "lying-write", 0, 1, 2, 3):
            destination = parent / f"package-{fault}"; calls = []
            def durable_fsync(fd):
                calls.append(stat.S_ISDIR(formal.os.fstat(fd).st_mode))
                if type(fault) is int and len(calls) - 1 == fault: raise OSError("fsync fault")
                return real_fsync(fd)
            def short_write(fd, raw):
                if fault == "zero-write": return 0
                if fault == "write-error": raise OSError("write fault")
                if fault == "lying-write": return len(raw)
                return real_write(fd, raw[:17])
            errors = io.StringIO(); output = io.StringIO()
            with patch.dict(formal.os.environ, {**expected, "CYCLE_JOB_RESULT": "success",
                    "CYCLE_AGGREGATE_ROOT": temporary, "CYCLE_CUSTODY_MAP": str(custody_path),
                    "PACKAGE_STAGING": str(destination)}, clear=True), patch.object(
                    sys, "argv", ["qualifier", "publish-package"]), patch.object(
                    formal.os, "fsync", side_effect=durable_fsync), patch.object(
                    formal.os, "write", side_effect=short_write), patch.object(
                    sys, "stdout", output), patch.object(sys, "stderr", errors):
                if fault is None: formal.cli()
                else:
                    try: formal.cli()
                    except SystemExit as error: assert error.code == 2
                    else: raise AssertionError("uncertain publication enabled upload")
            assert not output.getvalue()
            if fault is None:
                assert not errors.getvalue() and calls == [False, False, True, True]
                assert (destination / "pre-aws-package-v5.json").read_bytes() == package_raw
                assert (destination / "cycle-artifact-custody-v2.json").read_bytes() == custody()
                assert stat.S_IMODE(destination.stat().st_mode) == 0o555
            else: assert errors.getvalue() in {"stage2-formal-local-qualification: io.failed\n",
                                              "stage2-formal-local-qualification: validation.failed\n"}
            # Even failed/partial destinations are never retried or adopted.
            rejected(lambda: formal.publish_package(destination, temporary, custody(), expected, "success"))
            destination.chmod(0o700)
        published = parent / "package-None"; readback = parent / "readback"; readback.mkdir()
        for name in formal.PACKAGE_MEMBERS: (readback / name).write_bytes((published / name).read_bytes())
        formal.package_readback(published, readback)
        extra = readback / "extra"; extra.write_bytes(b"unexpected")
        rejected(lambda: formal.package_readback(published, readback)); extra.unlink()
        member = readback / "pre-aws-package-v5.json"; saved = member.read_bytes(); member.unlink()
        member.symlink_to(published / member.name)
        rejected(lambda: formal.package_readback(published, readback)); member.unlink()
        formal.os.link(published / member.name, member)
        rejected(lambda: formal.package_readback(published, readback)); member.unlink()
        member.write_bytes(saved + b" ")
        rejected(lambda: formal.package_readback(published, readback))
        for kind in ("file", "directory", "symlink"):
            path = parent / kind
            if kind == "file": path.write_bytes(b"must survive")
            elif kind == "directory": path.mkdir()
            else: path.symlink_to(published, target_is_directory=True)
            rejected(lambda: formal.publish_package(path, temporary, custody(), expected, "success"))
        assert (parent / "file").read_bytes() == b"must survive"
        with patch.object(formal, "aggregate", return_value=b"x" * (96 * 1024 + 1)):
            rejected(lambda: formal.publish_package(parent / "oversize", temporary, custody(), expected, "success"))
        assert not (parent / "oversize").exists()

    # Every immutable binding is common to all cycles; none is borrowed from cycle one.
    for binding in formal.SOURCE_KEYS:
        hostile = receipt(2)
        hostile["source_bindings"][binding] = ("3" * 40 if binding == "source_head"
                                                else d(f"hostile-{binding}"))
        rejected(lambda hostile=hostile: formal.validate_receipt(
            formal.canonical(hostile), expected, 2))

    # Every identity class, ordinal, artifact, status and canonical byte sequence is fail-closed.
    for identity in ("host_boot_id", "operation_token", "rootfs_token", "runtime",
                     "client_key_commitment", "host_key_commitment"):
        hostile = receipt(2); prior = receipt(1)
        if identity == "host_boot_id": hostile["timing"][identity] = prior["timing"][identity]
        elif identity == "runtime":
            qmp_names = ("qemu_argv_sha256", "qemu_pid", "qemu_starttime",
                "qemu_executable_device", "qemu_executable_inode", "observer_qmp_device",
                "observer_qmp_inode", "kvm_device", "kvm_inode", "kvm_rdev", "kvm_api")
            for name in qmp_names: hostile["qmp_lineage"][name] = prior["qmp_lineage"][name]
            hostile["qmp_lineage"]["runtime_identity_sha256"] = prior["qmp_lineage"]["runtime_identity_sha256"]
            hostile["runtime_readiness_lineage"]["runtime_identity_sha256"] = prior["qmp_lineage"]["runtime_identity_sha256"]
            hostile["runtime_readiness_lineage"]["qmp_identity"] = [
                hostile["qmp_lineage"][name] for name in qmp_names[1:]]
        elif identity.endswith("key_commitment"):
            hostile["key_freshness"][identity] = prior["key_freshness"][identity]
        else:
            hostile[identity] = prior[identity]
            if identity == "operation_token":
                hostile["runtime_readiness_lineage"]["operation_token"] = prior[identity]
        other = tempfile.TemporaryDirectory()
        try:
            for ordinal in range(1, 8): write_cycle(other.name, ordinal, hostile if ordinal == 2 else receipt(ordinal))
            rejected(lambda: aggregate(other.name))
        finally: other.cleanup()

    for left, right in (("operation_token", "rootfs_token"),):
        hostile = receipt(2); hostile[left] = receipt(1)[right]
        hostile["runtime_readiness_lineage"]["operation_token"] = hostile[left]
        other = tempfile.TemporaryDirectory()
        try:
            for ordinal in range(1, 8): write_cycle(other.name, ordinal, hostile if ordinal == 2 else receipt(ordinal))
            rejected(lambda: aggregate(other.name))
        finally: other.cleanup()
    for live_fact in ("mapping", "pre", "post", "post-from-pre", "pre-from-post"):
        hostile = receipt(3); prior = receipt(2)
        if live_fact == "mapping":
            hostile["qmp_lineage"]["live_mapping_sha256"] = prior["qmp_lineage"]["live_mapping_sha256"]
            hostile["runtime_readiness_lineage"]["live_mapping_sha256"] = prior["qmp_lineage"]["live_mapping_sha256"]
        elif live_fact == "pre":
            hostile["qmp_lineage"]["qemu_process_sha256"] = prior["qmp_lineage"]["qemu_process_sha256"]
        elif live_fact == "post":
            hostile["runtime_readiness_lineage"]["qemu_process_sha256"] = \
                prior["runtime_readiness_lineage"]["qemu_process_sha256"]
        elif live_fact == "post-from-pre":
            hostile["runtime_readiness_lineage"]["qemu_process_sha256"] = prior["qmp_lineage"]["qemu_process_sha256"]
        else:
            hostile["qmp_lineage"]["qemu_process_sha256"] = \
                prior["runtime_readiness_lineage"]["qemu_process_sha256"]
        other = tempfile.TemporaryDirectory()
        try:
            for ordinal in range(1, 8):
                write_cycle(other.name, ordinal, hostile if ordinal == 3 else receipt(ordinal))
            rejected(lambda: aggregate(other.name))
        finally: other.cleanup()

    hostile = receipt(2); hostile["key_freshness"]["client_key_commitment"] = receipt(1)["key_freshness"]["host_key_commitment"]
    other = tempfile.TemporaryDirectory()
    try:
        for ordinal in range(1, 8): write_cycle(other.name, ordinal, hostile if ordinal == 2 else receipt(ordinal))
        rejected(lambda: aggregate(other.name))
    finally: other.cleanup()

    mutations = []
    wrong = receipt(2); wrong["aws_authority"] = wrong["cycle_grant"]["grant_commitment"]; mutations.append(wrong)
    wrong = receipt(2); wrong["lifecycle_objects"]["task_launches"] = 2; mutations.append(wrong)
    wrong = receipt(2); wrong["cycle_grant"]["cycle_ordinal"] = 3; mutations.append(wrong)
    wrong = receipt(2); wrong["parser_source_sha256"] = d("substituted-parser"); mutations.append(wrong)
    wrong = receipt(2); wrong["workloads"] = []; mutations.append(wrong)
    wrong = receipt(1); wrong["workloads"] = wrong["workloads"][:-1]; mutations.append(wrong)
    wrong = receipt(1); wrong["workloads"][0]["ordinal"] = True; mutations.append(wrong)
    wrong = receipt(2); wrong["launch_attempts"] = True; mutations.append(wrong)
    wrong = receipt(2); wrong["lifecycle_objects"]["task_launches"] = True; mutations.append(wrong)
    wrong = receipt(2); wrong["unexpected"] = True; mutations.append(wrong)
    for hostile in mutations:
        rejected(lambda hostile=hostile: formal.validate_receipt(formal.canonical(hostile), expected,
                                                                  hostile["cycle_grant"]["cycle_ordinal"]))
    qmp_fields = ("qemu_pid", "qemu_starttime", "qemu_executable_device",
                  "qemu_executable_inode", "observer_qmp_device", "observer_qmp_inode",
                  "kvm_device", "kvm_inode", "kvm_rdev", "kvm_api")
    for index, name in enumerate(qmp_fields):
        hostile = receipt(2)
        hostile["runtime_readiness_lineage"]["qmp_identity"][index] += 1
        rejected(lambda hostile=hostile: formal.validate_receipt(
            formal.canonical(hostile), expected, 2))
    hostile = receipt(2)
    hostile["runtime_readiness_lineage"]["live_mapping_sha256"] = d("foreign-live-mapping")
    rejected(lambda: formal.validate_receipt(formal.canonical(hostile), expected, 2))
    hostile = receipt(2); qmp = hostile["qmp_lineage"]
    qmp["qemu_executable_inode"] = formal.SAFE_INTEGER + 1
    identity_value = {name: item for name, item in qmp.items()
                      if name not in {"live_mapping_sha256", "runtime_identity_sha256",
                                      "qemu_process_sha256"}}
    qmp["runtime_identity_sha256"] = hashlib.sha256(
        b"cogs.stage2-qemu-runtime-identity/v1\0" + formal.canonical(identity_value)).hexdigest()
    hostile["runtime_readiness_lineage"]["runtime_identity_sha256"] = qmp["runtime_identity_sha256"]
    hostile["runtime_readiness_lineage"]["qmp_identity"][3] = qmp["qemu_executable_inode"]
    rejected(lambda: formal.validate_receipt(formal.canonical(hostile), expected, 2))

    sample_raw = (Path(temporary) / "cycle-1/receipt.json").read_bytes()
    rejected(lambda: formal.validate_receipt(sample_raw[:-1], expected, 1))
    rejected(lambda: formal.validate_receipt(sample_raw + b" ", expected, 1))
    rejected(lambda: formal.validate_receipt(sample_raw.replace(b'{"authority":', b'{"authority":"x","authority":', 1), expected, 1))
    extra = Path(temporary) / "cycle-8"; extra.mkdir()
    rejected(lambda: aggregate(temporary)); extra.rmdir()
    missing = Path(temporary) / "cycle-7/status.json"; saved = missing.read_bytes(); missing.unlink()
    rejected(lambda: aggregate(temporary)); missing.write_bytes(saved)
    status_path = Path(temporary) / "cycle-7/status.json"; status_raw = status_path.read_bytes()
    status = json.loads(status_raw); status["workflow_run"]["attempt"] = True
    hostile_status = formal.canonical(status)
    rejected(lambda: formal.validate_status(hostile_status,
        (Path(temporary) / "cycle-7/receipt.json").read_bytes(), expected, 7))
    status = json.loads(status_raw); status["claims"]["aws_authorized"] = 0
    rejected(lambda: formal.validate_status(formal.canonical(status),
        (Path(temporary) / "cycle-7/receipt.json").read_bytes(), expected, 7))
    status = json.loads(status_raw); status["outcomes"]["recovery"] = "uncertain"
    status_path.write_bytes(formal.canonical(status)); rejected(lambda: aggregate(temporary))

# Static authentication is independent of agreement across receipts.
for ordinal in range(1, 8):
    wrong = receipt(ordinal)
    wrong["source_bindings"]["runtime_manifest_sha256"] = d("same-substitution-in-all-seven")
    rejected(lambda: formal.validate_receipt(formal.canonical(wrong), expected, ordinal))
for name in (formal.CONTROL_MEMBER, formal.ENVELOPE_MEMBER, formal.RUNTIME_MEMBER):
    path = formal.CONTROL_PACKAGE / name; saved = path.read_bytes()
    valid_raw = receipt_bytes(1)
    path.write_bytes(saved + b" ")
    try: rejected(lambda: formal.validate_receipt(valid_raw, expected, 1))
    finally: path.write_bytes(saved)

# Reproduce the historical producer mismatch on BOTH routes, without editing
# emitted JSON. The ordinary projection still does not supply a live attestation.
legacy = admission._host_bound_binding(base, runtime.value["executables"])
assert set(legacy) == admission.BINDING_KEYS - {"runtime_attestation_sha256"}
assert "runtime_manifest_sha256" not in legacy
rejected(lambda: admission._static_manifest_binding(base,
    admission.preparation.StaticDescription(runtime.raw, d("not-held-bytes"), runtime.value)))
changed_runtime = copy.deepcopy(runtime.value)
changed_runtime["executables"][0]["executable_sha256"] = d("not-held-executable")
rejected(lambda: admission._static_manifest_binding(base,
    admission.preparation.StaticDescription(runtime.raw, runtime.sha256, changed_runtime)))
for ordinal in (1, 2):
    _, _, old_issue, _, old_consume = cycle_evidence._new_cycle_receipt_routes(
        lambda raw: fixture_records[raw],
        lambda _custody: admission._host_bound_binding(base, runtime.value["executables"]),
        reject_diagnostic, close_custody)
    route, lifecycle = terminal(ordinal)
    raw = old_consume(old_issue(route, lifecycle))
    try: formal.validate_receipt(raw, expected, ordinal)
    except formal.FormalQualificationError as error:
        assert error.code == "receipt.source_bindings.keyset"
    else: raise AssertionError("old producer projection accepted")
    assert lifecycle.static_custody.close_attempts == 1
    wrong = receipt(ordinal); wrong["cycle_grant"]["result_schema_sha256"] = d("old-schema")
    rejected(lambda: formal.validate_receipt(formal.canonical(wrong), expected, ordinal))
    wrong = receipt(ordinal); wrong["version"] = "cogs.stage2-formal-local-cycle-receipt/v1"
    rejected(lambda: formal.validate_receipt(formal.canonical(wrong), expected, ordinal))

# Even an internally valid stale-schema grant is rejected, independently of its
# commitment and expected-environment equality. Local minting also rejects it.
stale_expected = {**expected, "EXPECTED_RESULT_SCHEMA_SHA256": d("stale-schema")}
rejected(lambda: formal.issue_grant(1, stale_expected, authority))
stale_fields = authority.asdict(grants[0])
for name in ("authority", "batch_commitment", "grant_commitment"): stale_fields.pop(name)
stale_fields["result_schema_sha256"] = d("stale-schema")
stale_grant = authority.issue(stale_fields)
wrong = receipt(1); wrong_grant = authority.asdict(stale_grant)
wrong_grant["cycle_ordinal"] = wrong_grant.pop("ordinal")
wrong["cycle_grant"] = wrong_grant
wrong["formal_qualification_authority"] = stale_grant.grant_commitment
try: formal.validate_receipt(formal.canonical(wrong))
except formal.FormalQualificationError as error: assert error.code == "receipt.schema"
else: raise AssertionError("stale result schema accepted")

# Typed owner/transaction failures close exactly once and mint nothing.
settle = inspect.getclosurevars(issue).nonlocals["settle"]
registry = inspect.getclosurevars(settle).nonlocals["receipts"]
assert not registry
for ordinal in (1, 2):
    faults = ("parser", "teardown", "residue", "wrong-owner", "grant-mode", "extra-launch")
    if ordinal == 2: faults += ("durable-role", "mount-lineage", "network-lineage")
    for fault in faults:
        route, lifecycle = terminal(ordinal)
        rows = fixture_records[lifecycle.retired.raw]
        if fault == "parser":
            next(row for row in rows if row.record_type == "SSH_COMMAND_SETTLED_V1").body["parser_sha256"] = d("wrong-parser")
        elif fault == "teardown": rows.pop(-2)
        elif fault == "residue":
            rejected(lambda: owners._ResidueOwnerResult(lifecycle.residue.operation_token,
                lifecycle.residue.final_baselines_sha256, local.RESIDUE_FACTS[:-1]))
            lifecycle.residue = owners._ResidueOwnerResult(d("wrong-operation"),
                lifecycle.residue.final_baselines_sha256, local.RESIDUE_FACTS)
        elif fault == "wrong-owner":
            _, other = terminal(2 if ordinal == 1 else 1)
            lifecycle.runtime_proof = other.runtime_proof
        elif fault == "grant-mode":
            next(row for row in rows if row.record_type == "CYCLE_ROUTE_V1").body["route"] = "readiness" if ordinal == 1 else "full"
        elif fault == "durable-role":
            role = next(row for row in rows if row.record_type == "RUNTIME_ROLE_IDENTITIES_V1").body["roles"][0]
            role["executable_inode"] += 1
        elif fault == "mount-lineage":
            next(row for row in rows if row.record_type == "RUNTIME_MOUNT_V2").body["issuance_sha256"] = d("foreign-mount")
        elif fault == "network-lineage":
            next(row for row in rows if row.record_type == "NETWORK_SNAPSHOT_V2").body["proof_sha256"] = d("foreign-network")
        else: rows.insert(3, next(row for row in rows if row.record_type == "CTR_LAUNCH_ISSUED_V1"))
        rejected(lambda: issue(route, lifecycle))
        assert lifecycle.static_custody.close_attempts == 1 and not registry

def close_fault(custody):
    close_custody(custody)
    raise OSError("private close detail must not escape")
_, _, failing_issue, _, failing_consume = cycle_evidence._new_cycle_receipt_routes(
    lambda raw: fixture_records[raw], project_custody, reject_diagnostic, close_fault)
failing_registry = inspect.getclosurevars(inspect.getclosurevars(failing_issue).nonlocals["settle"]).nonlocals["receipts"]
for ordinal in (1, 2):
    route, lifecycle = terminal(ordinal)
    rejected(lambda: failing_issue(route, lifecycle))
    assert lifecycle.static_custody.close_attempts == 1 and not failing_registry
    rejected(lambda: failing_consume(object()))
    diagnostic = cycle_evidence._diagnostic_full_route() if ordinal == 1 else cycle_evidence._diagnostic_readiness_route()
    route, lifecycle = terminal(ordinal)
    rejected(lambda: issue(diagnostic, lifecycle))
    assert lifecycle.static_custody.close_attempts == 0 and not registry

# Guard verifies actual self-contained schema bytes, not a stale constant or an
# environment-supplied replacement. Synthetic H/G avoids reviving retired pins.
assert guard.REVIEWED_RESULT_SCHEMA_SHA256 == expected["EXPECTED_RESULT_SCHEMA_SHA256"]
assert "$ref\": \"https://" not in guard.RESULT_SCHEMA.read_text()
guard_environment = {
    "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "nenb/cogs",
    "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true",
    "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "71", "PRE_EFFECT_ADMITTED_RUN_ID": "71",
    "EXACT_IMPLEMENTATION_HEAD": expected["EXPECTED_IMPLEMENTATION_HEAD"],
    "CONFIGURED_IMPLEMENTATION_HEAD": expected["EXPECTED_IMPLEMENTATION_HEAD"],
    "EXACT_CONTROL_HEAD": expected["EXPECTED_CONTROL_HEAD"],
    "CONFIGURED_CONTROL_HEAD": expected["EXPECTED_CONTROL_HEAD"],
    "EXACT_QUALIFICATION_HEAD": expected["EXPECTED_QUALIFICATION_HEAD"],
    "CONFIGURED_QUALIFICATION_HEAD": expected["EXPECTED_QUALIFICATION_HEAD"],
    "GITHUB_SHA": expected["EXPECTED_QUALIFICATION_HEAD"],
    "GITHUB_ACTOR": "fixture-actor", "CONFIGURED_AUTHORIZED_ACTOR": "fixture-actor",
    "GITHUB_WORKFLOW_REF": "nenb/cogs/.github/workflows/stage2-prebuilt-local-kata-qualification.yml@refs/heads/main"}
guard_event = {"repository": {"full_name": "nenb/cogs"}, "inputs": {
    "reviewed_implementation_head": expected["EXPECTED_IMPLEMENTATION_HEAD"],
    "reviewed_control_head": expected["EXPECTED_CONTROL_HEAD"],
    "reviewed_qualification_head": expected["EXPECTED_QUALIFICATION_HEAD"]}}
with tempfile.TemporaryDirectory() as source_root:
    source_root = Path(source_root)
    for row in selected:
        path = source_root / row["path"]; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / row["path"]).read_bytes())
    with patch.multiple(guard, ROOT=source_root, CONTROL=formal.CONTROL_PACKAGE / formal.CONTROL_MEMBER,
            WORKFLOW=source_root / guard.WORKFLOW.relative_to(ROOT),
            RESULT_SCHEMA=source_root / guard.RESULT_SCHEMA.relative_to(ROOT),
            REVIEWED_IMPLEMENTATION_HEAD=expected["EXPECTED_IMPLEMENTATION_HEAD"],
            REVIEWED_CONTROL_HEAD=expected["EXPECTED_CONTROL_HEAD"],
            REVIEWED_IMPLEMENTATION_MANIFEST_SHA256=expected["EXPECTED_SOURCE_MANIFEST_SHA256"],
            REVIEWED_CONTROL_SHA256=expected["EXPECTED_CONTROL_SHA256"],
            REVIEWED_ROOTFS_DESCRIPTOR_SHA256=expected["EXPECTED_ROOTFS_DESCRIPTOR_SHA256"],
            REVIEWED_WORKFLOW_SHA256=hashlib.sha256(guard.WORKFLOW.read_bytes()).hexdigest(),
            REVIEWED_STATIC_CONTROL_RUN_ID=61, REVIEWED_STATIC_CONTROL_ARTIFACT_ID=62,
            REVIEWED_STATIC_CONTROL_ARTIFACT_DIGEST=expected["EXPECTED_STATIC_CONTROL_ARTIFACT_DIGEST"]):
        assert guard.guard(guard_environment, guard_event)["result_schema_sha256"] == expected["EXPECTED_RESULT_SCHEMA_SHA256"]
        # Every selected H-owned consumer rejects a Q-only substitution before
        # the effect sentinel, including the qualifier, schema and cleanup owner.
        for row in selected:
            path = source_root / row["path"]; saved = path.read_bytes(); path.write_bytes(saved + b" ")
            try:
                if row["path"] == guard.Q_BINDING_ADAPTER: guard.guard(guard_environment, guard_event)
                else: rejected(lambda: guard.guard(guard_environment, guard_event))
            finally: path.write_bytes(saved)
        with patch.object(guard, "REVIEWED_RESULT_SCHEMA_SHA256", d("stale-schema")):
            rejected(lambda: guard.guard(guard_environment, guard_event))
        for name in (formal.CONTROL_MEMBER, formal.ENVELOPE_MEMBER, formal.RUNTIME_MEMBER):
            path = formal.CONTROL_PACKAGE / name; saved = path.read_bytes(); path.write_bytes(saved + b" ")
            try: rejected(lambda: guard.guard(guard_environment, guard_event))
            finally: path.write_bytes(saved)
        # Coherently rehashed control mutations still cannot omit mandatory
        # consumers or change directional envelope/runtime bindings.
        for fault in ("missing", "duplicate", "source-digest", "envelope", "runtime"):
            changed = copy.deepcopy(control); changed_envelope = copy.deepcopy(envelope)
            if fault == "missing":
                changed["implementation"]["selected_sources"] = [row for row in selected
                    if row["path"] != "scripts/stage2-formal-local-qualification.py"]
            elif fault == "duplicate": changed["implementation"]["selected_sources"].append(selected[-1])
            changed["implementation"]["selected_sources_sha256"] = (d("wrong") if fault == "source-digest"
                else hashlib.sha256(formal.canonical(changed["implementation"]["selected_sources"])).hexdigest())
            changed_envelope["implementation"] = copy.deepcopy(changed["implementation"])
            if fault == "envelope": changed_envelope["control_revision"] = "4" * 40
            if fault == "runtime": changed_envelope["runtime"]["manifest_sha256"] = d("wrong")
            changed_envelope_raw = formal.canonical(changed_envelope)
            row = next(row for row in changed["members"] if row["kind"] == "envelope")
            row.update(size=len(changed_envelope_raw), sha256=hashlib.sha256(changed_envelope_raw).hexdigest())
            path = formal.CONTROL_PACKAGE / formal.CONTROL_MEMBER
            envelope_path = formal.CONTROL_PACKAGE / formal.ENVELOPE_MEMBER
            changed_raw = formal.canonical(changed); path.write_bytes(changed_raw)
            envelope_path.write_bytes(changed_envelope_raw)
            try:
                with patch.object(guard, "REVIEWED_CONTROL_SHA256", hashlib.sha256(changed_raw).hexdigest()):
                    rejected(lambda: guard.guard(guard_environment, guard_event))
            finally:
                path.write_bytes(control_raw); envelope_path.write_bytes(formal.canonical(envelope))
        path = source_root / "scripts"; path.rename(source_root / "scripts-held")
        path.symlink_to(source_root / "scripts-held", target_is_directory=True)
        rejected(lambda: guard.guard(guard_environment, guard_event)); path.unlink()
        (source_root / "scripts-held").rename(path)
# The only bootstrap import is sealed before compilation/execution; a Q-only
# retirement script substitution cannot run even before ordinary admission.
with patch.object(guard, "_read_bytes", return_value=b'raise RuntimeError("EFFECT")\n'), patch(
        "builtins.exec", side_effect=AssertionError("unverified source executed")):
    rejected(guard._load_retirement)
# Retired operational constants reject before opening any package or source.
with patch.object(guard, "_read_bytes", side_effect=AssertionError("pre-effect read")):
    rejected(lambda: guard.guard(guard_environment, guard_event))

# CLI diagnostics are bounded categories only, with unchanged failure exit status.
for module, faults in ((formal, [formal.FormalQualificationError("receipt.source_bindings.keyset"),
                                OSError("secret-file-path"), ValueError("private-receipt")]),
                       (guard, [guard.GuardError("receipt.schema"), OSError("secret-file-path")])):
    for fault in faults:
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(module, "main", side_effect=fault), patch.object(sys, "stdout", output), patch.object(sys, "stderr", errors):
            try: module.cli()
            except SystemExit as error: assert error.code == 2
            else: raise AssertionError("CLI failure accepted")
        assert output.getvalue() == "" and len(errors.getvalue()) < 120
        expected_code = (fault.code if isinstance(fault, formal.FormalQualificationError) else
                         "io.failed" if isinstance(fault, OSError) else
                         "receipt.schema" if isinstance(fault, guard.GuardError) else "input.invalid")
        prefix = "stage2-formal-local-qualification" if module is formal else "stage2-prebuilt-local-qualification-guard"
        assert errors.getvalue() == f"{prefix}: {expected_code}\n"

# Formal owner entrypoints collapse private initialization/owner errors to one
# fixed bounded diagnostic while preserving failure and emitting no receipt.
for module, owner_name, diagnostic in (
        (formal_full_entry, "_run_formal_local_full_cycle",
         b"stage2-formal-cycle-full: owner.failed\n"),
        (formal_readiness_entry, "_run_formal_local_readiness_cycle",
         b"stage2-formal-cycle-readiness: owner.failed\n")):
    errors = bytearray()
    def diagnostic_write(descriptor, raw):
        assert descriptor == 2 and raw == diagnostic
        errors.extend(raw); return len(raw)
    with patch.object(module.coordinator, owner_name,
            side_effect=OSError("/private/secret " + "AKIA" + "ABCDEFGHIJKLMNOP")), patch.object(
            module.os, "write", side_effect=diagnostic_write):
        try: module.cli()
        except SystemExit as error: assert error.code == 2
        else: raise AssertionError("formal owner failure returned success")
    assert bytes(errors) == diagnostic

# Publication uses test-owned storage and simulated ownership only: never a real
# root publication. The actual writer/readback and directory fsync are exercised.
for directory_fault in (False, True):
    with tempfile.TemporaryDirectory(
            dir="/private/tmp" if Path("/private/tmp").is_dir() else None) as temporary:
        parent = Path(temporary) / "cogs-stage2-local-result-71-1"
        parent.mkdir(mode=0o700); parent.chmod(0o700)
        path = parent / "cycle-1"; path.mkdir(mode=0o700); path.chmod(0o700)
        source = path / "receipt.partial"; source.write_bytes(receipt_bytes(1))
        calls = []; real_fsync = formal.os.fsync; real_write = formal.os.write
        real_stat = formal.os.stat; real_fstat = formal.os.fstat
        ancestor_inode = Path(temporary).stat().st_ino
        def publication_fstat(descriptor):
            seen = real_fstat(descriptor)
            if seen.st_ino == ancestor_inode:
                values = {name: getattr(seen, name) for name in dir(seen) if name.startswith("st_")}
                values["st_uid"] = 0; values["st_mode"] |= stat.S_ISVTX
                return SimpleNamespace(**values)
            return seen
        def publication_stat(target, *args, **kwargs):
            seen = real_stat(target, *args, **kwargs)
            if target in {"cycle-1", "cogs-stage2-local-result-71-1"} and kwargs.get("dir_fd") is not None:
                values = {name: getattr(seen, name) for name in dir(seen) if name.startswith("st_")}
                values["st_uid"] = 0
                return SimpleNamespace(**values)
            return seen
        def publication_fsync(descriptor):
            is_directory = stat.S_ISDIR(formal.os.fstat(descriptor).st_mode)
            calls.append(is_directory)
            if is_directory and directory_fault: raise OSError("directory fsync fault")
            return real_fsync(descriptor)
        try:
            with patch.object(formal, "CYCLE_PUBLICATION_ROOT", Path(temporary)), patch.object(
                    formal.os, "geteuid", return_value=0), patch.object(formal.os, "chown"), patch.object(
                    formal.os, "fchown"), patch.object(formal.os, "fstat", side_effect=publication_fstat), patch.object(
                    formal.os, "stat", side_effect=publication_stat), patch.object(
                    formal.os, "fsync", side_effect=publication_fsync), patch.object(
                    formal.os, "write", side_effect=lambda fd, raw: real_write(fd, raw[:17])):
                if directory_fault: rejected(lambda: formal.publish(path, expected, 1, source.stat().st_uid))
                else: formal.publish(path, expected, 1, source.stat().st_uid)
            assert calls == ([False, False, True] if directory_fault else
                             [False, False, True, True, True])
            assert set(path.iterdir()) == {path / "receipt.json", path / "status.json"}
            if not directory_fault: formal.validate_cycle_artifact_root(path.parent, expected, 1)
        finally:
            path.chmod(0o700); parent.chmod(0o700)

# A pathname alias cannot redirect root publication into a foreign directory.
with tempfile.TemporaryDirectory(
        dir="/private/tmp" if Path("/private/tmp").is_dir() else None) as temporary:
    parent = Path(temporary) / "cogs-stage2-local-result-71-1"
    parent.mkdir(mode=0o700); parent.chmod(0o700)
    foreign = Path(temporary) / "foreign"; foreign.mkdir(mode=0o700); foreign.chmod(0o700)
    path = parent / "cycle-1"; path.symlink_to(foreign, target_is_directory=True)
    (foreign / "receipt.partial").write_bytes(receipt_bytes(1))
    before = set(foreign.iterdir()); real_fstat = formal.os.fstat
    ancestor_inode = Path(temporary).stat().st_ino
    def trusted_ancestor(descriptor):
        seen = real_fstat(descriptor)
        if seen.st_ino == ancestor_inode:
            values = {name: getattr(seen, name) for name in dir(seen) if name.startswith("st_")}
            values["st_uid"] = 0; values["st_mode"] |= stat.S_ISVTX
            return SimpleNamespace(**values)
        return seen
    with patch.object(formal, "CYCLE_PUBLICATION_ROOT", Path(temporary)), patch.object(
            formal.os, "geteuid", return_value=0), patch.object(
            formal.os, "fstat", side_effect=trusted_ancestor):
        rejected(lambda: formal.publish(path, expected, 1, (foreign / "receipt.partial").stat().st_uid))
    assert set(foreign.iterdir()) == before

# Grant publication fsyncs the containing directory and fails closed on that boundary.
grant_environment = {**expected, "FORMAL_CYCLE_ORDINAL": "1"}
with tempfile.TemporaryDirectory() as temporary:
    authority.ROOT = Path(temporary) / "formal-authority"
    calls = []
    real_fsync = formal.os.fsync
    def observe_fsync(descriptor):
        calls.append(stat.S_ISDIR(formal.os.fstat(descriptor).st_mode)); return real_fsync(descriptor)
    with patch.object(formal.os, "geteuid", return_value=0), patch.object(
            formal.os, "chown", return_value=None), patch.object(
            formal.os, "fsync", side_effect=observe_fsync):
        formal.materialize_grant(grant_environment, authority=authority)
    assert calls == [False, True]
with tempfile.TemporaryDirectory() as temporary:
    authority.ROOT = Path(temporary) / "formal-authority"
    real_fsync = formal.os.fsync
    def reject_directory_fsync(descriptor):
        if stat.S_ISDIR(formal.os.fstat(descriptor).st_mode): raise OSError("directory fsync fault")
        return real_fsync(descriptor)
    with patch.object(formal.os, "geteuid", return_value=0), patch.object(
            formal.os, "chown", return_value=None), patch.object(
            formal.os, "fsync", side_effect=reject_directory_fsync):
        rejected(lambda: formal.materialize_grant(grant_environment, authority=authority))

# Consumption fsyncs the grant directory after unlink and its ancestor after rmdir.
with tempfile.TemporaryDirectory() as temporary:
    parent = Path(temporary) / "cycle"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    path = parent / "grant.json"; path.write_bytes(authority.encode(grants[0])); path.chmod(0o400)
    owner = parent.lstat(); calls = []
    real_fsync = authority.os.fsync
    def observe_consume_fsync(descriptor):
        calls.append(authority.os.fstat(descriptor).st_ino); return real_fsync(descriptor)
    with patch.object(authority.os, "fsync", side_effect=observe_consume_fsync):
        assert authority._read_fixed(path, "full", (owner.st_uid, owner.st_gid)) == grants[0]
    assert len(calls) == 2 and calls[0] == owner.st_ino and calls[1] == Path(temporary).stat().st_ino
with tempfile.TemporaryDirectory() as temporary:
    parent = Path(temporary) / "cycle"; parent.mkdir(mode=0o700); parent.chmod(0o700)
    path = parent / "grant.json"; path.write_bytes(authority.encode(grants[0])); path.chmod(0o400)
    owner = parent.lstat(); calls = []
    real_fsync = authority.os.fsync
    def fault_after_rmdir(descriptor):
        calls.append(descriptor)
        if len(calls) == 2: raise OSError("ancestor fsync fault")
        return real_fsync(descriptor)
    with patch.object(authority.os, "fsync", side_effect=fault_after_rmdir):
        rejected(lambda: authority._read_fixed(path, "full", (owner.st_uid, owner.st_gid)))
    assert not parent.exists() and len(calls) == 2

control_fixture.cleanup()
if sys.argv[1:] == ["--schema-samples"]:
    sys.stdout.buffer.write(formal.canonical(schema_samples))
else:
    assert len(sys.argv) == 1
    print("stage2 formal seven-cycle qualification hostile checks passed")

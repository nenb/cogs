#!/usr/bin/env python3
"""In-process pure-fixture checks; no command, provider, or network invocation."""
import copy
import ctypes  # Initialize stdlib before blocking all subsequent native calls.
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_campaign_production as production


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def d(value): return hashlib.sha256(value.encode()).hexdigest()
def canonical(value): return production._canonical(value) + b"\n"
def sha(value): return hashlib.sha256(canonical(value)).hexdigest()


def bind_grants(package):
    """Use the actual producer's grant codec, not the consumer's hash helper."""
    authority = load("qualification_fixture_authority",
        "deploy/aws-feasibility/remote/completion_formal_cycle_authority.py")
    run = package["cycle_artifact_custody"]["workflow_run"]
    for cycle in package["cycles"]:
        grant = authority.issue({**{name: package[name] for name in (
            "implementation_revision", "control_revision", "source_manifest_sha256",
            "static_control_sha256", "workflow_sha256", "result_schema_sha256",
            "rootfs_descriptor_sha256")}, "ordinal": cycle["ordinal"], "mode": cycle["mode"],
            "workflow_run_id": run["id"], "workflow_run_attempt": run["attempt"]})
        package["batch_commitment"] = grant.batch_commitment
        cycle["grant_commitment"] = grant.grant_commitment


def qualification_package(bindings, control_sha256):
    """Complete synthetic v5 projection for the planner's fake command fixture."""
    package = {
        "version": "cogs.stage2-pre-aws-qualification-package/v5",
        "authority": "non-aws-prerequisite-evidence-only",
        "implementation_revision": bindings["source_head"], "control_revision": "2" * 40,
        "qualification_revision": "3" * 40,
        "source_manifest_sha256": bindings["source_manifest_sha256"],
        "static_control_sha256": control_sha256,
        "workflow_sha256": hashlib.sha256((ROOT /
            ".github/workflows/stage2-prebuilt-local-kata-qualification.yml").read_bytes()).hexdigest(),
        "result_schema_sha256": hashlib.sha256((ROOT /
            "schemas/stage2-formal-local-cycle-receipt-v2.json").read_bytes()).hexdigest(),
        "rootfs_descriptor_sha256": bindings["rootfs_descriptor_sha256"],
        "runtime_manifest_sha256": bindings["runtime_manifest_sha256"],
        "fixture_commitment": bindings["final_pin_sha256"], "source_bindings": bindings,
        "cycle_count": 7, "workload_measurements": 21,
        "cycle_artifact_custody": {
            "version": "cogs.stage2-formal-local-artifact-custody/v2",
            "authority": "authenticated-github-actions-api-cycle-artifact-custody-only",
            "repository": "nenb/cogs", "workflow_run": {"id": 71, "attempt": 1, "head_sha": "3" * 40},
            "artifacts": []},
        "mixed_preflight_run_id": 63,
        "static_control_observation": {"run_id": 61, "artifact_id": 62,
            "artifact_archive_digest": "sha256:" + d("static-archive")},
        "cycles": [],
        "predecessor_versions": [f"cogs.stage2-pre-aws-qualification-package/v{i}" for i in range(1, 5)],
        "claims": {"formal_non_aws_qualification_passed": True, "aws_authorized": False,
            "aws_executed": False, "provider_executed": False, "promotion_authorized": False},
    }
    for ordinal in range(1, 8):
        name = f"stage2-formal-cycle-{ordinal}-{bindings['source_head']}-{'2' * 40}-71-1"
        artifact = {"ordinal": ordinal, "name": name, "artifact_id": 700 + ordinal,
                    "archive_digest": "sha256:" + d(f"archive-{ordinal}")}
        package["cycle_artifact_custody"]["artifacts"].append(artifact)
        package["cycles"].append({"ordinal": ordinal, "mode": "full" if ordinal == 1 else "readiness",
            "receipt_sha256": d(f"receipt-{ordinal}"), "status_sha256": d(f"status-{ordinal}"),
            "artifact_name": name, "artifact_id": artifact["artifact_id"],
            "artifact_archive_digest": artifact["archive_digest"],
            "identities": {"host_boot_id": f"0000000{ordinal}-0000-4000-8000-00000000000{ordinal}",
                **{role: d(f"{role}-{ordinal}") for role in (
                    "operation", "rootfs", "runtime", "client_key", "host_key")}}})
    package["cycle_artifact_custody_sha256"] = sha(package["cycle_artifact_custody"])
    bind_grants(package)
    return package


def draft_for(package):
    bindings = package["source_bindings"]
    value = {
        "version": "cogs.stage2-production-approval-draft/v3",
        **{name: package[name] for name in ("implementation_revision", "control_revision",
            "qualification_revision", "source_manifest_sha256", "static_control_sha256",
            "rootfs_descriptor_sha256", "runtime_manifest_sha256", "fixture_commitment")},
        "source_bindings_sha256": production._commit(b"cogs.stage2-source-bindings/v1", bindings),
        "pre_aws_package_sha256": sha(package),
        **{name: bindings[name] for name in ("rootfs_package_manifest_sha256",
            "rootfs_provenance_sha256", "rootfs_publication_receipt_sha256")},
        "rootfs_qualification_receipt_sha256": d("qualification"),
        "provider_binary_sha256": d("provider"), "aws_cli_sha256": d("aws"),
        "account_commitment": d("account"), "partition": "aws", "region": "us-east-1",
        "ami_id": "ami-" + "a" * 17, "ami_owner_id": "099720109477",
        "ami_architecture": "x86_64", "ami_virtualization_type": "hvm",
        "ami_root_device_type": "ebs", "ami_state": "available",
        "plan_sha256s": [d(f"plan-{index}") for index in range(7)],
        "not_before_unix_ns": 1, "effect_deadline_ns": 90 * 60 * 10**9,
        "cleanup_reserve_ns": 10 * 60 * 10**9, "expires_unix_ns": 101 * 60 * 10**9,
        "maximum_cycle_duration_ns": 10 * 60 * 10**9, "maximum_cost_micro_usd": 499_999,
        "executor_principal_commitment": d("executor"),
        "inventory_observer_principal_commitment": d("observer"),
    }
    value["ami_commitment"] = production.resolved_ami_commitment(value)
    return value


def hostile_packages(package):
    # Every required root/nested member is required, and no extension is accepted.
    def objects(value, path=()):
        if type(value) is dict:
            yield path, value
            for name, child in value.items(): yield from objects(child, (*path, name))
        elif type(value) is list:
            for index, child in enumerate(value): yield from objects(child, (*path, index))
    for path, obj in objects(package):
        for key in (*obj, "unexpected"):
            candidate = copy.deepcopy(package); target = candidate
            for part in path: target = target[part]
            if key == "unexpected": target[key] = "historical"
            else: del target[key]
            yield f"inventory-{path}-{key}", candidate

    def mutate(label, action, grants=False):
        candidate = copy.deepcopy(package); action(candidate)
        if grants: bind_grants(candidate)
        candidate["cycle_artifact_custody_sha256"] = sha(candidate["cycle_artifact_custody"])
        return label, candidate
    for version in range(1, 5):
        yield mutate(f"package-v{version}", lambda p: p.update(
            version=f"cogs.stage2-pre-aws-qualification-package/v{version}"))
    for field in ("workflow_sha256", "result_schema_sha256"):
        # All grants, batch, custody hash, and outer approval hashes are re-bound.
        yield mutate("coherent-" + field, lambda p: p.update({field: d("historical-contract")}), True)
    for value in (2, True, 1.0, "1"):
        yield mutate("attempt-" + repr(value), lambda p: p["cycle_artifact_custody"]["workflow_run"].update(
            attempt=value))
    for field in ("batch_commitment", "cycle_artifact_custody_sha256"):
        candidate = copy.deepcopy(package); candidate[field] = d("wrong-hash")
        yield field, candidate
    yield mutate("custody-v1", lambda p: p["cycle_artifact_custody"].update(
        version="cogs.stage2-formal-local-artifact-custody/v1"))
    yield mutate("custody-authority", lambda p: p["cycle_artifact_custody"].update(authority="historical"))
    yield mutate("custody-repository", lambda p: p["cycle_artifact_custody"].update(repository="other/cogs"))
    yield mutate("custody-head", lambda p: p["cycle_artifact_custody"]["workflow_run"].update(head_sha="4" * 40))
    yield mutate("predecessors", lambda p: p["predecessor_versions"].pop())
    yield mutate("legacy-field", lambda p: p["source_bindings"].update(runtime_attestation_sha256=d("live")))
    yield mutate("static-drift", lambda p: p["source_bindings"].update(runtime_manifest_sha256=d("drift")))
    def live_as_static(p):
        p["runtime_manifest_sha256"] = p["cycles"][0]["identities"]["runtime"]
        p["source_bindings"]["runtime_manifest_sha256"] = p["runtime_manifest_sha256"]
    yield mutate("coherent-live-as-static", live_as_static)
    yield mutate("claims", lambda p: p["claims"].update(formal_non_aws_qualification_passed=1))
    yield mutate("retired-run", lambda p: p.update(mixed_preflight_run_id=34301325559))
    yield mutate("retired-custody-run", lambda p: p["cycle_artifact_custody"]["workflow_run"].update(
        id=34302034014), True)
    yield mutate("reused-run", lambda p: p.update(mixed_preflight_run_id=p["static_control_observation"]["run_id"]))
    for field in ("cycle_count", "workload_measurements", "mixed_preflight_run_id"):
        yield mutate("type-" + field, lambda p: p.update({field: True}))
    for field in ("grant_commitment", "receipt_sha256", "status_sha256"):
        for value in ("G" * 64, None, True):
            yield mutate("hash-type-" + field, lambda p: p["cycles"][0].update({field: value}))
        yield mutate("duplicate-" + field, lambda p: p["cycles"][1].update({field: p["cycles"][0][field]}))
    for field in ("ordinal", "mode", "artifact_name", "artifact_id", "artifact_archive_digest"):
        yield mutate("cycle-drift-" + field, lambda p: p["cycles"][0].update({field: p["cycles"][1][field]}))
    for role in package["cycles"][0]["identities"]:
        yield mutate("reused-" + role, lambda p: p["cycles"][1]["identities"].update(
            {role: p["cycles"][0]["identities"][role]}))
        yield mutate("invalid-" + role, lambda p: p["cycles"][0]["identities"].update({role: "invalid"}))
    for left, right in (("operation", "rootfs"), ("client_key", "host_key")):
        yield mutate("cross-role-" + left, lambda p: p["cycles"][1]["identities"].update(
            {right: p["cycles"][0]["identities"][left]}))
    for field, other in (("artifact_id", "artifact_id"), ("archive_digest", "artifact_archive_digest"),
                         ("name", "artifact_name")):
        for label, value in (("duplicate", package["cycle_artifact_custody"]["artifacts"][1][field]),
                ("static", package["static_control_observation"].get(other, "wrong-name")),
                ("retired", 10082440691 if field == "artifact_id" else "historical")):
            def substitute(p):
                p["cycle_artifact_custody"]["artifacts"][0][field] = value
                p["cycles"][0][other] = value
            yield mutate(f"coherent-{label}-{field}", substitute)
    for collection in ("cycles", "artifacts"):
        def rows(p): return p["cycles"] if collection == "cycles" else p["cycle_artifact_custody"]["artifacts"]
        yield mutate("missing-" + collection, lambda p: rows(p).pop())
        yield mutate("extra-" + collection, lambda p: rows(p).append(copy.deepcopy(rows(p)[0])))
        yield mutate("reordered-" + collection, lambda p: rows(p).reverse())
    for field in ("implementation_revision", "control_revision", "qualification_revision"):
        yield mutate("retired-" + field, lambda p: p.update({field: "c10fc103532f3e3a8b746727bd0f48c6d8498148"}))


def compose_campaign(formal, package_raw, approval_raw, authentication_raw):
    """Actual byte codecs; only terminal owners and effect/durability ports are fake."""
    import completion_campaign_remote_adapter as adapter
    import completion_campaign_evidence_issuer as evidence_issuer
    import completion_cycle_authority as authority
    import completion_cycle_evidence as cycle_evidence

    with patch.object(sys, "stdout", io.StringIO()):
        fixtures = runpy.run_path(str(ROOT / "test/aws-stage2-completion-campaign-production.py"))
    value = json.loads(approval_raw)
    value["plan_sha256s"] = tuple(value["plan_sha256s"])
    approval = production.ProductionApproval(**value)
    package = json.loads(package_raw)
    production.validate_approval_package(approval, package, hashlib.sha256(package_raw).hexdigest())
    authentication = json.loads(authentication_raw)
    assert authentication_raw == canonical(authentication)
    assert authentication["approval_sha256"] == hashlib.sha256(approval_raw).hexdigest()
    assert authentication["issuer_commitment"] == approval.issuer_commitment
    issue, consume = formal["issue"], formal["consume"]
    assert issue.__code__ is cycle_evidence._issue_cycle_receipt.__code__
    private_raws, rootfs_tokens = [], []

    class ComposedHarness(fixtures["Harness"]):
        def consume(self, value, commitment, observed):
            return replace(super().consume(value, commitment, observed),
                authentication_receipt_sha256=hashlib.sha256(authentication_raw).hexdigest())

        def remote(self, grant, apply, running, deadline):
            assert self.time < deadline
            self.calls.append(("remote", grant.ordinal, grant.mode))
            invocation = adapter.invocation(grant)
            decoded = authority.decode(invocation.grant_bytes)
            assert decoded == grant
            route, lifecycle = formal["terminal"](grant.ordinal, decoded)
            rootfs_tokens.append(formal["fixture_records"][lifecycle.retired.raw][0].body["rootfs_token"])
            receipt = issue(route, lifecycle)
            assert lifecycle.static_custody.close_attempts == 1
            raw = consume(receipt)
            assert receipt.receipt_commitment == hashlib.sha256(
                b"cogs.stage2-cycle-private-owner-receipt/v2\0" + raw).hexdigest()
            private_raws.append(raw)
            # Pass the serializer's exact bytes, not a reconstructed JSON object.
            remote = adapter.remote_receipt(approval, grant, apply, running, raw)
            assert remote.host_receipt_commitment == receipt.receipt_commitment
            assert remote.instance_commitment == running.identity_commitment
            assert remote.instance_commitment != dict(running.resource_commitments)["instance"]
            assert remote.bindings.source == production.RemoteSourceBindings(**package["source_bindings"])
            assert remote.bindings.qemu.runtime_identity_sha256 not in {
                row["identities"]["runtime"] for row in package["cycles"]}
            if grant.ordinal <= 2:
                # Hostile byte substitutions only; no successful boundary repairs
                # JSON or manufactures the static manifest from a live identity.
                static = approval.runtime_manifest_sha256.encode()
                live = remote.bindings.qemu.runtime_identity_sha256.encode()
                assert static != live and static in raw and live in raw
                for hostile in (raw.replace(static, live), raw.replace(live, static)):
                    try: adapter.remote_receipt(approval, grant, apply, running, hostile)
                    except adapter.RemoteAdapterError: pass
                    else: raise AssertionError("static/live substitution crossed remote consumer")
                # Reproduce the old producer projection on both production routes.
                _, _, old_issue, _, old_consume = cycle_evidence._new_cycle_receipt_routes(
                    lambda raw: formal["fixture_records"][raw],
                    lambda _custody: formal["admission"]._host_bound_binding(
                        formal["base"], formal["runtime"].value["executables"]),
                    formal["reject_diagnostic"], formal["close_custody"])
                old_route, old_lifecycle = formal["terminal"](grant.ordinal, decoded)
                old_raw = old_consume(old_issue(old_route, old_lifecycle))
                assert b'"runtime_manifest_sha256"' not in old_raw
                try: adapter.remote_receipt(approval, grant, apply, running, old_raw)
                except adapter.RemoteAdapterError: pass
                else: raise AssertionError("legacy production serializer projection accepted")
                assert old_lifecycle.static_custody.close_attempts == 1
            if grant.ordinal == 1:
                # Same exact full-owner type is not enough: bind the operation,
                # mapping and immutable QEMU identity to the observed journal.
                for field, hostile in (("operation_token", d("foreign-operation")),
                        ("live_mapping_sha256", d("foreign-mapping")),
                        ("runtime_identity_sha256", approval.runtime_manifest_sha256),
                        ("qemu_pid", 999), ("journal-qemu", 999)):
                    bad_route, bad = formal["terminal"](grant.ordinal, decoded)
                    if field == "journal-qemu":
                        rows = formal["fixture_records"][bad.retired.raw]
                        next(row for row in rows if row.record_type ==
                             "RUNTIME_ROLE_IDENTITIES_V1").body["roles"][0]["pid"] = hostile
                    else: bad.runtime_proof = replace(bad.runtime_proof, **{field: hostile})
                    try: issue(bad_route, bad)
                    except cycle_evidence.CycleEvidenceError: pass
                    else: raise AssertionError(f"foreign full proof accepted: {field}")
                    assert bad.static_custody.close_attempts == 1
            return remote

    harness = ComposedHarness(approval_value=approval)
    controller = production.ProductionCampaignController(harness.ports())
    candidate = controller.run()
    assert candidate.approval is approval and harness.consumed
    assert len(private_raws) == len(set(rootfs_tokens)) == 7 and harness.inventory_count == 8
    assert not set(rootfs_tokens) & {row["identities"]["rootfs"] for row in package["cycles"]}
    assert not harness.active and harness.cleanup_count == 0
    assert [row[2] for row in harness.calls if row[0] == "remote"] == list(production.CYCLE_MODES)
    receipts = [json.loads(raw) for raw in private_raws]
    for identities in (
            [row["operation_token"] for row in receipts],
            [row["timing"]["host_boot_id"] for row in receipts],
            *([row["qmp_lineage"][key] for row in receipts] for key in (
                "runtime_identity_sha256", "live_mapping_sha256", "qemu_process_sha256")),
            *([row["key_freshness"][key] for row in receipts] for key in (
                "client_key_commitment", "host_key_commitment"))):
        assert len(set(identities)) == 7
    # These candidates retain test-only custody even though all byte codecs are
    # production functions. The real AWS publication gate must still reject.
    with tempfile.TemporaryDirectory() as directory:
        os.chmod(directory, 0o700)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            try: evidence_issuer.issue_completion_evidence(
                candidate, evidence_issuer.open_publication_custody(fd))
            except evidence_issuer.EvidenceIssuanceError: pass
            else: raise AssertionError("composition acquired AWS publication authority")
            assert not list(Path(directory).iterdir())
        finally: os.close(fd)
    evidence_raw, report_raw = evidence_issuer._project_test_candidate(candidate)
    evidence = json.loads(evidence_raw)
    assert evidence["bindings"]["pre_aws_package_commitment"] == hashlib.sha256(package_raw).hexdigest()
    assert evidence["bindings"]["approval_authentication_commitment"] == hashlib.sha256(authentication_raw).hexdigest()
    assert [row["remote"]["host_receipt_commitment"] for row in evidence["cycles"]] == [
        remote.host_receipt_commitment for remote in candidate.remotes]
    try: controller.run()
    except production.ProductionCampaignError: pass
    else: raise AssertionError("composition replay accepted")
    return {"package": package_raw.decode(), "approval": approval_raw.decode(),
        "authentication": authentication_raw.decode(),
        "private_receipts": [raw.decode() for raw in private_raws],
        "evidence": evidence_raw.decode(), "report": report_raw.decode()}


def main():
    issuer = load("production_issuer_test", "scripts/stage2-production-approval.py")
    stager = load("production_stager_test", "scripts/stage2-stage-production-approval.py")
    planner = load("production_planner_test", "scripts/stage2-production-planner.py")

    def capture(action, *args):
        output = io.BytesIO()
        def write(descriptor, raw):
            assert descriptor == 1
            return output.write(raw)
        with patch.object(issuer.os, "write", side_effect=write): action(*args)
        return output.getvalue()

    def rejected(action):
        try: action()
        except (issuer.ApprovalIssuerError, stager.StagingError, planner.PlanningError,
                production.ProductionCampaignError, OSError, TypeError): return
        raise AssertionError("unqualified package/approval accepted")

    with patch.object(issuer.os, "write", return_value=0):
        rejected(lambda: issuer.emit(b"bounded-output\n"))

    environment = {"GITHUB_SHA": "4" * 40, "COGS_STAGE2_CONTROL_REVISION": "2" * 40,
        "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTOR": "nenb",
        "COGS_STAGE2_EXECUTOR_PRINCIPAL_COMMITMENT": d("executor"),
        "COGS_STAGE2_APPROVAL_WORKFLOW_SHA256": d("workflow")}
    with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, environment, clear=True):
        # Compose the real formal serializers/status/aggregate, retaining its
        # emitted bytes without repairing any producer/consumer boundary.
        with patch.object(sys, "stdout", io.StringIO()), patch.object(sys, "argv", ["formal-fixture"]):
            formal = runpy.run_path(str(ROOT / "test/stage2-formal-local-qualification.py"))
        package_raw = formal["package_raw"]; package = json.loads(package_raw)
        assert package_raw == canonical(package)
        value = draft_for(package)
        planning, source = Path(temporary) / "planning", Path(temporary) / "approval"
        planning.mkdir(); source.mkdir()
        draft, approved = planning / "approval-draft.json", source / "approval.json"
        planning_package = planning / production.QUALIFICATION_PACKAGE_NAME
        package_path = source / production.QUALIFICATION_PACKAGE_NAME
        planning_package.write_bytes(package_raw); draft.write_bytes(canonical(value))
        hostile_link = Path(temporary) / "input-link"
        hostile_link.symlink_to(draft)
        hostile_fifo = Path(temporary) / "input-fifo"
        os.mkfifo(hostile_fifo, 0o600)
        issuer_large = Path(temporary) / "issuer-large"
        planner_large = Path(temporary) / "planner-large"
        with issuer_large.open("wb") as stream: stream.truncate(issuer.MAX_BYTES + 1)
        with planner_large.open("wb") as stream: stream.truncate(planner.MAX + 1)
        for action in (lambda: issuer.read(hostile_link), lambda: planner.read(hostile_link),
                       lambda: issuer.read(hostile_fifo), lambda: planner.read(hostile_fifo),
                       lambda: issuer.read(issuer_large), lambda: planner.read(planner_large)):
            rejected(action)
        issued_raw = capture(issuer.issue, draft); issued = json.loads(issued_raw)
        issued["plan_sha256s"] = tuple(issued["plan_sha256s"])
        approval = production.ProductionApproval(**issued)
        assert approval.version == "cogs.stage2-completion-production-approval/v5"
        assert approval.batch_commitment == production.approval_batch_commitment(value)
        assert approval.batch_commitment != production._commit(
            b"cogs.stage2-production-approved-batch/v4", production._approval_fields(value))
        for field, impostor in (("maximum_cost_micro_usd", 499_999.5),
                                ("not_before_unix_ns", 0), ("not_before_unix_ns", -1)):
            hostile = {**issued, field: impostor}
            hostile["batch_commitment"] = production.approval_batch_commitment(hostile)
            rejected(lambda hostile=hostile: production.ProductionApproval(**hostile))
        approved.write_bytes(issued_raw)
        # Regression: same-directory fixtures hid the missing workflow copy.
        rejected(lambda: capture(issuer.authenticate, approved))
        shutil.copyfile(planning_package, package_path); package_path.chmod(0o600)
        assert package_path.read_bytes() == package_raw == planning_package.read_bytes()
        assert package_path.stat().st_mode & 0o777 == 0o600
        assert hashlib.sha256(package_path.read_bytes()).hexdigest() == approval.pre_aws_package_sha256
        issuer.eligibility(approved); planner.eligibility(planning_package)
        authentication_raw = capture(issuer.authenticate, approved)
        authentication = json.loads(authentication_raw)
        assert authentication["approval_sha256"] == hashlib.sha256(issued_raw).hexdigest()
        assert authentication["result"] == "pass"
        composition = compose_campaign(formal, package_raw, issued_raw, authentication_raw)

        original_read = stager.read
        def stage_until_package_rejected():
            reads = []
            def guarded_read(path, maximum=stager.MAX):
                reads.append(Path(path).name)
                assert Path(path).name in {"approval.json", production.QUALIFICATION_PACKAGE_NAME}
                return original_read(path, maximum)
            with patch.object(stager, "read", guarded_read), \
                    patch.object(stager.os, "geteuid", return_value=0), \
                    patch.object(stager.os, "getegid", return_value=0):
                rejected(lambda: stager.stage(source, "unread-budget", "unread-config", "unread-credentials"))
            assert reads == ["approval.json", production.QUALIFICATION_PACKAGE_NAME]

        count = 0
        for label, hostile in hostile_packages(package):
            try:
                changed = {**value, "pre_aws_package_sha256": sha(hostile)}
                draft.write_bytes(canonical(changed)); planning_package.write_bytes(canonical(hostile))
                package_path.write_bytes(canonical(hostile))
                # Rebind approval/package/batch digests too, so each gate must
                # reject the prerequisite itself, not just an outer hash mismatch.
                candidate = {**issued, "pre_aws_package_sha256": sha(hostile)}
                candidate["batch_commitment"] = production.approval_batch_commitment(candidate)
                approved.write_bytes(canonical(candidate))
                candidate_approval = production.ProductionApproval(**candidate)
                rejected(lambda: production.qualification_source_bindings(hostile))
                rejected(lambda: production.validate_approval_package(candidate_approval, hostile, sha(hostile)))
                rejected(lambda: planner.eligibility(planning_package))
                rejected(lambda: capture(issuer.issue, draft))
                rejected(lambda: capture(issuer.authenticate, approved))
                rejected(lambda: issuer.eligibility(approved))
                stage_until_package_rejected()
                count += 1
            except AssertionError as error: raise AssertionError(label) from error
        assert count > 250
        draft.write_bytes(canonical(value)); approved.write_bytes(issued_raw)
        planning_package.write_bytes(package_raw); package_path.write_bytes(package_raw)

        # Even structurally valid substitutions cannot borrow an old digest.
        substituted = copy.deepcopy(package); substituted["mixed_preflight_run_id"] = 64
        production.qualification_source_bindings(substituted)
        rejected(lambda: production.validate_approval_package(approval, substituted, approval.pre_aws_package_sha256))
        for raw in (None, package_raw + b" ", package_raw.replace(b'"attempt":1', b'"attempt":1,"attempt":1')):
            if raw is None:
                package_path.unlink(); planning_package.unlink()
            else:
                package_path.write_bytes(raw); planning_package.write_bytes(raw)
            rejected(lambda: capture(issuer.issue, draft))
            rejected(lambda: planner.eligibility(planning_package))
            rejected(lambda: capture(issuer.authenticate, approved))
            rejected(lambda: issuer.eligibility(approved))
            stage_until_package_rejected()
        package_path.write_bytes(package_raw)

        # Success reaches only the authentication boundary, never tools,
        # credentials, publication writes, or a production execution capability.
        class AuthenticationBoundary(Exception): pass
        def stop_at_authentication(path, maximum=stager.MAX):
            if Path(path).name == "approval-authentication.json": raise AuthenticationBoundary()
            assert Path(path).name in {"approval.json", production.QUALIFICATION_PACKAGE_NAME}
            return original_read(path, maximum)
        with patch.object(stager, "read", stop_at_authentication), \
                patch.object(stager.os, "geteuid", return_value=0), \
                patch.object(stager.os, "getegid", return_value=0):
            try: stager.stage(source, "unread-budget", "unread-config", "unread-credentials")
            except AuthenticationBoundary: pass
            else: raise AssertionError("static package acquired authentication authority")
        for version in range(1, 5):
            rejected(lambda: production.ProductionApproval(**{
                **issued, "version": f"cogs.stage2-completion-production-approval/v{version}"}))
        draft.write_bytes(canonical({**value, "version": "cogs.stage2-production-approval-draft/v2"}))
        rejected(lambda: capture(issuer.issue, draft))
    if sys.argv[1:] == ["--composition-samples"]:
        sys.stdout.buffer.write(canonical(composition))
    else:
        assert len(sys.argv) == 1
        print("stage2 production approval issuer checks passed")


if __name__ == "__main__":
    blocked = []
    def forbidden_audit(event, args):
        if (event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {
                "os.system", "os.exec", "os.posix_spawn", "os.fork", "os.forkpty"}
                or (event == "import" and args[0].split(".")[0] in {
                    "boto3", "botocore", "completion_campaign_aws_provider"})
                or (event == "open" and args[0] in {"/dev/kvm", "/dev/net/tun"})):
            blocked.append(event)
            raise AssertionError("provider/process/network/KVM seam forbidden")
    sys.addaudithook(forbidden_audit)
    # Exercise the audit gate without attempting any underlying operation.
    for event, args in (("subprocess.Popen", ("aws",)), ("subprocess.Popen", ("tofu",)),
            ("socket.connect", ()), ("os.system", ()), ("ctypes.dlopen", ()),
            ("import", ("completion_campaign_aws_provider",)), ("open", ("/dev/kvm",))):
        try: sys.audit(event, *args)
        except AssertionError: pass
        else: raise AssertionError("audit gate did not block forbidden operation")
    assert len(blocked) == 7
    blocked.clear()
    def forbidden_call(*_args, **_kwargs):
        blocked.append("mocked process/network")
        raise AssertionError("process/network forbidden")
    with patch("subprocess.Popen", side_effect=forbidden_call), \
            patch("socket.socket", side_effect=forbidden_call), \
            patch("socket.create_connection", side_effect=forbidden_call), \
            patch("socket.getaddrinfo", side_effect=forbidden_call):
        main()
    assert not blocked, "even a caught forbidden effect attempt fails composition"

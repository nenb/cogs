"""Sealed full/readiness cycle routes and terminal private owner receipts.

The two routes are closure-issued capabilities, not values selected by a caller.
Receipt issuance accepts only live typed owners, a reparsed retired journal, and
the independent residue result.  It cannot consume report or transcript bytes.
"""

from __future__ import annotations

import hashlib
import json

import completion_guest_readiness_v1 as readiness_guest
import completion_guest_workloads_v3 as full_guest
import completion_kata_admission as admission
import completion_kata_operation as operation
import completion_kata_preparation_bridge as preparation
import completion_kata_ssh as ssh
import completion_local_evidence as evidence
import completion_local_full as local

PRIVATE_VERSION = "cogs.stage2-cycle-private-owner-receipt/v1"
FORMAL_PRIVATE_VERSION = "cogs.stage2-formal-local-cycle-receipt/v1"
TEARDOWN_PROJECTION = local.TEARDOWN_PHASES
PRIVATE_TEARDOWN_RECORDS = evidence.JOURNAL_TEARDOWN_ORDER
RESIDUE_FACTS = local.RESIDUE_FACTS


class CycleEvidenceError(ValueError):
    pass


class _CycleEvidenceErrorGroup(CycleEvidenceError):
    """Portable ordered aggregate for hosts predating native exception groups."""
    def __init__(self, message, errors):
        self.errors = tuple(errors)
        super().__init__(message)


def _error_group(message, errors):
    try:
        group = BaseExceptionGroup
    except NameError:
        return _CycleEvidenceErrorGroup(message, errors)
    return group(message, tuple(errors))


def _require(condition, message="exact sealed cycle owner evidence required"):
    if not condition:
        raise CycleEvidenceError(message)


def _digest(value):
    _require(type(value) is str and len(value) == 64
             and all(character in "0123456789abcdef" for character in value),
             "lowercase SHA-256 required")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def _runtime_identity_sha256(value):
    fields = {name: getattr(value, name) for name in (
        "qemu_argv_sha256", "qemu_pid",
        "qemu_starttime", "qemu_executable_device", "qemu_executable_inode",
        "observer_qmp_device", "observer_qmp_inode", "kvm_device", "kvm_inode",
        "kvm_rdev", "kvm_api", "qmp_present", "qmp_enabled")}
    return hashlib.sha256(
        b"cogs.stage2-qemu-runtime-identity/v1\0" + _canonical(fields)).hexdigest()


def _route_realm():
    seal = object()
    registry = {}

    class _FullRoute:
        __slots__ = ()
        def __new__(cls, key=None):
            _require(key is seal, "full route is sealed")
            return super().__new__(cls)

    class _ReadinessRoute:
        __slots__ = ()
        def __new__(cls, key=None):
            _require(key is seal, "readiness route is sealed")
            return super().__new__(cls)

    full, readiness = _FullRoute(seal), _ReadinessRoute(seal)
    synthetic_full = _FullRoute(seal)
    synthetic_readiness = _ReadinessRoute(seal)
    diagnostic_full = _FullRoute(seal)
    diagnostic_readiness = _ReadinessRoute(seal)
    formal_full = _FullRoute(seal)
    formal_readiness = _ReadinessRoute(seal)
    authorized = {synthetic_full, synthetic_readiness}
    diagnostics = {diagnostic_full, diagnostic_readiness}
    formal = {formal_full, formal_readiness}
    no_grant = authorized | diagnostics
    classifications = {}
    for route, name, program, marker, classification, domain in (
        (full, "full", full_guest.GUEST_PROGRAM_SHA256,
         hashlib.sha256(full_guest.GUEST_READY_MARKER).hexdigest(),
         "production", b"production"),
        (readiness, "readiness", readiness_guest.GUEST_PROGRAM_SHA256,
         readiness_guest.MARKER_SHA256, "production", b"production"),
        (synthetic_full, "full", full_guest.GUEST_PROGRAM_SHA256,
         hashlib.sha256(full_guest.GUEST_READY_MARKER).hexdigest(),
         "synthetic", b"synthetic"),
        (synthetic_readiness, "readiness", readiness_guest.GUEST_PROGRAM_SHA256,
         readiness_guest.MARKER_SHA256, "synthetic", b"synthetic"),
        (diagnostic_full, "full", full_guest.GUEST_PROGRAM_SHA256,
         hashlib.sha256(full_guest.GUEST_READY_MARKER).hexdigest(),
         "diagnostic", b"diagnostic-current-source"),
        (diagnostic_readiness, "readiness", readiness_guest.GUEST_PROGRAM_SHA256,
         readiness_guest.MARKER_SHA256, "diagnostic", b"diagnostic-current-source"),
        (formal_full, "full", full_guest.GUEST_PROGRAM_SHA256,
         hashlib.sha256(full_guest.GUEST_READY_MARKER).hexdigest(),
         "formal", b"formal-non-cloud-qualification"),
        (formal_readiness, "readiness", readiness_guest.GUEST_PROGRAM_SHA256,
         readiness_guest.MARKER_SHA256, "formal", b"formal-non-cloud-qualification"),
    ):
        capability = hashlib.sha256(
            b"cogs.stage2-cycle-route/v1\0" + domain + b"\0" + name.encode("ascii") +
            bytes.fromhex(program) + bytes.fromhex(marker)).hexdigest()
        registry[route] = (name, capability, program, marker)
        classifications[route] = classification

    def full_route(): return full
    def readiness_route(): return readiness
    def synthetic_full_route(): return synthetic_full
    def synthetic_readiness_route(): return synthetic_readiness
    def diagnostic_full_route(): return diagnostic_full
    def diagnostic_readiness_route(): return diagnostic_readiness
    def formal_full_route(): return formal_full
    def formal_readiness_route(): return formal_readiness
    def classify(route):
        describe(route)
        value = classifications.get(route)
        _require(value in {"production", "synthetic", "diagnostic", "formal"},
                 "exact cycle route classification required")
        return value
    def is_diagnostic(route): return route in diagnostics
    def is_formal(route): return route in formal
    def launch_authorized(route, grant=None):
        name, _capability, _program, _marker = describe(route)
        if route in no_grant:
            return grant is None
        if route in formal:
            import completion_formal_cycle_authority as formal_authority
            return (type(grant) is formal_authority.FormalCycleGrant
                    and grant.authority == formal_authority.AUTHORITY
                    and grant.mode == name)
        import completion_cycle_authority as cycle_authority
        return (type(grant) is cycle_authority.campaign.CycleLaunchGrant
                and grant.mode == name)
    def describe(route):
        value = registry.get(route)
        _require((type(route) is _FullRoute or type(route) is _ReadinessRoute)
                 and value is not None, "closure-issued cycle route required")
        return value
    def bind(route, journal, grant=None):
        name, capability, program, marker = describe(route)
        _require(operation._cycle_route(journal) is None,
                 "cycle route already durably bound")
        if route in formal:
            import completion_formal_cycle_authority as formal_authority
            _require(type(grant) is formal_authority.FormalCycleGrant
                     and grant.authority == formal_authority.AUTHORITY
                     and grant.mode == name,
                     "complete non-cloud formal grant required before route binding")
        elif route not in no_grant:
            import completion_cycle_authority as cycle_authority
            _require(type(grant) is cycle_authority.campaign.CycleLaunchGrant
                     and grant.mode == name,
                     "complete production grant required before route binding")
        else:
            _require(grant is None, "non-production route cannot carry production grant")
        operation._record_cycle_route(
            journal, name, capability, program, marker, grant)
        return route
    return (_FullRoute, _ReadinessRoute, full_route, readiness_route,
            synthetic_full_route, synthetic_readiness_route,
            diagnostic_full_route, diagnostic_readiness_route,
            formal_full_route, formal_readiness_route, classify,
            is_diagnostic, is_formal, launch_authorized, describe, bind)


(_FullRoute, _ReadinessRoute, _fixed_full_route, _fixed_readiness_route,
 _synthetic_full_route_for_tests, _synthetic_readiness_route_for_tests,
 _diagnostic_full_route, _diagnostic_readiness_route,
 _formal_full_route, _formal_readiness_route, _classify_route,
 _is_diagnostic_route, _is_formal_route, _cycle_launch_authorized,
 _describe_route, _bind_operation_route) = _route_realm()
del _route_realm


def _runtime_readiness_realm():
    seal, issued = object(), {}

    class _RuntimeReadinessOwnerResult:
        __slots__ = ("operation_token", "runtime_mount_record_sha256",
                     "runtime_network_sha256", "live_mapping_sha256",
                     "runtime_identity_sha256", "qemu_process_sha256", "qmp_identity")
        def __new__(cls, key=None, **values):
            _require(key is seal, "runtime readiness result is sealed")
            value = super().__new__(cls)
            for name in cls.__slots__: setattr(value, name, values[name])
            return value
        def canonical_value(self):
            return {name: getattr(self, name) for name in self.__slots__}

    def issue(**values):
        _require(set(values) == set(_RuntimeReadinessOwnerResult.__slots__))
        for name in ("operation_token", "runtime_mount_record_sha256",
                     "runtime_network_sha256", "live_mapping_sha256",
                     "runtime_identity_sha256", "qemu_process_sha256"):
            _digest(values[name])
        qmp = values["qmp_identity"]
        _require(type(qmp) is tuple and len(qmp) == 10
                 and all(type(item) is int and item >= 0 for item in qmp)
                 and qmp[0] > 1 and qmp[1] > 0 and qmp[3] > 0
                 and qmp[5] > 0 and qmp[7] > 0 and qmp[9] == 12)
        result = _RuntimeReadinessOwnerResult(seal, **values)
        issued[id(result)] = result
        return result
    def validate(value):
        _require(type(value) is _RuntimeReadinessOwnerResult
                 and issued.get(id(value)) is value,
                 "issued runtime readiness lineage required")
        return value
    return _RuntimeReadinessOwnerResult, issue, validate


(_RuntimeReadinessOwnerResult, _issue_runtime_readiness_owner_result,
 _validate_runtime_readiness_owner_result) = _runtime_readiness_realm()
del _runtime_readiness_realm


def _receipt_realm(parse_journal=None, formal_custody_binding=None,
                   diagnostic_custody_lineage=None, close_custody=None):
    """Build an isolated realm; alternate realms cannot mint production receipts."""
    _require(all(value is None or callable(value) for value in (
        parse_journal, formal_custody_binding,
        diagnostic_custody_lineage, close_custody)),
        "exact cycle receipt dependencies required")
    seal, receipts = object(), {}

    class _FullCycleReceipt:
        __slots__ = ("_value", "_commitment")
        def __new__(cls, key=None, value=None, commitment=None):
            _require(key is seal, "full cycle receipt is sealed")
            result = super().__new__(cls)
            result._value, result._commitment = value, commitment
            return result
        @property
        def receipt_commitment(self): return self._commitment

    class _ReadinessCycleReceipt:
        __slots__ = ("_value", "_commitment")
        def __new__(cls, key=None, value=None, commitment=None):
            _require(key is seal, "readiness cycle receipt is sealed")
            result = super().__new__(cls)
            result._value, result._commitment = value, commitment
            return result
        @property
        def receipt_commitment(self): return self._commitment

    def records_by_kind(records):
        result = {}
        for row in records: result.setdefault(row.record_type, []).append(row)
        return result

    def common(route, lifecycle):
        name, capability, program, marker = _describe_route(route)
        classification = _classify_route(route)
        _require(type(lifecycle.retired) is evidence._RetiredJournalOwnerResult
                 and type(lifecycle.residue) is evidence._ResidueOwnerResult,
                 "retired journal and independent residue owners required")
        records = ((operation._parse if parse_journal is None else parse_journal)
                   (lifecycle.retired.raw))
        _require(records[-1].record_type == "RETIRED")
        by_kind = records_by_kind(records)
        for kind in ("CYCLE_ROUTE_V1", "CTR_LAUNCH_ISSUED_V1",
                     "SSH_MARKER_OBSERVED_V1", "SSH_COMMAND_SETTLED_V1",
                     "RUNTIME_ROLE_IDENTITIES_V1", "RUNTIME_SHARE_IDENTITY_V1",
                     "RUNTIME_ROLE_ABSENCE_V1", "RUNTIME_NETWORK_RELEASED_V1"):
            _require(len(by_kind.get(kind, ())) == 1, f"exact {kind} required")
        route_record = by_kind["CYCLE_ROUTE_V1"][0]
        parser_source = (operation.SSH_PARSER_SHA256 if name == "full"
                         else readiness_guest.PARSER_SHA256)
        _require((route_record.body["route"],
                  route_record.body["cycle_capability_sha256"],
                  route_record.body["program_sha256"],
                  route_record.body["parser_source_sha256"],
                  route_record.body["marker_sha256"]) ==
                 (name, capability, program, parser_source, marker))
        production_grant = route_record.body["grant_authority"] == "production"
        formal_grant = classification == "formal"
        _require(production_grant == (classification == "production")
                 and (not formal_grant or route_record.body["grant_authority"] ==
                      "non-cloud-formal-qualification-cycle-only"),
                 "route/grant authority differs")
        if classification in {"synthetic", "diagnostic"}:
            _require(route_record.body["grant_authority"] == "synthetic"
                     and all(route_record.body[name] is None for name in (
                         "batch_commitment", "cycle_ordinal", "implementation_revision",
                         "control_revision", "static_control_sha256",
                         "rootfs_descriptor_sha256", "ami_commitment", "plan_sha256",
                         "grant_commitment")),
                     "non-production route requires exact no-grant journal fields")
        launch = by_kind["CTR_LAUNCH_ISSUED_V1"][0]
        observed = by_kind["SSH_MARKER_OBSERVED_V1"][0]
        settled = by_kind["SSH_COMMAND_SETTLED_V1"][0]
        _require(launch.body["kata_launch_started_boottime_ns"] <
                 observed.body["ssh_marker_observed_boottime_ns"] <=
                 settled.body["ssh_command_settled_boottime_ns"]
                 and settled.body["parser_sha256"] == parser_source
                 and launch.body["host_boot_id"] == observed.body["host_boot_id"] ==
                     settled.body["host_boot_id"] == records[0].body["host_boot_id"])
        intents = [row for row in records if row.record_type == "COMMAND_INTENT_V2"]
        runs = [row for row in intents if row.body["command_id"] == "CTR_RUN"]
        ssh_intents = [row for row in intents
                       if row.body["command_id"] in {"SSH_READY", "SSH_READINESS"}]
        expected_ssh = "SSH_READY" if name == "full" else "SSH_READINESS"
        _require(len(runs) == len(ssh_intents) == 1
                 and ssh_intents[0].body["command_id"] == expected_ssh)
        _require(type(lifecycle.runtime_observation) is evidence._PlatformOwnerResult
                 and lifecycle.runtime_observation.operation_token ==
                     records[0].body["operation_token"])
        residue = lifecycle.residue
        _require(residue.operation_token == records[0].body["operation_token"]
                 and residue.absent_facts == RESIDUE_FACTS)
        teardown_kinds = tuple(row.record_type for row in records
                               if row.record_type in PRIVATE_TEARDOWN_RECORDS)
        _require(teardown_kinds == PRIVATE_TEARDOWN_RECORDS)
        custody_projection = (
            (admission._diagnostic_custody_lineage
             if diagnostic_custody_lineage is None else diagnostic_custody_lineage)(
                 lifecycle.static_custody)
            if classification == "diagnostic" else
            (admission._static_custody_binding
             if formal_custody_binding is None else formal_custody_binding)(
                 lifecycle.static_custody))
        settled_key_grants = [row.body for row in records
                              if row.record_type == "INPUT_GRANT"
                              and row.body["action"] == "settled"]
        def key_commitment(path):
            rows = [row for row in settled_key_grants if row["path"] == path]
            _require(len(rows) == 1, "exact fresh SSH key grant required")
            return hashlib.sha256(
                b"cogs.stage2-ssh-key-generation/v1\0" + _canonical(rows[0])).hexdigest()
        key_freshness = {
            "client_key_commitment": key_commitment("@key-stage/client"),
            "host_key_commitment": key_commitment("@key-stage/server"),
        }
        _require(len(set(key_freshness.values())) == 2)
        timing = {
            "host_boot_id": launch.body["host_boot_id"],
            "launch_record_sha256": launch.line_sha256,
            "marker_record_sha256": observed.line_sha256,
            "settlement_record_sha256": settled.line_sha256,
            "kata_launch_started_boottime_ns": launch.body["kata_launch_started_boottime_ns"],
            "ssh_marker_observed_boottime_ns": observed.body["ssh_marker_observed_boottime_ns"],
            "ssh_command_settled_boottime_ns": settled.body["ssh_command_settled_boottime_ns"],
            "ssh_ready_ns": observed.body["ssh_marker_observed_boottime_ns"] -
                            launch.body["kata_launch_started_boottime_ns"],
        }
        qmp = lifecycle.runtime_observation
        _require(qmp.runtime_identity_sha256 == _runtime_identity_sha256(qmp),
                 "pre-SSH runtime identity commitment differs")
        production_cycle_grant = ({field: route_record.body[field] for field in (
            "batch_commitment", "cycle_ordinal", "implementation_revision",
            "control_revision", "static_control_sha256", "rootfs_descriptor_sha256",
            "ami_commitment", "plan_sha256", "grant_commitment")}
            if production_grant else None)
        formal_cycle_grant = ({
            **{field: route_record.body[field] for field in (
                "authority", "batch_commitment", "cycle_ordinal",
                "implementation_revision", "control_revision", "source_manifest_sha256",
                "static_control_sha256", "workflow_sha256", "result_schema_sha256",
                "rootfs_descriptor_sha256", "workflow_run_id", "workflow_run_attempt",
                "grant_commitment")}, "mode": name} if formal_grant else None)
        value = {
            "version": PRIVATE_VERSION, "route": name,
            "cycle_capability_sha256": capability,
            "cycle_grant": production_cycle_grant,
            "production_publication_authorized": False,
            "provider_execution_observed": False,
            "aws_authority": (route_record.body["grant_commitment"]
                              if production_grant else None),
            "operation_token": records[0].body["operation_token"],
            "journal_sha256": hashlib.sha256(lifecycle.retired.raw).hexdigest(),
            "program_sha256": program, "parser_source_sha256": parser_source,
            "marker_sha256": marker,
            "launch_attempts": 1, "ssh_attempts": 1, "timing": timing,
            "key_freshness": key_freshness,
            "runtime_network_sha256": next(
                row.body["proof_sha256"] for row in records
                if row.record_type == "NETWORK_SNAPSHOT_V2"
                and row.body["snapshot_kind"] == "runtime"),
            "qmp_lineage": {
                "live_mapping_sha256": qmp.live_mapping_sha256,
                "runtime_identity_sha256": qmp.runtime_identity_sha256,
                "qemu_process_sha256": qmp.qemu_process_sha256,
                "qemu_argv_sha256": qmp.qemu_argv_sha256,
                "qemu_pid": qmp.qemu_pid, "qemu_starttime": qmp.qemu_starttime,
                "qemu_executable_device": qmp.qemu_executable_device,
                "qemu_executable_inode": qmp.qemu_executable_inode,
                "observer_qmp_device": qmp.observer_qmp_device,
                "observer_qmp_inode": qmp.observer_qmp_inode,
                "kvm_device": qmp.kvm_device, "kvm_inode": qmp.kvm_inode,
                "kvm_rdev": qmp.kvm_rdev, "kvm_api": qmp.kvm_api,
                "qmp_present": qmp.qmp_present, "qmp_enabled": qmp.qmp_enabled,
            },
            "teardown_projection": list(TEARDOWN_PROJECTION),
            "private_teardown_records": list(PRIVATE_TEARDOWN_RECORDS),
            "final_baselines_sha256": residue.final_baselines_sha256,
            "independent_residue_absent": list(residue.absent_facts),
        }
        if classification == "diagnostic":
            value["diagnostic_custody_lineage"] = custody_projection
        else:
            value["source_bindings"] = custody_projection
        if formal_grant:
            lifecycle_objects = {
                "rootfs_leases": len(by_kind.get("ROOTFS_LEASED", ())),
                "runtime_stages": len(by_kind.get("RUNTIME_STAGED_V3", ())),
                "task_launches": len(by_kind.get("CTR_LAUNCH_ISSUED_V1", ())),
            }
            _require(set(lifecycle_objects.values()) == {1},
                     "exact rootfs lease, runtime, and task required")
            value.update({
                "version": FORMAL_PRIVATE_VERSION,
                "authority": "non-aws-formal-qualification-owner-evidence-only",
                "cycle_grant": formal_cycle_grant,
                "aws_authority": None,
                "formal_qualification_authority": route_record.body["grant_commitment"],
                "rootfs_token": records[0].body["rootfs_token"],
                "lifecycle_objects": lifecycle_objects,
            })
        return value

    def prepare(route, lifecycle):
        value = common(route, lifecycle)
        if type(route) is _FullRoute:
            _require(type(lifecycle.session) is ssh.AuthenticatedSession
                     and type(lifecycle.runtime_proof) is evidence._RuntimeOwnerResult)
            parsed = lifecycle.session.parsed_result
            _require(type(parsed) is full_guest.GuestWorkloadResult
                     and len(parsed.samples) == 21
                     and parsed.network_markers == full_guest.GUEST_NETWORK_MARKERS
                     and all(row.deleted for row in parsed.samples))
            value["network_markers"] = list(parsed.network_markers)
            value["route_before_sha256"] = parsed.route_before_sha256
            value["route_after_sha256"] = parsed.route_after_sha256
            value["workloads"] = [{
                "ordinal": row.ordinal, "category": row.category,
                "duration_ns": row.duration_ns, "result_sha256": row.result_sha256,
                "deleted": row.deleted} for row in parsed.samples]
            value["network_causal_proof_sha256"] = (
                lifecycle.runtime_proof.network_causal_proof_sha256)
            cls = _FullCycleReceipt
        else:
            _require(type(lifecycle.session) is ssh.ReadinessAuthenticatedSession)
            runtime = _validate_runtime_readiness_owner_result(lifecycle.runtime_proof)
            observed = lifecycle.runtime_observation
            _require(runtime.runtime_identity_sha256 == observed.runtime_identity_sha256
                     and runtime.qemu_process_sha256 != observed.qemu_process_sha256,
                     "ordered post-SSH runtime observation or immutable identity differs")
            value["runtime_readiness_lineage"] = runtime.canonical_value()
            cls = _ReadinessCycleReceipt
        raw = _canonical(value)
        domain = (b"cogs.stage2-formal-local-cycle-receipt/v1\0"
                  if _is_formal_route(route)
                  else b"cogs.stage2-cycle-private-owner-receipt/v1\0")
        commitment = hashlib.sha256(domain + raw).hexdigest()
        return cls, value, raw, commitment, domain

    def settle(route, lifecycle, mint):
        """Validate exact receipt bytes, then close custody once before any mint."""
        prepared, primary = None, None
        try:
            prepared = prepare(route, lifecycle)
        except BaseException as error:
            primary = error
        close_error = None
        try:
            (preparation._abort_fixed_static_preparation
             if close_custody is None else close_custody)(lifecycle.static_custody)
        except BaseException as error:
            close_error = error
        if primary is not None or close_error is not None:
            causes = [error for error in (primary, close_error) if error is not None]
            cause = causes[0] if len(causes) == 1 else _error_group(
                "cycle receipt validation and custody close failed", causes)
            raise CycleEvidenceError(
                "cycle receipt transaction failed; nothing minted") from cause
        if not mint:
            return None
        cls, value, raw, commitment, domain = prepared
        try:
            receipt = cls(seal, value, commitment)
            receipts[receipt] = (raw, commitment, domain)
            return receipt
        except BaseException as error:
            raise CycleEvidenceError("cycle receipt commit failed; nothing minted") from error

    def issue(route, lifecycle):
        _require(not _is_diagnostic_route(route),
                 "diagnostic route can never mint cycle evidence")
        return settle(route, lifecycle, True)

    def validate_and_discard(route, lifecycle):
        return settle(route, lifecycle, False)

    def consume(receipt):
        state = receipts.pop(receipt, None)
        _require((type(receipt) is _FullCycleReceipt or
                  type(receipt) is _ReadinessCycleReceipt) and state is not None,
                 "issued one-shot cycle receipt required")
        raw, commitment, domain = state
        _require(hashlib.sha256(domain + raw).hexdigest() == commitment)
        return raw

    return (_FullCycleReceipt, _ReadinessCycleReceipt, issue,
            validate_and_discard, consume)


_new_cycle_receipt_routes = _receipt_realm
(_FullCycleReceipt, _ReadinessCycleReceipt, _issue_cycle_receipt,
 _validate_and_discard_cycle_receipt, _consume_cycle_receipt) = _receipt_realm()
del _receipt_realm

#!/usr/bin/env python3
"""Portable fixed-file cycle grant and route authority checks."""

import hashlib,inspect,json,os
from pathlib import Path
import sys,tempfile
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"deploy/aws-feasibility/remote"))
sys.path.insert(0,str(ROOT/"deploy/aws-feasibility"))
import completion_campaign_production as campaign
import completion_cycle_authority as authority
import completion_cycle_evidence as evidence
import completion_cycle_full as full_entry
import completion_cycle_readiness as readiness_entry
import completion_kata_operation as operation
import completion_kata_ssh as ssh
import completion_local_evidence as owner_evidence
import completion_local_full as local


def d(char): return char*64

def grant(mode="full",ordinal=1):
    value={"batch_commitment":d("1"),"ordinal":ordinal,"mode":mode,
           "implementation_revision":"2"*40,"control_revision":"3"*40,
           "static_control_sha256":d("4"),"rootfs_descriptor_sha256":d("5"),
           "ami_commitment":d("7"),"plan_sha256":d("6")}
    return campaign.CycleLaunchGrant(**value,grant_commitment=campaign._commit(b"cogs.stage2-cycle-launch-grant/v1",value))

def raw(value):
    body={"version":"cogs.stage2-cycle-launch-grant/v1",**value.__dict__}
    return json.dumps(body,sort_keys=True,separators=(",",":")).encode()+b"\n"

for mode,ordinal,route in (("full",1,evidence._fixed_full_route()),("readiness",2,evidence._fixed_readiness_route())):
    value=grant(mode,ordinal);encoded=raw(value);assert authority.decode(encoded)==value
    assert evidence._cycle_launch_authorized(route,value)
    assert not evidence._cycle_launch_authorized(route,None)
    route_name,capability,program,marker=evidence._describe_route(route)
    cycle_body={"operation_token":d("8"),"route":route_name,
                "cycle_capability_sha256":capability,"program_sha256":program,
                "parser_source_sha256": (operation.SSH_PARSER_SHA256 if route_name == "full"
                                          else operation.guest_readiness.PARSER_SHA256),
                "marker_sha256":marker,"grant_authority":"production",
                "batch_commitment":value.batch_commitment,"cycle_ordinal":value.ordinal,
                "implementation_revision":value.implementation_revision,
                "control_revision":value.control_revision,
                "static_control_sha256":value.static_control_sha256,
                "rootfs_descriptor_sha256":value.rootfs_descriptor_sha256,
                "ami_commitment":value.ami_commitment,"plan_sha256":value.plan_sha256,
                "grant_commitment":value.grant_commitment}
    operation._validate_body("CYCLE_ROUTE_V1",cycle_body)
    hostile=dict(cycle_body);hostile["grant_commitment"]=d("9")
    try: operation._validate_body("CYCLE_ROUTE_V1",hostile)
    except operation.OperationError: pass
    else: raise AssertionError("hostile cycle commitment accepted")
    hostile=dict(cycle_body)
    hostile["parser_source_sha256"] = (operation.guest_readiness.PARSER_SHA256
        if route_name == "full" else operation.SSH_PARSER_SHA256)
    try: operation._validate_body("CYCLE_ROUTE_V1",hostile)
    except operation.OperationError: pass
    else: raise AssertionError("route parser source substitution accepted")
    with tempfile.TemporaryDirectory() as temporary:
        parent=Path(temporary)/"cycle";parent.mkdir(mode=0o700);parent.chmod(0o700);path=parent/"grant.json"
        path.write_bytes(encoded);path.chmod(0o400);authority._claimed=False
        seen=parent.lstat();real_read=os.read
        with patch.object(authority.os,"read",side_effect=lambda fd,size:real_read(fd,min(size,7))):
            observed=authority._claim(path,mode,(seen.st_uid,seen.st_gid))
        assert observed==value and not parent.exists()

for entry,run_name in ((full_entry,"_run_fixed_full_cycle"),(readiness_entry,"_run_fixed_readiness_cycle")):
    writes=[]
    def short_write(descriptor,value):
        written=min(3,len(value));writes.append((descriptor,value[:written]));return written
    with patch.object(entry.coordinator,run_name,return_value=object()), patch.object(
            entry.evidence,"_consume_cycle_receipt",return_value=b"receipt\n"), patch.object(
            entry.os,"write",side_effect=short_write):
        entry.main()
    assert b"".join(value for descriptor,value in writes if descriptor==1)==b"receipt\n"
    with patch.object(entry.coordinator,run_name,return_value=object()), patch.object(
            entry.evidence,"_consume_cycle_receipt",return_value=b"receipt\n"), patch.object(
            entry.os,"write",return_value=0):
        try:entry.main()
        except OSError:pass
        else:raise AssertionError("zero-progress cycle receipt write accepted")

synthetic=evidence._synthetic_full_route_for_tests()
assert evidence._cycle_launch_authorized(synthetic,None)
assert not evidence._cycle_launch_authorized(synthetic,grant())
assert evidence._classify_route(evidence._fixed_full_route())=="production"
assert evidence._classify_route(synthetic)=="synthetic"
assert evidence._classify_route(evidence._diagnostic_full_route())=="diagnostic"

# Exercise the unmocked receipt transaction in an isolated realm with exact
# typed terminal owners and production-shaped records. Alternate dependencies
# cannot mint into the module's production receipt registry.
class DiagnosticCustody:
    def __init__(self):self.close_attempts=0
class FormalCustody:
    def __init__(self):self.close_attempts=0

def diagnostic_lineage(custody):
    if type(custody) is not DiagnosticCustody or custody.close_attempts:
        raise ValueError("exact diagnostic custody required")
    return {"version":"cogs.stage2-current-source-prebuilt-diagnostic-custody-lineage/v1",
            "authority":"diagnostic-only-split-lineage-no-mint"}
def formal_binding(custody):
    if type(custody) is not FormalCustody or custody.close_attempts:
        raise ValueError("exact formal custody required")
    return {"source_head":"1"*40}
def close_custody(custody):
    if type(custody) not in {DiagnosticCustody,FormalCustody} or custody.close_attempts:
        raise ValueError("custody close replay")
    custody.close_attempts+=1

def rec(sequence,kind,body):
    digest=hashlib.sha256(f"{sequence}:{kind}".encode("ascii")).hexdigest()
    return operation.Record(sequence,sequence*10,(sequence+1)*10,digest,kind,body)
def terminal(route,raw_bytes,production=False):
    name,capability,program,marker=evidence._describe_route(route); token=d("8"); boot="boot-fixture"
    grant_names=("batch_commitment","cycle_ordinal","implementation_revision",
                 "control_revision","static_control_sha256","rootfs_descriptor_sha256",
                 "ami_commitment","plan_sha256","grant_commitment")
    parser = (operation.SSH_PARSER_SHA256 if name == "full"
              else operation.guest_readiness.PARSER_SHA256)
    route_body={"operation_token":token,"route":name,
                "cycle_capability_sha256":capability,"program_sha256":program,
                "parser_source_sha256":parser,
                "marker_sha256":marker,"grant_authority":"production" if production else "synthetic",
                **{key:None for key in grant_names}}
    rows=[rec(0,"GENESIS",{"operation_token":token,"host_boot_id":boot}),
          rec(1,"CYCLE_ROUTE_V1",route_body),
          rec(2,"CTR_LAUNCH_ISSUED_V1",{"kata_launch_started_boottime_ns":10,"host_boot_id":boot}),
          rec(3,"SSH_MARKER_OBSERVED_V1",{"ssh_marker_observed_boottime_ns":20,"host_boot_id":boot}),
          rec(4,"SSH_COMMAND_SETTLED_V1",{"ssh_command_settled_boottime_ns":30,
              "host_boot_id":boot,"parser_sha256":parser}),
          rec(5,"COMMAND_INTENT_V2",{"command_id":"CTR_RUN"}),
          rec(6,"COMMAND_INTENT_V2",{"command_id":"SSH_READY" if name=="full" else "SSH_READINESS"}),
          rec(7,"INPUT_GRANT",{"action":"settled","path":"@key-stage/client"}),
          rec(8,"INPUT_GRANT",{"action":"settled","path":"@key-stage/server"}),
          rec(9,"NETWORK_SNAPSHOT_V2",{"snapshot_kind":"runtime","proof_sha256":d("9")})]
    for kind in evidence.PRIVATE_TEARDOWN_RECORDS:
        rows.append(rec(len(rows),kind,{"operation_token":token}))
    parsed=evidence.full_guest.GuestWorkloadResult(
        d("a"),tuple(evidence.full_guest.GuestSampleResult(
            ordinal,label,ordinal,d("b"),True)
            for ordinal,(label,_digest) in enumerate(evidence.full_guest.GUEST_WORKLOAD_PLAN,1)),
        evidence.full_guest.GUEST_NETWORK_MARKERS,d("c"),d("c"))
    full_session=ssh.AuthenticatedSession(1,d("d"),program,d("e"),d("f"),parsed)
    readiness_session=ssh.ReadinessAuthenticatedSession(
        1,d("d"),evidence.readiness_guest.GUEST_PROGRAM_SHA256,
        evidence.readiness_guest.MARKER_SHA256,evidence.readiness_guest.MARKER_SHA256)
    observed=owner_evidence._PlatformOwnerResult(
        token,d("1"),d("2"),d("3"),101,102,8,9,10,11,12,13,14,12,True,True)
    residue=owner_evidence._ResidueOwnerResult(token,d("4"),local.RESIDUE_FACTS)
    if name=="full":
        runtime=owner_evidence._RuntimeOwnerResult(
            token,d("5"),d("6"),d("1"),d("2"),d("3"),101,102,
            8,9,10,11,12,13,14,12,True,True)
        session=full_session
    else:
        runtime=evidence._issue_runtime_readiness_owner_result(
            operation_token=token,runtime_mount_record_sha256=d("5"),
            runtime_network_sha256=d("9"),live_mapping_sha256=d("1"),
            qemu_process_sha256=d("2"),qmp_identity=(101,102,8,9,10,11,12,13,14,12))
        session=readiness_session
    lifecycle=SimpleNamespace(
        retired=owner_evidence._RetiredJournalOwnerResult(raw_bytes),residue=residue,
        runtime_observation=observed,runtime_proof=runtime,session=session,
        static_custody=DiagnosticCustody())
    return tuple(rows),lifecycle

fixture_records={}
def parse_terminal(raw_bytes):return fixture_records[raw_bytes]
_receipt_types,_,issue_diagnostic,validate_diagnostic,consume_diagnostic=evidence._new_cycle_receipt_routes(
    parse_terminal,formal_binding,diagnostic_lineage,close_custody)
assert validate_diagnostic.__code__ is evidence._validate_and_discard_cycle_receipt.__code__
settle=inspect.getclosurevars(validate_diagnostic).nonlocals["settle"]
registry=inspect.getclosurevars(settle).nonlocals["receipts"]
production_settle=inspect.getclosurevars(
    evidence._validate_and_discard_cycle_receipt).nonlocals["settle"]
production_registry=inspect.getclosurevars(production_settle).nonlocals["receipts"]
assert not registry and not production_registry
for route,label in ((evidence._diagnostic_full_route(),b"diagnostic-full\n"),
                    (evidence._diagnostic_readiness_route(),b"diagnostic-readiness\n")):
    records,lifecycle=terminal(route,label);fixture_records[label]=records
    try:issue_diagnostic(route,lifecycle)
    except evidence.CycleEvidenceError:pass
    else:raise AssertionError("diagnostic mint path accepted")
    assert lifecycle.static_custody.close_attempts==0 and not registry
    assert validate_diagnostic(route,lifecycle) is None
    assert lifecycle.static_custody.close_attempts==1 and not registry
    try:consume_diagnostic(object())
    except evidence.CycleEvidenceError:pass
    else:raise AssertionError("discarded diagnostic registered a receipt")

# A diagnostic journal can neither claim production authority nor substitute
# formal custody; both failures still transfer custody to exactly one close.
route=evidence._diagnostic_full_route()
for label,production,formal in ((b"production-labelled-diagnostic\n",True,False),
                                (b"formal-custody-diagnostic\n",False,True)):
    records,lifecycle=terminal(route,label,production);fixture_records[label]=records
    if formal:lifecycle.static_custody=FormalCustody()
    try:validate_diagnostic(route,lifecycle)
    except evidence.CycleEvidenceError:pass
    else:raise AssertionError("hostile diagnostic terminal accepted")
    assert lifecycle.static_custody.close_attempts==1 and not registry
assert not production_registry

for hostile in (b"{}\n",raw(grant())[:-1],raw(grant())+b" ",raw(grant()).replace(b'"ordinal":1',b'"ordinal":2')):
    try: authority.decode(hostile)
    except (authority.CycleAuthorityError,campaign.ProductionCampaignError): pass
    else: raise AssertionError("hostile cycle authority accepted")
print("stage2 fixed cycle authority checks passed")

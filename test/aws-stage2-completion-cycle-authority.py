#!/usr/bin/env python3
"""Portable fixed-file cycle grant and route authority checks."""

import json,os
from pathlib import Path
import sys,tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"deploy/aws-feasibility/remote"))
sys.path.insert(0,str(ROOT/"deploy/aws-feasibility"))
import completion_campaign_production as campaign
import completion_cycle_authority as authority
import completion_cycle_evidence as evidence
import completion_kata_operation as operation


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
    with tempfile.TemporaryDirectory() as temporary:
        parent=Path(temporary)/"cycle";parent.mkdir(mode=0o700);parent.chmod(0o700);path=parent/"grant.json"
        path.write_bytes(encoded);path.chmod(0o400);authority._claimed=False
        seen=parent.lstat();observed=authority._claim(path,mode,(seen.st_uid,seen.st_gid))
        assert observed==value and not parent.exists()

synthetic=evidence._synthetic_full_route_for_tests()
assert evidence._cycle_launch_authorized(synthetic,None)
assert not evidence._cycle_launch_authorized(synthetic,grant())
for hostile in (b"{}\n",raw(grant())[:-1],raw(grant())+b" ",raw(grant()).replace(b'"ordinal":1',b'"ordinal":2')):
    try: authority.decode(hostile)
    except (authority.CycleAuthorityError,campaign.ProductionCampaignError): pass
    else: raise AssertionError("hostile cycle authority accepted")
print("stage2 fixed cycle authority checks passed")

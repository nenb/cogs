#!/usr/bin/env python3
"""Canonical non-AWS issuer for one authenticated Stage 2 campaign approval."""
from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
import completion_campaign_production as production

MAX_BYTES = 256 * 1024
SHA1 = re.compile(r"[0-9a-f]{40}")
POSITIVE = re.compile(r"[1-9][0-9]*")


class ApprovalIssuerError(Exception): pass


def require(value):
    if not value: raise ApprovalIssuerError()


def pairs(rows):
    value = {}
    for key, item in rows:
        require(type(key) is str and key not in value); value[key] = item
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def read(path):
    raw = Path(path).read_bytes()
    require(0 < len(raw) <= MAX_BYTES and raw.endswith(b"\n") and b"\r" not in raw)
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise ApprovalIssuerError() from error
    require(type(value) is dict and canonical(value) == raw)
    return raw, value


def digest(domain, value):
    return hashlib.sha256(domain + b"\0" + canonical(value)[:-1]).hexdigest()


def environment():
    revision = os.environ.get("GITHUB_SHA", "")
    control = os.environ.get("COGS_STAGE2_CONTROL_REVISION", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    actor = os.environ.get("GITHUB_ACTOR", "")
    require(SHA1.fullmatch(revision) is not None and SHA1.fullmatch(control) is not None
            and revision != control and POSITIVE.fullmatch(run_id) is not None
            and actor == "nenb" and os.environ.get("GITHUB_RUN_ATTEMPT") == "1")
    return revision, control, int(run_id), actor


def issue(path):
    revision, control, run_id, actor = environment()
    _raw, draft = read(path)
    require(draft.pop("version", None) == "cogs.stage2-production-approval-draft/v2")
    allowed = {item.name for item in fields(production.ProductionApproval)} - {
        "version", "phrase", "batch_commitment", "issuer_commitment",
        "rate_source_commitment", "one_attempt"}
    require(set(draft) == allowed and draft.get("control_revision") == control)
    issuer = digest(b"cogs.stage2-production-approval-issuer/v1", {
        "workflow": ".github/workflows/stage2-production-approval.yml",
        "workflow_revision": revision, "control_revision": control,
        "run_id": run_id, "actor": actor})
    value = {
        "version": "cogs.stage2-completion-production-approval/v4",
        "phrase": production.APPROVAL_PHRASE,
        **draft,
        "rate_source_commitment": production.RATE_SOURCE_COMMITMENT,
        "issuer_commitment": issuer, "one_attempt": True,
    }
    value["plan_sha256s"] = tuple(value["plan_sha256s"])
    value["batch_commitment"] = production.approval_batch_commitment(value)
    approval = production.ProductionApproval(**value)
    output = approval.__dict__.copy(); output["plan_sha256s"] = list(approval.plan_sha256s)
    sys.stdout.buffer.write(canonical(output))


def authenticate(approval_path):
    revision, control, run_id, actor = environment()
    approval_raw, approval_value = read(approval_path)
    approval_value["plan_sha256s"] = tuple(approval_value["plan_sha256s"])
    approval = production.ProductionApproval(**approval_value)
    require(approval.control_revision == control)
    executor = os.environ.get("COGS_STAGE2_EXECUTOR_PRINCIPAL_COMMITMENT", "")
    production._digest(executor)
    require(executor == approval.executor_principal_commitment)
    approver = digest(b"cogs.stage2-approval-principal/v1", {"actor": actor})
    require(approver != executor)
    value = {
        "version": "cogs.stage2-production-approval-authentication/v1",
        "result": "pass", "approval_sha256": hashlib.sha256(approval_raw).hexdigest(),
        "issuer_commitment": approval.issuer_commitment,
        "workflow_sha256": os.environ.get("COGS_STAGE2_APPROVAL_WORKFLOW_SHA256", ""),
        "workflow_run_id": run_id, "workflow_run_attempt": 1,
        "control_revision": control,
        "approver_principal_commitment": approver,
        "executor_principal_commitment": executor,
        "inventory_observer_principal_commitment":
            approval.inventory_observer_principal_commitment,
        "first_created": True,
    }
    production._digest(value["workflow_sha256"])
    sys.stdout.buffer.write(canonical(value))


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3)
        if sys.argv[1] == "issue" and len(sys.argv) == 3: issue(sys.argv[2])
        elif sys.argv[1] == "authenticate" and len(sys.argv) == 3:
            authenticate(sys.argv[2])
        else: raise ApprovalIssuerError()
    except (ApprovalIssuerError, OSError, production.ProductionCampaignError):
        raise SystemExit(2)

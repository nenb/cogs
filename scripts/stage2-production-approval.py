#!/usr/bin/env python3
"""Canonical v6 approval tooling and explicit bounded GitHub OIDC/STS helper.

Package authenticity comes from the separately authenticated workflow artifact;
the static issue/authentication paths never authorize provider effects. Only the
``assume-github-role`` command performs the one-shot credential exchange.
"""
import base64
from dataclasses import fields
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import ssl
import stat
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import (HTTPRedirectHandler, HTTPSHandler, ProxyHandler,
                            Request, build_opener)
from xml.etree import ElementTree

_DIAGNOSTIC = b"stage2-production-approval: owner.failed\n"


def _fail():
    try: os.write(2, _DIAGNOSTIC)
    except BaseException: pass
    raise SystemExit(2) from None


try:
    ROOT = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(ROOT / "deploy/aws-feasibility"))
    import completion_campaign_production as production
    retirement = runpy.run_path(str(ROOT / "scripts/stage2-revision-retirement.py"))
except BaseException:
    if __name__ == "__main__": _fail()
    raise

MAX_BYTES = 256 * 1024
SHA1 = re.compile(r"[0-9a-f]{40}")
POSITIVE = re.compile(r"[1-9][0-9]*")
AWS_ACCOUNT_ID = "372495030090"
AWS_REGION = "us-east-1"
STS_URL = "https://sts.us-east-1.amazonaws.com/"
ISSUANCE_ROOT = Path("/var/lib/cogs/stage2-aws-issuance-v1")
ISSUANCE_APPROVAL = ISSUANCE_ROOT / "approval.json"
ISSUANCE_AUTHENTICATION = ISSUANCE_ROOT / "approval-authentication.json"
ISSUANCE_PACKAGE = ISSUANCE_ROOT / production.QUALIFICATION_PACKAGE_NAME
ISSUANCE_CONTINUATION = ISSUANCE_ROOT / "aws-stage2-production-continuation-v1.json"
ISSUANCE_CONTINUATION_BUNDLE = ISSUANCE_ROOT / "aws-stage2-production-continuation-v1.bundle.json"
ISSUANCE_ADMISSION = ISSUANCE_ROOT / "aws-stage2-production-continuation-admission-v1.json"
AUTHENTICATION_FIELDS = {
    "version", "result", "approval_sha256", "issuer_commitment",
    "workflow_sha256", "workflow_run_id", "workflow_run_attempt",
    "control_revision", "approver_principal_commitment",
    "executor_principal_commitment", "inventory_observer_principal_commitment",
    "first_created",
}


class ApprovalIssuerError(Exception): pass


def require(value):
    if not value: raise ApprovalIssuerError()


def eligible(revisions):
    try: retirement["select"](tuple(revisions))
    except (TypeError, ValueError) as error: raise ApprovalIssuerError() from error


def pairs(rows):
    value = {}
    for key, item in rows:
        require(type(key) is str and key not in value); value[key] = item
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def emit(raw):
    offset = 0
    while offset < len(raw):
        written = os.write(1, raw[offset:])
        require(written > 0)
        offset += written


def _read_regular(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= maximum)
        chunks, total = [], 0
        while total <= maximum:
            part = os.read(descriptor, min(65536, maximum + 1 - total))
            if not part: break
            chunks.append(part); total += len(part)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                 item.st_gid, item.st_nlink, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        raw = b"".join(chunks)
        require(len(raw) == before.st_size and identity(before) == identity(after))
        return raw
    finally: os.close(descriptor)


def read(path):
    raw = _read_regular(path, MAX_BYTES)
    require(raw.endswith(b"\n") and b"\r" not in raw)
    try: value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise ApprovalIssuerError() from error
    require(type(value) is dict and canonical(value) == raw)
    return raw, value


def validate_package(path, approval):
    raw, package = read(Path(path).with_name(production.QUALIFICATION_PACKAGE_NAME))
    production.validate_approval_package(approval, package, hashlib.sha256(raw).hexdigest())


def eligibility(path):
    _raw, value = read(path)
    eligible((value.get("implementation_revision"), value.get("control_revision"),
              value.get("qualification_revision")))
    value["plan_sha256s"] = tuple(value["plan_sha256s"])
    value["phase_cycle_counts"] = tuple(value["phase_cycle_counts"])
    validate_package(path, production.ProductionApproval(**value))


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
    eligible((draft.get("implementation_revision"), draft.get("control_revision"),
              draft.get("qualification_revision")))
    require(draft.pop("version", None) == "cogs.stage2-production-approval-draft/v4")
    allowed = {item.name for item in fields(production.ProductionApproval)} - {
        "version", "phrase", "batch_commitment", "issuer_commitment",
        "rate_source_commitment", "one_attempt"}
    require(set(draft) == allowed and draft.get("control_revision") == control)
    issuer = digest(b"cogs.stage2-production-approval-issuer/v1", {
        "workflow": ".github/workflows/stage2-production-approval.yml",
        "workflow_revision": revision, "control_revision": control,
        "run_id": run_id, "actor": actor})
    value = {
        "version": "cogs.stage2-completion-production-approval/v6",
        "phrase": production.APPROVAL_PHRASE,
        **draft,
        "rate_source_commitment": production.RATE_SOURCE_COMMITMENT,
        "issuer_commitment": issuer, "one_attempt": True,
    }
    value["plan_sha256s"] = tuple(value["plan_sha256s"])
    value["phase_cycle_counts"] = tuple(value["phase_cycle_counts"])
    value["batch_commitment"] = production.approval_batch_commitment(value)
    approval = production.ProductionApproval(**value)
    validate_package(path, approval)
    output = approval.__dict__.copy()
    output["plan_sha256s"] = list(approval.plan_sha256s)
    output["phase_cycle_counts"] = list(approval.phase_cycle_counts)
    emit(canonical(output))


def _bounded_response(response, maximum):
    raw = response.read(maximum + 1)
    require(0 < len(raw) <= maximum)
    return raw


def _jwt_claims(token):
    require(type(token) is str and token.count(".") == 2 and len(token) <= 16 * 1024)
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    try: value = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ApprovalIssuerError() from error
    require(type(value) is dict)
    return value


class _RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        del request, file_pointer, code, message, headers, new_url
        raise ApprovalIssuerError()


def _direct_https_opener():
    context = ssl.create_default_context()
    require(context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED)
    return build_opener(ProxyHandler({}), HTTPSHandler(context=context), _RejectRedirect())


def _approved_oidc_url(request_url):
    parsed = urlsplit(request_url)
    token_id = r"[0-9A-Fa-f-]{32,36}"
    token_path = rf"/{token_id}/_apis/distributedtask/hubs/[A-Za-z0-9._-]{{1,64}}/plans/{token_id}/jobs/{token_id}/idtoken"
    require(
        parsed.scheme == "https"
        and parsed.hostname == "pipelines.actions.githubusercontent.com"
        and parsed.port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and re.fullmatch(token_path, parsed.path)
    )
    query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    require(query == [("api-version", "2.0")])
    return urlunsplit(
        (
            "https",
            parsed.netloc,
            parsed.path,
            urlencode([*query, ("audience", "sts.amazonaws.com")]),
            "",
        )
    )


def _root_issuance_read(path, maximum):
    require(path.parent == ISSUANCE_ROOT)
    root, item = ISSUANCE_ROOT.lstat(), path.lstat()
    require(
        stat.S_ISDIR(root.st_mode)
        and root.st_uid == root.st_gid == 0
        and stat.S_IMODE(root.st_mode) == 0o555
        and not ISSUANCE_ROOT.is_symlink()
        and stat.S_ISREG(item.st_mode)
        and item.st_uid == item.st_gid == 0
        and item.st_nlink == 1
        and stat.S_IMODE(item.st_mode) == 0o444
    )
    return _read_regular(path, maximum)


def _validated_role_authority(selector, role_arn, approval_path):
    require(selector in {"executor", "observer"} and Path(approval_path) == ISSUANCE_APPROVAL)
    match = re.fullmatch(r"arn:(aws):iam::(372495030090):role/([A-Za-z0-9+=,.@_-]{1,64})", role_arn)
    require(match is not None)
    partition, account_id, role_name = match.groups()
    approval_raw = _root_issuance_read(ISSUANCE_APPROVAL, MAX_BYTES)
    authentication_raw = _root_issuance_read(ISSUANCE_AUTHENTICATION, MAX_BYTES)
    package_raw = _root_issuance_read(ISSUANCE_PACKAGE, MAX_BYTES)
    try:
        value, authentication, package = map(
            json.loads, (approval_raw, authentication_raw, package_raw)
        )
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise ApprovalIssuerError() from error
    require(
        canonical(value) == approval_raw
        and canonical(authentication) == authentication_raw
        and canonical(package) == package_raw
    )
    value["plan_sha256s"] = tuple(value.get("plan_sha256s", ()))
    value["phase_cycle_counts"] = tuple(value.get("phase_cycle_counts", ()))
    approval = production.ProductionApproval(**value)
    production.validate_approval_package(approval, package, hashlib.sha256(package_raw).hexdigest())
    require(
        set(authentication) == AUTHENTICATION_FIELDS
        and authentication.get("version") == "cogs.stage2-production-approval-authentication/v1"
        and authentication.get("result") == "pass"
        and authentication.get("first_created") is True
        and authentication.get("workflow_run_attempt") == 1
        and authentication.get("approval_sha256") == hashlib.sha256(approval_raw).hexdigest()
        and authentication.get("issuer_commitment") == approval.issuer_commitment
        and authentication.get("control_revision") == approval.control_revision
        and authentication.get("executor_principal_commitment")
        == approval.executor_principal_commitment
        and authentication.get("inventory_observer_principal_commitment")
        == approval.inventory_observer_principal_commitment
        and approval.partition == partition == "aws"
        and approval.region == AWS_REGION
        and hashlib.sha256(account_id.encode("ascii")).hexdigest() == approval.account_commitment
    )
    expected = (
        approval.executor_principal_commitment
        if selector == "executor"
        else approval.inventory_observer_principal_commitment
    )
    require(production.executor_principal_commitment(partition, account_id, role_name) == expected)
    return approval, hashlib.sha256(authentication_raw).hexdigest(), account_id, role_name


def assume_github_role(
    selector, role_arn, session_name, duration_raw, minimum_raw, approval_path, runway_path=None
):
    """One-shot direct GitHub OIDC/regional STS exchange for an approved role."""
    approval, authentication_sha256, account_id, role_name = _validated_role_authority(
        selector, role_arn, approval_path
    )
    require(
        re.fullmatch(r"[A-Za-z0-9+=,.@_-]{2,64}", session_name)
        and POSITIVE.fullmatch(duration_raw)
        and POSITIVE.fullmatch(minimum_raw)
    )
    duration, minimum, now = int(duration_raw), int(minimum_raw), int(time.time())
    require(900 <= minimum <= duration <= 43200)
    runway_deadline = approval.expires_unix_ns
    if runway_path is not None:
        require(Path(runway_path) == ISSUANCE_CONTINUATION)
        runway_raw = _root_issuance_read(ISSUANCE_CONTINUATION, 4 * 1024 * 1024)
        bundle_raw = _root_issuance_read(ISSUANCE_CONTINUATION_BUNDLE, 1024 * 1024)
        admission_raw = _root_issuance_read(ISSUANCE_ADMISSION, 64 * 1024)
        try:
            preliminary = json.loads(admission_raw)
        except (UnicodeError, ValueError, TypeError, RecursionError) as error:
            raise ApprovalIssuerError() from error
        continuation = production.continuation_from_bytes(
            runway_raw,
            approval,
            preliminary.get("run_id"),
            preliminary.get("run_attempt"),
            "authenticated-aws-adapter",
        )
        admission = production.admission_from_bytes(admission_raw, continuation, approval)
        require(
            continuation.consumption.authentication_receipt_sha256 == authentication_sha256
            and admission.continuation_sha256 == hashlib.sha256(runway_raw).hexdigest()
            and admission.bundle_sha256 == hashlib.sha256(bundle_raw).hexdigest()
        )
        runway_deadline = min(runway_deadline, continuation.cleanup_deadline_unix_ns)
    require(duration <= runway_deadline // 1_000_000_000 - now - 900)
    # The private opener disables proxies and redirects before either token is read.
    opener = _direct_https_opener()
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    oidc_url = _approved_oidc_url(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""))
    require("\r" not in request_token and "\n" not in request_token and len(request_token) >= 32)
    with opener.open(
        Request(oidc_url, headers={"Authorization": f"Bearer {request_token}"}), timeout=30
    ) as response:
        require(getattr(response, "status", 200) == 200 and response.geturl() == oidc_url)
        oidc = json.loads(_bounded_response(response, 24 * 1024))
    oidc_now = int(time.time())
    require(type(oidc) is dict and set(oidc) == {"value"})
    web_identity = oidc["value"]
    claims = _jwt_claims(web_identity)
    audience = claims.get("aud")
    require(
        (
            audience == "sts.amazonaws.com"
            or type(audience) is list
            and audience == ["sts.amazonaws.com"]
        )
        and claims.get("iss") == "https://token.actions.githubusercontent.com"
        and claims.get("sub") == "repo:nenb/cogs:ref:refs/heads/main"
        and type(claims.get("exp")) is int
        and claims["exp"] >= oidc_now + 60
    )
    body = urlencode(
        {
            "Action": "AssumeRoleWithWebIdentity",
            "Version": "2011-06-15",
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "WebIdentityToken": web_identity,
            "DurationSeconds": str(duration),
        }
    ).encode("ascii")
    with opener.open(
        Request(STS_URL, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}),
        timeout=60,
    ) as response:
        require(getattr(response, "status", 200) == 200 and response.geturl() == STS_URL)
        sts_raw = _bounded_response(response, 64 * 1024)
    try:
        xml = ElementTree.fromstring(sts_raw)
    except ElementTree.ParseError as error:
        raise ApprovalIssuerError() from error
    namespace = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
    require(
        xml.tag == "{https://sts.amazonaws.com/doc/2011-06-15/}AssumeRoleWithWebIdentityResponse"
    )

    def response_text(path):
        node = xml.find(path, namespace)
        require(node is not None and type(node.text) is str)
        return node.text

    credentials = ".//s:Credentials/s:"
    access, secret, token, expiration = (
        response_text(credentials + name)
        for name in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration")
    )
    assumed_arn, assumed_id = response_text(".//s:AssumedRoleUser/s:Arn"), response_text(
        ".//s:AssumedRoleUser/s:AssumedRoleId"
    )
    require(
        assumed_arn == f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
        and re.fullmatch(rf"[A-Z0-9]{{16,128}}:{re.escape(session_name)}", assumed_id)
        and re.fullmatch(r"ASIA[A-Z0-9]{16}", access)
        and re.fullmatch(r"[A-Za-z0-9/+=]{40,128}", secret)
        and 100 <= len(token) <= 8192
        and token.isascii()
        and all(
            "\n" not in item and "\r" not in item and "\0" not in item
            for item in (access, secret, token)
        )
    )
    try:
        require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", expiration))
        expires = int(datetime.strptime(expiration, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except (ValueError, OverflowError) as error:
        raise ApprovalIssuerError() from error
    response_now = int(time.time())
    require(
        duration <= runway_deadline // 1_000_000_000 - response_now - 900
        and expires >= response_now + minimum
        and expires >= response_now + duration - 60
        and expires <= response_now + duration + 300
        and expires <= runway_deadline // 1_000_000_000
    )
    for value in (access, secret, token):
        command = f"::add-mask::{value}\n".encode("ascii")
        require(os.write(1, command) == len(command))
    descriptor = os.open(
        Path(os.environ.get("GITHUB_ENV", "")),
        os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(descriptor)
        caller_uid = (
            int(os.environ["SUDO_UID"])
            if os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit()
            else os.geteuid()
        )
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == caller_uid
            and stat.S_IMODE(info.st_mode) & 0o022 == 0
        )
        os.fchmod(descriptor, 0o600)
        output = (
            f"AWS_ACCESS_KEY_ID={access}\nAWS_SECRET_ACCESS_KEY={secret}\nAWS_SESSION_TOKEN={token}\nAWS_DEFAULT_REGION={AWS_REGION}\nAWS_REGION={AWS_REGION}\n"
        ).encode("ascii")
        require(os.write(descriptor, output) == len(output))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def authenticate(approval_path):
    revision, control, run_id, actor = environment()
    approval_raw, approval_value = read(approval_path)
    eligible((approval_value.get("implementation_revision"), approval_value.get("control_revision"),
              approval_value.get("qualification_revision")))
    approval_value["plan_sha256s"] = tuple(approval_value["plan_sha256s"])
    approval_value["phase_cycle_counts"] = tuple(approval_value["phase_cycle_counts"])
    approval = production.ProductionApproval(**approval_value)
    validate_package(approval_path, approval)
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
    emit(canonical(value))


if __name__ == "__main__":
    try:
        require(len(sys.argv) in {3, 8, 9})
        if sys.argv[1] == "assume-github-role" and len(sys.argv) in {8, 9}:
            assume_github_role(*sys.argv[2:])
        elif sys.argv[1] == "issue" and len(sys.argv) == 3: issue(sys.argv[2])
        elif sys.argv[1] == "authenticate" and len(sys.argv) == 3:
            authenticate(sys.argv[2])
        elif sys.argv[1] == "eligibility" and len(sys.argv) == 3:
            eligibility(sys.argv[2])
        else: raise ApprovalIssuerError()
    except BaseException: _fail()

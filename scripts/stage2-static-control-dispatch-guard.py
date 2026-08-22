"""Versioned authenticated guard for the sole replacement no-KVM static-control event."""
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

GUARD_VERSION = "cogs.stage2-static-control-dispatch-guard/v14"
REPOSITORY = "nenb/cogs"
WORKFLOW_NAME = "stage2-local-static-control-candidate.yml"
WORKFLOW_PATH = f".github/workflows/{WORKFLOW_NAME}"
REVIEWED_IMPLEMENTATION_HEAD = "33314a9999cbe1e0eb927ba4a1e6f1ee10fcd5df"
RUN_TITLE = f"Non-authoritative Stage 2 static control H={REVIEWED_IMPLEMENTATION_HEAD}"
PREDECESSOR_RUN_ID = 32558263561
PREDECESSOR_WORKFLOW_HEAD = "a201d5688013377069b6fb4a36159360dc307cae"
PREDECESSOR_REVIEWED_HEAD = "62bcfbcd58f90d0e329683e3297693c32bb71877"
PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={PREDECESSOR_REVIEWED_HEAD}")
SECOND_PREDECESSOR_RUN_ID = 32560385792
SECOND_PREDECESSOR_WORKFLOW_HEAD = "7ccb35d14d749a0ef14602889ce2b52934c03d4d"
SECOND_PREDECESSOR_REVIEWED_HEAD = "67b1ca45f101f98c56b2717549e9252a38a9f2a1"
SECOND_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={SECOND_PREDECESSOR_REVIEWED_HEAD}")
THIRD_PREDECESSOR_RUN_ID = 32561859288
THIRD_PREDECESSOR_WORKFLOW_HEAD = "549126bd7ba72d571d53113722e766967aaa0d23"
THIRD_PREDECESSOR_REVIEWED_HEAD = "5f8c04899422ccf546c0f500b3647a5816b2675c"
THIRD_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={THIRD_PREDECESSOR_REVIEWED_HEAD}")
FOURTH_PREDECESSOR_RUN_ID = 32563007701
FOURTH_PREDECESSOR_WORKFLOW_HEAD = "7f43d9acc5897b11b5d9794eb2e184767446aa48"
FOURTH_PREDECESSOR_REVIEWED_HEAD = "d05bbc5928bda9b6bd27da1c290b0238219fd185"
FOURTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={FOURTH_PREDECESSOR_REVIEWED_HEAD}")
FIFTH_PREDECESSOR_RUN_ID = 32564546902
FIFTH_PREDECESSOR_WORKFLOW_HEAD = "dd0e604afabe32f184ede5ec5c3ae2bbecdf464c"
FIFTH_PREDECESSOR_REVIEWED_HEAD = "a263b7eb38b1b0aa4a3732cf3d7a2d72db243109"
FIFTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={FIFTH_PREDECESSOR_REVIEWED_HEAD}")
SIXTH_PREDECESSOR_RUN_ID = 32565389560
SIXTH_PREDECESSOR_WORKFLOW_HEAD = "b5fc2996695d8b9fb0621df556cf4c3e66b5c526"
SIXTH_PREDECESSOR_REVIEWED_HEAD = "fdd4b82d07a218d10c7bce11c8146689e4cafdc1"
SIXTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={SIXTH_PREDECESSOR_REVIEWED_HEAD}")
SEVENTH_PREDECESSOR_RUN_ID = 32566515932
SEVENTH_PREDECESSOR_WORKFLOW_HEAD = "0bbb7047e451d1957302b705242d0fa6e8058006"
SEVENTH_PREDECESSOR_REVIEWED_HEAD = "130832252da16efa1772e76b07051d50f20973ca"
SEVENTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={SEVENTH_PREDECESSOR_REVIEWED_HEAD}")
EIGHTH_PREDECESSOR_RUN_ID = 32568536415
EIGHTH_PREDECESSOR_WORKFLOW_HEAD = "9642dcd247aedc0a29068be3aa4e8873db89de3a"
EIGHTH_PREDECESSOR_REVIEWED_HEAD = "94ad8206c696f950fdcdbba2a6ea2bb0136e76d9"
EIGHTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={EIGHTH_PREDECESSOR_REVIEWED_HEAD}")
NINTH_PREDECESSOR_RUN_ID = 32569177840
NINTH_PREDECESSOR_WORKFLOW_HEAD = "0da45c37b0a0cf73e288eb9c3f8b23c436f25ac6"
NINTH_PREDECESSOR_REVIEWED_HEAD = "25bfbb4277c9051da352e9c699d4ca98dcb248e2"
NINTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={NINTH_PREDECESSOR_REVIEWED_HEAD}")
TENTH_PREDECESSOR_RUN_ID = 32569932861
TENTH_PREDECESSOR_WORKFLOW_HEAD = "ee789aecc77319909186b4a7d769227896fb3c66"
TENTH_PREDECESSOR_REVIEWED_HEAD = "dd676027801370f7bf025539b8c2c14991689afa"
TENTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={TENTH_PREDECESSOR_REVIEWED_HEAD}")
ELEVENTH_PREDECESSOR_RUN_ID = 32574273244
ELEVENTH_PREDECESSOR_WORKFLOW_HEAD = "c727b167cea2f470807588df913d815148fbb858"
ELEVENTH_PREDECESSOR_REVIEWED_HEAD = "7b1dcc045182616cf657bcf941ba8aee7108eb76"
ELEVENTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={ELEVENTH_PREDECESSOR_REVIEWED_HEAD}")
TWELFTH_PREDECESSOR_RUN_ID = 32576106736
TWELFTH_PREDECESSOR_WORKFLOW_HEAD = "8dd6d58f4f9e24a2f1bcccbd4719fbf03e72bbb2"
TWELFTH_PREDECESSOR_REVIEWED_HEAD = "4a3beae8683309f3fef30cecce3187262efc4b23"
TWELFTH_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={TWELFTH_PREDECESSOR_REVIEWED_HEAD}")
SUCCESSFUL_PREDECESSOR_RUN_ID = 32577727971
SUCCESSFUL_PREDECESSOR_WORKFLOW_HEAD = "c2540af5cb85e2845de1eebfad3475d28c0483e5"
SUCCESSFUL_PREDECESSOR_REVIEWED_HEAD = "59d992b305cfd243f2d7b9c770fe24b0a36cc053"
SUCCESSFUL_PREDECESSOR_RUN_TITLE = (
    f"Non-authoritative Stage 2 static control H={SUCCESSFUL_PREDECESSOR_REVIEWED_HEAD}")
PREDECESSORS = {
    PREDECESSOR_RUN_ID: (PREDECESSOR_WORKFLOW_HEAD, PREDECESSOR_RUN_TITLE),
    SECOND_PREDECESSOR_RUN_ID: (
        SECOND_PREDECESSOR_WORKFLOW_HEAD, SECOND_PREDECESSOR_RUN_TITLE),
    THIRD_PREDECESSOR_RUN_ID: (
        THIRD_PREDECESSOR_WORKFLOW_HEAD, THIRD_PREDECESSOR_RUN_TITLE),
    FOURTH_PREDECESSOR_RUN_ID: (
        FOURTH_PREDECESSOR_WORKFLOW_HEAD, FOURTH_PREDECESSOR_RUN_TITLE),
    FIFTH_PREDECESSOR_RUN_ID: (
        FIFTH_PREDECESSOR_WORKFLOW_HEAD, FIFTH_PREDECESSOR_RUN_TITLE),
    SIXTH_PREDECESSOR_RUN_ID: (
        SIXTH_PREDECESSOR_WORKFLOW_HEAD, SIXTH_PREDECESSOR_RUN_TITLE),
    SEVENTH_PREDECESSOR_RUN_ID: (
        SEVENTH_PREDECESSOR_WORKFLOW_HEAD, SEVENTH_PREDECESSOR_RUN_TITLE),
    EIGHTH_PREDECESSOR_RUN_ID: (
        EIGHTH_PREDECESSOR_WORKFLOW_HEAD, EIGHTH_PREDECESSOR_RUN_TITLE),
    NINTH_PREDECESSOR_RUN_ID: (
        NINTH_PREDECESSOR_WORKFLOW_HEAD, NINTH_PREDECESSOR_RUN_TITLE),
    TENTH_PREDECESSOR_RUN_ID: (
        TENTH_PREDECESSOR_WORKFLOW_HEAD, TENTH_PREDECESSOR_RUN_TITLE),
    ELEVENTH_PREDECESSOR_RUN_ID: (
        ELEVENTH_PREDECESSOR_WORKFLOW_HEAD, ELEVENTH_PREDECESSOR_RUN_TITLE),
    TWELFTH_PREDECESSOR_RUN_ID: (
        TWELFTH_PREDECESSOR_WORKFLOW_HEAD, TWELFTH_PREDECESSOR_RUN_TITLE),
}
MAX_EVENT_BYTES = 1024 * 1024
MAX_API_BYTES = 4 * 1024 * 1024
MAX_RUNS = 100
MAX_TOKEN_BYTES = 1024
SHA1 = re.compile(r"[0-9a-f]{40}")
POSITIVE = re.compile(r"[1-9][0-9]*")
DENIED_ENVIRONMENT = frozenset((
    "GITHUB_TOKEN", "GH_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET",
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "PYTHONPATH", "PYTHONHOME",
    "PYTHONOPTIMIZE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
))
DIAGNOSTIC_CODES = frozenset((
    "API_AUTH_REJECTED", "API_FORBIDDEN_OR_RATE_LIMITED", "API_REDIRECT_REJECTED",
    "API_RESPONSE_REJECTED", "API_UNAVAILABLE", "CURRENT_GENERATION_MISSING",
    "CURRENT_RUN_NOT_EARLIEST", "CURRENT_SECOND_RUN", "ENVIRONMENT_REJECTED",
    "EVENT_BOUND_REJECTED", "EVENT_IO_REJECTED", "EVENT_JSON_REJECTED",
    "EVENT_OBJECT_REJECTED", "EVENT_PATH_REJECTED", "EVENT_STABILITY_REJECTED",
    "HISTORY_INCOMPLETE", "HISTORY_JSON_REJECTED", "HISTORY_RUN_REJECTED",
    "IDENTITY_REJECTED", "LOCAL_IO_REJECTED",
    "PREDECESSOR_REJECTED", "TOKEN_BOUND", "TOKEN_CHAR", "TOKEN_MISSING",
    "UNKNOWN_HISTORY_REJECTED",
))


class GuardError(Exception):
    def __init__(self, code):
        self.code = code if code in DIAGNOSTIC_CODES else "IDENTITY_REJECTED"
        super().__init__(self.code)


def _require(condition, code="IDENTITY_REJECTED"):
    if not condition:
        raise GuardError(code)


def _required(environ, name, code="IDENTITY_REJECTED"):
    value = environ.get(name)
    _require(type(value) is str and value != "", code)
    return value


def _actions_read_token(environ):
    token = environ.get("ACTIONS_READ_TOKEN")
    _require(type(token) is str and token != "", "TOKEN_MISSING")
    try:
        raw = token.encode("ascii")
    except UnicodeEncodeError:
        raise GuardError("TOKEN_CHAR") from None
    _require(1 <= len(raw) <= MAX_TOKEN_BYTES, "TOKEN_BOUND")
    _require(all(0x21 <= byte <= 0x7e for byte in raw), "TOKEN_CHAR")
    return token


def _read_event(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise GuardError("EVENT_IO_REJECTED") from None
    try:
        try:
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_EVENT_BYTES,
                     "EVENT_BOUND_REJECTED")
            chunks = []
            remaining = before.st_size
            while remaining:
                part = os.read(descriptor, min(65_536, remaining))
                _require(type(part) is bytes and part, "EVENT_STABILITY_REJECTED")
                chunks.append(part)
                remaining -= len(part)
            _require(os.read(descriptor, 1) == b"", "EVENT_STABILITY_REJECTED")
            after = os.fstat(descriptor)
        except GuardError:
            raise
        except OSError:
            raise GuardError("EVENT_IO_REJECTED") from None
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns)
        _require(identity(before) == identity(after), "EVENT_STABILITY_REJECTED")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise GuardError("EVENT_JSON_REJECTED") from error
    _require(type(value) is dict, "EVENT_OBJECT_REJECTED")
    return value


def _link_header(response):
    if hasattr(response, "getheader"):
        return response.getheader("Link")
    headers = getattr(response, "headers", None)
    return None if headers is None else headers.get("Link")


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _request, _file_pointer, _code, _message, _headers, _new_url):
        raise GuardError("API_REDIRECT_REJECTED")


def _authenticated_open(request, timeout):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirect())
    return opener.open(request, timeout=timeout)


def _open_history(request, urlopen):
    try:
        return urlopen(request, timeout=20)
    except GuardError:
        raise
    except urllib.error.HTTPError as error:
        try:
            status = error.code
        finally:
            error.close()
        if status in (401, 403):
            raise GuardError("API_AUTH_REJECTED") from None
        if status == 429:
            raise GuardError("API_FORBIDDEN_OR_RATE_LIMITED") from None
        if 300 <= status < 400:
            raise GuardError("API_REDIRECT_REJECTED") from None
        raise GuardError("API_RESPONSE_REJECTED") from None
    except Exception:
        raise GuardError("API_UNAVAILABLE") from None


def _response_bytes(response):
    try:
        status = getattr(response, "status", None)
        if status in (401, 403):
            raise GuardError("API_AUTH_REJECTED")
        if status == 429:
            raise GuardError("API_FORBIDDEN_OR_RATE_LIMITED")
        if type(status) is int and 300 <= status < 400:
            raise GuardError("API_REDIRECT_REJECTED")
        _require(status == 200, "API_RESPONSE_REJECTED")
        raw = response.read(MAX_API_BYTES + 1)
        link = _link_header(response)
    except GuardError:
        raise
    except Exception:
        raise GuardError("API_UNAVAILABLE") from None
    finally:
        try:
            response.close()
        except Exception:
            pass
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_API_BYTES,
             "API_RESPONSE_REJECTED")
    _require(not link, "HISTORY_INCOMPLETE")
    return raw


def _common_run_identity(run):
    _require(type(run) is dict, "HISTORY_RUN_REJECTED")
    run_id = run.get("id")
    attempt = run.get("run_attempt")
    _require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt == 1,
             "HISTORY_RUN_REJECTED")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    _require(run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
             and run.get("path") == WORKFLOW_PATH,
             "HISTORY_RUN_REJECTED")
    _require(type(repository) is dict and repository.get("full_name") == REPOSITORY,
             "HISTORY_RUN_REJECTED")
    _require(type(head_repository) is dict and head_repository.get("full_name") == REPOSITORY,
             "HISTORY_RUN_REJECTED")
    return run_id


def _predecessor_binding(run):
    binding = PREDECESSORS.get(run.get("id"))
    if binding is not None:
        return (*binding, "failure")
    if run.get("id") == SUCCESSFUL_PREDECESSOR_RUN_ID:
        return (SUCCESSFUL_PREDECESSOR_WORKFLOW_HEAD, SUCCESSFUL_PREDECESSOR_RUN_TITLE, "success")
    return None


def _validate_predecessor(run, binding):
    workflow_head, run_title, conclusion = binding
    _require(run.get("head_sha") == workflow_head,
             "PREDECESSOR_REJECTED")
    _require(run.get("display_title") == run_title,
             "PREDECESSOR_REJECTED")
    _require(run.get("status") == "completed" and run.get("conclusion") == conclusion,
             "PREDECESSOR_REJECTED")


def _is_current_generation(run, workflow_head):
    return run.get("head_sha") == workflow_head and run.get("display_title") == RUN_TITLE


def _history(workflow_head, current_run_id, token, urlopen=_authenticated_open):
    query = urllib.parse.urlencode({
        "event": "workflow_dispatch", "per_page": MAX_RUNS, "page": 1,
    })
    url = f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/{WORKFLOW_NAME}/runs?{query}"
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "cogs-stage2-static-replacement-guard-v5",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    response = _open_history(request, urlopen)
    raw = _response_bytes(response)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GuardError("HISTORY_JSON_REJECTED") from error
    _require(type(value) is dict and set(value) >= {"total_count", "workflow_runs"},
             "HISTORY_INCOMPLETE")
    total, runs = value["total_count"], value["workflow_runs"]
    _require(type(total) is int and type(runs) is list and 1 <= total <= MAX_RUNS,
             "HISTORY_INCOMPLETE")
    _require(len(runs) == total, "HISTORY_INCOMPLETE")
    run_ids = []
    predecessor_ids = set()
    current_ids = []
    for run in runs:
        run_id = _common_run_identity(run)
        run_ids.append(run_id)
        binding = _predecessor_binding(run)
        if binding is not None:
            _validate_predecessor(run, binding)
            predecessor_ids.add(run_id)
        elif _is_current_generation(run, workflow_head):
            current_ids.append(run_id)
        else:
            raise GuardError("UNKNOWN_HISTORY_REJECTED")
    _require(len(run_ids) == len(set(run_ids)), "HISTORY_RUN_REJECTED")
    _require(predecessor_ids == set(PREDECESSORS) | {SUCCESSFUL_PREDECESSOR_RUN_ID},
             "PREDECESSOR_REJECTED")
    _require(current_ids, "CURRENT_GENERATION_MISSING")
    _require(current_run_id == min(current_ids), "CURRENT_RUN_NOT_EARLIEST")
    _require(len(current_ids) == 1, "CURRENT_SECOND_RUN")


def guard(environ=os.environ, urlopen=_authenticated_open):
    _require(not (DENIED_ENVIRONMENT & set(environ)), "ENVIRONMENT_REJECTED")
    token = _actions_read_token(environ)
    _require(_required(environ, "GITHUB_EVENT_NAME") == "workflow_dispatch",
             "IDENTITY_REJECTED")
    _require(_required(environ, "GITHUB_REPOSITORY") == REPOSITORY,
             "IDENTITY_REJECTED")
    _require(_required(environ, "GITHUB_REF") == "refs/heads/main"
             and _required(environ, "GITHUB_REF_PROTECTED") == "true",
             "IDENTITY_REJECTED")
    _require(_required(environ, "GITHUB_RUN_ATTEMPT") == "1",
             "IDENTITY_REJECTED")
    run_id_text = _required(environ, "GITHUB_RUN_ID")
    _require(POSITIVE.fullmatch(run_id_text) is not None, "IDENTITY_REJECTED")
    workflow_head = _required(environ, "GITHUB_SHA")
    _require(SHA1.fullmatch(workflow_head) is not None, "IDENTITY_REJECTED")
    _require(workflow_head not in ({value[0] for value in PREDECESSORS.values()}
                                   | {SUCCESSFUL_PREDECESSOR_WORKFLOW_HEAD}),
             "IDENTITY_REJECTED")
    workflow_ref = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
    _require(_required(environ, "GITHUB_WORKFLOW_REF") == workflow_ref,
             "IDENTITY_REJECTED")
    reviewed_head = _required(environ, "EXACT_IMPLEMENTATION_HEAD")
    _require(reviewed_head == REVIEWED_IMPLEMENTATION_HEAD, "IDENTITY_REJECTED")
    # GitHub's trusted default environment and typed input bind identity. The
    # payload is accepted only as a bounded stable JSON object; duplicated
    # payload identity fields are intentionally not an authorization source.
    _read_event(_required(environ, "GITHUB_EVENT_PATH", "EVENT_PATH_REJECTED"))
    _history(workflow_head, int(run_id_text), token, urlopen=urlopen)


def _safe_diagnostic(error):
    code = error.code if isinstance(error, GuardError) else "LOCAL_IO_REJECTED"
    if code not in DIAGNOSTIC_CODES:
        code = "IDENTITY_REJECTED"
    message = f"{GUARD_VERSION}: {code}\n"
    return message if len(message) <= 96 else f"{GUARD_VERSION}: IDENTITY_REJECTED\n"


def main():
    try:
        _require(len(sys.argv) == 1, "IDENTITY_REJECTED")
        guard()
    except (GuardError, OSError) as error:
        sys.stderr.write(_safe_diagnostic(error))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

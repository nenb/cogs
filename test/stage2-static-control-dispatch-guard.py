#!/usr/bin/env python3
"""Hostile tests for the authenticated pre-checkout static-control dispatch guard."""
import importlib.util
import inspect
import io
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "stage2_static_dispatch_guard_test", ROOT / "scripts/stage2-static-control-dispatch-guard.py")
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)
H = GUARD.REVIEWED_IMPLEMENTATION_HEAD
G = "b" * 40
TOKEN_VALUE = "ghs_" + "A" * 36
CURRENT_RUN_ID = 32570000001


def rejection(call, code=None):
    try:
        call()
    except GUARD.GuardError as error:
        if code is not None:
            assert error.code == code, (error.code, code)
        return error
    raise AssertionError("hostile dispatch guard input was accepted")


def environment(**changes):
    value = {
        "ACTIONS_READ_TOKEN": TOKEN_VALUE,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_EVENT_PATH": VALID_EVENT_PATH,
        "GITHUB_REPOSITORY": GUARD.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": str(CURRENT_RUN_ID),
        "GITHUB_SHA": G,
        "GITHUB_WORKFLOW_REF": (
            f"{GUARD.REPOSITORY}/{GUARD.WORKFLOW_PATH}@refs/heads/main"),
        "EXACT_IMPLEMENTATION_HEAD": H,
    }
    value.update(changes)
    return value


EVENT = {
    "ref": "main",
    "repository": {"full_name": GUARD.REPOSITORY},
    "inputs": {"exact_implementation_head": H},
}
EVENT_DIRECTORY = tempfile.TemporaryDirectory(prefix="cogs-static-event-test-")
VALID_EVENT_PATH = str(Path(EVENT_DIRECTORY.name) / "event.json")
Path(VALID_EVENT_PATH).write_text(json.dumps(EVENT), encoding="utf-8")


def event_environment(raw):
    path = Path(EVENT_DIRECTORY.name) / f"event-{len(tuple(Path(EVENT_DIRECTORY.name).iterdir()))}.json"
    path.write_bytes(raw)
    return environment(GITHUB_EVENT_PATH=str(path))


def run(run_id, *, head=G, title=None, **changes):
    value = {
        "id": run_id,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": head,
        "path": GUARD.WORKFLOW_PATH,
        "display_title": GUARD.RUN_TITLE if title is None else title,
        "status": "in_progress",
        "conclusion": None,
        "repository": {"full_name": GUARD.REPOSITORY},
        "head_repository": {"full_name": GUARD.REPOSITORY},
    }
    value.update(changes)
    return value


def predecessor(run_id=GUARD.PREDECESSOR_RUN_ID, **changes):
    workflow_head, title = GUARD.PREDECESSORS[run_id]
    value = run(
        run_id,
        head=workflow_head,
        title=title,
        status="completed",
        conclusion="failure",
    )
    value.update(changes)
    return value


class Response:
    def __init__(self, value=None, *, status=200, link=None, raw=None):
        self.status = status
        self.link = link
        self.raw = json.dumps(value).encode() if raw is None else raw

    def read(self, maximum):
        return self.raw[:maximum]

    def getheader(self, name):
        return self.link if name.lower() == "link" else None

    def close(self):
        pass


def opener(runs, *, total=None, link=None, status=200, raw=None, observe=None,
           token=TOKEN_VALUE):
    def open_request(request, timeout):
        assert timeout == 20
        assert request.full_url.startswith(
            "https://api.github.com/repos/nenb/cogs/actions/workflows/"
            "stage2-local-static-control-candidate.yml/runs?")
        assert "event=workflow_dispatch" in request.full_url
        assert "per_page=100" in request.full_url and "page=1" in request.full_url
        headers = {name.lower(): value for name, value in request.header_items()}
        assert headers["authorization"] == f"Bearer {token}"
        assert token not in request.full_url
        if observe is not None:
            observe(request, headers)
        value = {
            "total_count": len(runs) if total is None else total,
            "workflow_runs": runs,
        }
        return Response(value, status=status, link=link, raw=raw)
    return open_request


BASE_HISTORY = [
    *(predecessor(run_id) for run_id in GUARD.PREDECESSORS),
    run(CURRENT_RUN_ID),
]
auth_observations = []
GUARD.guard(
    environment(),
    urlopen=opener(BASE_HISTORY, observe=lambda request, headers: auth_observations.append(
        (request.host, headers["authorization"])))),
assert auth_observations == [("api.github.com", f"Bearer {TOKEN_VALUE}")]
# Response order does not confer authority; the exact current ID is still the sole earliest ID.
GUARD.guard(environment(), urlopen=opener(list(reversed(BASE_HISTORY))))

# All seven consumed attempt-one failures are exact required predecessors.
for predecessor_id in GUARD.PREDECESSORS:
    other_predecessors = [
        predecessor(other_id) for other_id in GUARD.PREDECESSORS if other_id != predecessor_id
    ]
    for hostile_predecessor in (
        predecessor(predecessor_id, run_attempt=2),
        predecessor(predecessor_id, head_sha="c" * 40),
        predecessor(predecessor_id, head_branch="foreign"),
        predecessor(predecessor_id, display_title="foreign"),
        predecessor(predecessor_id, status="completed", conclusion="cancelled"),
        predecessor(predecessor_id, repository={"full_name": "attacker/cogs"}),
    ):
        rejection(lambda value=hostile_predecessor, others=other_predecessors: GUARD.guard(
            environment(), urlopen=opener(others + [value, run(CURRENT_RUN_ID)])))
    rejection(lambda missing=other_predecessors: GUARD.guard(
        environment(), urlopen=opener(missing + [run(CURRENT_RUN_ID)])),
        "PREDECESSOR_REJECTED")
rejection(lambda: GUARD.guard(
    environment(),
    urlopen=opener([
        *(predecessor(run_id) for run_id in GUARD.PREDECESSORS),
        run(32550000000, head="d" * 40), run(CURRENT_RUN_ID),
    ])), "UNKNOWN_HISTORY_REJECTED")
rejection(lambda: GUARD.guard(
    environment(),
    urlopen=opener([
        *(predecessor(run_id) for run_id in GUARD.PREDECESSORS),
        run(GUARD.THIRD_PREDECESSOR_RUN_ID + 1,
            head=GUARD.THIRD_PREDECESSOR_WORKFLOW_HEAD,
            title=GUARD.THIRD_PREDECESSOR_RUN_TITLE),
    ])), "UNKNOWN_HISTORY_REJECTED")

# A second corrected-generation creation consumes no authority, regardless of which ID is current.
second = run(CURRENT_RUN_ID + 1)
rejection(lambda: GUARD.guard(
    environment(), urlopen=opener(BASE_HISTORY + [second])),
    "CURRENT_SECOND_RUN")
rejection(lambda: GUARD.guard(
    environment(GITHUB_RUN_ID=str(CURRENT_RUN_ID + 1)),
    urlopen=opener(BASE_HISTORY + [second])),
    "CURRENT_RUN_NOT_EARLIEST")
rejection(lambda: GUARD.guard(
    environment(GITHUB_RUN_ATTEMPT="2"), urlopen=opener(BASE_HISTORY)))

# Tokens are opaque bounded HTTP field values: every visible ASCII punctuation
# character and realistic long forms pass without guessing GitHub's token format.
visible_ascii = "".join(chr(value) for value in range(0x21, 0x7f))
for accepted_token in (
    "!",
    "ghs_A1b2-C3d4.E5f6_F7g8~H9i0+/=:;,@[]{}()$&'\"\\|`?#%^*<>",
    visible_ascii,
    (visible_ascii * 11)[:GUARD.MAX_TOKEN_BYTES],
):
    GUARD.guard(
        environment(ACTIONS_READ_TOKEN=accepted_token),
        urlopen=opener(BASE_HISTORY, token=accepted_token))

for name, hostile in (
    ("GITHUB_EVENT_NAME", "push"),
    ("GITHUB_REPOSITORY", "attacker/cogs"),
    ("GITHUB_SHA", GUARD.PREDECESSOR_WORKFLOW_HEAD),
    ("GITHUB_SHA", GUARD.SECOND_PREDECESSOR_WORKFLOW_HEAD),
    ("GITHUB_SHA", GUARD.THIRD_PREDECESSOR_WORKFLOW_HEAD),
    ("GITHUB_SHA", GUARD.FOURTH_PREDECESSOR_WORKFLOW_HEAD),
    ("EXACT_IMPLEMENTATION_HEAD", "c" * 40),
):
    rejection(lambda name=name, hostile=hostile: GUARD.guard(
        environment(**{name: hostile}), urlopen=opener(BASE_HISTORY)))

missing_token_environment = environment()
del missing_token_environment["ACTIONS_READ_TOKEN"]
rejection(lambda: GUARD.guard(
    missing_token_environment, urlopen=opener(BASE_HISTORY)), "TOKEN_MISSING")
for hostile in ("", None):
    rejection(lambda hostile=hostile: GUARD.guard(
        environment(ACTIONS_READ_TOKEN=hostile),
        urlopen=opener(BASE_HISTORY)), "TOKEN_MISSING")
rejection(lambda: GUARD.guard(
    environment(ACTIONS_READ_TOKEN="x" * (GUARD.MAX_TOKEN_BYTES + 1)),
    urlopen=opener(BASE_HISTORY)), "TOKEN_BOUND")
for hostile in (
    *(TOKEN_VALUE + chr(value) for value in range(0x00, 0x21)),
    TOKEN_VALUE + "\x7f",
    TOKEN_VALUE + "é",
    TOKEN_VALUE + "\r\nX-Injected: yes",
):
    rejection(lambda hostile=hostile: GUARD.guard(
        environment(ACTIONS_READ_TOKEN=hostile),
        urlopen=opener(BASE_HISTORY)), "TOKEN_CHAR")
for denied in GUARD.DENIED_ENVIRONMENT:
    rejection(lambda denied=denied: GUARD.guard(
        {**environment(), denied: "hostile"}, urlopen=opener(BASE_HISTORY)),
        "ENVIRONMENT_REJECTED")
# The payload has no injectable caller path and contributes no duplicate
# authorization fields. Documented object variants and subsets all parse; the
# trusted default environment and typed input remain the sole identity binding.
assert "event" not in inspect.signature(GUARD.guard).parameters
for payload in (
    b"{}",
    json.dumps(EVENT).encode(),
    json.dumps({"ref": "refs/heads/main", "inputs": EVENT["inputs"]}).encode(),
    json.dumps({"repository": {"full_name": "attacker/cogs"},
                "inputs": {"exact_implementation_head": "c" * 40}}).encode(),
):
    GUARD.guard(event_environment(payload), urlopen=opener(BASE_HISTORY))

missing_event_path = environment()
del missing_event_path["GITHUB_EVENT_PATH"]
rejection(lambda: GUARD.guard(missing_event_path, urlopen=opener(BASE_HISTORY)),
          "EVENT_PATH_REJECTED")
rejection(lambda: GUARD.guard(
    environment(GITHUB_EVENT_PATH=str(Path(EVENT_DIRECTORY.name) / "absent")),
    urlopen=opener(BASE_HISTORY)), "EVENT_IO_REJECTED")
for raw, code in (
    (b"", "EVENT_BOUND_REJECTED"),
    (b" " * (GUARD.MAX_EVENT_BYTES + 1), "EVENT_BOUND_REJECTED"),
    (b"{", "EVENT_JSON_REJECTED"),
    (b"NaN", "EVENT_JSON_REJECTED"),
    (b"[]", "EVENT_OBJECT_REJECTED"),
):
    error = rejection(lambda raw=raw: GUARD.guard(
        event_environment(raw), urlopen=opener(BASE_HISTORY)), code)
    assert GUARD._safe_diagnostic(error) == f"{GUARD.GUARD_VERSION}: {code}\n"
event_symlink = Path(EVENT_DIRECTORY.name) / "event-symlink"
event_symlink.symlink_to(VALID_EVENT_PATH)
rejection(lambda: GUARD.guard(
    environment(GITHUB_EVENT_PATH=str(event_symlink)), urlopen=opener(BASE_HISTORY)),
    "EVENT_IO_REJECTED")

# Authenticated API failures and every malformed/incomplete history fail closed.
for status in (401, 403):
    error = rejection(lambda status=status: GUARD.guard(
        environment(),
        urlopen=opener(BASE_HISTORY, status=status, raw=TOKEN_VALUE.encode())),
        "API_AUTH_REJECTED")
    diagnostic = GUARD._safe_diagnostic(error)
    assert diagnostic == f"{GUARD.GUARD_VERSION}: API_AUTH_REJECTED\n"
    assert TOKEN_VALUE not in diagnostic and "body" not in diagnostic.lower()
rejection(lambda: GUARD.guard(
    environment(), urlopen=opener(BASE_HISTORY, status=429)),
    "API_FORBIDDEN_OR_RATE_LIMITED")
rejection(lambda: GUARD.guard(
    environment(), urlopen=opener(BASE_HISTORY, status=302)),
    "API_REDIRECT_REJECTED")
rejection(lambda: GUARD.guard(
    environment(),
    urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(TOKEN_VALUE))),
    "API_UNAVAILABLE")
for malformed in (
    opener(BASE_HISTORY, link='<https://api.github.com/next>; rel="next"'),
    opener(BASE_HISTORY, total=101),
    opener(BASE_HISTORY, total=1),
    opener(BASE_HISTORY, raw=b"{"),
    opener(BASE_HISTORY, raw=b"x" * (GUARD.MAX_API_BYTES + 1)),
    opener([predecessor(), run(CURRENT_RUN_ID, id="not-an-integer")]),
    opener([predecessor(), run(CURRENT_RUN_ID, head_repository=None)]),
    opener([predecessor(), run(CURRENT_RUN_ID), run(CURRENT_RUN_ID)]),
):
    rejection(lambda malformed=malformed: GUARD.guard(
        environment(), urlopen=malformed))

# Diagnostics are fixed, bounded classifications; exception text, response bytes,
# token bytes, and token lengths stay absent.
for hostile, code in (
    ("", "TOKEN_MISSING"),
    ("x" * (GUARD.MAX_TOKEN_BYTES + 1), "TOKEN_BOUND"),
    (TOKEN_VALUE + "\n", "TOKEN_CHAR"),
):
    error = rejection(lambda hostile=hostile: GUARD.guard(
        environment(ACTIONS_READ_TOKEN=hostile),
        urlopen=opener(BASE_HISTORY)), code)
    diagnostic = GUARD._safe_diagnostic(error)
    assert diagnostic == f"{GUARD.GUARD_VERSION}: {code}\n"
    assert not hostile or hostile not in diagnostic
    assert str(len(hostile.encode())) not in diagnostic

error = rejection(lambda: GUARD.guard(
    environment(),
    urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(TOKEN_VALUE))),
    "API_UNAVAILABLE")
diagnostic = GUARD._safe_diagnostic(error)
assert diagnostic == f"{GUARD.GUARD_VERSION}: API_UNAVAILABLE\n"
assert len(diagnostic) <= 96
assert TOKEN_VALUE not in diagnostic
assert "response" not in diagnostic.lower()
assert TOKEN_VALUE not in GUARD._safe_diagnostic(OSError(TOKEN_VALUE))

print("stage2 authenticated static-control dispatch guard hostile tests passed")

#!/usr/bin/env python3
"""Hostile tests for the authenticated pre-checkout static-control dispatch guard."""
import importlib.util
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "stage2_static_dispatch_guard_test", ROOT / "scripts/stage2-static-control-dispatch-guard.py")
GUARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)
H = GUARD.REVIEWED_IMPLEMENTATION_HEAD
G = "b" * 40
TOKEN_VALUE = "ghs_" + "A" * 36
CURRENT_RUN_ID = 32560000001


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
    predecessor(), predecessor(GUARD.SECOND_PREDECESSOR_RUN_ID), run(CURRENT_RUN_ID),
]
auth_observations = []
GUARD.guard(
    environment(), event=EVENT,
    urlopen=opener(BASE_HISTORY, observe=lambda request, headers: auth_observations.append(
        (request.host, headers["authorization"])))),
assert auth_observations == [("api.github.com", f"Bearer {TOKEN_VALUE}")]
# Response order does not confer authority; the exact current ID is still the sole earliest ID.
GUARD.guard(environment(), event=EVENT, urlopen=opener(list(reversed(BASE_HISTORY))))

# Both consumed attempt-one failures are exact required predecessors.
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
            environment(), event=EVENT, urlopen=opener(others + [value, run(CURRENT_RUN_ID)])))
    rejection(lambda missing=other_predecessors: GUARD.guard(
        environment(), event=EVENT, urlopen=opener(missing + [run(CURRENT_RUN_ID)])),
        "PREDECESSOR_REJECTED")
rejection(lambda: GUARD.guard(
    environment(), event=EVENT,
    urlopen=opener([
        predecessor(), predecessor(GUARD.SECOND_PREDECESSOR_RUN_ID),
        run(32550000000, head="d" * 40), run(CURRENT_RUN_ID),
    ])), "UNKNOWN_HISTORY_REJECTED")
rejection(lambda: GUARD.guard(
    environment(), event=EVENT,
    urlopen=opener([
        predecessor(), predecessor(GUARD.SECOND_PREDECESSOR_RUN_ID),
        run(GUARD.SECOND_PREDECESSOR_RUN_ID + 1,
            head=GUARD.SECOND_PREDECESSOR_WORKFLOW_HEAD,
            title=GUARD.SECOND_PREDECESSOR_RUN_TITLE),
    ])), "UNKNOWN_HISTORY_REJECTED")

# A second corrected-generation creation consumes no authority, regardless of which ID is current.
second = run(CURRENT_RUN_ID + 1)
rejection(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=opener(BASE_HISTORY + [second])),
    "CURRENT_SECOND_RUN")
rejection(lambda: GUARD.guard(
    environment(GITHUB_RUN_ID=str(CURRENT_RUN_ID + 1)), event=EVENT,
    urlopen=opener(BASE_HISTORY + [second])),
    "CURRENT_RUN_NOT_EARLIEST")
rejection(lambda: GUARD.guard(
    environment(GITHUB_RUN_ATTEMPT="2"), event=EVENT, urlopen=opener(BASE_HISTORY)))

# The bounded token68-style subset accepts every permitted visible character and
# one optional terminal padding marker, while rejecting separators and injection.
for accepted_token in (
    "A" * GUARD.MIN_TOKEN_CHARS,
    "Aa0-._~+/" * 3,
    ("z" * (GUARD.MIN_TOKEN_CHARS - 1)) + "=",
    "x" * GUARD.MAX_TOKEN_CHARS,
):
    GUARD.guard(
        environment(ACTIONS_READ_TOKEN=accepted_token), event=EVENT,
        urlopen=opener(BASE_HISTORY, token=accepted_token))

for name, hostile in (
    ("GITHUB_EVENT_NAME", "push"),
    ("GITHUB_REPOSITORY", "attacker/cogs"),
    ("GITHUB_SHA", GUARD.PREDECESSOR_WORKFLOW_HEAD),
    ("GITHUB_SHA", GUARD.SECOND_PREDECESSOR_WORKFLOW_HEAD),
    ("EXACT_IMPLEMENTATION_HEAD", "c" * 40),
    ("ACTIONS_READ_TOKEN", "short"),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + "\n"),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + "\r\nX-Injected: yes"),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + "\t"),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + " "),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + "\x00"),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + "\x7f"),
    ("ACTIONS_READ_TOKEN", "=" + TOKEN_VALUE),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + "=tail"),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + "=="),
    ("ACTIONS_READ_TOKEN", TOKEN_VALUE + "é"),
    ("ACTIONS_READ_TOKEN", "x" * (GUARD.MAX_TOKEN_CHARS + 1)),
):
    rejection(lambda name=name, hostile=hostile: GUARD.guard(
        environment(**{name: hostile}), event=EVENT, urlopen=opener(BASE_HISTORY)))
for denied in GUARD.DENIED_ENVIRONMENT:
    rejection(lambda denied=denied: GUARD.guard(
        {**environment(), denied: "hostile"}, event=EVENT, urlopen=opener(BASE_HISTORY)),
        "ENVIRONMENT_REJECTED")
rejection(lambda: GUARD.guard(
    environment(), event={**EVENT, "repository": {"full_name": "attacker/cogs"}},
    urlopen=opener(BASE_HISTORY)))
rejection(lambda: GUARD.guard(
    environment(), event={**EVENT, "inputs": {"exact_implementation_head": "c" * 40}},
    urlopen=opener(BASE_HISTORY)))
rejection(lambda: GUARD.guard(
    environment(), event=[], urlopen=opener(BASE_HISTORY)), "EVENT_REJECTED")

# Authenticated API failures and every malformed/incomplete history fail closed.
rejection(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=opener(BASE_HISTORY, status=403)),
    "API_FORBIDDEN_OR_RATE_LIMITED")
rejection(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=opener(BASE_HISTORY, status=429)),
    "API_FORBIDDEN_OR_RATE_LIMITED")
rejection(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=opener(BASE_HISTORY, status=302)),
    "API_REDIRECT_REJECTED")
rejection(lambda: GUARD.guard(
    environment(), event=EVENT,
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
        environment(), event=EVENT, urlopen=malformed))

# Diagnostics are fixed, bounded classifications; exception text, response bytes, and token stay absent.
error = rejection(lambda: GUARD.guard(
    environment(), event=EVENT,
    urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(TOKEN_VALUE))),
    "API_UNAVAILABLE")
diagnostic = GUARD._safe_diagnostic(error)
assert diagnostic == f"{GUARD.GUARD_VERSION}: API_UNAVAILABLE\n"
assert len(diagnostic) <= 96
assert TOKEN_VALUE not in diagnostic
assert "response" not in diagnostic.lower()
assert TOKEN_VALUE not in GUARD._safe_diagnostic(OSError(TOKEN_VALUE))

print("stage2 authenticated static-control dispatch guard hostile tests passed")

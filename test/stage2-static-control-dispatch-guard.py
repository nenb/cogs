#!/usr/bin/env python3
"""Hostile tests for the pre-checkout static-control dispatch guard."""
import importlib.util
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
G = "a" * 40


def rejected(call):
    try:
        call()
    except GUARD.GuardError:
        return
    raise AssertionError("hostile dispatch guard input was accepted")


def environment(**changes):
    value = {
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": GUARD.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REF_PROTECTED": "true",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_RUN_ID": "71",
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


def run(run_id, **changes):
    value = {
        "id": run_id,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_sha": G,
        "path": GUARD.WORKFLOW_PATH,
        "display_title": GUARD.RUN_TITLE,
        "repository": {"full_name": GUARD.REPOSITORY},
        "head_repository": {"full_name": GUARD.REPOSITORY},
    }
    value.update(changes)
    return value


class Response:
    def __init__(self, value, *, status=200, link=None, raw=None):
        self.status = status
        self.link = link
        self.raw = json.dumps(value).encode() if raw is None else raw

    def read(self, maximum):
        return self.raw[:maximum]

    def getheader(self, name):
        return self.link if name.lower() == "link" else None

    def close(self):
        pass


def opener(runs, *, total=None, link=None, status=200):
    def open_request(request, timeout):
        assert timeout == 20
        assert request.full_url.startswith(
            "https://api.github.com/repos/nenb/cogs/actions/workflows/"
            "stage2-local-static-control-candidate.yml/runs?")
        assert "event=workflow_dispatch" in request.full_url
        assert "per_page=100" in request.full_url and "page=1" in request.full_url
        assert "authorization" not in {name.lower() for name in request.headers}
        return Response({
            "total_count": len(runs) if total is None else total,
            "workflow_runs": runs,
        }, status=status, link=link)
    return open_request


GUARD.guard(environment(), event=EVENT, urlopen=opener([run(71)]))
# A concurrent second creation cannot gain authority; only exact earliest ID can.
GUARD.guard(environment(), event=EVENT, urlopen=opener([run(80), run(71)]))
rejected(lambda: GUARD.guard(
    environment(GITHUB_RUN_ID="80"), event=EVENT, urlopen=opener([run(80), run(71)])))
rejected(lambda: GUARD.guard(
    environment(GITHUB_RUN_ATTEMPT="2"), event=EVENT, urlopen=opener([run(71, run_attempt=2)])))
rejected(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=opener([run(71, run_attempt=2)])))

for name, hostile in (
    ("GITHUB_EVENT_NAME", "push"),
    ("GITHUB_REPOSITORY", "attacker/cogs"),
    ("GITHUB_SHA", "b" * 40),
    ("EXACT_IMPLEMENTATION_HEAD", "c" * 40),
):
    rejected(lambda name=name, hostile=hostile: GUARD.guard(
        environment(**{name: hostile}), event=EVENT, urlopen=opener([run(71)])))
rejected(lambda: GUARD.guard(
    {**environment(), "GITHUB_TOKEN": "hostile"}, event=EVENT, urlopen=opener([run(71)])))
rejected(lambda: GUARD.guard(environment(), event={**EVENT, "repository": {
    "full_name": "attacker/cogs"}}, urlopen=opener([run(71)])))
rejected(lambda: GUARD.guard(environment(), event={**EVENT, "inputs": {
    "exact_implementation_head": "c" * 40}}, urlopen=opener([run(71)])))

for hostile_run in (
    run(71, event="push"),
    run(71, head_sha="b" * 40),
    run(71, repository={"full_name": "attacker/cogs"}),
    run(71, head_repository={"full_name": "attacker/cogs"}),
    run(71, display_title="Non-authoritative Stage 2 static control H=" + "c" * 40),
    run(71, path=".github/workflows/foreign.yml"),
):
    rejected(lambda hostile_run=hostile_run: GUARD.guard(
        environment(), event=EVENT, urlopen=opener([hostile_run])))

rejected(lambda: GUARD.guard(environment(), event=EVENT, urlopen=opener(
    [run(71)], link='<https://api.github.com/next>; rel="next"')))
rejected(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=opener([run(71)], total=101)))
rejected(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=opener([run(71)], total=2)))
rejected(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())))
rejected(lambda: GUARD.guard(
    environment(), event=EVENT, urlopen=opener([run(71)], status=500)))

print("stage2 static-control dispatch guard hostile tests passed")

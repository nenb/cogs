#!/usr/bin/env python3
"""Portable bootstrap, issuer, descriptor binding, and T2 state-machine tests."""

import importlib.util
import json
from pathlib import Path
import sys

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 launcher tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
FIXTURES = ROOT / "test/fixtures/outcome-two/launcher/cases.json"


def load_module():
    spec = importlib.util.spec_from_file_location("completion_trusted_runtime_launcher", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ModelSystemOps:
    """Primitive-only model; it never constructs a successful security result."""

    def __init__(self, transcript, *, cut=None, attack=None, architecture="x86_64"):
        self.expected = tuple(transcript)
        self.cut = cut
        self.attack = attack
        self.architecture = architecture
        self.events = []
        self.effects = 0
        self.resources = {
            "descriptors": set(), "children": set(), "mounts": set(),
            "namespaces": set(), "paths": set(), "checkout": "clean",
        }
        self.claims = {}

    def operation(self, name, *, effect=True):
        if name not in self.expected:
            raise AssertionError(f"undeclared production operation: {name}")
        self.events.append(name)
        if effect:
            self.effects += 1
        if name == self.cut:
            raise OSError(f"unavailable:{name}")
        return self._observation(name)

    def _observation(self, name):
        if name == "platform.architecture":
            return ("linux", self.architecture)
        if name.startswith("baseline."):
            return frozenset()
        if name.startswith("capability."):
            return 0
        if name in {"securebits.noroot-lock", "nnp.set"}:
            return True
        if name.startswith("seccomp."):
            return "EPERM"
        if name.startswith("final-map."):
            return "stable-bound-generations"
        return None

    def acquire(self, domain, identity):
        self.resources[domain].add(identity)

    def release(self, domain, identity):
        if identity not in self.resources[domain]:
            raise AssertionError(f"foreign {domain} release: {identity}")
        self.resources[domain].remove(identity)

    def observe_claim(self, name, value):
        self.claims[name] = value

    def restored(self):
        return all(not self.resources[name] for name in
                   ("descriptors", "children", "mounts", "namespaces", "paths")) \
            and self.resources["checkout"] == "clean"


class AdmissionOps:
    def __init__(self, attack=None):
        self.attack = attack
        self.events = []
        self.effects = 0

    def operation(self, name, *, effect=False):
        self.events.append(name)
        if effect:
            self.effects += 1
        if self.attack == name or self.attack == name.removeprefix("admission."):
            raise ValueError(f"admission rejected:{self.attack}")
        return None


class IssuerOps:
    def __init__(self, attack=None):
        self.attack = attack
        self.events = []
        self.exec_attempts = 0
        self.claims = 0
        self.owned = {"issuer": {198, 199, 200}, "consumer": set()}

    def operation(self, name, *, effect=True):
        self.events.append(name)
        if self.attack == name or self.attack == name.removeprefix("attack."):
            raise ValueError(f"issuer rejected:{self.attack}")
        if name == "exec":
            self.exec_attempts += 1
        if name == "claim":
            self.claims += 1
        return None


def require_route(module, name):
    route = getattr(module, name, None)
    if not callable(route):
        raise AssertionError(f"production portable state-machine route missing: {name}")
    return route


def expect_failure(action, label):
    try:
        action()
    except Exception:
        return
    raise AssertionError(f"hostile launcher case accepted: {label}")


def run_unavailable(module, route, ops):
    try:
        return route(ops)
    except Exception as error:
        unavailable = getattr(module, "RuntimeLauncherUnavailable", ())
        if unavailable and isinstance(error, unavailable):
            return error
        raise


def assert_unavailable(outcome, cut, ops):
    status = getattr(outcome, "status", "unavailable" if type(outcome).__name__.endswith("Unavailable") else None)
    if status != "unavailable":
        raise AssertionError(f"{cut}: denial was not typed unavailable: {status!r}")
    claims = getattr(outcome, "claims", None)
    if not isinstance(claims, dict):
        raise AssertionError(f"{cut}: unavailable omitted observed claim map")
    if any(value is True for value in claims.values()):
        raise AssertionError(f"{cut}: unavailable overclaimed success: {claims}")
    if not getattr(outcome, "cleanup_restored", False) or not ops.restored():
        raise AssertionError(f"{cut}: unavailable cleanup was not proved")


def bootstrap_matrix(module, fixture, executed):
    route = require_route(module, "_drive_fixed_bootstrap_with_adapter_for_tests")
    success = AdmissionOps()
    route(success)
    authority = tuple(success.events)
    if not authority or success.effects:
        raise AssertionError("bootstrap success did not remain pre-effect admission")
    for attack in fixture["bootstrap_attacks"]:
        ops = AdmissionOps(attack)
        expect_failure(lambda: route(ops), attack)
        if ops.effects:
            raise AssertionError(f"{attack}: authority-bearing effect preceded rejection")
        executed.append(f"bootstrap:{attack}")


def issuer_matrix(module, fixture, executed):
    route = require_route(module, "_drive_fixed_issuer_with_adapter_for_tests")
    success = IssuerOps()
    outcome = route(success)
    if success.claims != 1 or success.exec_attempts:
        raise AssertionError("issuer did not make exactly one pre-exec atomic claim")
    if not getattr(outcome, "consumed", False):
        raise AssertionError("issuer success was not consumed")
    for attack in fixture["issuer_attacks"]:
        ops = IssuerOps(attack)
        expect_failure(lambda: route(ops), attack)
        if ops.exec_attempts:
            raise AssertionError(f"{attack}: attack reached exec")
        if ops.claims > 1:
            raise AssertionError(f"{attack}: issuance was replayable")
        executed.append(f"issuer:{attack}")


def t2_matrix(module, fixture, executed):
    route = require_route(module, "_drive_fixed_t2_with_adapter_for_tests")
    expected = fixture["t2_transcript"]
    if len(expected) != len(set(expected)):
        raise AssertionError("T2 fixture repeats an operation")
    success = ModelSystemOps(expected)
    outcome = route(success)
    if success.events != expected:
        raise AssertionError(f"T2 transcript mismatch\nexpected={expected}\nactual={success.events}")
    if not success.restored() or not getattr(outcome, "cleanup_restored", False):
        raise AssertionError("T2 success published before complete cleanup")
    if success.events.index("final-map.equal") > success.events.index("input.release"):
        raise AssertionError("input released before final map equality")
    for cut in fixture["unavailable_cuts"]:
        ops = ModelSystemOps(expected, cut=cut)
        outcome = run_unavailable(module, route, ops)
        assert_unavailable(outcome, cut, ops)
        if "result.publish" in ops.events or "input.release" in ops.events:
            raise AssertionError(f"{cut}: unavailable path published/released input")
        executed.append(f"unavailable:{cut}")
    for architecture in ("arm64", "riscv64"):
        ops = ModelSystemOps(expected, architecture=architecture)
        outcome = run_unavailable(module, route, ops)
        assert_unavailable(outcome, architecture, ops)
        if ops.effects != 1 or ops.events != ["platform.architecture"]:
            raise AssertionError(f"{architecture}: architecture gate followed an effect")
        executed.append(f"architecture:{architecture}")


def parent():
    module = load_module()
    fixture = json.loads(FIXTURES.read_text())
    if fixture["fixed_fd_map"] != [["gzip", 198], ["zstd", 199], ["report", 200]]:
        raise AssertionError("fixed descriptor map changed")
    executed = []
    bootstrap_matrix(module, fixture, executed)
    issuer_matrix(module, fixture, executed)
    t2_matrix(module, fixture, executed)
    declared = ([f"bootstrap:{name}" for name in fixture["bootstrap_attacks"]]
                + [f"issuer:{name}" for name in fixture["issuer_attacks"]]
                + [f"unavailable:{name}" for name in fixture["unavailable_cuts"]]
                + ["architecture:arm64", "architecture:riscv64"])
    if executed != declared or len(executed) != len(set(executed)):
        raise AssertionError("launcher fixtures did not execute exactly once")
    print("Outcome 2 trusted launcher portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()

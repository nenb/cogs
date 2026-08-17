"""Closed authenticated-SSH readiness boundary for Stage 2 Kata.

Only the immutable command and an offline typed fake are available.  Loading a
host SSH tool closure remains deliberately absent, so this module cannot open a
production command issuer or make a connection.
"""
from dataclasses import dataclass
import hashlib

MARKER = b"COGS_STAGE2_SSH_READY_V1\n"
MARKER_SHA256 = hashlib.sha256(MARKER).hexdigest()
KEY_FD = 200
KNOWN_HOSTS_FD = 201
QUALIFICATION = "UNQUALIFIED_OFFLINE_FAKE_SSH_S5_V1"
ARGV = (
    "/usr/bin/ssh", "-F", "/dev/null", "-n", "-T",
    "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-o", "PreferredAuthentications=publickey", "-o", "PubkeyAuthentication=yes",
    "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UserKnownHostsFile=/proc/self/fd/201",
    "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", "HostKeyAlias=cogs-stage2-ssh-v1", "-o", "CheckHostIP=no",
    "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=5",
    "-o", "ControlMaster=no", "-o", "ControlPath=none",
    "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
    "-o", "PermitLocalCommand=no", "-o", "CanonicalizeHostname=no",
    "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
    "-o", "ForwardX11=no", "-o", "ForwardX11Trusted=no", "-o", "Tunnel=no",
    "-o", "RequestTTY=no", "-o", "EscapeChar=none", "-o", "LogLevel=ERROR",
    "-p", "22", "-i", "/proc/self/fd/200", "root@192.0.2.2",
    "printf '%s\\n' COGS_STAGE2_SSH_READY_V1",
)


class SshError(Exception):
    """SSH authority, command, outcome, or lifecycle state was not exact."""


def _fail(condition, message="SSH contract"):
    if not condition:
        raise SshError(message)


@dataclass(frozen=True)
class SshCommand:
    command_id: str = "SSH_READY"
    argv: tuple = ARGV
    stdin: bytes = b""
    deadline_class: str = "ssh"
    inherited_fds: tuple = (KEY_FD, KNOWN_HOSTS_FD)

    def __post_init__(self):
        _fail(type(self.command_id) is str and self.command_id == "SSH_READY")
        _fail(type(self.argv) is tuple and self.argv == ARGV)
        _fail(type(self.stdin) is bytes and self.stdin == b"")
        _fail(type(self.deadline_class) is str and self.deadline_class == "ssh")
        _fail(type(self.inherited_fds) is tuple and self.inherited_fds == (200, 201))


@dataclass(frozen=True)
class SshOutcome:
    command_id: str
    outcome: str
    status: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool
    reaped: bool
    errors: tuple

    def __post_init__(self):
        _fail(type(self.command_id) is str and self.command_id == "SSH_READY")
        _fail(type(self.outcome) is str)
        _fail(self.status is None or type(self.status) is int)
        _fail(type(self.stdout) is bytes and type(self.stderr) is bytes)
        _fail(type(self.stdout_truncated) is bool and type(self.stderr_truncated) is bool)
        _fail(type(self.timed_out) is bool and type(self.reaped) is bool)
        _fail(type(self.errors) is tuple and all(type(item) is str for item in self.errors))


@dataclass(frozen=True)
class Readiness:
    marker_sha256: str
    authentication_attempts: int
    stdout_length: int
    stderr_length: int

    def __post_init__(self):
        _fail(self.marker_sha256 == MARKER_SHA256)
        _fail(type(self.authentication_attempts) is int and self.authentication_attempts == 1)
        _fail(type(self.stdout_length) is int and self.stdout_length == len(MARKER))
        _fail(type(self.stderr_length) is int and self.stderr_length == 0)


def command_spec():
    """Return immutable bytes only; this is not command authority."""
    return SshCommand()


def validate_outcome(outcome):
    """Require one exact authenticated marker and no diagnostic side channel."""
    _fail(type(outcome) is SshOutcome)
    _fail(outcome.outcome == "exited" and outcome.status == 0, "SSH did not exit zero")
    _fail(outcome.stdout == MARKER and outcome.stderr == b"", "non-exact SSH output")
    _fail(not outcome.stdout_truncated and not outcome.stderr_truncated, "truncated SSH output")
    _fail(not outcome.timed_out and outcome.reaped and outcome.errors == (), "uncertain SSH outcome")
    return Readiness(MARKER_SHA256, 1, len(MARKER), 0)


def _fake_routes():
    seal = object()
    states = {}

    class _FakeSsh:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal, "sealed fake capability")
            return super().__new__(cls)
        def authenticate_process_outcome(self, outcome):
            state = states.get(self)
            _fail(state is not None and outcome == state["outcome"], "adapted outcome mismatch")
            return authenticate(self)
        def poison_and_ensure_revoked(self):
            poison_and_ensure_revoked(self)
        def ensure_revoked(self):
            ensure_revoked(self)

    def make(outcome):
        _fail(type(outcome) is SshOutcome)
        value = _FakeSsh(seal)
        states[value] = {"outcome": outcome, "attempted": False, "revoked": False,
                         "poisoned": False, "revocations": 0}
        return value

    def revoke_once(state):
        if not state["revoked"]:
            state["revoked"] = True
            state["revocations"] += 1

    def authenticate(value):
        state = states.get(value)
        _fail(type(value) is _FakeSsh and state is not None, "typed fake required")
        _fail(not state["revoked"] and not state["attempted"], "SSH retry or revoked readiness")
        state["attempted"] = True
        try:
            return validate_outcome(state["outcome"])
        except BaseException:
            state["poisoned"] = True
            revoke_once(state)
            raise

    def poison_and_ensure_revoked(value):
        state = states.get(value)
        _fail(type(value) is _FakeSsh and state is not None, "typed fake required")
        state["poisoned"] = True
        revoke_once(state)

    def ensure_revoked(value):
        state = states.get(value)
        _fail(type(value) is _FakeSsh and state is not None, "typed fake required")
        revoke_once(state)

    def revoke(value):
        state = states.get(value)
        _fail(type(value) is _FakeSsh and state is not None, "typed fake required")
        _fail(not state["revoked"], "readiness already revoked")
        revoke_once(state)

    def snapshot(value):
        state = states.get(value)
        _fail(type(value) is _FakeSsh and state is not None)
        return (QUALIFICATION, state["attempted"], state["revoked"],
                state["poisoned"], state["revocations"])

    return make, authenticate, revoke, snapshot


make_test_local_fake, authenticate_test_local, revoke_test_local, fake_state_for_tests = _fake_routes()
del _fake_routes


def open_fixed_ssh_owner():
    """Fail closed until the exact host-tool contract loader is committed."""
    raise SshError("production SSH unavailable: host-tool contract loader is absent")

"""Strict one-session authenticated SSH facet for the fixed Kata guest.

Public opening remains blocked.  Trusted T1 can compose the package-private
route with the exact attested process transaction and guest-program source.
"""
from dataclasses import dataclass
import hashlib
import completion_guest_workloads_v3 as guest
import completion_guest_readiness_v1 as readiness_guest
import completion_kata_fdmap as fdmap
import completion_kata_operation as operation
import completion_kata_network as network

_issue_guest_network_proof = network._take_guest_network_proof_issuer()
MARKER = guest.GUEST_READY_MARKER
MARKER_SHA256 = hashlib.sha256(MARKER).hexdigest()
KEY_FD = 200
KNOWN_HOSTS_FD = 201
PARENT_KEY_FD = 1000
PARENT_KNOWN_HOSTS_FD = 1001
QUALIFICATION = "UNQUALIFIED_OFFLINE_FAKE_SSH_S5_V1"
ARGV = (
    "/usr/bin/ssh", "-F", "/dev/null", "-T",
    "-o", "BatchMode=yes", "-o", "StdinNull=no",
    "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
    "-o", "AddKeysToAgent=no", "-o", "PreferredAuthentications=publickey",
    "-o", "PubkeyAuthentication=yes", "-o", "PubkeyAcceptedAlgorithms=ssh-ed25519",
    "-o", "HostbasedAuthentication=no", "-o", "GSSAPIAuthentication=no",
    "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
    "-o", "NumberOfPasswordPrompts=0", "-o", "StrictHostKeyChecking=yes",
    "-o", "UserKnownHostsFile=/proc/{command-parent-pid}/fd/1001", "-o", "UpdateHostKeys=no",
    "-o", "GlobalKnownHostsFile=/dev/null", "-o", "VerifyHostKeyDNS=no",
    "-o", "HostKeyAlgorithms=ssh-ed25519",
    "-o", "HostKeyAlias=cogs-stage2-ssh-v1", "-o", "CheckHostIP=no",
    "-o", "AddressFamily=inet", "-o", "ConnectionAttempts=1",
    "-o", "ConnectTimeout=5",
    "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no",
    "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ProxyUseFdpass=no",
    "-o", "PermitLocalCommand=no", "-o", "LocalCommand=none",
    "-o", "CanonicalizeHostname=no", "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
    "-o", "ForwardX11Trusted=no", "-o", "Tunnel=no", "-o", "GatewayPorts=no",
    "-o", "RequestTTY=no", "-o", "EscapeChar=none", "-o", "LogLevel=ERROR",
    "-p", "22", "-i", "/proc/{command-parent-pid}/fd/1000", "root@192.0.2.2", "/bin/sh -s",
)
OUTPUT_LIMIT = 4096
RESULT_LINES = 21


class SshError(Exception):
    """SSH authority, command, outcome, or lifecycle state was not exact."""


def _fail(condition, message="SSH contract"):
    if not condition:
        raise SshError(message)


@dataclass(frozen=True)
class SshCommand:
    command_id: str = "SSH_READY"
    argv: tuple = ARGV
    stdin: bytes = guest.guest_program_bytes()
    deadline_class: str = "ssh"
    inherited_fds: tuple = (KEY_FD, KNOWN_HOSTS_FD)

    def __post_init__(self):
        _fail(type(self.command_id) is str and self.command_id in {"SSH_READY", "SSH_READINESS"})
        _fail(type(self.argv) is tuple and self.argv == ARGV)
        expected = (guest.guest_program_bytes() if self.command_id == "SSH_READY"
                    else readiness_guest.guest_program_bytes())
        expected_sha = (guest.GUEST_PROGRAM_SHA256 if self.command_id == "SSH_READY"
                        else readiness_guest.GUEST_PROGRAM_SHA256)
        _fail(type(self.stdin) is bytes and self.stdin == expected)
        _fail(hashlib.sha256(self.stdin).hexdigest() == expected_sha)
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


def readiness_command_spec():
    """Return the distinct immutable marker-only stdin; never authority."""
    return SshCommand(command_id="SSH_READINESS", stdin=readiness_guest.guest_program_bytes())


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


PARSER_ID = "completion_guest_workloads_v3.parse_guest_workload_output/v3"
PARSER_SHA256 = hashlib.sha256(PARSER_ID.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class AuthenticatedSession:
    command_serial: int
    binding_sha256: str
    stdin_sha256: str
    stdout_sha256: str
    result_sha256: str
    parsed_result: guest.GuestWorkloadResult
    guest_network_proof: object = None


@dataclass(frozen=True, slots=True)
class ReadinessAuthenticatedSession:
    command_serial: int
    binding_sha256: str
    stdin_sha256: str
    stdout_sha256: str
    marker_sha256: str

    def __post_init__(self):
        _fail(self.stdin_sha256 == readiness_guest.GUEST_PROGRAM_SHA256
              and self.stdout_sha256 == self.marker_sha256 ==
                  readiness_guest.MARKER_SHA256)


def _canonical_result(result):
    _fail(type(result) is guest.GuestWorkloadResult and len(result.samples) == RESULT_LINES)
    return guest.canonical_guest_workload_result(result)


def _production_routes():
    """Compose only fixed module identities; no behavior/data callback enters."""
    seal, states = object(), {}

    class _ProductionSsh:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal, "production SSH is package-private")
            return super().__new__(cls)
        def authenticate(self):
            state = states[self]
            _fail(not state["issued"] and not state["revoked"], "SSH retry or revoked")
            context = operation._command_context(state["journal"])
            _fail(context.lifecycle_phase == "RUNTIME_READY", "SSH phase revoked")
            claimed, primary, session = False, None, None
            import completion_kata_process as process
            try:
                identity = state["inputs"].prepare_launch()
                owner = state["inputs"].claim_ssh_bindings(); claimed = True
                bindings = fdmap._claim_production_inputs(
                    owner, context.operation_token, identity.manifest_sha256)
                _fail(operation._command_context(state["journal"]) == context,
                      "SSH journal changed before issuance")
                state["issued"] = True
                outcome, receipt = process._transact_fixed_ssh(
                    state["journal"], state["executable"], bindings)
                _fail(type(outcome) is process.ProcessOutcome
                      and type(receipt) is operation.DurableCommandOutcome)
                _fail(receipt.command_id == outcome.command_id == "SSH_READY"
                      and receipt.command_serial == context.command_serial)
                durable = operation._durable_command_output(
                    state["journal"], context.command_serial, "SSH_READY",
                    receipt.binding_sha256, outcome.stdout, outcome.stderr)
                _fail(durable.body == receipt.body and outcome.stderr == b"")
                body = durable.body
                _fail(body["outcome"] == "exited" and body["status"] == 0
                      and body["errno"] is None and not body["uncertain"])
                _fail(not body["stdout_truncated"] and not body["stderr_truncated"]
                      and body["leader_reaped"] and body["descendants_reaped"])
                _fail(body["cgroup_empty"] and body["cgroup_removed"]
                      and body["pipes_eof"] and body["errors"] == [])
                parsed = guest.parse_guest_workload_output(outcome.stdout)
                canonical = _canonical_result(parsed)
                result_sha256 = hashlib.sha256(canonical).hexdigest()
                network_proof = _issue_guest_network_proof(parsed)
                session = AuthenticatedSession(
                    context.command_serial, receipt.binding_sha256,
                    guest.GUEST_PROGRAM_SHA256, body["stdout_sha256"],
                    result_sha256, parsed, network_proof)
                state["pending_result"] = (
                    context.command_serial, receipt.binding_sha256,
                    identity.manifest_sha256, outcome.stdout, canonical)
                state["session"] = session
            except BaseException as error:
                primary = error
            state["revoked"] = primary is not None
            settlement_errors = []
            if primary is not None and state["issued"]:
                try: process._recover_pending_production(state["journal"])
                except BaseException as error: settlement_errors.append(error)
            if primary is not None:
                try: operation._revoke_or_require_terminal(state["journal"])
                except BaseException as error: settlement_errors.append(error)
            if claimed:
                try: state["inputs"].release_ssh_bindings()
                except BaseException as error: settlement_errors.append(error)
            if not state["executable_released"]:
                try:
                    process._release_attested_executable(state["executable"])
                    state["executable_released"] = True
                except BaseException as error: settlement_errors.append(error)
            if primary is not None or settlement_errors:
                errors = ([primary] if primary is not None else []) + settlement_errors
                raise BaseExceptionGroup("SSH failure/revocation/descriptor settlement", errors)
            return session
        def finalize_authenticated(self, session):
            state = states[self]
            _fail(state["session"] is session and state["pending_result"] is not None
                  and not state["finalized"] and not state["revoked"],
                  "authenticated SSH finalization lineage")
            operation._record_ssh_result(state["journal"], *state["pending_result"])
            if operation._cycle_route(state["journal"]) is not None:
                operation._record_ssh_settled(
                    state["journal"], "SSH_READY", session.command_serial,
                    session.binding_sha256, session.stdout_sha256, PARSER_SHA256,
                    operation._boottime_ns())
            operation._record_ssh_ready(state["journal"])
            state["finalized"] = True
            state["pending_result"] = None
            return session
        def revoke(self):
            import completion_kata_process as process
            state = states[self]
            operation._revoke_or_require_terminal(state["journal"])
            state["revoked"] = True
            if not state["executable_released"]:
                process._release_attested_executable(state["executable"])
                state["executable_released"] = True

    def recover(journal, input_cleanup):
        import completion_kata_inputs as inputs
        import completion_kata_process as process
        journal = operation._claim_production_cleanup_operation(journal)
        _fail(type(input_cleanup) is inputs._ProductionInputCleanup)
        errors = []
        if operation._has_recovery_command(journal):
            try: process._recover_pending_production(journal)
            except BaseException as error: errors.append(error)
        try: operation._revoke_or_require_terminal(journal)
        except BaseException as error: errors.append(error)
        try: input_cleanup.continue_cleanup()
        except BaseException as error: errors.append(error)
        if errors: raise BaseExceptionGroup("fresh SSH recovery settlement", errors)
        return operation._durable_phase(journal)

    def compose(journal, input_owner, executable_owner):
        import completion_kata_inputs as inputs
        import completion_kata_process as process
        journal = operation._claim_production_operation(journal)
        _fail(type(input_owner) is inputs._ProductionInputs)
        ssh_executable = process._claim_attested_executable(executable_owner, "ssh")
        _fail((ssh_executable.role, ssh_executable.path) == ("ssh", "/usr/bin/ssh"))
        _fail(guest.guest_program_bytes() == command_spec().stdin)
        _fail(operation._command_context(journal).lifecycle_phase == "RUNTIME_READY")
        value = _ProductionSsh(seal)
        states[value] = {"journal": journal, "inputs": input_owner,
                         "executable": ssh_executable, "executable_released": False,
                         "issued": False, "revoked": False, "finalized": False,
                         "pending_result": None, "session": None}
        return value

    return _ProductionSsh, compose, recover


(_ProductionSsh, _compose_production_ssh,
 _recover_production_ssh) = _production_routes()
del _production_routes


def _production_readiness_routes():
    """A separate sealed marker-only SSH owner with no workload capability."""
    seal, states = object(), {}

    class _ProductionReadinessSsh:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal, "production readiness SSH is package-private")
            return super().__new__(cls)
        def authenticate(self):
            import completion_kata_process as process
            state = states[self]
            _fail(not state["issued"] and not state["revoked"],
                  "readiness SSH retry or revoked")
            context = operation._command_context(state["journal"])
            _fail(context.lifecycle_phase == "RUNTIME_READY")
            claimed, primary = False, None
            try:
                identity = state["inputs"].prepare_launch()
                binding_owner = state["inputs"].claim_ssh_bindings(); claimed = True
                bindings = fdmap._claim_production_inputs(
                    binding_owner, context.operation_token, identity.manifest_sha256)
                _fail(operation._command_context(state["journal"]) == context)
                state["issued"] = True
                outcome, receipt = process._transact_fixed_ssh_readiness(
                    state["journal"], state["executable"], bindings)
                _fail(type(outcome) is process.ProcessOutcome
                      and type(receipt) is operation.DurableCommandOutcome
                      and receipt.command_id == outcome.command_id == "SSH_READINESS"
                      and receipt.command_serial == context.command_serial)
                durable = operation._durable_command_output(
                    state["journal"], context.command_serial, "SSH_READINESS",
                    receipt.binding_sha256, outcome.stdout, outcome.stderr)
                body = durable.body
                _fail(body["outcome"] == "exited" and body["status"] == 0
                      and body["errno"] is None and not body["uncertain"]
                      and not body["stdout_truncated"] and not body["stderr_truncated"]
                      and body["leader_reaped"] and body["descendants_reaped"]
                      and body["cgroup_empty"] and body["cgroup_removed"]
                      and body["pipes_eof"] and body["errors"] == []
                      and outcome.stderr == b"")
                readiness_guest.parse_guest_readiness_output(outcome.stdout)
                session = ReadinessAuthenticatedSession(
                    context.command_serial, receipt.binding_sha256,
                    readiness_guest.GUEST_PROGRAM_SHA256, body["stdout_sha256"],
                    readiness_guest.MARKER_SHA256)
                state["pending"] = (outcome.stdout, session)
                return session
            except BaseException as error:
                primary = error
                raise
            finally:
                errors = []
                if primary is not None and state["issued"]:
                    try: process._recover_pending_production(state["journal"])
                    except BaseException as error: errors.append(error)
                if primary is not None:
                    state["revoked"] = True
                    try: operation._revoke_or_require_terminal(state["journal"])
                    except BaseException as error: errors.append(error)
                if claimed:
                    try: state["inputs"].release_ssh_bindings()
                    except BaseException as error: errors.append(error)
                if not state["executable_released"]:
                    try:
                        process._release_attested_executable(state["executable"])
                        state["executable_released"] = True
                    except BaseException as error: errors.append(error)
                if errors:
                    raise BaseExceptionGroup("readiness SSH settlement", errors)
        def finalize_authenticated(self, session):
            state = states[self]
            _fail(state["pending"] is not None and state["pending"][1] is session
                  and not state["finalized"] and not state["revoked"])
            stdout = state["pending"][0]
            operation._record_ssh_readiness_result(
                state["journal"], session.command_serial,
                session.binding_sha256, stdout)
            operation._record_ssh_settled(
                state["journal"], "SSH_READINESS", session.command_serial,
                session.binding_sha256, session.stdout_sha256,
                readiness_guest.PARSER_SHA256, operation._boottime_ns())
            operation._record_ssh_readiness_ready(state["journal"])
            state["finalized"], state["pending"] = True, None
            return session
        def revoke(self):
            import completion_kata_process as process
            state = states[self]
            operation._revoke_or_require_terminal(state["journal"])
            state["revoked"] = True
            if not state["executable_released"]:
                process._release_attested_executable(state["executable"])
                state["executable_released"] = True

    def compose(journal, input_owner, executable_owner):
        import completion_kata_inputs as inputs
        import completion_kata_process as process
        journal = operation._claim_production_operation(journal)
        _fail(type(input_owner) is inputs._ProductionInputs
              and operation._cycle_route(journal)["route"] == "readiness")
        executable = process._claim_attested_executable(executable_owner, "ssh")
        _fail((executable.role, executable.path) == ("ssh", "/usr/bin/ssh")
              and readiness_guest.guest_program_bytes() == readiness_command_spec().stdin)
        value = _ProductionReadinessSsh(seal)
        states[value] = {"journal": journal, "inputs": input_owner,
                         "executable": executable, "executable_released": False,
                         "issued": False, "revoked": False, "finalized": False,
                         "pending": None}
        return value

    return _ProductionReadinessSsh, compose


(_ProductionReadinessSsh,
 _compose_production_readiness_ssh) = _production_readiness_routes()
del _production_readiness_routes


def open_fixed_ssh_owner():
    """Fail closed until exact attestation and the fixed coordinator compose T1."""
    raise SshError("production SSH requires exact attestation/coordinator")

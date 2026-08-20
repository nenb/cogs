#!/usr/bin/env python3
"""Optimization-safe hostile checks for ADR0099 fixed network composition."""
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
from types import MappingProxyType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_network as network
import completion_kata_network_journal as journal_model
import completion_kata_operation as operation
import completion_kata_process as process
import completion_kata_runtime as runtime


def check(value, message):
    if not value: raise AssertionError(message)


def reject(call, message="hostile network lifecycle value accepted"):
    try: call()
    except BaseException: return
    raise AssertionError(message)


def proof(body):
    body["proof_sha256"] = hashlib.sha256(operation._canonical(
        {name: value for name, value in body.items() if name != "proof_sha256"})).hexdigest()
    return body


def link(index, name, mac, peer, kind="veth"):
    return {"ifindex": index, "ifname": name, "kind": kind, "mac": mac,
            "peer_ifindex": peer, "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "operstate": "UP", "up": True, "qdisc": "noqueue", "addrgenmode": "none"}


BASELINES = {name: hashlib.sha256(name.encode()).hexdigest() for name in journal_model.BASELINES}
def bind(value, sources):
    value = {**value, "state_sha256": operation.ZERO}
    value["state_sha256"] = hashlib.sha256(operation._canonical({"identity": {
        name: child for name, child in value.items() if name != "state_sha256"},
        "sources": sources})).hexdigest()
    return value


SOURCE = [{"observation_serial": 0, "source_id": "IP_ALL_LINKS",
           "output_sha256": hashlib.sha256(b"[]").hexdigest(), "output_length": 2}]
EMPTY = bind({"netns": None, "host_link": None, "peer_link": None, "nft": None,
         "tap": None, "tc": None, "addresses_sha256": operation.ZERO,
         "routes_sha256": operation.ZERO, "state_sha256": operation.ZERO}, SOURCE)
NETNS = {"name": "c42naaaaaaaaaa", "mount_id": 41, "parent_id": 30, "device": "0:4",
         "inode_device": 4, "inode": 4026533000}
NFT = {"table_name": "c42taaaaaaaaaa", "table_handle": 7,
       "chain_handles": [["input", 8], ["output", 9], ["forward", 10]],
       "rule_handles": [[name, ordinal, 20 + index * 2 + ordinal]
                        for index, name in enumerate(("input", "output", "forward"))
                        for ordinal in (0, 1)]}
HOST = link(7, "c42h0", network.HOST_MAC, 8)
GUEST = link(8, "eth0", network.GUEST_MAC, 7)
READY_ID = bind({**EMPTY, "netns": NETNS, "host_link": HOST, "peer_link": GUEST, "nft": NFT,
            "addresses_sha256": "a" * 64, "routes_sha256": "b" * 64}, SOURCE)
BASELINE = proof({"operation_token": "a" * 64, "policy_version": journal_model.POLICY_VERSION,
                  "snapshot_kind": "baseline", "sources": SOURCE,
                  "baselines": BASELINES, "identity": EMPTY, "proof_sha256": operation.ZERO})
operation._validate_body("NETWORK_SNAPSHOT_V2", BASELINE)
class HistoryJournal:
    def network_history(self):
        return (("NETWORK_SNAPSHOT_V2", BASELINE),
                (journal_model.OUTPUT_RECORD, {"observation_serial": 4, "source_id": "IP_NS_LINKS",
                    "output_sha256": "e" * 64, "output_length": 2, "chunk_index": 0, "chunk_count": 1}))
check(network._sources(HistoryJournal(), "NETWORK_SNAPSHOT_V2")[0]["source_id"] == "IP_NS_LINKS",
      "authentic network_history snapshot cursor omitted")
check(type(journal_model.SUCCESS_PHASE_TRACES) is MappingProxyType and
      type(journal_model.EFFECT_COMMAND_TRACES) is MappingProxyType and
      type(journal_model.LIFECYCLE_REQUIREMENTS) is MappingProxyType,
      "B1 traces are mutable")
setup_trace = journal_model.SUCCESS_PHASE_TRACES["BASELINES_CAPTURED"]
journal_model.successful_trace(setup_trace, "BASELINES_CAPTURED")
reject(lambda: journal_model.successful_trace(setup_trace[:-1], "BASELINES_CAPTURED"),
       "B1 successful lifecycle accepted a skipped command")

# Firewall exists before addresses or either link-up; host addrgen precedes host-up.
check(journal_model.EFFECT_COMMAND_TRACES["IP_GUEST_LINK_UP"][:3] ==
      ("IP_GUEST_LINK_UP", "IP_HOST_LINKS", "IP_HOST_ADDRESSES"),
      "final setup trace retained obsolete partial observers")
check(network._SETUP_ACTIONS == tuple(network.Action(name) for name in journal_model.SETUP) and
      network.Action.IP_VETH_ADD_ATOMIC in network._SETUP_ACTIONS and
      not {network.Action.IP_LINK_ADD, network.Action.IP_LINK_MOVE, network.Action.IP_PEER_RENAME} & set(network._SETUP_ACTIONS),
      "setup is not atomic-netns veth policy")
check("RUNTIME_READY" not in journal_model.LIFECYCLE_REQUIREMENTS,
      "B1 improperly requires a deferred runtime-ready transition")
check(len(journal_model.SETUP_ABORT_TRACES) == len(journal_model.SETUP),
      "settled setup effects lack abort cuts")
for count, trace in enumerate(journal_model.SETUP_ABORT_TRACES, 1):
    prefix = tuple(item for action in journal_model.SETUP[:count]
                   for item in journal_model.EFFECT_COMMAND_TRACES[action])
    check(trace[:len(prefix)] == prefix, "setup abort did not retain the exact settled prefix")
    journal_model.successful_trace(trace, "BASELINES_CAPTURED")
    tail = trace[len(prefix):]
    check(not set(journal_model.SETUP) & set(tail) and tail.count("IP_NETNS_REMOVE") == 0,
          "setup abort replayed setup or retried local removal")
    state = journal_model.initial()
    state["effects"] = [{"action": action} for action in journal_model.SETUP[:count]] + [
        {"action": "IP_NETNS_REMOVE"},
        *([{"action": "NFT_REMOVE_ATOMIC"}]
          if count > journal_model.SETUP.index("NFT_INSTALL_OWNED") else []),
    ]
    state["quarantine"] = ("NETWORK_DETACHED_V2", {})
    check(journal_model.setup_abort_complete(state), "complete reverse setup chain rejected")
    state["pending"] = ("NETWORK_EFFECT_INTENT_V2", {}, 0)
    check(not journal_model.setup_abort_complete(state), "pending reverse effect treated as absent")
class DetachedJournal:
    def network_history(self): return ()
with patch.object(network, "_quarantine_stage", return_value=("NETWORK_DETACHED_V2", {
        "placeholder": {"device": 7, "inode": 8}})), \
     patch.object(network, "_original_placeholder", return_value={"device": 7, "inode": 9}), \
     patch.object(network, "_bound_names", return_value=("c42naaaaaaaaaa", "c42taaaaaaaaaa")), \
     patch.object(network, "_quarantine_name", return_value="c42qaaaaaaaaaa"), \
     patch.object(network.os, "unlink", side_effect=AssertionError("legacy shape cleanup attempted")):
    reject(lambda: network._cleanup_detached_placeholders(DetachedJournal()),
           "detached V2 history without durable cleanup ownership was deleted by shape")
positions = {action: network._SETUP_ACTIONS.index(action) for action in network._SETUP_ACTIONS}
check(positions[network.Action.NFT_INSTALL_OWNED] < positions[network.Action.IP_HOST_ADDRESS_ADD] and
      positions[network.Action.NFT_INSTALL_OWNED] < positions[network.Action.IP_GUEST_ADDRESS_ADD] and
      positions[network.Action.IP_HOST_ADDRGEN_NONE] < positions[network.Action.IP_HOST_LINK_UP],
      "live link/address precedes firewall or addrgen")

# Persistent ownership precedes the first authoritative baseline command, and
# every setup mutation checks it before recording or mutating.
gate_events = []
class GateCut(Exception): pass
with patch.object(network.nft_owner, "acquire", side_effect=lambda _j: gate_events.append("acquire")), \
     patch.object(network.nft_owner, "require_active", side_effect=lambda _j: gate_events.append("require")), \
     patch.object(network, "_perform_fixed", side_effect=lambda *_a: (_ for _ in ()).throw(GateCut())):
    try: network._capture_fixed_baselines(object(), object(), object(), object())
    except GateCut: pass
check(gate_events == ["acquire", "require"], "baseline command preceded persistent NFT admission")
for setup_action in network._SETUP_ACTIONS:
    recorded = []
    with patch.object(network.nft_owner, "require_active", side_effect=GateCut()), \
         patch.object(network, "_record_effect", side_effect=lambda *_a: recorded.append(1)):
        try: network._effect(object(), setup_action, object(), object(), object(), EMPTY)
        except GateCut: pass
    check(not recorded, f"setup mutation intent preceded NFT gate:{setup_action.value}")

# The real journal codec enforces intent/observed/settled ordering, exact setup
# order, and nsfs replacement rejection rather than trusting a fake owner type.
state = journal_model.initial(); state["snapshots"] = [BASELINE]; state["current"] = EMPTY
intent = {"operation_token": "a" * 64, "policy_version": journal_model.POLICY_VERSION,
          "effect_serial": 0, "action": "IP_NETNS_ADD",
          "prior_proof_sha256": operation.ZERO, "target": EMPTY}
operation._validate_body("NETWORK_EFFECT_INTENT_V2", intent)
state = journal_model.advance(state, "NETWORK_EFFECT_INTENT_V2", intent, "BASELINES_CAPTURED")
def command_intent(command_id):
    source = network.command(network.Action(command_id)); role = ("nft" if source.tool_contract.startswith("libnftables")
        else "tc" if source.tool_contract.startswith("tc-") else "ip")
    argv = ["/usr/sbin/" + role, *(NFT["table_name"] if item == network.TABLE else
            NETNS["name"] if item == network.NETNS else "c42haaaaaaaaaa" if item == network.HOST_IF else item
            for item in source.argv_tail)]
    return {"command_id": command_id, "command_serial": 99, "operation_token": "a" * 64, "executable_role": role,
            "executable_path": "/usr/sbin/" + role, "argv": argv,
            "stdin_hex": source.stdin.replace(network.TABLE.encode(), NFT["table_name"].encode()).hex(),
            "stdin_length": len(source.stdin),
            "deadline_class": "network", "duration_ns": 10_000_000_000, "output_grammar": "json",
            "stdout_limit": 65536, "stderr_limit": 65536, "inherited_fds": []}
for action, trace in journal_model.EFFECT_COMMAND_TRACES.items():
    first = 1 if action == "IP_NETNS_REMOVE" else 2
    for cut in range(first, len(trace) + 1):
        cursor_state = journal_model.initial(); cursor_state["snapshots"] = [{"identity": READY_ID}]
        cursor_state["pending"] = ("NETWORK_EFFECT_INTENT_V2", {"action": action, "target": READY_ID}, 0)
        cursor_state["effect_commands"] = list(trace[:cut])
        cursor_state["output_pending"] = {"base": {"source_id": trace[cut - 1]}, "chunks": [b"x"]}
        journal_model.command_intent(command_intent(trace[cut - 1]), cursor_state)
for observer in journal_model.EFFECT_COMMAND_TRACES["IP_NETNS_ADD"]:
    state = journal_model.command_intent(command_intent(observer), state)
reject(lambda: journal_model.advance(state, "NETWORK_EFFECT_INTENT_V2", intent, "BASELINES_CAPTURED"),
       "pending mutation could be reissued")
wrong_target = copy.deepcopy(intent); wrong_target["target"] = {**EMPTY, "routes_sha256": "f" * 64}
fresh = journal_model.initial(); fresh["snapshots"] = [BASELINE]; fresh["current"] = EMPTY
reject(lambda: journal_model.advance(fresh, "NETWORK_EFFECT_INTENT_V2", wrong_target,
                                     "BASELINES_CAPTURED"), "effect intent did not bind exact target")
def quarantine_body(placeholder, preserved=None):
    return proof({"operation_token": "a" * 64, "policy_version": journal_model.POLICY_VERSION,
        "original_name": NETNS["name"], "quarantine_name": "c42qaaaaaaaaaa", "target": EMPTY,
        "placeholder": placeholder, "preserved": preserved, "proof_sha256": operation.ZERO})
qstate = journal_model.initial(); qstate["current"] = EMPTY
quarantine = quarantine_body(None)
qstate = journal_model.advance(qstate, "NETWORK_QUARANTINE_INTENT_V2", quarantine, "TASK_STOPPED")
quarantine = quarantine_body({"device": 7, "inode": 8})
qstate = journal_model.advance(qstate, "NETWORK_QUARANTINE_PLACEHOLDER_V2", quarantine, "TASK_STOPPED")
quarantine = quarantine_body({"device": 7, "inode": 9})
qstate = journal_model.advance(qstate, "NETWORK_QUARANTINE_PLACEHOLDER_V2", quarantine, "TASK_STOPPED")
quarantine = quarantine_body({"device": 7, "inode": 9},
    {"name": "c42naaaaaaaaaa", "device": 7, "inode": 10})
qstate = journal_model.advance(qstate, "NETWORK_QUARANTINE_MOVED_V2", quarantine, "TASK_STOPPED")
qstate = journal_model.advance(qstate, "NETWORK_QUARANTINE_SETTLED_V2", quarantine, "TASK_STOPPED")
qstate = journal_model.advance(qstate, "NETWORK_DETACH_INTENT_V2", quarantine, "TASK_STOPPED")
detached = quarantine_body({"device": 7, "inode": 9},
    {"name": "c42qaaaaaaaaaa", "device": 7, "inode": 9})
qstate = journal_model.advance(qstate, "NETWORK_DETACHED_V2", detached, "TASK_STOPPED")
reject(lambda: journal_model.advance(qstate, "NETWORK_QUARANTINE_MOVED_V2", quarantine, "TASK_STOPPED"),
       "detached quarantine replayed move")
# V3 gives every cleanup object a durable exact owner and fixes all ten
# relocation/removal reopen cuts without changing historical V2 meanings.
def exact_stat(inode):
    return {"device": 7, "inode": inode, "mode": 0o600, "uid": 0, "gid": 0,
            "nlink": 1, "size": 0, "mtime_ns": 1, "ctime_ns": 1}
def cleanup_envelope(**values):
    return proof({"operation_token": "a" * 64, "policy_version": journal_model.POLICY_VERSION,
                  **values, "proof_sha256": operation.ZERO})
support = {"preserved_directory": exact_stat(30), "parent_stage_directory": exact_stat(31)}
parent_mount = {"mount_id": 40, "parent_id": 4, "device": "0:7", "root": "/netns",
    "mount_point": "/run/netns", "mount_options": ["rw"], "optional_fields": [],
    "fs_type": "tmpfs", "source": "tmpfs", "super_options": ["rw"],
    "inode_device": 7, "inode": 32}
cstate = journal_model.initial()
support_body = cleanup_envelope(support=support)
journal_model.validate(journal_model.SUPPORT_RECORD, support_body, operation._canonical)
cstate = journal_model.advance(cstate, journal_model.SUPPORT_RECORD, support_body, "FS_SETTLED")
cstate["pending"] = ("NETWORK_EFFECT_INTENT_V2", {"action": "IP_NETNS_ADD"}, 0)
mount_body = cleanup_envelope(parent_mount=parent_mount)
cstate = journal_model.advance(cstate, journal_model.PARENT_MOUNT_RECORD, mount_body, "BASELINES_CAPTURED")
cstate["pending"] = None
cstate["original_placeholder"] = {"placeholder": exact_stat(33)}
cstate["quarantine"] = ("NETWORK_DETACHED_V2", {"placeholder": exact_stat(34)})
authority = {"support": support, "parent_mount": parent_mount,
             "placeholders": {"original": exact_stat(33), "quarantine": exact_stat(34)}}
intent_v3 = cleanup_envelope(authority=authority)
cstate = journal_model.advance(cstate, journal_model.DETACHED_CLEANUP_INTENT, intent_v3, "TASK_STOPPED")
cleanup_order = (("original-placeholder", "relocated"), ("original-placeholder", "removed"),
    ("quarantine-placeholder", "relocated"), ("quarantine-placeholder", "removed"),
    ("preserved-directory", "relocated"), ("preserved-directory", "removed"),
    ("parent-mount", "relocated"), ("parent-mount", "removed"),
    ("parent-stage-directory", "relocated"), ("parent-stage-directory", "removed"))
relocated_identities = {}
for index, (resource, action) in enumerate(cleanup_order):
    expected_cleanup = {"original-placeholder": authority["placeholders"]["original"],
        "quarantine-placeholder": authority["placeholders"]["quarantine"],
        "preserved-directory": support["preserved_directory"],
        "parent-stage-directory": support["parent_stage_directory"]}
    identity = (relocated_identities[resource] if action == "removed" else
                {**parent_mount, "mount_point": ""} if resource == "parent-mount" else
                {**expected_cleanup[resource], "ctime_ns": 10 + index})
    if action == "relocated": relocated_identities[resource] = identity
    step = cleanup_envelope(resource=resource, action=action, identity=identity)
    journal_model.validate(journal_model.DETACHED_CLEANUP_STEP, step, operation._canonical)
    replacement = copy.deepcopy(identity)
    replacement["mount_id" if resource == "parent-mount" else "inode"] += 1
    replaced_step = cleanup_envelope(resource=resource, action=action, identity=replacement)
    reject(lambda replaced_step=replaced_step: journal_model.advance(copy.deepcopy(cstate),
        journal_model.DETACHED_CLEANUP_STEP, replaced_step, "TASK_STOPPED"),
        f"detached cleanup replacement accepted at {resource}/{action}")
    cstate = journal_model.advance(copy.deepcopy(cstate), journal_model.DETACHED_CLEANUP_STEP,
                                   step, "TASK_STOPPED")
check(len(cstate["cleanup_steps"]) == 10, "detached cleanup crash/reopen cursor incomplete")
reject(lambda: journal_model.advance(cstate, journal_model.DETACHED_CLEANUP_STEP,
    cleanup_envelope(resource="original-placeholder", action="relocated", identity=exact_stat(99)),
    "TASK_STOPPED"), "detached cleanup step replay accepted")

# A crash after atomic relocation or unlink is recovered from exact retained
# inode state. A replacement appearing after relocation is left untouched.
with tempfile.TemporaryDirectory() as temporary:
    source_dir = os.path.join(temporary, "source"); target_dir = os.path.join(temporary, "target")
    os.mkdir(source_dir); os.mkdir(target_dir)
    source_fd = os.open(source_dir, os.O_RDONLY | os.O_DIRECTORY)
    target_fd = os.open(target_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        Path(source_dir, "owned").write_bytes(b"owned")
        expected = network._placeholder_identity(os.stat(Path(source_dir, "owned"), follow_symlinks=False))
        rows = []
        def append_step(_journal, _kind, **values): rows.append((_kind, values))
        def real_rename(source_parent, source, target_parent, target):
            os.rename(source, target, src_dir_fd=source_parent, dst_dir_fd=target_parent)
        def crash_after_rename(*args): real_rename(*args); raise RuntimeError("crash")
        with patch.object(network, "_cleanup_rows", side_effect=lambda _journal: rows), \
             patch.object(network, "_cleanup_record", side_effect=append_step), \
             patch.object(network, "_rename_noreplace", side_effect=crash_after_rename):
            reject(lambda: network._cleanup_owned_entry(object(), "original-placeholder",
                source_fd, "owned", target_fd, "staged", expected))
        with patch.object(network, "_cleanup_rows", side_effect=lambda _journal: rows), \
             patch.object(network, "_cleanup_record", side_effect=append_step), \
             patch.object(network, "_rename_noreplace", side_effect=real_rename):
            network._cleanup_owned_entry(object(), "original-placeholder", source_fd, "owned",
                                         target_fd, "staged", expected)
        check(not os.path.exists(Path(source_dir, "owned")) and not os.path.exists(Path(target_dir, "staged")),
              "relocation/unlink crash did not reopen")
        Path(source_dir, "owned").write_bytes(b"owned")
        expected = network._placeholder_identity(os.stat(Path(source_dir, "owned"), follow_symlinks=False)); rows.clear()
        def replace_after_rename(*args):
            real_rename(*args); Path(source_dir, "owned").write_bytes(b"foreign")
        with patch.object(network, "_cleanup_rows", side_effect=lambda _journal: rows), \
             patch.object(network, "_cleanup_record", side_effect=append_step), \
             patch.object(network, "_rename_noreplace", side_effect=replace_after_rename):
            reject(lambda: network._cleanup_owned_entry(object(), "original-placeholder",
                source_fd, "owned", target_fd, "staged", expected))
        check(Path(source_dir, "owned").read_bytes() == b"foreign" and Path(target_dir, "staged").read_bytes() == b"owned",
              "cleanup replacement was not preserved")
    finally: os.close(target_fd); os.close(source_fd)
raw_chunks = b"x" * (journal_model.MAX_CHUNK_BYTES + 3); output_hash = hashlib.sha256(raw_chunks).hexdigest()
cursor = journal_model.initial(); cursor = journal_model.command_outcome(cursor, {
    "command_serial": 0, "command_id": "IP_ALL_LINKS", "stdout_sha256": output_hash,
    "stdout_length": len(raw_chunks), "stderr_length": 0, "stdout_truncated": False,
    "stderr_truncated": False, "outcome": "exited", "status": 0, "uncertain": False})
def output_chunk(index, raw):
    return proof({"operation_token": "a" * 64, "policy_version": journal_model.POLICY_VERSION,
        "observation_serial": 0, "source_id": "IP_ALL_LINKS", "command_serial": 0,
        "chunk_index": index, "chunk_count": 2, "output_sha256": output_hash,
        "output_length": len(raw_chunks), "raw_hex": raw.hex(), "proof_sha256": operation.ZERO})
cursor = journal_model.advance(cursor, journal_model.OUTPUT_RECORD,
                               output_chunk(0, raw_chunks[:journal_model.MAX_CHUNK_BYTES]), "FS_SETTLED")
cursor = journal_model.command_intent(command_intent("IP_ALL_LINKS"), cursor)
cursor = journal_model.advance(cursor, journal_model.OUTPUT_RECORD,
                               output_chunk(1, raw_chunks[journal_model.MAX_CHUNK_BYTES:]), "FS_SETTLED")
check(cursor["output_pending"] is None and cursor["observations"][0]["raw"] == raw_chunks,
      "observer chunk cursor did not resume")
# Production pass resumes only its missing suffix; partial nft mutation reuses retained list bytes.
pass_rows = [{"observation_serial": index, "source_id": name,
              "output_sha256": hashlib.sha256(name.encode()).hexdigest(), "output_length": len(name)}
             for index, name in enumerate(("IP_HOST_LINKS", "IP_NS_LINKS"))]
def pass_perform(_journal, action, *_args, **_kwargs):
    name = action.value; raw = name.encode(); pass_rows.append({"observation_serial": len(pass_rows),
        "source_id": name, "output_sha256": hashlib.sha256(raw).hexdigest(), "output_length": len(raw)})
with patch.object(network, "_resume_observer_chunk"), patch.object(network, "_sources", side_effect=lambda *_a: list(pass_rows)), \
     patch.object(network, "_source_raw", side_effect=lambda _j, row: row["source_id"].encode()), \
     patch.object(network, "_perform_fixed", side_effect=pass_perform):
    resumed = network._observer_pass(object(), object(), object(), object(),
        ("IP_HOST_LINKS", "IP_NS_LINKS", "IP_HOST_ADDRESSES", "IP_NS_ADDRESSES"), "NETWORK_SNAPSHOT_V2")
check(resumed == tuple(name.encode() for name in ("IP_HOST_LINKS", "IP_NS_LINKS", "IP_HOST_ADDRESSES", "IP_NS_ADDRESSES")),
      "production observer pass duplicated retained prefix")
recorded_resume = []
with patch.object(network, "_pending_observation", return_value={"source_id": "NFT_REMOVE_ATOMIC", "command_serial": 7}), \
     patch.object(network, "_retained_observation_raw", return_value=b"retained-table"), \
     patch.object(network, "_record_observation", side_effect=lambda _j, source, raw, serial: recorded_resume.append((source, raw, serial))):
    network._resume_observer_chunk(object(), object(), object(), object(), network.Action.NFT_REMOVE_ATOMIC)
check(recorded_resume == [("NFT_REMOVE_ATOMIC", b"retained-table", 7)], "partial nft mutation resumed empty bytes")

# Complete runtime address inventory includes the TAP row and requires it empty.
tap_row = link(30, "tap-fixed", "02:00:00:00:00:30", None, "tap")
tap = network.Link(30, "tap-fixed", "tap", tap_row["mac"], None,
                   tuple(tap_row["flags"]), "UP", True, "noqueue", "none")
lo = network.Link(1, "lo", "loopback", "00:00:00:00:00:00", None,
                  ("LOOPBACK", "UP", "LOWER_UP"), "UNKNOWN", True, "noqueue", None)
guest = network.Link(8, "eth0", "veth", network.GUEST_MAC, 7,
                     tuple(GUEST["flags"]), "UP", True, "noqueue", "none")
addresses = b'[{"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},{"ifindex":8,"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.2","prefixlen":30,"scope":"global"}]},{"ifindex":30,"ifname":"tap-fixed","addr_info":[]}]'
check(len(network.parse_runtime_addresses(addresses, (lo, guest, tap))) == 3,
      "authentic TAP-empty address inventory rejected")
reject(lambda: network.parse_runtime_addresses(addresses.replace(b'"addr_info":[]',
    b'"addr_info":[{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]'),
    (lo, guest, tap)), "TAP IPv6 address accepted")

# Endpoint-derived tc argv is admitted only when its endpoint name is retained
# by the durable ready/runtime identity.
runtime_id = copy.deepcopy(READY_ID); runtime_id["tap"] = tap_row
runtime_id["tc"] = {"qdiscs": [{}] * 4, "filters": [{}] * 4}
runtime_snapshot = {"snapshot_kind": "discovered", "identity": runtime_id}
tc_state = {"snapshots": [runtime_snapshot], "effects": [], "pending": None}
intent_tc = {"command_id": "TC_QDISC", "executable_role": "tc",
             "executable_path": "/usr/sbin/tc", "stdin_hex": "", "stdin_length": 0,
             "deadline_class": "network", "duration_ns": 10_000_000_000,
             "output_grammar": "json", "stdout_limit": 65536, "stderr_limit": 65536,
             "inherited_fds": [],
             "argv": ["/usr/sbin/tc", "-n", NETNS["name"], "-j", "qdisc", "show", "dev", "tap-fixed"]}
journal_model.tc_intent(intent_tc, tc_state)
foreign = copy.deepcopy(intent_tc); foreign["argv"][-1] = "foreign0"
reject(lambda: journal_model.tc_intent(foreign, tc_state), "foreign tc endpoint accepted")
ready_teardown = journal_model.SUCCESS_PHASE_TRACE_VARIANTS["TASK_STOPPED"][1]
discovered_teardown = journal_model.SUCCESS_PHASE_TRACE_VARIANTS["TASK_STOPPED"][2]
absent_teardown = journal_model.SUCCESS_PHASE_TRACE_VARIANTS["TASK_STOPPED"][-1]
journal_model.successful_trace(ready_teardown, "TASK_STOPPED")
journal_model.successful_trace(discovered_teardown, "TASK_STOPPED")
journal_model.successful_trace(absent_teardown, "TASK_STOPPED")
for trace in journal_model.SUCCESS_PHASE_TRACE_VARIANTS["OWNERSHIP_OBSERVED"]:
    journal_model.successful_trace(trace, "OWNERSHIP_OBSERVED")
check("IP_NETNS_REMOVE" not in absent_teardown and
      "NFT_REMOVE_ATOMIC" not in journal_model.SUCCESS_PHASE_TRACE_VARIANTS["SHARE_ABSENT"][-1],
      "absent resource trace executes rm")
operation_netns_path = runtime.operation_netns_path("a" * 64)
retained_network = {"operation_token": "a" * 64, "identity": NETNS, "path": operation_netns_path}
with patch.object(network, "_consume_runtime_network", return_value=retained_network), \
     patch.object(network, "_verify_runtime_network", return_value=retained_network):
    runtime_permit = runtime._make_operation_launch_permit(object())
    run_spec = runtime.ctr_run_spec(runtime_permit)
    runtime._preexec_launch_network(runtime_permit, 1234); runtime._release_launch_preexec(runtime_permit)
    stored = {"ID": runtime.CONTAINER_ID, "Labels": {}, "Image": "",
        "Runtime": {"Name": runtime.RUNTIME, "Options": {"type_url": "io.containerd.kata.v2.options",
                    "config_path": runtime.RUNTIME_CONFIG}}, "SnapshotKey": "", "Snapshotter": "",
        "CreatedAt": "2026-01-01T00:00:00Z", "UpdatedAt": "2026-01-01T00:00:00Z",
        "Extensions": {}, "Spec": runtime._expected_operation_oci_spec("a" * 64, "/proc/1234/fd/202")}
    runtime.validate_stored_info(
        stored, runtime._stored_launch_network_grant(runtime_permit),
        runtime._resolved_launch_network_path(runtime_permit))
check(operation_netns_path == "/run/netns/" + NETNS["name"] and
      run_spec.argv[5:7] == ("containers", "create") and "run" not in run_spec.argv and
      stored["Spec"]["linux"]["namespaces"][-1] == {"type": "network", "path": "/proc/1234/fd/202"},
      "runtime operation-owned metadata grant diverged")

# Production observation selects the exact durable CTR_RUN preexec after reopen;
# it never falls back to the historical namespace alias.
run_intent = {"command_serial": 0, "command_id": "CTR_RUN", "binding_sha256": "1" * 64,
              "lifecycle_phase": "NETWORK_READY"}
run_preexec = {"command_serial": 0, "command_id": "CTR_RUN", "binding_sha256": "1" * 64,
               "pid": 1234, "namespace_fd": 202, "namespace_path": "/proc/1234/fd/202"}
run_outcome = {"command_serial": 0, "command_id": "CTR_RUN", "binding_sha256": "1" * 64,
               "outcome": "exited", "status": 0, "uncertain": False}
container_rows = b"CONTAINER    IMAGE    RUNTIME\ncogs-stage2-ssh-v1    -    io.containerd.kata.v2\n"
task_rows = b"TASK    PID    STATUS\n"
info_rows = json.dumps(stored, sort_keys=True, separators=(",", ":")).encode()
observer_rows = (("CTR_CONTAINER_INFO", info_rows), ("CTR_CONTAINER_LIST", container_rows),
                 ("CTR_TASK_LIST", task_rows))
observer_intents = tuple({"command_serial": index, "command_id": command_id,
                          "binding_sha256": str(index) * 64, "lifecycle_phase": "RUNTIME_READY"}
                         for index, (command_id, _raw) in enumerate(observer_rows, 2))
observer_outcomes = tuple({"command_serial": row["command_serial"], "command_id": row["command_id"],
                           "binding_sha256": row["binding_sha256"], "outcome": "exited", "status": 0,
                           "uncertain": False, "stdout_sha256": hashlib.sha256(raw).hexdigest(),
                           "stderr_sha256": hashlib.sha256(b"").hexdigest()}
                          for row, (_command_id, raw) in zip(observer_intents, observer_rows, strict=True))
observer_outputs = tuple({"command_serial": row["command_serial"], "stdout_hex": raw.hex(), "stderr_hex": ""}
                         for row, (_command_id, raw) in zip(observer_intents, observer_rows, strict=True))
durable_history = {"operation_token": "a" * 64, "phase": "RUNTIME_READY", "tip": "RUNTIME_READY",
    "terminal_sha256": "f" * 64, "intents": (run_intent, *observer_intents), "preexecs": (run_preexec,),
    "outcomes": (run_outcome, *observer_outcomes), "outputs": observer_outputs,
    "daemon_retained": (), "daemon_outcomes": (), "runtime_resumes": ()}
class ReopenedObservationJournal:
    def runtime_recovery_history(self): return copy.deepcopy(durable_history)
nonlocals = inspect.getclosurevars(runtime._observe_fixed_runtime).nonlocals
owners = nonlocals["owners"]
attestations = inspect.getclosurevars(nonlocals["verify_attestation"]).nonlocals["attestations"]
daemons = inspect.getclosurevars(nonlocals["verify_daemon"]).nonlocals["daemons"]
retained_grant = object(); attestation = object(); daemon = object(); config = object(); control = object()
attestations[attestation] = [(), config, control, hashlib.sha256(b"config").hexdigest()]
def observe_from_reopen():
    journal = ReopenedObservationJournal(); owner = object()
    daemons[daemon] = [journal, None, None, control, None, None, None, None, None, None, {}]
    owners[owner] = [journal, None, None, None, retained_network, attestation, daemon,
                     control, None, retained_grant, None, None]
    try: return runtime._observe_fixed_runtime(owner)
    finally: owners.pop(owner, None); daemons.pop(daemon, None)
empty_processes = runtime.ProcessClassification(runtime.Observation.ABSENT, (), "absent")
with patch.object(network, "_verify_runtime_network", return_value=retained_network), \
     patch.object(runtime.rootfs_fs, "_read_regular", return_value=b"config"), \
     patch.object(runtime, "_proc_snapshot", return_value=empty_processes), \
     patch.object(runtime, "_qmp_kvm", return_value={"state": "absent"}), \
     patch.object(runtime, "_share_fact", return_value={"state": "absent"}):
    check(observe_from_reopen()["mount"] == runtime.MOUNT_LIST_SHA256,
          "production observation ignored durable CTR_RUN launch path")
    historical = copy.deepcopy(stored); historical["Spec"] = runtime.expected_oci_spec()
    historical_raw = json.dumps(historical, sort_keys=True, separators=(",", ":")).encode()
    durable_history["outcomes"] = (run_outcome, {**observer_outcomes[0],
        "stdout_sha256": hashlib.sha256(historical_raw).hexdigest()}, *observer_outcomes[1:])
    durable_history["outputs"] = ({**observer_outputs[0], "stdout_hex": historical_raw.hex()},
                                  *observer_outputs[1:])
    reject(observe_from_reopen, "production observation accepted historical network alias")
attestations.pop(attestation, None)

check(operation.command_policy.LEGACY_V1_VERSION.endswith("protected-746") and
      "CONTAINERD_START" not in operation.command_policy.LEGACY_COMMANDS,
      "protected historical v1 vocabulary widened")
# Production ready->discovered->runtime records TAP discovery before its first
# tc intent, then validates the exact full runtime snapshot.
netns_object = network.NetnsIdentity(41, 30, "0:4", "net:[4026533000]",
    "/run/netns/" + NETNS["name"], ("rw",), (), "nsfs", "nsfs", ("rw",), 4, 4026533000)
host_object = network.Link(**{**HOST, "flags": tuple(HOST["flags"])})
guest_object = network.Link(**{**GUEST, "flags": tuple(GUEST["flags"])})
qroot = network.TcQdisc(8, "eth0", "noqueue", "0:", None, True, 2)
qing = network.TcQdisc(8, "eth0", "ingress", "ffff:", "ffff:fff1", False, None)
troot = network.TcQdisc(30, "tap-fixed", "noqueue", "0:", None, True, 2)
ting = network.TcQdisc(30, "tap-fixed", "ingress", "ffff:", "ffff:fff1", False, None)
def directional(source_link, target_link, index):
    table = network.TcFilterTable(source_link.ifindex, source_link.ifname, "ingress", "all", 49152, "u32", 0, "800:", 1)
    action = network.TcAction(index, "mirred", "pipe", "redirect", "egress",
                              target_link.ifindex, target_link.ifname, 1, 1)
    return (table, network.TcFilter(source_link.ifindex, source_link.ifname, "ingress", "all",
                                    49152, "u32", 0, "800::800", 2048, action))
nft_object = network.NftSnapshot({"nftables": [{"table": {"name": NFT["table_name"]}}]},
    network.NftKernelIdentity(7, tuple(tuple(row) for row in NFT["chain_handles"]),
                              tuple(tuple(row) for row in NFT["rule_handles"])))
ready = network._identity(netns_object, host_object, guest_object, nft_object,
                          tc=network._tc_value((qroot,), ()))
ready = bind(ready, SOURCE)
class JournalCut:
    def __init__(self): self.rows = [{"snapshot_kind": "ready", "identity": ready, "baselines": BASELINES}]
    def network_history(self): return ()
    def begin_network_cleanup(self, _target): pass
    def settle_network_cleanup(self, _target): pass
    def durable_phase(self): return "NETWORK_ABSENT"
cut = JournalCut(); snapshots = []
def source_rows(*ids):
    return [{"observation_serial": index + 10, "source_id": name,
             "output_sha256": hashlib.sha256(name.encode()).hexdigest(), "output_length": len(name)}
            for index, name in enumerate(ids)]
def fake_sources(_journal, _after=None):
    return source_rows("IP_HOST_LINKS", "IP_NS_LINKS", "IP_HOST_ADDRESSES", "IP_NS_ADDRESSES") if len(snapshots) == 0 else source_rows(
        "IP_HOST_ROUTES4", "IP_HOST_ROUTES6", "IP_NS_ROUTES4", "IP_NS_ROUTES6",
        "TC_QDISC", "TC_QDISC:tap-fixed", "TC_INGRESS_FILTER:eth0",
        "TC_INGRESS_FILTER:tap-fixed", "MOUNTINFO", "NETNS_STAT", "NFT_TABLE")
def fake_snapshot(_journal, kind, baselines, identity, sources):
    identity = network._bind_identity(identity, sources)
    body = proof({"operation_token": "a" * 64, "policy_version": journal_model.POLICY_VERSION,
                  "snapshot_kind": kind, "baselines": baselines, "sources": sources,
                  "identity": identity, "proof_sha256": operation.ZERO})
    operation._validate_body("NETWORK_SNAPSHOT_V2", body)
    snapshots.append(body); cut.rows.append(body); return body
def fake_perform(_journal, action, _ip, _nft, _tc, **_kwargs):
    if action in {network.Action.TC_QDISC, network.Action.TC_INGRESS_FILTER}:
        endpoint = _kwargs.get("endpoint") or guest_object
        tail = (("qdisc", "show", "dev", endpoint.ifname) if action is network.Action.TC_QDISC else
                ("filter", "show", "dev", endpoint.ifname, "ingress"))
        candidate = {**intent_tc, "operation_token": "a" * 64, "command_id": action.value,
                     "argv": ["/usr/sbin/tc", "-n", NETNS["name"], "-j", *tail], "stdin_hex": ""}
        journal_model.tc_intent(candidate, {"snapshots": cut.rows, "effects": [], "pending": None})
    return action.value.encode()
with patch.object(network, "_baselines", return_value=(BASELINES, cut.rows)), \
     patch.object(network, "_perform_fixed", side_effect=fake_perform), \
     patch.object(network, "parse_links", return_value=(host_object,)), \
     patch.object(network, "parse_runtime_links", return_value=(lo, guest_object, tap)), \
     patch.object(network, "parse_addresses"), patch.object(network, "parse_runtime_addresses"), \
     patch.object(network, "parse_routes"), patch.object(network, "_netns_identity", return_value=netns_object), \
     patch.object(network, "_journal_netns", return_value=netns_object), \
     patch.object(network, "_observer_pass", side_effect=lambda _j, _i, _n, _t, expected, *_a, **_k: tuple(name.encode() for name in expected)), \
     patch.object(network, "parse_tc_qdiscs", side_effect=((qroot, qing), (troot, ting))), \
     patch.object(network, "parse_tc_filters", side_effect=(directional(guest_object, tap, 11), directional(tap, guest_object, 12))), \
     patch.object(network, "parse_nft_snapshot", return_value=nft_object), \
     patch.object(network, "_sources", side_effect=fake_sources), patch.object(network, "_snapshot", side_effect=fake_snapshot), \
     patch.object(network, "_bound_names", return_value=(NETNS["name"], NFT["table_name"])), \
     patch.object(network, "_bound_host", return_value=network.HOST_IF):
    network._observe_fixed_runtime_network(cut, object(), object(), object())
check([row["snapshot_kind"] for row in snapshots] == ["discovered", "runtime"],
      "production runtime did not durably discover TAP before tc/full runtime")

# The production ready-only failed-launch path removes only the retained unique
# namespace; an already-absent namespace takes the direct baseline trace and
# issues no removal command.
def ready_cut(kind="ready"):
    value = JournalCut()
    if kind == "discovered": value.rows[-1] = {"snapshot_kind": kind, "identity": runtime_id, "baselines": BASELINES}
    return value
def absent_identity():
    return {**network._empty_identity(), "nft": READY_ID["nft"]}
def teardown_snapshot(_journal, kind, baselines, identity, sources):
    snapshots.append({"snapshot_kind": kind, "identity": network._bind_identity(identity, sources),
                      "baselines": baselines, "proof_sha256": "f" * 64})
    return snapshots[-1]
for snapshot_kind, existing, expected_removals in (("ready", netns_object, [network.Action.IP_NETNS_REMOVE]),
        ("discovered", netns_object, [network.Action.IP_NETNS_REMOVE]), ("ready", None, [])):
    teardown = ready_cut(snapshot_kind); removals = []; snapshots.clear(); netns_calls = []
    def netns_observe(*_args, **_kwargs):
        netns_calls.append(1); return existing if len(netns_calls) == 1 else None
    def remove_effect(_journal, action, _ip, _nft, _tc, _prior):
        removals.append(action); return absent_identity()
    with patch.object(network.nft_owner, "require_active"), \
         patch.object(network, "_baselines", return_value=(BASELINES, teardown.rows)), \
         patch.object(network, "_resume_effect"), patch.object(network, "_netns_identity", side_effect=netns_observe), \
         patch.object(network, "_observe_ready_teardown", return_value=ready), \
         patch.object(network, "_observe_discovered_identity", return_value=runtime_id), \
         patch.object(network, "_effect", side_effect=remove_effect), patch.object(network, "_settled_effects", return_value=[]), \
         patch.object(network, "_quarantine_netns"), patch.object(network, "_bound_names", return_value=(NETNS["name"], NFT["table_name"])), \
         patch.object(network, "_bound_host", return_value=network.HOST_IF), \
         patch.object(network, "_fresh_baseline_outputs", return_value=((b"[]",) * 6, b"mount\n", BASELINES)), \
         patch.object(network, "_snapshot", side_effect=teardown_snapshot), \
         patch.object(network, "_sources", return_value=SOURCE), \
         patch.object(operation, "_settle_network_phase"), \
         patch.object(operation, "_durable_phase", return_value="NETWORK_ABSENT"):
        network._remove_fixed_network(teardown, object(), object(), object())
    check(removals == expected_removals, "ready-only/absent teardown issued wrong rm")

# Recovery of a successful direct table deletion reconstructs its real empty
# stdout and never substitutes the cached pre-delete NFT_TABLE observation.
removal_body = {"action": network.Action.NFT_REMOVE_ATOMIC.value, "target": READY_ID}
removal_outcome = {"command_id": network.Action.NFT_REMOVE_ATOMIC.value,
    "command_serial": 17, "outcome": "exited", "status": 0,
    "stdout_length": 0, "stdout_sha256": hashlib.sha256(b"").hexdigest()}
removal_raw = []
removal_history = [("NETWORK_EFFECT_INTENT_V2", removal_body),
                   ("COMMAND_OUTCOME_V2", removal_outcome)]
removal_context = type("Context", (), {"lifecycle_phase": "TASK_STOPPED"})()
with patch.object(operation, "_network_history", return_value=removal_history), \
     patch.object(operation, "_command_context", return_value=removal_context), \
     patch.object(network, "_resume_observer_chunk"), \
     patch.object(network, "_sources", return_value=[]), \
     patch.object(network, "_retained_observation_raw", side_effect=AssertionError("cached NFT_TABLE used")), \
     patch.object(network, "_record_observation", side_effect=lambda _j, _a, raw, _s: removal_raw.append(raw)), \
     patch.object(network, "_settled_effects", return_value=[]), \
     patch.object(network, "_observed_identity", return_value=EMPTY), \
     patch.object(network, "_effect_body", return_value={"identity": EMPTY}), \
     patch.object(network, "_record_effect"):
    network._resume_effect(object(), object(), object(), object())
check(removal_raw == [b""], "successful deletion recovery did not reconstruct empty stdout")

# Cleanup intent is durable before fallible work. If poisoning cannot append
# UNCERTAIN, both failures survive and neither this owner nor a reopen can progress.
class CleanupRecord:
    def __init__(self, kind, body=None):
        self.record_type = kind
        self.body = body

# The real poison helper invalidates memory before opening/appending. An append
# failure cannot restore that authority.
poison_owner = object(); poison_set = set(); poison_append = OSError("append failed")
poison_records = [CleanupRecord("GENESIS", {"operation_token": "a" * 64})]
def poison_reload(authority, preserve):
    check(authority in poison_set and preserve is None, "uncertainty opened before poison")
    return object(), poison_records, "exact"
def poison_write(authority, kind, body):
    check(authority in poison_set and kind == "UNCERTAIN" and
          body["operation_token"] == "a" * 64, "uncertainty append was not poison-bound")
    raise poison_append
try:
    journal_model.poison_uncertain(poison_owner, "incomplete", operation.UNCERTAIN_REASONS,
        poison_set, poison_reload, poison_write, lambda _records: "TASK_STOPPED",
        lambda value: value or (_ for _ in ()).throw(operation.OperationError()))
except OSError as error:
    check(error is poison_append and poison_owner in poison_set, "append failure cleared poison")
else:
    raise AssertionError("uncertainty append failure accepted")

class CleanupFaultJournal:
    def __init__(self, durable, target=None, settlement=None, poisoned=False):
        self.durable = durable
        self.target = target
        self.settlement = settlement
        self.poisoned = poisoned
    def durable_phase(self):
        return "SHARE_ABSENT" if self.target == "firewall" else "TASK_STOPPED"
    def begin_network_cleanup(self, observed_target):
        check(observed_target == self.target, "wrong cleanup intent target")
        marker = {"network": "NETWORK_CLEANUP_INTENT_V2",
                  "firewall": "FIREWALL_CLEANUP_INTENT_V2"}[observed_target]
        self.durable.append(CleanupRecord(marker))
    def record_uncertain(self, reason):
        check(reason == "incomplete", "wrong cleanup poison")
        self.poisoned = True
        raise self.settlement
    def advance(self, kind):
        if self.poisoned:
            raise operation.OperationError()
        active = journal_model.active_cleanup(self.durable)
        try: journal_model.cleanup_step(active, kind, "TASK_STOPPED")
        except ValueError as error: raise operation.OperationError() from error

for target, cleanup, marker in (
        ("network", network._remove_fixed_network, "NETWORK_CLEANUP_INTENT_V2"),
        ("firewall", network._remove_fixed_firewall, "FIREWALL_CLEANUP_INTENT_V2")):
    durable = []
    primary = RuntimeError(target + " cleanup failed")
    settlement = OSError(target + " uncertainty append failed")
    owner = CleanupFaultJournal(durable, target, settlement)
    def fail_after_intent(*_args):
        check(journal_model.active_cleanup(durable) == marker,
              "cleanup began before durable intent")
        raise primary
    with patch.object(network.nft_owner, "require_active"), \
         patch.object(operation, "_durable_phase", return_value="SHARE_ABSENT"), \
         patch.object(network, "_baselines", side_effect=fail_after_intent):
        try:
            cleanup(owner, object(), object(), object())
        except network.NetworkCleanupError as error:
            check(error.errors == (primary, settlement), "cleanup errors were not preserved")
        else:
            raise AssertionError("cleanup/uncertainty double failure accepted")
    reject(lambda: owner.advance("NETWORK_SNAPSHOT_V2"), "poisoned owner remained usable")
    reopened = CleanupFaultJournal(durable)
    reject(lambda: reopened.advance("TASK_ABSENT"), "cleanup-only reopen advanced lifecycle")
    reject(lambda: reopened.advance("FINAL_BASELINES"), "cleanup-only reopen advanced retirement")

# V1 completion retains its historical settlement meaning. V2 completion does
# not retire cleanup authority until the explicit, post-confirmation ack.
legacy = [CleanupRecord("NETWORK_CLEANUP_INTENT_V1"), CleanupRecord("NETWORK_ABSENT")]
check(journal_model.active_cleanup(legacy) is None, "historical cleanup meaning changed")
unfinished = [CleanupRecord("NETWORK_CLEANUP_INTENT_V2"), CleanupRecord("NETWORK_ABSENT")]
check(journal_model.active_cleanup(unfinished) == "NETWORK_CLEANUP_INTENT_V2",
      "completion retired unacknowledged cleanup")
reject(lambda: journal_model.cleanup_step(journal_model.active_cleanup(unfinished),
    "TASK_ABSENT", "NETWORK_ABSENT"), "unacknowledged cleanup advanced after reopen")
reject(lambda: journal_model.cleanup_step(journal_model.active_cleanup(unfinished),
    "FINAL_BASELINES", "NETWORK_ABSENT"), "unacknowledged cleanup retired after reopen")

class SettlementJournal:
    def __init__(self, target):
        self.target = target
        self.intent = {"network": "NETWORK_CLEANUP_INTENT_V2",
                       "firewall": "FIREWALL_CLEANUP_INTENT_V2"}[target]
        self.phase = {"network": "NETWORK_ABSENT", "firewall": "FIREWALL_ABSENT"}[target]
        self.ack = {"network": "NETWORK_CLEANUP_SETTLED_V2",
                    "firewall": "FIREWALL_CLEANUP_SETTLED_V2"}[target]
        self.durable = [CleanupRecord(self.intent)]
    def complete(self, error=None):
        self.durable.append(CleanupRecord(self.phase))
        if error is not None: raise error
    def durable_phase(self): return self.durable[-1].record_type
    def settle_network_cleanup(self, target):
        check(target == self.target and self.durable[-1].record_type == self.phase,
              "cleanup ack preceded verified completion")
        self.durable.append(CleanupRecord(self.ack))

# Normal completion and a durable completion that reports failure both append
# the ack. A reopened owner then sees no cleanup-only residue.
for target in ("network", "firewall"):
    for reported_failure in (False, True):
        settled = SettlementJournal(target)
        settlement_error = OSError("post-fsync completion failure")
        def complete(*_args): settled.complete(settlement_error if reported_failure else None)
        with patch.object(operation, "_settle_network_phase", side_effect=complete), \
             patch.object(operation, "_durable_phase", return_value=settled.phase):
            network._settle_cleanup(settled, target, settled.phase)
        check([row.record_type for row in settled.durable][-2:] == [settled.phase, settled.ack],
              "successful cleanup omitted explicit ack")
        active = journal_model.active_cleanup(settled.durable)
        check(active is None, "acked cleanup remained active after reopen")
        next_kind = "TASK_ABSENT" if target == "network" else "INPUT_REMOVED"
        check(journal_model.cleanup_step(active, next_kind, settled.phase) == (None, False),
              "acked cleanup blocked normal reopen")

# Re-entry at either already-durable terminal cleanup snapshot cannot report
# success while leaving persistent ownership ACTIVE.
settlement_calls = []
class DurableSnapshotJournal:
    def durable_phase(self): return "FIREWALL_ABSENT"
    def begin_network_cleanup(self, _target): pass
    def network_history(self):
        return (("FIREWALL_CLEANUP_INTENT_V2", {}),
                ("FIREWALL_CLEANUP_SETTLED_V2", {}))
class PendingFirewallAckJournal(DurableSnapshotJournal):
    def network_history(self):
        return (("FIREWALL_CLEANUP_INTENT_V2", {}),)
check(not network._network_cleanup_active(DurableSnapshotJournal()),
      "acknowledged firewall cleanup remained active")
check(network._network_cleanup_active(PendingFirewallAckJournal()),
      "unacknowledged firewall cleanup was lost")
firewall_snapshot = {"snapshot_kind": "firewall-restored"}
with patch.object(network.nft_owner, "require_active"), \
     patch.object(operation, "_durable_phase", return_value="FIREWALL_ABSENT"), \
     patch.object(network, "_baselines", return_value=(BASELINES, [firewall_snapshot])), \
     patch.object(network.nft_owner, "settle_free", side_effect=lambda _j, target: settlement_calls.append(target)):
    check(network._remove_fixed_firewall(DurableSnapshotJournal(), object(), object(), object()) is firewall_snapshot,
          "durable firewall snapshot did not return")
network_snapshot = {"snapshot_kind": "network-absent"}
with patch.object(network.nft_owner, "require_active"), \
     patch.object(network, "_baselines", return_value=(BASELINES, [network_snapshot])), \
     patch.object(operation, "_durable_phase", return_value="NETWORK_ABSENT"), \
     patch.object(network, "_network_cleanup_active", return_value=False), \
     patch.object(network.nft_owner, "settle_free", side_effect=lambda _j, target: settlement_calls.append(target)):
    check(network._abort_fixed_setup(DurableSnapshotJournal(), object(), object(), object()) is network_snapshot,
          "durable setup-abort snapshot did not return")
check(settlement_calls == ["firewall", "network"], "durable cleanup omitted or repeated FREE settlement")

# If completion is durably appended, its reported failure cannot erase intent
# when confirmation and the subsequent UNCERTAIN append both fail. This is the
# exact ambiguous-durability reopen cut.
for target, cleanup, phase, snapshot_kind in (
        ("network", network._remove_fixed_network, "NETWORK_ABSENT", "network-absent"),
        ("firewall", network._remove_fixed_firewall, "FIREWALL_ABSENT", "firewall-restored")):
    durable = []; completion_error = OSError(target + " completion report failed")
    confirmation_error = OSError(target + " completion confirmation failed")
    uncertainty_error = OSError(target + " uncertainty append failed")
    class AmbiguousJournal(CleanupFaultJournal):
        def __init__(self):
            super().__init__(durable, target, uncertainty_error)
            self.direct_phase_reads = 0
        def durable_phase(self):
            self.direct_phase_reads += 1
            if target == "firewall" and self.direct_phase_reads == 1:
                return "SHARE_ABSENT"
            raise confirmation_error
    ambiguous = AmbiguousJournal()
    def complete_then_report_failure(_journal, observed_phase):
        check(observed_phase == phase, "wrong ambiguous completion phase")
        durable.append(CleanupRecord(phase)); raise completion_error
    phase_reads = []
    def ambiguous_phase(_journal):
        phase_reads.append(1)
        if target == "firewall" and len(phase_reads) == 1:
            return "SHARE_ABSENT"
        raise confirmation_error
    with patch.object(network.nft_owner, "require_active"), \
         patch.object(network, "_baselines", return_value=(BASELINES, [{"snapshot_kind": snapshot_kind}])), \
         patch.object(network, "_resume_effect"), \
         patch.object(operation, "_settle_network_phase", side_effect=complete_then_report_failure), \
         patch.object(operation, "_durable_phase", side_effect=ambiguous_phase):
        try: cleanup(ambiguous, object(), object(), object())
        except network.NetworkCleanupError as error:
            primary, poison = error.errors
            check(isinstance(primary, network.NetworkCleanupError) and
                  primary.errors == (completion_error, confirmation_error) and poison is uncertainty_error,
                  "ambiguous completion failures were not preserved")
        else: raise AssertionError("completion/confirmation/uncertainty failure accepted")
    check(journal_model.active_cleanup(durable) == ambiguous.durable[0].record_type,
          "ambiguous durable completion erased cleanup intent")
    reopened = CleanupFaultJournal(durable)
    reject(lambda: reopened.advance("TASK_ABSENT"), "ambiguous reopen advanced lifecycle")
    reject(lambda: reopened.advance("FINAL_BASELINES"), "ambiguous reopen retired")

class PlaceholderStat:
    st_dev = 7; st_ino = 9; st_mode = 0o100600; st_uid = 0; st_gid = 0
    st_nlink = 1; st_size = 0; st_mtime_ns = 11; st_ctime_ns = 12
placeholder = PlaceholderStat(); full_placeholder = network._placeholder_identity(placeholder)
with patch.object(network.os, "stat", return_value=placeholder):
    check(network._exact_unmounted_placeholder(
        b"1 0 0:1 / / rw - tmpfs tmpfs rw\n", "c42n0123456789", full_placeholder),
        "exact durable original placeholder rejected")

source = network.tc_observer_command(network.Action.TC_QDISC, tap)
check(process._internally_fixed(process.FixedCommand(
    network.Action.TC_QDISC, "tc", "/usr/sbin/tc",
    tuple(NETNS["name"] if item == network.NETNS else item
          for item in ("/usr/sbin/tc", *source.argv_tail)),
    b"", 10_000_000_000, output_grammar="json")), "retained tc command rejected")
ip_source = process._FIXED_COMMANDS[network.Action.IP_NS_LINKS]
check(process._internally_fixed(process.FixedCommand(
    ip_source.command_id, ip_source.executable_role, ip_source.executable_path,
    tuple(NETNS["name"] if item == network.NETNS else item for item in ip_source.argv),
    ip_source.stdin, ip_source.duration_ns, ip_source.stdout_limit, ip_source.stderr_limit,
    ip_source.output_grammar, ip_source.inherited_fds)), "bound netns command rejected")

check("RETRY" not in network.Recovery.__members__, "retry disposition remains")
check({item.value for item in network._MUTATIONS} == journal_model.MUTATIONS,
      "journal mutation closure omitted a fixed mutation")
check({item.value for item in operation.actions.CLEANUP_NETWORK_COMMANDS} & journal_model.MUTATIONS
      == set(journal_model.REMOVALS), "cleanup network allowlist is not exact removals plus observers")
check(not ({item.value for item in operation.actions.CLEANUP_NETWORK_COMMANDS} - set(journal_model.REMOVALS))
      & journal_model.MUTATIONS, "cleanup observer allowlist contains setup")
check(operation.actions.CLEANUP_COMMANDS == operation.actions.CLEANUP_NETWORK_COMMANDS | operation.actions.CLEANUP_RUNTIME_COMMANDS
      and not {operation.actions.CommandId.IP_LINK_ADD, operation.actions.CommandId.IP_LINK_MOVE,
               operation.actions.CommandId.IP_PEER_RENAME, operation.actions.CommandId.NFT_INSTALL}
      & operation.actions.CLEANUP_COMMANDS, "legacy setup mutation admitted after expiry")
source_text = (ROOT / "deploy/aws-feasibility/remote/completion_kata_network.py").read_text()
for required in ("runtime_difference(before, after)", "NETWORK_EFFECT_INTENT_V2",
                 "_resume_effect(journal", "fresh != baselines"):
    check(required in source_text, f"missing production invariant: {required}")
for forbidden in ("subprocess", "os.system", "shell=True", "iptables", "masquerade", "SNAT", "DNAT"):
    check(forbidden not in source_text, f"forbidden production route: {forbidden}")
print("completion Kata fixed production network lifecycle matrix passed")

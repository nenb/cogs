"""Strict durable replay model for the fixed ADR0099 network facet."""
import hashlib
import re
from types import MappingProxyType
POLICY_VERSION = "cogs.stage2-kata-network-policy/b1-owner-3"
BASELINES = (
    "host_links", "host_addresses", "host_routes4", "host_routes6",
    "netns_names", "nft_ruleset", "mountinfo",
)
SNAPSHOTS = ("baseline", "ready", "discovered", "runtime", "network-absent", "firewall-restored")
SETUP = (
    "IP_NETNS_ADD", "IP_VETH_ADD_ATOMIC", "NFT_INSTALL_OWNED",
    "IP_HOST_ADDRESS_ADD", "IP_HOST_ADDRGEN_NONE",
    "IP_PEER_ADDRGEN_NONE", "IP_LOOPBACK_UP", "IP_GUEST_ADDRESS_ADD",
    "IP_HOST_LINK_UP", "IP_GUEST_LINK_UP",
)
REMOVALS = ("IP_NETNS_REMOVE", "NFT_REMOVE_ATOMIC")
EFFECTS = frozenset(SETUP + REMOVALS)
RECORDS = frozenset({"NETWORK_EFFECT_INTENT_V2", "NETWORK_EFFECT_OBSERVED_V2",
                     "NETWORK_EFFECT_SETTLED_V2"})
OUTPUT_RECORD = "NETWORK_OBSERVER_CHUNK_V2"
ORIGINAL_PLACEHOLDER_RECORD = "NETWORK_ORIGINAL_PLACEHOLDER_V2"
CREATED_NSFS_RECORD = "NETWORK_CREATED_NSFS_V2"
QUARANTINE_RECORDS = frozenset({"NETWORK_QUARANTINE_INTENT_V2", "NETWORK_QUARANTINE_PLACEHOLDER_V2",
    "NETWORK_QUARANTINE_MOVED_V2", "NETWORK_QUARANTINE_SETTLED_V2",
    "NETWORK_DETACH_INTENT_V2", "NETWORK_DETACHED_V2"})
ALL_RECORDS = RECORDS | QUARANTINE_RECORDS | {OUTPUT_RECORD, ORIGINAL_PLACEHOLDER_RECORD, CREATED_NSFS_RECORD}
CLEANUP_INTENTS = MappingProxyType({
    # V1 completion records historically settled their intent. V2 keeps the
    # intent active until a separately appended acknowledgement.
    "NETWORK_CLEANUP_INTENT_V1": ({"TASK_STOPPED", "OWNERSHIP_OBSERVED"}, "NETWORK_ABSENT", None),
    "FIREWALL_CLEANUP_INTENT_V1": ({"SHARE_ABSENT"}, "FIREWALL_ABSENT", None),
    "NETWORK_CLEANUP_INTENT_V2": ({"TASK_STOPPED", "OWNERSHIP_OBSERVED"}, "NETWORK_ABSENT", "NETWORK_CLEANUP_SETTLED_V2"),
    "FIREWALL_CLEANUP_INTENT_V2": ({"SHARE_ABSENT"}, "FIREWALL_ABSENT", "FIREWALL_CLEANUP_SETTLED_V2"),
})
CLEANUP_SETTLED = frozenset(value[2] for value in CLEANUP_INTENTS.values() if value[2] is not None)
_CLEANUP_TARGETS = MappingProxyType({
    "network": ("NETWORK_CLEANUP_INTENT_V1", "NETWORK_CLEANUP_INTENT_V2"),
    "firewall": ("FIREWALL_CLEANUP_INTENT_V1", "FIREWALL_CLEANUP_INTENT_V2"),
})
_CLEANUP_RECORDS = frozenset({
    "COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2", "COMMAND_OUTPUT_V3", "COMMAND_OUTCOME_V2",
    "NETWORK_SNAPSHOT_V2", "UNCERTAIN", *ALL_RECORDS,
})
MAX_CHUNK_BYTES = 1024
_BASELINE_TRACE = ("IP_ALL_LINKS", "IP_ALL_ADDRESSES", "IP_ALL_ROUTES4",
                   "IP_ALL_ROUTES6", "IP_NETNS_LIST", "NFT_RULESET")
_PARTIAL = ("IP_ALL_LINKS", "IP_NS_LINKS")
def _setup_effect_trace(index, action):
    if index == 0: return _PARTIAL
    if index < 2: return (action, *_PARTIAL)
    if index < len(SETUP) - 1: return (action, *_PARTIAL, "NFT_TABLE")
    return (action, "IP_HOST_LINKS", "IP_HOST_ADDRESSES", "IP_HOST_ROUTES4",
            "IP_HOST_ROUTES6", "IP_NS_LINKS", "IP_NS_ADDRESSES", "IP_NS_ROUTES4",
            "IP_NS_ROUTES6", "NFT_TABLE", "TC_QDISC", "TC_INGRESS_FILTER")
_EFFECT_COMMAND_TRACES = {action: _setup_effect_trace(index, action)
                          for index, action in enumerate(SETUP)}
_EFFECT_COMMAND_TRACES.update({
    "IP_NETNS_REMOVE": ("IP_ALL_LINKS", "NFT_TABLE"),
    "NFT_REMOVE_ATOMIC": ("NFT_REMOVE_ATOMIC", "IP_ALL_LINKS"),
})
EFFECT_COMMAND_TRACES = MappingProxyType(_EFFECT_COMMAND_TRACES)
_SETUP_TRACE = tuple(item for action in SETUP for item in _EFFECT_COMMAND_TRACES[action])
_OWNED = ("IP_HOST_LINKS", "IP_HOST_ADDRESSES", "IP_HOST_ROUTES4",
          "IP_HOST_ROUTES6", "IP_NS_LINKS", "IP_NS_ADDRESSES", "IP_NS_ROUTES4",
          "IP_NS_ROUTES6", "NFT_TABLE")
_RUNTIME_NET = ("IP_HOST_LINKS", "IP_NS_LINKS", "IP_HOST_ADDRESSES",
                "IP_NS_ADDRESSES", "IP_HOST_ROUTES4", "IP_HOST_ROUTES6",
                "IP_NS_ROUTES4", "IP_NS_ROUTES6", "TC_QDISC", "TC_QDISC",
                "TC_INGRESS_FILTER", "TC_INGRESS_FILTER", "NFT_TABLE")
_READY_NET = (*_OWNED, "TC_QDISC", "TC_INGRESS_FILTER")
_DISCOVERED_NET = ("IP_HOST_LINKS", "IP_NS_LINKS", "IP_HOST_ADDRESSES", "IP_NS_ADDRESSES")
SUCCESS_PHASE_TRACES = MappingProxyType({
    "FS_SETTLED": _BASELINE_TRACE, "BASELINES_CAPTURED": _SETUP_TRACE,
    "TASK_STOPPED": (*_RUNTIME_NET, "IP_ALL_LINKS", "NFT_TABLE", *_BASELINE_TRACE),
    "SHARE_ABSENT": ("NFT_RULESET", "NFT_TABLE", "NFT_REMOVE_ATOMIC", "IP_ALL_LINKS", *_BASELINE_TRACE),
    "OWNERSHIP_OBSERVED": _BASELINE_TRACE,
})
SUCCESS_PHASE_TRACE_VARIANTS = MappingProxyType({
    "OWNERSHIP_OBSERVED": (SUCCESS_PHASE_TRACES["OWNERSHIP_OBSERVED"],
        (*_READY_NET, "IP_ALL_LINKS", "NFT_TABLE", *_BASELINE_TRACE),
        (*_DISCOVERED_NET, "IP_ALL_LINKS", "NFT_TABLE", *_BASELINE_TRACE),
        ("IP_ALL_LINKS", "NFT_TABLE", *_BASELINE_TRACE)),
    "TASK_STOPPED": (SUCCESS_PHASE_TRACES["TASK_STOPPED"],
        (*_READY_NET, "IP_ALL_LINKS", "NFT_TABLE", *_BASELINE_TRACE),
        (*_DISCOVERED_NET, "IP_ALL_LINKS", "NFT_TABLE", *_BASELINE_TRACE),
        ("IP_HOST_ROUTES4", "IP_ALL_LINKS", "NFT_TABLE", *_BASELINE_TRACE),
        _BASELINE_TRACE),
    "SHARE_ABSENT": (SUCCESS_PHASE_TRACES["SHARE_ABSENT"], ("NFT_RULESET", *_BASELINE_TRACE)),
})
LIFECYCLE_REQUIREMENTS = MappingProxyType({
    "BASELINES_CAPTURED": "FS_SETTLED", "NETWORK_READY": "BASELINES_CAPTURED",
    "NETWORK_ABSENT": "TASK_STOPPED", "FIREWALL_ABSENT": "SHARE_ABSENT",
})
del _BASELINE_TRACE, _PARTIAL, _SETUP_TRACE, _OWNED, _RUNTIME_NET, _READY_NET, _DISCOVERED_NET, _setup_effect_trace, _EFFECT_COMMAND_TRACES
HEX = frozenset("0123456789abcdef")
def _fail(value):
    if not value: raise ValueError("network journal")
def active_cleanup(records, require=_fail):
    active = None
    for record in records:
        kind = record.record_type
        if kind in CLEANUP_INTENTS:
            require(active is None); active = kind
        elif active is not None:
            _starts, completion, acknowledgement = CLEANUP_INTENTS[active]
            if kind == acknowledgement or acknowledgement is None and kind == completion:
                active = None
    return active

def cleanup_step(active, kind, phase, require=_fail):
    if active is not None:
        _starts, completion, acknowledgement = CLEANUP_INTENTS[active]
        require(kind in _CLEANUP_RECORDS or kind in {completion, acknowledgement})
        if kind == acknowledgement:
            require(phase == completion); return None, True
        return (None if acknowledgement is None and kind == completion else active), False
    if kind in CLEANUP_INTENTS:
        require(phase in CLEANUP_INTENTS[kind][0]); return kind, True
    require(kind not in CLEANUP_SETTLED)
    return None, False

def begin_cleanup(authority, target, reload, write, legal, require):
    kinds = _CLEANUP_TARGETS.get(target); require(kinds is not None)
    _io, records, status = reload(authority); require(status == "exact" and records)
    active = active_cleanup(records, require)
    if active is not None:
        require(active in kinds); return
    kind = kinds[-1]
    require(legal(records) in CLEANUP_INTENTS[kind][0])
    write(authority, kind, {"operation_token": records[0].body["operation_token"]})

def settle_cleanup(authority, target, reload, write, legal, require):
    kinds = _CLEANUP_TARGETS.get(target); require(kinds is not None)
    _io, records, status = reload(authority); require(status == "exact" and records)
    active = active_cleanup(records, require); phase = legal(records)
    if active is None:
        latest = next((row.record_type for row in reversed(records)
                       if row.record_type in CLEANUP_INTENTS), None)
        legacy = kinds[0]
        require(latest == legacy and phase == CLEANUP_INTENTS[legacy][1]); return
    require(active == kinds[-1])
    _starts, completion, acknowledgement = CLEANUP_INTENTS[active]
    require(phase == completion and acknowledgement is not None)
    write(authority, acknowledgement, {"operation_token": records[0].body["operation_token"]})

def poison_uncertain(authority, reason, reasons, poisoned, reload, write, legal, require):
    require(type(reason) is str and reason in reasons); poisoned.add(authority)
    _io, records, status = reload(authority, None); require(status == "exact" and records)
    if legal(records) != "UNCERTAIN":
        write(authority, "UNCERTAIN", {
            "operation_token": records[0].body["operation_token"], "reason": reason})

def _hex(value, zero=False):
    _fail(type(value) is str and len(value) == 64 and set(value) <= HEX and (zero or value != "0" * 64))
def _keys(value, names):
    _fail(type(value) is dict and set(value) == set(names))
_RECORD_FIELDS = MappingProxyType({
    ORIGINAL_PLACEHOLDER_RECORD: ("original_name", "placeholder"),
    CREATED_NSFS_RECORD: ("helper_pid", "identity"),
    OUTPUT_RECORD: ("observation_serial", "source_id", "command_serial", "chunk_index",
                    "chunk_count", "output_sha256", "output_length", "raw_hex"),
    "NETWORK_SNAPSHOT_V2": ("snapshot_kind", "baselines", "sources", "identity"),
})
def validate(kind, body, canonical):
    """Validate the cryptographic envelope; ``advance`` owns semantic validation."""
    common = ("operation_token", "policy_version")
    if kind in QUARANTINE_RECORDS:
        fields = ("original_name", "quarantine_name", "target", "placeholder", "preserved")
    elif kind in RECORDS:
        fields = ("effect_serial", "action", "prior_proof_sha256", "target")
        if kind != "NETWORK_EFFECT_INTENT_V2": fields += ("disposition", "sources", "identity")
    else:
        _fail(kind in _RECORD_FIELDS); fields = _RECORD_FIELDS[kind]
    proof = kind != "NETWORK_EFFECT_INTENT_V2"; names = common + fields + (("proof_sha256",) if proof else ())
    _keys(body, names); _hex(body["operation_token"]); _fail(body["policy_version"] == POLICY_VERSION)
    if proof:
        _hex(body["proof_sha256"])
        _fail(hashlib.sha256(canonical({key: value for key, value in body.items()
              if key != "proof_sha256"})).hexdigest() == body["proof_sha256"])
def _source_outputs(state, sources):
    selected = []
    for source in sources:
        _fail(source["observation_serial"] < len(state["observations"]))
        observed = state["observations"][source["observation_serial"]]
        _fail(all(source[name] == observed[name] for name in source)); selected.append(observed)
    return selected
def advance(state, kind, body, phase):
    state = {**state, "snapshots": list(state["snapshots"]), "effects": list(state["effects"]),
             "effect_commands": list(state["effect_commands"]), "effect_replays": list(state["effect_replays"]),
             "replay_serials": list(state["replay_serials"]), "observations": list(state["observations"])}
    if kind == OUTPUT_RECORD:
        pending = state["output_pending"]
        if body["chunk_index"] == 0:
            _fail(pending is None and body["observation_serial"] == len(state["observations"]))
            pending = {"base": {name: body[name] for name in ("observation_serial", "source_id",
                "command_serial", "chunk_count", "output_sha256", "output_length")}, "chunks": []}
        _fail(pending is not None and body["chunk_index"] == len(pending["chunks"]) and
              all(body[name] == pending["base"][name] for name in pending["base"]))
        pending["chunks"].append(bytes.fromhex(body["raw_hex"])); state["output_pending"] = pending
        if len(pending["chunks"]) == pending["base"]["chunk_count"]:
            raw = b"".join(pending["chunks"]); base = pending["base"]
            _fail(len(raw) == base["output_length"] and hashlib.sha256(raw).hexdigest() == base["output_sha256"])
            if base["command_serial"] is not None:
                matches = [row for row in state["outcomes"] if row["command_serial"] == base["command_serial"]]
                _fail(len(matches) == 1 and matches[0]["command_id"] == base["source_id"].split(":", 1)[0] and
                      matches[0]["stdout_sha256"] == base["output_sha256"] and matches[0]["stdout_length"] == len(raw) and
                      matches[0]["outcome"] == "exited" and matches[0]["status"] == 0 and not matches[0]["uncertain"] and
                      matches[0]["stderr_length"] == 0 and not matches[0]["stdout_truncated"] and not matches[0]["stderr_truncated"])
            state["observations"].append({**base, "raw": raw}); state["output_pending"] = None
        return state
    _fail(state["output_pending"] is None)
    if kind in {ORIGINAL_PLACEHOLDER_RECORD, CREATED_NSFS_RECORD}:
        _fail(state["pending"] is not None and state["pending"][1]["action"] == "IP_NETNS_ADD" and
              state["current"]["netns"] is None)
        if kind == CREATED_NSFS_RECORD:
            identity = body["identity"]
            _fail(type(body["helper_pid"]) is int and body["helper_pid"] > 0)
            _keys(identity, ("mount_id", "device", "inode_device", "inode"))
            _fail(all(type(identity[name]) is int and identity[name] > 0
                      for name in ("mount_id", "inode_device", "inode")) and
                  type(identity["device"]) is str and re.fullmatch(r"[0-9]+:[0-9]+", identity["device"]))
        state["original_placeholder" if kind == ORIGINAL_PLACEHOLDER_RECORD else "created_nsfs"] = body
        return state
    if kind in QUARANTINE_RECORDS:
        stage = state["quarantine"]
        core = {name: body[name] for name in ("operation_token", "policy_version", "original_name",
                                               "quarantine_name", "target")}
        if kind == "NETWORK_QUARANTINE_INTENT_V2":
            _fail(stage is None and body["target"] == state["current"] and body["placeholder"] is None and body["preserved"] is None)
        elif kind == "NETWORK_QUARANTINE_PLACEHOLDER_V2":
            _fail(stage is not None and stage[0] in {"NETWORK_QUARANTINE_INTENT_V2", "NETWORK_QUARANTINE_PLACEHOLDER_V2"} and
                  {name: stage[1][name] for name in core} == core and body["placeholder"] is not None and body["preserved"] is None)
        elif kind == "NETWORK_QUARANTINE_MOVED_V2":
            _fail(stage is not None and stage[0] == "NETWORK_QUARANTINE_PLACEHOLDER_V2" and
                  {name: stage[1][name] for name in core} == core and body["placeholder"] == stage[1]["placeholder"] and body["preserved"] is not None)
        elif kind == "NETWORK_QUARANTINE_SETTLED_V2":
            _fail(stage is not None and stage[0] == "NETWORK_QUARANTINE_MOVED_V2" and
                  {name: stage[1][name] for name in (*core, "placeholder")} == {**core, "placeholder": body["placeholder"]} and
                  body["preserved"] is not None)
        elif kind == "NETWORK_DETACH_INTENT_V2":
            _fail(stage is not None and stage[0] == "NETWORK_QUARANTINE_SETTLED_V2" and stage[1] ==
                  {**core, "placeholder": body["placeholder"], "preserved": body["preserved"]})
        else:
            _fail(stage is not None and stage[0] == "NETWORK_DETACH_INTENT_V2" and
                  {name: stage[1][name] for name in (*core, "placeholder")} == {**core, "placeholder": body["placeholder"]} and
                  body["preserved"] is not None)
        state["quarantine"] = (kind, {**core, "placeholder": body["placeholder"], "preserved": body["preserved"]}); return state
    if kind == "NETWORK_SNAPSHOT_V2":
        outputs = _source_outputs(state, body["sources"])
        import completion_kata_network as network
        derived, derived_baselines = network._derive_journal_identity(
            body["snapshot_kind"], None, outputs, state["current"],
            state["snapshots"][0]["baselines"] if state["snapshots"] else None)
        _fail(all(body["identity"][name] == derived[name] for name in derived if name != "state_sha256"))
        if body["snapshot_kind"] == "baseline": _fail(body["baselines"] == derived_baselines)
        allowed_phase = {"baseline": {"ROOTFS_LEASED", "FS_SETTLED"},
            "ready": {"BASELINES_CAPTURED"}, "discovered": {"NETWORK_READY", "RUNTIME_READY"},
            "runtime": {"NETWORK_READY", "RUNTIME_READY"},
            "network-absent": {"TASK_STOPPED", "OWNERSHIP_OBSERVED"},
            "firewall-restored": {"SHARE_ABSENT"}}
        _fail(phase in allowed_phase[body["snapshot_kind"]])
        expected = {None: "baseline", "baseline": "ready", "ready": "discovered",
                    "discovered": "runtime", "runtime": "network-absent",
                    "network-absent": "firewall-restored"}
        previous = state["snapshots"][-1]["snapshot_kind"] if state["snapshots"] else None
        # Runtime is optional on failed launch.
        allowed = {expected[previous]}
        if previous in {"ready", "discovered"}: allowed.add("network-absent")
        _fail(body["snapshot_kind"] in allowed)
        if state["snapshots"]: _fail(body["baselines"] == state["snapshots"][0]["baselines"])
        if body["snapshot_kind"] == "ready":
            _fail(state["effects"] and body["identity"] == state["effects"][-1]["identity"])
        if body["snapshot_kind"] == "discovered":
            ready = state["snapshots"][-1]["identity"]
            for name in ("netns", "host_link", "peer_link", "nft", "tc", "routes_sha256"):
                _fail(body["identity"][name] == ready[name])
        if body["snapshot_kind"] == "runtime":
            discovered = state["snapshots"][-1]["identity"]
            for name in ("netns", "host_link", "peer_link", "nft", "tap", "addresses_sha256"):
                _fail(body["identity"][name] == discovered[name])
        if body["snapshot_kind"] == "network-absent":
            source = next(row for row in reversed(state["snapshots"]) if row["snapshot_kind"] in {"ready", "discovered", "runtime"})
            _fail(body["identity"]["nft"] == source["identity"]["nft"])
        state["snapshots"].append(body); state["current"] = body["identity"]; return state
    if kind == "NETWORK_EFFECT_INTENT_V2":
        phases = ({"BASELINES_CAPTURED"} if body["action"] in SETUP else
                  {"BASELINES_CAPTURED", "NETWORK_READY", "READINESS_REVOKED", "OWNERSHIP_OBSERVED", "TASK_STOPPED"}
                  if body["action"] == "IP_NETNS_REMOVE" else
                  {"BASELINES_CAPTURED", "NETWORK_READY", "SHARE_ABSENT"})
        _fail(phase in phases)
        _fail(state["pending"] is None and body["effect_serial"] == len(state["effects"]))
        _fail(body["target"] == state["current"])
        _fail(body["prior_proof_sha256"] == (state["effects"][-1]["proof_sha256"] if state["effects"] else "0" * 64))
        actions = [row["action"] for row in state["effects"]]
        _fail(body["action"] not in actions)
        if body["action"] in SETUP:
            _fail(actions == list(SETUP[:len(actions)]) and body["action"] == SETUP[len(actions)])
        state["pending"] = (kind, body, len(state["outcomes"])); state["effect_commands"] = []; state["effect_replays"] = []
        return state
    _fail(state["pending"] is not None)
    pending_kind, pending, outcome_start = state["pending"]
    for name in ("operation_token", "policy_version", "effect_serial", "action", "prior_proof_sha256", "target"):
        _fail(body[name] == pending[name])
    if kind == "NETWORK_EFFECT_OBSERVED_V2":
        _fail(pending_kind == "NETWORK_EFFECT_INTENT_V2")
        commands = tuple(value for index, value in enumerate(state["effect_commands"]) if index not in state["effect_replays"])
        _fail(commands == EFFECT_COMMAND_TRACES[pending["action"]])
        outputs = _source_outputs(state, body["sources"])
        import completion_kata_network as network
        scope = "ready" if body["action"] == SETUP[-1] else "effect"
        derived, _unused = network._derive_journal_identity(scope, body["action"], outputs, pending["target"])
        _fail(all(body["identity"][name] == derived[name] for name in derived if name != "state_sha256"))
        if body["action"] == "IP_NETNS_ADD":
            created = state["created_nsfs"]["identity"] if state["created_nsfs"] else None
            _fail(created is not None and all(body["identity"]["netns"][name] == created[name]
                  for name in ("device", "inode_device", "inode")))
        matches = [row for row in state["outcomes"][outcome_start:]
                   if row["command_id"] == pending["action"]]
        _fail((not matches if pending["action"] in {"IP_NETNS_ADD", "IP_NETNS_REMOVE"} else
              len(matches) == 1 and matches[0]["outcome"] == "exited" and
              matches[0]["status"] == 0 and not matches[0]["uncertain"]))
        state["pending"] = (kind, body, outcome_start); return state
    _fail(pending_kind == "NETWORK_EFFECT_OBSERVED_V2" and body == pending)
    state["effects"].append(body); state["pending"] = None; state["current"] = body["identity"]; return state
def command_outcome(state, body):
    state = {**state, "outcomes": list(state["outcomes"])}
    state["outcomes"].append(body)
    return state
def initial():
    return {"snapshots": [], "effects": [], "pending": None, "outcomes": [],
            "effect_commands": [], "effect_replays": [], "replay_serials": [], "current": None,
            "observations": [], "output_pending": None, "quarantine": None,
            "original_placeholder": None, "created_nsfs": None}
def successful_phase_trace(records, index, phase, state, settled):
    intents = [item for item in records[:index]
               if item.record_type == "COMMAND_INTENT_V2" and item.body["lifecycle_phase"] == phase]
    replay_indices = {position for position, item in enumerate(intents)
                      if item.body["command_serial"] in state["replay_serials"]}
    successful_trace((item.body["command_id"] for item in intents), phase, replay_indices)
    _fail(all(settled(records, item, index) for item in intents))

def successful_trace(command_ids, phase, replay_indices=()):
    observed = tuple(value for index, value in enumerate(command_ids) if index not in replay_indices)
    variants = SUCCESS_PHASE_TRACE_VARIANTS.get(phase)
    valid = (observed in variants if variants is not None else
             phase in SUCCESS_PHASE_TRACES and observed == SUCCESS_PHASE_TRACES[phase])
    if not valid:
        raise ValueError(f"network journal trace:{phase}:{observed!r}")
def command_intent(intent, state):
    import completion_kata_network as network
    command_id = intent["command_id"]
    if command_id == "CTR_RUN":
        import completion_kata_runtime as runtime
        runtime._validate_ctr_launch_intent(intent); return state
    if state["output_pending"] is not None:
        _fail(command_id == state["output_pending"]["base"]["source_id"].split(":", 1)[0])
    suffix = intent["operation_token"][:10]; expected_netns, expected_table, expected_host = "c42n" + suffix, "c42t" + suffix, "c42h" + suffix
    expected_command_netns = "c42q" + suffix if command_id == "IP_NETNS_REMOVE" else expected_netns
    _fail(all(not re.fullmatch(r"c42[qn][0-9a-f]{10}", item) or item == expected_command_netns for item in intent["argv"] if type(item) is str))
    _fail(all(not re.fullmatch(r"c42t[0-9a-f]{10}", item) or item == expected_table for item in intent["argv"] if type(item) is str))
    _fail(all(not re.fullmatch(r"c42h[0-9a-f]{10}", item) or item == expected_host for item in intent["argv"] if type(item) is str))
    stdin = bytes.fromhex(intent["stdin_hex"])
    _fail(re.search(rb"c42t[0-9a-f]{10}", stdin) in (None,) or expected_table.encode() in stdin)
    if command_id not in {"TC_QDISC", "TC_INGRESS_FILTER"}:
        source = network.command(network.Action(command_id)); role = ("nft" if source.tool_contract.startswith("libnftables") else "ip"); path = "/usr/sbin/" + role
        tail = tuple(expected_table if item == network.TABLE else expected_command_netns if item == network.NETNS else expected_host if item == network.HOST_IF else item for item in source.argv_tail)
        expected_argv = [path, *tail]
        expected_stdin = source.stdin.replace(network.TABLE.encode(), expected_table.encode()).replace(network.HOST_IF.encode(), expected_host.encode())
        if command_id == "NFT_REMOVE_ATOMIC":
            target = state["pending"][1]["target"]["nft"] if state["pending"] else None
            _fail(target is not None)
            expected_stdin = expected_stdin.replace(network.TABLE_HANDLE.encode(), str(target["table_handle"]).encode())
        _fail(intent["executable_role"] == role and intent["executable_path"] == path and intent["argv"] == expected_argv
              and stdin == expected_stdin and intent["deadline_class"] == "network" and intent["duration_ns"] == 10_000_000_000 and intent["output_grammar"] == "json"
              and intent["stdout_limit"] == intent["stderr_limit"] == 65536 and intent["inherited_fds"] == [])
    if command_id == "IP_NETNS_REMOVE":
        target = state["pending"][1]["target"]["netns"] if state["pending"] else None
        _fail(target is not None and target["name"] == expected_netns and expected_command_netns in intent["argv"])
    state = {**state, "effect_commands": list(state["effect_commands"]),
             "effect_replays": list(state["effect_replays"]), "replay_serials": list(state["replay_serials"])}
    replay = state["output_pending"] is not None
    if replay: state["replay_serials"].append(intent["command_serial"])
    if state["pending"] is not None and state["pending"][0] == "NETWORK_EFFECT_INTENT_V2":
        action = state["pending"][1]["action"]; canonical = EFFECT_COMMAND_TRACES[action]
        stripped = tuple(value for index, value in enumerate(state["effect_commands"]) if index not in state["effect_replays"])
        if replay:
            _fail(state["effect_commands"] and command_id == state["effect_commands"][-1] and stripped == canonical[:len(stripped)])
            state["effect_replays"].append(len(state["effect_commands"]))
        else: _fail(len(stripped) < len(canonical) and command_id == canonical[len(stripped)])
        state["effect_commands"].append(command_id)
    elif command_id in EFFECTS:
        _fail(False)
    if command_id in {"TC_QDISC", "TC_INGRESS_FILTER"}:
        tc_intent(intent, state)
    return state
def tc_intent(intent, state):
    _fail(intent["command_id"] in {"TC_QDISC", "TC_INGRESS_FILTER"} and state["snapshots"])
    identity = state["snapshots"][-1]["identity"]
    if identity.get("peer_link") is None and state["effects"]:
        identity = state["effects"][-1]["identity"]
    name = intent["argv"][-1] if intent["command_id"] == "TC_QDISC" else intent["argv"][-2]
    allowed = {row["ifname"] for row in (identity.get("peer_link"), identity.get("tap")) if row is not None}
    tail = (["qdisc", "show", "dev", name] if intent["command_id"] == "TC_QDISC" else
            ["filter", "show", "dev", name, "ingress"])
    _fail(name in allowed and intent["argv"] ==
          ["/usr/sbin/tc", "-n", identity["netns"]["name"], "-j", *tail])
    _fail(intent["executable_role"] == "tc" and intent["executable_path"] == "/usr/sbin/tc"
          and intent["stdin_hex"] == "" and intent["stdin_length"] == 0
          and intent["deadline_class"] == "network" and intent["duration_ns"] == 10_000_000_000
          and intent["output_grammar"] == "json" and intent["stdout_limit"] == 65536
          and intent["stderr_limit"] == 65536 and intent["inherited_fds"] == [])

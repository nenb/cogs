"""Closed, fixed Stage 2 Kata network-state contracts.

Only fixed command construction and bounded offline snapshot parsing are present.
The JSON shapes below are qualification candidates, not qualified host-tool
fixtures. Production stays unavailable until exact pinned Linux/Kata/iproute2/
nftables fixtures and command permits are supplied; any fixture drift stops.
"""
from dataclasses import dataclass
from enum import Enum
import ipaddress
import json
import os
import re
import completion_kata_actions as actions
import completion_kata_process as process
import completion_kata_qualification as qualification

NETNS = "cogs-stage2-ssh"
NETNS_PATH = "/run/netns/cogs-stage2-ssh"
HOST_IF = "c42h0"
TEMP_IF = "c42g0"
GUEST_IF = "eth0"
HOST_MAC = "02:00:00:42:00:01"
GUEST_MAC = "02:00:00:42:00:02"
HOST_CIDR = "192.0.2.1/30"
GUEST_CIDR = "192.0.2.2/30"
TABLE = "cogs_stage2_ssh_v1"
MAX_JSON = 262_144
MAX_ITEMS = 64
MAX_DEPTH = 16
MAX_MOUNTINFO_BYTES = 4_194_304
MAX_MOUNTINFO_LINES = 4096
QUALIFICATION_CANDIDATE = "UNQUALIFIED_FIXED_HOST_TOOL_OUTPUT_CANDIDATE_V1"
IP_CONTRACT = "iproute2-json-qualification-candidate-v1"
TC_CONTRACT = "tc-json-qualification-candidate-v1"
NFT_CONTRACT = "libnftables-json-qualification-candidate-v1"

NFT_TRANSACTION = b'''add table inet cogs_stage2_ssh_v1
add chain inet cogs_stage2_ssh_v1 input { type filter hook input priority filter; policy accept; }
add chain inet cogs_stage2_ssh_v1 output { type filter hook output priority filter; policy accept; }
add chain inet cogs_stage2_ssh_v1 forward { type filter hook forward priority filter; policy accept; }
add rule inet cogs_stage2_ssh_v1 output oifname "c42h0" ip saddr 192.0.2.1 ip daddr 192.0.2.2 tcp dport 22 ct state new,established accept
add rule inet cogs_stage2_ssh_v1 output oifname "c42h0" drop
add rule inet cogs_stage2_ssh_v1 input iifname "c42h0" ip saddr 192.0.2.2 ip daddr 192.0.2.1 tcp sport 22 ct state established accept
add rule inet cogs_stage2_ssh_v1 input iifname "c42h0" drop
add rule inet cogs_stage2_ssh_v1 forward iifname "c42h0" drop
add rule inet cogs_stage2_ssh_v1 forward oifname "c42h0" drop
'''


class NetworkError(Exception):
    """A command request, snapshot, or ownership transition was not exact."""


Action = actions.CommandId
TcObservation = actions.CommandId


@dataclass(frozen=True)
class Command:
    action: Action | TcObservation
    tool_contract: str
    argv_tail: tuple
    stdin: bytes = b""


_MUTATIONS = {
    Action.NETNS_ADD: (IP_CONTRACT, ("netns", "add", NETNS), b""),
    Action.LINK_ADD: (IP_CONTRACT, ("link", "add", "name", HOST_IF, "address", HOST_MAC, "type", "veth", "peer", "name", TEMP_IF, "address", GUEST_MAC), b""),
    Action.LINK_MOVE: (IP_CONTRACT, ("link", "set", "dev", TEMP_IF, "netns", NETNS), b""),
    Action.HOST_ADDRESS_ADD: (IP_CONTRACT, ("address", "add", HOST_CIDR, "dev", HOST_IF), b""),
    Action.HOST_LINK_UP: (IP_CONTRACT, ("link", "set", "dev", HOST_IF, "up"), b""),
    Action.PEER_RENAME: (IP_CONTRACT, ("-n", NETNS, "link", "set", "dev", TEMP_IF, "name", GUEST_IF), b""),
    Action.PEER_ADDRGEN_NONE: (IP_CONTRACT, ("-n", NETNS, "link", "set", "dev", GUEST_IF, "addrgenmode", "none"), b""),
    Action.LOOPBACK_UP: (IP_CONTRACT, ("-n", NETNS, "link", "set", "dev", "lo", "up"), b""),
    Action.GUEST_ADDRESS_ADD: (IP_CONTRACT, ("-n", NETNS, "address", "add", GUEST_CIDR, "dev", GUEST_IF), b""),
    Action.GUEST_LINK_UP: (IP_CONTRACT, ("-n", NETNS, "link", "set", "dev", GUEST_IF, "up"), b""),
    Action.NFT_INSTALL: (NFT_CONTRACT, ("-f", "-"), NFT_TRANSACTION),
    Action.NFT_REMOVE: (NFT_CONTRACT, ("delete", "table", "inet", TABLE), b""),
    Action.NETNS_REMOVE: (IP_CONTRACT, ("netns", "delete", NETNS), b""),
}
_OBSERVERS = {
    Action.HOST_LINKS: (IP_CONTRACT, ("-j", "-d", "link", "show", "dev", HOST_IF), b""),
    Action.HOST_ADDRESSES: (IP_CONTRACT, ("-j", "address", "show", "dev", HOST_IF), b""),
    Action.HOST_ROUTES4: (IP_CONTRACT, ("-4", "-j", "route", "show", "table", "all", "dev", HOST_IF), b""),
    Action.HOST_ROUTES6: (IP_CONTRACT, ("-6", "-j", "route", "show", "table", "all", "dev", HOST_IF), b""),
    Action.NS_LINKS: (IP_CONTRACT, ("-n", NETNS, "-j", "-d", "link", "show"), b""),
    Action.NS_ADDRESSES: (IP_CONTRACT, ("-n", NETNS, "-j", "address", "show"), b""),
    Action.NS_ROUTES4: (IP_CONTRACT, ("-n", NETNS, "-4", "-j", "route", "show", "table", "all"), b""),
    Action.NS_ROUTES6: (IP_CONTRACT, ("-n", NETNS, "-6", "-j", "route", "show", "table", "all"), b""),
    Action.NFT_TABLE: (NFT_CONTRACT, ("-j", "list", "table", "inet", TABLE), b""),
}


def command(action):
    """Return one fixed command shape, never a generic executable or argv."""
    if type(action) is not Action:
        raise NetworkError("typed action required")
    row = (_MUTATIONS | _OBSERVERS).get(action)
    if row is None:
        raise NetworkError("unknown action")
    return Command(action, *row)


def mutation_snapshots_for_tests():
    return tuple(command(action) for action in _MUTATIONS)


def observer_snapshots_for_tests():
    return tuple(command(action) for action in _OBSERVERS)


class _Pairs(list):
    pass


def _load(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON or b"\x00" in raw:
        raise NetworkError("bounded JSON bytes required")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_Pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))

        def convert(item, depth=0):
            if depth > MAX_DEPTH:
                raise NetworkError("JSON depth")
            if type(item) is _Pairs:
                if len(item) > MAX_ITEMS:
                    raise NetworkError("JSON object bound")
                result = {}
                for key, child in item:
                    if type(key) is not str or key in result:
                        raise NetworkError("duplicate JSON key")
                    result[key] = convert(child, depth + 1)
                return result
            if type(item) is list:
                if len(item) > MAX_ITEMS:
                    raise NetworkError("JSON array bound")
                return [convert(child, depth + 1) for child in item]
            if item is None or type(item) in (str, int, bool):
                return item
            raise NetworkError("JSON scalar")
        return convert(value)
    except NetworkError:
        raise
    except BaseException as error:
        raise NetworkError("invalid JSON") from error


def _keys(value, required, optional=()):
    if (type(value) is not dict or not set(required) <= set(value)
            or not set(value) <= set(required) | set(optional)):
        raise NetworkError("unexpected JSON shape")


def _uint(value, allow_zero=False):
    low = 0 if allow_zero else 1
    if type(value) is not int or value < low or value > (1 << 31) - 1:
        raise NetworkError("invalid identity number")
    return value


def _strings(value, allowed):
    if type(value) is not list or len(value) != len(set(value)) or set(value) != set(allowed):
        raise NetworkError("flags drift")


@dataclass(frozen=True)
class Link:
    ifindex: int
    ifname: str
    kind: str
    mac: str
    peer_ifindex: int | None
    flags: tuple
    operstate: str
    up: bool
    qdisc: str
    addrgenmode: str | int | None


_LINK_OPTIONAL = ("mtu", "min_mtu", "max_mtu", "group", "txqlen", "linkmode", "master",
                  "promiscuity", "num_tx_queues", "num_rx_queues", "gso_max_size",
                  "gso_max_segs", "tso_max_size", "tso_max_segs", "link_netnsid", "link",
                  "broadcast", "altnames")
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")


def _parse_link_row(row, runtime=False):
    _keys(row, ("ifindex", "ifname", "flags", "operstate", "link_type", "address", "qdisc"),
          _LINK_OPTIONAL + ("link_index", "addrgenmode", "linkinfo"))
    name, mac = row["ifname"], row["address"]
    if type(name) is not str or not name or len(name) > 15 or type(mac) is not str or not _MAC.fullmatch(mac):
        raise NetworkError("link name or address")
    if type(row["flags"]) is not list or len(row["flags"]) != len(set(row["flags"])):
        raise NetworkError("link flags")
    kind = row["link_type"]
    info = row.get("linkinfo")
    if info is not None:
        _keys(info, ("info_kind",), ("info_data", "info_slave_kind", "info_slave_data"))
        kind = info["info_kind"]
        if runtime and kind == "tap":
            raise NetworkError("synthetic TAP kind")
        if runtime and kind == "tun":
            data = info.get("info_data")
            _keys(data, ("type", "pi", "vnet_hdr", "multi_queue", "persist"))
            if data != {"type": "tap", "pi": False, "vnet_hdr": True,
                        "multi_queue": False, "persist": False}:
                raise NetworkError("TAP detail drift")
            kind = "tap"
    if type(kind) is not str or type(row["qdisc"]) is not str or type(row["operstate"]) is not str:
        raise NetworkError("link scalar")
    peer = row.get("link_index")
    if peer is not None:
        peer = _uint(peer)
    return Link(_uint(row["ifindex"]), name, kind, mac, peer, tuple(row["flags"]), row["operstate"],
                "UP" in row["flags"] and row["operstate"] in ("UP", "UNKNOWN"),
                row["qdisc"], row.get("addrgenmode"))


def parse_links(raw, namespace):
    value = _load(raw)
    if (type(value) is not list or type(namespace) is not bool or (namespace and not value)):
        raise NetworkError("link list")
    result = tuple(_parse_link_row(row) for row in value)
    if len({item.ifname for item in result}) != len(result) or len({item.ifindex for item in result}) != len(result):
        raise NetworkError("duplicate interface")
    by_name = {item.ifname: item for item in result}
    if namespace:
        if set(by_name) != {"lo", GUEST_IF}:
            raise NetworkError("namespace interface inventory")
        lo, guest = by_name["lo"], by_name[GUEST_IF]
        if (lo.kind != "loopback" or lo.mac != "00:00:00:00:00:00" or not lo.up
                or set(lo.flags) != {"LOOPBACK", "UP", "LOWER_UP"} or lo.operstate != "UNKNOWN"
                or lo.qdisc != "noqueue" or lo.peer_ifindex is not None):
            raise NetworkError("loopback drift")
        if (guest.kind != "veth" or guest.mac != GUEST_MAC or guest.peer_ifindex is None
                or not guest.up or set(guest.flags) != {"BROADCAST", "MULTICAST", "UP", "LOWER_UP"}
                or guest.operstate != "UP" or guest.qdisc != "noqueue"
                or guest.addrgenmode not in ("none", 1)):
            raise NetworkError("guest veth drift")
    else:
        if set(by_name) not in (set(), {HOST_IF}):
            raise NetworkError("host interface inventory")
        if result:
            host = result[0]
            valid_state = ((set(host.flags) == {"BROADCAST", "MULTICAST"} and host.operstate == "DOWN" and not host.up)
                           or (set(host.flags) == {"BROADCAST", "MULTICAST", "UP", "LOWER_UP"}
                               and host.operstate == "UP" and host.up))
            if (host.kind != "veth" or host.mac != HOST_MAC or host.peer_ifindex is None
                    or host.qdisc != "noqueue" or not valid_state):
                raise NetworkError("host veth drift")
    return result


def validate_peer_pair(host_links, namespace_links):
    if type(host_links) is not tuple or type(namespace_links) is not tuple or len(host_links) != 1:
        raise NetworkError("complete peer snapshots required")
    host = host_links[0]
    guests = {item.ifname: item for item in namespace_links}
    guest = guests.get(GUEST_IF)
    if (host.ifname != HOST_IF or guest is None or host.peer_ifindex != guest.ifindex
            or guest.peer_ifindex != host.ifindex or host.mac != HOST_MAC or guest.mac != GUEST_MAC):
        raise NetworkError("veth peer identity mismatch")
    return host, guest


@dataclass(frozen=True)
class Address:
    ifindex: int
    ifname: str
    family: str
    local: str
    prefixlen: int
    scope: str


def parse_addresses(raw, namespace, links):
    value = _load(raw)
    if type(value) is not list or type(namespace) is not bool or type(links) is not tuple:
        raise NetworkError("address list")
    bound = {item.ifname: item.ifindex for item in links}
    result, seen = [], set()
    for link in value:
        _keys(link, ("ifindex", "ifname", "addr_info"),
              _LINK_OPTIONAL + ("flags", "operstate", "link_type", "address", "qdisc"))
        name, index = link["ifname"], _uint(link["ifindex"])
        if name not in bound or bound[name] != index or name in seen or type(link["addr_info"]) is not list:
            raise NetworkError("address/link cross-binding")
        seen.add(name)
        for row in link["addr_info"]:
            _keys(row, ("family", "local", "prefixlen", "scope"),
                  ("label", "broadcast", "valid_life_time", "preferred_life_time", "dynamic", "noprefixroute"))
            if type(row["prefixlen"]) is not int:
                raise NetworkError("address prefix")
            result.append(Address(index, name, row["family"], row["local"], row["prefixlen"], row["scope"]))
    identities = {(item.ifname, item.family, item.local, item.prefixlen, item.scope) for item in result}
    if len(identities) != len(result):
        raise NetworkError("duplicate address")
    expected = ({("lo", "inet", "127.0.0.1", 8, "host"),
                 ("lo", "inet6", "::1", 128, "host"),
                 (GUEST_IF, "inet", "192.0.2.2", 30, "global")} if namespace else
                ({(HOST_IF, "inet", "192.0.2.1", 30, "global")} if links else set()))
    if identities != expected or seen != set(bound):
        raise NetworkError("address inventory drift")
    return tuple(result)


@dataclass(frozen=True)
class Route:
    family: int
    route_type: str
    dst: str
    dev: str
    table: str
    protocol: str
    scope: str | None
    source: str | None
    metric: int | None
    flags: tuple
    pref: str | None


_HOST_ROUTE4_CANDIDATE = {
    ("unicast", "192.0.2.0/30", HOST_IF, "main", "kernel", "link", "192.0.2.1", None, (), None),
    ("local", "192.0.2.1", HOST_IF, "local", "kernel", "host", "192.0.2.1", None, (), None),
    ("broadcast", "192.0.2.3", HOST_IF, "local", "kernel", "link", "192.0.2.1", None, (), None),
}
_ROUTE4_CANDIDATE = {
    ("unicast", "192.0.2.0/30", GUEST_IF, "main", "kernel", "link", "192.0.2.2", None, (), None),
    ("local", "127.0.0.0/8", "lo", "local", "kernel", "host", "127.0.0.1", None, (), None),
    ("local", "127.0.0.1", "lo", "local", "kernel", "host", "127.0.0.1", None, (), None),
    ("broadcast", "127.255.255.255", "lo", "local", "kernel", "link", "127.0.0.1", None, (), None),
    ("local", "192.0.2.2", GUEST_IF, "local", "kernel", "host", "192.0.2.2", None, (), None),
    ("broadcast", "192.0.2.3", GUEST_IF, "local", "kernel", "link", "192.0.2.2", None, (), None),
}
_ROUTE6_CANDIDATE = {
    ("local", "::1", "lo", "local", "kernel", None, None, 0, (), "medium"),
}


def parse_routes(raw, family, links):
    value = _load(raw)
    if type(value) is not list or family not in (4, 6) or type(links) is not tuple:
        raise NetworkError("route list")
    bound = {item.ifname for item in links}
    if bound not in ({HOST_IF}, {"lo", GUEST_IF}):
        raise NetworkError("complete route link binding")
    result = []
    for row in value:
        _keys(row, ("dst", "dev", "protocol"),
              ("table", "prefsrc", "src", "type", "scope", "metric", "flags", "pref"))
        if row["dst"] == "default" or row["dev"] not in bound or row["protocol"] != "kernel":
            raise NetworkError("default, foreign, or misbound route")
        try:
            network = ipaddress.ip_network(row["dst"], strict=False)
        except (TypeError, ValueError) as error:
            raise NetworkError("route prefix") from error
        if network.version != family:
            raise NetworkError("route family")
        flags = row.get("flags", [])
        if type(flags) is not list or any(type(item) is not str for item in flags):
            raise NetworkError("route flags")
        result.append(Route(family, row.get("type", "unicast"), row["dst"], row["dev"],
                            str(row.get("table", "main")), row["protocol"], row.get("scope"),
                            row.get("prefsrc", row.get("src")), row.get("metric"), tuple(flags), row.get("pref")))
    actual = {(item.route_type, item.dst, item.dev, item.table, item.protocol, item.scope,
               item.source, item.metric, item.flags, item.pref) for item in result}
    if bound == {HOST_IF}:
        expected = _HOST_ROUTE4_CANDIDATE if family == 4 else set()
    else:
        expected = _ROUTE4_CANDIDATE if family == 4 else _ROUTE6_CANDIDATE
    if len(actual) != len(result) or actual != expected:
        raise NetworkError("complete route inventory drift")
    return tuple(result)


def _nft_match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def _nft_meta(key):
    return {"meta": {"key": key}}


def _nft_payload(protocol, field):
    return {"payload": {"protocol": protocol, "field": field}}


def _nft_verdict(name):
    return {name: None}


_NFT_RULES = {
    "input": (
        (_nft_match(_nft_meta("iifname"), HOST_IF), _nft_match(_nft_payload("ip", "saddr"), "192.0.2.2"),
         _nft_match(_nft_payload("ip", "daddr"), "192.0.2.1"), _nft_match(_nft_payload("tcp", "sport"), 22),
         _nft_match({"ct": {"key": "state"}}, {"set": ["established"]}, "in"), _nft_verdict("accept")),
        (_nft_match(_nft_meta("iifname"), HOST_IF), _nft_verdict("drop")),
    ),
    "output": (
        (_nft_match(_nft_meta("oifname"), HOST_IF), _nft_match(_nft_payload("ip", "saddr"), "192.0.2.1"),
         _nft_match(_nft_payload("ip", "daddr"), "192.0.2.2"), _nft_match(_nft_payload("tcp", "dport"), 22),
         _nft_match({"ct": {"key": "state"}}, {"set": ["established", "new"]}, "in"), _nft_verdict("accept")),
        (_nft_match(_nft_meta("oifname"), HOST_IF), _nft_verdict("drop")),
    ),
    "forward": (
        (_nft_match(_nft_meta("iifname"), HOST_IF), _nft_verdict("drop")),
        (_nft_match(_nft_meta("oifname"), HOST_IF), _nft_verdict("drop")),
    ),
}
_NFT_ROW_ORDER = ("table", "chain", "rule", "rule", "chain", "rule", "rule", "chain", "rule", "rule")


def _normalize_nft_expr(expressions):
    normalized = json.loads(json.dumps(expressions))
    for expression in normalized:
        match = expression.get("match") if type(expression) is dict else None
        right = match.get("right") if type(match) is dict else None
        if match and match.get("left") == {"ct": {"key": "state"}}:
            _keys(right, ("set",))
            if type(right["set"]) is not list or not right["set"] or any(type(item) is not str for item in right["set"]):
                raise NetworkError("nft set expression")
            right["set"].sort()
    return normalized


@dataclass(frozen=True)
class NftKernelIdentity:
    table_handle: int
    chain_handles: tuple
    rule_handles: tuple


@dataclass(frozen=True)
class NftSnapshot:
    content: dict
    identity: NftKernelIdentity


def parse_nft_snapshot(raw):
    """Validate candidate list-table order/content and retain every handle."""
    value = _load(raw)
    _keys(value, ("nftables",))
    rows = value["nftables"]
    if type(rows) is not list or len(rows) != len(_NFT_ROW_ORDER) + 1:
        raise NetworkError("nft list")
    meta = rows[0]
    _keys(meta, ("metainfo",))
    _keys(meta["metainfo"], ("json_schema_version",), ("release_name", "version"))
    if meta["metainfo"]["json_schema_version"] != 1:
        raise NetworkError("nft metainfo drift")
    normalized, chain_handles, rule_handles = [], [], []
    table_handle = None
    active_chain = None
    rule_ordinals = {name: 0 for name in _NFT_RULES}
    for expected_kind, row in zip(_NFT_ROW_ORDER, rows[1:]):
        if type(row) is not dict or tuple(row) != (expected_kind,):
            raise NetworkError("nft output ordering drift")
        body = row[expected_kind]
        if type(body) is not dict:
            raise NetworkError("nft body")
        handle = _uint(body.get("handle"))
        content = {key: child for key, child in body.items() if key != "handle"}
        if expected_kind == "table":
            if content != {"family": "inet", "name": TABLE}:
                raise NetworkError("nft table drift")
            table_handle = handle
        elif expected_kind == "chain":
            _keys(content, ("family", "table", "name", "type", "hook", "prio", "policy"))
            active_chain = content["name"]
            if (active_chain not in _NFT_RULES or content != {"family": "inet", "table": TABLE,
                    "name": active_chain, "type": "filter", "hook": active_chain, "prio": 0, "policy": "accept"}
                    or active_chain in {name for name, _handle in chain_handles}):
                raise NetworkError("nft chain drift")
            chain_handles.append((active_chain, handle))
        else:
            _keys(content, ("family", "table", "chain", "expr"))
            chain = content["chain"]
            if chain != active_chain or content["family"] != "inet" or content["table"] != TABLE:
                raise NetworkError("nft rule ownership drift")
            expr = tuple(_normalize_nft_expr(content["expr"]))
            ordinal = rule_ordinals[chain]
            if ordinal >= len(_NFT_RULES[chain]) or expr != _NFT_RULES[chain][ordinal]:
                raise NetworkError("nft normalized content drift")
            rule_ordinals[chain] += 1
            content["expr"] = list(expr)
            rule_handles.append((chain, ordinal, handle))
        normalized.append({expected_kind: content})
    if ([name for name, _handle in chain_handles] != ["input", "output", "forward"]
            or any(value != 2 for value in rule_ordinals.values())
            or len({handle for _name, handle in chain_handles}) != 3
            or len({handle for _chain, _ordinal, handle in rule_handles}) != 6
            or len({handle for _name, handle in chain_handles}
                   | {handle for _chain, _ordinal, handle in rule_handles}) != 9):
        raise NetworkError("nft inventory identity drift")
    return NftSnapshot({"nftables": normalized},
                       NftKernelIdentity(table_handle, tuple(chain_handles), tuple(rule_handles)))


@dataclass(frozen=True)
class NetnsStat:
    device: int
    inode: int


@dataclass(frozen=True)
class NetnsIdentity:
    mount_id: int
    parent_id: int
    device: str
    root: str
    mount_point: str
    mount_options: tuple
    optional_fields: tuple
    fs_type: str
    source: str
    super_options: tuple
    inode_device: int
    inode: int


_OCTAL = re.compile(r"\\([0-7]{3})")
_DEVICE = re.compile(r"[0-9]+:[0-9]+")


def parse_netns_identity(raw, stat):
    if (type(raw) is not bytes or not raw or len(raw) > MAX_MOUNTINFO_BYTES
            or type(stat) is not NetnsStat or stat.device <= 0 or stat.inode <= 0):
        raise NetworkError("mountinfo bound or stat proof")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise NetworkError("mountinfo encoding") from error
    if not lines or len(lines) > MAX_MOUNTINFO_LINES:
        raise NetworkError("complete mountinfo count")

    def unescape(text):
        return _OCTAL.sub(lambda match: chr(int(match.group(1), 8)), text)

    found = []
    for line in lines:
        fields = line.split(" ")
        if fields.count("-") != 1:
            raise NetworkError("mountinfo separator")
        separator = fields.index("-")
        if separator < 6 or len(fields) != separator + 4 or not _DEVICE.fullmatch(fields[2]):
            raise NetworkError("mountinfo shape")
        try:
            mount_id, parent_id = _uint(int(fields[0])), _uint(int(fields[1]))
        except (ValueError, NetworkError) as error:
            raise NetworkError("mountinfo identity") from error
        root, point = unescape(fields[3]), unescape(fields[4])
        mount_options = tuple(fields[5].split(","))
        optional = tuple(fields[6:separator])
        fs_type, source = fields[separator + 1], unescape(fields[separator + 2])
        super_options = tuple(fields[separator + 3].split(","))
        if (not mount_options or not super_options or "" in mount_options + super_options
                or len(set(mount_options)) != len(mount_options)
                or len(set(super_options)) != len(super_options)):
            raise NetworkError("mountinfo options")
        if point == NETNS_PATH:
            found.append(NetnsIdentity(mount_id, parent_id, fields[2], root, point,
                                       mount_options, optional, fs_type, source, super_options,
                                       stat.device, stat.inode))
    expected_device = f"{os.major(stat.device)}:{os.minor(stat.device)}"
    if len(found) != 1:
        raise NetworkError("netns mount cardinality")
    identity = found[0]
    if (identity.device != expected_device or identity.root != f"net:[{stat.inode}]"
            or identity.mount_options != ("rw",) or identity.optional_fields
            or identity.fs_type != "nsfs" or identity.source != "nsfs"
            or identity.super_options != ("rw",)):
        raise NetworkError("netns mount/stat identity drift")
    return identity


@dataclass(frozen=True)
class TcQdisc:
    dev_ifindex: int
    dev_name: str
    kind: str
    handle: str
    parent: str | None
    root: bool
    refcnt: int | None


@dataclass(frozen=True)
class TcAction:
    index: int
    kind: str
    control: str
    eaction: str
    direction: str
    to_ifindex: int
    to_name: str
    ref: int
    bind: int


@dataclass(frozen=True)
class TcFilterTable:
    dev_ifindex: int
    dev_name: str
    hook: str
    protocol: str
    pref: int
    kind: str
    chain: int
    handle: str
    divisor: int


@dataclass(frozen=True)
class TcFilter:
    dev_ifindex: int
    dev_name: str
    hook: str
    protocol: str
    pref: int
    kind: str
    chain: int
    handle: str
    order: int
    action: TcAction


def _tc_endpoint(link):
    if type(link) is not Link or link.ifname in ("", "lo", HOST_IF) or link.kind not in ("veth", "tap"):
        raise NetworkError("retained tc endpoint required")
    return link


def tc_observer_command(observation, endpoint):
    endpoint = _tc_endpoint(endpoint)
    if type(observation) is not TcObservation:
        raise NetworkError("typed tc observation required")
    if observation is TcObservation.QDISC:
        tail = ("-n", NETNS, "-j", "qdisc", "show", "dev", endpoint.ifname)
    else:
        tail = ("-n", NETNS, "-j", "filter", "show", "dev", endpoint.ifname, "ingress")
    return Command(observation, TC_CONTRACT, tail)


def tc_observer_commands(veth, tap):
    veth, tap = _tc_endpoint(veth), _tc_endpoint(tap)
    if veth.kind != "veth" or veth.ifname != GUEST_IF or tap.kind != "tap" or veth.ifindex == tap.ifindex:
        raise NetworkError("exact veth/TAP endpoints required")
    return tuple(tc_observer_command(kind, endpoint)
                 for endpoint in (veth, tap)
                 for kind in (TcObservation.QDISC, TcObservation.INGRESS_FILTER))


def parse_tc_qdiscs(raw, endpoint):
    endpoint = _tc_endpoint(endpoint)
    value = _load(raw)
    if type(value) is not list or len(value) not in (1, 2):
        raise NetworkError("tc qdisc list")
    result = []
    for index, row in enumerate(value):
        if index == 0:
            _keys(row, ("kind", "handle", "root", "refcnt", "options"))
            if (row["kind"], row["handle"], row["root"], row["options"]) != ("noqueue", "0:", True, {}):
                raise NetworkError("tc root qdisc drift")
            if row["refcnt"] != 2:
                raise NetworkError("tc root qdisc refcnt drift")
            result.append(TcQdisc(endpoint.ifindex, endpoint.ifname, "noqueue", "0:", None,
                                  True, 2))
        else:
            _keys(row, ("kind", "handle", "parent"))
            if row != {"kind": "ingress", "handle": "ffff:", "parent": "ffff:fff1"}:
                raise NetworkError("tc ingress qdisc drift")
            result.append(TcQdisc(endpoint.ifindex, endpoint.ifname, "ingress", "ffff:",
                                  "ffff:fff1", False, None))
    return tuple(result)


def parse_tc_filters(raw, source, target):
    source, target = _tc_endpoint(source), _tc_endpoint(target)
    if source == target:
        raise NetworkError("tc self redirect")
    value = _load(raw)
    if type(value) is not list or len(value) != 2:
        raise NetworkError("tc filter list")
    table_row, row = value
    for item in value:
        _keys(item, ("protocol", "pref", "kind", "chain", "options"))
        if (item["protocol"], item["pref"], item["kind"], item["chain"]) != ("all", 49152, "u32", 0):
            raise NetworkError("tc filter header drift")
    if table_row["options"] != {"fh": "800:", "ht_divisor": 1}:
        raise NetworkError("tc u32 table drift")
    table = TcFilterTable(source.ifindex, source.ifname, "ingress", "all", 49152,
                          "u32", 0, "800:", 1)
    options = row["options"]
    _keys(options, ("fh", "ht", "order", "key_ht", "bkt", "terminal", "not_in_hw", "match", "actions"))
    expected = {"fh": "800::800", "ht": "800:", "order": 2048, "key_ht": 32768,
                "bkt": "0", "terminal": True, "not_in_hw": True,
                "match": {"value": "00000000", "mask": "00000000", "off": 0}}
    if {key: options[key] for key in expected} != expected or type(options["actions"]) is not list or len(options["actions"]) != 1:
        raise NetworkError("tc u32 match drift")
    action = options["actions"][0]
    _keys(action, ("order", "kind", "control_action", "index", "ref", "bind", "eaction", "direction", "to_dev"))
    _keys(action["control_action"], ("type",))
    if (action["order"], action["kind"], action["control_action"]["type"], action["ref"], action["bind"],
            action["eaction"], action["direction"], action["to_dev"]) != (
            1, "mirred", "pipe", 1, 1, "redirect", "egress", target.ifname):
        raise NetworkError("tc action binding drift")
    parsed_action = TcAction(_uint(action["index"]), "mirred", "pipe", "redirect", "egress",
                             target.ifindex, target.ifname, _uint(action["ref"]), _uint(action["bind"]))
    return (table, TcFilter(source.ifindex, source.ifname, "ingress", "all", 49152, "u32", 0,
                            "800::800", 2048, parsed_action))


def parse_runtime_links(raw):
    value = _load(raw)
    if type(value) is not list:
        raise NetworkError("runtime link list")
    result = tuple(_parse_link_row(row, True) for row in value)
    if len({item.ifname for item in result}) != len(result) or len({item.ifindex for item in result}) != len(result):
        raise NetworkError("duplicate runtime link identity")
    taps = [item for item in result if item.kind == "tap"]
    retained = tuple(item for item in result if item.kind != "tap")
    if len(taps) > 1:
        raise NetworkError("runtime TAP cardinality")
    # Re-validate the retained namespace inventory, including exact flags/state.
    retained_json_names = {item.ifname for item in retained}
    if retained_json_names != {"lo", GUEST_IF}:
        raise NetworkError("runtime namespace link inventory")
    lo, guest = ({item.ifname: item for item in retained}[name] for name in ("lo", GUEST_IF))
    if (lo.kind != "loopback" or set(lo.flags) != {"LOOPBACK", "UP", "LOWER_UP"}
            or lo.operstate != "UNKNOWN" or not lo.up or lo.qdisc != "noqueue"):
        raise NetworkError("runtime loopback drift")
    if (guest.kind != "veth" or set(guest.flags) != {"BROADCAST", "MULTICAST", "UP", "LOWER_UP"}
            or guest.operstate != "UP" or not guest.up or guest.qdisc != "noqueue"):
        raise NetworkError("runtime veth drift")
    for tap in taps:
        if (tap.peer_ifindex is not None or not tap.up or tap.qdisc != "noqueue"
                or tap.mac == "00:00:00:00:00:00" or tap.operstate != "UP"
                or set(tap.flags) != {"BROADCAST", "MULTICAST", "UP", "LOWER_UP"}):
            raise NetworkError("runtime TAP identity drift")
    return result


@dataclass(frozen=True)
class RuntimeState:
    netns_identity: NetnsIdentity
    host_links: tuple
    namespace_links: tuple
    qdiscs: tuple
    filters: tuple


@dataclass(frozen=True)
class TcBinding:
    netns_identity: NetnsIdentity
    host_veth: Link
    guest_veth: Link
    tap: Link
    qdiscs: tuple
    filters: tuple


def runtime_difference(before, after):
    if (type(before) is not RuntimeState or type(after) is not RuntimeState
            or type(before.netns_identity) is not NetnsIdentity
            or type(after.netns_identity) is not NetnsIdentity):
        raise NetworkError("typed runtime states required")
    if before.netns_identity != after.netns_identity:
        raise NetworkError("network namespace identity replacement")
    if before.host_links != after.host_links or len(before.host_links) != 1:
        raise NetworkError("host link baseline replacement")
    host, guest = validate_peer_pair(before.host_links, before.namespace_links)
    after_without_tap = tuple(item for item in after.namespace_links if item.kind != "tap")
    after_host, after_guest = validate_peer_pair(after.host_links, after_without_tap)
    if (host != after_host or guest != after_guest or before.namespace_links != after_without_tap
            or len(after.namespace_links) != len(before.namespace_links) + 1):
        raise NetworkError("full namespace link baseline replacement")
    taps = tuple(item for item in after.namespace_links if item.kind == "tap")
    if len(taps) != 1:
        raise NetworkError("exact runtime TAP difference required")
    tap = taps[0]
    guest_root = TcQdisc(guest.ifindex, guest.ifname, "noqueue", "0:", None, True, 2)
    guest_ingress = TcQdisc(guest.ifindex, guest.ifname, "ingress", "ffff:", "ffff:fff1", False, None)
    tap_root = TcQdisc(tap.ifindex, tap.ifname, "noqueue", "0:", None, True, 2)
    tap_ingress = TcQdisc(tap.ifindex, tap.ifname, "ingress", "ffff:", "ffff:fff1", False, None)
    if before.qdiscs != (guest_root,) or before.filters:
        raise NetworkError("unexpected tc baseline")
    if set(after.qdiscs) != {guest_root, guest_ingress, tap_root, tap_ingress} or len(after.qdiscs) != 4:
        raise NetworkError("complete qdisc difference required")
    tables = tuple(item for item in after.filters if type(item) is TcFilterTable)
    filters = tuple(item for item in after.filters if type(item) is TcFilter)
    if len(after.filters) != 4 or len(tables) != 2 or len(filters) != 2:
        raise NetworkError("complete directional filter difference required")
    if {(item.dev_ifindex, item.handle, item.divisor) for item in tables} != {
            (guest.ifindex, "800:", 1), (tap.ifindex, "800:", 1)}:
        raise NetworkError("complete u32 table difference required")
    directions = {(item.dev_ifindex, item.action.to_ifindex) for item in filters}
    if (directions != {(guest.ifindex, tap.ifindex), (tap.ifindex, guest.ifindex)}
            or len({item.action.index for item in filters}) != 2
            or any(item.hook != "ingress" or item.action.direction != "egress" for item in filters)):
        raise NetworkError("exact bidirectional tc binding required")
    return TcBinding(after.netns_identity, host, guest, tap, after.qdiscs, after.filters)


def runtime_restored(baseline, observed):
    if (type(baseline) is not RuntimeState or type(observed) is not RuntimeState
            or type(baseline.netns_identity) is not NetnsIdentity
            or type(observed.netns_identity) is not NetnsIdentity):
        raise NetworkError("typed runtime restoration states required")
    if baseline != observed:
        raise NetworkError("runtime baseline not exactly restored")
    return baseline


class Recovery(Enum):
    RETRY = "retry"
    SETTLED = "settled"
    ABSENT = "absent"
    PRESERVE = "preserve"
    REMOVE = "remove"


class TransitionPhase(Enum):
    CREATE_INTENT = "create-intent"
    IDENTITY_DURABLE = "identity-durable"
    SETTLED = "settled"
    REMOVE_INTENT = "remove-intent"


class TeardownPrerequisite(Enum):
    TASK_STOPPED = "task-stopped"
    NETWORK_AND_MOUNT_ABSENT = "network-and-mount-absent"
    TASK_AND_CONTAINER_DELETED = "task-and-container-deleted"
    PROCESS_SHARE_MOUNTS_ABSENT = "process-share-mounts-absent"
    FIREWALL_ABSENT = "firewall-absent"


_TEARDOWN_ORDER = tuple(TeardownPrerequisite)


@dataclass(frozen=True)
class TeardownProof:
    completed: tuple

    def __post_init__(self):
        if (type(self.completed) is not tuple or self.completed != _TEARDOWN_ORDER[:len(self.completed)]
                or len(self.completed) > len(_TEARDOWN_ORDER)):
            raise NetworkError("ordered teardown prerequisite proof required")

    def includes(self, prerequisite):
        if type(prerequisite) is not TeardownPrerequisite:
            raise NetworkError("typed teardown prerequisite required")
        return prerequisite in self.completed


@dataclass(frozen=True)
class NetnsTransition:
    phase: TransitionPhase
    identity: NetnsIdentity


@dataclass(frozen=True)
class NetnsObservation:
    identity: NetnsIdentity | None


@dataclass(frozen=True)
class TcTransition:
    phase: TransitionPhase
    identity: TcBinding
    netns_identity: NetnsIdentity


@dataclass(frozen=True)
class TcObservationState:
    identity: TcBinding | None
    netns_identity: NetnsIdentity | None


@dataclass(frozen=True)
class NftTransition:
    phase: TransitionPhase
    identity: NftSnapshot


@dataclass(frozen=True)
class NftObservation:
    identity: NftSnapshot | None


def _validate_phase(phase):
    if type(phase) is not TransitionPhase:
        raise NetworkError("typed durable transition phase required")


def recover_netns(transition, observed, teardown):
    if (type(transition) is not NetnsTransition or type(transition.identity) is not NetnsIdentity
            or type(observed) is not NetnsObservation or type(teardown) is not TeardownProof):
        raise NetworkError("typed netns recovery state required")
    _validate_phase(transition.phase)
    if observed.identity is not None and type(observed.identity) is not NetnsIdentity:
        raise NetworkError("complete netns identity required")
    if observed.identity not in (None, transition.identity):
        return Recovery.PRESERVE
    if transition.phase is TransitionPhase.CREATE_INTENT:
        return Recovery.RETRY if observed.identity is None else Recovery.PRESERVE
    if transition.phase in (TransitionPhase.IDENTITY_DURABLE, TransitionPhase.SETTLED):
        return Recovery.SETTLED if observed.identity == transition.identity else Recovery.PRESERVE
    if observed.identity is None:
        return Recovery.ABSENT
    return (Recovery.REMOVE if teardown.includes(TeardownPrerequisite.TASK_STOPPED)
            else Recovery.PRESERVE)


def recover_tc(transition, observed, teardown):
    if (type(transition) is not TcTransition or type(transition.identity) is not TcBinding
            or type(transition.netns_identity) is not NetnsIdentity
            or transition.identity.netns_identity != transition.netns_identity
            or type(observed) is not TcObservationState or type(teardown) is not TeardownProof):
        raise NetworkError("typed correlated tc recovery state required")
    _validate_phase(transition.phase)
    if (observed.identity is not None and type(observed.identity) is not TcBinding
            or observed.netns_identity is not None and type(observed.netns_identity) is not NetnsIdentity
            or observed.identity is not None
            and (type(observed.identity.netns_identity) is not NetnsIdentity
                 or observed.identity.netns_identity != observed.netns_identity)):
        raise NetworkError("complete correlated tc/netns identity required")
    if (observed.netns_identity not in (None, transition.netns_identity)
            or observed.identity not in (None, transition.identity)):
        return Recovery.PRESERVE
    if transition.phase is TransitionPhase.CREATE_INTENT:
        return Recovery.RETRY if observed.identity is None else Recovery.PRESERVE
    if transition.phase in (TransitionPhase.IDENTITY_DURABLE, TransitionPhase.SETTLED):
        return Recovery.SETTLED if observed.identity == transition.identity else Recovery.PRESERVE
    if observed.identity is None:
        return Recovery.ABSENT
    return (Recovery.REMOVE if teardown.includes(TeardownPrerequisite.TASK_STOPPED)
            else Recovery.PRESERVE)


def recover_nft(transition, observed, teardown):
    if (type(transition) is not NftTransition or type(transition.identity) is not NftSnapshot
            or type(observed) is not NftObservation or type(teardown) is not TeardownProof):
        raise NetworkError("typed nft recovery state required")
    _validate_phase(transition.phase)
    if observed.identity is not None and type(observed.identity) is not NftSnapshot:
        raise NetworkError("complete nft identity required")
    if observed.identity not in (None, transition.identity):
        return Recovery.PRESERVE
    if transition.phase is TransitionPhase.CREATE_INTENT:
        return Recovery.RETRY if observed.identity is None else Recovery.PRESERVE
    if transition.phase in (TransitionPhase.IDENTITY_DURABLE, TransitionPhase.SETTLED):
        return Recovery.SETTLED if observed.identity == transition.identity else Recovery.PRESERVE
    if observed.identity is None:
        return Recovery.ABSENT
    return (Recovery.REMOVE if teardown.includes(TeardownPrerequisite.PROCESS_SHARE_MOUNTS_ABSENT)
            else Recovery.PRESERVE)


class _TestPermit:
    __slots__ = ("_unused",)

    def __init__(self):
        self._unused = True


class TestLocalNetworkFake:
    """Typed recorder for fixed offline fixtures; it cannot execute argv."""
    __slots__ = ("_permit", "_responses", "calls")

    def __init__(self, permit, responses=()):
        if type(permit) is not _TestPermit or type(responses) not in (tuple, list):
            raise NetworkError("test permit")
        self._permit = permit
        self._responses = list(responses)
        self.calls = []

    def issue(self, action):
        if not self._permit._unused or type(action) is not Action:
            raise NetworkError("spent test permit or untyped action")
        spec = command(action)
        self.calls.append(spec)
        return self._responses.pop(0) if self._responses else b""

    def close(self):
        if not self._permit._unused:
            raise NetworkError("fake already closed")
        self._permit._unused = False


def make_test_local_fake(responses=()):
    return TestLocalNetworkFake(_TestPermit(), responses)


def _fixed_network_owner_routes():
    """Seal the fixed /30 owner and its only setup/cleanup plans."""
    seal = object()
    states = {}
    setup_actions = tuple(action for action in _MUTATIONS
                          if action not in {Action.NFT_REMOVE, Action.NETNS_REMOVE})
    cleanup_actions = (Action.NFT_REMOVE, Action.NETNS_REMOVE)

    class FixedNetworkOwner:
        __slots__ = ()
        def __new__(cls, key=None):
            if key is not seal:
                raise NetworkError("sealed network owner")
            return super().__new__(cls)
        @property
        def uncertain(self):
            return states[self]["uncertain"]
        @property
        def closed(self):
            return states[self]["closed"]
        def setup_plan(self):
            state = states[self]
            if state["closed"] or state["uncertain"]:
                raise NetworkError("network owner is closed or uncertain")
            return tuple(command(action) for action in setup_actions)
        def cleanup_plan(self):
            state = states[self]
            if state["closed"] or state["uncertain"]:
                raise NetworkError("network owner is closed or uncertain")
            return tuple(command(action) for action in cleanup_actions)
        def poison(self):
            states[self]["uncertain"] = True
        def close(self):
            state = states[self]
            if state["uncertain"]:
                raise NetworkError("network ownership is uncertain")
            state["closed"] = True

    def make(process_owner):
        if type(process_owner) is not process.FixedProcessOwner or process_owner.closed:
            raise NetworkError("exact live process owner required")
        owner = FixedNetworkOwner(seal)
        states[owner] = {"closed": False, "uncertain": False,
                         "process_owner": process_owner}
        return owner

    def open_owner(grant, process_owner):
        qualification._consume_fixed_owner_grant(grant, "network")
        return make(process_owner)

    return FixedNetworkOwner, open_owner, make


(FixedNetworkOwner, _open_production_owner,
 _make_fixed_network_owner_for_tests) = _fixed_network_owner_routes()
del _fixed_network_owner_routes


def open_fixed_network_owner():
    """The zero-argument route cannot substitute for coordinator authority."""
    raise NetworkError("production network owner requires the sealed coordinator gate")


# No generic command, executable, shell, host probe, network mutation entry point,
# forced removal, broad reset, translation, adoption, or fallback route exists.

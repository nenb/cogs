"""Closed, fixed Stage 2 Kata network-state contracts.

Historical snapshot parsing remains data-only. Package-private trusted-T1
composition performs only journal-bound fixed transactions with retained,
authenticated tools. The runtime handoff retains and freshly revalidates the
exact fixed nsfs descriptor and accepts no caller identity. Public production
opening remains unavailable until the coordinator facet is complete.
"""
from dataclasses import asdict, dataclass
from enum import Enum
import ctypes
import errno
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import completion_kata_actions as actions
import completion_kata_nft_owner as nft_owner
import completion_kata_owner as owner_helpers

NETNS = "cogs-stage2-ssh"
NETNS_PATH = "/run/netns/cogs-stage2-ssh"
PRESERVED_DIR = "/run/netns/.cogs-stage2-preserved"
PARENT_STAGE_DIR = "/run/.cogs-stage2-netns-parent"
PRESERVED_REMOVING = ".cogs-stage2-preserved-removing"
PARENT_STAGE_REMOVING = ".cogs-stage2-netns-parent-removing"
HOST_IF = "c42h0"
TEMP_IF = "c42g0"
GUEST_IF = "eth0"
HOST_MAC = "02:00:00:42:00:01"
GUEST_MAC = "02:00:00:42:00:02"
HOST_CIDR = "192.0.2.1/30"
GUEST_CIDR = "192.0.2.2/30"
TABLE = "cogs_stage2_ssh_v1"
TABLE_HANDLE = "18446744073709551615"
MAX_JSON = 262_144
MAX_ITEMS = 64
MAX_NFT_ITEMS = 256
MAX_DEPTH = 16
MAX_MOUNTINFO_BYTES = 4_194_304
MAX_MOUNTINFO_LINES = 4096
QUALIFICATION_CANDIDATE = "UNQUALIFIED_FIXED_HOST_TOOL_OUTPUT_CANDIDATE_V1"
ZERO = "0" * 64
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
NFT_OWNED_TRANSACTION = NFT_TRANSACTION.replace(
    b"add table inet cogs_stage2_ssh_v1\n",
    b'add table inet cogs_stage2_ssh_v1 { comment "owner:cogs_stage2_ssh_v1"; }\n', 1)
NFT_DELETE_TRANSACTION = ("list table inet " + TABLE + "\ndelete table inet " + TABLE + "\n").encode()


class NetworkError(Exception):
    """A command request, snapshot, or ownership transition was not exact."""


class NetworkCleanupError(NetworkError):
    """Retain the cleanup failure and its failed uncertainty settlement."""
    def __init__(self, primary, settlement):
        self.errors = (primary, settlement)
        super().__init__("cleanup failure and uncertainty settlement failure")


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
    Action.IP_VETH_ADD_ATOMIC: (IP_CONTRACT, ("link", "add", "name", HOST_IF, "address", HOST_MAC,
        "type", "veth", "peer", "name", GUEST_IF, "address", GUEST_MAC, "netns", NETNS), b""),
    Action.HOST_ADDRESS_ADD: (IP_CONTRACT, ("address", "add", HOST_CIDR, "dev", HOST_IF), b""),
    Action.HOST_ADDRGEN_NONE: (IP_CONTRACT, ("link", "set", "dev", HOST_IF, "addrgenmode", "none"), b""),
    Action.HOST_LINK_UP: (IP_CONTRACT, ("link", "set", "dev", HOST_IF, "up"), b""),
    Action.PEER_RENAME: (IP_CONTRACT, ("-n", NETNS, "link", "set", "dev", TEMP_IF, "name", GUEST_IF), b""),
    Action.PEER_ADDRGEN_NONE: (IP_CONTRACT, ("-n", NETNS, "link", "set", "dev", GUEST_IF, "addrgenmode", "none"), b""),
    Action.LOOPBACK_UP: (IP_CONTRACT, ("-n", NETNS, "link", "set", "dev", "lo", "up"), b""),
    Action.GUEST_ADDRESS_ADD: (IP_CONTRACT, ("-n", NETNS, "address", "add", GUEST_CIDR, "dev", GUEST_IF), b""),
    Action.GUEST_LINK_UP: (IP_CONTRACT, ("-n", NETNS, "link", "set", "dev", GUEST_IF, "up"), b""),
    Action.NFT_INSTALL: (NFT_CONTRACT, ("-f", "-"), NFT_TRANSACTION),
    Action.NFT_INSTALL_OWNED: (NFT_CONTRACT, ("-f", "-"), NFT_OWNED_TRANSACTION),
    Action.NFT_REMOVE: (NFT_CONTRACT, ("delete", "table", "inet", TABLE), b""),
    Action.NFT_REMOVE_ATOMIC: (NFT_CONTRACT, ("delete", "table", "inet", TABLE), b""),
    Action.HOST_LINK_REMOVE: (IP_CONTRACT, ("link", "delete", "dev", HOST_IF), b""),
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
    Action.IP_NETNS_LIST: (IP_CONTRACT, ("-j", "netns", "list"), b""),
    Action.IP_ALL_LINKS: (IP_CONTRACT, ("-j", "-d", "link", "show"), b""),
    Action.IP_ALL_ADDRESSES: (IP_CONTRACT, ("-j", "address", "show"), b""),
    Action.IP_ALL_ROUTES4: (IP_CONTRACT, ("-4", "-j", "route", "show", "table", "all"), b""),
    Action.IP_ALL_ROUTES6: (IP_CONTRACT, ("-6", "-j", "route", "show", "table", "all"), b""),
    Action.NFT_RULESET: (NFT_CONTRACT, ("-j", "list", "ruleset"), b""),
    Action.QDISC: (TC_CONTRACT, ("-n", NETNS, "-j", "qdisc", "show", "dev", GUEST_IF), b""),
    Action.INGRESS_FILTER: (TC_CONTRACT, ("-n", NETNS, "-j", "filter", "show", "dev", GUEST_IF, "ingress"), b""),
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


def _load(raw, item_limit=MAX_ITEMS):
    if (type(raw) is not bytes or not raw or len(raw) > MAX_JSON or b"\x00" in raw
            or type(item_limit) is not int or item_limit not in {MAX_ITEMS, MAX_NFT_ITEMS}):
        raise NetworkError("bounded JSON bytes required")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_Pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))

        def convert(item, depth=0):
            if depth > MAX_DEPTH:
                raise NetworkError("JSON depth")
            if type(item) is _Pairs:
                if len(item) > item_limit:
                    raise NetworkError("JSON object bound")
                result = {}
                for key, child in item:
                    if type(key) is not str or key in result:
                        raise NetworkError("duplicate JSON key")
                    result[key] = convert(child, depth + 1)
                return result
            if type(item) is list:
                if len(item) > item_limit:
                    raise NetworkError("JSON array bound")
                return [convert(child, depth + 1) for child in item]
            if item is None or type(item) in (str, int, bool):
                return item
            if type(item) is float and math.isfinite(item):
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
                  "gso_max_segs", "tso_max_size", "tso_max_segs", "gro_max_size",
                  "allmulti", "inet6_addr_gen_mode", "ifalias", "parentbus", "parentdev",
                  "link_netnsid", "link", "broadcast", "altnames")
_MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")


def _parse_link_row(row, runtime=False):
    try:
        _keys(row, ("ifindex", "ifname", "flags", "operstate", "link_type", "address", "qdisc"),
              _LINK_OPTIONAL + ("link_index", "addrgenmode", "linkinfo"))
    except NetworkError as error:
        keys = sorted(row) if type(row) is dict and all(type(key) is str for key in row) else []
        raise NetworkError(f"unexpected link JSON keys:{keys!r}") from error
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
                row["qdisc"], row.get("addrgenmode", row.get("inet6_addr_gen_mode")))


def parse_links(raw, namespace, host_if=HOST_IF):
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
        if set(by_name) not in (set(), {host_if}):
            raise NetworkError("host interface inventory")
        if result:
            host = result[0]
            valid_state = ((set(host.flags) == {"BROADCAST", "MULTICAST"} and host.operstate == "DOWN" and not host.up)
                           or (set(host.flags) == {"BROADCAST", "MULTICAST", "UP", "LOWER_UP"}
                               and host.operstate == "UP" and host.up))
            if (host.kind != "veth" or host.mac != HOST_MAC or host.peer_ifindex is None
                    or host.qdisc != "noqueue" or host.addrgenmode not in ("none", 1)
                    or not valid_state):
                raise NetworkError(f"host veth drift:{host!r}")
    return result


def validate_peer_pair(host_links, namespace_links, host_if=HOST_IF):
    if type(host_links) is not tuple or type(namespace_links) is not tuple or len(host_links) != 1:
        raise NetworkError("complete peer snapshots required")
    host = host_links[0]
    guests = {item.ifname: item for item in namespace_links}
    guest = guests.get(GUEST_IF)
    if (host.ifname != host_if or guest is None or host.peer_ifindex != guest.ifindex
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


def parse_addresses(raw, namespace, links, host_if=HOST_IF):
    value = _load(raw)
    if type(value) is not list or type(namespace) is not bool or type(links) is not tuple:
        raise NetworkError("address list")
    bound = {item.ifname: item.ifindex for item in links}
    result, seen = [], set()
    for link in value:
        try:
            _keys(link, ("ifindex", "ifname", "addr_info"),
                  _LINK_OPTIONAL + ("flags", "operstate", "link_type", "address", "qdisc",
                                    "link_index"))
        except NetworkError as error:
            keys = sorted(link) if type(link) is dict and all(type(key) is str for key in link) else []
            raise NetworkError(f"unexpected address-link JSON keys:{keys!r}") from error
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
                ({(host_if, "inet", "192.0.2.1", 30, "global")} if links else set()))
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
_HOST_ROUTE6_CANDIDATE = {
    ("multicast", "ff00::/8", HOST_IF, "local", "kernel", None, None, 256, (), "medium"),
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
    ("multicast", "ff00::/8", GUEST_IF, "local", "kernel", None, None, 256, (), "medium"),
}


def parse_routes(raw, family, links, host_if=HOST_IF):
    value = _load(raw)
    if type(value) is not list or family not in (4, 6) or type(links) is not tuple:
        raise NetworkError("route list")
    bound = {item.ifname for item in links}
    runtime_taps = {item.ifname for item in links if item.kind == "tap"}
    namespace_bound = (bound == {"lo", GUEST_IF} | runtime_taps
                       and len(runtime_taps) <= 1)
    if bound != {host_if} and not namespace_bound:
        raise NetworkError("complete route link binding")
    result = []
    for row in value:
        try:
            _keys(row, ("dst", "protocol"),
                  ("dev", "table", "prefsrc", "src", "type", "scope", "metric", "flags", "pref"))
        except NetworkError as error:
            keys = sorted(row) if type(row) is dict and all(type(key) is str for key in row) else []
            raise NetworkError(f"unexpected route JSON keys:{keys!r}:{row!r}") from error
        source = row.get("prefsrc", row.get("src"))
        dev = row.get("dev")
        if dev is None:
            dev = (host_if if source == "192.0.2.1" else GUEST_IF
                   if source == "192.0.2.2" else "lo"
                   if source in {"127.0.0.1", "::1"} or row["dst"].startswith("127.")
                   or row["dst"] == "::1" else host_if
                   if row.get("type") == "multicast" and row["dst"] == "ff00::/8"
                   and bound == {host_if} else GUEST_IF
                   if row.get("type") == "multicast" and row["dst"] == "ff00::/8"
                   and namespace_bound else None)
        if row["dst"] == "default" or dev not in bound or row["protocol"] != "kernel":
            raise NetworkError(
                f"default, foreign, or misbound route:{dev!r}:{source!r}:{row!r}")
        try:
            network = ipaddress.ip_network(row["dst"], strict=False)
        except (TypeError, ValueError) as error:
            raise NetworkError("route prefix") from error
        if network.version != family:
            raise NetworkError("route family")
        flags = row.get("flags", [])
        if type(flags) is not list or any(type(item) is not str for item in flags):
            raise NetworkError("route flags")
        result.append(Route(family, row.get("type", "unicast"), row["dst"], dev,
                            str(row.get("table", "main")), row["protocol"], row.get("scope"),
                            source, row.get("metric"), tuple(flags), row.get("pref")))
    actual = {(item.route_type, item.dst, item.dev, item.table, item.protocol, item.scope,
               item.source, item.metric, item.flags, item.pref) for item in result}
    if bound == {host_if}:
        candidates = _HOST_ROUTE4_CANDIDATE if family == 4 else _HOST_ROUTE6_CANDIDATE
        expected = {tuple(host_if if item == HOST_IF else item for item in row)
                    for row in candidates}
    else:
        expected = set(_ROUTE4_CANDIDATE if family == 4 else _ROUTE6_CANDIDATE)
        if family == 6:
            expected.update(("multicast", "ff00::/8", tap, "local", "kernel", None,
                             None, 256, (), "medium") for tap in runtime_taps)
    if len(actual) != len(result) or actual != expected:
        raise NetworkError("complete route inventory drift")
    return tuple(result)


def parse_runtime_addresses(raw, links):
    """Validate complete lo/veth/TAP rows and exact TAP address absence."""
    value = _load(raw)
    if type(value) is not list or type(links) is not tuple:
        raise NetworkError("runtime address list")
    bound = {item.ifname: item.ifindex for item in links}
    if set(bound) != {"lo", GUEST_IF, *(item.ifname for item in links if item.kind == "tap")}:
        raise NetworkError("runtime address link binding")
    seen, identities = set(), set()
    for link in value:
        _keys(link, ("ifindex", "ifname", "addr_info"),
              _LINK_OPTIONAL + ("flags", "operstate", "link_type", "address", "qdisc",
                                "link_index"))
        name, index = link["ifname"], _uint(link["ifindex"])
        if name not in bound or bound[name] != index or name in seen or type(link["addr_info"]) is not list:
            raise NetworkError("runtime address/link cross-binding")
        seen.add(name)
        for row in link["addr_info"]:
            _keys(row, ("family", "local", "prefixlen", "scope"),
                  ("label", "broadcast", "valid_life_time", "preferred_life_time", "dynamic", "noprefixroute"))
            identities.add((name, row["family"], row["local"], row["prefixlen"], row["scope"]))
    expected = {("lo", "inet", "127.0.0.1", 8, "host"),
                ("lo", "inet6", "::1", 128, "host"),
                (GUEST_IF, "inet", "192.0.2.2", 30, "global")}
    if seen != set(bound) or identities != expected:
        raise NetworkError("runtime TAP/address inventory drift")
    return tuple(sorted(identities))


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
_NFT_ROW_ORDER = ("table", "chain", "chain", "chain", "rule", "rule", "rule", "rule", "rule", "rule")
_NFT_RULE_CHAIN_ORDER = ("input", "input", "output", "output", "forward", "forward")


def _normalize_nft_expr(expressions):
    normalized = json.loads(json.dumps(expressions))
    for expression in normalized:
        match = expression.get("match") if type(expression) is dict else None
        right = match.get("right") if type(match) is dict else None
        if match and match.get("left") == {"ct": {"key": "state"}}:
            if right == "established":
                right = {"set": [right]}; match["right"] = right
            elif (type(right) is list and len(right) == 2
                  and set(right) == {"established", "new"}):
                right = {"set": right}; match["right"] = right
            else:
                try: _keys(right, ("set",))
                except NetworkError as error:
                    raise NetworkError(f"nft state-set shape:{right!r}") from error
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


def parse_nft_snapshot(raw, table_name=TABLE, host_if=HOST_IF):
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
            actual = tuple(tuple(item) if type(item) is dict else () for item in rows[1:])
            raise NetworkError(f"nft output ordering drift:{actual!r}")
        body = row[expected_kind]
        if type(body) is not dict:
            raise NetworkError("nft body")
        handle = _uint(body.get("handle"))
        content = {key: child for key, child in body.items() if key != "handle"}
        if expected_kind == "table":
            expected_table = {"family": "inet", "name": table_name}
            if re.fullmatch(r"c42t[0-9a-f]{10}", table_name): expected_table["comment"] = "owner:" + table_name
            if content != expected_table:
                raise NetworkError("nft table drift")
            table_handle = handle
        elif expected_kind == "chain":
            _keys(content, ("family", "table", "name", "type", "hook", "prio", "policy"))
            active_chain = content["name"]
            if (active_chain not in _NFT_RULES or content != {"family": "inet", "table": table_name,
                    "name": active_chain, "type": "filter", "hook": active_chain, "prio": 0, "policy": "accept"}
                    or active_chain in {name for name, _handle in chain_handles}):
                raise NetworkError("nft chain drift")
            chain_handles.append((active_chain, handle))
        else:
            _keys(content, ("family", "table", "chain", "expr"))
            chain = content["chain"]
            expected_chain = _NFT_RULE_CHAIN_ORDER[len(rule_handles)]
            if (chain != expected_chain or chain not in {name for name, _handle in chain_handles}
                    or content["family"] != "inet" or content["table"] != table_name):
                raise NetworkError("nft rule ownership drift")
            expr = tuple(_normalize_nft_expr(content["expr"]))
            ordinal = rule_ordinals[chain]
            if ordinal >= len(_NFT_RULES[chain]): raise NetworkError("nft normalized content drift")
            expected_expr = tuple(json.loads(json.dumps(_NFT_RULES[chain][ordinal]).replace(HOST_IF, host_if)))
            if expr != expected_expr:
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


def parse_netns_identity(raw, stat, path=NETNS_PATH):
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
    nearby = []
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
        if point.startswith("/run/netns"):
            nearby.append((root, point, fs_type, source))
        if point == path:
            found.append(NetnsIdentity(mount_id, parent_id, fields[2], root, point,
                                       mount_options, optional, fs_type, source, super_options,
                                       stat.device, stat.inode))
    expected_device = f"{os.major(stat.device)}:{os.minor(stat.device)}"
    if len(found) != 1:
        raise NetworkError(f"netns mount cardinality:{len(found)}:{nearby!r}")
    identity = found[0]
    propagation = tuple(field.split(":", 1)[0] for field in identity.optional_fields)
    optional_ok = (len(identity.optional_fields) <= 2
                   and len(set(propagation)) == len(propagation)
                   and all(re.fullmatch(r"(?:shared|master):[1-9][0-9]*", field) is not None
                           for field in identity.optional_fields))
    if (identity.device != expected_device or identity.root != f"net:[{stat.inode}]"
            or identity.mount_options != ("rw",) or not optional_ok
            or identity.fs_type != "nsfs" or identity.source != "nsfs"
            or identity.super_options != ("rw",)):
        raise NetworkError(
            "netns mount/stat identity drift:"
            f"{identity.device}:{expected_device}:{identity.root}:"
            f"{identity.mount_options}:{identity.optional_fields}:{identity.fs_type}:"
            f"{identity.source}:{identity.super_options}")
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


_NATIVE_FQ_CODEL_OPTIONS = {
    "limit": 10240, "flows": 1024, "quantum": 1514, "target": 4999,
    "interval": 99999, "memory_limit": 33554432, "ecn": True, "drop_batch": 64,
}


def parse_tc_qdiscs(raw, endpoint):
    endpoint = _tc_endpoint(endpoint)
    value = _load(raw)
    if type(value) is not list or len(value) not in (1, 2):
        raise NetworkError("tc qdisc list")
    result = []
    for index, row in enumerate(value):
        if index == 0:
            _keys(row, ("kind", "handle", "root", "refcnt", "options"))
            root_identity = (row["kind"], row["handle"], row["root"], row["options"])
            noqueue = root_identity == ("noqueue", "0:", True, {})
            native_fq_codel = (endpoint.kind == "tap" and endpoint.qdisc == "fq_codel"
                               and root_identity == ("fq_codel", "0:", True,
                                                     _NATIVE_FQ_CODEL_OPTIONS))
            if not (noqueue or native_fq_codel):
                raise NetworkError(f"tc root qdisc drift:{row!r}")
            if row["refcnt"] != 2:
                raise NetworkError("tc root qdisc refcnt drift")
            result.append(TcQdisc(endpoint.ifindex, endpoint.ifname, row["kind"], "0:", None,
                                  True, 2))
        else:
            try: _keys(row, ("kind", "handle", "parent"), ("options",))
            except NetworkError as error:
                raise NetworkError(f"native ingress qdisc shape:{row!r}") from error
            if ({key: value for key, value in row.items() if key != "options"}
                    != {"kind": "ingress", "handle": "ffff:", "parent": "ffff:fff1"}
                    or row.get("options", {}) != {}):
                raise NetworkError("tc ingress qdisc drift")
            result.append(TcQdisc(endpoint.ifindex, endpoint.ifname, "ingress", "ffff:",
                                  "ffff:fff1", False, None))
    return tuple(result)


def parse_tc_filters(raw, source, target):
    source, target = _tc_endpoint(source), _tc_endpoint(target)
    if source == target:
        raise NetworkError("tc self redirect")
    value = _load(raw)
    if type(value) is not list or len(value) not in {2, 3}:
        raise NetworkError(f"tc filter list:{value!r}")
    native = len(value) == 3
    if native:
        header, table_row, row = value
        _keys(header, ("protocol", "pref", "kind", "chain"))
    else:
        table_row, row = value
    for item in (table_row, row):
        _keys(item, ("protocol", "pref", "kind", "chain", "options"))
    for item in value:
        if (item["protocol"], item["pref"], item["kind"], item["chain"]) != ("all", 49152, "u32", 0):
            raise NetworkError("tc filter header drift")
    if table_row["options"] != {"fh": "800:", "ht_divisor": 1}:
        raise NetworkError("tc u32 table drift")
    table = TcFilterTable(source.ifindex, source.ifname, "ingress", "all", 49152,
                          "u32", 0, "800:", 1)
    options = row["options"]
    if native:
        _keys(options, ("fh", "order", "key_ht", "bkt", "not_in_hw", "match", "actions"))
        expected = {"fh": "800::800", "order": 2048, "key_ht": "800", "bkt": "0",
                    "not_in_hw": True,
                    "match": {"value": "0", "mask": "0", "offmask": "", "off": 0}}
    else:
        _keys(options, ("fh", "ht", "order", "key_ht", "bkt", "terminal", "not_in_hw", "match", "actions"))
        expected = {"fh": "800::800", "ht": "800:", "order": 2048, "key_ht": 32768,
                    "bkt": "0", "terminal": True, "not_in_hw": True,
                    "match": {"value": "00000000", "mask": "00000000", "off": 0}}
    if ({key: options[key] for key in expected} != expected
            or type(options["actions"]) is not list or len(options["actions"]) != 1):
        raise NetworkError("tc u32 match drift")
    action = options["actions"][0]
    if native:
        _keys(action, ("order", "kind", "mirred_action", "direction", "to_dev",
                       "control_action", "index", "ref", "bind"))
        control, redirect = "stolen", action["mirred_action"]
    else:
        _keys(action, ("order", "kind", "control_action", "index", "ref", "bind", "eaction", "direction", "to_dev"))
        control, redirect = "pipe", action["eaction"]
    _keys(action["control_action"], ("type",))
    if (action["order"], action["kind"], action["control_action"]["type"], action["ref"], action["bind"],
            redirect, action["direction"], action["to_dev"]) != (
            1, "mirred", control, 1, 1, "redirect", "egress", target.ifname):
        raise NetworkError("tc action binding drift")
    parsed_action = TcAction(_uint(action["index"]), "mirred", control, "redirect", "egress",
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
        tap_state = (tap.qdisc, tap.operstate)
        if (tap.peer_ifindex is not None or not tap.up
                or tap_state not in {("noqueue", "UP"), ("fq_codel", "UNKNOWN")}
                or tap.addrgenmode not in ("none", 1)
                or tap.mac == "00:00:00:00:00:00"
                or set(tap.flags) != {"BROADCAST", "MULTICAST", "UP", "LOWER_UP"}):
            raise NetworkError(f"runtime TAP identity drift:{tap!r}")
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
    host_if = before.host_links[0].ifname
    if host_if != HOST_IF and re.fullmatch(r"c42h[0-9a-f]{10}", host_if) is None: raise NetworkError("host veth name")
    host, guest = validate_peer_pair(before.host_links, before.namespace_links, host_if)
    after_without_tap = tuple(item for item in after.namespace_links if item.kind != "tap")
    after_host, after_guest = validate_peer_pair(after.host_links, after_without_tap, host_if)
    if (host != after_host or guest != after_guest or before.namespace_links != after_without_tap
            or len(after.namespace_links) != len(before.namespace_links) + 1):
        raise NetworkError("full namespace link baseline replacement")
    taps = tuple(item for item in after.namespace_links if item.kind == "tap")
    if len(taps) != 1:
        raise NetworkError("exact runtime TAP difference required")
    tap = taps[0]
    guest_root = TcQdisc(guest.ifindex, guest.ifname, "noqueue", "0:", None, True, 2)
    guest_ingress = TcQdisc(guest.ifindex, guest.ifname, "ingress", "ffff:", "ffff:fff1", False, None)
    tap_root = TcQdisc(tap.ifindex, tap.ifname, tap.qdisc, "0:", None, True, 2)
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
        return Recovery.PRESERVE
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
        return Recovery.PRESERVE
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
        return Recovery.PRESERVE
    if transition.phase in (TransitionPhase.IDENTITY_DURABLE, TransitionPhase.SETTLED):
        return Recovery.SETTLED if observed.identity == transition.identity else Recovery.PRESERVE
    if observed.identity is None:
        return Recovery.ABSENT
    return (Recovery.REMOVE if teardown.includes(TeardownPrerequisite.PROCESS_SHARE_MOUNTS_ABSENT)
            else Recovery.PRESERVE)


# Production composition below is package-private trusted-T1 code.  Its only
# effects route is the journal-bound fixed process transaction; supplied
# RetainedExecutable values are reauthenticated there and convey no Python
# authority by their type or identity.
_BASELINE_ACTIONS = (
    Action.IP_ALL_LINKS, Action.IP_ALL_ADDRESSES, Action.IP_ALL_ROUTES4,
    Action.IP_ALL_ROUTES6, Action.IP_NETNS_LIST, Action.NFT_RULESET,
)
_SETUP_ACTIONS = (
    Action.IP_NETNS_ADD, Action.IP_VETH_ADD_ATOMIC, Action.NFT_INSTALL_OWNED,
    Action.IP_HOST_ADDRESS_ADD, Action.IP_HOST_ADDRGEN_NONE,
    Action.IP_PEER_ADDRGEN_NONE, Action.IP_LOOPBACK_UP, Action.IP_GUEST_ADDRESS_ADD,
    Action.IP_HOST_LINK_UP, Action.IP_GUEST_LINK_UP,
)
_BASELINE_KEYS = (
    "host_links", "host_addresses", "host_routes4", "host_routes6",
    "netns_names", "nft_ruleset", "mountinfo",
)


def _bound_names(journal):
    import completion_kata_operation as operation
    token = operation._command_context(journal).operation_token
    return "c42n" + token[:10], "c42t" + token[:10]


def _bound_host(journal):
    import completion_kata_operation as operation
    return "c42h" + operation._command_context(journal).operation_token[:10]


def _bound_fixed(journal, fixed, target=None):
    import completion_kata_process as process
    netns, table = _bound_names(journal); host = _bound_host(journal)
    command_netns = _quarantine_name(journal) if fixed.command_id is Action.NETNS_REMOVE else netns
    argv = tuple(table if item == TABLE else command_netns if item == NETNS else host if item == HOST_IF else item for item in fixed.argv)
    stdin = fixed.stdin.replace(TABLE.encode(), table.encode()).replace(HOST_IF.encode(), host.encode())
    inherited_fds = fixed.inherited_fds
    if fixed.command_id is Action.NFT_REMOVE_ATOMIC:
        if target is None or target.get("nft") is None: raise NetworkError("exact nft removal target required")
        handle = target["nft"]["table_handle"]
        if type(handle) is not int or handle <= 0: raise NetworkError("exact nft table handle")
        stdin = stdin.replace(TABLE_HANDLE.encode(), str(handle).encode())
        inherited_fds = (nft_owner.LOCK_TARGET_FD,)
    return process.FixedCommand(fixed.command_id, fixed.executable_role, fixed.executable_path,
        argv, stdin, fixed.duration_ns, fixed.stdout_limit, fixed.stderr_limit,
        fixed.output_grammar, inherited_fds)


def _perform_fixed(journal, action, ip, nft, tc, target=None, endpoint=None):
    import completion_kata_operation as operation
    import completion_kata_process as process
    source = process._FIXED_COMMANDS[action]
    if endpoint is not None:
        source = process.FixedCommand(action, "tc", "/usr/sbin/tc",
            ("/usr/sbin/tc", *tc_observer_command(action, endpoint).argv_tail), b"",
            source.duration_ns, source.stdout_limit, source.stderr_limit, "json", ())
    fixed = _bound_fixed(journal, source, target)
    inherited = ()
    if action in {Action.NFT_INSTALL, Action.NFT_INSTALL_OWNED, Action.NFT_REMOVE,
                  Action.NFT_REMOVE_ATOMIC}:
        nft_owner.require_active(journal)
    if action is Action.NFT_REMOVE_ATOMIC:
        inherited = nft_owner.claim_child_binding(journal)
    executable = ip if fixed.executable_role == "ip" else nft if fixed.executable_role == "nft" else tc
    outcome, durable = process._transact_fixed(journal, fixed, executable, inherited)
    operation._durable_command_output(
        journal, durable.command_serial, durable.command_id, durable.binding_sha256,
        outcome.stdout, outcome.stderr,
    )
    if (outcome.outcome != "exited" or outcome.status != 0 or outcome.stderr
            or outcome.stdout_truncated or outcome.stderr_truncated or outcome.errors
            or not outcome.reaped):
        raise NetworkError(
            f"fixed network command failed:{fixed.command_id.value}:{outcome.outcome}:"
            f"{outcome.status}:{len(outcome.stdout)}:{len(outcome.stderr)}:"
            f"{int(outcome.stdout_truncated)}:{int(outcome.stderr_truncated)}:"
            f"{len(outcome.errors)}:{int(outcome.reaped)}")
    _record_observation(journal, action.value + ((":" + endpoint.ifname) if endpoint is not None else ""),
                        outcome.stdout, durable.command_serial)
    return outcome.stdout


def _read_mountinfo():
    with open("/proc/self/mountinfo", "rb", buffering=0) as source:
        raw = source.read(MAX_MOUNTINFO_BYTES + 1)
    if len(raw) > MAX_MOUNTINFO_BYTES or not raw.endswith(b"\n"):
        raise NetworkError("bounded complete mountinfo required")
    return raw


def _mount_identity(path, raw=None):
    raw = _read_mountinfo() if raw is None else raw
    try: lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError as error: raise NetworkError("parent mountinfo encoding") from error
    found = []
    for line in lines:
        fields = line.split(" ")
        if fields.count("-") != 1: raise NetworkError("parent mountinfo separator")
        separator = fields.index("-")
        if separator < 6 or len(fields) != separator + 4 or not _DEVICE.fullmatch(fields[2]):
            raise NetworkError("parent mountinfo shape")
        point = _OCTAL.sub(lambda match: chr(int(match.group(1), 8)), fields[4])
        if point == path:
            try: mount_id, parent_id = int(fields[0]), int(fields[1])
            except ValueError as error: raise NetworkError("parent mount identity") from error
            observed = os.stat(path, follow_symlinks=False)
            found.append({"mount_id": _uint(mount_id), "parent_id": _uint(parent_id),
                "device": fields[2], "root": fields[3], "mount_point": point,
                "mount_options": fields[5].split(","), "optional_fields": fields[6:separator],
                "fs_type": fields[separator + 1], "source": fields[separator + 2],
                "super_options": fields[separator + 3].split(","),
                "inode_device": observed.st_dev, "inode": observed.st_ino})
    if len(found) > 1: raise NetworkError("netns parent mount cardinality")
    return None if not found else found[0]


def _netns_parent_mount(raw=None):
    identity = _mount_identity("/run/netns", raw)
    return None if identity is None else (identity["root"], identity["fs_type"], identity["source"],
                                          tuple(identity["optional_fields"]))


def _parent_mount_record(journal, identity):
    import completion_kata_operation as operation
    body = {"operation_token": operation._command_context(journal).operation_token,
            "policy_version": operation.network_journal.POLICY_VERSION,
            "parent_mount": identity, "proof_sha256": ZERO}
    body["proof_sha256"] = hashlib.sha256(operation._canonical({name: value for name, value in body.items()
        if name != "proof_sha256"})).hexdigest()
    operation._record_network(journal, operation.network_journal.PARENT_MOUNT_RECORD, body)


def _prepare_netns_parent(journal=None):
    import completion_kata_operation as operation
    rows = ([] if journal is None else [body["parent_mount"] for kind, body in
        operation._network_history(journal) if kind == operation.network_journal.PARENT_MOUNT_RECORD])
    observed = _mount_identity("/run/netns")
    libc = ctypes.CDLL(None, use_errno=True)
    if observed is None:
        if rows: raise NetworkError("durable private parent mount absent")
        if libc.mount(b"/run/netns", b"/run/netns", None, 4096, None) != 0:
            saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
    elif observed["root"] != "/netns" or observed["fs_type"] != "tmpfs" or observed["source"] != "tmpfs":
        raise NetworkError("foreign netns parent mount")
    if not rows and libc.mount(None, b"/run/netns", None, 1 << 18, None) != 0:
        saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
    settled = _mount_identity("/run/netns")
    if (settled is None or settled["root"] != "/netns" or settled["fs_type"] != "tmpfs"
            or settled["source"] != "tmpfs" or settled["optional_fields"]):
        raise NetworkError("private netns parent mount absent")
    if rows:
        if len(rows) != 1 or settled != rows[0]: raise NetworkError("private parent mount replacement")
    elif journal is not None: _parent_mount_record(journal, settled)
    return settled


def _netns_identity(journal=None, raw=None, name=None):
    raw = _read_mountinfo() if raw is None else raw
    if journal is not None: _record_observation(journal, "MOUNTINFO", raw)
    name = name or (NETNS if journal is None else _bound_names(journal)[0])
    path = "/run/netns/" + name
    try:
        observed = os.stat(path, follow_symlinks=False)
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise NetworkError("netns stat uncertainty") from error
        try:
            lines = raw.decode("utf-8", "strict").splitlines()
        except UnicodeError as decode_error:
            raise NetworkError("mountinfo encoding") from decode_error
        if not lines or len(lines) > MAX_MOUNTINFO_LINES:
            raise NetworkError("complete mountinfo count")
        for line in lines:
            fields = line.split(" ")
            if fields.count("-") != 1:
                raise NetworkError("mountinfo separator")
            separator = fields.index("-")
            if separator < 6 or len(fields) != separator + 4 or not _DEVICE.fullmatch(fields[2]):
                raise NetworkError("mountinfo shape")
            point = _OCTAL.sub(lambda match: chr(int(match.group(1), 8)), fields[4])
            if point == path:
                raise NetworkError("netns path/mount contradiction")
        if journal is not None: _record_observation(journal, "NETNS_STAT", b"null")
        return None
    try: result = parse_netns_identity(raw, NetnsStat(observed.st_dev, observed.st_ino), path)
    except NetworkError:
        planned = _original_placeholder(journal) if journal is not None and name == _bound_names(journal)[0] else None
        if journal is not None and name == _quarantine_name(journal):
            stage = _quarantine_stage(journal); planned = None if stage is None else stage[1]["placeholder"]
        if planned is None or (observed.st_dev, observed.st_ino) != (planned["device"], planned["inode"]): raise
        if journal is not None: _record_observation(journal, "NETNS_STAT", b"null")
        return None
    if journal is not None:
        stat_raw = json.dumps({"device": observed.st_dev, "inode": observed.st_ino},
                              sort_keys=True, separators=(",", ":")).encode()
        _record_observation(journal, "NETNS_STAT", stat_raw)
    return result


def _support_ownership(journal=None):
    import completion_kata_operation as operation
    rows = ([] if journal is None else [body["support"] for kind, body in operation._network_history(journal)
        if kind == operation.network_journal.SUPPORT_RECORD])
    observed = {}
    for key, path in (("preserved_directory", PRESERVED_DIR),
                      ("parent_stage_directory", PARENT_STAGE_DIR)):
        if not rows:
            try: os.mkdir(path, 0o700)
            except FileExistsError: pass
        stat = os.stat(path, follow_symlinks=False)
        if (not os.path.isdir(path) or stat.st_uid != 0 or stat.st_gid != 0
                or stat.st_mode & 0o7777 != 0o700):
            raise NetworkError("cleanup support directory replacement")
        observed[key] = _placeholder_identity(stat)
    if rows:
        if (len(rows) != 1 or any(not _same_directory_owner(observed[name], rows[0][name])
                                  for name in observed)):
            raise NetworkError("cleanup support ownership replacement")
        return rows[0]
    elif journal is not None:
        body = {"operation_token": operation._command_context(journal).operation_token,
                "policy_version": operation.network_journal.POLICY_VERSION,
                "support": observed, "proof_sha256": ZERO}
        body["proof_sha256"] = hashlib.sha256(operation._canonical({name: value for name, value in body.items()
            if name != "proof_sha256"})).hexdigest()
        operation._record_network(journal, operation.network_journal.SUPPORT_RECORD, body)
    return observed


def _preserved_directory():
    _support_ownership()
    return os.open(PRESERVED_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def _placeholder_identity(value):
    return {"device": value.st_dev, "inode": value.st_ino, "mode": value.st_mode & 0o7777,
            "uid": value.st_uid, "gid": value.st_gid, "nlink": value.st_nlink, "size": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns}


def _original_placeholder_record(journal, identity):
    import completion_kata_operation as operation
    body = {"operation_token": operation._command_context(journal).operation_token,
            "policy_version": operation.network_journal.POLICY_VERSION,
            "original_name": _bound_names(journal)[0], "placeholder": identity, "proof_sha256": ZERO}
    body["proof_sha256"] = hashlib.sha256(operation._canonical({name: value for name, value in body.items()
        if name != "proof_sha256"})).hexdigest()
    operation._record_network(journal, operation.network_journal.ORIGINAL_PLACEHOLDER_RECORD, body)


def _original_placeholder(journal):
    import completion_kata_operation as operation
    rows = [body for kind, body in operation._network_history(journal)
            if kind == operation.network_journal.ORIGINAL_PLACEHOLDER_RECORD]
    return None if not rows else rows[-1]["placeholder"]


def _created_nsfs_identity(descriptor):
    import completion_kata_process as process
    stat = os.fstat(descriptor); generation = process._host_generation(descriptor)
    return {"mount_id": generation["mount_id"],
            "device": f"{os.major(stat.st_dev)}:{os.minor(stat.st_dev)}",
            "inode_device": stat.st_dev, "inode": stat.st_ino}


def _created_nsfs_record(journal, helper_pid, identity):
    import completion_kata_operation as operation
    body = {"operation_token": operation._command_context(journal).operation_token,
            "policy_version": operation.network_journal.POLICY_VERSION,
            "helper_pid": helper_pid, "identity": identity, "proof_sha256": ZERO}
    body["proof_sha256"] = hashlib.sha256(operation._canonical({name: value for name, value in body.items()
        if name != "proof_sha256"})).hexdigest()
    operation._record_network(journal, operation.network_journal.CREATED_NSFS_RECORD, body)


def _created_nsfs(journal):
    import completion_kata_operation as operation
    rows = [body for kind, body in operation._network_history(journal)
            if kind == operation.network_journal.CREATED_NSFS_RECORD]
    return None if not rows else rows[-1]["identity"]


def _quarantine_name(journal):
    return "c42q" + _bound_names(journal)[0][4:]


def _quarantine_record(journal, kind, retained, placeholder=None, preserved=None):
    import completion_kata_operation as operation
    body = {"operation_token": operation._command_context(journal).operation_token,
            "policy_version": operation.network_journal.POLICY_VERSION,
            "original_name": _bound_names(journal)[0], "quarantine_name": _quarantine_name(journal),
            "target": retained, "placeholder": placeholder, "preserved": preserved, "proof_sha256": ZERO}
    body["proof_sha256"] = hashlib.sha256(operation._canonical({name: value for name, value in body.items()
        if name != "proof_sha256"})).hexdigest()
    operation._record_network(journal, kind, body)


def _quarantine_stage(journal):
    import completion_kata_operation as operation
    rows = [(kind, body) for kind, body in operation._network_history(journal)
            if kind in operation.network_journal.QUARANTINE_RECORDS]
    return None if not rows else rows[-1]


def _establish_netns(journal):
    """Create, retain, and journal the inode before the exact bind mount."""
    _prepare_netns_parent(journal)
    name = _bound_names(journal)[0]; parent = os.open("/run/netns", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    opened = [parent]; helper_pid = None; helper_waited = False
    try:
        planned = _original_placeholder(journal)
        try: observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: observed = None
        if observed is None:
            temporary = os.open("/run/netns", os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC, 0o600); opened.append(temporary)
            stat = os.fstat(temporary); planned = _placeholder_identity(stat)
            _original_placeholder_record(journal, planned)
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.linkat(temporary, b"", parent, name.encode(), 0x1000) != 0:
                saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
            planned = _placeholder_identity(os.fstat(temporary))
            _original_placeholder_record(journal, planned)
            descriptor = os.open(
                name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            opened.append(descriptor)
            if _placeholder_identity(os.fstat(descriptor)) != planned:
                raise NetworkError("linked placeholder descriptor drift")
        else:
            mounted = None; mount_error = None
            try: mounted = _netns_identity(journal=None, name=name)
            except NetworkError as error: mount_error = error
            if mounted is not None:
                created = _created_nsfs(journal)
                if created is None or any(getattr(mounted, field) != created[field]
                        for field in ("device", "inode_device", "inode")):
                    _poison_fixed_network(journal, "replaced")
                    raise NetworkError("mounted namespace differs from created nsfs")
                _record_observation(journal, Action.IP_NETNS_ADD.value, b"", None); return
            observed_identity = _placeholder_identity(observed)
            if planned is None or (observed.st_dev, observed.st_ino) != (planned["device"], planned["inode"]):
                _poison_fixed_network(journal, "replaced")
                if mount_error is not None:
                    raise NetworkError(f"mounted namespace identity invalid:{mount_error}") from mount_error
                raise NetworkError("original namespace placeholder replacement")
            if observed_identity != planned:
                if planned["nlink"] != 0 or observed_identity["nlink"] != 1:
                    raise NetworkError(
                        f"linked placeholder drift:{planned['nlink']}:{observed_identity['nlink']}")
                planned = observed_identity; _original_placeholder_record(journal, planned)
            descriptor = os.open(name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW,
                                 dir_fd=parent); opened.append(descriptor)
        # This is the final name lookup before the operation-unique bind mount;
        # retained source/target descriptors and the post-mount nsfs proof detect drift.
        descriptor_identity = _placeholder_identity(os.fstat(descriptor))
        path_identity = _placeholder_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
        if descriptor_identity != planned or path_identity != planned:
            raise NetworkError("pre-bind placeholder replacement")
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC); release_r, release_w = os.pipe2(os.O_CLOEXEC)
        opened.extend((ready_r, ready_w, release_r, release_w))
        child = os.fork(); helper_pid = child
        if child == 0:
            os.close(ready_r); os.close(release_w)
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.unshare(0x40000000) != 0: os._exit(121)
            source_fd = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
            if os.write(ready_w, b"R") != 1 or os.read(release_r, 1) != b"B": os._exit(122)
            if os.write(ready_w, b"M") != 1 or os.read(release_r, 1) != b"A": os._exit(124)
            os._exit(0)
        os.close(ready_w); os.close(release_r)
        if os.read(ready_r, 1) != b"R": raise NetworkError("namespace helper readiness")
        source_path = f"/proc/{child}/ns/net"
        source_fd = os.open(source_path, os.O_RDONLY | os.O_CLOEXEC); opened.append(source_fd)
        created = _created_nsfs_identity(source_fd); _created_nsfs_record(journal, child, created)
        if _created_nsfs_identity(source_fd) != created: raise NetworkError("created nsfs changed before bind")
        if os.write(release_w, b"B") != 1 or os.read(ready_r, 1) != b"M":
            raise NetworkError("namespace helper release")
        if _created_nsfs_identity(source_fd) != created:
            raise NetworkError("created nsfs changed at bind")
        libc = ctypes.CDLL(None, use_errno=True)
        target_path = "/run/netns/" + name
        if libc.mount(source_path.encode(), target_path.encode(), None, 4096, None) != 0:
            saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
        identity = _netns_identity(journal=None, name=name)
        if identity is None or any(getattr(identity, field) != created[field]
                                   for field in ("device", "inode_device", "inode")):
            raise NetworkError("bound namespace differs from created nsfs")
        if os.write(release_w, b"A") != 1: raise NetworkError("namespace mount settlement")
        os.close(ready_r); os.close(release_w)
        _pid, status = os.waitpid(child, 0); helper_waited = True
        helper_status = os.waitstatus_to_exitcode(status)
        if helper_status != 0:
            raise NetworkError(f"fixed namespace bind helper:{helper_status}")
        if _netns_identity(journal=None, name=name) != identity:
            raise NetworkError("settled namespace mount drift")
        _record_observation(journal, Action.IP_NETNS_ADD.value, b"", None)
    finally:
        for descriptor in reversed(opened):
            try: os.close(descriptor)
            except OSError: pass
        if helper_pid not in {None, 0} and not helper_waited:
            try: os.waitpid(helper_pid, 0)
            except ChildProcessError: pass


def _quarantine_netns(journal, retained):
    original, quarantine = _bound_names(journal)[0], _quarantine_name(journal)
    expected = retained["netns"]; fields = ("mount_id", "parent_id", "device", "inode_device", "inode")
    parent = os.open("/run/netns", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    held = None; opened = []
    try:
        stage_row = _quarantine_stage(journal); stage = None if stage_row is None else stage_row[0]
        placeholder = None if stage_row is None else stage_row[1]["placeholder"]
        preserved = None if stage_row is None else stage_row[1]["preserved"]
        def open_identity(name):
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
            opened.append(descriptor)
            stat = os.fstat(descriptor)
            identity = parse_netns_identity(_read_mountinfo(), NetnsStat(stat.st_dev, stat.st_ino), "/run/netns/" + name)
            return descriptor, identity
        source = moved = None
        try: source = open_identity(original)
        except (FileNotFoundError, NetworkError): pass
        try: moved = open_identity(quarantine)
        except (FileNotFoundError, NetworkError): pass
        if stage is None:
            if source is None or any(getattr(source[1], name) != expected[name] for name in fields):
                raise NetworkError("retained nsfs changed before quarantine intent")
            held = source[0]; _quarantine_record(journal, "NETWORK_QUARANTINE_INTENT_V2", retained)
            stage = "NETWORK_QUARANTINE_INTENT_V2"
        if stage in {"NETWORK_QUARANTINE_INTENT_V2", "NETWORK_QUARANTINE_PLACEHOLDER_V2"}:
            if moved is None:
                if source is None or any(getattr(source[1], name) != expected[name] for name in fields):
                    raise NetworkError("retained nsfs changed before move")
                fresh_source = open_identity(original)
                if (any(getattr(fresh_source[1], name) != expected[name] for name in fields) or
                        (os.fstat(fresh_source[0]).st_dev, os.fstat(fresh_source[0]).st_ino) !=
                        (os.fstat(held or source[0]).st_dev, os.fstat(held or source[0]).st_ino)):
                    raise NetworkError("retained nsfs path changed before move")
                libc = ctypes.CDLL(None, use_errno=True); syscall = libc.syscall
                tree_fd = syscall(428, parent, original.encode(), 0x80000)  # open_tree, O_CLOEXEC
                if tree_fd < 0: saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
                opened.append(tree_fd)
                tree_stat = os.fstat(tree_fd); retained_stat = os.fstat(held or source[0])
                if (tree_stat.st_dev, tree_stat.st_ino) != (retained_stat.st_dev, retained_stat.st_ino):
                    raise NetworkError("open_tree retained mount mismatch")
                try: existing_placeholder = os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: existing_placeholder = None
                if existing_placeholder is None:
                    target_fd = os.open("/run/netns", os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC, 0o600)
                    opened.append(target_fd); planned = os.fstat(target_fd)
                    placeholder = _placeholder_identity(planned)
                    _quarantine_record(journal, "NETWORK_QUARANTINE_PLACEHOLDER_V2", retained, placeholder)
                    stage = "NETWORK_QUARANTINE_PLACEHOLDER_V2"
                    if libc.linkat(target_fd, b"", parent, quarantine.encode(), 0x1000) != 0:  # AT_EMPTY_PATH
                        saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
                else:
                    if (stage != "NETWORK_QUARANTINE_PLACEHOLDER_V2" or placeholder is None or
                            (existing_placeholder.st_dev, existing_placeholder.st_ino) !=
                            (placeholder["device"], placeholder["inode"])):
                        raise NetworkError("unowned quarantine placeholder preserved")
                    target_fd = os.open(quarantine, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
                    opened.append(target_fd)
                target_stat = os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
                if (placeholder is None or (target_stat.st_dev, target_stat.st_ino) !=
                        (placeholder["device"], placeholder["inode"])):
                    raise NetworkError("quarantine target changed before move")
                if libc.mount(("/run/netns/" + original).encode(),
                              ("/run/netns/" + quarantine).encode(), None, 8192, None) != 0:
                    saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
                moved = open_identity(quarantine)
            if any(getattr(moved[1], name) != expected[name] for name in fields):
                raise NetworkError("quarantined nsfs identity mismatch")
            revealed = os.stat(original, dir_fd=parent, follow_symlinks=False)
            original_placeholder = _original_placeholder(journal)
            if original_placeholder is None or (revealed.st_dev, revealed.st_ino) != (
                    original_placeholder["device"], original_placeholder["inode"]):
                raise NetworkError("revealed original placeholder replacement")
            preserved = {"name": original, "device": revealed.st_dev, "inode": revealed.st_ino}
            _quarantine_record(journal, "NETWORK_QUARANTINE_MOVED_V2", retained, placeholder, preserved)
            stage = "NETWORK_QUARANTINE_MOVED_V2"
        if stage == "NETWORK_QUARANTINE_MOVED_V2":
            # Keep the pre-bind inode at its original name; no name mutation can
            # relocate a replacement between validation and preservation.
            observed_placeholder = os.stat(original, dir_fd=parent, follow_symlinks=False)
            if (observed_placeholder.st_dev, observed_placeholder.st_ino) != (preserved["device"], preserved["inode"]):
                raise NetworkError("revealed placeholder replacement preserved")
            _quarantine_record(journal, "NETWORK_QUARANTINE_SETTLED_V2", retained, placeholder, preserved)
        _descriptor, observed = open_identity(quarantine)
        if any(getattr(observed, name) != expected[name] for name in fields):
            raise NetworkError("settled quarantine identity mismatch")
        return observed
    finally:
        for descriptor in set(opened):
            try: os.close(descriptor)
            except OSError: pass
        os.close(parent)


def _descriptor_remove_netns(journal, retained):
    """Detach only the retained nsfs mount; preserve both regular placeholders."""
    quarantine = _quarantine_name(journal); expected = retained["netns"]
    stage = _quarantine_stage(journal)
    if stage is None or stage[0] not in {"NETWORK_QUARANTINE_SETTLED_V2", "NETWORK_DETACH_INTENT_V2",
                                         "NETWORK_DETACHED_V2"} or stage[1]["placeholder"] is None:
        raise NetworkError("settled quarantine placeholder absent")
    placeholder = stage[1]["placeholder"]
    if stage[0] == "NETWORK_QUARANTINE_SETTLED_V2":
        _quarantine_record(journal, "NETWORK_DETACH_INTENT_V2", retained, placeholder, stage[1]["preserved"])
        stage = _quarantine_stage(journal)
    parent = os.open("/run/netns", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC); opened = [parent]
    try:
        try: exposed = os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: raise NetworkError("quarantine placeholder absent")
        if stage[0] == "NETWORK_DETACHED_V2":
            if (exposed.st_dev, exposed.st_ino) != (stage[1]["preserved"]["device"], stage[1]["preserved"]["inode"]):
                raise NetworkError("detached placeholder replacement")
            _record_observation(journal, Action.IP_NETNS_REMOVE.value, b"", None); return
        if (exposed.st_dev, exposed.st_ino) == (expected["inode_device"], expected["inode"]):
            libc = ctypes.CDLL(None, use_errno=True); tree_fd = libc.syscall(428, parent, quarantine.encode(), 0x80000)
            if tree_fd < 0: saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
            opened.append(tree_fd); stat = os.fstat(tree_fd)
            if (stat.st_dev, stat.st_ino) != (expected["inode_device"], expected["inode"]): raise NetworkError("quarantine mount replacement")
            if libc.umount2(("/run/netns/" + quarantine).encode(), 2) != 0:
                saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
            exposed = os.stat(quarantine, dir_fd=parent, follow_symlinks=False)
        if (exposed.st_dev, exposed.st_ino) != (placeholder["device"], placeholder["inode"]):
            raise NetworkError("post-detach placeholder replacement")
        detached = {"name": quarantine, "device": exposed.st_dev, "inode": exposed.st_ino}
        _quarantine_record(journal, "NETWORK_DETACHED_V2", retained, placeholder, detached)
        _record_observation(journal, Action.IP_NETNS_REMOVE.value, b"", None)
    finally:
        for descriptor in reversed(opened):
            try: os.close(descriptor)
            except OSError: pass


def _cleanup_rows(journal):
    import completion_kata_operation as operation
    return [(kind, body) for kind, body in operation._network_history(journal)
            if kind in {operation.network_journal.DETACHED_CLEANUP_INTENT,
                        operation.network_journal.DETACHED_CLEANUP_STEP}]


def _cleanup_record(journal, kind, **values):
    import completion_kata_operation as operation
    body = {"operation_token": operation._command_context(journal).operation_token,
            "policy_version": operation.network_journal.POLICY_VERSION, **values,
            "proof_sha256": ZERO}
    body["proof_sha256"] = hashlib.sha256(operation._canonical({name: value for name, value in body.items()
        if name != "proof_sha256"})).hexdigest()
    operation._record_network(journal, kind, body)


def _same_file_owner(observed, expected):
    return all(observed[name] == expected[name] for name in
               ("device", "inode", "mode", "uid", "gid", "nlink", "size", "mtime_ns"))


def _same_directory_owner(observed, expected):
    return all(observed[name] == expected[name] for name in
               ("device", "inode", "mode", "uid", "gid"))


def _open_owned(parent, name, expected, directory=False, stable=False):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if directory: flags |= os.O_DIRECTORY
    descriptor = os.open(name, flags, dir_fd=parent)
    observed = _placeholder_identity(os.fstat(descriptor))
    matched = (_same_directory_owner(observed, expected) if directory else
               _same_file_owner(observed, expected))
    if (not matched if stable else observed != expected):
        os.close(descriptor); raise NetworkError("cleanup replacement preserved")
    return descriptor


def _rename_noreplace(source_parent, source, target_parent, target):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(source_parent, source.encode(), target_parent, target.encode(), 1) != 0:
        saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))


def _cleanup_owned_entry(journal, resource, source_parent, source, target_parent, target,
                         expected, directory=False):
    import completion_kata_operation as operation
    steps = {(body["resource"], body["action"]): body["identity"] for kind, body in _cleanup_rows(journal)
             if kind == operation.network_journal.DETACHED_CLEANUP_STEP}
    relocated_identity = steps.get((resource, "relocated")); removed = (resource, "removed") in steps
    if relocated_identity is None:
        try: target_stat = os.stat(target, dir_fd=target_parent, follow_symlinks=False)
        except FileNotFoundError: target_stat = None
        try: source_stat = os.stat(source, dir_fd=source_parent, follow_symlinks=False)
        except FileNotFoundError: source_stat = None
        if target_stat is not None and source_stat is None:
            held = _open_owned(target_parent, target, expected, directory, True)
        else:
            observed_source = None if source_stat is None else _placeholder_identity(source_stat)
            matched_source = (False if observed_source is None else
                              _same_directory_owner(observed_source, expected) if directory else
                              _same_file_owner(observed_source, expected))
            if target_stat is not None or not matched_source:
                raise NetworkError("cleanup relocation replacement preserved")
            held = _open_owned(source_parent, source, expected, directory, True)
            _rename_noreplace(source_parent, source, target_parent, target)
            retained_identity = _placeholder_identity(os.fstat(held))
            if not (_same_directory_owner(retained_identity, expected) if directory else
                    _same_file_owner(retained_identity, expected)):
                os.close(held); raise NetworkError("cleanup retained descriptor changed")
            post = _open_owned(target_parent, target, expected, directory, True); os.close(post)
            try: os.stat(source, dir_fd=source_parent, follow_symlinks=False)
            except FileNotFoundError: pass
            else: os.close(held); raise NetworkError("cleanup source replacement preserved")
        relocated_identity = _placeholder_identity(os.fstat(held)); os.close(held)
        os.fsync(source_parent); os.fsync(target_parent)
        _cleanup_record(journal, operation.network_journal.DETACHED_CLEANUP_STEP,
                        resource=resource, action="relocated", identity=relocated_identity)
    if removed: return
    try: os.stat(source, dir_fd=source_parent, follow_symlinks=False)
    except FileNotFoundError: pass
    else: raise NetworkError("cleanup post-relocation replacement preserved")
    try: held = _open_owned(target_parent, target, relocated_identity, directory)
    except FileNotFoundError:
        held = None
    if held is not None:
        before = os.fstat(held)
        (os.rmdir if directory else os.unlink)(target, dir_fd=target_parent)
        after = os.fstat(held); os.close(held)
        if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or after.st_nlink != 0):
            raise NetworkError("cleanup unlink identity uncertainty")
        os.fsync(target_parent)
    _cleanup_record(journal, operation.network_journal.DETACHED_CLEANUP_STEP,
                    resource=resource, action="removed", identity=relocated_identity)


def _cleanup_parent_mount(journal, authority):
    """Detach only the exact retained private mount; exact absence settles a crash cut."""
    import completion_kata_operation as operation
    steps = [(body["resource"], body["action"], body["identity"]) for kind, body in _cleanup_rows(journal)
             if kind == operation.network_journal.DETACHED_CLEANUP_STEP]
    expected = authority["parent_mount"]
    detached = {**expected, "mount_point": ""}
    relocated = next((identity for resource, action, identity in steps
                      if (resource, action) == ("parent-mount", "relocated")), None)
    if relocated is None:
        current = _mount_identity("/run/netns")
        if current is not None:
            if current != expected: raise NetworkError("private parent mount replacement preserved")
            libc = ctypes.CDLL(None, use_errno=True); tree = libc.syscall(428, -100, b"/run/netns", 0x80000)
            if tree < 0: saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
            try:
                retained = os.fstat(tree)
                if (retained.st_dev, retained.st_ino) != (expected["inode_device"], expected["inode"]):
                    raise NetworkError("private parent mount descriptor mismatch")
                if libc.umount2(b"/run/netns", 2) != 0:
                    saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
                if (_mount_identity("/run/netns") is not None or
                        (os.fstat(tree).st_dev, os.fstat(tree).st_ino) != (retained.st_dev, retained.st_ino)):
                    raise NetworkError("private parent unmount uncertainty")
            finally: os.close(tree)
        if _mount_identity(PARENT_STAGE_DIR) is not None:
            raise NetworkError("foreign parent staging mount preserved")
        relocated = detached
        _cleanup_record(journal, operation.network_journal.DETACHED_CLEANUP_STEP,
                        resource="parent-mount", action="relocated", identity=relocated)
    if relocated != detached or _mount_identity("/run/netns") is not None or _mount_identity(PARENT_STAGE_DIR) is not None:
        raise NetworkError("detached parent mount replacement preserved")
    if any((resource, action) == ("parent-mount", "removed") for resource, action, _identity in steps): return
    _cleanup_record(journal, operation.network_journal.DETACHED_CLEANUP_STEP,
                    resource="parent-mount", action="removed", identity=relocated)


def _cleanup_authority(journal, original, quarantine, stage):
    import completion_kata_operation as operation
    rows = _cleanup_rows(journal)
    intents = [body["authority"] for kind, body in rows
               if kind == operation.network_journal.DETACHED_CLEANUP_INTENT]
    if intents:
        if len(intents) != 1: raise NetworkError("detached cleanup authority cardinality")
        return intents[0]
    support_rows = [body["support"] for kind, body in operation._network_history(journal)
                    if kind == operation.network_journal.SUPPORT_RECORD]
    mount_rows = [body["parent_mount"] for kind, body in operation._network_history(journal)
                  if kind == operation.network_journal.PARENT_MOUNT_RECORD]
    if len(support_rows) != 1 or len(mount_rows) != 1: raise NetworkError("durable cleanup ownership absent")
    if _support_ownership(journal) != support_rows[0] or _mount_identity("/run/netns") != mount_rows[0]:
        raise NetworkError("durable cleanup support replacement preserved")
    placeholders = {}
    for key, name, prior in (("original", original, _original_placeholder(journal)),
                             ("quarantine", quarantine, stage[1]["placeholder"])):
        if prior is None: raise NetworkError("detached placeholder identity absent")
        observed = os.stat("/run/netns/" + name, follow_symlinks=False)
        if (observed.st_dev, observed.st_ino) != (prior["device"], prior["inode"]):
            raise NetworkError("detached placeholder replacement preserved")
        placeholders[key] = _placeholder_identity(observed)
    authority = {"support": support_rows[0], "parent_mount": mount_rows[0],
                 "placeholders": placeholders}
    _cleanup_record(journal, operation.network_journal.DETACHED_CLEANUP_INTENT, authority=authority)
    return authority


def _cleanup_detached_owned(journal):
    """Relocate exact durable owners into retained private directories before unlink."""
    original, quarantine = _bound_names(journal)[0], _quarantine_name(journal)
    stage = _quarantine_stage(journal)
    if stage is None or stage[0] != "NETWORK_DETACHED_V2":
        raise NetworkError("detached placeholder cleanup authority")
    authority = _cleanup_authority(journal, original, quarantine, stage)
    completed = {(body["resource"], body["action"]) for kind, body in _cleanup_rows(journal)
                 if kind.endswith("STEP_V3")}
    if not all((resource, "removed") in completed for resource in
               ("original-placeholder", "quarantine-placeholder")):
        parent = os.open("/run/netns", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        preserved = os.open(PRESERVED_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            parent_stat = os.fstat(parent)
            if (parent_stat.st_dev, parent_stat.st_ino) != (authority["parent_mount"]["inode_device"],
                                                            authority["parent_mount"]["inode"]):
                raise NetworkError("private parent descriptor replacement")
            if not _same_directory_owner(_placeholder_identity(os.fstat(preserved)),
                                         authority["support"]["preserved_directory"]):
                raise NetworkError("preserved directory descriptor replacement")
            suffix = _bound_names(journal)[0][4:]
            _cleanup_owned_entry(journal, "original-placeholder", parent, original, preserved,
                                 "c42p" + suffix + "-original", authority["placeholders"]["original"])
            _cleanup_owned_entry(journal, "quarantine-placeholder", parent, quarantine, preserved,
                                 "c42p" + suffix + "-quarantine", authority["placeholders"]["quarantine"])
        finally: os.close(preserved); os.close(parent)
    completed = {(body["resource"], body["action"]) for kind, body in _cleanup_rows(journal)
                 if kind.endswith("STEP_V3")}
    if ("preserved-directory", "removed") not in completed:
        parent = os.open("/run/netns", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            _cleanup_owned_entry(journal, "preserved-directory", parent, os.path.basename(PRESERVED_DIR),
                                 parent, PRESERVED_REMOVING, authority["support"]["preserved_directory"], True)
        finally: os.close(parent)
    _cleanup_parent_mount(journal, authority)
    run = os.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _cleanup_owned_entry(journal, "parent-stage-directory", run, os.path.basename(PARENT_STAGE_DIR),
                             run, PARENT_STAGE_REMOVING,
                             authority["support"]["parent_stage_directory"], True)
    finally: os.close(run)


def _cleanup_detached_placeholders(journal):
    try: return _cleanup_detached_owned(journal)
    except NetworkError:
        _poison_fixed_network(journal, "replaced")
        raise


def _normalize_baseline_links(links):
    normalized = json.loads(json.dumps(links))
    for row in normalized:
        linkinfo = row.get("linkinfo") if type(row) is dict else None
        if type(linkinfo) is dict and linkinfo.get("info_kind") == "bridge":
            data = linkinfo.get("info_data")
            if type(data) is not dict: raise NetworkError("bridge link detail")
            for name in ("hello_timer", "tcn_timer", "topology_change_timer", "gc_timer"):
                value = data.get(name)
                if (type(value) not in (int, float) or type(value) is bool
                        or not math.isfinite(value) or value < 0):
                    raise NetworkError("bridge timer metric")
                data[name] = 0
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()


def _normalize_baseline_nft(value):
    """Preserve complete ruleset objects while excluding traffic-only counters."""
    normalized = json.loads(json.dumps(value))
    def walk(item, depth=0):
        if depth > 32: raise NetworkError("nft normalization depth")
        if type(item) is list:
            for child in item: walk(child, depth + 1)
        elif type(item) is dict:
            counter = item.get("counter")
            if type(counter) is dict and {"packets", "bytes"} <= set(counter):
                if (type(counter["packets"]) is not int or counter["packets"] < 0 or
                        type(counter["bytes"]) is not int or counter["bytes"] < 0):
                    raise NetworkError("nft counter metric")
                counter["packets"] = counter["bytes"] = 0
            for child in item.values(): walk(child, depth + 1)
    walk(normalized)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()


def _pre_admission_host_links_binding(raw):
    """Bind every host link, waiting for an announced Hyper-V VF attachment."""
    links = _load(raw)
    if (type(links) is not list or not links or any(type(row) is not dict for row in links)
            or any(type(row.get("ifindex")) is not int or type(row.get("ifname")) is not str
                   or not row["ifname"] or type(row.get("flags")) is not list
                   or any(type(flag) is not str for flag in row["flags"]) for row in links)
            or len({row["ifindex"] for row in links}) != len(links)
            or len({row["ifname"] for row in links}) != len(links)):
        raise NetworkError("pre-admission host link inventory")
    hyperv = [row for row in links if row.get("parentbus") == "vmbus"]
    for master in hyperv:
        address = master.get("address")
        attached = [row for row in links if (
            row.get("master") == master["ifname"] and row.get("parentbus") == "pci"
            and row.get("address") == address and "SLAVE" in row["flags"]
            and type(master.get("tso_max_size")) is int
            and row.get("tso_max_size") == master["tso_max_size"]
            and type(row.get("parentdev")) is str
            and re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", row["parentdev"]))]
        if type(address) is not str or len(attached) != 1:
            return None
    return hashlib.sha256(_normalize_baseline_links(links)).hexdigest()


def _exact_unmounted_placeholder(raw, name, expected):
    full = {"device", "inode", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"}
    if type(expected) is not dict or set(expected) not in ({"device", "inode"}, full):
        return False
    try: observed = os.stat("/run/netns/" + name, follow_symlinks=False)
    except FileNotFoundError: return False
    except OSError as error: raise NetworkError("placeholder stat uncertainty") from error
    if ((observed.st_dev, observed.st_ino) != (expected["device"], expected["inode"])
            or set(expected) == full and _placeholder_identity(observed) != expected):
        return False
    try: lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError as error: raise NetworkError("placeholder mountinfo encoding") from error
    if not lines or len(lines) > MAX_MOUNTINFO_LINES:
        raise NetworkError("placeholder mountinfo count")
    path = "/run/netns/" + name
    for line in lines:
        fields = line.split(" ")
        if fields.count("-") != 1: raise NetworkError("placeholder mountinfo separator")
        separator = fields.index("-")
        if separator < 6 or len(fields) != separator + 4 or not _DEVICE.fullmatch(fields[2]):
            raise NetworkError("placeholder mountinfo shape")
        point = _OCTAL.sub(lambda match: chr(int(match.group(1), 8)), fields[4])
        if point == path: return False
    return True


def _complete_baseline(raws, mountinfo, journal, allow_owned_nft=False):
    if type(raws) is not tuple or len(raws) != 6:
        raise NetworkError("complete baseline outputs required")
    parsed = []
    for label, raw in zip(("links", "addresses", "routes4", "routes6", "names", "ruleset"),
                          raws, strict=True):
        try:
            parsed.append(_load(raw, MAX_NFT_ITEMS if label == "ruleset" else MAX_ITEMS))
        except NetworkError as error:
            raise NetworkError(f"complete baseline {label}: {error}") from error
    links, addresses, routes4, routes6, names, ruleset = parsed
    if _netns_parent_mount(mountinfo) is not None:
        raise NetworkError("baseline netns parent must be an unmounted private directory")
    if any(type(value) is not list for value in (links, addresses, routes4, routes6, names)):
        raise NetworkError("complete baseline arrays required")
    if any(type(row) is not dict for value in (links, addresses, routes4, routes6, names) for row in value):
        raise NetworkError("complete baseline row required")
    if (any(type(row.get("ifindex")) is not int or type(row.get("ifname")) is not str for row in links)
            or any(type(row.get("ifindex")) is not int or type(row.get("ifname")) is not str
                   or type(row.get("addr_info")) is not list for row in addresses)
            or any(type(row.get("dst")) is not str or type(row.get("dev")) is not str
                   for row in routes4 + routes6)
            or any(type(row.get("name")) is not str for row in names)):
        raise NetworkError("complete baseline typed row required")
    if (len({row["ifindex"] for row in links}) != len(links)
            or len({row["ifname"] for row in links}) != len(links)
            or len({row["name"] for row in names}) != len(names)):
        raise NetworkError("complete baseline duplicate identity")
    host_name = _bound_host(journal) if journal is not None else None
    if any(row.get("ifname") in {host_name, TEMP_IF} or journal is None and re.fullmatch(r"c42h[0-9a-f]{10}", row.get("ifname", "")) for row in links + addresses):
        raise NetworkError("fixed host interface already exists")
    if any(row.get("dev") in {host_name, TEMP_IF} or journal is None and re.fullmatch(r"c42h[0-9a-f]{10}", row.get("dev", "")) for row in routes4 + routes6):
        raise NetworkError("fixed host route already exists")
    netns_name, table_name = _bound_names(journal) if journal is not None else (None, None)
    planned = _original_placeholder(journal) if journal is not None else None
    placeholder_present = False; active_netns = None
    if journal is not None:
        try: active_netns = _netns_identity(None, mountinfo, netns_name)
        except NetworkError:
            if not _exact_unmounted_placeholder(mountinfo, netns_name, planned): raise
            placeholder_present = True
    if active_netns is not None:
        raise NetworkError("fixed namespace already exists")
    ignored_names = {netns_name} if placeholder_present else set()
    quarantine_stage = _quarantine_stage(journal) if journal is not None else None
    if quarantine_stage is not None and quarantine_stage[1]["placeholder"] is not None:
        qname = quarantine_stage[1]["quarantine_name"]
        if _exact_unmounted_placeholder(mountinfo, qname, quarantine_stage[1]["placeholder"]):
            ignored_names.add(qname)
    if any(re.fullmatch(r"c42[qn][0-9a-f]{10}", row["name"])
           and row["name"] not in ignored_names for row in names):
        raise NetworkError("fixed namespace already exists")
    nft = ruleset
    _keys(nft, ("nftables",))
    if type(nft["nftables"]) is not list:
        raise NetworkError("complete ruleset required")
    for row in nft["nftables"]:
        if type(row) is not dict:
            raise NetworkError("ruleset row")
        table = row.get("table")
        if table is not None and type(table) is not dict:
            raise NetworkError("ruleset table row")
        if (not allow_owned_nft and type(table) is dict and table.get("family") == "inet" and
                (table.get("name") == table_name or journal is None and re.fullmatch(r"c42t[0-9a-f]{10}", table.get("name", "")))):
            raise NetworkError("fixed nft table already exists")
    normalized_names = json.dumps([row for row in names if row["name"] not in ignored_names],
                                  sort_keys=True, separators=(",", ":")).encode()
    all_raw = (_normalize_baseline_links(links), *raws[1:4], normalized_names,
               _normalize_baseline_nft(nft), mountinfo)
    return dict(zip(_BASELINE_KEYS, (hashlib.sha256(raw).hexdigest() for raw in all_raw), strict=True))


def _netns_value(value):
    if value is None: return None
    result = {name: getattr(value, name) for name in
        ("mount_id", "parent_id", "device", "inode_device", "inode")}
    result["name"] = value.mount_point.rsplit("/", 1)[-1]
    return result


def _link_value(value):
    if value is None:
        return None
    row = asdict(value); row["flags"] = list(row["flags"])
    return row


def _nft_value(value):
    if value is None:
        return None
    identity = value.identity
    return {"table_name": value.content["nftables"][0]["table"]["name"],
            "table_handle": identity.table_handle,
            "chain_handles": [list(row) for row in identity.chain_handles],
            "rule_handles": [list(row) for row in identity.rule_handles]}


def _empty_identity():
    return {"netns": None, "host_link": None, "peer_link": None, "nft": None,
            "tap": None, "tc": None, "addresses_sha256": ZERO,
            "routes_sha256": ZERO, "state_sha256": ZERO}

def _identity(netns=None, host=None, peer=None, nft=None, tap=None, tc=None,
              addresses=ZERO, routes=ZERO):
    return {"netns": _netns_value(netns), "host_link": _link_value(host),
            "peer_link": _link_value(peer), "nft": _nft_value(nft),
            "tap": _link_value(tap), "tc": tc, "addresses_sha256": addresses,
            "routes_sha256": routes, "state_sha256": ZERO}

def _record_observation(journal, source_id, raw, command_serial=None):
    import completion_kata_operation as operation
    history = operation._network_history(journal)
    completed = [body for kind, body in history if kind == operation.network_journal.OUTPUT_RECORD
                 and body["chunk_index"] + 1 == body["chunk_count"]]
    serial = len(completed); prior_chunks = [body for kind, body in history
        if kind == operation.network_journal.OUTPUT_RECORD and body["observation_serial"] == serial]
    chunks = tuple(raw[index:index + operation.network_journal.MAX_CHUNK_BYTES]
                   for index in range(0, len(raw), operation.network_journal.MAX_CHUNK_BYTES)) or (b"",)
    digest = hashlib.sha256(raw).hexdigest(); start = len(prior_chunks)
    if prior_chunks:
        first = prior_chunks[0]
        if (first["source_id"], first["output_sha256"], first["output_length"], first["chunk_count"]) != (
                source_id, digest, len(raw), len(chunks)):
            raise NetworkError("observer chunk resume mismatch")
        command_serial = first["command_serial"]
    for index, chunk in enumerate(chunks[start:], start):
        body = {"operation_token": operation._command_context(journal).operation_token,
                "policy_version": operation.network_journal.POLICY_VERSION,
                "observation_serial": serial, "source_id": source_id, "command_serial": command_serial,
                "chunk_index": index, "chunk_count": len(chunks), "output_sha256": digest,
                "output_length": len(raw), "raw_hex": chunk.hex(), "proof_sha256": ZERO}
        body["proof_sha256"] = hashlib.sha256(operation._canonical({name: value for name, value in body.items()
            if name != "proof_sha256"})).hexdigest()
        operation._record_network(journal, operation.network_journal.OUTPUT_RECORD, body)

def _retained_observation_raw(journal, source_id, before_kind=None):
    import completion_kata_operation as operation
    history = operation._network_history(journal)
    if before_kind is not None:
        positions = [index for index, (kind, _body) in enumerate(history) if kind == before_kind]
        if positions: history = history[:positions[-1]]
    grouped = {}
    for kind, body in history:
        if kind == operation.network_journal.OUTPUT_RECORD:
            grouped.setdefault(body["observation_serial"], []).append(body)
    for serial in sorted(grouped, reverse=True):
        rows = sorted(grouped[serial], key=lambda row: row["chunk_index"])
        if (rows[0]["source_id"] == source_id and len(rows) == rows[0]["chunk_count"] and
                rows[-1]["chunk_index"] + 1 == rows[-1]["chunk_count"]):
            raw = b"".join(bytes.fromhex(row["raw_hex"]) for row in rows)
            if hashlib.sha256(raw).hexdigest() == rows[0]["output_sha256"]: return raw
    raise NetworkError("retained observer raw unavailable")


def _first_retained_observation_raw(journal, source_id):
    import completion_kata_operation as operation
    grouped = {}
    for kind, body in operation._network_history(journal):
        if kind == operation.network_journal.OUTPUT_RECORD:
            grouped.setdefault(body["observation_serial"], []).append(body)
        elif kind == "NETWORK_SNAPSHOT_V2":
            break
    for serial in sorted(grouped):
        rows = sorted(grouped[serial], key=lambda row: row["chunk_index"])
        if (rows[0]["source_id"] == source_id and len(rows) == rows[0]["chunk_count"]
                and rows[-1]["chunk_index"] + 1 == rows[-1]["chunk_count"]):
            raw = b"".join(bytes.fromhex(row["raw_hex"]) for row in rows)
            if hashlib.sha256(raw).hexdigest() == rows[0]["output_sha256"]: return raw
    raise NetworkError("first retained observer raw unavailable")


def _pending_observation(journal):
    import completion_kata_operation as operation
    history = operation._network_history(journal)
    completed = sum(1 for kind, body in history if kind == operation.network_journal.OUTPUT_RECORD
                    and body["chunk_index"] + 1 == body["chunk_count"])
    rows = [body for kind, body in history if kind == operation.network_journal.OUTPUT_RECORD
            and body["observation_serial"] == completed]
    return None if not rows else rows[0]


def _resume_observer_chunk(journal, ip, nft, tc, mutation_action=None):
    pending = _pending_observation(journal)
    if pending is None: return
    source_id = pending["source_id"]
    if mutation_action is None and source_id in {item.value for item in _SETUP_ACTIONS} | {
            Action.IP_NETNS_REMOVE.value, Action.NFT_REMOVE_ATOMIC.value}:
        return
    if mutation_action is not None and source_id == mutation_action.value:
        raw = (_retained_observation_raw(journal, "NFT_TABLE", "NETWORK_EFFECT_INTENT_V2")
               if mutation_action is Action.NFT_REMOVE_ATOMIC else b"")
        _record_observation(journal, source_id, raw, pending["command_serial"]); return
    if source_id == "MOUNTINFO":
        _record_observation(journal, source_id, _read_mountinfo()); return
    if source_id == "NETNS_STAT":
        path = "/run/netns/" + _bound_names(journal)[0]
        try:
            observed = os.stat(path, follow_symlinks=False)
            raw = json.dumps({"device": observed.st_dev, "inode": observed.st_ino},
                             sort_keys=True, separators=(",", ":")).encode()
        except FileNotFoundError:
            raw = b"null"
        _record_observation(journal, source_id, raw); return
    action_name = source_id.split(":", 1)[0]
    if action_name not in {item.value for item in _BASELINE_ACTIONS} | {
            item.value for item in (Action.IP_ALL_LINKS, Action.IP_NS_LINKS, Action.NFT_TABLE,
                                    Action.IP_HOST_LINKS, Action.IP_HOST_ADDRESSES,
                                    Action.IP_HOST_ROUTES4, Action.IP_HOST_ROUTES6,
                                    Action.IP_NS_ADDRESSES, Action.IP_NS_ROUTES4, Action.IP_NS_ROUTES6,
                                    Action.TC_QDISC, Action.TC_INGRESS_FILTER)}:
        raise NetworkError("observer chunk source")
    endpoint = None
    if ":" in source_id:
        import completion_kata_operation as operation
        rows = operation._network_records(journal)
        if not rows: raise NetworkError("dynamic endpoint snapshot absent")
        name = source_id.split(":", 1)[1]; identity = rows[-1]["identity"]
        value = next((row for row in (identity.get("peer_link"), identity.get("tap"))
                      if row is not None and row["ifname"] == name), None)
        if value is None: raise NetworkError("dynamic endpoint identity absent")
        endpoint = Link(**{**value, "flags": tuple(value["flags"])})
    _perform_fixed(journal, Action(action_name), ip, nft, tc, endpoint=endpoint)


def _sources(journal, after=None):
    import completion_kata_operation as operation
    history = operation._network_history(journal); start = 0
    if after is not None: start = max(index for index, (kind, _body) in enumerate(history) if kind == after) + 1
    return [{"observation_serial": body["observation_serial"], "source_id": body["source_id"],
             "output_sha256": body["output_sha256"], "output_length": body["output_length"]}
            for kind, body in history[start:] if kind == operation.network_journal.OUTPUT_RECORD
            and body["chunk_index"] + 1 == body["chunk_count"]]

def _source_raw(journal, source):
    import completion_kata_operation as operation
    rows = [body for kind, body in operation._network_history(journal)
            if kind == operation.network_journal.OUTPUT_RECORD and
            body["observation_serial"] == source["observation_serial"]]
    rows.sort(key=lambda row: row["chunk_index"])
    if (not rows or len(rows) != rows[0]["chunk_count"] or
            rows[-1]["chunk_index"] + 1 != rows[-1]["chunk_count"]):
        raise NetworkError("complete retained source unavailable")
    raw = b"".join(bytes.fromhex(row["raw_hex"]) for row in rows)
    if hashlib.sha256(raw).hexdigest() != source["output_sha256"] or len(raw) != source["output_length"]:
        raise NetworkError("retained source digest")
    return raw


def _observer_pass(journal, ip, nft, tc, expected, after, mutation=None, endpoints=None):
    """Resume one exact source pass; never append an already complete prefix."""
    endpoints = {} if endpoints is None else endpoints
    _resume_observer_chunk(journal, ip, nft, tc, mutation)
    while True:
        sources = _sources(journal, after)
        ids = tuple(row["source_id"] for row in sources)
        if ids != tuple(expected[:len(ids)]) or len(ids) > len(expected):
            raise NetworkError("observer pass cursor")
        if len(ids) == len(expected): return tuple(_source_raw(journal, row) for row in sources)
        source_id = expected[len(ids)]
        if mutation is not None and source_id == mutation.value:
            raise NetworkError("durable mutation source absent")
        if source_id == "MOUNTINFO":
            _netns_identity(journal)
        elif source_id == "NETNS_STAT":
            raise NetworkError("orphan netns stat cursor")
        else:
            action_name = source_id.split(":", 1)[0]
            try: action = Action(action_name)
            except ValueError as error: raise NetworkError("observer pass source") from error
            _perform_fixed(journal, action, ip, nft, tc, endpoint=endpoints.get(source_id))


def _effect_source_ids(action, prior):
    if action is Action.IP_GUEST_LINK_UP:
        return (action.value, "IP_HOST_LINKS", "IP_HOST_ADDRESSES", "IP_HOST_ROUTES4",
                "IP_HOST_ROUTES6", "IP_NS_LINKS", "IP_NS_ADDRESSES", "IP_NS_ROUTES4",
                "IP_NS_ROUTES6", "NFT_TABLE", "TC_QDISC", "TC_INGRESS_FILTER",
                "MOUNTINFO", "NETNS_STAT")
    suffix = (("NFT_RULESET",) if action is Action.NFT_REMOVE_ATOMIC else ()) + (
        "MOUNTINFO", "NETNS_STAT", "IP_ALL_LINKS")
    if action not in {Action.IP_NETNS_REMOVE, Action.NFT_REMOVE_ATOMIC}: suffix += ("IP_NS_LINKS",)
    if action is Action.NFT_INSTALL_OWNED or prior.get("nft") is not None and action is not Action.NFT_REMOVE_ATOMIC:
        suffix += ("NFT_TABLE",)
    return (action.value, *suffix)


def _effect_sources(journal, action, prior):
    sources = _sources(journal, "NETWORK_EFFECT_INTENT_V2"); expected = _effect_source_ids(action, prior)
    mutation = next((row for row in sources if row["source_id"] == expected[0]), None)
    for start in range(len(sources) - len(expected) + 1, -1, -1):
        suffix = sources[start:start + len(expected) - 1]
        if tuple(row["source_id"] for row in suffix) == expected[1:]:
            if mutation is None: raise NetworkError("durable mutation output absent")
            return [mutation, *suffix]
    raise NetworkError("complete post-effect observer sources absent")


def _bind_identity(identity, sources):
    import completion_kata_operation as operation
    value = {**identity, "state_sha256": ZERO}
    value["state_sha256"] = hashlib.sha256(operation._canonical({"identity": {
        name: child for name, child in value.items() if name != "state_sha256"},
        "sources": sources})).hexdigest()
    return value
def _snapshot(journal, kind, baselines, identity, sources=None):
    import completion_kata_operation as operation
    if sources is None: sources = _sources(journal)
    identity = _bind_identity(identity, sources)
    body = {"operation_token": operation._command_context(journal).operation_token,
            "policy_version": operation.network_journal.POLICY_VERSION,
            "snapshot_kind": kind, "baselines": baselines, "sources": sources, "identity": identity,
            "proof_sha256": operation.ZERO}
    body["proof_sha256"] = hashlib.sha256(operation._canonical(
        {name: value for name, value in body.items() if name != "proof_sha256"})).hexdigest()
    operation._record_network(journal, "NETWORK_SNAPSHOT_V2", body)
    return body
def _effect_body(journal, action, identity=None, disposition="exact", target=None):
    import completion_kata_operation as operation
    history = operation._network_history(journal)
    settled = [body for kind, body in history if kind == "NETWORK_EFFECT_SETTLED_V2"]
    base = {"operation_token": operation._command_context(journal).operation_token,
            "policy_version": operation.network_journal.POLICY_VERSION,
            "effect_serial": len(settled), "action": action.value,
            "prior_proof_sha256": settled[-1]["proof_sha256"] if settled else ZERO,
            "target": target if target is not None else
                      (settled[-1]["identity"] if settled else operation._network_records(journal)[0]["identity"])}
    if identity is None:
        return base
    sources = _effect_sources(journal, action, target)
    identity = _bind_identity(identity, sources)
    body = {**base, "disposition": disposition, "sources": sources, "identity": identity,
            "proof_sha256": operation.ZERO}
    body["proof_sha256"] = hashlib.sha256(operation._canonical(
        {name: value for name, value in body.items() if name != "proof_sha256"})).hexdigest()
    return body
def _record_effect(journal, kind, body):
    import completion_kata_operation as operation
    operation._record_network(journal, kind, body)

def _baselines(journal):
    import completion_kata_operation as operation
    rows = operation._network_records(journal)
    if not rows or rows[0]["snapshot_kind"] != "baseline":
        raise NetworkError("durable network baseline unavailable")
    return rows[0]["baselines"], rows


def _capture_fixed_baselines(journal, ip, nft, tc):
    import completion_kata_operation as operation
    nft_owner.acquire(journal)
    nft_owner.require_active(journal)
    raws = tuple(_perform_fixed(journal, action, ip, nft, tc) for action in _BASELINE_ACTIONS)
    _support_ownership(journal)
    mountinfo = _read_mountinfo(); baselines = _complete_baseline(raws, mountinfo, journal)
    _netns_identity(journal, mountinfo)
    body = _snapshot(journal, "baseline", baselines, _empty_identity())
    operation._settle_network_phase(journal, "BASELINES_CAPTURED")
    return body


def _owned_links(raw, names):
    value = _load(raw)
    if (type(value) is not list or type(names) is not tuple or not names
            or len(names) != len(set(names))):
        raise NetworkError("complete owned links")
    parsed = {}
    for row in value:
        if type(row) is not dict:
            raise NetworkError("owned link row")
        candidate = row.get("ifname")
        if candidate in names:
            link = _parse_link_row(row)
            if link.ifname in parsed: raise NetworkError("duplicate owned link")
            parsed[link.ifname] = link
    return tuple(parsed.get(name) for name in names)


def _observed_identity(journal, ip, nft, tc, prior, action, ready=False):
    """Use the replay derivation for live effects as the single state authority."""
    expected = _effect_source_ids(action, prior)
    observer_expected = (("NFT_TABLE", *expected)
                         if action is Action.NFT_REMOVE_ATOMIC else expected)
    raw = _observer_pass(
        journal, ip, nft, tc, observer_expected, "NETWORK_EFFECT_INTENT_V2", action)
    if action is Action.NFT_REMOVE_ATOMIC:
        raw = raw[1:]
    outputs = [{"source_id": name, "raw": value} for name, value in zip(expected, raw, strict=True)]
    scope = "ready" if ready else "effect"
    return _derive_journal_identity(scope, action.value, outputs, prior)[0]


def _observe_ready_teardown(journal, ip, nft, tc, prior):
    expected = _effect_source_ids(Action.IP_GUEST_LINK_UP, prior)[1:]
    raw = _observer_pass(journal, ip, nft, tc, expected, "NETWORK_SNAPSHOT_V2")
    outputs = [{"source_id": Action.IP_GUEST_LINK_UP.value, "raw": b""}, *(
        {"source_id": name, "raw": value} for name, value in zip(expected, raw, strict=True))]
    identity, _baselines_value = _derive_journal_identity("ready", None, outputs, prior)
    return identity


def _effect(journal, action, ip, nft, tc, prior, final=False):
    if action in _SETUP_ACTIONS or action in {
            Action.IP_NETNS_REMOVE, Action.NFT_REMOVE_ATOMIC}:
        nft_owner.require_active(journal)
    intent = _effect_body(journal, action, target=prior)
    try:
        _record_effect(journal, "NETWORK_EFFECT_INTENT_V2", intent)
    except BaseException as error:
        raise NetworkError(f"network effect intent rejected:{action.value}") from error
    if action is Action.IP_NETNS_ADD: _establish_netns(journal)
    elif action is Action.IP_NETNS_REMOVE: _descriptor_remove_netns(journal, prior)
    else:
        if action is Action.NFT_REMOVE_ATOMIC:
            table_name = prior["nft"]["table_name"]
            current = parse_nft_snapshot(
                _perform_fixed(journal, Action.NFT_TABLE, ip, nft, tc),
                table_name, _bound_host(journal))
            if _nft_value(current) != prior["nft"]:
                raise NetworkError("NFT replacement before post-intent deletion")
        _perform_fixed(journal, action, ip, nft, tc, prior)
    identity = _observed_identity(journal, ip, nft, tc, prior, action, final)
    observed = _effect_body(journal, action, identity,
                            "absent" if action in {Action.IP_NETNS_REMOVE, Action.NFT_REMOVE_ATOMIC} else "exact", prior)
    _record_effect(journal, "NETWORK_EFFECT_OBSERVED_V2", observed)
    _record_effect(journal, "NETWORK_EFFECT_SETTLED_V2", observed)
    return observed["identity"]


def _setup_fixed_network(journal, ip, nft, tc):
    import completion_kata_operation as operation
    baselines, rows = _baselines(journal)
    if len(rows) != 1 or any(kind in operation.network_journal.RECORDS
                             for kind, _body in operation._network_history(journal)):
        raise NetworkError("setup replay forbidden")
    identity = rows[0]["identity"]
    nft_owner.require_active(journal)
    for index, action in enumerate(_SETUP_ACTIONS):
        identity = _effect(journal, action, ip, nft, tc, identity,
                           index == len(_SETUP_ACTIONS) - 1)
        # NFT handles are settled before any address is assigned or link raised.
    ready = _snapshot(journal, "ready", baselines, identity, _settled_effects(journal)[-1]["sources"])
    operation._settle_network_phase(journal, "NETWORK_READY")
    return ready


def _tc_value(qdiscs, filters):
    return json.loads(json.dumps({"qdiscs": [asdict(row) for row in qdiscs],
                                  "filters": [asdict(row) for row in filters]}))


def _observe_discovered_identity(journal, ip, nft, tc, retained):
    expected = ("IP_HOST_LINKS", "IP_NS_LINKS", "IP_HOST_ADDRESSES", "IP_NS_ADDRESSES")
    raw = _observer_pass(journal, ip, nft, tc, expected, "NETWORK_SNAPSHOT_V2")
    outputs = [{"source_id": name, "raw": value} for name, value in zip(expected, raw, strict=True)]
    value = _derive_journal_identity("discovered", None, outputs, retained)[0]
    return _bind_identity(value, _sources(journal, "NETWORK_SNAPSHOT_V2"))


def _observe_fixed_runtime_network(journal, ip, nft, tc, record=True):
    """Observe once and feed the same pure derivation used by fresh replay."""
    _resume_observer_chunk(journal, ip, nft, tc); baselines, rows = _baselines(journal)
    allowed = {"ready", "discovered"} if record else {"runtime"}
    if rows[-1]["snapshot_kind"] not in allowed: raise NetworkError("runtime network observation order")
    prior = rows[-1]["identity"]
    if record and rows[-1]["snapshot_kind"] == "ready":
        prior = _observe_discovered_identity(journal, ip, nft, tc, prior)
        prior = _snapshot(journal, "discovered", baselines, prior,
                          _sources(journal, "NETWORK_SNAPSHOT_V2"))["identity"]
    tap = Link(**{**prior["tap"], "flags": tuple(prior["tap"]["flags"])})
    guest = Link(**{**prior["peer_link"], "flags": tuple(prior["peer_link"]["flags"])})
    expected = ("IP_HOST_ROUTES4", "IP_HOST_ROUTES6", "IP_NS_ROUTES4", "IP_NS_ROUTES6",
                "TC_QDISC", "TC_QDISC:" + tap.ifname, "TC_INGRESS_FILTER:eth0",
                "TC_INGRESS_FILTER:" + tap.ifname, "MOUNTINFO", "NETNS_STAT", "NFT_TABLE")
    raw = _observer_pass(journal, ip, nft, tc, expected, "NETWORK_SNAPSHOT_V2", endpoints={
        "TC_QDISC:" + tap.ifname: tap, "TC_INGRESS_FILTER:eth0": guest,
        "TC_INGRESS_FILTER:" + tap.ifname: tap})
    outputs = [{"source_id": name, "raw": value} for name, value in zip(expected, raw, strict=True)]
    identity = _derive_journal_identity("runtime", None, outputs, prior, baselines)[0]
    sources = _sources(journal, "NETWORK_SNAPSHOT_V2")
    return _snapshot(journal, "runtime", baselines, identity, sources) if record else _bind_identity(identity, sources)


def _journal_output_map(outputs):
    rows = {}
    for output in outputs:
        rows.setdefault(output["source_id"], []).append(output["raw"])
    return rows


def _journal_netns(rows, prior):
    if set(("MOUNTINFO", "NETNS_STAT")) - set(rows):
        raise NetworkError("netns evidence absent")
    mountinfo, stat_raw = rows["MOUNTINFO"][-1], rows["NETNS_STAT"][-1]
    if stat_raw == b"null":
        name = None if prior is None or prior.get("netns") is None else prior["netns"]["name"]
        if name is not None and ("/run/netns/" + name).encode() in mountinfo:
            raise NetworkError("absent netns mount contradiction")
        return None
    stat_value = _load(stat_raw)
    _keys(stat_value, ("device", "inode"))
    if any(type(stat_value[name]) is not int or stat_value[name] <= 0 for name in stat_value): raise NetworkError("netns stat evidence")
    stat = NetnsStat(stat_value["device"], stat_value["inode"])
    name = prior["netns"]["name"] if prior and prior.get("netns") else None
    if name is None:
        text = mountinfo.decode("utf-8", "strict")
        names = re.findall(r" /run/netns/(c42n[0-9a-f]{10}) ", text)
        if len(names) != 1: raise NetworkError("unique netns evidence")
        name = names[0]
    return parse_netns_identity(mountinfo, stat, "/run/netns/" + name)


def _derive_journal_identity(kind, action, outputs, prior=None, baselines=None):
    """Purely derive durable state from exact canonical observer bytes."""
    rows = _journal_output_map(outputs)
    ids = tuple(output["source_id"] for output in outputs)
    baseline_ids = tuple(item.value for item in _BASELINE_ACTIONS) + ("MOUNTINFO", "NETNS_STAT")
    if kind in {"baseline", "network-absent", "firewall-restored"}:
        if ids[-len(baseline_ids):] != baseline_ids: raise NetworkError("terminal source cardinality")
        raw = tuple(rows[item.value][-1] for item in _BASELINE_ACTIONS)
        mountinfo = rows["MOUNTINFO"][-1]
        if rows["NETNS_STAT"][-1] != b"null": raise NetworkError("terminal netns present")
        complete = _complete_baseline(raw, mountinfo, None, kind == "network-absent")
        if baselines is not None:
            compared = (_BASELINE_KEYS if kind != "network-absent" or prior.get("nft") is None
                        else (*_BASELINE_KEYS[:5], _BASELINE_KEYS[-1]))
            if any(complete[name] != baselines[name] for name in compared): raise NetworkError("baseline digest drift")
        if kind == "baseline": return _empty_identity(), complete
        identity = _empty_identity()
        if kind == "network-absent": identity["nft"] = prior["nft"]
        return identity, complete
    if kind == "discovered":
        expected = ("IP_HOST_LINKS", "IP_NS_LINKS", "IP_HOST_ADDRESSES", "IP_NS_ADDRESSES")
        if ids != expected: raise NetworkError("discovered source cardinality")
        host_name = prior["host_link"]["ifname"]
        host = parse_links(rows["IP_HOST_LINKS"][0], False, host_name); links = parse_runtime_links(rows["IP_NS_LINKS"][0])
        tap = next((item for item in links if item.kind == "tap"), None); retained = tuple(item for item in links if item.kind != "tap")
        host_link, guest = validate_peer_pair(host, retained, host_name)
        parse_addresses(rows["IP_HOST_ADDRESSES"][0], False, host, host_name)
        parse_runtime_addresses(rows["IP_NS_ADDRESSES"][0], links)
        if tap is None: raise NetworkError("discovered TAP absent")
        value = {**prior, "host_link": _link_value(host_link), "peer_link": _link_value(guest),
                 "tap": _link_value(tap), "addresses_sha256": hashlib.sha256(
                 rows["IP_HOST_ADDRESSES"][0] + b"\0" + rows["IP_NS_ADDRESSES"][0]).hexdigest(), "state_sha256": ZERO}
        return value, baselines
    if kind == "ready":
        expected = (Action.IP_GUEST_LINK_UP.value, "IP_HOST_LINKS", "IP_HOST_ADDRESSES",
                    "IP_HOST_ROUTES4", "IP_HOST_ROUTES6", "IP_NS_LINKS", "IP_NS_ADDRESSES",
                    "IP_NS_ROUTES4", "IP_NS_ROUTES6", "NFT_TABLE", "TC_QDISC", "TC_INGRESS_FILTER",
                    "MOUNTINFO", "NETNS_STAT")
        if ids != expected: raise NetworkError("ready source cardinality")
        host_name = prior["host_link"]["ifname"] if prior and prior.get("host_link") else None
        if host_name is None:
            candidate = _load(rows["IP_HOST_LINKS"][0]); host_name = candidate[0]["ifname"] if len(candidate) == 1 else None
        host = parse_links(rows["IP_HOST_LINKS"][0], False, host_name); namespace = parse_links(rows["IP_NS_LINKS"][0], True)
        host_link, guest = validate_peer_pair(host, namespace, host_name)
        parse_addresses(rows["IP_HOST_ADDRESSES"][0], False, host, host_name); parse_addresses(rows["IP_NS_ADDRESSES"][0], True, namespace)
        for name, family, links in (("IP_HOST_ROUTES4", 4, host), ("IP_HOST_ROUTES6", 6, host),
                ("IP_NS_ROUTES4", 4, namespace), ("IP_NS_ROUTES6", 6, namespace)):
            parse_routes(rows[name][0], family, links, host_name)
        netns = _journal_netns(rows, prior); table = "c42t" + netns.mount_point.rsplit("c42n", 1)[-1]
        nft_state = parse_nft_snapshot(rows["NFT_TABLE"][0], table, host_name)
        qdisc = parse_tc_qdiscs(rows["TC_QDISC"][0], guest)
        if len(qdisc) != 1 or _load(rows["TC_INGRESS_FILTER"][0]) != []: raise NetworkError("ready tc drift")
        value = _identity(netns, host_link, guest, nft_state, tc=_tc_value(qdisc, ()),
            addresses=hashlib.sha256(rows["IP_HOST_ADDRESSES"][0] + b"\0" + rows["IP_NS_ADDRESSES"][0]).hexdigest(),
            routes=hashlib.sha256(b"".join(rows[name][0] for name in
                ("IP_HOST_ROUTES4", "IP_HOST_ROUTES6", "IP_NS_ROUTES4", "IP_NS_ROUTES6"))).hexdigest())
        return value, baselines
    if kind == "runtime":
        expected = ("IP_HOST_ROUTES4", "IP_HOST_ROUTES6", "IP_NS_ROUTES4", "IP_NS_ROUTES6",
                    "TC_QDISC", "TC_QDISC:" + prior["tap"]["ifname"], "TC_INGRESS_FILTER:eth0",
                    "TC_INGRESS_FILTER:" + prior["tap"]["ifname"], "MOUNTINFO", "NETNS_STAT", "NFT_TABLE")
        if ids != expected: raise NetworkError("runtime source cardinality")
        host = Link(**{**prior["host_link"], "flags": tuple(prior["host_link"]["flags"])})
        guest = Link(**{**prior["peer_link"], "flags": tuple(prior["peer_link"]["flags"])})
        tap = Link(**{**prior["tap"], "flags": tuple(prior["tap"]["flags"])})
        netns = _journal_netns(rows, prior)
        host_links, retained, links = (host,), (Link(1, "lo", "loopback", "00:00:00:00:00:00", None,
            ("LOOPBACK", "UP", "LOWER_UP"), "UNKNOWN", True, "noqueue", None), guest), None
        links = (*retained, tap)
        parse_routes(rows["IP_HOST_ROUTES4"][0], 4, host_links, host.ifname)
        parse_routes(rows["IP_HOST_ROUTES6"][0], 6, host_links, host.ifname)
        parse_routes(rows["IP_NS_ROUTES4"][0], 4, links); parse_routes(rows["IP_NS_ROUTES6"][0], 6, links)
        guest_q = parse_tc_qdiscs(rows["TC_QDISC"][0], guest); tap_q = parse_tc_qdiscs(rows["TC_QDISC:" + tap.ifname][0], tap)
        filters = (parse_tc_filters(rows["TC_INGRESS_FILTER:eth0"][0], guest, tap) +
                   parse_tc_filters(rows["TC_INGRESS_FILTER:" + tap.ifname][0], tap, guest))
        binding = runtime_difference(RuntimeState(netns, host_links, retained, (guest_q[0],), ()),
                                     RuntimeState(netns, host_links, links, guest_q + tap_q, filters))
        table = prior["nft"]["table_name"]; nft_state = parse_nft_snapshot(rows["NFT_TABLE"][0], table, host.ifname)
        value = _identity(netns, host, guest, nft_state, tap, _tc_value(binding.qdiscs, binding.filters),
                          prior["addresses_sha256"], hashlib.sha256(b"".join(rows[name][0] for name in
                          ("IP_HOST_ROUTES4", "IP_HOST_ROUTES6", "IP_NS_ROUTES4", "IP_NS_ROUTES6"))).hexdigest())
        return value, baselines
    # Effect observations are derived from exact post-effect inventory.
    if action is not None:
        if action == "NFT_REMOVE_ATOMIC":
            table_name = prior["nft"]["table_name"]
            if not re.fullmatch(r"c42t[0-9a-f]{10}", table_name):
                raise NetworkError("conditional nft table binding")
            if rows[action][0] != b"": raise NetworkError("conditional nft removal output")
            ruleset = _load(rows["NFT_RULESET"][0], MAX_NFT_ITEMS); _keys(ruleset, ("nftables",))
            if type(ruleset["nftables"]) is not list or any(type(row) is not dict for row in ruleset["nftables"]):
                raise NetworkError("conditional nft ruleset shape")
            tables = [row["table"] for row in ruleset["nftables"] if "table" in row]
            if any(type(table) is not dict for table in tables): raise NetworkError("conditional nft table shape")
            if any(table.get("family") == "inet" and table.get("name") == table_name for table in tables):
                raise NetworkError("conditional nft table retained")
        suffix = (("NFT_RULESET",) if action == "NFT_REMOVE_ATOMIC" else ()) + ("MOUNTINFO", "NETNS_STAT", "IP_ALL_LINKS")
        if action not in {"IP_NETNS_REMOVE", "NFT_REMOVE_ATOMIC"}: suffix += ("IP_NS_LINKS",)
        if action == "NFT_INSTALL_OWNED" or prior and prior.get("nft") is not None and action != "NFT_REMOVE_ATOMIC": suffix += ("NFT_TABLE",)
        if ids != (action, *suffix): raise NetworkError("effect source cardinality")
    netns = _journal_netns(rows, prior)
    host_name = prior["host_link"]["ifname"] if prior and prior.get("host_link") else None
    if host_name is None:
        candidates = [row.get("ifname") for row in _load(rows["IP_ALL_LINKS"][-1]) if re.fullmatch(r"c42h[0-9a-f]{10}", row.get("ifname", ""))]
        host_name = candidates[0] if len(candidates) == 1 else None
    host, temporary = _owned_links(rows["IP_ALL_LINKS"][-1], (host_name, TEMP_IF)); peer = temporary
    if "IP_NS_LINKS" in rows:
        links = tuple(_parse_link_row(row) for row in _load(rows["IP_NS_LINKS"][-1]))
        peer = next((item for item in links if item.ifname in {TEMP_IF, GUEST_IF}), peer)
    nft_state = None
    if "NFT_TABLE" in rows:
        table = prior["nft"]["table_name"] if prior and prior.get("nft") else "c42t" + netns.mount_point.rsplit("c42n", 1)[-1]
        nft_state = parse_nft_snapshot(rows["NFT_TABLE"][-1], table, host_name)
    value = _identity(netns, host, peer, nft_state)
    if prior and prior.get("nft") is not None and nft_state is None and action != "NFT_REMOVE_ATOMIC":
        value["nft"] = prior["nft"]
    return value, baselines


def _fresh_baseline_outputs(journal, ip, nft, tc):
    raws = tuple(_perform_fixed(journal, action, ip, nft, tc) for action in _BASELINE_ACTIONS)
    mountinfo = _read_mountinfo()
    return raws, mountinfo, _complete_baseline(raws, mountinfo, journal, True)


def _settled_effects(journal):
    import completion_kata_operation as operation
    return [body for kind, body in operation._network_history(journal)
            if kind == "NETWORK_EFFECT_SETTLED_V2"]


def _resume_effect(journal, ip, nft, tc):
    """Settle only an already-issued effect; never issue its mutation again."""
    import completion_kata_operation as operation
    history = operation._network_history(journal)
    effects = [(kind, body) for kind, body in history if kind in operation.network_journal.RECORDS]
    if not effects or effects[-1][0] == "NETWORK_EFFECT_SETTLED_V2":
        return
    kind, body = effects[-1]
    if body["action"] in {item.value for item in _SETUP_ACTIONS}:
        nft_owner.require_active(journal)
    if (operation._command_context(journal).lifecycle_phase == "UNCERTAIN"
            and body["action"] != Action.IP_NETNS_REMOVE.value):
        raise NetworkError("uncertain setup effect cannot resume")
    if kind == "NETWORK_EFFECT_OBSERVED_V2":
        _record_effect(journal, "NETWORK_EFFECT_SETTLED_V2", body); return
    outcomes = [value for record, value in history if record == "COMMAND_OUTCOME_V2"
                and value["command_id"] == body["action"]]
    local_action = body["action"] in {Action.IP_NETNS_ADD.value, Action.IP_NETNS_REMOVE.value}
    if not local_action and (not outcomes or outcomes[-1]["outcome"] != "exited" or outcomes[-1]["status"] != 0):
        raise NetworkError("effect outcome cannot be recovered")
    mutation_outcome = None if local_action else outcomes[-1]
    if local_action and body["action"] not in {row["source_id"] for row in _sources(journal, "NETWORK_EFFECT_INTENT_V2")}:
        (_establish_netns(journal) if body["action"] == Action.IP_NETNS_ADD.value
         else _descriptor_remove_netns(journal, body["target"]))
    _resume_observer_chunk(journal, ip, nft, tc, Action(body["action"]))
    if body["action"] not in {row["source_id"] for row in _sources(journal, "NETWORK_EFFECT_INTENT_V2")}:
        raw = b""
        if (mutation_outcome is None or mutation_outcome["stdout_length"] != len(raw) or
                mutation_outcome["stdout_sha256"] != hashlib.sha256(raw).hexdigest()):
            raise NetworkError("mutation output cannot be reconstructed")
        _record_observation(journal, body["action"], raw, mutation_outcome["command_serial"])
    prior = _settled_effects(journal)
    identity = _observed_identity(journal, ip, nft, tc,
        prior[-1]["identity"] if prior else _empty_identity(), Action(body["action"]))
    observed = _effect_body(journal, Action(body["action"]), identity,
                            "absent" if body["action"] in {item.value for item in
                            (Action.IP_NETNS_REMOVE, Action.NFT_REMOVE_ATOMIC)} else "exact", body["target"])
    _record_effect(journal, "NETWORK_EFFECT_OBSERVED_V2", observed)
    _record_effect(journal, "NETWORK_EFFECT_SETTLED_V2", observed)


def _network_cleanup_active(journal):
    import completion_kata_operation as operation
    active = None
    for kind, _body in operation._network_history(journal):
        if kind in operation.network_journal.CLEANUP_INTENTS:
            active = kind
        elif kind in operation.network_journal.CLEANUP_SETTLED or (
                kind in {"NETWORK_ABSENT", "FIREWALL_ABSENT"}
                and active in {"NETWORK_CLEANUP_INTENT_V1",
                               "FIREWALL_CLEANUP_INTENT_V1"}):
            active = None
    return active is not None


def _settle_cleanup(journal, target, phase):
    import completion_kata_operation as operation
    completion_error = None
    try: operation._settle_network_phase(journal, phase)
    except BaseException as error: completion_error = error
    try: confirmed = journal.durable_phase() == phase
    except BaseException as confirmation_error:
        if completion_error is not None:
            raise NetworkCleanupError(completion_error, confirmation_error)
        raise
    if not confirmed:
        if completion_error is not None: raise completion_error
        raise NetworkError("cleanup completion not durable")
    journal.settle_network_cleanup(target)


def _remove_fixed_network(journal, ip, nft, tc):
    try:
        nft_owner.require_active(journal)
        journal.begin_network_cleanup("network")
        baselines, rows = _baselines(journal); _resume_effect(journal, ip, nft, tc)
        if rows[-1]["snapshot_kind"] == "network-absent":
            _settle_cleanup(journal, "network", "NETWORK_ABSENT"); return rows[-1]
        retained = rows[-1]
        if retained["snapshot_kind"] not in {"ready", "discovered", "runtime"}:
            raise NetworkError("network removal order")
        quarantine_stage = _quarantine_stage(journal)
        if quarantine_stage is not None and quarantine_stage[0] in {"NETWORK_QUARANTINE_INTENT_V2",
                "NETWORK_QUARANTINE_PLACEHOLDER_V2", "NETWORK_QUARANTINE_MOVED_V2"}:
            _quarantine_netns(journal, retained["identity"])
        original = _netns_identity(journal)
        quarantined = _netns_identity(journal, name=_quarantine_name(journal)) if original is None else None
        if original is None and quarantined is None:
            absent = {**_empty_identity(), "nft": retained["identity"]["nft"]}
        else:
            if quarantined is None:
                observed = (_observe_fixed_runtime_network(journal, ip, nft, tc, False)
                            if retained["snapshot_kind"] == "runtime" else
                            _observe_discovered_identity(journal, ip, nft, tc, retained["identity"])
                            if retained["snapshot_kind"] == "discovered" else _bind_identity(
                            _observe_ready_teardown(journal, ip, nft, tc, retained["identity"]),
                            _sources(journal, "NETWORK_SNAPSHOT_V2")))
                if {name: value for name, value in observed.items() if name != "state_sha256"} != {
                        name: value for name, value in retained["identity"].items() if name != "state_sha256"}:
                    raise NetworkError("network identity replacement before removal")
            _quarantine_netns(journal, retained["identity"])
            settled = _settled_effects(journal)
            absent = (_effect(journal, Action.IP_NETNS_REMOVE, ip, nft, tc, retained["identity"])
                      if not settled or settled[-1]["action"] != Action.IP_NETNS_REMOVE.value
                      else settled[-1]["identity"])
        if _quarantine_stage(journal) is not None:
            _cleanup_detached_placeholders(journal)
        raws, mountinfo, fresh = _fresh_baseline_outputs(journal, ip, nft, tc)
        if _netns_identity(journal, mountinfo) is not None:
            raise NetworkError("namespace remains after removal")
        qstage = _quarantine_stage(journal)
        if qstage is not None:
            if qstage[0] != "NETWORK_DETACHED_V2":
                raise NetworkError("quarantine not detached at baseline")
            for path in ("/run/netns/" + _bound_names(journal)[0],
                         "/run/netns/" + _quarantine_name(journal), PRESERVED_DIR,
                         "/run/netns/" + PRESERVED_REMOVING, PARENT_STAGE_DIR,
                         "/run/" + PARENT_STAGE_REMOVING):
                if os.path.lexists(path): raise NetworkError("private netns residue")
        for name in _BASELINE_KEYS[:5]:
            if fresh[name] != baselines[name]:
                detail = ""
                if name == "host_links":
                    detail = (f":{_load(_first_retained_observation_raw(journal, 'IP_ALL_LINKS'))!r}"
                              f":{_load(raws[0])!r}")
                raise NetworkError(
                    f"complete network baseline not restored:{name}:{baselines[name]}:{fresh[name]}{detail}")
        body = _snapshot(journal, "network-absent", baselines, absent,
                         _sources(journal, "NETWORK_SNAPSHOT_V2"))
        _settle_cleanup(journal, "network", "NETWORK_ABSENT"); return body
    except BaseException as error:
        try: _poison_fixed_network(journal, "incomplete")
        except BaseException as settlement_error:
            raise NetworkCleanupError(error, settlement_error)
        raise


def _remove_fixed_firewall(journal, ip, nft, tc):
    try:
        nft_owner.require_active(journal)
        phase = journal.durable_phase()
        if phase == "FIREWALL_ABSENT":
            baselines, rows = _baselines(journal)
            if rows[-1]["snapshot_kind"] != "firewall-restored":
                raise NetworkError("durable firewall absence snapshot missing")
            if _network_cleanup_active(journal):
                journal.settle_network_cleanup("firewall")
            nft_owner.settle_free(journal, "firewall")
            return rows[-1]
        journal.begin_network_cleanup("firewall")
        baselines, rows = _baselines(journal)
        _resume_effect(journal, ip, nft, tc)
        baselines, rows = _baselines(journal)
        if rows[-1]["snapshot_kind"] == "firewall-restored":
            _settle_cleanup(journal, "firewall", "FIREWALL_ABSENT")
            nft_owner.settle_free(journal, "firewall")
            return rows[-1]
        retained = rows[-1]
        if retained["snapshot_kind"] != "network-absent":
            raise NetworkError("firewall removal order")
        settled = _settled_effects(journal)
        removal_settled = bool(
            settled and settled[-1]["action"] == Action.NFT_REMOVE_ATOMIC.value)
        table_name = _bound_names(journal)[1]
        if removal_settled:
            absent = settled[-1]["identity"]
        else:
            ruleset = _perform_fixed(journal, Action.NFT_RULESET, ip, nft, tc)
            rows_value = _load(ruleset)
            tables = [row["table"] for row in rows_value.get("nftables", [])
                      if type(row) is dict and "table" in row]
            owned = [row for row in tables
                     if row.get("family") == "inet" and row.get("name") == table_name]
            if len(owned) != 1:
                raise NetworkError("owned NFT table replacement before removal")
            absent = _effect(
                journal, Action.NFT_REMOVE_ATOMIC, ip, nft, tc, retained["identity"])
        _raws, mountinfo, fresh = _fresh_baseline_outputs(journal, ip, nft, tc)
        if fresh != baselines or _netns_identity(journal, mountinfo) is not None:
            raise NetworkError("final network/firewall/mount baseline not restored")
        body = _snapshot(journal, "firewall-restored", baselines, absent,
                         _sources(journal, "NETWORK_SNAPSHOT_V2"))
        _settle_cleanup(journal, "firewall", "FIREWALL_ABSENT")
        nft_owner.settle_free(journal, "firewall")
        return body
    except BaseException as error:
        try: _poison_fixed_network(journal, "incomplete")
        except BaseException as settlement_error:
            raise NetworkCleanupError(error, settlement_error)
        raise


def _setup_abort_observed(journal, ip, nft, tc, settled):
    """Freshly prove the last setup identity without reissuing its mutation."""
    import completion_kata_operation as operation
    retained = settled[-1]["identity"]; action = Action(settled[-1]["action"])
    expected = _effect_source_ids(action, retained)[1:]
    history = operation._network_history(journal)
    starts = [index for index, (kind, _body) in enumerate(history)
              if kind == "NETWORK_CLEANUP_INTENT_V2"]
    if not starts: raise NetworkError("setup abort intent absent")
    end = next((index for index in range(starts[-1] + 1, len(history))
                if history[index][0] == "NETWORK_EFFECT_INTENT_V2" and
                history[index][1]["action"] in {item.value for item in
                    (Action.IP_NETNS_REMOVE, Action.NFT_REMOVE_ATOMIC)}), len(history))
    rows = [body for kind, body in history[starts[-1] + 1:end]
            if kind == operation.network_journal.OUTPUT_RECORD and
            body["chunk_index"] + 1 == body["chunk_count"]]
    if end == len(history):
        raws = _observer_pass(journal, ip, nft, tc, expected, "NETWORK_CLEANUP_INTENT_V2")
        rows = _sources(journal, "NETWORK_CLEANUP_INTENT_V2")
    else:
        if tuple(row["source_id"] for row in rows) != expected:
            raise NetworkError("setup abort identity proof incomplete")
        raws = tuple(_source_raw(journal, row) for row in rows)
    outputs = [{"source_id": action.value, "raw": b""}, *(
        {"source_id": name, "raw": raw} for name, raw in zip(expected, raws, strict=True))]
    scope = "ready" if action is _SETUP_ACTIONS[-1] else "effect"
    return _derive_journal_identity(scope, action.value, outputs, retained)[0]


def _abort_fixed_setup(journal, ip, nft, tc):
    """Reverse a settled setup prefix once, then durably enter cleanup-only absence."""
    import completion_kata_operation as operation
    try:
        nft_owner.require_active(journal)
        baselines, rows = _baselines(journal)
        if rows[-1]["snapshot_kind"] == "network-absent":
            phase = operation._durable_phase(journal)
            if phase != "NETWORK_ABSENT":
                _settle_cleanup(journal, "network", "NETWORK_ABSENT")
            elif _network_cleanup_active(journal):
                journal.settle_network_cleanup("network")
            nft_owner.settle_free(journal, "network")
            return rows[-1]
        if len(rows) != 1 or rows[0]["snapshot_kind"] != "baseline":
            raise NetworkError("setup abort order")
        history = operation._network_history(journal)
        effect_rows = [(kind, body) for kind, body in history
                       if kind in operation.network_journal.RECORDS]
        if effect_rows and effect_rows[-1][0] != "NETWORK_EFFECT_SETTLED_V2":
            if effect_rows[-1][1]["action"] not in {item.value for item in
                    (Action.IP_NETNS_REMOVE, Action.NFT_REMOVE_ATOMIC)}:
                raise NetworkError("unsettled setup effect cannot abort")
            _resume_effect(journal, ip, nft, tc)
        settled = _settled_effects(journal)
        setup = []
        for expected, body in zip(_SETUP_ACTIONS, settled, strict=False):
            if body["action"] != expected.value: break
            setup.append(body)
        if not setup or len(setup) > len(_SETUP_ACTIONS):
            raise NetworkError("settled setup prefix absent")
        suffix = [body["action"] for body in settled[len(setup):]]
        expected_suffix = [Action.IP_NETNS_REMOVE.value]
        if setup[-1]["identity"]["nft"] is not None:
            expected_suffix.append(Action.NFT_REMOVE_ATOMIC.value)
        if suffix != expected_suffix[:len(suffix)]:
            raise NetworkError("setup abort effect order")
        journal.begin_network_cleanup("network")
        current = _setup_abort_observed(journal, ip, nft, tc, setup)
        retained = setup[-1]["identity"]
        for name in ("netns", "host_link", "peer_link", "nft"):
            if current[name] != retained[name]:
                raise NetworkError("failed-setup identity replacement")
        if Action.IP_NETNS_REMOVE.value not in suffix:
            _quarantine_netns(journal, retained)
            retained = _effect(journal, Action.IP_NETNS_REMOVE, ip, nft, tc, retained)
        else:
            retained = settled[len(setup)]["identity"]
        if _quarantine_stage(journal) is not None:
            _cleanup_detached_placeholders(journal)
        if retained["nft"] is not None and Action.NFT_REMOVE_ATOMIC.value not in suffix:
            table_name = retained["nft"]["table_name"]
            if not re.fullmatch(r"c42t[0-9a-f]{10}", table_name):
                raise NetworkError("setup abort nft table binding")
            retained = _effect(journal, Action.NFT_REMOVE_ATOMIC, ip, nft, tc, retained)
        elif Action.NFT_REMOVE_ATOMIC.value in suffix:
            retained = settled[-1]["identity"]
        raws, mountinfo, fresh = _fresh_baseline_outputs(journal, ip, nft, tc)
        if fresh != baselines or _netns_identity(journal, mountinfo) is not None:
            drift = tuple(name for name in _BASELINE_KEYS if fresh[name] != baselines[name])
            raise NetworkError(f"setup abort baseline not restored:{drift!r}")
        qstage = _quarantine_stage(journal)
        if qstage is None or qstage[0] != "NETWORK_DETACHED_V2":
            raise NetworkError("setup abort namespace not detached")
        for path in ("/run/netns/" + _bound_names(journal)[0],
                     "/run/netns/" + _quarantine_name(journal), PRESERVED_DIR,
                     "/run/netns/" + PRESERVED_REMOVING, PARENT_STAGE_DIR,
                     "/run/" + PARENT_STAGE_REMOVING):
            if os.path.lexists(path): raise NetworkError("setup abort placeholder residue")
        body = _snapshot(journal, "network-absent", baselines, retained,
                         _sources(journal, "NETWORK_SNAPSHOT_V2"))
        _settle_cleanup(journal, "network", "NETWORK_ABSENT")
        nft_owner.settle_free(journal, "network")
        return body
    except BaseException as error:
        try: _poison_fixed_network(journal, "incomplete")
        except BaseException as settlement_error:
            raise NetworkCleanupError(error, settlement_error)
        raise


def _poison_fixed_network(journal, reason="unknown"):
    journal.record_uncertain(reason)


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


def _runtime_network_routes():
    """Issue one operation-bound nsfs grant from a retained durable snapshot."""
    owners = owner_helpers.Registry(
        "_RuntimeNetworkOwner", NetworkError, "runtime network owner",
        sealed_message="sealed runtime network owner")
    grants = owner_helpers.Registry(
        "_RuntimeNetworkGrant", NetworkError, "runtime network grant",
        sealed_message="sealed runtime network grant")
    _RuntimeNetworkOwner, _RuntimeNetworkGrant = owners.kind, grants.kind
    def observe(path, descriptor):
        stat = os.fstat(descriptor)
        return parse_netns_identity(_read_mountinfo(), NetnsStat(stat.st_dev, stat.st_ino), path)
    def reopen(journal):
        import completion_kata_operation as operation
        rows = operation._network_records(journal)
        if not rows or rows[-1]["snapshot_kind"] not in {"ready", "discovered", "runtime"}:
            raise NetworkError("runtime network snapshot")
        expected = rows[-1]["identity"]["netns"]; path = "/run/netns/" + expected["name"]
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        try:
            observed = observe(path, descriptor)
            if _netns_value(observed) != expected: raise NetworkError("runtime nsfs identity")
        except BaseException:
            os.close(descriptor); raise
        return owners.issue([
            journal, descriptor, observed,
            operation._command_context(journal).operation_token, False,
        ])
    def claim(owner, journal):
        state = owners.require(owner)
        if state[0] is not journal or state[4]:
            raise NetworkError("runtime network owner")
        state[4] = True
        return grants.issue([owner, False])
    def verify(grant):
        row = grants.require(grant)
        state = owners.require(row[0])
        path = state[2].mount_point
        if observe(path, state[1]) != state[2]: raise NetworkError("runtime nsfs replacement")
        return {"operation_token": state[3], "identity": _netns_value(state[2]), "path": path}
    def consume(grant):
        row = grants.require(grant)
        if row[1]: raise NetworkError("spent runtime network grant")
        value = verify(grant); row[1] = True; return value
    def descriptor(grant):
        verify(grant)
        return os.dup(owners.require(grants.require(grant)[0])[1])
    def close(owner):
        state = owners.pop(owner)
        os.close(state[1])
        for grant, row in grants.items():
            if row[0] is owner:
                grants.pop(grant)
    return reopen, claim, verify, consume, descriptor, close

(_reopen_runtime_network, _claim_runtime_network, _verify_runtime_network,
 _consume_runtime_network, _runtime_network_descriptor, _close_runtime_network) = _runtime_network_routes()
del _runtime_network_routes


def open_fixed_network_owner(*_args, **_kwargs):
    raise NetworkError("production unavailable pending exact qualified host-tool fixtures and command permits")


# No public/generic executor, caller argv/path/deadline, shell, broad reset,
# translation, adoption, retry, fallback, or forced removal route exists.

#!/usr/bin/env python3
"""Offline hostile matrix for the closed Kata network-state contracts."""
import copy
import json
import os
from pathlib import Path
import sys

if sys.flags.optimize:
    raise RuntimeError("network tests refuse Python optimization")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_network as network


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def rejected(function):
    try:
        function()
    except network.NetworkError:
        return
    raise AssertionError("hostile network snapshot accepted")


# Fixed builders remain closed and bind candidate tool contracts, never executables.
commands = {item.action: item for item in network.mutation_snapshots_for_tests()}
assert commands[network.Action.NETNS_ADD].argv_tail == ("netns", "add", "cogs-stage2-ssh")
assert commands[network.Action.LINK_ADD].argv_tail == (
    "link", "add", "name", "c42h0", "address", "02:00:00:42:00:01", "type", "veth",
    "peer", "name", "c42g0", "address", "02:00:00:42:00:02",
)
assert commands[network.Action.HOST_ADDRGEN_NONE].argv_tail == (
    "link", "set", "dev", "c42h0", "addrgenmode", "none",
)
assert commands[network.Action.PEER_ADDRGEN_NONE].argv_tail[-2:] == ("addrgenmode", "none")
assert commands[network.Action.LOOPBACK_UP].argv_tail[-2:] == ("lo", "up")
assert commands[network.Action.GUEST_ADDRESS_ADD].argv_tail[-3:] == ("192.0.2.2/30", "dev", "eth0")
assert commands[network.Action.NFT_INSTALL].stdin == network.NFT_TRANSACTION
assert commands[network.Action.NFT_REMOVE].argv_tail == (
    "delete", "table", "inet", "cogs_stage2_ssh_v1",
)
assert commands[network.Action.NFT_INSTALL_OWNED].stdin == network.NFT_OWNED_TRANSACTION
assert commands[network.Action.NFT_REMOVE_ATOMIC].stdin == network.NFT_DELETE_TRANSACTION
assert commands[network.Action.HOST_LINK_REMOVE].argv_tail == ("link", "delete", "dev", "c42h0")
assert commands[network.Action.NETNS_REMOVE].argv_tail == ("netns", "delete", "cogs-stage2-ssh")
assert commands[network.Action.IP_VETH_ADD_ATOMIC].argv_tail[-4:] == ("address", network.GUEST_MAC, "netns", network.NETNS)
assert len(commands) == 18
assert all("qualification-candidate" in item.tool_contract for item in commands.values())
assert network.QUALIFICATION_CANDIDATE.startswith("UNQUALIFIED_")
assert network.NFT_TRANSACTION.endswith(b'add rule inet cogs_stage2_ssh_v1 forward oifname "c42h0" drop\n')
assert b"policy accept" in network.NFT_TRANSACTION and b"priority filter" in network.NFT_TRANSACTION
assert b"flush" not in network.NFT_TRANSACTION and b"nat" not in network.NFT_TRANSACTION.lower()
rejected(lambda: network.command("NETNS_ADD"))
rejected(lambda: network.open_fixed_network_owner())

fake = network.make_test_local_fake((b"one", b"two"))
assert fake.issue(network.Action.NETNS_ADD) == b"one"
assert fake.issue(network.Action.NFT_INSTALL) == b"two"
assert fake.calls == [commands[network.Action.NETNS_ADD], commands[network.Action.NFT_INSTALL]]
fake.close()
rejected(lambda: fake.issue(network.Action.NETNS_ADD))

# Real iproute2-shaped link qualification candidates and exact peer identity.
host_links_json = [{
    "ifindex": 7, "ifname": "c42h0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
    "operstate": "UP", "link_type": "ether", "address": "02:00:00:42:00:01",
    "qdisc": "noqueue", "link_index": 8, "addrgenmode": "none",
    "linkinfo": {"info_kind": "veth"},
}]
ns_links_json = [
    {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"],
     "operstate": "UNKNOWN", "link_type": "loopback", "address": "00:00:00:00:00:00", "qdisc": "noqueue"},
    {"ifindex": 8, "ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
     "operstate": "UP", "link_type": "ether", "address": "02:00:00:42:00:02", "qdisc": "noqueue",
     "link_index": 7, "addrgenmode": "none", "linkinfo": {"info_kind": "veth"}},
]
parsed_host = network.parse_links(encoded(host_links_json), False)
parsed_ns = network.parse_links(encoded(ns_links_json), True)
host, guest = network.validate_peer_pair(parsed_host, parsed_ns)
assert (host.ifindex, guest.ifindex) == (7, 8)
rejected(lambda: network.validate_peer_pair(parsed_host, parsed_ns[:-1]))
for mutate in (
    lambda value: value.append(copy.deepcopy(value[-1])),
    lambda value: value[-1].update(address="02:00:00:42:00:03"),
    lambda value: value[-1].update(qdisc="fq_codel"),
    lambda value: value[-1].update(addrgenmode="eui64"),
    lambda value: value.append({**value[0], "ifindex": 9, "ifname": "tun0"}),
):
    hostile = copy.deepcopy(ns_links_json)
    mutate(hostile)
    rejected(lambda hostile=hostile: network.parse_links(encoded(hostile), True))

# Complete address inventories are cross-bound by retained name and ifindex.
host_addresses = [{"ifindex": 7, "ifname": "c42h0", "addr_info": [
    {"family": "inet", "local": "192.0.2.1", "prefixlen": 30, "scope": "global"},
]}]
ns_addresses = [
    {"ifindex": 1, "ifname": "lo", "addr_info": [
        {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
        {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"},
    ]},
    {"ifindex": 8, "ifname": "eth0", "addr_info": [
        {"family": "inet", "local": "192.0.2.2", "prefixlen": 30, "scope": "global"},
    ]},
]
assert len(network.parse_addresses(encoded(host_addresses), False, parsed_host)) == 1
assert len(network.parse_addresses(encoded(ns_addresses), True, parsed_ns)) == 3
assert network.parse_addresses(b"[]", False, ()) == ()
for hostile, namespace, links in (
    ([{"ifindex": 99, "ifname": "other0", "addr_info": []}], False, parsed_host),
    ([{**host_addresses[0], "ifindex": 8}], False, parsed_host),
    (ns_addresses + [{"ifindex": 99, "ifname": "other0", "addr_info": []}], True, parsed_ns),
):
    rejected(lambda hostile=hostile, namespace=namespace, links=links:
             network.parse_addresses(encoded(hostile), namespace, links))
hostile = copy.deepcopy(ns_addresses)
hostile[1]["addr_info"].append({"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"})
rejected(lambda: network.parse_addresses(encoded(hostile), True, parsed_ns))

# Complete normal iproute2 IPv4/IPv6 route candidates, including loopback and types.
routes4 = [
    {"dst": "192.0.2.0/30", "dev": "eth0", "protocol": "kernel", "scope": "link", "prefsrc": "192.0.2.2"},
    {"type": "local", "dst": "127.0.0.0/8", "dev": "lo", "table": "local", "protocol": "kernel", "scope": "host", "prefsrc": "127.0.0.1"},
    {"type": "local", "dst": "127.0.0.1", "dev": "lo", "table": "local", "protocol": "kernel", "scope": "host", "prefsrc": "127.0.0.1"},
    {"type": "broadcast", "dst": "127.255.255.255", "dev": "lo", "table": "local", "protocol": "kernel", "scope": "link", "prefsrc": "127.0.0.1"},
    {"type": "local", "dst": "192.0.2.2", "dev": "eth0", "table": "local", "protocol": "kernel", "scope": "host", "prefsrc": "192.0.2.2"},
    {"type": "broadcast", "dst": "192.0.2.3", "dev": "eth0", "table": "local", "protocol": "kernel", "scope": "link", "prefsrc": "192.0.2.2"},
]
routes6 = [{"type": "local", "dst": "::1", "dev": "lo", "table": "local",
            "protocol": "kernel", "metric": 0, "flags": [], "pref": "medium"}]
host_routes4 = [
    {"dst": "192.0.2.0/30", "dev": "c42h0", "protocol": "kernel", "scope": "link", "prefsrc": "192.0.2.1"},
    {"type": "local", "dst": "192.0.2.1", "dev": "c42h0", "table": "local", "protocol": "kernel", "scope": "host", "prefsrc": "192.0.2.1"},
    {"type": "broadcast", "dst": "192.0.2.3", "dev": "c42h0", "table": "local", "protocol": "kernel", "scope": "link", "prefsrc": "192.0.2.1"},
]
assert len(network.parse_routes(encoded(routes4), 4, parsed_ns)) == 6
assert len(network.parse_routes(encoded(routes6), 6, parsed_ns)) == 1
assert len(network.parse_routes(encoded(host_routes4), 4, parsed_host)) == 3
assert len(network.parse_routes(encoded([{key: value for key, value in row.items() if key != "dev"}
                                         for row in host_routes4]), 4, parsed_host)) == 3
assert network.parse_routes(b"[]", 6, parsed_host) == ()
for hostile, family in (
    (routes4 + [{"type": "blackhole", "dst": "203.0.113.0/24", "dev": "lo", "table": "main", "protocol": "kernel"}], 4),
    (routes4 + [copy.deepcopy(routes4[0])], 4),
    ([{"dst": "default", "dev": "eth0", "protocol": "static", "gateway": "192.0.2.1"}], 4),
    ([{**routes6[0], "dev": "eth0"}], 6),
    ([{**routes6[0], "scope": "host"}], 6),
):
    rejected(lambda hostile=hostile, family=family: network.parse_routes(encoded(hostile), family, parsed_ns))
rejected(lambda: network.parse_routes(encoded(routes4), 4, parsed_host))
rejected(lambda: network.parse_routes(encoded(host_routes4 + [{**host_routes4[0], "dev": "other0"}]), 4, parsed_host))

# Duplicate members, malformed depth/scalars, and byte bounds fail closed.
rejected(lambda: network.parse_links(b'[{"ifindex":1,"ifindex":2}]', False))
assert network.parse_links(b"[]", False) == ()
rejected(lambda: network.parse_links(b"[]", True))
rejected(lambda: network.parse_links(b"[" * 20 + b"]" * 20, False))
rejected(lambda: network.parse_links(b"x" * (network.MAX_JSON + 1), False))

# Canonical libnftables set expressions, grouped output order, and retained handles.
def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def meta(key):
    return {"meta": {"key": key}}


def payload(protocol, field):
    return {"payload": {"protocol": protocol, "field": field}}


def verdict(name):
    return {name: None}


rules = {
    "input": [
        [match(meta("iifname"), "c42h0"), match(payload("ip", "saddr"), "192.0.2.2"),
         match(payload("ip", "daddr"), "192.0.2.1"), match(payload("tcp", "sport"), 22),
         match({"ct": {"key": "state"}}, {"set": ["established"]}, "in"), verdict("accept")],
        [match(meta("iifname"), "c42h0"), verdict("drop")],
    ],
    "output": [
        [match(meta("oifname"), "c42h0"), match(payload("ip", "saddr"), "192.0.2.1"),
         match(payload("ip", "daddr"), "192.0.2.2"), match(payload("tcp", "dport"), 22),
         match({"ct": {"key": "state"}}, {"set": ["new", "established"]}, "in"), verdict("accept")],
        [match(meta("oifname"), "c42h0"), verdict("drop")],
    ],
    "forward": [
        [match(meta("iifname"), "c42h0"), verdict("drop")],
        [match(meta("oifname"), "c42h0"), verdict("drop")],
    ],
}


def nft_fixture(handle_offset=0):
    rows = [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": "cogs_stage2_ssh_v1", "handle": 7 + handle_offset}},
    ]
    rule_handle = 20 + handle_offset
    for chain_index, chain in enumerate(("input", "output", "forward")):
        rows.append({"chain": {"family": "inet", "table": "cogs_stage2_ssh_v1", "name": chain,
                               "type": "filter", "hook": chain, "prio": 0, "policy": "accept",
                               "handle": 8 + chain_index + handle_offset}})
    for chain in ("input", "output", "forward"):
        for expression in rules[chain]:
            rows.append({"rule": {"family": "inet", "table": "cogs_stage2_ssh_v1", "chain": chain,
                                  "expr": expression, "handle": rule_handle}})
            rule_handle += 1
    return {"nftables": rows}


nft = nft_fixture()
nft_snapshot = network.parse_nft_snapshot(encoded(nft))
assert nft_snapshot.identity.table_handle == 7
assert nft_snapshot.identity.chain_handles == (("input", 8), ("output", 9), ("forward", 10))
assert all("handle" not in json.dumps(row) for row in nft_snapshot.content["nftables"])
replaced_nft_snapshot = network.parse_nft_snapshot(encoded(nft_fixture(100)))
assert replaced_nft_snapshot.content == nft_snapshot.content
dynamic_nft = json.loads(json.dumps(nft).replace("cogs_stage2_ssh_v1", "c42taaaaaaaaaa").replace("c42h0", "c42haaaaaaaaaa"))
dynamic_nft["nftables"][1]["table"]["comment"] = "owner:c42taaaaaaaaaa"
network.parse_nft_snapshot(encoded(dynamic_nft), "c42taaaaaaaaaa", "c42haaaaaaaaaa")
assert replaced_nft_snapshot.identity != nft_snapshot.identity
native_singleton_nft = copy.deepcopy(nft)
native_singleton_nft["nftables"][5]["rule"]["expr"][4]["match"]["right"] = "established"
native_set_nft = copy.deepcopy(native_singleton_nft)
native_set_nft["nftables"][7]["rule"]["expr"][4]["match"]["right"] = ["established", "new"]
assert network.parse_nft_snapshot(encoded(native_singleton_nft)).content == nft_snapshot.content
assert network.parse_nft_snapshot(encoded(native_set_nft)).content == nft_snapshot.content
for change in ("policy", "interface", "duplicate", "bare-set", "ordering", "handle"):
    hostile = copy.deepcopy(nft)
    if change == "policy":
        hostile["nftables"][2]["chain"]["policy"] = "drop"
    if change == "interface":
        hostile["nftables"][-1]["rule"]["expr"][0]["match"]["right"] = "other0"
    if change == "duplicate":
        hostile["nftables"].append(copy.deepcopy(hostile["nftables"][-1]))
    if change == "bare-set":
        hostile["nftables"][5]["rule"]["expr"][4]["match"]["right"] = ["established", "invalid"]
    if change == "ordering":
        hostile["nftables"][2], hostile["nftables"][3] = hostile["nftables"][3], hostile["nftables"][2]
    if change == "handle":
        hostile["nftables"][-1]["rule"]["handle"] = hostile["nftables"][-2]["rule"]["handle"]
    rejected(lambda hostile=hostile: network.parse_nft_snapshot(encoded(hostile)))

# Complete mountinfo is bounded at 4096 and target fields correlate with descriptor stat.
inode = 4026533000
device = os.makedev(0, 4)
mountinfo = (
    b"30 20 8:1 / / rw,relatime - ext4 /dev/root rw\n"
    b"41 30 0:4 net:[4026533000] /run/netns/cogs-stage2-ssh rw - nsfs nsfs rw\n"
)
stat = network.NetnsStat(device, inode)
netns_identity = network.parse_netns_identity(mountinfo, stat)
assert (netns_identity.mount_id, netns_identity.device, netns_identity.inode) == (41, "0:4", inode)
shared_netns = network.parse_netns_identity(
    mountinfo.replace(b"cogs-stage2-ssh rw -", b"cogs-stage2-ssh rw shared:308 -"), stat)
assert shared_netns.optional_fields == ("shared:308",)
master_netns = network.parse_netns_identity(
    mountinfo.replace(b"cogs-stage2-ssh rw -", b"cogs-stage2-ssh rw master:309 -"), stat)
assert master_netns.optional_fields == ("master:309",)
both_netns = network.parse_netns_identity(
    mountinfo.replace(
        b"cogs-stage2-ssh rw -", b"cogs-stage2-ssh rw shared:308 master:309 -"), stat)
assert both_netns.optional_fields == ("shared:308", "master:309")
replacement_mount_netns = network.parse_netns_identity(mountinfo.replace(b"41 30", b"42 30"), stat)
replacement_inode_netns = network.parse_netns_identity(
    mountinfo.replace(b"4026533000", b"4026533001"), network.NetnsStat(device, inode + 1),
)
assert replacement_mount_netns != netns_identity and replacement_inode_netns != netns_identity
for hostile in (
    mountinfo + mountinfo.splitlines(keepends=True)[1],
    mountinfo.replace(b"0:4 net:", b"0:5 net:"),
    mountinfo.replace(b"net:[4026533000]", b"net:[4026533001]"),
    mountinfo.replace(b"- nsfs nsfs rw", b"- tmpfs nsfs rw"),
    mountinfo.replace(b"- nsfs nsfs rw", b"- nsfs other rw"),
    mountinfo.replace(b"cogs-stage2-ssh rw -", b"cogs-stage2-ssh ro -"),
    mountinfo.replace(b"cogs-stage2-ssh rw -", b"cogs-stage2-ssh rw shared:0 -"),
    mountinfo.replace(b"cogs-stage2-ssh rw -", b"cogs-stage2-ssh rw master:0 -"),
    mountinfo.replace(
        b"cogs-stage2-ssh rw -", b"cogs-stage2-ssh rw shared:308 shared:309 -"),
    mountinfo.replace(b"nsfs nsfs rw", b"nsfs nsfs rw,nosuid"),
):
    rejected(lambda hostile=hostile: network.parse_netns_identity(hostile, stat))
rejected(lambda: network.parse_netns_identity(b"x\n" * (network.MAX_MOUNTINFO_LINES + 1), stat))
rejected(lambda: network.parse_netns_identity(mountinfo, network.NetnsStat(os.makedev(0, 5), inode)))

# Real tc qdisc/filter/action candidate shapes bind both retained veth/TAP directions.
tap_json = {
    "ifindex": 30, "ifname": "tap-dynamic", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
    "operstate": "UP", "link_type": "ether", "address": "02:00:00:00:00:30", "qdisc": "noqueue",
    "addrgenmode": "none",
    "linkinfo": {"info_kind": "tun", "info_data": {"type": "tap", "pi": False, "vnet_hdr": True,
                                                          "multi_queue": False, "persist": False}},
}
parsed_runtime = network.parse_runtime_links(encoded(ns_links_json + [tap_json]))
tap = parsed_runtime[-1]
assert tap.kind == "tap" and tap.ifindex == 30
runtime_addresses = ns_addresses + [{"ifindex": 30, "ifname": "tap-dynamic", "addr_info": []}]
assert len(network.parse_runtime_addresses(encoded(runtime_addresses), parsed_runtime)) == 3
hostile_tap_addresses = copy.deepcopy(runtime_addresses)
hostile_tap_addresses[-1]["addr_info"] = [
    {"family": "inet6", "local": "fe80::30", "prefixlen": 64, "scope": "link"},
]
rejected(lambda: network.parse_runtime_addresses(encoded(hostile_tap_addresses), parsed_runtime))
specs = network.tc_observer_commands(guest, tap)
assert [item.action for item in specs] == [
    network.TcObservation.QDISC, network.TcObservation.INGRESS_FILTER,
    network.TcObservation.QDISC, network.TcObservation.INGRESS_FILTER,
]
assert specs[0].argv_tail == ("-n", "cogs-stage2-ssh", "-j", "qdisc", "show", "dev", "eth0")
assert specs[-1].argv_tail == (
    "-n", "cogs-stage2-ssh", "-j", "filter", "show", "dev", "tap-dynamic", "ingress",
)
qdisc_root = [{"kind": "noqueue", "handle": "0:", "root": True, "refcnt": 2, "options": {}}]
qdisc_ingress = qdisc_root + [{"kind": "ingress", "handle": "ffff:", "parent": "ffff:fff1"}]


def filter_fixture(target, action_index):
    header = {"protocol": "all", "pref": 49152, "kind": "u32", "chain": 0}
    return [
        {**header, "options": {"fh": "800:", "ht_divisor": 1}},
        {**header, "options": {
            "fh": "800::800", "ht": "800:", "order": 2048, "key_ht": 32768, "bkt": "0",
            "terminal": True, "not_in_hw": True,
            "match": {"value": "00000000", "mask": "00000000", "off": 0},
            "actions": [{"order": 1, "kind": "mirred", "control_action": {"type": "pipe"},
                         "index": action_index, "ref": 1, "bind": 1, "eaction": "redirect",
                         "direction": "egress", "to_dev": target}],
        }},
    ]


guest_root = network.parse_tc_qdiscs(encoded(qdisc_root), guest)
guest_qdiscs = network.parse_tc_qdiscs(encoded(qdisc_ingress), guest)
tap_qdiscs = network.parse_tc_qdiscs(encoded(qdisc_ingress), tap)
guest_filter = network.parse_tc_filters(encoded(filter_fixture("tap-dynamic", 11)), guest, tap)
tap_filter = network.parse_tc_filters(encoded(filter_fixture("eth0", 12)), tap, guest)
before_runtime = network.RuntimeState(netns_identity, parsed_host, parsed_ns, guest_root, ())
after_runtime = network.RuntimeState(netns_identity, parsed_host, parsed_ns + (tap,),
                                     guest_qdiscs + tap_qdiscs, guest_filter + tap_filter)
tc_binding = network.runtime_difference(before_runtime, after_runtime)
assert tc_binding.netns_identity == netns_identity
assert (tc_binding.host_veth.ifindex, tc_binding.guest_veth.ifindex, tc_binding.tap.ifindex) == (7, 8, 30)

# Durable replay uses the same pure codecs over retained canonical observer bytes.
def observation(source_id, raw): return {"source_id": source_id, "raw": raw}
ready_identity = network._identity(netns_identity, parsed_host[0], guest, nft_snapshot,
                                   tc=network._tc_value((guest_root[0],), ()))
discovered_outputs = [
    observation("IP_HOST_LINKS", encoded(host_links_json)),
    observation("IP_NS_LINKS", encoded(ns_links_json + [tap_json])),
    observation("IP_HOST_ADDRESSES", encoded(host_addresses)),
    observation("IP_NS_ADDRESSES", encoded(runtime_addresses)),
]
discovered_identity, _ = network._derive_journal_identity("discovered", None,
                                                           discovered_outputs, ready_identity, {})
assert discovered_identity["tap"]["ifname"] == "tap-dynamic"
stat_raw = json.dumps({"device": device, "inode": inode}, sort_keys=True,
                      separators=(",", ":")).encode()
runtime_outputs = [
    observation("IP_HOST_ROUTES4", encoded(host_routes4)), observation("IP_HOST_ROUTES6", b"[]"),
    observation("IP_NS_ROUTES4", encoded(routes4)), observation("IP_NS_ROUTES6", encoded(routes6)),
    observation("TC_QDISC", encoded(qdisc_ingress)), observation("TC_QDISC:tap-dynamic", encoded(qdisc_ingress)),
    observation("TC_INGRESS_FILTER:eth0", encoded(filter_fixture("tap-dynamic", 11))),
    observation("TC_INGRESS_FILTER:tap-dynamic", encoded(filter_fixture("eth0", 12))),
    observation("MOUNTINFO", mountinfo), observation("NETNS_STAT", stat_raw),
    observation("NFT_TABLE", encoded(nft)),
]
derived_runtime, _ = network._derive_journal_identity("runtime", None, runtime_outputs,
                                                        discovered_identity, {})
assert derived_runtime["tc"] == network._tc_value(tc_binding.qdiscs, tc_binding.filters)
assert network.runtime_restored(before_runtime, copy.deepcopy(before_runtime)) == before_runtime
for replacement in (replacement_mount_netns, replacement_inode_netns):
    hostile_runtime = network.RuntimeState(replacement, after_runtime.host_links,
                                           after_runtime.namespace_links, after_runtime.qdiscs,
                                           after_runtime.filters)
    rejected(lambda hostile_runtime=hostile_runtime:
             network.runtime_difference(before_runtime, hostile_runtime))
    hostile_restoration = network.RuntimeState(replacement, before_runtime.host_links,
                                               before_runtime.namespace_links, before_runtime.qdiscs,
                                               before_runtime.filters)
    rejected(lambda hostile_restoration=hostile_restoration:
             network.runtime_restored(before_runtime, hostile_restoration))
for hostile in (
    [{**qdisc_ingress[0], "refcnt": 3}, qdisc_ingress[1]],
    [qdisc_ingress[1], qdisc_ingress[0]],
    qdisc_ingress + [copy.deepcopy(qdisc_ingress[1])],
):
    rejected(lambda hostile=hostile: network.parse_tc_qdiscs(encoded(hostile), guest))
for change in ("target", "direction", "kind", "match", "extra-action"):
    hostile = filter_fixture("tap-dynamic", 11)
    action = hostile[1]["options"]["actions"][0]
    if change == "target": action["to_dev"] = "other0"
    if change == "direction": action["direction"] = "ingress"
    if change == "kind": hostile[0]["kind"] = "bpf"
    if change == "match": hostile[1]["options"]["match"]["mask"] = "ffffffff"
    if change == "extra-action": hostile[1]["options"]["actions"].append(copy.deepcopy(action))
    rejected(lambda hostile=hostile: network.parse_tc_filters(encoded(hostile), guest, tap))
for changed in ("ifname", "peer", "state", "qdisc"):
    links = list(parsed_host)
    item = links[0]
    updates = {
        "ifname": {**item.__dict__, "ifname": "renamed0"},
        "peer": {**item.__dict__, "peer_ifindex": 99},
        "state": {**item.__dict__, "up": False},
        "qdisc": {**item.__dict__, "qdisc": "fq_codel"},
    }
    links[0] = network.Link(**updates[changed])
    hostile_after = network.RuntimeState(netns_identity, tuple(links), after_runtime.namespace_links,
                                         after_runtime.qdiscs, after_runtime.filters)
    rejected(lambda hostile_after=hostile_after: network.runtime_difference(before_runtime, hostile_after))
wrong_filter = network.parse_tc_filters(encoded(filter_fixture("tap-dynamic", 11)), guest, tap)
rejected(lambda: network.runtime_difference(
    before_runtime,
    network.RuntimeState(netns_identity, parsed_host, parsed_ns + (tap,),
                         guest_qdiscs + tap_qdiscs, wrong_filter + wrong_filter),
))
rejected(lambda: network.runtime_restored(before_runtime, after_runtime))
synthetic_tap = copy.deepcopy(tap_json)
synthetic_tap["linkinfo"] = {"info_kind": "tap"}
rejected(lambda: network.parse_runtime_links(encoded(ns_links_json + [synthetic_tap])))

# Resource-specific durable recovery rejects adoption and enforces ordered teardown.
empty_proof = network.TeardownProof(())
stopped_proof = network.TeardownProof((network.TeardownPrerequisite.TASK_STOPPED,))
network_absent_proof = network.TeardownProof((
    network.TeardownPrerequisite.TASK_STOPPED,
    network.TeardownPrerequisite.NETWORK_AND_MOUNT_ABSENT,
))
firewall_ready_proof = network.TeardownProof((
    network.TeardownPrerequisite.TASK_STOPPED,
    network.TeardownPrerequisite.NETWORK_AND_MOUNT_ABSENT,
    network.TeardownPrerequisite.TASK_AND_CONTAINER_DELETED,
    network.TeardownPrerequisite.PROCESS_SHARE_MOUNTS_ABSENT,
))
rejected(lambda: network.TeardownProof((network.TeardownPrerequisite.NETWORK_AND_MOUNT_ABSENT,)))
rejected(lambda: network.TeardownProof((
    network.TeardownPrerequisite.TASK_STOPPED,
    network.TeardownPrerequisite.PROCESS_SHARE_MOUNTS_ABSENT,
)))

netns_create = network.NetnsTransition(network.TransitionPhase.CREATE_INTENT, netns_identity)
assert network.recover_netns(netns_create, network.NetnsObservation(None), empty_proof) is network.Recovery.PRESERVE
# Seeing a same-name object after unobserved create is not adoption, even with full identity.
assert network.recover_netns(netns_create, network.NetnsObservation(netns_identity), empty_proof) is network.Recovery.PRESERVE
netns_durable = network.NetnsTransition(network.TransitionPhase.IDENTITY_DURABLE, netns_identity)
assert network.recover_netns(netns_durable, network.NetnsObservation(netns_identity), empty_proof) is network.Recovery.SETTLED
netns_remove = network.NetnsTransition(network.TransitionPhase.REMOVE_INTENT, netns_identity)
assert network.recover_netns(netns_remove, network.NetnsObservation(netns_identity), empty_proof) is network.Recovery.PRESERVE
assert network.recover_netns(netns_remove, network.NetnsObservation(netns_identity), stopped_proof) is network.Recovery.REMOVE
assert network.recover_netns(netns_remove, network.NetnsObservation(None), stopped_proof) is network.Recovery.ABSENT
assert network.recover_netns(
    netns_remove, network.NetnsObservation(replacement_mount_netns), stopped_proof,
) is network.Recovery.PRESERVE

tc_create = network.TcTransition(network.TransitionPhase.CREATE_INTENT, tc_binding, netns_identity)
exact_tc = network.TcObservationState(tc_binding, netns_identity)
assert network.recover_tc(tc_create, exact_tc, empty_proof) is network.Recovery.PRESERVE
tc_remove = network.TcTransition(network.TransitionPhase.REMOVE_INTENT, tc_binding, netns_identity)
assert network.recover_tc(tc_remove, exact_tc, empty_proof) is network.Recovery.PRESERVE
assert network.recover_tc(tc_remove, exact_tc, stopped_proof) is network.Recovery.REMOVE
for replacement in (replacement_mount_netns, replacement_inode_netns):
    replacement_binding = network.TcBinding(
        replacement, tc_binding.host_veth, tc_binding.guest_veth, tc_binding.tap,
        tc_binding.qdiscs, tc_binding.filters,
    )
    hostile_tc = network.TcObservationState(replacement_binding, replacement)
    assert network.recover_tc(tc_remove, hostile_tc, stopped_proof) is network.Recovery.PRESERVE
rejected(lambda: network.recover_tc(
    tc_remove, network.TcObservationState(tc_binding, replacement_mount_netns), stopped_proof,
))

nft_create = network.NftTransition(network.TransitionPhase.CREATE_INTENT, nft_snapshot)
assert network.recover_nft(nft_create, network.NftObservation(nft_snapshot), empty_proof) is network.Recovery.PRESERVE
nft_remove = network.NftTransition(network.TransitionPhase.REMOVE_INTENT, nft_snapshot)
assert network.recover_nft(nft_remove, network.NftObservation(nft_snapshot), stopped_proof) is network.Recovery.PRESERVE
assert network.recover_nft(nft_remove, network.NftObservation(nft_snapshot), network_absent_proof) is network.Recovery.PRESERVE
assert network.recover_nft(nft_remove, network.NftObservation(nft_snapshot), firewall_ready_proof) is network.Recovery.REMOVE
# Identical normalized content with replacement handles is preserved, never removed.
assert network.recover_nft(nft_remove, network.NftObservation(replaced_nft_snapshot), firewall_ready_proof) is network.Recovery.PRESERVE
rejected(lambda: network.recover_nft(nft_remove, network.NftObservation(("cogs_stage2_ssh_v1",)), firewall_ready_proof))

print("completion Kata network owner fixed-snapshot matrix passed")

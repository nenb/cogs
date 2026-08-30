#!/usr/bin/env python3
"""Mandatory root/Linux isolated kernel fixture for the ADR0099 network owner."""
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import time
import sys

if sys.platform != "linux" or os.geteuid() != 0 or os.environ.get("COGS_REQUIRE_STAGE2_NETWORK_FOUNDATION") != "1":
    raise SystemExit("mandatory Linux/root network foundation guard closed")
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))
import completion_kata_network as network

suffix = secrets.token_hex(5)
netns, quarantine, host, table = "c42n" + suffix, "c42q" + suffix, "c42h" + suffix, "c42t" + suffix
tap_name = "tap" + suffix[:8]
created = {"parent_mount": False, "netns": False, "quarantine": False,
           "replacement": False, "nft": False, "tap_fd": None,
           "runtime_owner_fd": None, "launch_fd": None, "namespace_child": None}

def run(argv, stdin=None, allow=False):
    result = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={"HOME": "/root", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if not allow and (result.returncode != 0 or result.stderr):
        raise RuntimeError(f"command failed: {argv!r}: {result.returncode}: {result.stderr!r}")
    return result

def ip(*args): return run(("/usr/sbin/ip", *args)).stdout
def ns_ip(*args): return ip("-n", netns, *args)
def tc(*args): return run(("/usr/sbin/tc", "-n", netns, *args)).stdout

def host_baseline():
    commands = (("/usr/sbin/ip", "-j", "-d", "link", "show"),
        ("/usr/sbin/ip", "-j", "address", "show"),
        ("/usr/sbin/ip", "-4", "-j", "route", "show", "table", "all"),
        ("/usr/sbin/ip", "-6", "-j", "route", "show", "table", "all"),
        ("/usr/sbin/ip", "-j", "netns", "list"),
        ("/usr/sbin/nft", "-j", "list", "ruleset"))
    outputs = [run(command).stdout for command in commands]
    if outputs[4] == b"": outputs[4] = b"[]"
    values = [network._load(raw, network.MAX_NFT_ITEMS if index == 5 else network.MAX_ITEMS)
              for index, raw in enumerate(outputs)]
    normalized = [network._normalize_baseline_links(values[0]),
        *(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
          for value in values[1:5]), network._normalize_baseline_nft(values[5])]
    return tuple(hashlib.sha256(raw).hexdigest() for raw in normalized)

def checksum(raw):
    if len(raw) % 2: raw += b"\0"
    total = sum(struct.unpack(f"!{len(raw) // 2}H", raw))
    while total >> 16: total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def guest_frame(protocol, destination, port, sequence):
    source_ip, destination_ip = socket.inet_aton("192.0.2.2"), socket.inet_aton(destination)
    if protocol == socket.IPPROTO_TCP:
        transport = struct.pack("!HHLLBBHHH", 40000 + sequence, port, sequence, 0, 5 << 4, 2, 65535, 0, 0)
    else:
        transport = struct.pack("!HHHH", 50000 + sequence, port, 8, 0)
    pseudo = source_ip + destination_ip + struct.pack("!BBH", 0, protocol, len(transport))
    transport_checksum = checksum(pseudo + transport)
    if protocol == socket.IPPROTO_TCP:
        transport = transport[:16] + struct.pack("!H", transport_checksum) + transport[18:]
    elif transport_checksum:
        transport = transport[:6] + struct.pack("!H", transport_checksum)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), sequence,
                            0x4000, 64, protocol, 0, source_ip, destination_ip)
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    ethernet = bytes.fromhex(network.HOST_MAC.replace(":", "")) + bytes.fromhex(
        network.GUEST_MAC.replace(":", "")) + struct.pack("!H", 0x0800)
    return ethernet + ip_header + transport

def mountinfo(): return Path("/proc/self/mountinfo").read_bytes()
def ns_identity(name):
    path = "/run/netns/" + name; seen = os.stat(path, follow_symlinks=False)
    return network.parse_netns_identity(mountinfo(), network.NetnsStat(seen.st_dev, seen.st_ino), path)

def same_moved_identity(first, second):
    return all(getattr(first, name) == getattr(second, name) for name in
               ("mount_id", "parent_id", "device", "inode_device", "inode"))

def move_to_quarantine(expected):
    source, target = "/run/netns/" + netns, "/run/netns/" + quarantine
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600); os.close(fd)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(source.encode(), target.encode(), None, 8192, None) != 0:
        saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
    os.unlink(source); created["netns"] = False; created["quarantine"] = True
    if not same_moved_identity(ns_identity(quarantine), expected):
        raise AssertionError("quarantined nsfs identity changed")

def netns_references(pid, target, identity=None):
    references = []
    if os.readlink(f"/proc/{pid}/ns/net") == target: references.append((pid, "ns"))
    for name in os.listdir(f"/proc/{pid}/fd"):
        path = f"/proc/{pid}/fd/{name}"
        try:
            link = os.readlink(path); seen = os.stat(path)
            same = identity is not None and (seen.st_dev, seen.st_ino) == (
                identity.inode_device, identity.inode)
            if link == target or same: references.append((pid, int(name)))
        except FileNotFoundError: pass
    return references

def nft_input():
    return network.NFT_OWNED_TRANSACTION.replace(network.TABLE.encode(), table.encode()).replace(network.HOST_IF.encode(), host.encode())

baseline = host_baseline()
try:
    network._prepare_netns_parent(); created["parent_mount"] = True
    ip("netns", "add", netns); created["netns"] = True
    network._prepare_netns_parent()
    retained_ns = ns_identity(netns)
    created["runtime_owner_fd"] = os.open("/run/netns/" + netns, os.O_RDONLY | os.O_CLOEXEC)
    created["launch_fd"] = os.dup(created["runtime_owner_fd"])
    created["namespace_child"] = subprocess.Popen(
        ("/usr/sbin/ip", "netns", "exec", netns, "/bin/sleep", "30"),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ip("link", "add", "name", host, "address", network.HOST_MAC, "type", "veth",
       "peer", "name", network.GUEST_IF, "address", network.GUEST_MAC, "netns", netns)
    run(("/usr/sbin/nft", "-f", "-"), nft_input()); created["nft"] = True
    ip("address", "add", network.HOST_CIDR, "dev", host)
    ip("link", "set", "dev", host, "addrgenmode", "none")
    ns_ip("link", "set", "dev", network.GUEST_IF, "addrgenmode", "none")
    ns_ip("link", "set", "dev", "lo", "up")
    ns_ip("address", "add", network.GUEST_CIDR, "dev", network.GUEST_IF)
    ip("link", "set", "dev", host, "up"); ns_ip("link", "set", "dev", network.GUEST_IF, "up")

    host_links = network.parse_links(ip("-j", "-d", "link", "show", "dev", host), False, host)
    namespace = network.parse_links(ns_ip("-j", "-d", "link", "show"), True)
    host_link, guest = network.validate_peer_pair(host_links, namespace, host)
    network.parse_addresses(ip("-j", "address", "show", "dev", host), False, host_links, host)
    network.parse_addresses(ns_ip("-j", "address", "show"), True, namespace)
    network.parse_routes(ip("-4", "-j", "route", "show", "table", "all", "dev", host), 4, host_links, host)
    network.parse_routes(ip("-6", "-j", "route", "show", "table", "all", "dev", host), 6, host_links, host)
    network.parse_routes(ns_ip("-4", "-j", "route", "show", "table", "all"), 4, namespace)
    network.parse_routes(ns_ip("-6", "-j", "route", "show", "table", "all"), 6, namespace)
    nft_state = network.parse_nft_snapshot(run(("/usr/sbin/nft", "-j", "list", "table", "inet", table)).stdout,
                                           table, host)

    tun = os.open("/dev/net/tun", os.O_RDWR | os.O_CLOEXEC); created["tap_fd"] = tun
    flags = 0x0002 | 0x1000 | 0x4000
    fcntl.ioctl(tun, 0x400454CA, struct.pack("16sH", tap_name.encode(), flags))
    ip("link", "set", "dev", tap_name, "netns", netns)
    ns_ip("link", "set", "dev", tap_name, "addrgenmode", "none"); ns_ip("link", "set", "dev", tap_name, "up")
    tc("qdisc", "add", "dev", network.GUEST_IF, "ingress"); tc("qdisc", "add", "dev", tap_name, "ingress")
    tc("filter", "add", "dev", network.GUEST_IF, "ingress", "protocol", "all", "pref", "49152",
       "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", tap_name)
    tc("filter", "add", "dev", tap_name, "ingress", "protocol", "all", "pref", "49152",
       "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", network.GUEST_IF)
    runtime_links = network.parse_runtime_links(ns_ip("-j", "-d", "link", "show"))
    tap = next(item for item in runtime_links if item.kind == "tap")
    network.parse_runtime_addresses(ns_ip("-j", "address", "show"), runtime_links)
    guest_q = network.parse_tc_qdiscs(tc("-j", "qdisc", "show", "dev", network.GUEST_IF), guest)
    tap_q = network.parse_tc_qdiscs(tc("-j", "qdisc", "show", "dev", tap_name), tap)
    filters = (network.parse_tc_filters(tc("-j", "filter", "show", "dev", network.GUEST_IF, "ingress"), guest, tap) +
               network.parse_tc_filters(tc("-j", "filter", "show", "dev", tap_name, "ingress"), tap, guest))
    binding = network.runtime_difference(network.RuntimeState(retained_ns, host_links, namespace, (guest_q[0],), ()),
        network.RuntimeState(retained_ns, host_links, runtime_links, guest_q + tap_q, filters))
    if len(binding.qdiscs) != 4 or len(binding.filters) != 4: raise AssertionError("runtime tc difference")

    before = network.parse_nft_snapshot(run(("/usr/sbin/nft", "-j", "list", "table", "inet", table)).stdout,
                                        table, host)
    frames = ((socket.IPPROTO_TCP, "192.0.2.1", network.DIRECT_TCP_PORT),
              (socket.IPPROTO_UDP, "192.0.2.1", network.DIRECT_UDP_PORT),
              (socket.IPPROTO_TCP, network.ROUTE_PROBE_ADDRESS, network.ROUTE_TCP_PORT),
              (socket.IPPROTO_UDP, network.ROUTE_PROBE_ADDRESS, network.ROUTE_UDP_PORT))
    for sequence, (protocol, destination, port) in enumerate(frames, 1):
        if os.write(tun, b"\0" * 10 + guest_frame(protocol, destination, port, sequence)) <= 0:
            raise AssertionError("TAP frame injection failed")
    deadline = time.monotonic() + 3
    expected = {"direct-tcp-denied", "direct-udp-denied", "route-tcp-denied", "route-udp-denied"}
    while True:
        after = network.parse_nft_snapshot(run(("/usr/sbin/nft", "-j", "list", "table", "inet", table)).stdout,
                                           table, host)
        first, second = ({row.sensor: row for row in snapshot.counters} for snapshot in (before, after))
        if all(second[name].packets > first[name].packets for name in expected): break
        if time.monotonic() >= deadline: raise AssertionError("causal TAP/nft sensor timeout")
        time.sleep(0.05)
    if before != after: raise AssertionError("counter traffic changed immutable nft identity")
    for name, row in second.items():
        delta = row.packets - first[name].packets
        if (name in expected) != (delta > 0):
            raise AssertionError(f"unexpected nft sensor delta:{name}:{delta}")

    # Name detachment is not absence: runtime-owner, launch-duplicate, TAP,
    # and a role process all retain the exact nsfs inode until retirement.
    move_to_quarantine(retained_ns)
    # Crash/reopen cut: only the quarantined name survives and retains exact nsfs identity.
    if (not same_moved_identity(ns_identity(quarantine), retained_ns)
            or Path("/run/netns/" + netns).exists()):
        raise AssertionError("quarantine crash cut is not recoverable")
    ip("netns", "add", netns); created["replacement"] = True
    network._prepare_netns_parent()
    replacement = ns_identity(netns)
    if same_moved_identity(replacement, retained_ns):
        raise AssertionError("replacement nsfs not distinct")
    target = f"net:[{retained_ns.inode}]"
    if not netns_references(os.getpid(), target, retained_ns):
        raise AssertionError("detached runtime/launch nsfs fds escaped census")
    if not netns_references(created["namespace_child"].pid, target, retained_ns):
        raise AssertionError("detached role process netns escaped census")
    ip("netns", "delete", quarantine); created["quarantine"] = False
    if not Path("/sys/class/net/" + host).exists():
        raise AssertionError("detached namespace was declared absent while holds remained")
    if ns_identity(netns) != replacement: raise AssertionError("quarantine cleanup deleted replacement")
    # Simulated task/process retirement precedes every runtime network close.
    created["namespace_child"].terminate(); created["namespace_child"].wait(timeout=5)
    created["namespace_child"] = None
    for key in ("launch_fd", "runtime_owner_fd", "tap_fd"):
        os.close(created[key]); created[key] = None
    if netns_references(os.getpid(), target, retained_ns):
        raise AssertionError("nsfs fd census remained after final close")
    ip("netns", "delete", netns); created["replacement"] = False
    if Path("/sys/class/net/" + host).exists():
        deleted = run(("/usr/sbin/ip", "link", "delete", "dev", host), allow=True)
        if deleted.returncode != 0 and Path("/sys/class/net/" + host).exists():
            raise RuntimeError("exact host veth deletion failed")
    if Path("/sys/class/net/" + host).exists():
        raise AssertionError("host veth survived exact cleanup")
    # The same kernel transaction lists and deletes only the retained table handle.
    delete_batch = (network.NFT_DELETE_TRANSACTION.replace(network.TABLE.encode(), table.encode())
                    .replace(network.TABLE_HANDLE.encode(), str(nft_state.identity.table_handle).encode()))
    conditional = run(("/usr/sbin/nft", "-j", "-f", "-"), delete_batch, allow=True)
    if conditional.returncode == 0 and not conditional.stderr:
        if conditional.stdout:
            observed = network.parse_nft_snapshot(conditional.stdout, table, host)
            if observed.identity != nft_state.identity:
                raise AssertionError("conditional nft output identity changed")
        listed = run(("/usr/sbin/nft", "-j", "list", "table", "inet", table), allow=True)
        if listed.returncode == 0:
            retained = network.parse_nft_snapshot(listed.stdout, table, host)
            if retained.identity != nft_state.identity:
                raise AssertionError("conditional nft no-op changed replacement")
            run(("/usr/sbin/nft", "delete", "table", "inet", table))
        created["nft"] = False
    else:
        retained = network.parse_nft_snapshot(run(("/usr/sbin/nft", "-j", "list", "table", "inet", table)).stdout,
                                              table, host)
        if retained.identity != nft_state.identity: raise AssertionError("unsupported conditional delete changed replacement")
        run(("/usr/sbin/nft", "delete", "table", "inet", table)); created["nft"] = False
finally:
    if created["namespace_child"] is not None:
        try: created["namespace_child"].terminate(); created["namespace_child"].wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired): created["namespace_child"].kill()
    for key in ("tap_fd", "launch_fd", "runtime_owner_fd"):
        if created[key] is not None:
            try: os.close(created[key])
            except OSError: pass
    for name in (quarantine, netns): run(("/usr/sbin/ip", "netns", "delete", name), allow=True)
    run(("/usr/sbin/ip", "link", "delete", "dev", host), allow=True)
    run(("/usr/sbin/nft", "delete", "table", "inet", table), allow=True)
    for name in (quarantine, netns):
        if Path("/run/netns/" + name).exists(): raise RuntimeError("network namespace cleanup residue")
    if created["parent_mount"]:
        parent = network._netns_parent_mount()
        if parent is None or parent[:3] != ("/netns", "tmpfs", "tmpfs") or parent[3]:
            raise RuntimeError("owned private netns parent changed")
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.umount2(b"/run/netns", 2) != 0:
            saved = ctypes.get_errno(); raise OSError(saved, os.strerror(saved))
        created["parent_mount"] = False
        if network._netns_parent_mount() is not None:
            raise RuntimeError("owned private netns parent remains")
if host_baseline() != baseline:
    raise RuntimeError("final links/addresses/routes/netns/nft baseline drift")
print("completion Kata Linux network namespace foundation passed")

#!/usr/bin/env python3
"""Portable byte-snapshot and hostile codec tests for the ADR0099 guest plan."""

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_guest_workloads_v2 as guest
import completion_guest_workloads_v3 as guest_v3
import completion_guest_readiness_v1 as readiness
import completion_fixtures as fixtures


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def rejected(raw):
    try:
        guest.parse_guest_workload_output(raw)
    except guest.WorkloadError:
        return
    raise RuntimeError("hostile guest output was accepted")


program = guest.guest_program_bytes()
snapshot = (ROOT / "test/fixtures/stage2-completion/guest-workload-v1.sh").read_bytes()
check(program == snapshot, "guest stdin snapshot differs")
check(hashlib.sha256(program).hexdigest() == guest.GUEST_PROGRAM_SHA256, "guest stdin digest differs")
check(program.isascii() and program.endswith(b"\n") and b"\x00" not in program, "guest stdin encoding differs")
for forbidden in (b"http:", b"https:", b"curl", b"wget", b"fetch", b"retry", b"fallback", b"$@", b"eval "):
    check(forbidden not in program, "open guest-program surface")
for required in (
    b'invariant\n/usr/bin/printf', b'git_sample 01 01', b'git_sample 07 07',
    b'build_sample 01 08', b'build_sample 07 14', b'install_sample 01 15',
    b'install_sample 07 21', b'deleted=true', b'/run/cogs-stage2-ssh/work',
):
    check(required in program, "closed plan snapshot is incomplete")

# P1 regression: END must preserve an earlier mount failure, and all four custom
# mounts must have exact observable type/source/security/private semantics.
text = program.decode("ascii")
mount_awk = text.split("/usr/bin/awk '\n", 1)[1].split("\n  ' /proc/self/mountinfo", 1)[0]
valid_mounts = """10 1 0:1 / /run/cogs-stage2-ssh rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=65536k,nr_inodes=16384,mode=700
11 10 0:2 /mounts/random-a /run/cogs-stage2-ssh/ssh_host_ed25519_key ro,nosuid,nodev,noexec - virtiofs kataShared rw
12 10 0:2 /mounts/random-b /run/cogs-stage2-ssh/authorized_keys ro,nosuid,nodev,noexec - virtiofs kataShared rw
13 10 0:2 /mounts/random-c /run/cogs-stage2-ssh/input ro,nosuid,nodev,noexec - virtiofs kataShared rw
"""

def awk_status(raw):
    return subprocess.run(("awk", mount_awk), input=raw, text=True, capture_output=True, check=False).returncode

check(awk_status(valid_mounts) == 0, "exact mount contract rejected")
for hostile in (
    valid_mounts.replace("/input ro,", "/input rw,"),  # reviewed exit-override reproduction
    valid_mounts.replace(" - virtiofs kataShared", " shared:1 - virtiofs kataShared", 1),
    valid_mounts.replace(" - virtiofs kataShared", " - ext4 kataShared", 1),
    valid_mounts.replace(" - virtiofs kataShared", " - virtiofs hostile", 1),
    valid_mounts.replace("/mounts/random-b", "/mounts/random-a"),
    valid_mounts.replace("/mounts/random-c", "/mounts/random/c"),
    valid_mounts.replace("/mounts/random-c", "/mounts/."),
    valid_mounts.replace("/mounts/random-c", "/mounts/.."),
    valid_mounts.replace("/mounts/random-c", r"/mounts/random\040c"),
    valid_mounts.replace("ro,nosuid,nodev,noexec", "ro,nosuid,nodev", 1),
    valid_mounts + "14 10 0:1 /x /run/cogs-stage2-ssh/work rw - tmpfs tmpfs rw\n",
):
    check(awk_status(hostile) != 0, "hostile mount contract accepted")

# P1 metadata regression: PR397's sealed 0555/0444 view has a different logical
# identity.  The copied build tree is now normalized and then fully reverified.
package = fixtures.fixed_fixtures().package
readonly_records = tuple(dataclasses.replace(row, mode=0o555 if row.kind == "directory" else 0o444)
                         for row in package.source.records)
readonly_digest = hashlib.sha256(b"".join(fixtures._canonical_line(fixtures._record_value(row))
                                             for row in readonly_records)).hexdigest()
check(readonly_digest != package.source.logical_digest, "mode drift reproduction disappeared")
for required in (
    'normalize_source "$p/source"', '/bin/chmod 0755', '/bin/chmod 0644',
    '/bin/chown 0:0', '/usr/bin/touch -d @1782172800',
    'verify_metadata "$check" 4 256', 'verify_metadata "$p/installed" 4 256',
):
    check(required in text, "logical metadata correction is incomplete")

# P2 regression: all seven BUILD and all seven INSTALL rebuilds contribute an
# observed SHA-256/size tuple to one structural equality chain, without a pin.
check(text.count('observe_deb "$p/package.deb"') == 2, "build observation call sites differ")
for required in ("DEB_REFERENCE_SHA=", "DEB_REFERENCE_SIZE=", "DEB_BUILD_COUNT=0",
                 '/usr/bin/sha256sum -- "$deb"', "/usr/bin/stat -c '%s'",
                 '"$observed_sha:$observed_size" = "$DEB_REFERENCE_SHA:$DEB_REFERENCE_SIZE"',
                 '[ "$DEB_BUILD_COUNT" -eq 14 ]'):
    check(required in text, "deb structural comparison is incomplete")

# P3 regression: the historical shell idiom succeeds when traversal fails.  No
# find emptiness/count pipeline or command substitution remains; empty_tree
# itself propagates a real find failure before considering output emptiness.
old_idiom = subprocess.run(("/bin/sh", "-c", '[ -z "$(false)" ]'), check=False).returncode
check(old_idiom == 0, "find-failure reproduction changed")
check("$(/usr/bin/find" not in text and not any("/usr/bin/find" in row and "|" in row for row in text.splitlines()),
      "non-fail-closed find check remains")
empty_body = "empty_tree() {" + text.split("empty_tree() {", 1)[1].split("\n}", 1)[0] + "\n}"
with tempfile.TemporaryDirectory() as temporary:
    output = str(Path(temporary) / "rows")
    probe = f"set -eu\n{empty_body}\nempty_tree {temporary}/absent {output}\n"
    check(subprocess.run(("/bin/sh", "-c", probe), capture_output=True, check=False).returncode != 0,
          "find failure converted to empty success")

lines = [guest.GUEST_READY_MARKER]
for ordinal, (label, digest) in enumerate(guest.GUEST_WORKLOAD_PLAN, 1):
    lines.append(
        f"{guest.GUEST_RESULT_PREFIX}|{ordinal:02d}|{label}|{ordinal}|{digest}|deleted=true\n".encode("ascii")
    )
valid = b"".join(lines)
parsed = guest.parse_guest_workload_output(valid)
check(len(parsed.samples) == 21, "sample cardinality differs")
check(tuple(sample.ordinal for sample in parsed.samples) == tuple(range(1, 22)), "ordinals differ")
check(tuple(sample.category for sample in parsed.samples) == tuple(row[0] for row in guest.GUEST_WORKLOAD_PLAN), "plan differs")
check(all(sample.deleted for sample in parsed.samples), "deletion truth differs")
canonical_result = guest.canonical_guest_workload_result(parsed)
check(guest.parse_canonical_guest_workload_result(canonical_result) == parsed,
      "canonical parsed result did not round trip")
for hostile_result in (canonical_result[:-1],
                       canonical_result.replace(b'"ordinal":1', b'"ordinal":2', 1)):
    try:
        guest.parse_canonical_guest_workload_result(hostile_result)
    except guest.WorkloadError:
        pass
    else:
        raise RuntimeError("hostile canonical result was accepted")

# Missing, duplicate, extra, reordered, malformed, late, noncanonical,
# wrong-digest, and deletion-false streams all fail as one complete object.
rejected(b"".join(lines[:-1]))
rejected(b"".join(lines + [lines[-1]]))
rejected(b"".join(lines + [b"late\n"]))
rejected(b"".join([lines[0], lines[1], lines[1], *lines[3:]]))
rejected(b"".join([lines[0], lines[2], lines[1], *lines[3:]]))
rejected(b"".join([lines[1], lines[0], *lines[2:]]))
rejected(valid[:-1])
rejected(valid + b"\n")
rejected(valid.replace(b"|1|", b"|01|", 1))
rejected(valid.replace(b"|1|", b"|1200001|", 1))
rejected(valid.replace(b"|01|GIT_01|", b"|1|GIT_01|", 1))
rejected(valid.replace(b"|GIT_01|", b"|GIT_02|", 1))
rejected(valid.replace(guest.GUEST_WORKLOAD_PLAN[0][1].encode(), b"f" * 64, 1))
rejected(valid.replace(b"deleted=true", b"deleted=false", 1))
rejected(valid.replace(b"COGS_STAGE2_RESULT_V1", b"cogs_stage2_result_v1", 1))
rejected(valid.replace(b"\n", b"\r\n", 1))
rejected(valid + b"\x80")
rejected(bytearray(valid))
rejected(b"x" * (guest.GUEST_OUTPUT_LIMIT + 1))

# Every grammar mutation at every ordinal is rejected, including duplicates
# whose category and digest otherwise look valid.
for index in range(1, len(lines)):
    row = lines[index]
    rejected(b"".join([*lines[:index], row.replace(b"deleted=true", b"deleted=false"), *lines[index + 1 :]]))
    rejected(b"".join([*lines[:index], row.replace(f"|{index:02d}|".encode(), b"|00|", 1), *lines[index + 1 :]]))

# V3 is an additive route. Historical V2 stdin and canonical milliseconds stay
# byte-for-byte covered above rather than being silently reinterpreted.
program_v3 = guest_v3.guest_program_bytes()
snapshot_v3 = (ROOT / "test/fixtures/stage2-completion/guest-workload-v3.sh").read_bytes()
check(program_v3 == snapshot_v3, "V3 guest stdin snapshot differs")
check(hashlib.sha256(program_v3).hexdigest() == guest_v3.GUEST_PROGRAM_SHA256,
      "V3 guest stdin digest differs")
text_v3 = program_v3.decode("ascii")
mount_awk_v3 = text_v3.split("/usr/bin/awk '\n", 1)[1].split("\n  ' /proc/self/mountinfo", 1)[0]
native_mounts = """114 113 0:41 / /run/cogs-stage2-ssh rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,size=65536k,nr_inodes=16384,mode=700
115 114 0:34 /cogs-stage2-ssh-v1-4b987a1b02c2312d-ssh_host_ed25519_key /run/cogs-stage2-ssh/ssh_host_ed25519_key ro,nosuid,nodev,noexec,relatime - virtiofs kataShared rw
116 114 0:34 /cogs-stage2-ssh-v1-47c903dd2bba27ba-authorized_keys /run/cogs-stage2-ssh/authorized_keys ro,nosuid,nodev,noexec,relatime - virtiofs kataShared rw
118 114 0:42 / /run/cogs-stage2-ssh/input ro,nosuid,nodev,noexec,relatime - virtiofs none rw
"""
def awk_status_v3(raw):
    return subprocess.run(("awk", mount_awk_v3), input=raw, text=True,
                          capture_output=True, check=False).returncode
check(awk_status_v3(native_mounts) == 0, "native Kata guest mounts rejected")
for hostile in (
    native_mounts.replace("47c903dd2bba27ba", "47c903dd2bba27bg"),
    native_mounts.replace(" - virtiofs none rw", " - virtiofs kataShared rw"),
    native_mounts.replace("/run/cogs-stage2-ssh/input ro,", "/run/cogs-stage2-ssh/input rw,"),
):
    check(awk_status_v3(hostile) != 0, "hostile native Kata guest mount accepted")
source_v3 = (REMOTE / "completion_guest_workloads_v3.py").read_bytes()
config_v3 = json.loads(
    (ROOT / "config/stage2-completion-ssh-workload-v3.json").read_bytes())
check(config_v3 == {
    "canonical_result_version": "cogs.stage2-guest-workload-result/v3",
    "cleanup_reserve_ns": 30_000_000_000,
    "final_deb_bytes": guest_v3.FINAL_DEB_BYTES,
    "final_deb_sha256": guest_v3.FINAL_DEB_SHA256,
    "final_installed_bytes": guest_v3.FINAL_INSTALLED_BYTES,
    "final_installed_entries": guest_v3.FINAL_INSTALLED_ENTRIES,
    "final_installed_tree_sha256": guest_v3.FINAL_INSTALLED_TREE_SHA256,
    "guest_program_sha256": guest_v3.GUEST_PROGRAM_SHA256,
    "parser": "completion_guest_workloads_v3.parse_guest_workload_output",
    "source_path": "deploy/aws-feasibility/remote/completion_guest_workloads_v3.py",
    "source_sha256": hashlib.sha256(source_v3).hexdigest(),
    "total_deadline_ns": 1_200_000_000_000,
    "version": "cogs.stage2-completion-ssh-workload/v3",
}, "V3 workload config/source binding differs")
text_v3 = program_v3.decode("ascii")
check(guest_v3.FINAL_DEB_SHA256 ==
      "08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf"
      and guest_v3.FINAL_DEB_BYTES == 1_064_816,
      "V3 final DEB constants differ")
check(guest_v3.FINAL_INSTALLED_TREE_SHA256 ==
      "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2"
      and guest_v3.FINAL_INSTALLED_ENTRIES == 259
      and guest_v3.FINAL_INSTALLED_BYTES == 1_048_576,
      "V3 final installed-tree constants differ")
for forbidden in ("DEB_REFERENCE_SHA", "DEB_REFERENCE_SIZE", "/1000000", "duration_ms"):
    check(forbidden not in text_v3, "V3 retained an unpinned or rounded meaning")
for required in (
    "FINAL_DEB_SHA=08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf",
    "FINAL_DEB_SIZE=1064816", '[ "$observed_sha" = "$FINAL_DEB_SHA" ]',
    '[ "$observed_size" -eq "$FINAL_DEB_SIZE" ]',
    "ELAPSED=$(($2-$1))", '[ "$ELAPSED" -gt 0 ]',
    'require_sha "$scratch.tree" "$FINAL_TREE_SHA"',
    '[ "$observed_bytes" -eq "$FINAL_TREE_BYTES" ]',
    '[ "$DEB_BUILD_COUNT" -eq 14 ]', "COGS_STAGE2_SSH_READY_V2",
):
    check(required in text_v3, "V3 final-pin/nanosecond plan is incomplete")
check(text_v3.count('observe_deb "$p/package.deb"') == 2,
      "V3 build and install build sites differ")
check(text_v3.count('verify_installed_tree "$p/installed"') == 1
      and text_v3.count('verify_installed_tree "$check"') == 1,
      "V3 package extraction/install tree checks differ")
check("| /usr/bin" not in text_v3 and "$(/usr/bin/find" not in text_v3,
      "V3 find failure can be hidden by a pipeline or substitution")

route_sha = "a" * 64
lines_v3 = [guest_v3.GUEST_READY_MARKER]
for ordinal, marker in enumerate(guest_v3.GUEST_NETWORK_MARKERS, 1):
    suffix = f"|route_sha256={route_sha}" if ordinal in {1, 8} else ""
    lines_v3.append(
        f"{guest_v3.GUEST_NETWORK_PREFIX}|{ordinal:02d}|{marker}{suffix}\n".encode("ascii"))
for ordinal, (label, digest) in enumerate(guest_v3.GUEST_WORKLOAD_PLAN, 1):
    lines_v3.append(
        f"{guest_v3.GUEST_RESULT_PREFIX}|{ordinal:02d}|{label}|{ordinal}|{digest}|deleted=true\n".encode("ascii")
    )
valid_v3 = b"".join(lines_v3)
parsed_v3 = guest_v3.parse_guest_workload_output(valid_v3)
check(len(parsed_v3.samples) == 21 and parsed_v3.samples[0].duration_ns == 1
      and parsed_v3.network_markers == guest_v3.GUEST_NETWORK_MARKERS
      and parsed_v3.route_before_sha256 == parsed_v3.route_after_sha256 == route_sha,
      "V3 network/nanosecond result differs")
check(tuple(row.category for row in parsed_v3.samples)
      == tuple(row[0] for row in guest_v3.GUEST_WORKLOAD_PLAN),
      "V3 21-row order differs")
canonical_v3 = guest_v3.canonical_guest_workload_result(parsed_v3)
check(b'"duration_ns"' in canonical_v3 and b'"duration_ms"' not in canonical_v3
      and b'"version":"cogs.stage2-guest-workload-result/v3"' in canonical_v3,
      "V3 canonical timing/version differs")
check(guest_v3.parse_canonical_guest_workload_result(canonical_v3) == parsed_v3,
      "V3 canonical result did not round trip")
for hostile in (
    valid_v3.replace(b"|1|", b"|0|", 1),
    valid_v3.replace(b"|1|", b"|1200000000001|", 1),
    valid_v3.replace(b"deleted=true", b"deleted=false", 1),
    valid_v3.replace(guest_v3.FINAL_DEB_SHA256.encode("ascii"), b"f" * 64, 1),
    valid_v3.replace(b"COGS_STAGE2_RESULT_V2", b"COGS_STAGE2_RESULT_V1", 1),
    b"".join([lines_v3[0], lines_v3[2], lines_v3[1], *lines_v3[3:]]),
):
    try:
        guest_v3.parse_guest_workload_output(hostile)
    except guest_v3.WorkloadError:
        pass
    else:
        raise RuntimeError("hostile V3 guest output was accepted")
for hostile in (
    canonical_v3.replace(b'"duration_ns":1', b'"duration_ns":0', 1),
    canonical_v3.replace(b'"duration_ns":1', b'"duration_ns":1200000000001', 1),
    canonical_v3.replace(b'"deleted":true', b'"deleted":false', 1),
):
    try:
        guest_v3.parse_canonical_guest_workload_result(hostile)
    except guest_v3.WorkloadError:
        pass
    else:
        raise RuntimeError("hostile V3 canonical result was accepted")

# Exercise the literal shell tree codec where the production GNU userland is
# available. This independently proves that its stream is exactly the reviewed
# logical-tree digest rather than merely checking source text.
if platform.system() == "Linux" and os.geteuid() == 0:
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary)
        installed = base / "installed"
        installed.mkdir(mode=0o755)
        for record in fixtures.fixed_fixtures().package.installed.records[1:]:
            path = installed / record.path
            if record.kind == "directory":
                path.mkdir(mode=record.mode)
            else:
                path.write_bytes(record.content)
                path.chmod(record.mode)
        for record in reversed(fixtures.fixed_fixtures().package.installed.records):
            path = installed if record.path == "." else installed / record.path
            path.chmod(record.mode)
            os.utime(path, (record.mtime, record.mtime))
        helpers = (
            "line_count() {"
            + text_v3.split("line_count() {", 1)[1].split("mount_invariant() {", 1)[0]
            + "metadata_rows() {"
            + text_v3.split("metadata_rows() {", 1)[1].split("observe_deb() {", 1)[0]
            + "verify_installed_tree() {"
            + text_v3.split("verify_installed_tree() {", 1)[1].split("git_sample() {", 1)[0]
        )
        probe = (
            "set -eu\n"
            "FINAL_TREE_SHA=" + guest_v3.FINAL_INSTALLED_TREE_SHA256 + "\n"
            "FINAL_TREE_ENTRIES=259\nFINAL_TREE_BYTES=1048576\n"
            "INSTALLED_MANIFEST=f0d03497ac0a1784d0cb0c6bd7dd13932eb376c131fd550de438cefa25deb483\n"
            + helpers
            + f'\nverify_installed_tree "{installed}" "{base / "scratch"}"\n'
        )
        result = subprocess.run(("/bin/sh", "-c", probe), capture_output=True, check=False)
        check(result.returncode == 0,
              "literal V3 installed-tree shell codec failed: " + result.stderr.decode("utf-8", "replace"))

# Marker-only readiness is a distinct inert program/codec with no workload API.
readiness_raw = readiness.guest_program_bytes()
readiness_snapshot = (ROOT / "test/fixtures/stage2-completion/guest-readiness-v1.sh").read_bytes()
readiness_contract = json.loads(
    (ROOT / "config/stage2-completion-ssh-readiness-v1.json").read_bytes())
check(readiness_raw == readiness_snapshot
      and readiness_raw != guest_v3.guest_program_bytes()
      and hashlib.sha256(readiness_raw).hexdigest() == readiness.GUEST_PROGRAM_SHA256
      == readiness_contract["guest_program_sha256"], "readiness program pin")
check(readiness_contract["guest_program_size"] == len(readiness_raw)
      and readiness_contract["guest_output_limit"] == len(readiness.GUEST_READY_MARKER)
      and readiness_contract["marker_sha256"] == readiness.MARKER_SHA256
      and readiness_contract["parser_sha256"] == readiness.PARSER_SHA256
      and readiness_contract["source_path"] ==
          "deploy/aws-feasibility/remote/completion_guest_readiness_v1.py"
      and readiness_contract["source_sha256"] == hashlib.sha256(
          (REMOTE / "completion_guest_readiness_v1.py").read_bytes()).hexdigest(),
      "readiness contract")
check(readiness.parse_guest_readiness_output(readiness.GUEST_READY_MARKER) ==
      readiness.GUEST_READY_MARKER, "readiness parser")
for hostile in (b"", readiness.GUEST_READY_MARKER[:-1],
                readiness.GUEST_READY_MARKER + b"x",
                readiness.GUEST_READY_MARKER * 2, b"warning\n"):
    rejected(lambda hostile=hostile: readiness.parse_guest_readiness_output(hostile))
check(not hasattr(readiness, "GuestWorkloadResult")
      and not hasattr(readiness, "parse_guest_workload_output")
      and b"COGS_STAGE2_RESULT" not in readiness_raw,
      "readiness cannot reach workload codec")

print("completion guest workload program tests passed")

#!/usr/bin/env python3
"""Portable byte-snapshot and hostile codec tests for the ADR0099 guest plan."""

import dataclasses
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_guest_workloads_v2 as guest
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

print("completion guest workload program tests passed")

#!/usr/bin/env python3
"""Observation-only invoker for the workflow-bound native Linux C1 gate."""

import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_FILE = ".github/workflows/ci.yml"
INVOKER_FILE = "test/aws-stage2-completion-rootfs-builder-native.py"
NATIVE_TEST_FILE = "test/aws-stage2-completion-rootfs-builder.py"
BUILDER_TEST = ROOT / NATIVE_TEST_FILE
SUDO = Path("/usr/bin/sudo")
PYTHON = Path("/usr/bin/python3")
NAMESPACES = ("pid", "mnt", "user", "cgroup")
ROOT_MOUNT_FIELDS = (
    "mount_id", "parent_id", "major_minor", "mount_root", "mount_point", "mount_options",
    "fs_type", "source_sha256", "super_options",
)
EXPECTED_FIELDS = (
    "REPOSITORY", "WORKFLOW_FILE", "JOB", "EVENT", "ACTION", "RUN_ID", "RUN_ATTEMPT",
    "ENVELOPE_SHA", "EVENT_MERGE_SHA", "WORKFLOW_REF", "WORKFLOW_SHA", "BASE_SHA",
    "PR_NUMBER", "HEAD_REPOSITORY", "HEAD_SHA", "CHECKED_OUT_SHA", "WORKFLOW_BLOB_DIGEST",
)
GITHUB_FIELDS = (
    "CI", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS",
    "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_JOB",
    "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_SHA",
    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
)
PRESERVED_FIELDS = GITHUB_FIELDS + tuple(f"COGS_C1_EXPECTED_{name}" for name in EXPECTED_FIELDS)
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
DECIMAL_PATTERN = re.compile(r"[1-9][0-9]*")


def require(value, message):
    if not value:
        raise RuntimeError(f"native Linux C1 invoker: {message}")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def encoded(value):
    return base64.b64encode(canonical(value)).decode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def pairs(rows):
    value = {}
    for key, item in rows:
        require(key not in value, "duplicate JSON field")
        value[key] = item
    return value


def parse_record(raw):
    require(0 < len(raw) <= 1_048_576, "missing or oversized privileged record")
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _value: require(False, "record constant"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("native Linux C1 invoker: malformed privileged record") from error


def exact_fields(value, fields, name):
    require(type(value) is dict and set(value) == set(fields), f"invalid {name} shape")


def read_json(path):
    raw = path.read_bytes()
    require(0 < len(raw) <= 1_048_576, "missing or oversized event")
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _value: require(False, "event constant"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("native Linux C1 invoker: malformed event") from error


def git(*arguments, input_bytes=None):
    result = subprocess.run(
        ["/usr/bin/git", *arguments], cwd=ROOT, input=input_bytes, capture_output=True, check=False,
    )
    require(result.returncode == 0, f"git observation failed: {arguments[0]}")
    return result.stdout


def expected_values():
    values = {name.lower(): os.environ.get(f"COGS_C1_EXPECTED_{name}", "")
              for name in EXPECTED_FIELDS}
    require(all(values.values()), "missing expected workflow metadata")
    return values


def nested(value, *keys):
    for key in keys:
        require(type(value) is dict and key in value, "missing event observation")
        value = value[key]
    return value


def validate_revision_domains(envelope_sha, event_merge_sha, head_sha, base_sha, workflow_sha,
                              checked_out_sha):
    for name, value in (("envelope", envelope_sha), ("event merge", event_merge_sha)):
        require(SHA_PATTERN.fullmatch(value) is not None, f"malformed {name} revision")
        require(value not in {head_sha, base_sha},
                f"{name} revision collapsed into source domain")
    values = (head_sha, base_sha, workflow_sha, checked_out_sha)
    require(all(SHA_PATTERN.fullmatch(value) is not None for value in values),
            "malformed source or workflow revision domain")
    require(head_sha != base_sha, "head and base source revisions collapsed")
    require(checked_out_sha == head_sha, "checked-out source revision differs")
    require(workflow_sha in {envelope_sha, head_sha} and workflow_sha != base_sha,
            "workflow revision is outside the execution/source domains")


def validate_synthetic_context(envelope_sha, event_merge_sha, github_sha, event_payload_merge_sha):
    require(envelope_sha == github_sha, "envelope revision differs from GitHub SHA context")
    require(event_merge_sha == event_payload_merge_sha,
            "event merge revision differs from event payload context")


def workflow_observations():
    expected = expected_values()
    fixed = {
        "repository": "nenb/cogs", "workflow_file": WORKFLOW_FILE, "job": "native-c1",
        "event": "pull_request", "run_attempt": "1",
    }
    require(all(expected[name] == value for name, value in fixed.items()),
            "fixed workflow identity mismatch")
    require(expected["action"] in {"opened", "reopened", "synchronize"},
            "unexpected pull request action")
    for name in ("run_id", "run_attempt", "pr_number"):
        require(DECIMAL_PATTERN.fullmatch(expected[name]) is not None, f"malformed {name}")
    validate_revision_domains(
        expected["envelope_sha"], expected["event_merge_sha"], expected["head_sha"],
        expected["base_sha"], expected["workflow_sha"], expected["checked_out_sha"],
    )
    require(re.fullmatch(r"[0-9a-f]{64}", expected["workflow_blob_digest"]) is not None,
            "malformed workflow blob digest")
    require(expected["head_repository"] == expected["repository"],
            "pull request head repository mismatch")
    workflow_ref_pattern = re.escape(f'{expected["repository"]}/{WORKFLOW_FILE}@refs/') + r".+"
    require(re.fullmatch(workflow_ref_pattern, expected["workflow_ref"]) is not None,
            "workflow ref mismatch")

    fixed_environment = {
        "GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24",
        "GITHUB_WORKFLOW": "CI", "GITHUB_JOB": "native-c1",
        "GITHUB_REPOSITORY": expected["repository"], "GITHUB_EVENT_NAME": expected["event"],
        "GITHUB_SHA": expected["envelope_sha"], "GITHUB_RUN_ID": expected["run_id"],
        "GITHUB_RUN_ATTEMPT": expected["run_attempt"],
        "GITHUB_WORKFLOW_REF": expected["workflow_ref"],
        "GITHUB_WORKFLOW_SHA": expected["workflow_sha"],
    }
    require(all(os.environ.get(name) == value for name, value in fixed_environment.items()),
            "GitHub runner observation mismatch")
    event_path = Path(os.environ.get("GITHUB_EVENT_PATH", ""))
    require(event_path.is_absolute() and event_path.is_file(), "event observation unavailable")
    event = read_json(event_path)
    event_pairs = {
        "action": nested(event, "action"), "pr_number": nested(event, "number"),
        "repository": nested(event, "repository", "full_name"),
        "event_merge_sha": nested(event, "pull_request", "merge_commit_sha"),
        "base_sha": nested(event, "pull_request", "base", "sha"),
        "head_repository": nested(event, "pull_request", "head", "repo", "full_name"),
        "head_sha": nested(event, "pull_request", "head", "sha"),
    }
    validate_synthetic_context(
        expected["envelope_sha"], expected["event_merge_sha"],
        os.environ.get("GITHUB_SHA", ""), str(event_pairs["event_merge_sha"]),
    )
    for name, value in event_pairs.items():
        require(str(value) == expected[name], f"event {name} mismatch")

    head = git("rev-parse", "--verify", "HEAD").decode().strip()
    require(head == expected["head_sha"], "checked-out HEAD mismatch")
    require(git("diff", "--quiet", "HEAD", "--") == b"", "tracked source changed after checkout")
    workflow_bytes = (ROOT / WORKFLOW_FILE).read_bytes()
    require(git("show", f"HEAD:{WORKFLOW_FILE}") == workflow_bytes,
            "workflow bytes differ from source head")
    file_hash = hashlib.sha256(workflow_bytes).digest()
    workflow_blob_digest = hashlib.sha256(file_hash).hexdigest()
    require(workflow_blob_digest == expected["workflow_blob_digest"],
            "reviewed workflow blob digest mismatch")

    source_files = (
        WORKFLOW_FILE, INVOKER_FILE, NATIVE_TEST_FILE,
        "deploy/aws-feasibility/remote/completion_rootfs_builder.py",
        "deploy/aws-feasibility/remote/completion_rootfs_fs.py",
        "deploy/aws-feasibility/remote/completion_rootfs_ledger.py",
    )
    blobs = {}
    for path in source_files:
        source_bytes = (ROOT / path).read_bytes()
        require(git("show", f"HEAD:{path}") == source_bytes, f"{path} differs from source head")
        blobs[path] = git("rev-parse", f"HEAD:{path}").decode().strip()
        require(SHA_PATTERN.fullmatch(blobs[path]) is not None, f"malformed blob for {path}")

    envelope = {
        "repository": expected["repository"], "workflow_file": expected["workflow_file"],
        "job": expected["job"], "event": expected["event"], "action": expected["action"],
        "run_id": expected["run_id"], "run_attempt": expected["run_attempt"],
        "envelope_sha": expected["envelope_sha"],
        "event_merge_sha": expected["event_merge_sha"],
        "workflow_ref": expected["workflow_ref"], "workflow_sha": expected["workflow_sha"],
        "base_sha": expected["base_sha"],
        "pull_request_number": expected["pr_number"],
    }
    source = {
        "head_repository": expected["head_repository"], "source_sha": expected["head_sha"],
        "checked_out_sha": head, "reviewed_implementation_sha": head,
        "workflow_source_sha": head, "invoker_source_sha": head,
        "native_test_source_sha": head,
        "workflow_blob_digest": expected["workflow_blob_digest"],
        "workflow_file_sha256": file_hash.hex(), "git_blobs": blobs,
    }
    require(all(envelope[name] not in {source["source_sha"], envelope["base_sha"]}
                for name in ("envelope_sha", "event_merge_sha")),
            "execution and source domains are not distinct")
    return {"execution_envelope": envelope, "source": source,
            "runner_environment": fixed_environment}


def mount_root(pid):
    rows = []
    for line in Path(f"/proc/{pid}/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[4] == "/" and "-" in fields:
            separator = fields.index("-")
            rows.append(fields[:6] + fields[separator + 1:separator + 4])
    require(len(rows) == 1, "ambiguous root mount")
    fields = rows[0]
    return {
        "mount_id": fields[0], "parent_id": fields[1], "major_minor": fields[2],
        "mount_root": fields[3], "mount_point": fields[4], "mount_options": fields[5],
        "fs_type": fields[6], "source_sha256": hashlib.sha256(fields[7].encode()).hexdigest(),
        "super_options": fields[8],
    }


CONTAINER_TOKENS = (b"docker", b"kubepods", b"containerd", b"libpod", b"podman", b"lxc")


def cgroup2_identity(pid):
    rows = [line.split() for line in Path(f"/proc/{pid}/mountinfo").read_text().splitlines()
            if " - cgroup2 " in line]
    require(len(rows) == 1 and rows[0][3] == "/", "non-root cgroup observation")
    return [rows[0][0], rows[0][2], rows[0][3]]


def process_observations(pid):
    namespaces = {}
    for name in NAMESPACES:
        identity = os.stat(f"/proc/{pid}/ns/{name}")
        namespaces[name] = [identity.st_dev, identity.st_ino]
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                  if ":" in line)
    nspid = [int(value) for value in status.get("NSpid", "").split()]
    require(nspid and len(nspid) == 1, "nested or malformed PID namespace")
    require(Path(f"/proc/{pid}/uid_map").read_text().split() == ["0", "0", "4294967295"],
            "non-initial user UID map")
    require(Path(f"/proc/{pid}/gid_map").read_text().split() == ["0", "0", "4294967295"],
            "non-initial user GID map")
    root = os.stat(f"/proc/{pid}/root")
    root_mount = mount_root(pid)
    require(root_mount["mount_root"] == root_mount["mount_point"] == "/", "changed root")
    require(root_mount["fs_type"] not in {"overlay", "aufs", "fuse.lxcfs", "9p"},
            "container root filesystem")
    return {
        "namespaces": namespaces, "nspid_depth": len(nspid),
        "root_identity": [root.st_dev, root.st_ino], "root_mount": root_mount,
        "cgroup2": cgroup2_identity(pid),
    }


def kernel_observation():
    kernel = os.uname()
    return {"sysname": kernel.sysname, "release": kernel.release, "machine": kernel.machine}


def reject_container_cgroup(pid):
    cgroup = Path(f"/proc/{pid}/cgroup").read_bytes().lower()
    require(cgroup, "cgroup observation absent")
    require(not any(token in cgroup for token in CONTAINER_TOKENS), "container cgroup present")


def parent_observations():
    """Collect only the unprivileged parent's own process evidence."""
    require(sys.platform == "linux", "Linux required")
    markers = ("/.dockerenv", "/.containerenv", "/run/.containerenv", "/run/systemd/container")
    require(not any(Path(path).exists() for path in markers), "container marker present")
    reject_container_cgroup("self")
    return {
        "classification": "observation-only", "version": 2,
        "kernel": kernel_observation(), "self": process_observations("self"),
    }


def valid_identity(value):
    return (type(value) is list and len(value) == 2 and
            all(type(item) is int and item >= 0 for item in value) and value[1] > 0)


def validate_process(value, name):
    exact_fields(value, ("namespaces", "nspid_depth", "root_identity", "root_mount", "cgroup2"), name)
    exact_fields(value["namespaces"], NAMESPACES, f"{name} namespaces")
    require(all(valid_identity(value["namespaces"][item]) for item in NAMESPACES),
            f"invalid {name} namespace identity")
    require(type(value["nspid_depth"]) is int and value["nspid_depth"] == 1,
            f"invalid {name} NSpid depth")
    require(valid_identity(value["root_identity"]), f"invalid {name} root identity")
    mount = value["root_mount"]
    exact_fields(mount, ROOT_MOUNT_FIELDS, f"{name} root mount")
    require(all(type(item) is str and item for item in mount.values()),
            f"invalid {name} root mount value")
    require(DECIMAL_PATTERN.fullmatch(mount["mount_id"]) is not None and
            re.fullmatch(r"[0-9]+", mount["parent_id"]) is not None and
            re.fullmatch(r"[0-9]+:[0-9]+", mount["major_minor"]) is not None and
            re.fullmatch(r"[0-9a-f]{64}", mount["source_sha256"]) is not None,
            f"malformed {name} root mount")
    require(mount["mount_root"] == mount["mount_point"] == "/", f"changed {name} root")
    require(mount["fs_type"] not in {"overlay", "aufs", "fuse.lxcfs", "9p"},
            f"container {name} root filesystem")
    cgroup = value["cgroup2"]
    require(type(cgroup) is list and len(cgroup) == 3 and
            DECIMAL_PATTERN.fullmatch(cgroup[0]) is not None and
            re.fullmatch(r"[0-9]+:[0-9]+", cgroup[1]) is not None and cgroup[2] == "/",
            f"invalid {name} cgroup2 identity")


def validate_parent(value):
    exact_fields(value, ("classification", "version", "kernel", "self"), "parent record")
    require(value["classification"] == "observation-only" and
            type(value["version"]) is int and value["version"] == 2,
            "invalid parent classification")
    exact_fields(value["kernel"], ("sysname", "release", "machine"), "kernel")
    require(all(type(item) is str and item for item in value["kernel"].values()),
            "invalid kernel observation")
    validate_process(value["self"], "parent self")


def validate_local(value, parent):
    exact_fields(value, ("classification", "version", "kernel", "parent_self",
                         "privileged_child_self", "pid1"), "complete local record")
    validate_parent(parent)
    require(value["classification"] == "observation-only" and
            type(value["version"]) is int and value["version"] == 2 and
            value["kernel"] == parent["kernel"] and value["parent_self"] == parent["self"],
            "parent local observation mismatch")
    for name in ("parent_self", "privileged_child_self", "pid1"):
        validate_process(value[name], name)
    require(value["parent_self"] == value["privileged_child_self"] == value["pid1"],
            "parent, privileged child, and PID1 observations differ")


def complete_local_observations(parent):
    reject_container_cgroup("self")
    reject_container_cgroup("1")
    value = {
        "classification": "observation-only", "version": 2, "kernel": kernel_observation(),
        "parent_self": parent["self"], "privileged_child_self": process_observations("self"),
        "pid1": process_observations("1"),
    }
    validate_local(value, parent)
    return value


def privileged_command(uid, gid, package_digest):
    return [str(PYTHON), "-I", str(Path(__file__).resolve()), "--privileged",
            str(uid), str(gid), package_digest]


def command_readback(command):
    return " ".join(command)


def expected_native(workflow):
    return {
        "classification": "observation-only", "source_sha": workflow["source"]["source_sha"],
        "observations": ["counter-3-2-0", "descriptor-continuity", "exact-baseline-recovery",
                         "uncertain-state-preservation"],
    }


def validate_complete_record(value, workflow, parent, sudo):
    exact_fields(value, ("classification", "context", "execution_envelope", "source",
                         "runner_environment", "local_values", "sudo", "native_test"),
                 "privileged record")
    require(value["classification"] == "observation-only" and
            value["context"] == "workflow-bound-native-c1", "invalid privileged context")
    require(value["execution_envelope"] == workflow["execution_envelope"] and
            value["source"] == workflow["source"] and
            value["runner_environment"] == workflow["runner_environment"],
            "privileged workflow readback mismatch")
    validate_local(value["local_values"], parent)
    actual_sudo = value["sudo"]
    exact_fields(actual_sudo, ("caller_uid", "caller_gid", "caller_account", "command",
                               "parent_child_equal", "provenance"), "sudo record")
    require(type(sudo["caller_uid"]) is int and type(sudo["caller_gid"]) is int and
            type(actual_sudo["caller_uid"]) is int and
            actual_sudo["caller_uid"] == sudo["caller_uid"] and
            type(actual_sudo["caller_gid"]) is int and
            actual_sudo["caller_gid"] == sudo["caller_gid"] and
            actual_sudo["parent_child_equal"] is True and
            sudo["parent_child_equal"] is True and actual_sudo == sudo,
            "sudo provenance mismatch")
    require(value["native_test"] == expected_native(workflow), "native test observation mismatch")


def privileged(expected_uid, expected_gid, expected_digest):
    require(os.geteuid() == 0 and expected_uid > 0 and expected_gid >= 0, "invalid privilege transition")
    sudo_uid, sudo_gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    sudo_user, sudo_command = os.environ.get("SUDO_USER"), os.environ.get("SUDO_COMMAND")
    require(sudo_uid is not None and sudo_gid is not None and sudo_user and sudo_command,
            "missing sudo provenance")
    require(int(sudo_uid) == expected_uid and int(sudo_gid) == expected_gid, "sudo caller mismatch")
    caller = pwd.getpwnam(sudo_user)
    require((caller.pw_uid, caller.pw_gid) == (expected_uid, expected_gid), "sudo account mismatch")
    isolated_command = privileged_command(expected_uid, expected_gid, expected_digest)
    require(sudo_command == command_readback(isolated_command), "sudo command readback mismatch")
    raw = sys.stdin.buffer.read(32769)
    require(0 < len(raw) <= 32768, "missing or oversized invoker observations")
    try:
        package = parse_record(base64.b64decode(raw, validate=True))
    except ValueError as error:
        raise RuntimeError("native Linux C1 invoker: malformed invoker observations") from error
    exact_fields(package, ("workflow", "parent_local"), "invoker package")
    require(digest(package) == expected_digest, "invoker observations digest mismatch")
    validate_parent(package["parent_local"])
    child_workflow = workflow_observations()
    require(package["workflow"] == child_workflow, "parent/child workflow observations differ")
    child_local = complete_local_observations(package["parent_local"])
    result = subprocess.run(
        [str(PYTHON), "-I", "-B", str(BUILDER_TEST), "--native-linux-c1"], cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, text=True, capture_output=True,
        timeout=900, check=False,
    )
    require(result.returncode == 0, f"native route failed: {result.stderr[-1000:]}")
    native_test = parse_record(result.stdout.strip())
    require(native_test == expected_native(child_workflow), "native test observation mismatch")
    print(json.dumps({
        "classification": "observation-only", "context": "workflow-bound-native-c1",
        **child_workflow, "local_values": child_local,
        "sudo": {"caller_uid": expected_uid, "caller_gid": expected_gid,
                 "caller_account": sudo_user, "command": sudo_command,
                 "parent_child_equal": True, "provenance": "observed"},
        "native_test": native_test,
    }, sort_keys=True, separators=(",", ":")))


def invoke_workflow():
    require(os.geteuid() != 0 and os.getuid() == os.geteuid(),
            "must begin as an unprivileged caller")
    workflow = workflow_observations()
    parent_local = parent_observations()
    sudo_stat = SUDO.lstat()
    require(stat.S_ISREG(sudo_stat.st_mode) and sudo_stat.st_uid == sudo_stat.st_gid == 0,
            "sudo is not a root-owned regular file")
    require(sudo_stat.st_mode & 0o111 and not sudo_stat.st_mode & 0o022, "unsafe sudo mode")
    python_stat = PYTHON.stat()
    require(stat.S_ISREG(python_stat.st_mode) and python_stat.st_uid == python_stat.st_gid == 0 and
            python_stat.st_mode & 0o111 and not python_stat.st_mode & 0o022,
            "fixed system Python unavailable or unsafe")
    package = {"workflow": workflow, "parent_local": parent_local}
    package_digest = digest(package)
    preserve = "--preserve-env=" + ",".join(PRESERVED_FIELDS)
    child_command = privileged_command(os.geteuid(), os.getegid(), package_digest)
    command = [str(SUDO), "-n", preserve, "--", *child_command]
    result = subprocess.run(command, cwd=ROOT, input=encoded(package), text=True, capture_output=True,
                            timeout=960, check=False)
    require(result.returncode == 0, f"sudo child failed: {result.stderr[-1000:]}")
    observation = parse_record(result.stdout.strip())
    account = pwd.getpwuid(os.geteuid()).pw_name
    sudo = {"caller_uid": os.geteuid(), "caller_gid": os.getegid(),
            "caller_account": account, "command": command_readback(child_command),
            "parent_child_equal": True, "provenance": "observed"}
    validate_complete_record(observation, workflow, parent_local, sudo)
    print(result.stdout, end="")


def portable_tests():
    envelope_sha, event_merge_sha, source_sha, base_sha = "a" * 40, "d" * 40, "b" * 40, "c" * 40
    accepted = ((envelope_sha, envelope_sha, source_sha, base_sha, source_sha, source_sha),
                (envelope_sha, event_merge_sha, source_sha, base_sha, envelope_sha, source_sha))
    for values in accepted:
        validate_revision_domains(*values)
        validate_synthetic_context(values[0], values[1], values[0], values[1])
    rejected = (
        ("", event_merge_sha, source_sha, base_sha, source_sha, source_sha),
        (envelope_sha, "", source_sha, base_sha, source_sha, source_sha),
        ("A" * 40, event_merge_sha, source_sha, base_sha, source_sha, source_sha),
        (envelope_sha, "malformed", source_sha, base_sha, source_sha, source_sha),
        (source_sha, event_merge_sha, source_sha, base_sha, source_sha, source_sha),
        (envelope_sha, base_sha, source_sha, base_sha, source_sha, source_sha),
        (envelope_sha, event_merge_sha, source_sha, source_sha, source_sha, source_sha),
        (envelope_sha, event_merge_sha, source_sha, base_sha, base_sha, source_sha),
        (envelope_sha, event_merge_sha, source_sha, base_sha, event_merge_sha, source_sha),
        (envelope_sha, event_merge_sha, source_sha, base_sha, source_sha, base_sha),
        (envelope_sha, event_merge_sha, source_sha, base_sha, source_sha, envelope_sha),
    )
    for values in rejected:
        try:
            validate_revision_domains(*values)
            raise AssertionError("invalid revision domains accepted")
        except RuntimeError:
            pass
    for github_sha, merge_sha in (("", event_merge_sha), (envelope_sha, ""),
                                  (event_merge_sha, event_merge_sha),
                                  (envelope_sha, envelope_sha), (source_sha, event_merge_sha),
                                  (envelope_sha, base_sha)):
        try:
            validate_synthetic_context(envelope_sha, event_merge_sha, github_sha, merge_sha)
            raise AssertionError("substituted synthetic context accepted")
        except RuntimeError:
            pass
    mount = {
        "mount_id": "1", "parent_id": "0", "major_minor": "8:1",
        "mount_root": "/", "mount_point": "/", "mount_options": "rw",
        "fs_type": "ext4", "source_sha256": "0" * 64, "super_options": "rw",
    }
    process = {
        "namespaces": {name: [1, 2] for name in NAMESPACES}, "nspid_depth": 1,
        "root_identity": [8, 2], "root_mount": mount, "cgroup2": ["2", "0:2", "/"],
    }
    parent = {
        "classification": "observation-only", "version": 2,
        "kernel": {"sysname": "Linux", "release": "test", "machine": "x86_64"},
        "self": process,
    }
    source_paths = (
        WORKFLOW_FILE, INVOKER_FILE, NATIVE_TEST_FILE,
        "deploy/aws-feasibility/remote/completion_rootfs_builder.py",
        "deploy/aws-feasibility/remote/completion_rootfs_fs.py",
        "deploy/aws-feasibility/remote/completion_rootfs_ledger.py",
    )
    workflow = {
        "execution_envelope": {
            "repository": "nenb/cogs", "workflow_file": WORKFLOW_FILE, "job": "native-c1",
            "event": "pull_request", "action": "opened", "run_id": "1", "run_attempt": "1",
            "envelope_sha": envelope_sha, "event_merge_sha": event_merge_sha,
            "workflow_ref": "nenb/cogs/.github/workflows/ci.yml@refs/pull/1/merge",
            "workflow_sha": envelope_sha, "base_sha": base_sha, "pull_request_number": "1",
        },
        "source": {
            "head_repository": "nenb/cogs", "source_sha": source_sha,
            "checked_out_sha": source_sha, "reviewed_implementation_sha": source_sha,
            "workflow_source_sha": source_sha, "invoker_source_sha": source_sha,
            "native_test_source_sha": source_sha, "workflow_blob_digest": "0" * 64,
            "workflow_file_sha256": "1" * 64,
            "git_blobs": {path: source_sha for path in source_paths},
        },
        "runner_environment": {
            "CI": "true", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "ImageOS": "ubuntu24",
            "GITHUB_WORKFLOW": "CI", "GITHUB_JOB": "native-c1",
            "GITHUB_REPOSITORY": "nenb/cogs", "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_SHA": envelope_sha, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": "ref", "GITHUB_WORKFLOW_SHA": envelope_sha,
        },
    }
    local = {
        "classification": "observation-only", "version": 2, "kernel": parent["kernel"],
        "parent_self": process, "privileged_child_self": process, "pid1": process,
    }
    sudo = {
        "caller_uid": 1, "caller_gid": 0, "caller_account": "runner",
        "command": "/usr/bin/python3 -I invoker --privileged",
        "parent_child_equal": True, "provenance": "observed",
    }
    valid = {
        "classification": "observation-only", "context": "workflow-bound-native-c1", **workflow,
        "local_values": local, "sudo": sudo, "native_test": expected_native(workflow),
    }
    validate_complete_record(parse_record(canonical(valid)), workflow, parent, sudo)
    delete = object()
    cases = (
        ("missing", ("sudo", "caller_gid"), delete),
        ("extra", ("local_values", "parent_self", "extra"), 1),
        ("malformed", ("local_values", "parent_self", "namespaces", "pid"), ["bad", 2]),
        ("classification", ("classification",), "authority"),
        ("context", ("context",), "local-manual"),
        ("workflow", ("execution_envelope", "job"), "quality"),
        ("source", ("source", "source_sha"), base_sha),
        ("runner", ("runner_environment", "GITHUB_JOB"), "quality"),
        ("sudo-command", ("sudo", "command"), "python3"),
        ("version-float", ("local_values", "version"), 2.0),
        ("uid-float", ("sudo", "caller_uid"), 1.0),
        ("gid-float", ("sudo", "caller_gid"), 0.0),
        ("uid-bool", ("sudo", "caller_uid"), True),
        ("gid-bool", ("sudo", "caller_gid"), False),
        ("equality-int", ("sudo", "parent_child_equal"), 1),
        ("equality-float", ("sudo", "parent_child_equal"), 1.0),
        ("parent", ("local_values", "parent_self", "root_identity"), [9, 2]),
        ("child", ("local_values", "privileged_child_self", "nspid_depth"), 2),
        ("pid1", ("local_values", "pid1"), delete),
        ("native", ("native_test", "source_sha"), base_sha),
    )
    raws = [
        ("duplicate", canonical(valid).replace(
            b'{"classification":', b'{"classification":"forged","classification":', 1)),
        ("malformed-json", b"{"),
    ]
    for name, path, replacement in cases:
        candidate = json.loads(canonical(valid))
        target = candidate
        for key in path[:-1]:
            target = target[key]
        target.pop(path[-1]) if replacement is delete else target.__setitem__(path[-1], replacement)
        raws.append((name, canonical(candidate)))
    for name, raw in raws:
        try:
            validate_complete_record(parse_record(raw), workflow, parent, sudo)
            raise AssertionError(f"invalid {name} privileged record accepted")
        except RuntimeError:
            pass
    print("native C1 envelope/source domain portable tests passed")


def local_manual():
    print(json.dumps({
        "classification": "observation-only", "context": "local-manual",
        "local_values": {"classification": "observation-only", "status": "not-collected"},
        "workflow_authority": "unavailable",
    }, sort_keys=True, separators=(",", ":")))


if sys.argv == [sys.argv[0]]:
    local_manual()
elif sys.argv == [sys.argv[0], "--workflow-bound"]:
    invoke_workflow()
elif sys.argv == [sys.argv[0], "--portable-tests"]:
    portable_tests()
elif len(sys.argv) == 5 and sys.argv[1] == "--privileged":
    privileged(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
else:
    raise SystemExit("usage: aws-stage2-completion-rootfs-builder-native.py [--workflow-bound|--portable-tests]")

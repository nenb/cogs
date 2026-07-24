"""Immutable ADR 0043 OCI mount contract; this module performs no runtime I/O."""

from dataclasses import dataclass
import hashlib
import json


class KataMountContractError(Exception):
    """The stored OCI mount list differs from the fixed reviewed contract."""


@dataclass(frozen=True)
class MountRecord:
    type: str
    source: str
    destination: str
    options: tuple[str, ...]


def _make_contract():
    root = (
        "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/"
        "completion-v1/kata-input-v1/share"
    )
    # Primitive tuples are the sole authority. Public records below are only snapshots.
    mounts = (
        ("proc", "proc", "/proc", ("nosuid", "noexec", "nodev")),
        ("tmpfs", "tmpfs", "/dev", ("nosuid", "strictatime", "mode=755", "size=65536k")),
        (
            "devpts", "devpts", "/dev/pts",
            ("nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"),
        ),
        ("tmpfs", "shm", "/dev/shm", ("nosuid", "noexec", "nodev", "mode=1777", "size=65536k")),
        ("mqueue", "mqueue", "/dev/mqueue", ("nosuid", "noexec", "nodev")),
        ("sysfs", "sysfs", "/sys", ("nosuid", "noexec", "nodev", "ro")),
        ("tmpfs", "tmpfs", "/run", ("nosuid", "strictatime", "mode=755", "size=65536k")),
        (
            "tmpfs", "tmpfs", "/run/cogs-stage2-ssh",
            ("rw", "nosuid", "nodev", "noexec", "mode=0700", "size=67108864", "nr_inodes=16384"),
        ),
        (
            "bind", f"{root}/ssh_host_ed25519_key", "/run/cogs-stage2-ssh/ssh_host_ed25519_key",
            ("bind", "ro", "nosuid", "nodev", "noexec", "private"),
        ),
        (
            "bind", f"{root}/authorized_keys", "/run/cogs-stage2-ssh/authorized_keys",
            ("bind", "ro", "nosuid", "nodev", "noexec", "private"),
        ),
        (
            "bind", f"{root}/fixture", "/run/cogs-stage2-ssh/input",
            ("bind", "ro", "nosuid", "nodev", "noexec", "private"),
        ),
    )

    dumps = json.dumps

    def canonical_mount_json():
        """Return the canonical complete mount-list JSON, including its final newline."""
        value = [
            {"destination": destination, "options": list(options), "source": source, "type": type_}
            for type_, source, destination, options in mounts
        ]
        return dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8") + b"\n"

    digest = hashlib.sha256(canonical_mount_json()).hexdigest()
    error_type = KataMountContractError

    def require(condition):
        if not condition:
            raise error_type()

    def validate_stored_spec(stored_spec):
        """Fail closed unless ``stored_spec['mounts']`` is the exact canonical list."""
        require(type(stored_spec) is dict and all(type(key) is str for key in stored_spec) and "mounts" in stored_spec)
        stored_mounts = stored_spec["mounts"]
        require(type(stored_mounts) is list and len(stored_mounts) == len(mounts))
        keys = {"destination", "options", "source", "type"}
        for value, expected in zip(stored_mounts, mounts, strict=True):
            type_, source, destination, options = expected
            require(type(value) is dict and all(type(key) is str for key in value))
            require(set(value) == keys and len(value) == 4)
            require(type(value["type"]) is str and value["type"] == type_)
            require(type(value["source"]) is str and value["source"] == source)
            require(type(value["destination"]) is str and value["destination"] == destination)
            stored_options = value["options"]
            require(type(stored_options) is list and len(stored_options) == len(options))
            require(all(type(option) is str for option in stored_options) and tuple(stored_options) == options)
        return digest

    def custom_mount_argv():
        """Return only the four reviewed repeated ``ctr run --mount`` arguments."""
        argv = []
        for type_, source, destination, options in mounts[7:]:
            fields = (type_, source, destination, *options)
            require(all(type(field) is str and field.isascii() and field.isprintable() for field in fields))
            require(all("," not in field for field in fields) and all(":" not in option for option in options))
            value = f"type={type_},src={source},dst={destination},options={':'.join(options)}"
            argv.extend(("--mount", value))
        return tuple(argv)

    snapshots = tuple(
        MountRecord(type_, source, destination, tuple(option for option in options))
        for type_, source, destination, options in mounts
    )
    return snapshots, digest, canonical_mount_json, validate_stored_spec, custom_mount_argv


(
    CANONICAL_MOUNTS,
    MOUNT_LIST_SHA256,
    canonical_mount_json,
    validate_stored_spec,
    custom_mount_argv,
) = _make_contract()
del _make_contract

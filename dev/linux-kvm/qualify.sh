#!/usr/bin/env bash
set -euo pipefail

report_path=${1:-kvm-qualification-report.json}
started_epoch_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
workdir=$(mktemp -d)
umask 077
qemu_pid=""
cleanup() {
  if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  rm -rf "$workdir"
}
write_failure_report() {
  mkdir -p "$(dirname "$report_path")"
  python3 - "$report_path" "$started_epoch_ms" <<'PY'
import datetime
import json
import os
import platform
import shutil
import subprocess
import sys

report_path, started_epoch_ms_text = sys.argv[1:]
started_epoch_ms = int(started_epoch_ms_text)
completed_epoch_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
format_time = lambda value: datetime.datetime.fromtimestamp(value / 1000, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
qemu = shutil.which("qemu-system-x86_64")
qemu_version = subprocess.check_output([qemu, "--version"], text=True).splitlines()[0] if qemu else "unavailable"
dependency_names = ["authorization", "audit", "revocation", "identity", "network_enforcement"]
report = {
    "version": "cogs.security-report/v1alpha1",
    "report_id": f"kvm-qualification-{os.environ.get('GITHUB_RUN_ID', 'local')}",
    "source_revision": revision,
    "profile": "linux-kvm",
    "authority": "authoritative-local",
    "started_at": format_time(started_epoch_ms),
    "completed_at": format_time(completed_epoch_ms),
    "duration_ms": completed_epoch_ms - started_epoch_ms,
    "environment": {
        "os": platform.system().lower(),
        "architecture": platform.machine(),
        "runner": os.environ.get("RUNNER_NAME", "local-linux"),
        "runner_image": os.environ.get("ImageOS", "unknown"),
        "runtime_versions": {"qemu": qemu_version},
        "metadata": {
            "kvm_present": os.path.exists("/dev/kvm"),
            "kvm_enabled": False,
            "guest_root": False,
            "distinct_boot_ids": False,
        },
    },
    "components": [{"name": "qemu", "version": qemu_version}],
    "dependencies": {
        name: {"mode": "not-applicable", "implementation": "Stage 0 runner qualification only"}
        for name in dependency_names
    },
    "tests": [{
        "id": "runner.kvm-acceleration",
        "group": "runner-qualification",
        "result": "fail",
        "release_eligible": False,
        "dependency_modes": {name: "not-applicable" for name in dependency_names},
        "diagnostics_redacted": "KVM qualification failed; consult the CI step log for non-sensitive diagnostics.",
    }],
    "known_limitations": ["Failed qualification establishes no KVM or guest-root claim."],
}
with open(report_path, "w", encoding="utf-8") as output:
    json.dump(report, output, indent=2, sort_keys=True)
    output.write("\n")
PY
}
finish() {
  status=$?
  trap - EXIT
  cleanup
  if [[ $status -ne 0 && ! -f "$report_path" ]]; then
    write_failure_report || true
  fi
  exit "$status"
}
trap finish EXIT

if [[ ! -c /dev/kvm ]]; then
  echo "FAIL: /dev/kvm is absent; software emulation is not an acceptable fallback" >&2
  exit 1
fi
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "FAIL: /dev/kvm is not accessible to the runner user" >&2
  exit 1
fi

kernel_source=$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' -print | sort -V | tail -1)
if [[ -z "$kernel_source" ]]; then
  echo "FAIL: no guest kernel found under /boot" >&2
  exit 1
fi
kernel="$workdir/vmlinuz"
if [[ -r "$kernel_source" ]]; then
  cp "$kernel_source" "$kernel"
else
  sudo cp "$kernel_source" "$kernel"
  sudo chown "$(id -u):$(id -g)" "$kernel"
fi
chmod 0600 "$kernel"
kernel_sha256=$(sha256sum "$kernel" | awk '{print $1}')
if file /bin/busybox | grep -q 'dynamically linked'; then
  echo "FAIL: /bin/busybox is dynamic; the guest initramfs must be self-contained" >&2
  exit 1
fi

rootfs="$workdir/rootfs"
mkdir -p "$rootfs"/{bin,dev,proc,sys,tmp}
cp /bin/busybox "$rootfs/bin/busybox"
for command in sh mount cat id uname sleep poweroff; do
  ln -s busybox "$rootfs/bin/$command"
done
cat > "$rootfs/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev || true
exec </dev/console >/dev/console 2>&1
echo "COGS_GUEST_READY=1"
echo "COGS_GUEST_UID=$(id -u)"
echo "COGS_GUEST_KERNEL=$(uname -r)"
echo "COGS_GUEST_BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)"
# Leave enough time for the trusted host to query QMP and prove KVM is enabled.
sleep 15
poweroff -f
INIT
chmod 0755 "$rootfs/init"
(
  cd "$rootfs"
  find . -print0 | cpio --null --create --format=newc --quiet | gzip -9 > "$workdir/initramfs.cpio.gz"
)

host_boot_id=$(cat /proc/sys/kernel/random/boot_id)
qmp_socket="$workdir/qmp.sock"
guest_log="$workdir/guest.log"

# -accel kvm forbids silent TCG fallback. query-kvm below independently proves
# that KVM is present and enabled in the running VM.
qemu-system-x86_64 \
  -name cogs-stage0-kvm-qualification \
  -machine q35 \
  -accel kvm \
  -cpu host \
  -smp 1 \
  -m 256M \
  -kernel "$kernel" \
  -initrd "$workdir/initramfs.cpio.gz" \
  -append "console=ttyS0 panic=-1" \
  -display none \
  -serial file:"$guest_log" \
  -monitor none \
  -nic none \
  -qmp unix:"$qmp_socket",server=on,wait=off \
  -no-reboot &
qemu_pid=$!

for _ in $(seq 1 100); do
  [[ -S "$qmp_socket" ]] && break
  kill -0 "$qemu_pid" 2>/dev/null || { echo "FAIL: QEMU exited before QMP qualification" >&2; exit 1; }
  sleep 0.1
done
[[ -S "$qmp_socket" ]] || { echo "FAIL: QMP socket did not appear" >&2; exit 1; }

python3 - "$qmp_socket" "$workdir/query-kvm.json" <<'PY'
import json
import socket
import sys

socket_path, output_path = sys.argv[1:]
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.settimeout(10)
    client.connect(socket_path)
    stream = client.makefile("rwb", buffering=0)

    def receive(expected_id=None):
        while True:
            line = stream.readline()
            if not line:
                raise RuntimeError("QMP closed unexpectedly")
            message = json.loads(line)
            if expected_id is None or message.get("id") == expected_id:
                return message

    greeting = receive()
    if "QMP" not in greeting:
        raise RuntimeError(f"unexpected QMP greeting: {greeting}")
    stream.write(b'{"execute":"qmp_capabilities","id":"capabilities"}\n')
    capabilities = receive("capabilities")
    if "error" in capabilities:
        raise RuntimeError(f"QMP capabilities failed: {capabilities}")
    stream.write(b'{"execute":"query-kvm","id":"query-kvm"}\n')
    result = receive("query-kvm")

status = result.get("return", {})
if status.get("present") is not True or status.get("enabled") is not True:
    raise RuntimeError(f"KVM is not actively enabled: {result}")
with open(output_path, "w", encoding="utf-8") as output:
    json.dump(result, output, sort_keys=True)
PY

(
  sleep 30
  if kill -0 "$qemu_pid" 2>/dev/null; then
    echo "FAIL: guest did not shut down within 30 seconds" >&2
    kill -TERM "$qemu_pid" 2>/dev/null || true
  fi
) &
watchdog_pid=$!
if ! wait "$qemu_pid"; then
  kill "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  qemu_pid=""
  echo "FAIL: QEMU did not complete cleanly" >&2
  exit 1
fi
qemu_pid=""
kill "$watchdog_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true
grep -q '^COGS_GUEST_READY=1' "$guest_log"
grep -q '^COGS_GUEST_UID=0' "$guest_log"
guest_boot_id=$(sed -n 's/^COGS_GUEST_BOOT_ID=//p' "$guest_log" | tr -d '\r' | tail -1)
guest_kernel=$(sed -n 's/^COGS_GUEST_KERNEL=//p' "$guest_log" | tr -d '\r' | tail -1)
[[ -n "$guest_boot_id" ]] || { echo "FAIL: guest boot ID was not recorded" >&2; exit 1; }
[[ "$guest_boot_id" != "$host_boot_id" ]] || { echo "FAIL: host and guest boot IDs are identical" >&2; exit 1; }

mkdir -p "$(dirname "$report_path")"
python3 - "$report_path" "$host_boot_id" "$guest_boot_id" "$guest_kernel" "$kernel_sha256" "$started_epoch_ms" <<'PY'
import datetime
import json
import os
import platform
import subprocess
import sys

report_path, host_boot_id, guest_boot_id, guest_kernel, kernel_sha256, started_epoch_ms_text = sys.argv[1:]
started_epoch_ms = int(started_epoch_ms_text)
completed_epoch_ms = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
started_at = datetime.datetime.fromtimestamp(started_epoch_ms / 1000, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
completed_at = datetime.datetime.fromtimestamp(completed_epoch_ms / 1000, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
qemu_version = subprocess.check_output(["qemu-system-x86_64", "--version"], text=True).splitlines()[0]
report = {
    "version": "cogs.security-report/v1alpha1",
    "report_id": f"kvm-qualification-{os.environ.get('GITHUB_RUN_ID', 'local')}",
    "source_revision": revision,
    "profile": "linux-kvm",
    "authority": "authoritative-local",
    "started_at": started_at,
    "completed_at": completed_at,
    "duration_ms": completed_epoch_ms - started_epoch_ms,
    "environment": {
        "os": platform.system().lower(),
        "architecture": platform.machine(),
        "runner": os.environ.get("RUNNER_NAME", "local-linux"),
        "runner_image": os.environ.get("ImageOS", "unknown"),
        "runtime_versions": {"qemu": qemu_version, "guest_kernel": guest_kernel},
        "metadata": {
            "kvm_present": True,
            "kvm_enabled": True,
            "guest_root": True,
            "distinct_boot_ids": host_boot_id != guest_boot_id,
            "guest_kernel_sha256": kernel_sha256,
        },
    },
    "components": [{"name": "qemu", "version": qemu_version}],
    "dependencies": {
        name: {"mode": "not-applicable", "implementation": "Stage 0 runner qualification only"}
        for name in ["authorization", "audit", "revocation", "identity", "network_enforcement"]
    },
    "tests": [{
        "id": "runner.kvm-acceleration",
        "group": "runner-qualification",
        "result": "pass",
        "release_eligible": False,
        "dependency_modes": {
            name: "not-applicable"
            for name in ["authorization", "audit", "revocation", "identity", "network_enforcement"]
        },
        "diagnostics_redacted": "QEMU -accel kvm started and QMP query-kvm returned present=true, enabled=true.",
    }],
    "known_limitations": [
        "This proves runner capability only; it does not satisfy Stage 1 guest-root network-bypass acceptance.",
        "GitHub does not contractually guarantee general nested virtualization on hosted runners.",
    ],
}
with open(report_path, "w", encoding="utf-8") as output:
    json.dump(report, output, indent=2, sort_keys=True)
    output.write("\n")
PY

printf 'PASS: KVM acceleration active; guest root booted with distinct boot ID. Report: %s\n' "$report_path"

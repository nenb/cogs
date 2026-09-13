#!/usr/bin/env bash
set -euo pipefail
# Qualification boots a guest and is therefore effectful.  It shares the
# driver gate; only the driver's policy renderer is intentionally pure.
script=${BASH_SOURCE[0]}
repo=${script%/dev/linux-kvm/qualify.sh}
[[ "$repo" != "$script" ]] || repo=$PWD
repo=$(builtin cd "$repo" && builtin pwd -P)
# shellcheck source=dev/linux-kvm/git-tools.sh
source "$repo/dev/linux-kvm/git-tools.sh"
cogs_kvm_execution_gate

report_path=${1:-kvm-qualification-report.json}
report_dir=$(dirname "$report_path")
[[ ! -e "$report_path" && ! -L "$report_path" ]] || { echo "FAIL: report destination exists" >&2; exit 1; }
mkdir -p "$report_dir"
started_epoch_ms=$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')
workdir=$(mktemp -d)
umask 077
cleaned=false
report_tmp=
cleanup() {
  [[ $cleaned == true ]] && return 0
  # Pending custody or a missing owner settlement marker is recovery evidence.
  [[ ! -e "$workdir/qualification-pending" && -f "$workdir/owner-settled" && $(<"$workdir/owner-settled") == settled ]] || return 1
  rm -rf -- "$workdir" || return 1
  cleaned=true
}
stage_report() { report_tmp=$(mktemp "$report_dir/.kvm-qualification.XXXXXX"); }
publish_report() { mv -n -- "$1" "$report_path" && [[ ! -e "$1" ]]; }
write_failure_report() {
  stage_report || return 1
  python3 - "$report_tmp" "$started_epoch_ms" <<'PY' || { rm -f -- "$report_tmp"; return 1; }
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
revision = os.environ.get("COGS_SOURCE_REVISION") or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
qemu = shutil.which("qemu-system-x86_64")
try:
    qemu_version = subprocess.run([qemu, "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=True).stdout.splitlines()[0] if qemu else "unavailable"
except (subprocess.SubprocessError, IndexError):
    qemu_version = "unavailable"
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
  publish_report "$report_tmp" || { rm -f -- "$report_tmp"; return 1; }
  report_tmp=
}
finish() {
  status=$?
  trap - EXIT
  cleanup || status=1
  if [[ $status -ne 0 ]]; then
    [[ -z $report_tmp ]] || rm -f -- "$report_tmp"
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

# One fixed owner covers acquisition through QMP, UART capture, exit and
# pidfd-bound retirement. It has no driver state and cannot fabricate one.
owner_result="$workdir/owner-result.json"
python3 -I -B "$repo/dev/linux-kvm/qualification-owner.py" \
  "$workdir" "$kernel" "$workdir/initramfs.cpio.gz" "$host_boot_id" >"$owner_result"
read -r guest_boot_id guest_kernel < <(python3 -I -B - "$owner_result" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
boot, kernel = value.get("guest_boot_id"), value.get("guest_kernel")
if not isinstance(boot, str) or not isinstance(kernel, str) or not boot or not kernel:
    raise SystemExit(1)
print(boot, kernel)
PY
)

stage_report
python3 - "$report_tmp" "$host_boot_id" "$guest_boot_id" "$guest_kernel" "$kernel_sha256" "$started_epoch_ms" <<'PY'
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
revision = os.environ.get("COGS_SOURCE_REVISION") or subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
try:
    qemu_version = subprocess.run(["qemu-system-x86_64", "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=True).stdout.splitlines()[0]
except (subprocess.SubprocessError, IndexError):
    raise SystemExit("qemu version unavailable")
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
# Pass publication is the final operation: cleanup already proved custody settled.
cleanup
publish_report "$report_tmp"
report_tmp=

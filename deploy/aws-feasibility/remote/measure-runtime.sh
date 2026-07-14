#!/usr/bin/env bash
set -eEuo pipefail
stage=initialization
failure() {
  status=$?
  trap - ERR
  set +e
  cleanup_kata_tasks >/dev/null 2>&1 || true
  diagnostic_file=${work:-/tmp}/bounded-diagnostics.txt
  : >"$diagnostic_file"
  files=0
  remaining=8192
  for diagnostic in "${work:-/nonexistent}"/kata-stderr-*.txt "${work:-/nonexistent}"/task-*.txt; do
    [[ -f "$diagnostic" ]] || continue
    (( files < 8 && remaining > 0 )) || break
    header=$(printf 'cogs-stage2-bounded-diagnostic=%s\n' "$(basename "$diagnostic")")
    header_len=${#header}
    (( header_len < remaining )) || break
    printf '%s' "$header" >>"$diagnostic_file"
    remaining=$((remaining - header_len))
    tail -c 768 "$diagnostic" | tr -c '[:print:]\n\t' '?' | head -c "$remaining" >>"$diagnostic_file"
    remaining=$((8192 - $(wc -c <"$diagnostic_file")))
    if (( remaining > 0 )); then printf '\n' >>"$diagnostic_file"; remaining=$((remaining - 1)); fi
    files=$((files + 1))
  done
  printf 'cogs-stage2-measurement-failure-stage=%s status=%s\n' "$stage" "$status" >&2
  cat "$diagnostic_file" >&2
  exit "$status"
}
trap failure ERR
export DEBIAN_FRONTEND=noninteractive
work=/var/tmp/cogs-stage2-measure
report=$work/measurement-result.json
samples=${COGS_STAGE2_MEASUREMENT_SAMPLES:-7}
[[ "$samples" =~ ^[0-9]+$ && "$samples" -ge 5 && "$samples" -le 9 ]]
mkdir -p "$work"
chmod 700 "$work"
started=$(date +%s%3N)

stage=package-index
apt-get update -qq
stage=package-install
apt-get install -y -qq busybox-static build-essential containerd cpu-checker curl git jq qemu-system-x86 zstd >/var/log/cogs-stage2-measure-apt.log
install_completed=$(date +%s%3N)

stage=active-kvm
host_kernel=$(uname -r)
grep -qw vmx /proc/cpuinfo
modprobe kvm
modprobe kvm_intel
test -c /dev/kvm
test -r /dev/kvm
test -w /dev/kvm
kvm-ok >"$work/kvm-ok.txt" 2>&1
qmp=$work/qmp.sock
rm -f "$qmp"
qemu-system-x86_64 -S -nodefaults -display none -machine accel=kvm -cpu host -qmp "unix:$qmp,server=on,wait=off" &
qemu_pid=$!
for _ in $(seq 1 50); do [[ -S "$qmp" ]] && break; sleep 0.1; done
[[ -S "$qmp" ]]
python3 - "$qmp" "$work/qmp.json" <<'PY'
import json, socket, sys
path, output = sys.argv[1:]
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect(path)
f = s.makefile('rwb', buffering=0)
greeting = json.loads(f.readline())
def command(name):
    f.write(json.dumps({'execute': name}).encode() + b'\r\n')
    while True:
        value = json.loads(f.readline())
        if 'return' in value or 'error' in value:
            return value
capabilities = command('qmp_capabilities')
kvm = command('query-kvm')
command('quit')
with open(output, 'w', encoding='utf-8') as target:
    json.dump({'greeting': bool(greeting.get('QMP')), 'capabilities': capabilities, 'kvm': kvm}, target, separators=(',', ':'))
    target.write('\n')
if capabilities.get('return') != {} or kvm.get('return') != {'enabled': True, 'present': True}:
    raise SystemExit('QMP did not prove active KVM')
PY
wait "$qemu_pid"

kata_version=3.32.0
kata_archive="$work/kata-static-$kata_version-amd64.tar.zst"
kata_url="https://github.com/kata-containers/kata-containers/releases/download/$kata_version/kata-static-$kata_version-amd64.tar.zst"
stage=kata-download
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$kata_url" --output "$kata_archive"
stage=kata-digest
echo '1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01  '"$kata_archive" | sha256sum --check --status
stage=kata-extract
tar --zstd -xf "$kata_archive" -C /
rm -f "$kata_archive"

stage=kata-runtime-check
test -x /opt/kata/bin/kata-runtime
test -x /opt/kata/bin/containerd-shim-kata-v2
config=/opt/kata/share/defaults/kata-containers/configuration-qemu.toml
test -f "$config"
read -r guest_memory_mib guest_vcpus < <(python3 - "$config" <<'PY'
import re, sys
text = open(sys.argv[1], encoding='utf-8').read()
def value(name):
    match = re.search(r'^\s*' + re.escape(name) + r'\s*=\s*(\d+)\s*$', text, re.M)
    if not match:
        raise SystemExit(f'missing {name}')
    return int(match.group(1))
print(value('default_memory'), value('default_vcpus'))
PY
)
(( guest_memory_mib >= 128 && guest_memory_mib <= 4096 ))
(( guest_vcpus >= 1 && guest_vcpus <= 2 ))
ln -sf /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
/opt/kata/bin/kata-runtime --config "$config" check >"$work/kata-check.txt" 2>&1
kata_runtime_version=$(/opt/kata/bin/kata-runtime --version | head -n 1 | tr -cd '[:alnum:]. _/-')
containerd_version=$(containerd --version | tr -cd '[:alnum:]. _/-')
qemu_version=$(qemu-system-x86_64 --version | head -n 1 | tr -cd '[:alnum:]. _/()-')
systemctl start containerd

stage=workload-rootfs
rootfs=$work/rootfs
rm -rf "$rootfs"
mkdir -p "$rootfs/bin" "$rootfs/data/files"
cp /bin/busybox "$rootfs/bin/busybox"
python3 - "$rootfs/data/payload.bin" "$rootfs/data/files" <<'PY'
from pathlib import Path
import sys
payload = Path(sys.argv[1])
files = Path(sys.argv[2])
payload.write_bytes(bytes((i % 251 for i in range(16 * 1024 * 1024))))
for i in range(1024):
    (files / f'f{i:04d}.txt').write_text(('cogs-stage2-measurement\n' * 64), encoding='utf-8')
PY

qemu_pids() {
  python3 - <<'PY'
from pathlib import Path
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit():
        continue
    try:
        exe = (proc / 'exe').resolve()
    except OSError:
        continue
    if exe.name == 'qemu-system-x86_64':
        print(proc.name)
PY
}
qemu_diff_one() {
  python3 - "$1" "$2" <<'PY'
import sys
before = set(sys.argv[1].split()) if sys.argv[1] else set()
after = set(sys.argv[2].split()) if sys.argv[2] else set()
new = sorted(after - before)
if len(new) != 1:
    raise SystemExit(f'expected one new qemu-system-x86_64 process, found {len(new)}')
print(new[0])
PY
}
assert_qemu_baseline() {
  local current
  current=$(qemu_pids | tr '\n' ' ' | sed 's/ $//')
  [[ "$current" == "${qemu_baseline:-}" ]] || { printf 'Kata QEMU process leak: baseline="%s" current="%s"\n' "${qemu_baseline:-}" "$current" >&2; return 1; }
}
run_kata() {
  name=$1
  shift
  ctr --namespace cogs-stage2 containers rm "$name" >/dev/null 2>&1 || true
  ctr --namespace cogs-stage2 run --rm --runtime io.containerd.kata.v2 --runtime-config-path "$config" --rootfs --read-only "$rootfs" "$name" "$@"
  assert_qemu_baseline
}
start_kata_task() {
  name=$1
  stop_kata_task "$name" >/dev/null
  ctr --namespace cogs-stage2 run --runtime io.containerd.kata.v2 --runtime-config-path "$config" --rootfs --read-only --detach "$rootfs" "$name" /bin/busybox sleep 300
}
task_status() {
  name=$1
  list_output=$work/task-ls-$name.txt
  ctr --namespace cogs-stage2 tasks ls >"$list_output"
  awk -v target="$name" 'NR > 1 && $1 == target { print $3; found=1 } END { if (!found) print "ABSENT" }' "$list_output"
}
normalize_task_status() {
  case "$1" in
    ABSENT) printf 'ABSENT\n' ;;
    STOPPED|stopped|3) printf 'STOPPED\n' ;;
    UNKNOWN|unknown|0) printf 'UNKNOWN\n' ;;
    CREATED|created|1) printf 'CREATED\n' ;;
    RUNNING|running|2) printf 'RUNNING\n' ;;
    PAUSED|paused|4) printf 'PAUSED\n' ;;
    PAUSING|pausing|5) printf 'PAUSING\n' ;;
    *) printf 'unsupported Kata task status for %s: %s\n' "${2:-unknown}" "$1" >&2; return 2 ;;
  esac
}
wait_for_task_stopped_or_absent() {
  name=$1
  phase=$2
  steps=${COGS_STAGE2_TEARDOWN_WAIT_STEPS:-100}
  delay=${COGS_STAGE2_TEARDOWN_WAIT_DELAY:-0.1}
  for _ in $(seq 1 "$steps"); do
    raw_status=$(task_status "$name") || return $?
    status=$(normalize_task_status "$raw_status" "$name") || return $?
    printf '%s\n' "$status" >"$work/task-status-$name-$phase.txt"
    case "$status" in
      ABSENT|STOPPED) return 0 ;;
      UNKNOWN|CREATED|RUNNING|PAUSED|PAUSING) sleep "$delay" ;;
    esac
  done
  printf 'timed out waiting for Kata task %s to report STOPPED or disappear during %s; last status %s\n' "$name" "$phase" "${status:-unset}" >&2
  return 1
}
bounded_task_wait_after_signal() {
  name=$1
  signal=$2
  phase=$3
  wait_output=$work/task-wait-$name-$phase.txt
  wait_seconds=${COGS_STAGE2_TEARDOWN_WAIT_SECONDS:-10}
  ctr --namespace cogs-stage2 tasks kill --signal "$signal" "$name" >/dev/null 2>&1 || true
  if timeout --kill-after=1s "${wait_seconds}s" ctr --namespace cogs-stage2 tasks wait "$name" >"$wait_output" 2>&1; then
    status=0
  else
    status=$?
  fi
  return "$status"
}
stop_kata_task() {
  name=$1
  raw_status=$(task_status "$name") || return $?
  status=$(normalize_task_status "$raw_status" "$name") || return $?
  if [[ "$status" != ABSENT ]]; then
    if [[ "$status" != STOPPED ]]; then
      if [[ "$status" != RUNNING ]]; then
        printf 'refusing to signal/remove Kata task %s from non-running status %s\n' "$name" "$status" >&2
        return 1
      fi
      if bounded_task_wait_after_signal "$name" SIGTERM graceful; then wait_status=0; else wait_status=$?; fi
      if (( wait_status != 0 && wait_status != 124 && wait_status != 137 )); then
        printf 'Kata task %s wait failed after SIGTERM with status %s\n' "$name" "$wait_status" >&2
        return "$wait_status"
      fi
      if wait_for_task_stopped_or_absent "$name" graceful; then
        :
      else
        stopped_status=$?
        (( stopped_status == 1 )) || return "$stopped_status"
        if bounded_task_wait_after_signal "$name" SIGKILL killed; then wait_status=0; else wait_status=$?; fi
        if (( wait_status != 0 && wait_status != 124 && wait_status != 137 )); then
          printf 'Kata task %s wait failed after SIGKILL with status %s\n' "$name" "$wait_status" >&2
          return "$wait_status"
        fi
        wait_for_task_stopped_or_absent "$name" killed
      fi
    fi
    raw_status=$(task_status "$name") || return $?
    status=$(normalize_task_status "$raw_status" "$name") || return $?
    if [[ "$status" == STOPPED ]]; then
      ctr --namespace cogs-stage2 tasks rm "$name" >/dev/null
    elif [[ "$status" != ABSENT ]]; then
      printf 'refusing to remove Kata task %s before STOPPED/absent; status %s\n' "$name" "$status" >&2
      return 1
    fi
  fi
  for _ in $(seq 1 50); do
    [[ "$(normalize_task_status "$(task_status "$name")" "$name")" == ABSENT ]] && break
    sleep 0.1
  done
  [[ "$(normalize_task_status "$(task_status "$name")" "$name")" == ABSENT ]]
  if ctr --namespace cogs-stage2 containers info "$name" >/dev/null 2>&1; then
    ctr --namespace cogs-stage2 containers rm "$name" >/dev/null
  fi
  for _ in $(seq 1 50); do
    ctr --namespace cogs-stage2 containers info "$name" >/dev/null 2>&1 || break
    sleep 0.1
  done
  ! ctr --namespace cogs-stage2 containers info "$name" >/dev/null 2>&1
  [[ ${qemu_baseline+x} != x ]] || assert_qemu_baseline
}
cleanup_kata_tasks() {
  for name in cogs-stage2-warm cogs-stage2-idle; do
    stop_kata_task "$name" || true
  done
}
qemu_baseline=$(qemu_pids | tr '\n' ' ' | sed 's/ $//')
measure_ms() {
  local start_ms end_ms elapsed
  start_ms=$(date +%s%3N)
  "$@" >/dev/null 2>/dev/null
  end_ms=$(date +%s%3N)
  elapsed=$((end_ms - start_ms))
  (( elapsed >= 25 )) || { printf 'benchmark sample too short: %s ms\n' "$elapsed" >&2; return 1; }
  printf '%s\n' "$elapsed"
}
json_array() { python3 - "$@" <<'PY'
import json, sys
print(json.dumps([int(x) for x in sys.argv[1:]], separators=(',', ':')))
PY
}

stage=kata-cold-boot-samples
kata_boot_ms=()
guest_kernel=""
for i in $(seq 1 "$samples"); do
  out=$work/kata-output-$i.txt
  err=$work/kata-stderr-$i.txt
  boot_started=$(date +%s%3N)
  set +e
  run_kata "cogs-stage2-boot-$i" /bin/busybox sh -c '/bin/busybox echo COGS_UID=$(/bin/busybox id -u); /bin/busybox echo COGS_KERNEL=$(/bin/busybox uname -r)' >"$out" 2>"$err"
  runtime_status=$?
  set -e
  boot_completed=$(date +%s%3N)
  [[ "$runtime_status" == 0 ]]
  uid=$(sed -n 's/^COGS_UID=//p' "$out" | tail -n 1)
  kernel=$(sed -n 's/^COGS_KERNEL=//p' "$out" | tail -n 1)
  [[ "$uid" == 0 && -n "$kernel" && "$kernel" != "$host_kernel" ]]
  guest_kernel="$kernel"
  kata_boot_ms+=( $((boot_completed - boot_started)) )
done

stage=warm-workload-samples
host_cpu_ms=()
kata_cpu_ms=()
host_fs_ms=()
kata_fs_ms=()
start_kata_task cogs-stage2-warm
for i in $(seq 1 "$samples"); do
  host_cpu_ms+=( "$(measure_ms /bin/busybox sh -c 'n=0; while [ $n -lt 16 ]; do /bin/busybox sha256sum /var/tmp/cogs-stage2-measure/rootfs/data/payload.bin >/dev/null; n=$((n+1)); done')" )
  kata_cpu_ms+=( "$(measure_ms ctr --namespace cogs-stage2 tasks exec --exec-id "cpu-$i" cogs-stage2-warm /bin/busybox sh -c 'n=0; while [ $n -lt 16 ]; do /bin/busybox sha256sum /data/payload.bin >/dev/null; n=$((n+1)); done')" )
  host_fs_ms+=( "$(measure_ms /bin/busybox sh -c 'n=0; while [ $n -lt 16 ]; do /bin/busybox find /var/tmp/cogs-stage2-measure/rootfs/data/files -type f -print0 | /bin/busybox xargs -0 /bin/busybox cat >/dev/null; n=$((n+1)); done')" )
  kata_fs_ms+=( "$(measure_ms ctr --namespace cogs-stage2 tasks exec --exec-id "fs-$i" cogs-stage2-warm /bin/busybox sh -c 'n=0; while [ $n -lt 16 ]; do /bin/busybox find /data/files -type f -print0 | /bin/busybox xargs -0 /bin/busybox cat >/dev/null; n=$((n+1)); done')" )
done
stop_kata_task cogs-stage2-warm
assert_qemu_baseline

stage=host-baselines
git_ms=()
build_ms=()
repo=$work/synthetic-repo
rm -rf "$repo"
mkdir -p "$repo"
git -C "$repo" init -q
git -C "$repo" config user.email cogs-stage2@example.invalid
git -C "$repo" config user.name cogs-stage2
python3 - "$repo" <<'PY'
from pathlib import Path
import sys
repo = Path(sys.argv[1])
for i in range(512):
    (repo / f'file{i:04d}.txt').write_text(('line %04d\n' % i) * 128, encoding='utf-8')
PY
git -C "$repo" add .
git -C "$repo" commit -q -m 'synthetic baseline'
for i in $(seq 1 "$samples"); do
  git_ms+=( "$(measure_ms /bin/busybox sh -c 'n=0; while [ $n -lt 20 ]; do git -C /var/tmp/cogs-stage2-measure/synthetic-repo grep -n line >/dev/null; n=$((n+1)); done')" )
done
build=$work/synthetic-build
rm -rf "$build"
mkdir -p "$build"
cat >"$build/main.c" <<'C'
#include <stdio.h>
static unsigned long fib(unsigned n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
int main(void) { printf("%lu\n", fib(34)); return 0; }
C
cat >"$build/Makefile" <<'MK'
all: cogs-stage2
cogs-stage2: main.c
	cc -O2 -Wall -Wextra -o cogs-stage2 main.c
clean:
	rm -f cogs-stage2
MK
for i in $(seq 1 "$samples"); do
  build_ms+=( "$(measure_ms /bin/busybox sh -c 'n=0; while [ $n -lt 50 ]; do make -C /var/tmp/cogs-stage2-measure/synthetic-build clean all >/dev/null; n=$((n+1)); done')" )
done

stage=idle-memory
qemu_before=$(qemu_pids | tr '\n' ' ' | sed 's/ $//')
start_kata_task cogs-stage2-idle
sleep 8
qemu_after=$(qemu_pids | tr '\n' ' ' | sed 's/ $//')
qemu_pid_detected=$(qemu_diff_one "$qemu_before" "$qemu_after")
qemu_rss_mib=$(awk '/VmRSS:/ {print int($2/1024)}' "/proc/$qemu_pid_detected/status")
(( qemu_rss_mib > 0 ))
stop_kata_task cogs-stage2-idle
assert_qemu_baseline

stage=report
cleanup_kata_tasks
assert_qemu_baseline
completed=$(date +%s%3N)
host_vcpus=$(nproc)
python3 - "$report" "$samples" "$host_kernel" "$guest_kernel" "$containerd_version" "$qemu_version" "$kata_runtime_version" "$install_completed" "$started" "$completed" "$qemu_rss_mib" "$guest_memory_mib" "$guest_vcpus" "$host_vcpus" \
  "$(json_array "${kata_boot_ms[@]}")" "$(json_array "${host_cpu_ms[@]}")" "$(json_array "${kata_cpu_ms[@]}")" "$(json_array "${host_fs_ms[@]}")" "$(json_array "${kata_fs_ms[@]}")" "$(json_array "${git_ms[@]}")" "$(json_array "${build_ms[@]}")" <<'PY'
import json, math, sys
(
  output, samples, host_kernel, guest_kernel, containerd_version, qemu_version, kata_runtime_version,
  install_completed, started, completed, qemu_rss_mib, guest_memory_mib, guest_vcpus, host_vcpus,
  kata_boot_raw, host_cpu_raw, kata_cpu_raw, host_fs_raw, kata_fs_raw, git_raw, build_raw,
) = sys.argv[1:]
def values(raw): return [int(x) for x in json.loads(raw)]
def pct(xs, p):
    ordered = sorted(xs)
    index = math.ceil((p / 100) * len(ordered)) - 1
    return ordered[max(0, min(index, len(ordered) - 1))]
def summary(raw):
    xs = values(raw)
    return {'samples': xs, 'min_ms': min(xs), 'p50_ms': pct(xs, 50), 'p95_ms': pct(xs, 95), 'max_ms': max(xs)}
def ratio(host_raw, kata_raw):
    return round(pct(values(kata_raw), 50) / pct(values(host_raw), 50), 3)
qemu_rss = int(qemu_rss_mib)
guest_mem = int(guest_memory_mib)
guest_cpu = int(guest_vcpus)
host_cpu = int(host_vcpus)
memory_basis = max(qemu_rss, guest_mem)
memory_bound = max(1, (4096 - 1024) // memory_basis)
cpu_bound = max(1, host_cpu // guest_cpu)
value = {
  'version': 'cogs.aws-stage2-measurement-result/v1alpha1',
  'result': 'pass',
  'sample_count': int(samples),
  'host_kernel': host_kernel,
  'guest_kernel': guest_kernel,
  'guest_root': True,
  'cpu_vmx': True,
  'kvm_device': True,
  'qmp_kvm_present': True,
  'qmp_kvm_enabled': True,
  'containerd_version': containerd_version,
  'qemu_version': qemu_version,
  'kata_runtime_version': kata_runtime_version,
  'kata_archive_sha256': '1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01',
  'package_setup_ms': int(install_completed) - int(started),
  'measurement_duration_ms': int(completed) - int(started),
  'kata_cold_boot': summary(kata_boot_raw),
  'warm_cpu_workload': {'host': summary(host_cpu_raw), 'kata': summary(kata_cpu_raw), 'kata_to_host_p50_ratio': ratio(host_cpu_raw, kata_cpu_raw)},
  'warm_filesystem_workload': {'host': summary(host_fs_raw), 'kata': summary(kata_fs_raw), 'kata_to_host_p50_ratio': ratio(host_fs_raw, kata_fs_raw)},
  'host_git_baseline': summary(git_raw),
  'host_package_build_baseline': summary(build_raw),
  'idle_memory': {'qemu_rss_mib': qemu_rss, 'configured_guest_memory_mib': guest_mem, 'memory_basis_mib': memory_basis},
  'density_estimate': {
    'basis': 'min(memory_bound_after_1024_mib_host_reserve_using_max(qemu_rss,configured_guest_memory), cpu_bound_host_vcpus_per_configured_guest_vcpu)',
    'host_vcpus': host_cpu,
    'configured_guest_vcpus': guest_cpu,
    'memory_bound_sandboxes': memory_bound,
    'cpu_bound_sandboxes': cpu_bound,
    'bounded_estimate_sandboxes': max(1, min(memory_bound, cpu_bound)),
  },
  'limitations': [
    'single EC2 host campaign; EC2 launch p50/p95 requires multiple launches and is not measured by this harness',
    'SSM readiness has one sample per campaign; SSH-ready is not measured because Stage 2 access is SSM-only',
    'Git and package-build measurements are host baselines only; representative sandbox Git/build/package workload acceptance remains unmet by this evidence',
    'density estimate is a conservative bound, not a scheduler or isolation claim',
  ],
}
with open(output, 'w', encoding='utf-8') as target:
    json.dump(value, target, sort_keys=True, separators=(',', ':'))
    target.write('\n')
print(json.dumps(value, sort_keys=True, separators=(',', ':')))
PY
cat "$report"

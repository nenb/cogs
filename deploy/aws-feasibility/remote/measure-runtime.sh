#!/usr/bin/env bash
set -eEuo pipefail
if [[ ${COGS_STAGE2_MEASURE_IN_SESSION:-0} != 1 ]]; then
  export COGS_STAGE2_MEASURE_IN_SESSION=1
  exec python3 - "$0" "$@" <<'PY'
import os, sys
script, args = sys.argv[1], sys.argv[2:]
os.setsid()
os.execv('/usr/bin/env', ['env', 'bash', script, *args])
PY
fi
stage=initialization
sample=none
command_label=none
validate_seconds() {
  local name=$1 value=$2 min=$3 max=$4
  [[ "$value" =~ ^[0-9]+$ ]] || { printf '%s must be an integer number of seconds\n' "$name" >&2; exit 2; }
  (( value >= min && value <= max )) || { printf '%s must be between %s and %s seconds\n' "$name" "$min" "$max" >&2; exit 2; }
}
validate_kill_after() {
  local name=$1 value=$2
  [[ "$value" =~ ^[1-5]s$ ]] || { printf '%s must match ^[1-5]s$\n' "$name" >&2; exit 2; }
}
remote_deadline_seconds=${COGS_STAGE2_REMOTE_DEADLINE_SECONDS:-660}
command_kill_after=${COGS_STAGE2_COMMAND_KILL_AFTER:-2s}
package_update_timeout=${COGS_STAGE2_PACKAGE_UPDATE_TIMEOUT:-90}
package_install_timeout=${COGS_STAGE2_PACKAGE_INSTALL_TIMEOUT:-180}
download_timeout=${COGS_STAGE2_DOWNLOAD_TIMEOUT:-90}
extract_timeout=${COGS_STAGE2_EXTRACT_TIMEOUT:-60}
qmp_timeout=${COGS_STAGE2_QMP_TIMEOUT:-20}
qemu_probe_wait_timeout=${COGS_STAGE2_QEMU_PROBE_WAIT_TIMEOUT:-10}
kata_boot_timeout=${COGS_STAGE2_KATA_BOOT_TIMEOUT:-60}
warm_sample_timeout=${COGS_STAGE2_WARM_SAMPLE_TIMEOUT:-60}
host_baseline_sample_timeout=${COGS_STAGE2_HOST_BASELINE_SAMPLE_TIMEOUT:-45}
idle_timeout=${COGS_STAGE2_IDLE_TIMEOUT:-20}
validate_seconds COGS_STAGE2_REMOTE_DEADLINE_SECONDS "$remote_deadline_seconds" 1 840
validate_kill_after COGS_STAGE2_COMMAND_KILL_AFTER "$command_kill_after"
validate_seconds COGS_STAGE2_PACKAGE_UPDATE_TIMEOUT "$package_update_timeout" 10 180
validate_seconds COGS_STAGE2_PACKAGE_INSTALL_TIMEOUT "$package_install_timeout" 30 300
validate_seconds COGS_STAGE2_DOWNLOAD_TIMEOUT "$download_timeout" 10 180
validate_seconds COGS_STAGE2_EXTRACT_TIMEOUT "$extract_timeout" 5 120
validate_seconds COGS_STAGE2_QMP_TIMEOUT "$qmp_timeout" 5 60
validate_seconds COGS_STAGE2_QEMU_PROBE_WAIT_TIMEOUT "$qemu_probe_wait_timeout" 3 30
validate_seconds COGS_STAGE2_KATA_BOOT_TIMEOUT "$kata_boot_timeout" 10 90
validate_seconds COGS_STAGE2_WARM_SAMPLE_TIMEOUT "$warm_sample_timeout" 5 60
validate_seconds COGS_STAGE2_HOST_BASELINE_SAMPLE_TIMEOUT "$host_baseline_sample_timeout" 5 60
validate_seconds COGS_STAGE2_IDLE_TIMEOUT "$idle_timeout" 10 30
if [[ -z ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} ]]; then
  for per_command_timeout in "$package_update_timeout" "$package_install_timeout" "$download_timeout" "$extract_timeout" "$qmp_timeout" "$qemu_probe_wait_timeout" "$kata_boot_timeout" "$warm_sample_timeout" "$host_baseline_sample_timeout" "$idle_timeout"; do
    (( per_command_timeout < remote_deadline_seconds )) || { printf 'per-command timeout %s must be less than remote deadline %s\n' "$per_command_timeout" "$remote_deadline_seconds" >&2; exit 2; }
  done
fi
failure() {
  local failure_status=$?
  local failed_stage=$stage
  local failed_sample=$sample
  local failed_command=$command_label
  local state_stage state_sample state_command
  local diagnostic_file files remaining diagnostic header header_len
  if [[ -n ${timeout_state:-} && -f $timeout_state ]]; then
    read -r state_stage state_sample state_command <"$timeout_state" || true
    if [[ ${state_stage:-} =~ ^[A-Za-z0-9._:-]+$ && ${state_sample:-} =~ ^[A-Za-z0-9._:-]+$ && ${state_command:-} =~ ^[A-Za-z0-9._:-]+$ ]]; then
      failed_stage=$state_stage
      failed_sample=$state_sample
      failed_command=$state_command
    fi
  fi
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
  printf 'cogs-stage2-measurement-failure-stage=%s sample=%s command=%s status=%s\n' "$failed_stage" "$failed_sample" "$failed_command" "$failure_status" >&2
  cat "$diagnostic_file" >&2
  exit "$failure_status"
}
outer_timeout_watchdog() {
  local parent_pgid=$1 state_file=$2
  sleep "$remote_deadline_seconds"
  if [[ -f "$state_file" ]]; then
    read -r timeout_stage timeout_sample timeout_command <"$state_file" || true
  fi
  trap '' TERM
  printf 'cogs-stage2-measurement-timeout-stage=%s sample=%s command=%s status=outer-timeout\n' "${timeout_stage:-$stage}" "${timeout_sample:-$sample}" "${timeout_command:-$command_label}" >&2
  if [[ -f "${state_file}.active-pgid" ]]; then
    read -r active_pgid <"${state_file}.active-pgid" || true
    if [[ ${active_pgid:-} =~ ^[0-9]+$ ]]; then
      kill -TERM -- "-$active_pgid" >/dev/null 2>&1 || true
    fi
  fi
  kill -TERM -- "-$parent_pgid" >/dev/null 2>&1 || true
  sleep 2
  if [[ ${active_pgid:-} =~ ^[0-9]+$ ]]; then
    kill -KILL -- "-$active_pgid" >/dev/null 2>&1 || true
  fi
  kill -KILL -- "-$parent_pgid" >/dev/null 2>&1 || true
}
trap failure ERR
progress() {
  printf '%s %s %s\n' "$stage" "$sample" "$command_label" >"${timeout_state:-/dev/null}" 2>/dev/null || true
  printf 'cogs-stage2-progress stage=%s sample=%s command=%s\n' "$stage" "$sample" "$command_label" >&2
}
completion() {
  local completed_stage=$1 completed_sample=$2 completed_command=$3 elapsed_ms=$4 marker_file
  marker_file=${work:-/tmp}/completion-markers.ndjson
  printf 'cogs-stage2-complete stage=%s sample=%s command=%s elapsed_ms=%s\n' "$completed_stage" "$completed_sample" "$completed_command" "$elapsed_ms" >&2
  printf '{"stage":"%s","sample":"%s","command":"%s","elapsed_ms":%s}\n' "$completed_stage" "$completed_sample" "$completed_command" "$elapsed_ms" >>"$marker_file"
}
run_bounded() {
  local seconds=$1
  command_label=$2
  shift 2
  progress
  if python3 -c '
import os, signal, sys, time
active_path, kill_after_raw, seconds_raw, command = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
kill_after = int(kill_after_raw.removesuffix("s"))
seconds = int(seconds_raw.removesuffix("s"))
pid = os.fork()
if pid == 0:
    os.setsid()
    os.execvp(command[0], command)
with open(active_path, "w", encoding="utf-8") as handle:
    handle.write(f"{pid}\n")
def descendants(root):
    try:
        rows = os.popen("ps -axo pid=,ppid=").read().splitlines()
    except Exception:
        return []
    children = {}
    for row in rows:
        parts = row.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            children.setdefault(int(parts[1]), []).append(int(parts[0]))
    found = []
    stack = [root]
    while stack:
        parent = stack.pop()
        for child in children.get(parent, []):
            found.append(child)
            stack.append(child)
    return found

def signal_tree(root, sig):
    try:
        os.killpg(root, sig)
    except ProcessLookupError:
        pass
    for child in descendants(root):
        try:
            os.kill(child, sig)
        except ProcessLookupError:
            pass

deadline = time.monotonic() + seconds
term_sent = False
kill_deadline = None
status = None
while True:
    waited_pid, status = os.waitpid(pid, os.WNOHANG)
    if waited_pid == pid:
        break
    now = time.monotonic()
    if not term_sent and now >= deadline:
        signal_tree(pid, signal.SIGTERM)
        term_sent = True
        kill_deadline = now + kill_after
    elif term_sent and kill_deadline is not None and now >= kill_deadline:
        signal_tree(pid, signal.SIGKILL)
    time.sleep(0.02)
try:
    os.unlink(active_path)
except FileNotFoundError:
    pass
if os.WIFEXITED(status):
    code = os.WEXITSTATUS(status)
    if term_sent and code == 0:
        code = 124
    raise SystemExit(code)
if os.WIFSIGNALED(status):
    raise SystemExit(128 + os.WTERMSIG(status))
raise SystemExit(1)
' "${timeout_state:-/tmp/cogs-stage2-timeout}.active-pgid" "$command_kill_after" "${seconds}s" "$@"; then
    bounded_status=0
  else
    bounded_status=$?
  fi
  rm -f "${timeout_state:-/tmp/cogs-stage2-timeout}.active-pgid"
  return "$bounded_status"
}
measure_ms() {
  local seconds=$1 label=$2 start_ms end_ms elapsed completed_stage completed_sample
  shift 2
  completed_stage=$stage
  completed_sample=$sample
  start_ms=$(python3 -c 'import time; print(int(time.time() * 1000))')
  run_bounded "$seconds" "$label" "$@" >/dev/null
  end_ms=$(python3 -c 'import time; print(int(time.time() * 1000))')
  elapsed=$((end_ms - start_ms))
  (( elapsed >= 25 )) || { printf 'benchmark sample too short: %s ms\n' "$elapsed" >&2; return 1; }
  completion "$completed_stage" "$completed_sample" "$label" "$elapsed"
  printf '%s\n' "$elapsed"
}
export DEBIAN_FRONTEND=noninteractive
work=${COGS_STAGE2_WORK_DIR:-/var/tmp/cogs-stage2-measure}
report=$work/measurement-result.json
samples=${COGS_STAGE2_MEASUREMENT_SAMPLES:-7}
[[ "$samples" =~ ^[0-9]+$ && "$samples" -ge 7 && "$samples" -le 9 ]]
mkdir -p "$work"
chmod 700 "$work"
timeout_state=$work/timeout-state.txt
progress
script_pgid=$(ps -o pgid= $$ | tr -d ' ')
outer_timeout_watchdog "$script_pgid" "$timeout_state" &
outer_timeout_pid=$!
if [[ -n ${COGS_STAGE2_WATCHDOG_PID_FILE:-} ]]; then
  printf '%s\n' "$outer_timeout_pid" >"$COGS_STAGE2_WATCHDOG_PID_FILE"
fi
trap 'pkill -TERM -P "$outer_timeout_pid" >/dev/null 2>&1 || true; kill "$outer_timeout_pid" >/dev/null 2>&1 || true' EXIT
started=$(date +%s%3N)

if [[ ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} == stdin-pipeline ]]; then
  stage=timeout-self-test
  sample=pipeline
  printf 'pipeline-ok' | run_bounded 5 stdin-pipeline cat >"${COGS_STAGE2_STDIN_TEST_FILE:?}"
  exit 0
elif [[ ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} == stdin-heredoc ]]; then
  stage=timeout-self-test
  sample=heredoc
  run_bounded 5 stdin-heredoc python3 - "${COGS_STAGE2_STDIN_TEST_FILE:?}" <<'PY'
import sys
open(sys.argv[1], 'w', encoding='utf-8').write('heredoc-ok')
PY
  exit 0
elif [[ ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} == watchdog-success ]]; then
  stage=timeout-self-test
  sample=watchdog-success
  command_label=quick-success
  progress
  exit 0
elif [[ ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} == completion-marker ]]; then
  stage=warm-workload-samples
  sample=1
  measure_ms 5 host-cpu-1 sleep 0.03 >/dev/null
  exit 0
elif [[ ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} == host-sample ]]; then
  stage=warm-workload-samples
  sample=2
  if [[ -n ${COGS_STAGE2_TIMEOUT_PID_FILE:-} ]]; then
    measure_ms 1 host-cpu-2 bash -c 'echo $$ >"$1"; trap "" TERM; sleep 30' bash "$COGS_STAGE2_TIMEOUT_PID_FILE" >/dev/null
  else
    measure_ms 1 host-cpu-2 sleep 2 >/dev/null
  fi
  exit 99
elif [[ ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} == kata-sample ]]; then
  stage=warm-workload-samples
  sample=3
  if [[ -n ${COGS_STAGE2_TIMEOUT_PID_FILE:-} ]]; then
    measure_ms 1 kata-cpu-3 bash -c 'echo $$ >"$1"; trap "" TERM; sleep 30' bash "$COGS_STAGE2_TIMEOUT_PID_FILE" >/dev/null
  else
    measure_ms 1 kata-cpu-3 sleep 2 >/dev/null
  fi
  exit 99
elif [[ ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} == command-substitution-sample ]]; then
  stage=warm-workload-samples
  sample=7
  command_label=kata-start-cogs-stage2-warm
  progress
  sample_value=$(measure_ms 1 kata-cpu-7 sleep 2)
  printf '%s\n' "$sample_value" >/dev/null
  exit 99
elif [[ ${COGS_STAGE2_TIMEOUT_SELF_TEST:-} == outer ]]; then
  stage=host-baselines
  sample=7
  command_label=host-build-7
  progress
  if [[ -n ${COGS_STAGE2_TIMEOUT_PID_FILE:-} ]]; then
    run_bounded 30 host-build-7 bash -c 'echo $$ >"$1"; trap "" TERM; sleep 30' bash "$COGS_STAGE2_TIMEOUT_PID_FILE"
  else
    sleep 2
  fi
  exit 99
fi

stage=package-index
sample=none
run_bounded "$package_update_timeout" apt-get-update apt-get update -qq
stage=package-install
sample=none
run_bounded "$package_install_timeout" apt-get-install apt-get install -y -qq busybox-static build-essential containerd cpu-checker curl git jq qemu-system-x86 zstd >/var/log/cogs-stage2-measure-apt.log
install_completed=$(date +%s%3N)

stage=active-kvm
host_kernel=$(uname -r)
grep -qw vmx /proc/cpuinfo
modprobe kvm
modprobe kvm_intel
test -c /dev/kvm
test -r /dev/kvm
test -w /dev/kvm
run_bounded 10 kvm-ok kvm-ok >"$work/kvm-ok.txt" 2>&1
qmp=$work/qmp.sock
rm -f "$qmp"
command_label=qemu-probe-start
progress
qemu-system-x86_64 -S -nodefaults -display none -machine accel=kvm -cpu host -qmp "unix:$qmp,server=on,wait=off" &
qemu_pid=$!
cleanup_qemu_probe() {
  kill "$qemu_pid" >/dev/null 2>&1 || true
  timeout --kill-after=1s 3s tail --pid="$qemu_pid" -f /dev/null >/dev/null 2>&1 || true
  wait "$qemu_pid" >/dev/null 2>&1 || true
}
run_bounded "$qemu_probe_wait_timeout" qemu-probe-socket bash -c 'for _ in $(seq 1 50); do [[ -S "$1" ]] && exit 0; sleep 0.1; done; exit 1' bash "$qmp" || { cleanup_qemu_probe; false; }
set +e
run_bounded "$qmp_timeout" qmp-query python3 - "$qmp" "$work/qmp.json" <<'PY'
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
qmp_status=$?
set -e
(( qmp_status == 0 )) || { cleanup_qemu_probe; return "$qmp_status" 2>/dev/null || exit "$qmp_status"; }
run_bounded "$qemu_probe_wait_timeout" qemu-probe-exit tail --pid="$qemu_pid" -f /dev/null || { cleanup_qemu_probe; false; }
wait "$qemu_pid"

kata_version=3.32.0
kata_archive="$work/kata-static-$kata_version-amd64.tar.zst"
kata_url="https://github.com/kata-containers/kata-containers/releases/download/$kata_version/kata-static-$kata_version-amd64.tar.zst"
stage=kata-download
run_bounded "$download_timeout" kata-download curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$kata_url" --output "$kata_archive"
stage=kata-digest
printf '%s  %s\n' '1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01' "$kata_archive" | run_bounded 15 kata-digest sha256sum --check --status
stage=kata-extract
run_bounded "$extract_timeout" kata-extract tar --zstd -xf "$kata_archive" -C /
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
run_bounded 30 kata-runtime-check /opt/kata/bin/kata-runtime --config "$config" check >"$work/kata-check.txt" 2>&1
kata_runtime_version=$(/opt/kata/bin/kata-runtime --version | head -n 1 | tr -cd '[:alnum:]. _/-')
containerd_version=$(containerd --version | tr -cd '[:alnum:]. _/-')
qemu_version=$(qemu-system-x86_64 --version | head -n 1 | tr -cd '[:alnum:]. _/()-')
run_bounded 20 containerd-start systemctl start containerd

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
  local name=$1
  shift
  ctr --namespace cogs-stage2 containers rm "$name" >/dev/null 2>&1 || true
  run_bounded "$kata_boot_timeout" "kata-run-$name" ctr --namespace cogs-stage2 run --rm --runtime io.containerd.kata.v2 --runtime-config-path "$config" --rootfs --read-only "$rootfs" "$name" "$@"
  assert_qemu_baseline
}
start_kata_task() {
  local name=$1
  stop_kata_task "$name" >/dev/null
  run_bounded 30 "kata-start-$name" ctr --namespace cogs-stage2 run --runtime io.containerd.kata.v2 --runtime-config-path "$config" --rootfs --read-only --detach "$rootfs" "$name" /bin/busybox sleep 300
}
task_status() {
  local name=$1 list_output
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
  local name=$1 phase=$2 steps delay raw_status observed_status last_status attempt
  steps=${COGS_STAGE2_TEARDOWN_WAIT_STEPS:-100}
  delay=${COGS_STAGE2_TEARDOWN_WAIT_DELAY:-0.1}
  for attempt in $(seq 1 "$steps"); do
    raw_status=$(task_status "$name") || return $?
    observed_status=$(normalize_task_status "$raw_status" "$name") || return $?
    last_status=$observed_status
    printf '%s\n' "$observed_status" >"$work/task-status-$name-$phase.txt"
    case "$observed_status" in
      ABSENT|STOPPED) return 0 ;;
      RUNNING) sleep "$delay" ;;
      UNKNOWN|CREATED|PAUSED|PAUSING)
        printf 'Kata task %s reported terminal non-stopped status %s during %s\n' "$name" "$observed_status" "$phase" >&2
        return 2 ;;
    esac
  done
  printf 'timed out waiting for Kata task %s to report STOPPED or disappear during %s; last status %s\n' "$name" "$phase" "${last_status:-unset}" >&2
  [[ ${last_status:-} == RUNNING ]] && return 1
  return 2
}
bounded_task_wait_after_signal() {
  local name=$1 signal=$2 phase=$3 wait_output wait_seconds wait_status
  wait_output=$work/task-wait-$name-$phase.txt
  wait_seconds=${COGS_STAGE2_TEARDOWN_WAIT_SECONDS:-10}
  ctr --namespace cogs-stage2 tasks kill --signal "$signal" "$name" >/dev/null 2>&1 || true
  if timeout --kill-after=1s "${wait_seconds}s" ctr --namespace cogs-stage2 tasks wait "$name" >"$wait_output" 2>&1; then
    wait_status=0
  else
    wait_status=$?
  fi
  printf '%s\n' "$wait_status" >"$work/task-wait-status-$name-$phase.txt"
  return 0
}
stop_kata_task() {
  local name=$1 raw_status observed_status stopped_status attempt
  local previous_command_label=$command_label
  command_label="kata-stop-$name"
  progress
  if raw_status=$(task_status "$name"); then
    :
  else
    stopped_status=$?
    return "$stopped_status"
  fi
  if observed_status=$(normalize_task_status "$raw_status" "$name"); then
    :
  else
    stopped_status=$?
    return "$stopped_status"
  fi
  if [[ "$observed_status" != ABSENT ]]; then
    if [[ "$observed_status" != STOPPED ]]; then
      if [[ "$observed_status" != RUNNING ]]; then
        printf 'refusing to signal/remove Kata task %s from non-running status %s\n' "$name" "$observed_status" >&2
        return 1
      fi
      bounded_task_wait_after_signal "$name" SIGTERM graceful
      if wait_for_task_stopped_or_absent "$name" graceful; then
        :
      else
        stopped_status=$?
        if (( stopped_status == 1 )); then
          bounded_task_wait_after_signal "$name" SIGKILL killed
          if wait_for_task_stopped_or_absent "$name" killed; then
            :
          else
            stopped_status=$?
            return "$stopped_status"
          fi
        else
          return "$stopped_status"
        fi
      fi
    fi
    if raw_status=$(task_status "$name"); then
      :
    else
      stopped_status=$?
      return "$stopped_status"
    fi
    if observed_status=$(normalize_task_status "$raw_status" "$name"); then
      :
    else
      stopped_status=$?
      return "$stopped_status"
    fi
    if [[ "$observed_status" == STOPPED ]]; then
      ctr --namespace cogs-stage2 tasks rm "$name" >/dev/null
    elif [[ "$observed_status" != ABSENT ]]; then
      printf 'refusing to remove Kata task %s before STOPPED/absent; status %s\n' "$name" "$observed_status" >&2
      return 1
    fi
  fi
  for attempt in $(seq 1 50); do
    [[ "$(normalize_task_status "$(task_status "$name")" "$name")" == ABSENT ]] && break
    sleep 0.1
  done
  [[ "$(normalize_task_status "$(task_status "$name")" "$name")" == ABSENT ]] || return 1
  if ctr --namespace cogs-stage2 containers info "$name" >/dev/null 2>&1; then
    ctr --namespace cogs-stage2 containers rm "$name" >/dev/null
  fi
  for attempt in $(seq 1 50); do
    ctr --namespace cogs-stage2 containers info "$name" >/dev/null 2>&1 || break
    sleep 0.1
  done
  ! ctr --namespace cogs-stage2 containers info "$name" >/dev/null 2>&1 || return 1
  [[ ${qemu_baseline+x} != x ]] || assert_qemu_baseline
  command_label=$previous_command_label
}
cleanup_kata_tasks() {
  local name
  for name in cogs-stage2-warm cogs-stage2-idle; do
    stop_kata_task "$name" || true
  done
}
qemu_baseline=$(qemu_pids | tr '\n' ' ' | sed 's/ $//')
json_array() { python3 - "$@" <<'PY'
import json, sys
print(json.dumps([int(x) for x in sys.argv[1:]], separators=(',', ':')))
PY
}

stage=kata-cold-boot-samples
kata_boot_ms=()
guest_kernel=""
for i in $(seq 1 "$samples"); do
  sample=$i
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
sample=setup
host_cpu_ms=()
kata_cpu_ms=()
host_fs_ms=()
kata_fs_ms=()
start_kata_task cogs-stage2-warm
for i in $(seq 1 "$samples"); do
  sample=$i
  host_cpu_ms+=( "$(measure_ms "$warm_sample_timeout" "host-cpu-$i" /bin/busybox sh -c 'n=0; while [ $n -lt 16 ]; do /bin/busybox sha256sum /var/tmp/cogs-stage2-measure/rootfs/data/payload.bin >/dev/null; n=$((n+1)); done')" )
  kata_cpu_ms+=( "$(measure_ms "$warm_sample_timeout" "kata-cpu-$i" ctr --namespace cogs-stage2 tasks exec --exec-id "cpu-$i" cogs-stage2-warm /bin/busybox sh -c 'n=0; while [ $n -lt 16 ]; do /bin/busybox sha256sum /data/payload.bin >/dev/null; n=$((n+1)); done')" )
  host_fs_ms+=( "$(measure_ms "$warm_sample_timeout" "host-fs-$i" /bin/busybox sh -c 'n=0; while [ $n -lt 16 ]; do /bin/busybox find /var/tmp/cogs-stage2-measure/rootfs/data/files -type f -print0 | /bin/busybox xargs -0 /bin/busybox cat >/dev/null; n=$((n+1)); done')" )
  kata_fs_ms+=( "$(measure_ms "$warm_sample_timeout" "kata-fs-$i" ctr --namespace cogs-stage2 tasks exec --exec-id "fs-$i" cogs-stage2-warm /bin/busybox sh -c 'n=0; while [ $n -lt 16 ]; do /bin/busybox find /data/files -type f -print0 | /bin/busybox xargs -0 /bin/busybox cat >/dev/null; n=$((n+1)); done')" )
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
  sample=$i
  git_ms+=( "$(measure_ms "$host_baseline_sample_timeout" "host-git-$i" /bin/busybox sh -c 'n=0; while [ $n -lt 20 ]; do git -C /var/tmp/cogs-stage2-measure/synthetic-repo grep -n line >/dev/null; n=$((n+1)); done')" )
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
  sample=$i
  build_ms+=( "$(measure_ms "$host_baseline_sample_timeout" "host-build-$i" /bin/busybox sh -c 'n=0; while [ $n -lt 50 ]; do make -C /var/tmp/cogs-stage2-measure/synthetic-build clean all >/dev/null; n=$((n+1)); done')" )
done

stage=idle-memory
sample=idle
qemu_before=$(qemu_pids | tr '\n' ' ' | sed 's/ $//')
start_kata_task cogs-stage2-idle
run_bounded "$idle_timeout" idle-observation sleep 8
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

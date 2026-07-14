#!/usr/bin/env bash
set -eEuo pipefail
stage=initialization
failure() {
  status=$?
  trap - ERR
  set +e
  printf 'cogs-stage2-failure-stage=%s status=%s\n' "$stage" "$status" >&2
  if [[ "$stage" == kata-boot && -n "${work:-}" ]]; then
    for diagnostic in "$work/kata-stderr.txt" "$work/kata-output.txt"; do
      if [[ -f "$diagnostic" ]]; then
        printf 'cogs-stage2-bounded-diagnostic=%s\n' "$(basename "$diagnostic")" >&2
        tail -c 2048 "$diagnostic" | tr -c '[:print:]\n\t' '?' >&2
        printf '\n' >&2
      fi
    done
  fi
  exit "$status"
}
trap failure ERR
export DEBIAN_FRONTEND=noninteractive
work=/var/tmp/cogs-stage2
report=$work/runtime-result.json
mkdir -p "$work"
chmod 700 "$work"
started=$(date +%s%3N)

stage=package-index
apt-get update -qq
stage=package-install
apt-get install -y -qq busybox-static containerd cpu-checker curl jq qemu-system-x86 runc zstd >/var/log/cogs-stage2-apt.log
install_completed=$(date +%s%3N)

stage=cpu-vmx
host_kernel=$(uname -r)
grep -qw vmx /proc/cpuinfo
stage=kvm-modules
modprobe kvm
modprobe kvm_intel
stage=kvm-device
test -c /dev/kvm
test -r /dev/kvm
test -w /dev/kvm
stage=kvm-ok
kvm-ok >"$work/kvm-ok.txt" 2>&1

stage=qemu-start
qmp=$work/qmp.sock
rm -f "$qmp"
qemu-system-x86_64 -S -nodefaults -display none -machine accel=kvm -cpu host -qmp "unix:$qmp,server=on,wait=off" &
qemu_pid=$!
for _ in $(seq 1 50); do [[ -S "$qmp" ]] && break; sleep 0.1; done
[[ -S "$qmp" ]]
stage=qmp-active-kvm
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
status = command('query-status')
command('quit')
with open(output, 'w', encoding='utf-8') as target:
    json.dump({'greeting': bool(greeting.get('QMP')), 'capabilities': capabilities, 'kvm': kvm, 'status': status}, target, separators=(',', ':'))
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

stage=kata-runtime-files
test -x /opt/kata/bin/kata-runtime
config=/opt/kata/share/defaults/kata-containers/configuration-qemu.toml
test -f "$config"
stage=kata-runtime-check
/opt/kata/bin/kata-runtime --config "$config" check >"$work/kata-check.txt" 2>&1
kata_runtime_version=$(/opt/kata/bin/kata-runtime --version | head -n 1 | tr -cd '[:alnum:]. _/-')
containerd_version=$(containerd --version | tr -cd '[:alnum:]. _/-')
qemu_version=$(qemu-system-x86_64 --version | head -n 1 | tr -cd '[:alnum:]. _/()-')

stage=bundle-creation
bundle=$work/bundle
rm -rf "$bundle"
mkdir -p "$bundle/rootfs/bin"
cp /bin/busybox "$bundle/rootfs/bin/busybox"
(cd "$bundle" && runc spec)
python3 - "$bundle/config.json" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding='utf-8') as source:
    config = json.load(source)
config['process']['terminal'] = False
config['process']['cwd'] = '/'
config['process']['user'] = {'uid': 0, 'gid': 0}
config['process']['args'] = ['/bin/busybox', 'sh', '-c', '/bin/busybox echo COGS_UID=$(/bin/busybox id -u); /bin/busybox echo COGS_KERNEL=$(/bin/busybox uname -r)']
config['root']['readonly'] = True
with open(path, 'w', encoding='utf-8') as target:
    json.dump(config, target, separators=(',', ':'))
    target.write('\n')
PY

stage=kata-boot
boot_started=$(date +%s%3N)
set +e
/opt/kata/bin/kata-runtime --config "$config" run --bundle "$bundle" cogs-stage2 >"$work/kata-output.txt" 2>"$work/kata-stderr.txt"
runtime_status=$?
set -e
boot_completed=$(date +%s%3N)
[[ "$runtime_status" == 0 ]]
stage=guest-output
guest_uid=$(sed -n 's/^COGS_UID=//p' "$work/kata-output.txt" | tail -n 1)
guest_kernel=$(sed -n 's/^COGS_KERNEL=//p' "$work/kata-output.txt" | tail -n 1)
[[ "$guest_uid" == 0 ]]
[[ -n "$guest_kernel" ]]
[[ "$guest_kernel" != "$host_kernel" ]]
stage=qemu-teardown
! pgrep -f '[q]emu.*cogs-stage2'

stage=report
python3 - "$report" <<PY
import json
value = {
  'version': 'cogs.aws-runtime-result/v1alpha1',
  'result': 'pass',
  'host_kernel': '$host_kernel',
  'guest_kernel': '$guest_kernel',
  'guest_root': True,
  'cpu_vmx': True,
  'kvm_device': True,
  'qmp_kvm_present': True,
  'qmp_kvm_enabled': True,
  'containerd_version': '$containerd_version',
  'qemu_version': '$qemu_version',
  'kata_runtime_version': '$kata_runtime_version',
  'kata_archive_sha256': '1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01',
  'package_setup_ms': $install_completed - $started,
  'kata_boot_ms': $boot_completed - $boot_started,
}
with open('$report', 'w', encoding='utf-8') as output:
    json.dump(value, output, sort_keys=True, separators=(',', ':'))
    output.write('\n')
PY
cat "$report"

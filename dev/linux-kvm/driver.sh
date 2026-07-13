#!/usr/bin/env bash
set -euo pipefail
umask 077

operation=${1:-}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state=${COGS_KVM_STATE_DIR:-$repo/.cogs-dev/linux-kvm}
cache=${COGS_KVM_CACHE_DIR:-$repo/.cogs-dev/cache}
image_name=debian-13-generic-amd64-20260712-2537.qcow2
image_url="https://cloud.debian.org/images/cloud/trixie/20260712-2537/$image_name"
image_sha512=78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667
host_ip=192.0.2.1
guest_ip=192.0.2.2
network_suffix=$(printf '%s:%s' "$state" "$(id -u)" | sha256sum | cut -c1-8)
tap="cgk${network_suffix}"
input_chain="CGKI${network_suffix}"
drop_chain="CGKD${network_suffix}"
proxy_port=${COGS_KVM_PROXY_PORT:-18080}
sentinel="$state/.cogs-linux-kvm-v1"
lock="$repo/.cogs-dev/linux-kvm.lock"
mkdir -p "$repo/.cogs-dev"
exec 9>"$lock"
flock -w 30 9 || { echo 'FAIL: linux-kvm driver lock timed out' >&2; exit 1; }

validate_paths() {
  python3 - "$repo/.cogs-dev" "$state" "$cache" <<'PY'
import os,sys
root,state,cache=map(os.path.abspath,sys.argv[1:])
root_real=os.path.realpath(root)
for value in (state,cache):
    if os.path.dirname(value) != root or os.path.realpath(os.path.dirname(value)) != root_real:
        raise SystemExit("state/cache must be one direct child of .cogs-dev")
    if os.path.lexists(value) and os.path.islink(value):
        raise SystemExit("state/cache must not be symlinks")
PY
}
validate_paths

ssh_args() {
  printf '%s\0' -F /dev/null -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 \
    -o ServerAliveInterval=5 -o ServerAliveCountMax=1 -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$state/known_hosts" -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o ForwardAgent=no -o ClearAllForwardings=yes -i "$state/control/client_ed25519_key"
}
run_ssh() {
  local args=()
  while IFS= read -r -d '' item; do args+=("$item"); done < <(ssh_args)
  ssh "${args[@]}" root@"$guest_ip" "$@"
}

remove_firewall() {
  sudo iptables -D INPUT -i "$tap" -j "$input_chain" 2>/dev/null || true
  sudo iptables -D FORWARD -i "$tap" -j "$drop_chain" 2>/dev/null || true
  sudo iptables -F "$input_chain" 2>/dev/null || true
  sudo iptables -X "$input_chain" 2>/dev/null || true
  sudo iptables -F "$drop_chain" 2>/dev/null || true
  sudo iptables -X "$drop_chain" 2>/dev/null || true
  sudo ip6tables -D INPUT -i "$tap" -j DROP 2>/dev/null || true
  sudo ip6tables -D FORWARD -i "$tap" -j DROP 2>/dev/null || true
}
remove_network() {
  remove_firewall
  sudo ip link delete "$tap" 2>/dev/null || true
}
stop_vm() {
  if [[ -f "$state/qemu.pid" ]]; then
    pid=$(<"$state/qemu.pid")
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -KILL "$pid" 2>/dev/null || true
      for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -0 "$pid" 2>/dev/null && { echo 'FAIL: QEMU did not terminate' >&2; return 1; }
    fi
    rm -f "$state/qemu.pid"
  fi
}
cleanup_partial() {
  stop_vm
  remove_network
}

prepare_image() {
  mkdir -p "$cache"
  chmod 0700 "$cache"
  if [[ ! -f "$cache/$image_name" ]]; then
    tmp="$cache/$image_name.partial"
    rm -f "$tmp"
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$tmp" "$image_url"
    printf '%s  %s\n' "$image_sha512" "$tmp" | sha512sum --check --status
    mv "$tmp" "$cache/$image_name"
    chmod 0400 "$cache/$image_name"
  fi
  printf '%s  %s\n' "$image_sha512" "$cache/$image_name" | sha512sum --check --status
}

prepare_keys() {
  mkdir -p "$state/control"
  ssh-keygen -q -t ed25519 -N '' -C cogs-kvm-client -f "$state/control/client_ed25519_key"
  ssh-keygen -q -t ed25519 -N '' -C cogs-kvm-host -f "$state/control/host_ed25519_key"
  chmod 0600 "$state/control/"*_ed25519_key
  printf '%s %s\n' "$guest_ip" "$(<"$state/control/host_ed25519_key.pub")" > "$state/known_hosts"
}

prepare_seed() {
  client_pub=$(<"$state/control/client_ed25519_key.pub")
  host_private=$(base64 -w0 < "$state/control/host_ed25519_key")
  host_public=$(base64 -w0 < "$state/control/host_ed25519_key.pub")
  cat > "$state/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
ssh_deletekeys: false
ssh_genkeytypes: []
users:
  - name: root
    lock_passwd: true
    shell: /bin/bash
    ssh_authorized_keys:
      - $client_pub
write_files:
  - path: /etc/ssh/cogs_host_ed25519_key
    owner: root:root
    permissions: '0600'
    encoding: b64
    content: $host_private
  - path: /etc/ssh/cogs_host_ed25519_key.pub
    owner: root:root
    permissions: '0644'
    encoding: b64
    content: $host_public
  - path: /etc/ssh/sshd_config.d/10-cogs.conf
    owner: root:root
    permissions: '0644'
    content: |
      HostKey /etc/ssh/cogs_host_ed25519_key
      PermitRootLogin prohibit-password
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      AllowAgentForwarding no
      AllowTcpForwarding no
      X11Forwarding no
      PermitTunnel no
mounts:
  - [LABEL=COGS_WORKSPACE, /workspace, auto, 'defaults,nosuid,nodev', '0', '2']
runcmd:
  - [systemctl, restart, ssh]
EOF
  cat > "$state/meta-data" <<EOF
instance-id: cogs-kvm-$(sha256sum "$state/control/host_ed25519_key.pub" | cut -c1-16)
local-hostname: cogs-kvm-guest
EOF
  cat > "$state/network-config" <<EOF
version: 2
ethernets:
  id0:
    match:
      macaddress: '52:54:00:c0:65:01'
    set-name: eth0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    addresses: [$guest_ip/30]
EOF
  cloud-localds --network-config="$state/network-config" "$state/seed.img" "$state/user-data" "$state/meta-data"
  chmod 0400 "$state/seed.img" "$state/user-data" "$state/meta-data" "$state/network-config"
}

prepare_disks() {
  qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$image_name" "$state/root-overlay.qcow2" 12G
  qemu-img create -q -f raw "$state/workspace.img" 1G
  mkfs.ext4 -q -L COGS_WORKSPACE "$state/workspace.img"
  chmod 0600 "$state/root-overlay.qcow2" "$state/workspace.img"
}

prepare_network() {
  remove_network
  sudo ip tuntap add dev "$tap" mode tap user "$(id -u)"
  sudo ip addr add "$host_ip/30" dev "$tap"
  sudo ip link set "$tap" up
  sudo iptables -N "$input_chain"
  sudo iptables -A "$input_chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -A "$input_chain" -d "$host_ip" -p tcp --dport "$proxy_port" -j ACCEPT
  sudo iptables -A "$input_chain" -j DROP
  sudo iptables -I INPUT 1 -i "$tap" -j "$input_chain"
  sudo iptables -N "$drop_chain"
  sudo iptables -A "$drop_chain" -j DROP
  sudo iptables -I FORWARD 1 -i "$tap" -j "$drop_chain"
  sudo ip6tables -I INPUT 1 -i "$tap" -j DROP
  sudo ip6tables -I FORWARD 1 -i "$tap" -j DROP
}

start_vm() {
  prepare_network
  rm -f "$state/qmp.sock" "$state/serial.log"
  nohup qemu-system-x86_64 \
    -name cogs-stage1-linux-kvm -machine q35 -accel kvm -cpu host -smp 2 -m 2048M \
    -drive if=virtio,format=qcow2,file="$state/root-overlay.qcow2" \
    -drive if=virtio,format=raw,readonly=on,file="$state/seed.img" \
    -drive if=virtio,format=raw,file="$state/workspace.img" \
    -netdev tap,id=cogsnet,ifname="$tap",script=no,downscript=no \
    -device virtio-net-pci,netdev=cogsnet,mac=52:54:00:c0:65:01 \
    -display none -serial file:"$state/serial.log" -monitor none \
    -qmp unix:"$state/qmp.sock",server=on,wait=off -no-reboot \
    >"$state/qemu.stdout" 2>"$state/qemu.stderr" 9>&- &
  echo $! > "$state/qemu.pid"
  for _ in $(seq 1 600); do
    kill -0 "$(<"$state/qemu.pid")" 2>/dev/null || { echo 'FAIL: QEMU exited during guest boot' >&2; return 1; }
    run_ssh true >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo 'FAIL: verified SSH did not become ready' >&2
  return 1
}

query_kvm() {
  python3 - "$state/qmp.sock" <<'PY'
import json,socket,sys
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
 client.settimeout(10); client.connect(sys.argv[1]); stream=client.makefile('rwb',buffering=0)
 def recv(identifier=None):
  while True:
   line=stream.readline()
   if not line: raise RuntimeError('QMP closed')
   message=json.loads(line)
   if identifier is None or message.get('id')==identifier: return message
 if 'QMP' not in recv(): raise RuntimeError('bad QMP greeting')
 stream.write(b'{"execute":"qmp_capabilities","id":"caps"}\n'); recv('caps')
 stream.write(b'{"execute":"query-kvm","id":"kvm"}\n'); result=recv('kvm').get('return',{})
 if result.get('present') is not True or result.get('enabled') is not True: raise RuntimeError('KVM inactive')
 print(json.dumps(result,sort_keys=True))
PY
}

verify() {
  [[ -f "$sentinel" && ! -L "$sentinel" ]] || { echo 'FAIL: state sentinel missing' >&2; exit 1; }
  [[ -f "$state/qemu.pid" ]] && kill -0 "$(<"$state/qemu.pid")"
  query_kvm >/dev/null
  run_ssh 'test "$(id -u)" = 0'
  run_ssh 'test -d /workspace'
  run_ssh 'test -z "$(ip route show default)"'
  run_ssh 'test "$(cat /sys/class/net/eth0/address)" = 52:54:00:c0:65:01'
  fingerprint=$(ssh-keygen -lf "$state/control/host_ed25519_key.pub" -E sha256 | awk '{print $2}')
  scanned=$(ssh-keyscan -T 5 -t ed25519 "$guest_ip" 2>/dev/null | ssh-keygen -lf - -E sha256 | awk '{print $2}')
  [[ "$fingerprint" == "$scanned" ]] || { echo 'FAIL: guest host-key fingerprint mismatch' >&2; exit 1; }
  host_boot_id=$(cat /proc/sys/kernel/random/boot_id)
  guest_boot_id=$(run_ssh 'cat /proc/sys/kernel/random/boot_id')
  guest_kernel=$(run_ssh 'uname -r')
  [[ -n "$guest_boot_id" && "$guest_boot_id" != "$host_boot_id" && -n "$guest_kernel" ]] || {
    echo 'FAIL: guest boot or kernel identity is invalid' >&2; exit 1;
  }
  printf '{"status":"ready","profile":"linux-kvm","guest_root":true,"kvm_enabled":true,"distinct_boot_ids":true,"guest_kernel":"%s","guest_image_sha512":"%s","host_ip":"%s","guest_ip":"%s","proxy_port":%s}\n' \
    "$guest_kernel" "$image_sha512" "$host_ip" "$guest_ip" "$proxy_port"
}

case "$operation" in
  create)
    [[ ! -e "$state" ]] || { echo 'FAIL: linux-kvm state already exists' >&2; exit 1; }
    mkdir -p "$state"; chmod 0700 "$state"; : > "$sentinel"; chmod 0600 "$sentinel"
    trap 'status=$?; if [[ $status -ne 0 ]]; then cleanup_partial; rm -rf "$state"; fi; exit $status' EXIT
    prepare_image; prepare_keys; prepare_seed; prepare_disks; start_vm; verify
    trap - EXIT
    ;;
  verify) verify ;;
  reset)
    [[ -f "$sentinel" ]] || { echo 'FAIL: state sentinel missing' >&2; exit 1; }
    run_ssh 'printf reset-persistent > /workspace/reset-marker; sync'
    stop_vm; remove_network
    rm -f "$state/root-overlay.qcow2" "$state/seed.img" "$state/user-data" "$state/meta-data" "$state/network-config"
    qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$image_name" "$state/root-overlay.qcow2" 12G
    prepare_seed; start_vm
    run_ssh grep -qx reset-persistent /workspace/reset-marker
    verify
    ;;
  destroy)
    if [[ -e "$state" ]]; then
      [[ -f "$sentinel" && ! -L "$sentinel" ]] || { echo 'FAIL: refusing unowned state' >&2; exit 1; }
      stop_vm; remove_network; rm -rf "$state"
    else
      remove_network
    fi
    [[ ! -e "$state" ]] || { echo 'FAIL: state remained after destroy' >&2; exit 1; }
    printf '{"status":"destroyed","profile":"linux-kvm"}\n'
    ;;
  ssh)
    shift
    run_ssh "$@"
    ;;
  *) echo 'usage: driver.sh {create|verify|reset|destroy|ssh}' >&2; exit 2 ;;
esac

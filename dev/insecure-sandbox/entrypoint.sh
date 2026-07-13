#!/usr/bin/env bash
set -euo pipefail
umask 077

host_key=/run/cogs-input/ssh_host_ed25519_key
host_public=/run/cogs-input/ssh_host_ed25519_key.pub
client_public=/run/cogs-input/client_ed25519_key.pub
public_ca=/run/cogs-input/egress-ca.crt

for required in "$host_key" "$host_public" "$client_public" "$public_ca"; do
  if [[ ! -s "$required" ]]; then
    printf 'insecure-container: required injected material is absent\n' >&2
    exit 1
  fi
done

mkdir -p /workspace /run/sshd /run/cogs-runtime
chmod 0700 /workspace /run/cogs-runtime

install -m 0600 "$host_key" /run/cogs-runtime/ssh_host_ed25519_key
install -m 0644 "$host_public" /run/cogs-runtime/ssh_host_ed25519_key.pub
install -m 0600 "$client_public" /run/cogs-runtime/authorized_keys

ssh-keygen -y -f /run/cogs-runtime/ssh_host_ed25519_key > /run/cogs-runtime/derived_host_key.pub
expected=$(ssh-keygen -l -E sha256 -f /run/cogs-runtime/derived_host_key.pub | awk '{print $2}')
provided=$(ssh-keygen -l -E sha256 -f /run/cogs-runtime/ssh_host_ed25519_key.pub | awk '{print $2}')
rm -f /run/cogs-runtime/derived_host_key.pub
if [[ -z "$expected" || "$expected" != "$provided" ]]; then
  printf 'insecure-container: injected host key pair does not match\n' >&2
  exit 1
fi

if ! ssh-keygen -l -f /run/cogs-runtime/authorized_keys >/dev/null 2>&1; then
  printf 'insecure-container: injected client key is invalid\n' >&2
  exit 1
fi
if ! grep -q -- 'BEGIN CERTIFICATE' "$public_ca"; then
  printf 'insecure-container: injected public CA is invalid\n' >&2
  exit 1
fi

for name in COGS_PROFILE HTTP_PROXY HTTPS_PROXY NO_PROXY SSL_CERT_FILE; do
  value=${!name:-}
  if [[ -z "$value" || ${#value} -gt 2048 || "$value" =~ [[:space:]] ]]; then
    printf 'insecure-container: invalid session environment\n' >&2
    exit 1
  fi
done
cp /etc/ssh/sshd_config /run/cogs-runtime/sshd_config
printf 'SetEnv COGS_PROFILE=%s HTTP_PROXY=%s HTTPS_PROXY=%s NO_PROXY=%s SSL_CERT_FILE=%s\n' \
  "$COGS_PROFILE" "$HTTP_PROXY" "$HTTPS_PROXY" "$NO_PROXY" "$SSL_CERT_FILE" \
  >> /run/cogs-runtime/sshd_config

exec /usr/sbin/sshd -D -e -f /run/cogs-runtime/sshd_config

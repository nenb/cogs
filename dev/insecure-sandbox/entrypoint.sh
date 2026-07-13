#!/usr/bin/env bash
set -euo pipefail
umask 077

host_key=/run/cogs-input/ssh_host_ed25519_key
host_public=/run/cogs-input/ssh_host_ed25519_key.pub
client_public=/run/cogs-input/client_ed25519_key.pub
public_ca=/run/cogs-input/egress-ca.crt
runtime=/run/cogs-runtime

for required in "$host_key" "$host_public" "$client_public" "$public_ca"; do
  if [[ ! -s "$required" ]]; then
    printf 'insecure-container: required injected material is absent\n' >&2
    exit 1
  fi
done

mkdir -p /workspace /run/sshd "$runtime"
chmod 0700 /workspace "$runtime"

install -m 0600 "$host_key" "$runtime/ssh_host_ed25519_key"
install -m 0644 "$host_public" "$runtime/ssh_host_ed25519_key.pub"

host_type=$(awk 'NF {print $1; exit}' "$host_public")
if [[ "$host_type" != ssh-ed25519 ]] || ! ssh-keygen -l -f "$host_key" | grep -Fq '(ED25519)'; then
  printf 'insecure-container: injected host key is not Ed25519\n' >&2
  exit 1
fi
ssh-keygen -y -f "$runtime/ssh_host_ed25519_key" > "$runtime/derived_host_key.pub"
expected=$(ssh-keygen -l -E sha256 -f "$runtime/derived_host_key.pub" | awk '{print $2}')
provided=$(ssh-keygen -l -E sha256 -f "$runtime/ssh_host_ed25519_key.pub" | awk '{print $2}')
rm -f "$runtime/derived_host_key.pub"
if [[ -z "$expected" || "$expected" != "$provided" ]]; then
  printf 'insecure-container: injected host key pair does not match\n' >&2
  exit 1
fi

client_lines=$(awk 'NF {count += 1} END {print count + 0}' "$client_public")
client_type=$(awk 'NF {print $1; exit}' "$client_public")
client_blob=$(awk 'NF {print $2; exit}' "$client_public")
if [[ "$client_lines" != 1 || "$client_type" != ssh-ed25519 || ! "$client_blob" =~ ^[A-Za-z0-9+/]+={0,3}$ ]]; then
  printf 'insecure-container: injected client key must be one plain Ed25519 key\n' >&2
  exit 1
fi
printf 'restrict %s %s\n' "$client_type" "$client_blob" > "$runtime/authorized_keys"
chmod 0600 "$runtime/authorized_keys"
if ! ssh-keygen -l -f "$runtime/authorized_keys" | grep -Fq '(ED25519)'; then
  printf 'insecure-container: injected client key is invalid\n' >&2
  exit 1
fi

if grep -Eq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$public_ca" \
    || ! openssl x509 -in "$public_ca" -out "$runtime/egress-ca.crt"; then
  printf 'insecure-container: injected public CA is invalid\n' >&2
  exit 1
fi
chmod 0644 "$runtime/egress-ca.crt"

if [[ "${COGS_PROFILE:-}" != insecure-container ]]; then
  printf 'insecure-container: invalid profile identifier\n' >&2
  exit 1
fi
for name in HTTP_PROXY HTTPS_PROXY NO_PROXY; do
  value=${!name:-}
  if [[ -z "$value" || ${#value} -gt 2048 || ! "$value" =~ ^[A-Za-z0-9._:/,-]+$ ]]; then
    printf 'insecure-container: invalid session environment\n' >&2
    exit 1
  fi
done

cp /etc/ssh/sshd_config "$runtime/sshd_config"
printf 'SetEnv COGS_PROFILE=insecure-container HTTP_PROXY=%s HTTPS_PROXY=%s NO_PROXY=%s SSL_CERT_FILE=%s\n' \
  "$HTTP_PROXY" "$HTTPS_PROXY" "$NO_PROXY" "$runtime/egress-ca.crt" \
  >> "$runtime/sshd_config"

/usr/sbin/sshd -t -f "$runtime/sshd_config"
exec /usr/sbin/sshd -D -e -f "$runtime/sshd_config"

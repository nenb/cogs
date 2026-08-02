#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

readonly INPUT_ROOT=/run/cogs-input
readonly RUNTIME_ROOT=/run/cogs-runtime
readonly HOST_KEY="$INPUT_ROOT/ssh_host_ed25519_key"
readonly HOST_PUBLIC="$INPUT_ROOT/ssh_host_ed25519_key.pub"
readonly CLIENT_PUBLIC="$INPUT_ROOT/client_ed25519_key.pub"
readonly PUBLIC_CA="$INPUT_ROOT/egress-ca.crt"
readonly PROXY_CAPABILITY="$INPUT_ROOT/proxy-capability"
readonly TRUST_FILE="$RUNTIME_ROOT/egress-ca.crt"

fail() {
  printf '%s\n' 'cogs-sandbox: required runtime input unavailable' >&2
  exit 1
}

# Prints a stable identity only for a direct, root-owned, single-link regular file.
# Callers compare the result before and after every bounded read/copy.
regular_file_identity() {
  local path=$1 expected_mode=$2 minimum=$3 maximum=$4 identity size
  [[ ( "$path" == "$INPUT_ROOT/"* || "$path" == /etc/ssh/sshd_config ) && ! -L "$path" && -f "$path" ]] || return 1
  [[ "$(realpath -e -- "$path" 2>/dev/null)" == "$path" ]] || return 1
  identity=$(stat -c '%d:%i:%s:%u:%g:%a:%h:%F' -- "$path" 2>/dev/null) || return 1
  size=$(stat -c '%s' -- "$path" 2>/dev/null) || return 1
  [[ "$identity" == *":0:0:${expected_mode}:1:regular file" ]] || return 1
  [[ "$size" =~ ^[0-9]+$ && "$size" -ge "$minimum" && "$size" -le "$maximum" ]] || return 1
  printf '%s' "$identity"
}

exact_directory() {
  local path=$1 expected_mode=$2 identity
  [[ ! -L "$path" && -d "$path" ]] || return 1
  [[ "$(realpath -e -- "$path" 2>/dev/null)" == "$path" ]] || return 1
  identity=$(stat -c '%u:%g:%a:%F' -- "$path" 2>/dev/null) || return 1
  [[ "$identity" == "0:0:${expected_mode}:directory" ]]
}

read_only_path() {
  local path=$1 options
  options=$(findmnt --noheadings --output VFS-OPTIONS --target "$path" 2>/dev/null) || return 1
  [[ ",${options//[[:space:]]/}," == *,ro,* ]]
}

validate_capability() {
  local value=$1
  [[ ${#value} -ge 32 && ${#value} -le 128 && "$value" =~ ^[A-Za-z0-9_-]+$ ]]
}

# Accept only a canonical literal HTTP IPv4/IPv6 endpoint. Hostnames, userinfo,
# paths, queries, fragments, implicit ports, and non-canonical literals fail.
validate_proxy_endpoint() {
  local endpoint=$1
  python3 -I -c '
import ipaddress
import sys
from urllib.parse import urlsplit
try:
    raw = sys.argv[1]
    parsed = urlsplit(raw)
    if parsed.scheme != "http" or parsed.username is not None or parsed.password is not None:
        raise ValueError
    if parsed.path or parsed.query or parsed.fragment or parsed.hostname is None or parsed.port is None:
        raise ValueError
    address = ipaddress.ip_address(parsed.hostname)
    if not 1 <= parsed.port <= 65535:
        raise ValueError
    authority = f"[{address.compressed}]:{parsed.port}" if address.version == 6 else f"{address.compressed}:{parsed.port}"
    canonical = f"http://{authority}"
    if raw != canonical:
        raise ValueError
    print(canonical, end="")
except (ValueError, IndexError):
    raise SystemExit(1)
' "$endpoint" 2>/dev/null
}

reject_ambient_credentials() {
  local name
  for name in \
    AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_WEB_IDENTITY_TOKEN_FILE \
    GOOGLE_APPLICATION_CREDENTIALS GOOGLE_OAUTH_ACCESS_TOKEN \
    AZURE_CLIENT_SECRET AZURE_CLIENT_CERTIFICATE_PATH \
    VAULT_TOKEN VAULT_TOKEN_FILE BAO_TOKEN BAO_TOKEN_FILE OPENBAO_TOKEN OPENBAO_TOKEN_FILE \
    KUBERNETES_SERVICE_ACCOUNT_TOKEN; do
    [[ ${!name+x} != x ]] || return 1
  done
  for path in \
    /var/run/secrets/kubernetes.io/serviceaccount \
    /run/secrets/kubernetes.io/serviceaccount \
    /var/run/secrets/eks.amazonaws.com/serviceaccount; do
    [[ ! -e "$path" && ! -L "$path" ]] || return 1
  done
}

prepare_runtime_directories() {
  exact_directory "$INPUT_ROOT" 500 || fail
  read_only_path "$INPUT_ROOT" || fail
  exact_directory /workspace 700 || fail
  exact_directory /shared/skills 555 || fail
  read_only_path /shared/skills || fail
  exact_directory /user/skills 555 || fail
  read_only_path /user/skills || fail

  exact_directory "$RUNTIME_ROOT" 700 || fail
  if find "$RUNTIME_ROOT" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | grep -q .; then
    fail
  fi
  exact_directory /run/sshd 755 || fail
}

capture_regular_file() {
  local source=$1 destination=$2 source_mode=$3 destination_mode=$4 minimum=$5 maximum=$6 before after
  before=$(regular_file_identity "$source" "$source_mode" "$minimum" "$maximum") || fail
  install -o root -g root -m "$destination_mode" -- "$source" "$destination" 2>/dev/null || fail
  after=$(regular_file_identity "$source" "$source_mode" "$minimum" "$maximum") || fail
  [[ "$before" == "$after" ]] || fail
}

install_ssh_identity() {
  local private="$RUNTIME_ROOT/ssh_host_ed25519_key"
  local public="$RUNTIME_ROOT/ssh_host_ed25519_key.pub"
  local derived provided client_type client_blob client_fields client_lines

  capture_regular_file "$HOST_KEY" 400 "$private" 600 64 16384
  capture_regular_file "$HOST_PUBLIC" 444 "$public" 644 80 1024

  client_lines=$(awk 'END { print NR }' "$public" 2>/dev/null) || fail
  client_fields=$(awk 'NR == 1 { print NF }' "$public" 2>/dev/null) || fail
  provided=$(awk 'NR == 1 { print $1 " " $2 }' "$public" 2>/dev/null) || fail
  [[ "$client_lines" == 1 && ( "$client_fields" == 2 || "$client_fields" == 3 ) && "$provided" == ssh-ed25519\ * ]] || fail
  derived=$(ssh-keygen -y -f "$private" 2>/dev/null) || fail
  [[ "$derived" == "$provided" ]] || fail
  ssh-keygen -l -E sha256 -f "$private" 2>/dev/null | grep -Fq '(ED25519)' || fail

  local before after
  before=$(regular_file_identity "$CLIENT_PUBLIC" 444 80 1024) || fail
  client_lines=$(awk 'END { print NR }' "$CLIENT_PUBLIC" 2>/dev/null) || fail
  client_fields=$(awk 'NR == 1 { print NF }' "$CLIENT_PUBLIC" 2>/dev/null) || fail
  client_type=$(awk 'NR == 1 { print $1 }' "$CLIENT_PUBLIC" 2>/dev/null) || fail
  client_blob=$(awk 'NR == 1 { print $2 }' "$CLIENT_PUBLIC" 2>/dev/null) || fail
  after=$(regular_file_identity "$CLIENT_PUBLIC" 444 80 1024) || fail
  [[ "$before" == "$after" && "$client_lines" == 1 && ( "$client_fields" == 2 || "$client_fields" == 3 ) ]] || fail
  [[ "$client_type" == ssh-ed25519 && "$client_blob" =~ ^[A-Za-z0-9+/]+={0,3}$ ]] || fail
  printf 'restrict %s %s\n' "$client_type" "$client_blob" > "$RUNTIME_ROOT/authorized_keys"
  chmod 0600 "$RUNTIME_ROOT/authorized_keys"
  ssh-keygen -l -E sha256 -f "$RUNTIME_ROOT/authorized_keys" 2>/dev/null | grep -Fq '(ED25519)' || fail
}

install_public_ca() {
  local before after
  before=$(regular_file_identity "$PUBLIC_CA" 444 256 65536) || fail
  grep -Eq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$PUBLIC_CA" 2>/dev/null && fail
  awk '
    NR == 1 && $0 != "-----BEGIN CERTIFICATE-----" { exit 1 }
    $0 == "-----BEGIN CERTIFICATE-----" { begins += 1; next }
    $0 == "-----END CERTIFICATE-----" { ends += 1; ended = 1; next }
    ended || $0 !~ /^[A-Za-z0-9+\/=]+$/ { exit 1 }
    END { if (begins != 1 || ends != 1) exit 1 }
  ' "$PUBLIC_CA" 2>/dev/null || fail
  openssl x509 -in "$PUBLIC_CA" -noout -checkend 0 >/dev/null 2>&1 || fail
  openssl x509 -in "$PUBLIC_CA" -noout -text 2>/dev/null | grep -Fq 'CA:TRUE' || fail
  openssl verify -CAfile "$PUBLIC_CA" "$PUBLIC_CA" >/dev/null 2>&1 || fail
  openssl x509 -in "$PUBLIC_CA" -out "$TRUST_FILE" 2>/dev/null || fail
  chmod 0644 "$TRUST_FILE"
  after=$(regular_file_identity "$PUBLIC_CA" 444 256 65536) || fail
  [[ "$before" == "$after" ]] || fail
}

read_proxy_capability() {
  local before after size value
  before=$(regular_file_identity "$PROXY_CAPABILITY" 400 32 128) || fail
  size=$(stat -c '%s' -- "$PROXY_CAPABILITY" 2>/dev/null) || fail
  IFS= read -r value < "$PROXY_CAPABILITY" || [[ -n "$value" ]] || fail
  after=$(regular_file_identity "$PROXY_CAPABILITY" 400 32 128) || fail
  [[ "$before" == "$after" && ${#value} -eq "$size" ]] || fail
  validate_capability "$value" || fail
  printf '%s' "$value"
}

write_sshd_environment() {
  local proxy_url=$1 trust=$TRUST_FILE config="$RUNTIME_ROOT/sshd_config"
  capture_regular_file /etc/ssh/sshd_config 644 "$config" 600 256 16384
  {
    printf 'SetEnv COGS_PROFILE=kata-sandbox-guest\n'
    printf 'SetEnv HTTP_PROXY=%s HTTPS_PROXY=%s ALL_PROXY=%s\n' "$proxy_url" "$proxy_url" "$proxy_url"
    printf 'SetEnv http_proxy=%s https_proxy=%s all_proxy=%s\n' "$proxy_url" "$proxy_url" "$proxy_url"
    printf 'SetEnv NO_PROXY=127.0.0.1,localhost,::1 no_proxy=127.0.0.1,localhost,::1\n'
    printf 'SetEnv SSL_CERT_FILE=%s REQUESTS_CA_BUNDLE=%s CURL_CA_BUNDLE=%s NODE_EXTRA_CA_CERTS=%s\n' "$trust" "$trust" "$trust" "$trust"
    printf 'SetEnv AWS_CA_BUNDLE=%s GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=%s GIT_SSL_CAINFO=%s PIP_CERT=%s\n' "$trust" "$trust" "$trust" "$trust"
    printf 'SetEnv ssl_cert_file=%s requests_ca_bundle=%s curl_ca_bundle=%s node_extra_ca_certs=%s\n' "$trust" "$trust" "$trust" "$trust"
    printf 'SetEnv aws_ca_bundle=%s grpc_default_ssl_roots_file_path=%s git_ssl_cainfo=%s pip_cert=%s\n' "$trust" "$trust" "$trust" "$trust"
  } >> "$config"
  chmod 0600 "$config"
}

main() {
  local capability endpoint proxy_url
  reject_ambient_credentials || fail
  prepare_runtime_directories
  install_ssh_identity
  install_public_ca
  capability=$(read_proxy_capability)
  endpoint=$(validate_proxy_endpoint "${COGS_PROXY_ENDPOINT:-}") || fail
  proxy_url="http://cogs:${capability}@${endpoint#http://}"
  write_sshd_environment "$proxy_url"

  unset capability proxy_url COGS_PROXY_ENDPOINT
  /usr/sbin/sshd -t -f "$RUNTIME_ROOT/sshd_config" >/dev/null 2>&1 || fail
  exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
    /usr/sbin/sshd -D -e -f "$RUNTIME_ROOT/sshd_config"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi

#!/usr/bin/env bash
set -Eeuo pipefail
PATH=/usr/bin:/bin
export PATH
umask 077

fail() {
  printf 'stage2-cosign-keyless-sign: owner.failed\n' >&2
  exit 2
}

[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || fail
out_input="$1"
identity="$2"
payload_base="${3:-approval-authentication}"
readonly image='ghcr.io/sigstore/cosign/cosign@sha256:be924970ba7438c22e18067dec5637946d6566eac711f5bedd1584e7137008fb'
readonly expected_binary_sha256='5db1043ec70bf92296da977941b19b3d86869af3018d4f4a0f457bf54d76bb68'
readonly issuer='https://token.actions.githubusercontent.com'

case "$identity" in
  'https://github.com/nenb/cogs/.github/workflows/stage2-production-approval.yml@refs/heads/main' | \
    'https://github.com/nenb/cogs/.github/workflows/stage2-production-approval-signing-diagnostic.yml@refs/heads/main' | \
    'https://github.com/nenb/cogs/.github/workflows/stage2-r-diagnostic-preparation.yml@refs/heads/main' | \
    'https://github.com/nenb/cogs/.github/workflows/stage2-r-diagnostic-preparation.yml@refs/heads/fix/issue42-r-convergence')
      [ "$payload_base" = approval-authentication ] || fail ;;
  'https://github.com/nenb/cogs/.github/workflows/stage2-production-campaign.yml@refs/heads/main' | \
    'https://github.com/nenb/cogs/.github/workflows/stage2-r-diagnostic-campaign.yml@refs/heads/fix/issue42-r-convergence')
      [ "$payload_base" = aws-stage2-production-continuation-v1 ] || fail ;;
  *) fail ;;
esac

for command in /usr/bin/chmod /usr/bin/cut /usr/bin/docker /usr/bin/find /usr/bin/id \
  /usr/bin/install /usr/bin/mktemp /usr/bin/realpath /usr/bin/sha256sum /usr/bin/stat; do
  [ -x "$command" ] || fail
done
[ -n "${RUNNER_TEMP:-}" ] || fail
[ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] || fail
[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || fail
runner_temp="$(realpath -- "$RUNNER_TEMP")"
[ ! -L "$out_input" ] || fail
out="$(realpath -- "$out_input")"
case "$out" in "$runner_temp"/*) ;; *) fail ;; esac

runner_uid="$(id -u)"
runner_gid="$(id -g)"
[[ "$runner_uid" =~ ^[1-9][0-9]*$ ]] || fail
[[ "$runner_gid" =~ ^[1-9][0-9]*$ ]] || fail
[ "$(stat -c '%F:%u:%g:%a' -- "$out")" = "directory:$runner_uid:$runner_gid:700" ] || fail

if [ "$payload_base" = approval-authentication ]; then
  payload="$out/approval-authentication.json"
  bundle="$out/approval-authentication.bundle.json"
  payload_maximum=65536
else
  payload="$out/aws-stage2-production-continuation-v1.json"
  bundle="$out/aws-stage2-production-continuation-v1.bundle.json"
  payload_maximum=4194304
fi
[ -f "$payload" ] && [ ! -L "$payload" ] || fail
[ "$(stat -c '%F:%u:%g:%h' -- "$payload")" = \
  "regular file:$runner_uid:$runner_gid:1" ] || fail
payload_size="$(stat -c '%s' -- "$payload")"
[ "$payload_size" -gt 0 ] && [ "$payload_size" -le "$payload_maximum" ] || fail
chmod 0600 "$payload"

trusted_root_source='config/stage2-sigstore-trusted-root-v1.json'
[ -f "$trusted_root_source" ] && [ ! -L "$trusted_root_source" ] || fail
[ "$(stat -c '%F:%h' -- "$trusted_root_source")" = 'regular file:1' ] || fail
trusted_root="$out/sigstore-trusted-root.json"
binary="$out/cosign"
[ ! -e "$trusted_root" ] && [ ! -e "$bundle" ] && [ ! -e "$binary" ] || fail
install -m 0400 "$trusted_root_source" "$trusted_root"

sign_home="$(mktemp -d "$runner_temp/cogs-cosign-sign-home.XXXXXX")"
verify_home="$(mktemp -d "$runner_temp/cogs-cosign-verify-home.XXXXXX")"
[ "$(stat -c '%F:%u:%g:%a' -- "$sign_home")" = "directory:$runner_uid:$runner_gid:700" ] || fail
[ "$(stat -c '%F:%u:%g:%a' -- "$verify_home")" = "directory:$runner_uid:$runner_gid:700" ] || fail

common=(
  --rm
  --user "$runner_uid:$runner_gid"
  --cap-drop ALL
  --security-opt no-new-privileges
  --read-only
  --tmpfs "/tmp:rw,nosuid,nodev,noexec,uid=$runner_uid,gid=$runner_gid,mode=0700"
)

docker run "${common[@]}" --network host \
  -e HOME=/cosign-home \
  -e COSIGN_EXPERIMENTAL=1 \
  -e ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  -e ACTIONS_ID_TOKEN_REQUEST_URL \
  -v "$sign_home:/cosign-home" \
  -v "$out:/work" -w /work \
  "$image" sign-blob --yes --timeout 180s --oidc-provider github-actions \
  --bundle "$payload_base.bundle.json" "$payload_base.json" >/dev/null

[ -f "$bundle" ] && [ ! -L "$bundle" ] || fail
[ "$(stat -c '%F:%u:%g:%h' -- "$bundle")" = \
  "regular file:$runner_uid:$runner_gid:1" ] || fail
bundle_size="$(stat -c '%s' -- "$bundle")"
[ "$bundle_size" -gt 0 ] && [ "$bundle_size" -le 1048576 ] || fail
chmod 0600 "$bundle"
[ -d "$sign_home/.sigstore/root" ] || fail
[ -n "$(find "$sign_home/.sigstore/root" -type f -print -quit)" ] || fail

# A fresh empty home plus a network-disabled container proves verification uses
# only the committed trusted root and the signed bundle, never ambient TUF state.
[ -z "$(find "$verify_home" -mindepth 1 -print -quit)" ] || fail
docker run "${common[@]}" --network none \
  -e HOME=/cosign-home \
  -v "$verify_home:/cosign-home" \
  -v "$out:/work:ro" -w /work \
  "$image" verify-blob --timeout 180s \
  --trusted-root sigstore-trusted-root.json \
  --bundle "$payload_base.bundle.json" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  "$payload_base.json" >/dev/null

container="$(docker create --network none "$image")"
[ -n "$container" ] || fail
cleanup_container() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup_container EXIT
docker cp "$container:/ko-app/cosign" "$binary"
[ -f "$binary" ] && [ ! -L "$binary" ] || fail
[ "$(stat -c '%F:%h' -- "$binary")" = 'regular file:1' ] || fail
[ "$(sha256sum "$binary" | cut -d' ' -f1)" = "$expected_binary_sha256" ] || fail
chmod 0555 "$binary"
chmod 0444 "$trusted_root"

printf 'COSIGN-KEYLESS-SIGN-AND-OFFLINE-VERIFY=PASS\n'

#!/usr/bin/env bash
set -euo pipefail

version=1.12.4
os=$(uname -s | tr '[:upper:]' '[:lower:]')
architecture=$(uname -m)
case "$architecture" in
  x86_64) architecture=amd64 ;;
  arm64|aarch64) architecture=arm64 ;;
  *) printf 'unsupported OpenTofu architecture: %s\n' "$architecture" >&2; exit 1 ;;
esac
case "$os/$architecture" in
  darwin/amd64) expected=ff4d49559157697b4e3651868aead7ce0e85744242e1b60679f29d6ddc777a45 ;;
  darwin/arm64) expected=e5e8db9c2dd2c657a8b46931e41cd8dd1d89e5a30aebd742f4f8eafcf1815a35 ;;
  linux/amd64) expected=f5d2ae8a0efcddd3722546b3e0f2f2f0648ce5e5a3e411176041adcb7dccc1e8 ;;
  linux/arm64) expected=a3b01db857c7c650768ffa8ad9119dc2db82fe1b98125b7238392a160aca7f8a ;;
  *) printf 'unsupported OpenTofu platform: %s/%s\n' "$os" "$architecture" >&2; exit 1 ;;
esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
destination=${COGS_TOFU_BIN:-"$root/.tools/tofu-$version/tofu"}
if [[ -x "$destination" ]] && [[ $("$destination" version -json | python3 -c 'import json,sys; print(json.load(sys.stdin)["terraform_version"])') == "$version" ]]; then
  printf '%s\n' "$destination"
  exit 0
fi

mkdir -p "$(dirname "$destination")"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
archive="$temporary/tofu.zip"
url="https://github.com/opentofu/opentofu/releases/download/v$version/tofu_${version}_${os}_${architecture}.zip"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$url" --output "$archive"
actual=$(shasum -a 256 "$archive" | awk '{print $1}')
if [[ "$actual" != "$expected" ]]; then
  printf 'OpenTofu archive digest mismatch\n' >&2
  exit 1
fi
unzip -q "$archive" tofu -d "$temporary"
install -m 0755 "$temporary/tofu" "$destination"
printf '%s\n' "$destination"

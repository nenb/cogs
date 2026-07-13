#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
out=${1:-"$root/dist"}
goos=${GOOS:-linux}
goarch=${GOARCH:-amd64}
name="cogs-net-probe-${goos}-${goarch}"
mkdir -p "$out"
out=$(cd "$out" && pwd)

(
  cd "$root"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build \
    -trimpath \
    -buildvcs=false \
    -ldflags='-s -w -buildid=' \
    -o "$out/$name" \
    ./cmd/cogs-net-probe
)

hash=$(openssl dgst -sha256 "$out/$name" | awk '{print $NF}')
printf '%s  %s\n' "$hash" "$name" > "$out/$name.sha256"
printf '%s\n' "$hash"

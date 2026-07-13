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
  CGO_ENABLED=0 \
    GOENV=off \
    GOEXPERIMENT=none \
    GOFLAGS=-mod=readonly \
    GONOSUMDB='*' \
    GOPROXY=off \
    GOTOOLCHAIN=local \
    GOOS="$goos" \
    GOARCH="$goarch" \
    GOAMD64=${GOAMD64:-v1} \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags='-s -w -buildid=' \
      -o "$out/$name" \
      ./cmd/cogs-net-probe
)

hash=$(openssl dgst -sha256 "$out/$name" | awk '{print $NF}')
revision=$(git -C "$root" rev-parse HEAD)
go_version=$(GOTOOLCHAIN=local go version | awk '{print $3}')
printf '%s  %s\n' "$hash" "$name" > "$out/$name.sha256"
printf '{"version":"cogs.guest-probe-build/v1alpha1","source_revision":"%s","go_version":"%s","goos":"%s","goarch":"%s","goamd64":"%s","sha256":"%s"}\n' \
  "$revision" "$go_version" "$goos" "$goarch" "${GOAMD64:-v1}" "$hash" > "$out/$name.build.json"
printf '%s\n' "$hash"

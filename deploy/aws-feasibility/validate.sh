#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
tofu=$($root/scripts/install-opentofu.sh)
"$tofu" -chdir="$root/deploy/aws-feasibility" fmt -check -diff
temporary=$(mktemp -d)
cache="$root/.tools/tofu-plugin-cache"
mkdir -p "$cache"
trap 'rm -rf "$temporary"' EXIT
TF_PLUGIN_CACHE_DIR="$cache" TF_DATA_DIR="$temporary" "$tofu" -chdir="$root/deploy/aws-feasibility" init -backend=false -input=false
TF_PLUGIN_CACHE_DIR="$cache" TF_DATA_DIR="$temporary" "$tofu" -chdir="$root/deploy/aws-feasibility" validate

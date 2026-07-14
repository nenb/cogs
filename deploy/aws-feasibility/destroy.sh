#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
directory="$root/deploy/aws-feasibility"
tofu=$($root/scripts/install-opentofu.sh)
: "${AWS_PROFILE:=nebula}"
export AWS_PROFILE AWS_REGION=us-east-1
[[ -f "$directory/.state/terraform.tfstate" ]] || { printf 'local campaign state is missing; use inventory and targeted recovery, not an unbound destroy\n' >&2; exit 1; }
"$tofu" -chdir="$directory" destroy -auto-approve -input=false -lock-timeout=30s
for attempt in $(seq 1 30); do
  if "$directory/inventory.sh" >"$directory/.state/zero-resource-inventory.json"; then
    cat "$directory/.state/zero-resource-inventory.json"
    exit 0
  fi
  (( attempt < 30 )) && sleep 10
done
printf 'zero-resource inventory did not converge within five minutes\n' >&2
exit 1

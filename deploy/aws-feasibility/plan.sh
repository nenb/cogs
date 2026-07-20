#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
directory="$root/deploy/aws-feasibility"
tofu=$("$root/scripts/install-opentofu.sh")
: "${COGS_AWS_BUDGET_EMAIL:?set COGS_AWS_BUDGET_EMAIL to the owner budget-alert address}"
[[ $(git -C "$root" status --porcelain) == "" ]] || { printf 'refusing to plan from a dirty tree\n' >&2; exit 1; }
revision=$(git -C "$root" rev-parse HEAD)
expiry=$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone
print((datetime.now(timezone.utc) + timedelta(hours=4)).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
PY
)
mkdir -p "$directory/.state"
chmod 700 "$directory/.state"
variables="$directory/.state/campaign.auto.tfvars.json"
python3 - "$variables" "$revision" "$expiry" "$COGS_AWS_BUDGET_EMAIL" <<'PY'
import json, os, sys
path, revision, expiry, email = sys.argv[1:]
with open(path, 'w', encoding='utf-8') as output:
    json.dump({'source_revision': revision, 'expires_at': expiry, 'budget_alert_email': email}, output)
    output.write('\n')
os.chmod(path, 0o600)
PY
unset COGS_AWS_BUDGET_EMAIL
"$tofu" -chdir="$directory" init -input=false -reconfigure
"$tofu" -chdir="$directory" plan -input=false -lock-timeout=30s -var-file=.state/campaign.auto.tfvars.json -out=.state/campaign.tfplan
"$tofu" -chdir="$directory" show -json .state/campaign.tfplan >"$directory/.state/campaign.plan.json"
python3 "$directory/check-plan.py" "$directory/.state/campaign.plan.json"
"$tofu" -chdir="$directory" show -no-color .state/campaign.tfplan >"$directory/.state/campaign.plan.txt"
shasum -a 256 "$directory/.state/campaign.tfplan" | awk '{print $1}' >"$directory/.state/campaign.tfplan.sha256"
printf 'Saved checked plan for %s, expiry %s, digest %s\n' "$revision" "$expiry" "$(cat "$directory/.state/campaign.tfplan.sha256")"
printf 'Expected normal cost <USD 0.25; four-hour TTL estimate <USD 0.50. No resources were created.\n'

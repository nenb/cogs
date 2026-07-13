#!/usr/bin/env bash
set -uo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
report=${1:-"$repo/docs/security-evidence/generated/insecure-container-smoke.json"}
driver="$repo/dev/insecure-sandbox/driver.sh"
started=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
started_ms=$(date +%s%3N)
status=0
diagnostic='SSH/SFTP, injected host-key pin, root, workspace, CA, and proxy-variable controls passed.'

"$driver" create || { status=1; diagnostic='insecure-container create failed'; }
if (( status == 0 )); then
  "$driver" verify || { status=1; diagnostic='insecure-container SSH/SFTP verification failed'; }
fi
"$driver" destroy || { status=1; diagnostic='insecure-container teardown verification failed'; }

completed=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
completed_ms=$(date +%s%3N)
image_id=$(docker image inspect --format '{{.Id}}' "${COGS_INSECURE_IMAGE:-cogs-insecure-sandbox:dev}" 2>/dev/null || true)
docker_version=$(docker version --format '{{.Server.Version}}' 2>/dev/null || printf unavailable)
mkdir -p "$(dirname "$report")"

STATUS=$status \
DIAGNOSTIC=$diagnostic \
STARTED=$started \
COMPLETED=$completed \
DURATION_MS=$((completed_ms - started_ms)) \
IMAGE_ID=$image_id \
DOCKER_VERSION=$docker_version \
REPORT_ID="insecure-container-${GITHUB_RUN_ID:-local}" \
SOURCE_REVISION="${COGS_SOURCE_REVISION:-$(git -C "$repo" rev-parse HEAD)}" \
python3 - "$report" <<'PY'
import json
import os
import platform
import sys

status = int(os.environ["STATUS"])
image = os.environ["IMAGE_ID"]
component = {"name": "insecure-sandbox", "version": "stage1"}
if image.startswith("sha256:") and len(image) == 71:
    component["image_digest"] = image
report = {
    "version": "cogs.security-report/v1alpha1",
    "report_id": os.environ["REPORT_ID"],
    "source_revision": os.environ["SOURCE_REVISION"],
    "profile": "insecure-container",
    "authority": "functional-only",
    "started_at": os.environ["STARTED"],
    "completed_at": os.environ["COMPLETED"],
    "duration_ms": int(os.environ["DURATION_MS"]),
    "environment": {
        "os": "linux",
        "architecture": platform.machine(),
        "runner": f"GitHub Actions {os.environ.get('RUNNER_NAME', 'local')}",
        "runner_image": os.environ.get("ImageOS", "local"),
        "runtime_versions": {"docker": os.environ["DOCKER_VERSION"]},
        "metadata": {"guest_root": status == 0, "isolation_claim": False},
    },
    "components": [component],
    "dependencies": {
        name: {"mode": "not-applicable", "implementation": "Stage 1 driver smoke only"}
        for name in ["authorization", "audit", "revocation", "identity", "network_enforcement"]
    },
    "tests": [{
        "id": "driver.ssh-sftp-contract",
        "group": "driver-smoke",
        "result": "pass" if status == 0 else "fail",
        "release_eligible": False,
        "duration_ms": int(os.environ["DURATION_MS"]),
        "dependency_modes": {},
        "diagnostics_redacted": os.environ["DIAGNOSTIC"],
    }],
    "known_limitations": [
        "Plain containers provide no VM isolation or authoritative guest-root default-deny claim.",
        "Proxy behavior is not tested until the first Stage 1 candidate adapter exists.",
    ],
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

exit "$status"

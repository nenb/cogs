#!/usr/bin/env bash
set -euo pipefail
# Fixed zero-argument AWS entry. The authenticated root-staged admission capability,
# never a caller-selected segment string, is the only phase-two selector.
[ "$#" -eq 0 ] || exit 64
for forbidden in COGS_STAGE2_CAMPAIGN_SEGMENT COGS_STAGE2_CONTINUATION_SHA256; do
  [ -z "${!forbidden:-}" ] || exit 64
done

clean=(HOME=/root LANG=C LC_ALL=C PATH=/usr/local/bin:/usr/bin:/bin TZ=UTC)
admission=/var/lib/cogs/stage2-aws-production-v2/aws-stage2-production-continuation-admission-v1.json
diagnostic=${COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC:-}
split=${COGS_STAGE2_SPLIT_CONVERGENCE:-}
if [ "$diagnostic" = 1 ]; then
  clean+=(COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC=1)
  if [ "$split" = 1 ]; then
    [[ "${COGS_STAGE2_DIAGNOSTIC_REF:-}" =~ ^refs/heads/[A-Za-z0-9._/-]+$ ]] || exit 64
    clean+=(COGS_STAGE2_SPLIT_CONVERGENCE=1
      "COGS_STAGE2_DIAGNOSTIC_REF=$COGS_STAGE2_DIAGNOSTIC_REF")
  else
    [ -z "$split" ] && [ ! -e "$admission" ] || exit 64
  fi
else
  [ -z "$diagnostic" ] && [ -z "$split" ] &&
    [ -z "${COGS_STAGE2_DIAGNOSTIC_REF:-}" ] || exit 64
fi
if [ "$diagnostic" = 1 ] && [ -z "$split" ]; then
  :
elif [ -e "$admission" ]; then
  # Phase two receives no ambient run selectors; all provenance is in admission.
  :
else
  [[ "${COGS_STAGE2_WORKFLOW_REVISION:-}" =~ ^[0-9a-f]{40}$ ]] || exit 64
  for name in COGS_STAGE2_GITHUB_RUN_ID COGS_STAGE2_PRODUCER_JOB_ID \
      COGS_STAGE2_APPROVAL_ARTIFACT_RUN_ID COGS_STAGE2_APPROVAL_ARTIFACT_ID; do
    value=${!name:-}
    [[ "$value" =~ ^[1-9][0-9]*$ ]] || exit 64
    clean+=("$name=$value")
  done
  [[ "${COGS_STAGE2_APPROVAL_ARTIFACT_DIGEST:-}" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 64
  [[ "${COGS_STAGE2_APPROVAL_ARTIFACT_NAME:-}" =~ ^stage2-production-approval-[0-9a-f]{40}-[1-9][0-9]*$ ]] || exit 64
  clean+=(
    "COGS_STAGE2_WORKFLOW_REVISION=$COGS_STAGE2_WORKFLOW_REVISION"
    "COGS_STAGE2_APPROVAL_ARTIFACT_DIGEST=$COGS_STAGE2_APPROVAL_ARTIFACT_DIGEST"
    "COGS_STAGE2_APPROVAL_ARTIFACT_NAME=$COGS_STAGE2_APPROVAL_ARTIFACT_NAME"
  )
fi
cd /var/lib/cogs/stage2-completion-v1/source
exec /usr/bin/env -i "${clean[@]}" /usr/bin/python3 -I -B \
  /var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/completion_campaign_aws_entry.py

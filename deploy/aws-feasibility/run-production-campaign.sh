#!/usr/bin/env bash
set -euo pipefail
# Fixed zero-argument split AWS entry. Never used by non-AWS qualification.
[ "$#" -eq 0 ] || exit 64
case "${COGS_STAGE2_GITHUB_RUN_ID:-}" in ''|*[!0-9]*) exit 64 ;; esac
[ "${COGS_STAGE2_GITHUB_RUN_ATTEMPT:-}" = 1 ] || exit 64

clean=(
  HOME=/root LANG=C LC_ALL=C PATH=/usr/local/bin:/usr/bin:/bin TZ=UTC
  COGS_STAGE2_CAMPAIGN_SEGMENT="${COGS_STAGE2_CAMPAIGN_SEGMENT:-}"
  COGS_STAGE2_GITHUB_RUN_ID="$COGS_STAGE2_GITHUB_RUN_ID"
  COGS_STAGE2_GITHUB_RUN_ATTEMPT="$COGS_STAGE2_GITHUB_RUN_ATTEMPT"
)
case "${COGS_STAGE2_CAMPAIGN_SEGMENT:-}" in
  cycles-1-3)
    [ -z "${COGS_STAGE2_CONTINUATION_SHA256:-}" ] || exit 64
    [ -z "${COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC:-}" ] || exit 64
    ;;
  cycles-4-7)
    [[ "${COGS_STAGE2_CONTINUATION_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || exit 64
    [ -z "${COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC:-}" ] || exit 64
    clean+=(COGS_STAGE2_CONTINUATION_SHA256="$COGS_STAGE2_CONTINUATION_SHA256")
    ;;
  diagnostic)
    [ "${COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC:-}" = 1 ] || exit 64
    [ -z "${COGS_STAGE2_CONTINUATION_SHA256:-}" ] || exit 64
    clean+=(COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC=1)
    ;;
  *) exit 64 ;;
esac
cd /var/lib/cogs/stage2-completion-v1/source
exec /usr/bin/env -i "${clean[@]}" /usr/bin/python3 -I -B \
  /var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/completion_campaign_aws_entry.py

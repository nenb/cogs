#!/usr/bin/env bash
set -euo pipefail
# Sole zero-argument cleanup-only crash entry; it cannot resume or mint success.
[ "$#" -eq 0 ] || exit 64
clean=(HOME=/root LANG=C LC_ALL=C PATH=/usr/local/bin:/usr/bin:/bin TZ=UTC)
diagnostic=${COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC:-}
split=${COGS_STAGE2_SPLIT_CONVERGENCE:-}
if [ "$diagnostic" = 1 ]; then
  [ "$split" = 1 ] || exit 64
  [[ "${COGS_STAGE2_DIAGNOSTIC_REF:-}" =~ ^refs/heads/[A-Za-z0-9._/-]+$ ]] || exit 64
  clean+=(COGS_STAGE2_NONAUTHORITATIVE_DIAGNOSTIC=1 COGS_STAGE2_SPLIT_CONVERGENCE=1
    "COGS_STAGE2_DIAGNOSTIC_REF=$COGS_STAGE2_DIAGNOSTIC_REF")
else
  [ -z "$diagnostic" ] && [ -z "$split" ] &&
    [ -z "${COGS_STAGE2_DIAGNOSTIC_REF:-}" ] || exit 64
fi
cd /var/lib/cogs/stage2-completion-v1/source
exec /usr/bin/env -i "${clean[@]}" \
  /usr/bin/python3 -I -B \
  /var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/completion_campaign_aws_recovery_entry.py

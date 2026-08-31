#!/usr/bin/env bash
set -euo pipefail
# Sole zero-argument future AWS campaign entry. Never used by non-AWS qualification.
[ "$#" -eq 0 ] || exit 64
cd /var/lib/cogs/stage2-completion-v1/source
exec /usr/bin/env -i HOME=/root LANG=C LC_ALL=C PATH=/usr/local/bin:/usr/bin:/bin TZ=UTC \
  /usr/bin/python3 -I -B \
  /var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/completion_campaign_aws_entry.py

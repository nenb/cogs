#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || exit 64
exec /usr/bin/python3 -I -B /var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/completion_campaign_aws_provider.py remote "$@"

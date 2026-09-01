#!/bin/sh
# Sole zero-argument no-mint readiness-route rehearsal entry.
set -eu
[ "$#" -eq 0 ] || exit 64
for name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE \
  AWS_WEB_IDENTITY_TOKEN_FILE TF_VAR_credentials GOOGLE_APPLICATION_CREDENTIALS \
  ARM_CLIENT_SECRET COGS_KATA_PROCESS_TESTING_V1 COGS_KATA_SYNTHETIC_ATTESTATION_V1 \
  COGS_KATA_SYNTHETIC_ATTESTATION_V3 PYTHONPATH PYTHONHOME PYTHONOPTIMIZE
do
  eval '[ "${'"$name"'+x}" != x ]' || exit 65
done
cd /var/lib/cogs/stage2-completion-v1/source
exec /usr/bin/env -i HOME=/nonexistent LANG=C LC_ALL=C \
  PATH=/opt/kata/bin:/usr/sbin:/usr/bin:/sbin:/bin TZ=UTC \
  /usr/bin/python3 -I -B \
  /var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote/completion_cycle_readiness_rehearsal.py

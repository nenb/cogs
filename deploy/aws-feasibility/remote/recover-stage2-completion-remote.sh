#!/bin/sh
# Fixed cleanup-only Stage 2 recovery entry. It can settle exact durable state,
# but has no receipt/report route and can never produce a qualification pass.
set -eu
[ "$#" -eq 0 ] || exit 64
for name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE \
  AWS_WEB_IDENTITY_TOKEN_FILE TF_VAR_credentials GOOGLE_APPLICATION_CREDENTIALS \
  ARM_CLIENT_SECRET COGS_KATA_PROCESS_TESTING_V1 PYTHONPATH PYTHONHOME PYTHONOPTIMIZE
do
  eval '[ "${'"$name"'+x}" != x ]' || exit 65
done
cd /var/lib/cogs/stage2-completion-v1/source
exec /usr/bin/env -i HOME=/nonexistent LANG=C LC_ALL=C \
  PATH=/opt/kata/bin:/usr/sbin:/usr/bin:/sbin:/bin TZ=UTC \
  /usr/bin/python3 -I -B -c \
  'import sys; sys.path.insert(0,"/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote"); import completion_kata_coordinator as c; result = c._recover_fixed_local_qualification(); raise SystemExit(0 if result is None else 70)'

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
profile=formal
if [ "${COGS_STAGE2_DIAGNOSTIC_CONTROL_VERSION+x}" = x ]; then
  [ "$COGS_STAGE2_DIAGNOSTIC_CONTROL_VERSION" = \
    cogs.stage2-current-source-prebuilt-diagnostic-control/v1 ] || exit 65
  profile=diagnostic
fi
cd /var/lib/cogs/stage2-completion-v1/source
exec /usr/bin/env -i HOME=/nonexistent LANG=C LC_ALL=C \
  PATH=/opt/kata/bin:/usr/sbin:/usr/bin:/sbin:/bin TZ=UTC \
  COGS_STAGE2_RECOVERY_PROFILE="$profile" \
  /usr/bin/python3 -I -B -c \
  'import sys; sys.path.insert(0,"/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote"); import completion_kata_coordinator as c
try:
 import os
 result = (c._recover_current_source_diagnostic()
           if os.environ["COGS_STAGE2_RECOVERY_PROFILE"] == "diagnostic"
           else c._recover_fixed_local_qualification())
except BaseException:
 import completion_kata_immutable_preparation as p
 result = p.recover_failed_preparation()
raise SystemExit(0 if result is None else 70)'

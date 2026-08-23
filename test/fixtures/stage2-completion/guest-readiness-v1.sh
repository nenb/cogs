set -eu
umask 077
[ "$#" -eq 0 ]
export HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin TZ=UTC
/usr/bin/printf '%s\n' COGS_STAGE2_SSH_READINESS_V1

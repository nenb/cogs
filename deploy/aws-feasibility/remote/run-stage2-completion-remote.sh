#!/bin/sh
# Fixed local qualification entry. It accepts no argument or configuration and
# performs no runtime/network/cloud mutation; the Python preflight exits closed.
set -eu
[ "$#" -eq 0 ] || exit 64
cd /var/lib/cogs/stage2-completion-v1/source
exec /usr/bin/python3 -I /var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote/completion_kata_qualification.py

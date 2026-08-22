#!/usr/bin/env bash
# Non-authoritative exact mixed-H/G immutable preflight. Never enter KVM/Kata.
set -uo pipefail

H=1eaec52dd4e2f1222548362e92adc780a2169025
MANIFEST=ec4c46f2247df2fad872dd3f1f7e147d775dfb568fcb7e520ceb7d3653108768
CONTROL=d32dad750fdae5118ba164d394145a3c3e7e45894524c2a17cbd502ecb80e26d
ROOT=/var/lib/cogs/stage2-completion-v1/source
H_CHECKOUT=$GITHUB_WORKSPACE/preflight-H
REPORT=/var/tmp/cogs-stage2-local-result-$GITHUB_RUN_ID-1
READBACK=/var/tmp/cogs-stage2-local-result-upload-$GITHUB_RUN_ID-1
RECEIPT=/var/tmp/cogs-stage2-local-receipt-upload-$GITHUB_RUN_ID-1

phase() { /usr/bin/printf 'COGS_MIXED_HG_PHASE:%s\n' "$1"; }

admit() {
  phase admission
  test "$#" -eq 0 && test "$GITHUB_RUN_ATTEMPT" = 1 || return
  test "$GITHUB_EVENT_NAME" = workflow_dispatch || return
  test "$GITHUB_REPOSITORY" = nenb/cogs || return
  test "$GITHUB_REF" = refs/heads/main && test "$GITHUB_REF_PROTECTED" = true || return
  test "$EXACT_IMPLEMENTATION_HEAD" = "$H" || return
  test "$EXACT_CONTROL_HEAD" = "$GITHUB_SHA" || return
  for name in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE \
    AWS_WEB_IDENTITY_TOKEN_FILE ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL \
    GITHUB_TOKEN GH_TOKEN HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY PYTHONPATH PYTHONHOME; do
    test -z "${!name+x}" || return
  done
}

acquire_h() {
  phase acquire-h
  test ! -e "$H_CHECKOUT" || return
  clean=(env -i HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/bin:/bin \
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0)
  "${clean[@]}" /usr/bin/git init --quiet "$H_CHECKOUT" || return
  "${clean[@]}" /usr/bin/git -C "$H_CHECKOUT" remote add origin https://github.com/nenb/cogs.git || return
  "${clean[@]}" /usr/bin/git -C "$H_CHECKOUT" fetch --quiet --no-tags --depth=1 origin "$H" || return
  "${clean[@]}" /usr/bin/git -C "$H_CHECKOUT" checkout --quiet --detach FETCH_HEAD || return
  test "$(/usr/bin/git -C "$H_CHECKOUT" rev-parse HEAD)" = "$H" || return
  test -z "$(/usr/bin/git -C "$H_CHECKOUT" status --porcelain)" || return
}

prepare() {
  phase baseline
  test ! -e /var/lib/cogs && test ! -e /opt/kata || return
  phase source
  prepared=$(sudo -n /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 150s \
    env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B \
    "$H_CHECKOUT/scripts/prepare-stage2-fixed-source.py") || return
  /usr/bin/python3 -I -c 'import json,sys
v=json.loads(sys.stdin.buffer.read()); assert (v["revision"],v["manifest_sha256"]) == tuple(sys.argv[1:])' \
    "$H" "$MANIFEST" <<<"$prepared" || return
  phase control
  staged=$(sudo -n /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 75s \
    env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -B \
    "$GITHUB_WORKSPACE/scripts/stage2-stage-reviewed-control.py") || return
  test "$staged" = "control_sha256=$CONTROL" || return
  observed=$(sudo -n /usr/bin/sha256sum \
    /var/lib/cogs/stage2-completion-v1/control/stage2-local-static-control-v1.json \
    | /usr/bin/cut -d' ' -f1) || return
  test "$observed" = "$CONTROL" || return
  phase immutable
  immutable=$(sudo -n /usr/bin/timeout --foreground --signal=TERM --kill-after=10s 1770s \
    env -i HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/bin:/bin TZ=UTC \
    /usr/bin/python3 -I -B "$ROOT/deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py") || return
  /usr/bin/python3 -I -c 'import json,sys
v=json.loads(sys.stdin.buffer.read()); assert v == {"version":"cogs.stage2-local-immutable-preparation/v1","rootfs_artifact_count":16,"runtime_archive_count":2,"receipt_sha256":v["receipt_sha256"],"control_verified":True,"authority":"immutable-public-input-preparation-only"}; assert len(v["receipt_sha256"]) == 64' \
    <<<"$immutable" || return
  phase installed
  sudo -n /usr/bin/test -x "$ROOT/deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1/bin/containerd" || return
  sudo -n /usr/bin/test -x "$ROOT/deploy/aws-feasibility/.state/completion-v1/kata-runtime-v1/bin/ctr" || return
  sudo -n /usr/bin/test -x /opt/kata/bin/containerd-shim-kata-v2 || return
}

settle() {
  phase recovery
  recovery=failure
  if sudo -n /usr/bin/test -x "$ROOT/deploy/aws-feasibility/remote/recover-stage2-completion-remote.sh"; then
    sudo -n /usr/bin/timeout --foreground --signal=TERM --kill-after=10s 300s \
      env -i HOME=/nonexistent LANG=C LC_ALL=C PATH=/opt/kata/bin:/usr/sbin:/usr/bin:/sbin:/bin TZ=UTC \
      "$ROOT/deploy/aws-feasibility/remote/recover-stage2-completion-remote.sh" && recovery=success
  elif test ! -e /var/lib/cogs && test ! -e /opt/kata; then recovery=success; fi
  test "$recovery" = success || return
  phase cleanup
  /usr/bin/printf '%s\n' "$GITHUB_RUN_ID" 1 "$REPORT" "$READBACK" "$RECEIPT" success | \
    sudo -n /usr/bin/python3 -I -B "$GITHUB_WORKSPACE/scripts/stage2-local-settlement.py" supervise-cleanup || return
  phase residue
  /usr/bin/printf '%s\n' "$GITHUB_RUN_ID" 1 "$REPORT" "$READBACK" "$RECEIPT" | \
    sudo -n /usr/bin/python3 -I -B "$GITHUB_WORKSPACE/scripts/stage2-local-settlement.py" supervise-residue || return
  test ! -e /var/lib/cogs && test ! -e /opt/kata || return
}

test "$#" -eq 1 || exit 2
case "$1" in run|settle) ;; *) exit 2 ;; esac
if test "$1" = settle; then settle; exit $?; fi
status=0
admit && acquire_h && prepare || status=$?
settle || status=1
if test "$status" -eq 0; then phase passed; fi
exit "$status"

#!/usr/bin/env python3
"""Versioned final-pin guest workload and nanosecond result codec.

Historical V2 lives unchanged in ``completion_guest_workloads_v2``.  This V3
module grants no execution authority; it exposes only immutable SSH stdin and
strict codecs for the final-pin workload.
"""

from dataclasses import dataclass
import hashlib
import json
import re

from completion_guest_workloads_v2 import WorkloadError

# The surfaces below are pure guest-plan data/codecs.  They grant no process,
# SSH, Kata, journal, qualification, or result-publication authority.
GUEST_READY_MARKER = b"COGS_STAGE2_SSH_READY_V2\n"
GUEST_RESULT_PREFIX = "COGS_STAGE2_RESULT_V2"
GUEST_NETWORK_PREFIX = "COGS_STAGE2_NETWORK_V1"
GUEST_NETWORK_MARKERS = (
    "route-baseline-no-default", "direct-tcp-denied", "direct-udp-denied",
    "default-route-added", "route-tcp-denied", "route-udp-denied",
    "default-route-removed", "route-restored-no-default",
)
GUEST_OUTPUT_LIMIT = 4096
GUEST_DURATION_LIMIT_NS = 1_200_000_000_000
FINAL_DEB_SHA256 = "08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf"
FINAL_DEB_BYTES = 1_064_816
FINAL_INSTALLED_TREE_SHA256 = "78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2"
FINAL_INSTALLED_ENTRIES = 259
FINAL_INSTALLED_BYTES = 1_048_576
_GUEST_DIGESTS = {
    "GIT": "73ccf2bce069d96d1dbd7e927e0fbd9205dcedfdb4a8ff104eb29e3f3e9e0b7c",
    "BUILD": FINAL_DEB_SHA256,
    "INSTALL": FINAL_INSTALLED_TREE_SHA256,
}
GUEST_WORKLOAD_PLAN = tuple(
    (f"{category}_{sample:02d}", _GUEST_DIGESTS[category])
    for category in ("GIT", "BUILD", "INSTALL") for sample in range(1, 8)
)
_RESULT_RE = re.compile(
    rb"COGS_STAGE2_RESULT_V2\|([0-9]{2})\|(GIT|BUILD|INSTALL)_[0-9]{2}"
    rb"\|([1-9][0-9]{0,12})\|([0-9a-f]{64})\|deleted=(true|false)"
)
_NETWORK_ROUTE_RE = re.compile(
    rb"COGS_STAGE2_NETWORK_V1\|(01|08)\|(route-baseline-no-default|route-restored-no-default)"
    rb"\|route_sha256=([0-9a-f]{64})"
)

# This is the sole remote stdin.  All invocations and paths are closed in these
# bytes; an eventual coordinator may authenticate the bytes but cannot customize
# them. Guest mountinfo proves safe distinct Kata-generated leaves only; exact
# host-source-to-leaf correlation belongs to the future trusted runtime owner.
# Every package build is compared directly with the manually reviewed final
# package identity.  A mismatch is terminal; this program cannot refresh pins.
_GUEST_PROGRAM = r'''set -eu
umask 077
[ "$#" -eq 0 ]
export HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
export SOURCE_DATE_EPOCH=1782172800 TZ=UTC TMPDIR=/run/cogs-stage2-ssh/work
R=/run/cogs-stage2-ssh
W=/run/cogs-stage2-ssh/work
I=/run/cogs-stage2-ssh/input
GIT_COMMIT=ca429a94b73caea0fc39164b8087cc1c63f43818
GIT_STATUS=51ad8b3506601cd631d1da66ca40bbafc0c68a5e907600c21fba958a6f22330b
SOURCE_MANIFEST=fcda9e9ba79a1be78202d3f1808bc217e50a2b355c149598087a4e7cca4a698f
INSTALLED_MANIFEST=f0d03497ac0a1784d0cb0c6bd7dd13932eb376c131fd550de438cefa25deb483
FINAL_DEB_SHA=08702b0d8605121987d29dd7e4941e87f0063776f20229e14c57529fd7d4ddcf
FINAL_DEB_SIZE=1064816
FINAL_TREE_SHA=78aa672b7bd34a21fdd70d9adc2beb1693be06c8ad910db359456f8e5e57d7b2
FINAL_TREE_ENTRIES=259
FINAL_TREE_BYTES=1048576
DEB_BUILD_COUNT=0
network_marker() { /usr/bin/printf '%s|%02d|%s\n' COGS_STAGE2_NETWORK_V1 "$1" "$2"; }
route_snapshot() {
  /bin/cp -- /proc/net/route "$1"
  /usr/bin/awk 'BEGIN{link=0;bad=0} NR>1&&$1=="eth0"&&$2=="000200C0"&&$8=="FCFFFFFF"{link++} NR>1&&$1=="eth0"&&$2=="00000000"{bad++} END{exit(link==1&&bad==0?0:1)}' "$1"
}
route_change() {
  /usr/bin/perl -MSocket -e '
    use strict; use warnings; my $add=$ARGV[0] eq "add"; open my $f,"<","/sys/class/net/eth0/ifindex" or exit 10; my $ifindex=<$f>; close $f; $ifindex=~s/\s+//g; $ifindex=~/^[1-9][0-9]*$/ or exit 11;
    socket(my $s,16,3,0) or exit 12; my $rt=pack("C8L",2,0,0,0,254,3,0,1,0); my $attrs=pack("SSa4",8,5,inet_aton("192.0.2.1")).pack("SSL",8,4,$ifindex); my $payload=$rt.$attrs; my $type=$add?24:25; my $flags=$add?0x605:5; my $msg=pack("LSSLL",16+length($payload),$type,$flags,1,0).$payload; my $to=pack("SSLL",16,0,0,0); send($s,$msg,0,$to)==length($msg) or exit 13; recv($s,my $reply,4096,0) or exit 14; length($reply)>=20 or exit 15; my ($len,$reply_type,$reply_flags,$seq,$pid)=unpack("LSSLL",$reply); $len<=length($reply)&&$reply_type==2&&$seq==1 or exit 16; my $error=unpack("l",substr($reply,16,4)); exit($error==0?0:17);
  ' "$1"
}
tcp_drop_probe() {
  /usr/bin/perl -MSocket -e 'use strict; use warnings; socket(my $s,2,1,6) or exit 10; $SIG{ALRM}=sub{exit 0}; alarm 2; connect($s,sockaddr_in($ARGV[1],inet_aton($ARGV[0]))); exit 11' "$1" "$2"
}
udp_probe() {
  /usr/bin/perl -MSocket -e 'use strict; use warnings; socket(my $s,2,2,17) or exit 10; send($s,"x",0,sockaddr_in($ARGV[1],inet_aton($ARGV[0])))==1 or exit 11' "$1" "$2"
}
network_probes() {
  route_snapshot "$W/route.before"
  route_sha=$(/usr/bin/sha256sum "$W/route.before"); route_sha=${route_sha%% *}
  /usr/bin/printf '%s|01|%s|route_sha256=%s\n' COGS_STAGE2_NETWORK_V1 route-baseline-no-default "$route_sha"
  tcp_drop_probe 192.0.2.1 2222; network_marker 2 direct-tcp-denied
  udp_probe 192.0.2.1 5353; network_marker 3 direct-udp-denied
  route_change add
  network_marker 4 default-route-added
  tcp_drop_probe 198.51.100.1 443; network_marker 5 route-tcp-denied
  udp_probe 198.51.100.1 443; network_marker 6 route-udp-denied
  route_change del
  network_marker 7 default-route-removed
  route_snapshot "$W/route.after"
  /usr/bin/cmp -s "$W/route.before" "$W/route.after"
  route_after_sha=$(/usr/bin/sha256sum "$W/route.after"); route_after_sha=${route_after_sha%% *}
  [ "$route_sha" = "$route_after_sha" ]
  /usr/bin/printf '%s|08|%s|route_sha256=%s\n' COGS_STAGE2_NETWORK_V1 route-restored-no-default "$route_after_sha"
  /bin/rm -f -- "$W/route.before" "$W/route.after"
}
line_count() {
  /usr/bin/wc -l < "$1" > "$2"
  IFS= read -r observed < "$2"
  [ "$observed" -eq "$3" ]
  /bin/rm -f -- "$2"
}
require_sha() {
  /usr/bin/sha256sum -- "$1" > "$3"
  line_count "$3" "$3.count" 1
  IFS=' ' read -r observed observed_path < "$3"
  [ "$observed" = "$2" ] && [ "$observed_path" = "$1" ]
  /bin/rm -f -- "$3"
}
empty_tree() {
  /usr/bin/find "$1" -mindepth 1 -print > "$2"
  [ ! -s "$2" ]
  /bin/rm -f -- "$2"
}
manifest() {
  root=$1 expected=$2 count=$3 scratch=$4
  ( cd "$root"
    /usr/bin/find . -type f -print > "$scratch.paths"
    /usr/bin/find . ! -type d ! -type f -print > "$scratch.other"
    /usr/bin/sort "$scratch.paths" > "$scratch.sorted"
    line_count "$scratch.sorted" "$scratch.count" "$count"
    while IFS= read -r file; do /usr/bin/sha256sum -- "$file"; done < "$scratch.sorted" > "$scratch.sums"
    line_count "$scratch.sums" "$scratch.count" "$count"
    require_sha "$scratch.sums" "$expected" "$scratch.digest"
    [ ! -s "$scratch.other" ]
  )
  /bin/rm -f -- "$scratch.paths" "$scratch.sorted" "$scratch.sums" "$scratch.other"
}
mount_invariant() {
  /usr/bin/awk '
  function has(values,want, n,a,i){n=split(values,a,",");for(i=1;i<=n;i++)if(a[i]==want)return 1;return 0}
  function safeleaf(root, value){if(index(root,"/mounts/")!=1)return "";value=substr(root,9);if(length(value)<1||length(value)>255||value=="."||value==".."||value!~/^[A-Za-z0-9][A-Za-z0-9._-]*$/)return "";return value}
  function nativeleaf(root,role, prefix,suffix,value){prefix="/cogs-stage2-ssh-v1-";suffix="-" role;if(index(root,prefix)!=1||substr(root,length(root)-length(suffix)+1)!=suffix)return "";value=substr(root,length(prefix)+1,length(root)-length(prefix)-length(suffix));if(length(value)!=16||value!~/^[0-9a-f]+$/)return "";return root}
  BEGIN{bad=0;r=key=auth=input=0;keyleaf=authleaf=inputleaf=""}
  index($5,"/run/cogs-stage2-ssh/")==1 && $5!="/run/cogs-stage2-ssh/ssh_host_ed25519_key" && $5!="/run/cogs-stage2-ssh/authorized_keys" && $5!="/run/cogs-stage2-ssh/input" {bad=1}
  $5=="/run/cogs-stage2-ssh" {r++;if($4!="/"||$7!="-"||$8!="tmpfs"||$9!="tmpfs"||!has($6,"rw")||!has($6,"nosuid")||!has($6,"nodev")||!has($6,"noexec")||!has($10,"rw")||!has($10,"size=65536k")||!has($10,"nr_inodes=16384")||!has($10,"mode=700"))bad=1}
  $5=="/run/cogs-stage2-ssh/ssh_host_ed25519_key" {key++;keyleaf=safeleaf($4);if(keyleaf=="")keyleaf=nativeleaf($4,"ssh_host_ed25519_key");if(keyleaf==""||$7!="-"||$8!="virtiofs"||$9!="kataShared"||!has($6,"ro")||!has($6,"nosuid")||!has($6,"nodev")||!has($6,"noexec"))bad=1}
  $5=="/run/cogs-stage2-ssh/authorized_keys" {auth++;authleaf=safeleaf($4);if(authleaf=="")authleaf=nativeleaf($4,"authorized_keys");if(authleaf==""||$7!="-"||$8!="virtiofs"||$9!="kataShared"||!has($6,"ro")||!has($6,"nosuid")||!has($6,"nodev")||!has($6,"noexec"))bad=1}
  $5=="/run/cogs-stage2-ssh/input" {input++;inputnative=0;inputleaf=safeleaf($4);if(inputleaf==""&&$4=="/"&&$7=="-"&&$8=="virtiofs"&&$9=="none"){inputleaf="native-input";inputnative=1}if(inputleaf==""||$7!="-"||$8!="virtiofs"||(inputnative&&$9!="none")||(!inputnative&&$9!="kataShared")||!has($6,"ro")||!has($6,"nosuid")||!has($6,"nodev")||!has($6,"noexec"))bad=1}
  END{if(r!=1||key!=1||auth!=1||input!=1||keyleaf==authleaf||keyleaf==inputleaf||authleaf==inputleaf)bad=1;exit bad?1:0}
  ' /proc/self/mountinfo
}
invariant() {
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$R")" = '0:0:700:directory' ]
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$W")" = '0:0:700:directory' ]
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$R/ssh_host_ed25519_key")" = '0:0:400:regular file' ]
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$R/authorized_keys")" = '0:0:400:regular file' ]
  [ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- "$I")" = '0:0:555:directory' ]
  mount_invariant
  [ "$(/usr/bin/git --git-dir="$I/git.git" rev-parse refs/heads/main)" = "$GIT_COMMIT" ]
  /usr/bin/git --git-dir="$I/git.git" fsck --strict --full > "$W/invariant.git.out" 2> "$W/invariant.git.err"
  [ ! -s "$W/invariant.git.out" ] && [ ! -s "$W/invariant.git.err" ]
  manifest "$I/package" "$SOURCE_MANIFEST" 257 "$W/invariant"
  /usr/bin/find "$I/package" -type d -print > "$W/invariant.dirs"
  line_count "$W/invariant.dirs" "$W/invariant.count" 5
  /bin/rm -f -- "$W/invariant.git.out" "$W/invariant.git.err" "$W/invariant.dirs"
  empty_tree "$W" "$W-empty"
}
now() { /usr/bin/date +%s%N; }
elapsed() {
  [ "$2" -ge "$1" ]
  ELAPSED=$(($2-$1))
  [ "$ELAPSED" -gt 0 ] && [ "$ELAPSED" -le 1200000000000 ]
}
emit() { /usr/bin/printf '%s|%s|%s|%s|%s|deleted=true\n' COGS_STAGE2_RESULT_V2 "$1" "$2" "$3" "$4"; }
delete_sample() {
  /bin/rm -rf -- "$1"
  [ ! -e "$1" ] && [ ! -L "$1" ]
  if /usr/bin/stat -- "$1" > /dev/null 2>&1; then exit 1; fi
  empty_tree "$W" "$W-empty"
}
metadata_rows() {
  root=$1 dirs=$2 files=$3 scratch=$4
  /usr/bin/find "$root" -type d -print > "$scratch.dirs"
  /usr/bin/find "$root" -type f -print > "$scratch.files"
  /usr/bin/find "$root" ! -type d ! -type f -print > "$scratch.other"
  line_count "$scratch.dirs" "$scratch.count" "$dirs"
  line_count "$scratch.files" "$scratch.count" "$files"
  [ ! -s "$scratch.other" ]
}
normalize_source() {
  root=$1 scratch=$2
  metadata_rows "$root" 5 257 "$scratch"
  while IFS= read -r entry; do /bin/chown 0:0 -- "$entry"; /bin/chmod 0755 -- "$entry"; /usr/bin/touch -d @1782172800 -- "$entry"; done < "$scratch.dirs"
  while IFS= read -r entry; do /bin/chown 0:0 -- "$entry"; /bin/chmod 0644 -- "$entry"; /usr/bin/touch -d @1782172800 -- "$entry"; done < "$scratch.files"
  verify_metadata "$root" 5 257 "$scratch" 755 644
  /bin/rm -f -- "$scratch.dirs" "$scratch.files" "$scratch.other"
}
verify_metadata() {
  root=$1 dirs=$2 files=$3 scratch=$4 dmode=$5 fmode=$6
  metadata_rows "$root" "$dirs" "$files" "$scratch"
  while IFS= read -r entry; do
    /usr/bin/stat -c '%u:%g:%a:%Y:%F' -- "$entry" > "$scratch.stat"
    line_count "$scratch.stat" "$scratch.count" 1
    IFS= read -r observed < "$scratch.stat"
    [ "$observed" = "0:0:$dmode:1782172800:directory" ]
  done < "$scratch.dirs"
  while IFS= read -r entry; do
    /usr/bin/stat -c '%u:%g:%a:%Y:%F' -- "$entry" > "$scratch.stat"
    line_count "$scratch.stat" "$scratch.count" 1
    IFS= read -r observed < "$scratch.stat"
    [ "$observed" = "0:0:$fmode:1782172800:regular file" ]
  done < "$scratch.files"
  /bin/rm -f -- "$scratch.dirs" "$scratch.files" "$scratch.other" "$scratch.stat"
}
observe_deb() {
  deb=$1 scratch=$2
  /usr/bin/sha256sum -- "$deb" > "$scratch.sha"
  line_count "$scratch.sha" "$scratch.count" 1
  IFS=' ' read -r observed_sha observed_path < "$scratch.sha"
  [ "$observed_path" = "$deb" ] && [ "${#observed_sha}" -eq 64 ]
  /usr/bin/stat -c '%s' -- "$deb" > "$scratch.size"
  line_count "$scratch.size" "$scratch.count" 1
  IFS= read -r observed_size < "$scratch.size"
  [ "$observed_sha" = "$FINAL_DEB_SHA" ]
  [ "$observed_size" -eq "$FINAL_DEB_SIZE" ]
  DEB_BUILD_COUNT=$((DEB_BUILD_COUNT+1))
  /bin/rm -f -- "$scratch.sha" "$scratch.size"
}
verify_installed_tree() {
  root=$1 scratch=$2
  manifest "$root" "$INSTALLED_MANIFEST" 256 "$scratch.manifest"
  verify_metadata "$root" 4 256 "$scratch.metadata" 755 644
  ( cd "$root"
    /usr/bin/find . -mindepth 1 -type d -print > "$scratch.dirs"
    /usr/bin/find . -type f -print > "$scratch.files"
    /usr/bin/sort "$scratch.dirs" > "$scratch.dirs.sorted"
    /usr/bin/sort "$scratch.files" > "$scratch.files.sorted"
    /usr/bin/printf '%s\n' '{"gid":0,"kind":"directory","mode":493,"mtime":1782172800,"path":".","regular_sha256":null,"size":0,"uid":0,"version":"cogs.stage2-logical-tree/v1"}' > "$scratch.tree"
    while IFS= read -r entry; do
      path=${entry#./}
      /usr/bin/printf '{"gid":0,"kind":"directory","mode":493,"mtime":1782172800,"path":"%s","regular_sha256":null,"size":0,"uid":0,"version":"cogs.stage2-logical-tree/v1"}\n' "$path" >> "$scratch.tree"
    done < "$scratch.dirs.sorted"
    while IFS= read -r entry; do
      path=${entry#./}
      size=$(/usr/bin/stat -c '%s' -- "$entry")
      sha=$(/usr/bin/sha256sum -- "$entry"); sha=${sha%% *}
      /usr/bin/printf '{"gid":0,"kind":"file","mode":420,"mtime":1782172800,"path":"%s","regular_sha256":"%s","size":%s,"uid":0,"version":"cogs.stage2-logical-tree/v1"}\n' "$path" "$sha" "$size" >> "$scratch.tree"
    done < "$scratch.files.sorted"
  )
  line_count "$scratch.tree" "$scratch.count" $((FINAL_TREE_ENTRIES+1))
  require_sha "$scratch.tree" "$FINAL_TREE_SHA" "$scratch.digest"
  /usr/bin/find "$root" -type f -printf '%s\n' > "$scratch.sizes"
  line_count "$scratch.sizes" "$scratch.count" 256
  /usr/bin/awk '{ total += $1 } END { printf "%.0f\n", total }' "$scratch.sizes" > "$scratch.bytes"
  line_count "$scratch.bytes" "$scratch.count" 1
  IFS= read -r observed_bytes < "$scratch.bytes"
  [ "$observed_bytes" -eq "$FINAL_TREE_BYTES" ]
  /bin/rm -f -- "$scratch.tree" "$scratch.dirs" "$scratch.files" \
    "$scratch.dirs.sorted" "$scratch.files.sorted" "$scratch.sizes" "$scratch.bytes"
}
verify_deb() {
  deb=$1 check=$2
  [ "$(/usr/bin/dpkg-deb --field "$deb" Package)" = cogs-stage2-fixture ]
  [ "$(/usr/bin/dpkg-deb --field "$deb" Version)" = 1.0 ]
  [ "$(/usr/bin/dpkg-deb --field "$deb" Architecture)" = all ]
  /bin/mkdir -m 0700 -- "$check"
  /usr/bin/dpkg-deb --extract "$deb" "$check" > "$check.extract.out" 2> "$check.extract.err"
  [ ! -s "$check.extract.out" ] && [ ! -s "$check.extract.err" ]
  verify_installed_tree "$check" "$check.tree"
  /bin/rm -rf -- "$check"
}
git_sample() {
  n=$1 ord=$2 p="$W/git-$1"
  [ ! -e "$p" ] && [ ! -L "$p" ]
  start=$(now)
  /usr/bin/git -c init.templateDir= clone --quiet --no-hardlinks --no-tags "$I/git.git" "$p" 2> "$W/git.err"
  /usr/bin/git -C "$p" checkout --quiet --detach "$GIT_COMMIT" 2>> "$W/git.err"
  i=0; while [ "$i" -lt 32 ]; do /usr/bin/printf '%s\n' 'cogs-stage2-git-v1 modified' >> "$p/files/file-$(/usr/bin/printf '%04d' "$i").txt"; i=$((i+1)); done
  /bin/mkdir -m 0755 -- "$p/untracked"
  /usr/bin/printf '%s\n' 223fd29f1561711aa8b103007774eff0e4219b3a1fe5de532cd68a18655004ef 372cf2f7ed6ac3f64f6718557444132f10c760bb2af0e6c8398bc888380fd6c0 539c440d17714b0243f5b7a3694a51192c795d82c7b83a84f31868e92a28dcc3 135edac91796901ce00251283a50436d55c740055d016be0634978d3a6246dee 2534503de4f86da0fc5925d49f2a17aac088a29da9a6f531026febd5868b9667 23d5832443aada2936bcc495164304aa481f7b422dd9d9a10c379155e0f0c0f4 cd5d3e78c20f5eaf03d84832812d3f52fe7e5e120d6da4e968b0c8796004bf98 dbcf2c1f64841d8be161db397d3ae8a9a8bc07f40143aeee6ef53229b40125ac > "$W/payloads"
  i=0; while IFS= read -r payload; do /usr/bin/printf '%s\n' "$payload" > "$p/untracked/file-$(/usr/bin/printf '%04d' "$i").txt"; i=$((i+1)); done < "$W/payloads"
  /usr/bin/git -C "$p" status --porcelain=v1 --untracked-files=all > "$W/status" 2>> "$W/git.err"
  end=$(now); elapsed "$start" "$end"
  [ ! -s "$W/git.err" ] && [ "$i" -eq 8 ] && [ "$(/usr/bin/wc -l < "$W/status")" -eq 40 ]
  [ "$(/usr/bin/sha256sum "$W/status")" = "$GIT_STATUS  $W/status" ]
  /bin/rm -f -- "$W/git.err" "$W/status" "$W/payloads"
  delete_sample "$p"
  emit "$ord" "GIT_$n" "$ELAPSED" 73ccf2bce069d96d1dbd7e927e0fbd9205dcedfdb4a8ff104eb29e3f3e9e0b7c
}
build_sample() {
  n=$1 ord=$2 p="$W/build-$1"
  [ ! -e "$p" ] && [ ! -L "$p" ]; /bin/mkdir -m 0700 -- "$p"; /bin/cp -a -- "$I/package" "$p/source"
  normalize_source "$p/source" "$p/source.metadata"
  start=$(now); /usr/bin/dpkg-deb --build --root-owner-group --compression=xz --compression-level=6 --threads-max=1 "$p/source" "$p/package.deb" > "$p/build.out" 2> "$p/build.err"; end=$(now); elapsed "$start" "$end"
  [ ! -s "$p/build.err" ]; observe_deb "$p/package.deb" "$p/deb"; verify_deb "$p/package.deb" "$p/check"
  delete_sample "$p"
  emit "$ord" "BUILD_$n" "$ELAPSED" "$FINAL_DEB_SHA"
}
install_sample() {
  n=$1 ord=$2 p="$W/install-$1"
  [ ! -e "$p" ] && [ ! -L "$p" ]; /bin/mkdir -m 0700 -- "$p"; /bin/cp -a -- "$I/package" "$p/source"
  normalize_source "$p/source" "$p/source.metadata"
  /usr/bin/dpkg-deb --build --root-owner-group --compression=xz --compression-level=6 --threads-max=1 "$p/source" "$p/package.deb" > "$p/build.out" 2> "$p/build.err"
  [ ! -s "$p/build.err" ]; observe_deb "$p/package.deb" "$p/deb"; verify_deb "$p/package.deb" "$p/check"
  /bin/mkdir -m 0700 -- "$p/admin" "$p/admin/updates"; : > "$p/admin/status"; /bin/mkdir -m 0755 -- "$p/installed"; /usr/bin/touch -d @1782172800 -- "$p/installed"
  start=$(now); /usr/bin/dpkg --force-not-root --admindir "$p/admin" --instdir "$p/installed/" --install "$p/package.deb" > "$p/install.out" 2> "$p/install.err"; end=$(now); elapsed "$start" "$end"
  [ ! -s "$p/install.err" ]
  [ "$(/usr/bin/grep -c '^Package: cogs-stage2-fixture$' "$p/admin/status")" -eq 1 ]
  [ "$(/usr/bin/grep -c '^Version: 1.0$' "$p/admin/status")" -eq 1 ]
  [ "$(/usr/bin/grep -c '^Architecture: all$' "$p/admin/status")" -eq 1 ]
  [ "$(/usr/bin/grep -c '^Status: install ok installed$' "$p/admin/status")" -eq 1 ]
  verify_installed_tree "$p/installed" "$p/installed.tree"
  delete_sample "$p"
  emit "$ord" "INSTALL_$n" "$ELAPSED" "$FINAL_TREE_SHA"
}
invariant
/usr/bin/printf '%s\n' COGS_STAGE2_SSH_READY_V2
network_probes
git_sample 01 01; git_sample 02 02; git_sample 03 03; git_sample 04 04; git_sample 05 05; git_sample 06 06; git_sample 07 07
invariant
build_sample 01 08; build_sample 02 09; build_sample 03 10; build_sample 04 11; build_sample 05 12; build_sample 06 13; build_sample 07 14
invariant
install_sample 01 15; install_sample 02 16; install_sample 03 17; install_sample 04 18; install_sample 05 19; install_sample 06 20; install_sample 07 21
invariant
invariant
[ "$DEB_BUILD_COUNT" -eq 14 ]
empty_tree "$W" "$W-empty"
'''.encode("ascii")
# Regenerated only from the literal above after all program changes are final.
GUEST_PROGRAM_SHA256 = "64e47b459ad8716974e934478045a7a2729d6df44074573deb45e6ea090fb0b4"


@dataclass(frozen=True)
class GuestSampleResult:
    ordinal: int
    category: str
    duration_ns: int
    result_sha256: str
    deleted: bool


@dataclass(frozen=True)
class GuestWorkloadResult:
    marker_sha256: str
    samples: tuple[GuestSampleResult, ...]
    network_markers: tuple = ()
    route_before_sha256: str = ""
    route_after_sha256: str = ""


def guest_program_bytes():
    """Return verified exact stdin bytes; never execute or issue them."""
    if hashlib.sha256(_GUEST_PROGRAM).hexdigest() != GUEST_PROGRAM_SHA256:
        raise WorkloadError("guest program source digest mismatch")
    if not _GUEST_PROGRAM.endswith(b"\n") or any(byte not in range(128) for byte in _GUEST_PROGRAM):
        raise WorkloadError("guest program encoding mismatch")
    return _GUEST_PROGRAM


def canonical_guest_workload_result(result):
    """Bounded canonical parsed-result bytes used by durable SSH replay."""
    if (type(result) is not GuestWorkloadResult or len(result.samples) != len(GUEST_WORKLOAD_PLAN)
            or result.marker_sha256 != hashlib.sha256(GUEST_READY_MARKER).hexdigest()):
        raise WorkloadError("guest canonical result type mismatch")
    if (result.network_markers != GUEST_NETWORK_MARKERS
            or result.route_before_sha256 != result.route_after_sha256
            or re.fullmatch(r"[0-9a-f]{64}", result.route_before_sha256) is None):
        raise WorkloadError("guest canonical network proof mismatch")
    value = {"marker_sha256": result.marker_sha256,
             "network_markers": list(result.network_markers),
             "route_after_sha256": result.route_after_sha256,
             "route_before_sha256": result.route_before_sha256, "samples": [{
        "category": row.category, "deleted": row.deleted, "duration_ns": row.duration_ns,
        "ordinal": row.ordinal, "result_sha256": row.result_sha256,
    } for row in result.samples], "version": "cogs.stage2-guest-workload-result/v3"}
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                     allow_nan=False).encode("ascii") + b"\n"
    if len(raw) > GUEST_OUTPUT_LIMIT * 4:
        raise WorkloadError("guest canonical result bound")
    return raw


def parse_canonical_guest_workload_result(raw):
    if type(raw) is not bytes or not raw.endswith(b"\n") or len(raw) > GUEST_OUTPUT_LIMIT * 4:
        raise WorkloadError("guest canonical result bytes")
    try:
        value = json.loads(raw)
        if raw != json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode("ascii") + b"\n":
            raise WorkloadError("guest canonical result encoding")
        if (type(value) is not dict or set(value) != {
                "version", "marker_sha256", "network_markers", "route_before_sha256",
                "route_after_sha256", "samples"}
                or value["version"] != "cogs.stage2-guest-workload-result/v3"
                or type(value["marker_sha256"]) is not str
                or type(value["network_markers"]) is not list
                or not all(type(item) is str for item in value["network_markers"])
                or type(value["route_before_sha256"]) is not str
                or type(value["route_after_sha256"]) is not str):
            raise WorkloadError("guest canonical result shape")
        if type(value["samples"]) is not list:
            raise WorkloadError("guest canonical samples type")
        for row in value["samples"]:
            if (type(row) is not dict or set(row) != {"ordinal", "category", "duration_ns",
                                                 "result_sha256", "deleted"}
                    or type(row["ordinal"]) is not int or type(row["category"]) is not str
                    or type(row["duration_ns"]) is not int or type(row["result_sha256"]) is not str
                    or type(row["deleted"]) is not bool):
                raise WorkloadError("guest canonical sample shape")
        samples = tuple(GuestSampleResult(
            row["ordinal"], row["category"], row["duration_ns"], row["result_sha256"], row["deleted"])
            for row in value["samples"])
        result = GuestWorkloadResult(
            value["marker_sha256"], samples, tuple(value["network_markers"]),
            value["route_before_sha256"], value["route_after_sha256"])
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise WorkloadError("guest canonical result parse") from error
    if canonical_guest_workload_result(result) != raw:
        raise WorkloadError("guest canonical result semantics")
    for ordinal, (expected, row) in enumerate(
            zip(GUEST_WORKLOAD_PLAN, result.samples, strict=True), 1):
        if (row.ordinal, row.category, row.result_sha256, row.deleted) != (
                ordinal, expected[0], expected[1], True):
            raise WorkloadError("guest canonical result plan")
        if (type(row.duration_ns) is not int
                or not 1 <= row.duration_ns <= GUEST_DURATION_LIMIT_NS):
            raise WorkloadError("guest canonical duration")
    return result


def parse_guest_workload_output(raw):
    """Parse the sole complete stdout object and enforce the fixed plan semantics."""
    if type(raw) is not bytes or not raw or len(raw) > GUEST_OUTPUT_LIMIT or b"\0" in raw:
        raise WorkloadError("guest output bound mismatch")
    if not raw.endswith(b"\n") or any(byte > 127 for byte in raw):
        raise WorkloadError("guest output encoding mismatch")
    lines = raw.splitlines(keepends=True)
    network_count = len(GUEST_NETWORK_MARKERS)
    if len(lines) != len(GUEST_WORKLOAD_PLAN) + network_count + 1 or lines[0] != GUEST_READY_MARKER:
        raise WorkloadError("guest output readiness or cardinality mismatch")
    network_lines = lines[1:1 + network_count]
    route_digests = []
    for ordinal, (expected_marker, line) in enumerate(
            zip(GUEST_NETWORK_MARKERS, network_lines, strict=True), 1):
        if ordinal in {1, network_count}:
            match = _NETWORK_ROUTE_RE.fullmatch(line[:-1]) if line.endswith(b"\n") else None
            if (match is None or int(match.group(1)) != ordinal
                    or match.group(2).decode("ascii") != expected_marker):
                raise WorkloadError("guest network route marker mismatch")
            route_digests.append(match.group(3).decode("ascii"))
        else:
            expected = f"{GUEST_NETWORK_PREFIX}|{ordinal:02d}|{expected_marker}\n".encode("ascii")
            if line != expected:
                raise WorkloadError("guest network marker mismatch")
    if len(route_digests) != 2 or route_digests[0] != route_digests[1]:
        raise WorkloadError("guest route restoration mismatch")
    samples = []
    sample_lines = lines[1 + network_count:]
    for ordinal, ((label, expected_digest), line) in enumerate(
            zip(GUEST_WORKLOAD_PLAN, sample_lines, strict=True), 1):
        if not line.endswith(b"\n") or line.count(b"\n") != 1:
            raise WorkloadError("guest result framing mismatch")
        match = _RESULT_RE.fullmatch(line[:-1])
        if match is None:
            raise WorkloadError("guest result grammar mismatch")
        parsed_ordinal = int(match.group(1))
        parsed_label = line[:-1].split(b"|", 4)[2].decode("ascii")
        duration = int(match.group(3))
        digest = match.group(4).decode("ascii")
        deleted = match.group(5) == b"true"
        canonical = f"{GUEST_RESULT_PREFIX}|{ordinal:02d}|{label}|{duration}|{expected_digest}|deleted=true\n".encode("ascii")
        if (line != canonical or parsed_ordinal != ordinal or parsed_label != label or
                not 1 <= duration <= GUEST_DURATION_LIMIT_NS
                or digest != expected_digest or not deleted):
            raise WorkloadError("guest result semantic mismatch")
        samples.append(GuestSampleResult(ordinal, label, duration, digest, True))
    return GuestWorkloadResult(
        hashlib.sha256(GUEST_READY_MARKER).hexdigest(), tuple(samples),
        GUEST_NETWORK_MARKERS, route_digests[0], route_digests[1])

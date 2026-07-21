#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly COGS_GIT_TOOLS_LABEL=COGS_GITTOOLS
readonly COGS_GIT_TOOLS_MOUNT=/opt/cogs-git
readonly COGS_GIT_TOOLS_IMAGE=git-tools.img
readonly COGS_GIT_TOOLS_SIZE=256M
readonly COGS_GIT_TOOLS_SENTINEL=.cogs-git-tools-staging-v1
readonly COGS_GIT_TOOLS_MANIFEST=cogs-git-tools-manifest.tsv
readonly COGS_GIT_VERSION=2.47.3
readonly COGS_GIT_PACKAGE_COUNT=4
readonly COGS_GIT_TOOLS_CURL=/usr/bin/curl
readonly COGS_GIT_TOOLS_DPKG_DEB=/usr/bin/dpkg-deb
readonly COGS_GIT_TOOLS_MKFS=/usr/sbin/mkfs.ext4
readonly COGS_GIT_TOOLS_DEBUGFS=/usr/sbin/debugfs

cogs_git_tools_manifest() {
  cat <<'EOF'
git	1:2.47.3-0+deb13u1	amd64	git_2.47.3-0+deb13u1_amd64.deb	8861572	https://deb.debian.org/debian/pool/main/g/git/git_2.47.3-0+deb13u1_amd64.deb	3e35662fd5c46add561703e54031a1d8ad9df45811927689f0a51122b13be722
libcurl3t64-gnutls	8.14.1-2+deb13u4	amd64	libcurl3t64-gnutls_8.14.1-2+deb13u4_amd64.deb	384336	https://deb.debian.org/debian/pool/main/c/curl/libcurl3t64-gnutls_8.14.1-2+deb13u4_amd64.deb	351bf3bb1c816c1d88900cbfe59dc79433f20fb962947d78313028a00f97c856
libngtcp2-16	1.11.0-1+deb13u1	amd64	libngtcp2-16_1.11.0-1+deb13u1_amd64.deb	131904	https://deb.debian.org/debian/pool/main/n/ngtcp2/libngtcp2-16_1.11.0-1+deb13u1_amd64.deb	627eec81ebbd48c4e6091f5cd9dc5070b792b7075000eed60ab08c7daa961caf
libngtcp2-crypto-gnutls8	1.11.0-1+deb13u1	amd64	libngtcp2-crypto-gnutls8_1.11.0-1+deb13u1_amd64.deb	29524	https://deb.debian.org/debian/pool/main/n/ngtcp2/libngtcp2-crypto-gnutls8_1.11.0-1+deb13u1_amd64.deb	2a7f109c0c4db6a800e4661c5e5e34e1f1f83c8162482276183d1ada9da7c96c
EOF
}

cogs_git_tools_fail() { echo 'FAIL: Git tools prerequisite failed' >&2; exit 1; }

cogs_git_tools_fsync_parent() {
  python3 - "$1" <<'PY'
import os,sys
fd=os.open(sys.argv[1], os.O_RDONLY)
try: os.fsync(fd)
finally: os.close(fd)
PY
}

cogs_git_tools_verify_package() {
  local file=$1 name=$2 version=$3 arch=$4 size=$5 sha256=$6 mode=$7
  python3 - "$file" "$mode" <<'PY' || return 1
import os,stat,sys
path,expected=sys.argv[1:]
st=os.lstat(path)
if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (st.st_mode & 0o777) != int(expected,8):
    raise SystemExit(1)
if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
    raise SystemExit(1)
if os.path.realpath(path) != os.path.abspath(path):
    raise SystemExit(1)
PY
  actual_size=$(wc -c < "$file" | tr -d ' ')
  [[ "$actual_size" == "$size" ]] || return 1
  actual_sha=$(sha256sum "$file" | awk '{print $1}')
  [[ "$actual_sha" == "$sha256" ]] || return 1
  [[ "$("$COGS_GIT_TOOLS_DPKG_DEB" --field "$file" Package)" == "$name" ]] || return 1
  [[ "$("$COGS_GIT_TOOLS_DPKG_DEB" --field "$file" Version)" == "$version" ]] || return 1
  [[ "$("$COGS_GIT_TOOLS_DPKG_DEB" --field "$file" Architecture)" == "$arch" ]] || return 1
}

cogs_git_tools_cleanup_file_identity() {
  local path=$1 dev=$2 ino=$3
  python3 - "$path" "$dev" "$ino" <<'PY' || return 0
import os,sys
path,dev,ino=sys.argv[1:]
try: st=os.lstat(path)
except FileNotFoundError: raise SystemExit(0)
if str(st.st_dev)==dev and str(st.st_ino)==ino and os.path.isfile(path) and not os.path.islink(path):
    os.unlink(path)
PY
}

cogs_git_tools_prepare_package() {
  local cache=$1 name=$2 version=$3 arch=$4 filename=$5 size=$6 url=$7 sha256=$8
  local final="$cache/$filename"
  if [[ -e "$final" || -L "$final" ]]; then
    cogs_git_tools_verify_package "$final" "$name" "$version" "$arch" "$size" "$sha256" 0400 2>/dev/null || cogs_git_tools_fail
    return 0
  fi
  local tmp
  tmp=$(mktemp "$cache/.$filename.XXXXXX.partial") || cogs_git_tools_fail
  chmod 0600 "$tmp" || { rm -f "$tmp"; cogs_git_tools_fail; }
  local tmp_identity
  tmp_identity=$(python3 - "$tmp" <<'PY'
import os,sys
st=os.lstat(sys.argv[1])
print(f"{st.st_dev} {st.st_ino}")
PY
) || { rm -f "$tmp"; cogs_git_tools_fail; }
  read -r tmp_dev tmp_ino <<<"$tmp_identity"
  "$COGS_GIT_TOOLS_CURL" --fail --location --proto '=https' --tlsv1.2 --max-time 120 --max-filesize "$size" --retry 3 --output "$tmp" "$url" >/dev/null 2>&1 || {
    cogs_git_tools_cleanup_file_identity "$tmp" "$tmp_dev" "$tmp_ino"; cogs_git_tools_fail;
  }
  cogs_git_tools_verify_package "$tmp" "$name" "$version" "$arch" "$size" "$sha256" 0600 2>/dev/null || {
    cogs_git_tools_cleanup_file_identity "$tmp" "$tmp_dev" "$tmp_ino"; cogs_git_tools_fail;
  }
  python3 - "$tmp" <<'PY' || { cogs_git_tools_cleanup_file_identity "$tmp" "$tmp_dev" "$tmp_ino"; cogs_git_tools_fail; }
import os,sys
fd=os.open(sys.argv[1], os.O_RDONLY)
try: os.fsync(fd)
finally: os.close(fd)
PY
  chmod 0400 "$tmp" || { cogs_git_tools_cleanup_file_identity "$tmp" "$tmp_dev" "$tmp_ino"; cogs_git_tools_fail; }
  ln "$tmp" "$final" || { cogs_git_tools_cleanup_file_identity "$tmp" "$tmp_dev" "$tmp_ino"; cogs_git_tools_fail; }
  cogs_git_tools_cleanup_file_identity "$tmp" "$tmp_dev" "$tmp_ino"
  cogs_git_tools_fsync_parent "$cache" || cogs_git_tools_fail
  cogs_git_tools_verify_package "$final" "$name" "$version" "$arch" "$size" "$sha256" 0400 2>/dev/null || cogs_git_tools_fail
}

cogs_git_tools_prepare_cache() {
  local cache=$1 count=0
  mkdir -p "$cache" || cogs_git_tools_fail
  chmod 0700 "$cache" || cogs_git_tools_fail
  while IFS=$'\t' read -r name version arch filename size url sha256; do
    [[ -n "$name" && -n "$sha256" ]] || cogs_git_tools_fail
    cogs_git_tools_prepare_package "$cache" "$name" "$version" "$arch" "$filename" "$size" "$url" "$sha256"
    count=$((count + 1))
  done < <(cogs_git_tools_manifest)
  [[ "$count" -eq "$COGS_GIT_PACKAGE_COUNT" ]] || cogs_git_tools_fail
}

cogs_git_tools_write_wrapper() {
  local root=$1
  mkdir -p "$root/bin" || return 1
  cat > "$root/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
export GIT_EXEC_PATH=/opt/cogs-git/usr/lib/git-core
export GIT_TEMPLATE_DIR=/opt/cogs-git/usr/share/git-core/templates
export LD_LIBRARY_PATH=/opt/cogs-git/usr/lib/x86_64-linux-gnu
exec /opt/cogs-git/usr/bin/git "$@"
EOF
  chmod 0755 "$root/bin/git" || return 1
}

cogs_git_tools_write_manifest() {
  local root=$1
  cogs_git_tools_manifest | awk -F '\t' '{print $1"\t"$2"\t"$3}' > "$root/$COGS_GIT_TOOLS_MANIFEST" || return 1
  chmod 0444 "$root/$COGS_GIT_TOOLS_MANIFEST" || return 1
}

cogs_git_tools_postwalk() {
  python3 - "$1" <<'PY'
import os,re,stat,sys
root=os.path.realpath(sys.argv[1])
allowed={"bin","usr","lib","lib64","etc","opt","var","cogs-git-tools-manifest.tsv"}
name_re=re.compile(r"^[A-Za-z0-9._+@=-]+$")
max_entries=20000
max_bytes=256*1024*1024
entries=0
bytes_seen=0
for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
    names=dirs+files
    for name in names:
        if name in ("", ".", "..") or not name_re.match(name):
            raise SystemExit(1)
        path=os.path.join(current,name)
        rel=os.path.relpath(path, root)
        first=rel.split(os.sep,1)[0]
        if first not in allowed or rel.startswith("../") or os.path.isabs(rel):
            raise SystemExit(1)
        st=os.lstat(path)
        mode=st.st_mode
        entries += 1
        if entries > max_entries or (mode & 0o022):
            raise SystemExit(1)
        if stat.S_ISREG(mode):
            bytes_seen += st.st_size
            if bytes_seen > max_bytes:
                raise SystemExit(1)
        elif stat.S_ISDIR(mode):
            pass
        elif stat.S_ISLNK(mode):
            target=os.readlink(path)
            if target.startswith('/'):
                raise SystemExit(1)
            candidate=os.path.realpath(os.path.join(os.path.dirname(path), target))
            if not (candidate == root or candidate.startswith(root + os.sep)):
                raise SystemExit(1)
        else:
            raise SystemExit(1)
if entries < 10:
    raise SystemExit(1)
PY
}

cogs_git_tools_debugfs_ownership_commands() {
  python3 - "$1" <<'PY'
import os,re,sys
root=os.path.realpath(sys.argv[1])
name_re=re.compile(r"^[A-Za-z0-9._+@=/-]+$")
paths=['/']
for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
    for name in sorted(dirs+files):
        path=os.path.join(current,name)
        rel='/' + os.path.relpath(path, root)
        if not rel.startswith('/../') and name_re.match(rel):
            paths.append(rel)
        else:
            raise SystemExit(1)
for rel in sorted(paths):
    print(f"set_inode_field {rel} uid 0")
    print(f"set_inode_field {rel} gid 0")
PY
}

cogs_git_tools_cleanup_staging() {
  local state=$1 staging=$2 image_tmp=$3
  python3 - "$state" "$staging" "$COGS_GIT_TOOLS_SENTINEL" "$image_tmp" <<'PY' || return 0
import os,shutil,stat,sys
state,staging,sentinel,tmp=sys.argv[1:]
state=os.path.realpath(state)
staging_abs=os.path.abspath(staging)
if os.path.realpath(os.path.dirname(staging_abs)) == state and os.path.basename(staging_abs) == "git-tools.staging":
    marker=os.path.join(staging_abs,sentinel)
    try: st=os.lstat(marker)
    except FileNotFoundError: st=None
    if st and stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and (st.st_mode & 0o777) == 0o600:
        shutil.rmtree(staging_abs)
tmp_abs=os.path.abspath(tmp)
if os.path.realpath(os.path.dirname(tmp_abs)) == state and os.path.basename(tmp_abs) == "git-tools.img.tmp":
    try: st=os.lstat(tmp_abs)
    except FileNotFoundError: raise SystemExit(0)
    if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid():
        os.unlink(tmp_abs)
PY
}

cogs_git_tools_verify_image_file() {
  local image=$1
  python3 - "$image" <<'PY'
import os,stat,sys
path=sys.argv[1]
st=os.lstat(path)
if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (st.st_mode & 0o777) != 0o400:
    raise SystemExit(1)
if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
    raise SystemExit(1)
if os.path.realpath(path) != os.path.abspath(path):
    raise SystemExit(1)
PY
}

cogs_git_tools_build_image() {
  local state=$1 cache=$2 image="$state/$COGS_GIT_TOOLS_IMAGE" image_tmp="$state/$COGS_GIT_TOOLS_IMAGE.tmp" staging="$state/git-tools.staging" root="$staging/root"
  [[ ! -e "$staging" && ! -L "$staging" && ! -e "$image" && ! -L "$image" && ! -e "$image_tmp" && ! -L "$image_tmp" ]] || cogs_git_tools_fail
  mkdir -p "$root" || cogs_git_tools_fail
  : > "$staging/$COGS_GIT_TOOLS_SENTINEL" || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  chmod 0600 "$staging/$COGS_GIT_TOOLS_SENTINEL" || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  while IFS=$'\t' read -r name version arch filename size url sha256; do
    local package_file="$cache/$filename"
    cogs_git_tools_verify_package "$package_file" "$name" "$version" "$arch" "$size" "$sha256" 0400 2>/dev/null || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
    "$COGS_GIT_TOOLS_DPKG_DEB" -x "$package_file" "$root" >/dev/null 2>&1 || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  done < <(cogs_git_tools_manifest)
  cogs_git_tools_write_wrapper "$root" || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  cogs_git_tools_write_manifest "$root" || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  cogs_git_tools_postwalk "$root" || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  ( set -o noclobber; : > "$image_tmp" ) || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  truncate -s "$COGS_GIT_TOOLS_SIZE" "$image_tmp" || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  "$COGS_GIT_TOOLS_MKFS" -q -F -L "$COGS_GIT_TOOLS_LABEL" -d "$root" "$image_tmp" >/dev/null 2>&1 || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  cogs_git_tools_debugfs_ownership_commands "$root" | "$COGS_GIT_TOOLS_DEBUGFS" -w -f - "$image_tmp" >/dev/null 2>&1 || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  chmod 0400 "$image_tmp" || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  ln "$image_tmp" "$image" || { cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"; cogs_git_tools_fail; }
  cogs_git_tools_cleanup_staging "$state" "$staging" "$image_tmp"
  cogs_git_tools_fsync_parent "$state" || cogs_git_tools_fail
  cogs_git_tools_verify_image_file "$image" || cogs_git_tools_fail
}

prepare_git_tools_disk() {
  local state=$1 cache=$2
  cogs_git_tools_prepare_cache "$cache"
  cogs_git_tools_build_image "$state" "$cache"
}

"""Build the additive reviewed V3 synthetic static executable on Linux/amd64."""
import hashlib
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "test/fixtures/stage2-completion/attested-static-v3.c"
EXPECTED_STDOUT = ROOT / "test/fixtures/stage2-completion/attested-ssh-output-v3.txt"
OUTPUT = Path("/tmp/cogs-stage2-attested-static-v3.elf")
SHA256 = "7c2bfd83c6c9c600eb626b74c475e0c22e1fc1b5c963203083acf3a803539247"
SIZE = 13_688
TOOLCHAIN = ("/usr/bin/clang-18", "/usr/bin/ld")


def _identity(path):
    status = path.lstat()
    if not path.is_file() or path.is_symlink() or status.st_nlink != 1:
        raise RuntimeError("reviewed V3 synthetic fixture is not one regular file")
    raw = path.read_bytes()
    if len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != SHA256:
        raise RuntimeError("reviewed V3 synthetic fixture identity differs")
    return raw


def ensure_attested_static_fixture_v3():
    """Materialize only the clang-18/GNU-ld reviewed binary identity."""
    if OUTPUT.exists() or OUTPUT.is_symlink():
        _identity(OUTPUT)
        return OUTPUT
    configured = (
        os.environ.get("COGS_STAGE2_SYNTHETIC_V3_CLANG", TOOLCHAIN[0]),
        os.environ.get("COGS_STAGE2_SYNTHETIC_V3_LD", TOOLCHAIN[1]),
    )
    if configured != TOOLCHAIN or not all(Path(path).is_file() for path in configured):
        raise RuntimeError("reviewed V3 synthetic fixture clang18/ld unavailable")
    temporary = OUTPUT.with_suffix(".building")
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("reviewed V3 synthetic fixture staging path occupied")
    try:
        result = subprocess.run([
            configured[0], "-target", "x86_64-linux-gnu", "-nostdlib", "-static",
            f"-fuse-ld={configured[1]}", "-Wl,-e,_start", "-Wl,--build-id=none", "-Os",
            "-fno-builtin", "-fno-ident", "-o", str(temporary), str(SOURCE),
        ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
           timeout=120, check=False)
        if result.returncode != 0:
            raise RuntimeError("reviewed V3 synthetic fixture build failed")
        _identity(temporary)
        os.chmod(temporary, 0o500)
        os.rename(temporary, OUTPUT)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    _identity(OUTPUT)
    return OUTPUT

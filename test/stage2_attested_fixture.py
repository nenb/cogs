"""Build the reviewed synthetic static test executable from tracked source."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "test/fixtures/stage2-completion/attested-static-v1.c"
OUTPUT = Path("/tmp/cogs-stage2-attested-static-v1.elf")
SHA256 = "195f8c4f5812eb29247a6d99882f868a0266fbb237016285da49fdf53bd7c74f"
SIZE = 5968


def ensure_attested_static_fixture():
    if OUTPUT.exists():
        raw = OUTPUT.read_bytes()
    else:
        compiler = shutil.which("clang")
        if compiler is None:
            raise RuntimeError("reviewed synthetic fixture compiler unavailable")
        temporary = OUTPUT.with_suffix(".building")
        temporary.unlink(missing_ok=True)
        try:
            result = subprocess.run([
                compiler, "-target", "x86_64-linux-gnu", "-nostdlib", "-static",
                "-fuse-ld=lld", "-Wl,-e,_start", "-Wl,--build-id=none", "-Os",
                "-fno-builtin", "-fno-ident", "-o", str(temporary), str(SOURCE),
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               timeout=30, check=False)
            if result.returncode != 0:
                raise RuntimeError("reviewed synthetic fixture build failed")
            raw = temporary.read_bytes()
            if len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != SHA256:
                raise RuntimeError("reviewed synthetic fixture bytes differ")
            os.chmod(temporary, 0o500)
            os.rename(temporary, OUTPUT)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    if len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != SHA256:
        raise RuntimeError("reviewed synthetic fixture identity differs")
    return OUTPUT

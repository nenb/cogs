"""Build the reviewed synthetic static test executable from tracked source."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "test/fixtures/stage2-completion/attested-static-v1.c"
OUTPUT = Path("/tmp/cogs-stage2-attested-static-v1.elf")
SHA256 = "6a4e31c3fe1bf1d593660b4a95fc9b21229f70abfbec00218294b47c9e3ae383"
SIZE = 13160


def ensure_attested_static_fixture():
    if OUTPUT.exists():
        raw = OUTPUT.read_bytes()
    else:
        configured = (os.environ.get("COGS_STAGE2_SYNTHETIC_CLANG"),
                      os.environ.get("COGS_STAGE2_SYNTHETIC_LLD"))
        reviewed = {
            ("/usr/bin/clang-18", "/usr/bin/ld"),
            ("/usr/bin/clang-18", "/usr/bin/ld.lld-18"),
            ("/usr/bin/clang-18", "/usr/bin/ld.lld"),
            ("/usr/lib/llvm-18/bin/clang", "/usr/lib/llvm-18/bin/ld.lld"),
            ("/usr/local/swift/usr/bin/clang", "/usr/local/swift/usr/bin/ld.lld"),
        }
        if configured == (None, None):
            native = ("/usr/bin/clang-18", "/usr/bin/ld")
            compiler, linker = native if all(Path(path).is_file() for path in native) else (shutil.which("clang"), "lld")
        elif configured in reviewed:
            compiler, linker = configured
        else:
            raise RuntimeError("reviewed synthetic fixture toolchain invalid")
        if compiler is None:
            raise RuntimeError("reviewed synthetic fixture compiler unavailable")
        temporary = OUTPUT.with_suffix(".building")
        temporary.unlink(missing_ok=True)
        try:
            result = subprocess.run([
                compiler, "-target", "x86_64-linux-gnu", "-nostdlib", "-static",
                f"-fuse-ld={linker}", "-Wl,-e,_start", "-Wl,--build-id=none", "-Os",
                "-fno-builtin", "-fno-ident", "-o", str(temporary), str(SOURCE),
            ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
               timeout=120, check=False)
            if result.returncode != 0:
                raise RuntimeError("reviewed synthetic fixture build failed")
            raw = temporary.read_bytes()
            actual_sha256 = hashlib.sha256(raw).hexdigest()
            if len(raw) != SIZE or actual_sha256 != SHA256:
                raise RuntimeError("reviewed synthetic fixture bytes differ")
            os.chmod(temporary, 0o500)
            os.rename(temporary, OUTPUT)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    if len(raw) != SIZE or hashlib.sha256(raw).hexdigest() != SHA256:
        raise RuntimeError("reviewed synthetic fixture identity differs")
    return OUTPUT

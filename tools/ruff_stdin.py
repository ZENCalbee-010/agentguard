"""Run ruff lint + format by piping files through stdin.

Local workaround for blocker BLK-001: on the development machine the native ruff binary
receives "Access is denied (os error 5)" when opening files under C:/your-project, while
reading the same content via stdin works. CI runs ruff directly and does not need this.

Usage: python tools/ruff_stdin.py [--fix] [paths...]   (default paths: src tests tools)
Without --fix: exit code is non-zero if any file has lint findings or would be reformatted.
With --fix: applies safe lint fixes and formatting in place, then reports what remains.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _ruff() -> str:
    exe = Path(sys.executable).parent / ("ruff.exe" if sys.platform == "win32" else "ruff")
    found = str(exe) if exe.exists() else shutil.which("ruff")
    if not found:
        raise SystemExit("ruff not found in the active environment")
    return found


def _run(ruff: str, args: list[str], source: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603 - fixed local executable, no shell
        [ruff, *args], input=source, capture_output=True, cwd=ROOT, check=False
    )


def _lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def main(argv: list[str]) -> int:
    fix = "--fix" in argv
    paths = [a for a in argv if a != "--fix"] or ["src", "tests", "tools"]
    targets = [ROOT / p for p in paths]
    files = sorted(
        f for t in targets for f in ([t] if t.is_file() else t.rglob("*.py")) if f.suffix == ".py"
    )
    ruff = _ruff()
    failed = 0
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        source = f.read_bytes()
        if fix:
            fixed = _run(
                ruff, ["check", "--fix", "--no-cache", "--stdin-filename", rel, "-"], source
            )
            candidate = fixed.stdout or source
            formatted = _run(
                ruff, ["format", "--no-cache", "--stdin-filename", rel, "-"], candidate
            )
            result = (
                formatted.stdout if formatted.returncode == 0 and formatted.stdout else candidate
            )
            if _lf(result) != _lf(source):
                f.write_bytes(_lf(result))
            source = f.read_bytes()
        lint = _run(ruff, ["check", "--no-cache", "--stdin-filename", rel, "-"], source)
        if lint.returncode != 0:
            failed += 1
            sys.stdout.flush()
            sys.stdout.buffer.write(lint.stdout)  # bytes: console encodings may not cover test data
            sys.stdout.buffer.flush()
        fmt = _run(ruff, ["format", "--no-cache", "--stdin-filename", rel, "-"], source)
        if fmt.returncode != 0 or _lf(fmt.stdout) != _lf(source):
            failed += 1
            print(f"would reformat: {rel}")
    print(f"ruff (stdin mode): {len(files)} files checked, {failed} problem(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

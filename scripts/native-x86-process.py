#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys


def main():
    raven, fixture = map(Path, sys.argv[1:])
    output = fixture.with_suffix(".out")
    with output.open("wb") as stdout:
        result = subprocess.run([str(raven), "--run-process", "--execution=native", "--stdio=inherit", str(fixture)],
                                stdout=stdout, stderr=subprocess.PIPE, timeout=20)
    written = output.read_bytes()
    output.unlink()
    if result.returncode != 73 or written != b"x86 native\n" or result.stderr:
        raise RuntimeError(f"x86 process: status {result.returncode}, {written!r}, {result.stderr!r}")
    print("PE32 process ran in compatibility mode: Win32 environment, handles, WriteFile and ExitProcess status verified")


if __name__ == "__main__":
    main()

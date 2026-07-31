#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys


def main():
    raven, directory = map(Path, sys.argv[1:])
    for status, expected in [(0, 0), (73, 73), (256, 1)]:
        path = directory / f"return-{status}.exe"
        result = subprocess.run([str(raven), "--run-process", "--execution=native", str(path)],
                                capture_output=True, text=True, timeout=15)
        if result.returncode != expected or result.stderr or f"Native entry returned {status} " not in result.stdout:
            raise RuntimeError(f"process status {status}: {result.returncode}, {result.stdout!r}, {result.stderr!r}")
    result = subprocess.run([str(raven), "--run-entry", "--execution=native", str(directory / "return-73.exe")],
                            capture_output=True, text=True, timeout=15)
    if result.returncode or result.stderr or "Native entry returned 73 " not in result.stdout:
        raise RuntimeError("bare function inspection lost its result/status distinction")
    print("Native process returns preserve nonzero status, including a zero low byte")


if __name__ == "__main__":
    main()

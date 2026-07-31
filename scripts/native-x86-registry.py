#!/usr/bin/env python3

from pathlib import Path
import shutil
import subprocess
import sys


def run(raven, program, prefix, expected=0):
    env = {"RAVEN_PREFIX": str(prefix), "PATH": "/usr/bin:/bin"}
    result = subprocess.run([str(raven), "--run-process", "--execution=native", str(program)],
                            capture_output=True, text=True, timeout=20, env=env)
    if result.returncode != (expected and 11 or 0) or result.stderr or f"Native entry returned {expected} " not in result.stdout:
        raise RuntimeError(f"{program.name}: {result.returncode}, {result.stdout!r}, {result.stderr!r}")


def main():
    raven, writer, reader, prefix = map(Path, sys.argv[1:])
    shutil.rmtree(prefix, ignore_errors=True)
    # A fresh prefix holds no state: the reader fails its open check (status 11) before any writer runs.
    run(raven, reader, prefix, expected=11)
    run(raven, writer, prefix)
    hive = (prefix / "registry.dat").read_text().splitlines()
    wanted = {
        "K\tHKEY_CURRENT_USER\\\\Software\\\\Raven\\\\Contract",
        "V\tHKEY_CURRENT_USER\\\\Software\\\\Raven\\\\Contract\tCount\t4\tcdab3412",
        "V\tHKEY_CURRENT_USER\\\\Software\\\\Raven\\\\Contract\tName\t1\t72006100760065006e000000",
    }
    if not wanted.issubset(set(hive)):
        raise RuntimeError(f"hive differs from the independent expectation: {hive!r}")
    run(raven, reader, prefix)
    print("Registry values written by one PE32 process persisted on disk and were read by a fresh process")


if __name__ == "__main__":
    main()

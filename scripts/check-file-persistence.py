#!/usr/bin/env python3
"""Check from the host side that the kernel file fixture left exactly the file it was meant to keep.

usage: check-file-persistence.py PREFIX
"""

from pathlib import Path
import os
import sys


def main():
    prefix = Path(sys.argv[1])
    user = os.environ.get("USER", "user")
    directory = prefix / "drive_c" / "Users" / user / "AppData" / "Local" / "Temp" / "raven-file-test"
    entries = sorted(item.name for item in directory.iterdir())
    if entries != ["persist.txt"]:
        raise SystemExit(f"unexpected files after the guest cleaned up: {entries}")
    content = (directory / "persist.txt").read_bytes()
    if content != b"persisted by raven\n":
        raise SystemExit(f"persisted content differs: {content!r}")
    print("The guest's file landed in the prefix with the exact bytes it wrote")


main()

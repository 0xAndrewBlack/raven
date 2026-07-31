#!/usr/bin/env python3

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def provision(destination, manifest):
    destination.mkdir(parents=True, exist_ok=True)
    installed = []
    for component, package in manifest.items():
        archive = destination / package["archive"]
        if not archive.exists():
            partial = archive.with_suffix(archive.suffix + ".partial")
            created = False
            try:
                with partial.open("xb") as output:
                    created = True
                    received = 0
                    with urllib.request.urlopen(package["url"], timeout=45) as response:
                        while chunk := response.read(1024 * 1024):
                            received += len(chunk)
                            if received > package["size"]:
                                raise RuntimeError(f"archive exceeds pinned size: {component}")
                            output.write(chunk)
                if digest(partial) != package["sha256"]:
                    raise RuntimeError(f"archive checksum mismatch: {component}")
                partial.rename(archive)
            finally:
                if created:
                    partial.unlink(missing_ok=True)
        if digest(archive) != package["sha256"]:
            raise RuntimeError(f"cached archive checksum mismatch: {component}")

        expected = {
            f'{package["archive_root"]}/{folder}/{dll}': (architecture, dll)
            for architecture, folder in package["architectures"].items()
            for dll in package["dlls"]
        }
        if archive.suffix == ".zst":
            decoded = subprocess.run(["zstd", "-dc", str(archive)], check=True, capture_output=True)
            source = tarfile.open(fileobj=io.BytesIO(decoded.stdout), mode="r:")
        else:
            source = tarfile.open(archive, mode="r:gz")
        with source:
            found = set()
            for member in source:
                if member.name not in expected:
                    continue
                if not member.isfile() or member.name in found:
                    raise RuntimeError(f"invalid DLL archive entry: {member.name}")
                architecture, dll = expected[member.name]
                with source.extractfile(member) as data:
                    content = data.read()
                actual = hashlib.sha256(content).hexdigest()
                target = destination / component / architecture / dll
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if digest(target) != actual:
                        raise RuntimeError(f"cached DLL differs: {target}")
                else:
                    with target.open("xb") as output:
                        output.write(content)
                installed.append({"component": component, "version": package["version"],
                                  "architecture": architecture, "path": str(target.relative_to(destination)),
                                  "sha256": actual})
                found.add(member.name)
            if found != expected.keys():
                raise RuntimeError(f"missing DLLs in {component}: {sorted(expected.keys() - found)}")
        print(f'{component} {package["version"]}: {len(found)} DLLs verified')
    (destination / "installed.json").write_text(json.dumps(installed, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Provision pinned Raven graphics DLLs without installing into a prefix")
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args()
    manifest_path = Path(__file__).resolve().parent.parent / "native/graphics/backends.json"
    try:
        provision(arguments.destination.resolve(), json.loads(manifest_path.read_text()))
    except (OSError, RuntimeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"graphics provisioning failed: {error}\n")


if __name__ == "__main__":
    main()

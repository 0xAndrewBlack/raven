#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess


def compare(raven, llvm, path):
    native = subprocess.run([str(raven), "--inspect-imports", str(path)],
                            capture_output=True, text=True, check=True, timeout=30)
    reference = subprocess.run([str(llvm), "--coff-imports", "--file-headers", str(path)],
                               capture_output=True, text=True, check=True, timeout=30)
    lines = native.stdout.splitlines()
    header = re.fullmatch(r"PE(32|64) base=(0x[0-9a-f]+) entry=(0x[0-9a-f]+) size=(0x[0-9a-f]+) sections=(\d+) imports=(\d+)", lines[0])
    if not header:
        raise RuntimeError(f"invalid native inspection output: {path}")
    fields = ["AddressSize", "ImageBase", "AddressOfEntryPoint", "SizeOfImage", "SectionCount"]
    for index, field in enumerate(fields):
        match = re.search(r"^\s*" + field + r": (0x[0-9A-Fa-f]+|\d+)", reference.stdout, re.M)
        if not match or int(match[1], 0) != int(header[index + 1], 0):
            raise RuntimeError(f"native/LLVM {field} mismatch: {path}")
    symbols = []
    for block in re.findall(r"^Import \{\n(.*?)^\}", reference.stdout, re.M | re.S):
        module = re.search(r"^\s*Name: (.+)$", block, re.M)
        if not module:
            raise RuntimeError(f"missing LLVM import module: {path}")
        for name, ordinal in re.findall(r"^\s*Symbol: (.*?) \((\d+)\)$", block, re.M):
            symbols.append(module[1] + "!" + (name if name else "#" + ordinal))
    if lines[1:] != symbols or int(header[6]) != len(symbols):
        raise RuntimeError(f"native/LLVM import identity mismatch: {path}")
    with path.open("rb") as source:
        checksum = hashlib.file_digest(source, "sha256").hexdigest()
    return {"path": str(path), "sha256": checksum, "bits": int(header[1]),
            "imports": len(symbols), "symbols": symbols, "result": "PASS"}


def compare_images(raven, llvm, path):
    reference = subprocess.run([str(llvm), "--file-headers", "--sections", "--coff-basereloc", str(path)],
                               capture_output=True, text=True, check=True, timeout=30).stdout

    def field(text, name):
        match = re.search(r"^\s*" + name + r": (0x[0-9A-Fa-f]+|\d+)", text, re.M)
        if not match:
            raise RuntimeError(f"missing LLVM {name}: {path}")
        return int(match[1], 0)

    preferred = field(reference, "ImageBase")
    size = field(reference, "SizeOfImage")
    headers = field(reference, "SizeOfHeaders")
    file = path.read_bytes()
    original = bytearray(size)
    original[:headers] = file[:headers]
    for section in re.findall(r"^  Section \{\n(.*?)^  \}", reference, re.M | re.S):
        address = field(section, "VirtualAddress")
        offset = field(section, "PointerToRawData")
        length = field(section, "RawDataSize")
        original[address:address + length] = file[offset:offset + length]
    fixups = []
    for entry in re.findall(r"^  Entry \{\n(.*?)^  \}", reference, re.M | re.S):
        kind = re.search(r"^\s*Type: (\w+)$", entry, re.M)[1]
        if kind == "ABSOLUTE":
            continue
        if kind not in ["HIGHLOW", "DIR64"]:
            raise RuntimeError(f"reference has an untested relocation type {kind}: {path}")
        fixups.append((field(entry, "Address"), 8 if kind == "DIR64" else 4))
    relocatable = field(reference, "BaseRelocationTableSize") > 0 and "IMAGE_FILE_RELOCS_STRIPPED" not in reference
    results = []
    for base in ([preferred, preferred + 65536, preferred - 65536] if relocatable else [preferred]):
        expected = original.copy()
        if base != preferred:
            for address, width in fixups:
                value = int.from_bytes(expected[address:address + width], "little")
                value = (value + base - preferred) % (1 << (width * 8))
                expected[address:address + width] = value.to_bytes(width, "little")
        actual = subprocess.run([str(raven), "--dump-image", str(path), hex(base)],
                                capture_output=True, check=True, timeout=30).stdout
        if actual != expected:
            raise RuntimeError(f"loaded image bytes differ from LLVM-based reference at {hex(base)}: {path}")
        results.append({"base": hex(base), "size": len(actual),
                        "relocations": len(fixups) if base != preferred else 0,
                        "sha256": hashlib.sha256(actual).hexdigest(), "result": "PASS"})
    if not relocatable:
        rejected = subprocess.run([str(raven), "--dump-image", str(path), hex(preferred + 65536)],
                                  capture_output=True, timeout=30)
        if rejected.returncode != 1 or rejected.stdout:
            raise RuntimeError(f"fixed-base image was silently rebased: {path}")
    return results


def compare_exports(raven, llvm, path):
    native = subprocess.run([str(raven), "--inspect-exports", str(path)],
                            capture_output=True, text=True, check=True, timeout=30).stdout
    reference = subprocess.run([str(llvm), "--coff-exports", "--file-headers", "--sections", str(path)],
                               capture_output=True, text=True, check=True, timeout=30).stdout
    actual = []
    for line in native.splitlines()[1:]:
        values = shlex.split(line)
        if len(values) < 3:
            raise RuntimeError(f"invalid native export output: {path}")
        actual.append(dict(ordinal=int(values[0]), address=int(values[1], 0), forwarder=values[2], names=values[3:]))

    def field(text, name):
        match = re.search(r"^\s*" + name + r": (0x[0-9A-Fa-f]+|\d+)", text, re.M)
        if not match:
            raise RuntimeError(f"missing LLVM {name}: {path}")
        return int(match[1], 0)

    directory = field(reference, "ExportTableRVA")
    size = field(reference, "ExportTableSize")
    sections = [(field(section, "VirtualAddress"), field(section, "PointerToRawData"), field(section, "RawDataSize"))
                for section in re.findall(r"^  Section \{\n(.*?)^  \}", reference, re.M | re.S)]
    data = path.read_bytes()

    def read_rva(address, length):
        if address < field(reference, "SizeOfHeaders"):
            return data[address:address + length]
        for start, offset, size in sections:
            if start <= address and address + length <= start + size:
                position = offset + address - start
                return data[position:position + length]
        raise RuntimeError(f"reference RVA has no file data: {path}")

    expected = []
    for block in re.findall(r"^Export \{\n(.*?)^\}", reference, re.M | re.S):
        ordinal = field(block, "Ordinal")
        forwarded = re.search(r"^\s*ForwardedTo: (.+)$", block, re.M)
        if forwarded:
            base = int.from_bytes(read_rva(directory + 16, 4), "little")
            table = int.from_bytes(read_rva(directory + 28, 4), "little")
            address = int.from_bytes(read_rva(table + (ordinal - base) * 4, 4), "little")
        else:
            address = field(block, "RVA")
        name = re.search(r"^\s*Name: ?(.*)$", block, re.M)[1]
        forwarder = ""
        if directory <= address < directory + size:
            for start, offset, length in sections:
                if start <= address < start + length:
                    position = offset + address - start
                    limit = min(offset + length, position + directory + size - address)
                    end = data.find(b"\0", position, limit)
                    if end < 0:
                        raise RuntimeError(f"unterminated reference forwarder: {path}")
                    forwarder = data[position:end].decode("ascii")
                    break
            else:
                raise RuntimeError(f"reference forwarder has no file section: {path}")
        if forwarded and forwarder != forwarded[1]:
            raise RuntimeError(f"reference forwarder string differs from LLVM: {path}")
        expected.append(dict(ordinal=ordinal, address=address, forwarder=forwarder,
                             names=[name] if name else []))
    if actual != expected:
        raise RuntimeError(f"native/LLVM export identities or forwarders differ: {path}")
    return actual


def main():
    parser = argparse.ArgumentParser(description="Compare Raven PE inspection with LLVM")
    parser.add_argument("--raven", type=Path, required=True)
    parser.add_argument("--llvm-readobj", type=Path, required=True)
    parser.add_argument("--graphics", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, action="append", default=[])
    parser.add_argument("--images", action="store_true", help="Compare every loaded byte at preferred and alternate bases")
    parser.add_argument("--exports", action="store_true", help="Compare export ordinals, names, addresses and forwarders")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    manifest = json.loads((repo / "native/graphics/backends.json").read_text())
    paths = [args.graphics / component / architecture / dll
             for component, package in manifest.items()
             for architecture in package["architectures"]
             for dll in package["dlls"]]
    paths += [repo / "testdata/winmine/WINMINE.EXE", repo / "testdata/notepad.exe"]
    paths += args.fixture
    results = []
    try:
        for path in paths:
            result = compare(args.raven, args.llvm_readobj, path)
            if args.images:
                result["loaded_images"] = compare_images(args.raven, args.llvm_readobj, path)
            if args.exports:
                result["exports"] = compare_exports(args.raven, args.llvm_readobj, path)
            results.append(result)
            print(f'{path.name}: PE{result["bits"]}, {result["imports"]} exact imports match LLVM')
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        args.report.write_text(json.dumps({"result": "FAIL", "error": str(error), "files": results}, indent=2) + "\n")
        parser.exit(1, f"native PE regression failed: {error}\n")
    args.report.write_text(json.dumps({"result": "PASS", "files": results}, indent=2) + "\n")
    print(f"{len(results)} binaries matched; execution and rendering are outside this check")


if __name__ == "__main__":
    main()

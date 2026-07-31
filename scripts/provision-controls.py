#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import urllib.request


REVISION = "dacf2a6c47fa562799f9c8a41ab6d5c558556558"
ARCHIVE_SHA256 = "5373bbbb60541cb2a49e0acb53360e1218d4f5d56c31f9187b341b9fc16daa69"
PREFIXES = ("sdk/include/", "sdk/lib/pseh/include/", "sdk/tools/hpp/", "sdk/tools/spec2def/", "dll/win32/comctl32/",
            "win32ss/include/", "win32ss/user/user32/", "win32ss/user/rtl/")
# Upstream user-mode sources of the user32 component, and the exports they define that user32 programs import.
USER32_SOURCES = ("controls/button.c", "controls/combo.c", "controls/edit.c", "controls/listbox.c", "controls/static.c",
                  "windows/dialog.c", "windows/draw.c", "windows/font.c", "windows/text.c")
IDLS = ("shtypes", "commoncontrols")


def main():
    parser = argparse.ArgumentParser(description="Build the pinned selective ReactOS common controls component")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, TMPDIR=str(output), TMP=str(output), TEMP=str(output))
    repo = Path(__file__).resolve().parents[1]
    archive = args.archive.resolve() if args.archive else output / "reactos-source.tar.gz"
    if not archive.exists():
        urllib.request.urlretrieve(f"https://codeload.github.com/reactos/reactos/tar.gz/{REVISION}", archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise RuntimeError("ReactOS source archive checksum differs")
    source = output / "source"
    shutil.rmtree(source, ignore_errors=True)
    with tarfile.open(archive) as upstream:
        for member in upstream:
            parts = Path(member.name).parts[1:]
            name = "/".join(parts)
            if not member.isfile() or not name.startswith(PREFIXES):
                continue
            if not parts or ".." in parts or Path(name).is_absolute():
                raise RuntimeError("invalid upstream archive path")
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(upstream.extractfile(member).read())
    for tool in ("clang", "x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-windres", "widl"):
        if not shutil.which(tool):
            raise RuntimeError(f"required controls build tool is missing: {tool}")
    records = []

    def run(command, cwd=None):
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
        records.append(dict(command=[str(part) for part in command], returncode=result.returncode))
        if result.returncode:
            raise RuntimeError(result.stderr or "controls build command failed: " + " ".join(map(str, command)))
        return result

    generated = output / "generated"
    shutil.rmtree(generated, ignore_errors=True)
    (generated / "psdk").mkdir(parents=True)
    (generated / "reactos").mkdir()
    run(["clang", "-O2", "-w", source / "sdk/tools/hpp/hpp.c", "-o", output / "hpp"])
    run(["clang", "-O1", "-w", source / "sdk/tools/spec2def/spec2def.c", "-o", output / "spec2def"])
    for name in ("winnt", "ntdef", "devioctl"):
        run([output / "hpp", name + ".template.h", generated / "psdk" / (name + ".h")], source / "sdk/include/xdk")
    idls = set()

    def idl(name):
        if name in idls:
            return
        idls.add(name)
        path = source / "sdk/include/psdk" / (name + ".idl")
        for dependency in re.findall(r'import\s+"([^"]+)\.idl"', path.read_text()):
            idl(dependency)
        run(["widl", "-m64", "-h", "-H", generated / "psdk" / (name + ".h"), "-I", path.parent, path])

    for name in ("objidl", "oleidl", "urlmon", "propidl", "wtypes", "objidlbase") + IDLS:
        idl(name)
    # The version headers are configure-time templates upstream; the component pins their values.
    version = (source / "sdk/include/reactos/version.h.cmake").read_text()
    for key, value in (("KERNEL_VERSION_MAJOR", "0"), ("KERNEL_VERSION_MINOR", "4"), ("KERNEL_VERSION_PATCH_LEVEL", "17"), ("COPYRIGHT_YEAR", "2026")):
        version = version.replace("@" + key + "@", value)
    (generated / "version.h").write_text(version)
    (generated / "reactos/version.h").write_text(version)
    buildno = (source / "sdk/include/reactos/buildno.h.cmake").read_text()
    for key, value in (("KERNEL_VERSION_BUILD", "custom"), ("REVISION", REVISION[:7]), ("KERNEL_VERSION", "0.4.17-dev"), ("COMMIT_HASH", REVISION),
                       ("REACTOS_DLL_VERSION_MAJOR", "42"), ("DLL_VERSION_STR", "42.4.17-dev"), ("CMAKE_C_COMPILER_ID", "GNU"), ("CMAKE_C_COMPILER_VERSION", "13")):
        buildno = buildno.replace("@" + key + "@", value)
    (generated / "reactos/buildno.h").write_text(buildno)
    # The Wine-compat header overlay sits one directory below its psdk siblings upstream.
    overlay = source / "sdk/include/reactos/wine"
    shutil.copytree(source / "sdk/include/wine", overlay, dirs_exist_ok=True)
    gcc_include = run(["x86_64-w64-mingw32-gcc", "-print-file-name=include"]).stdout.strip()
    includes = [source / "dll/win32/comctl32", generated, generated / "psdk", source / "sdk/lib/pseh/include", source / "sdk/include/vcruntime",
                overlay, source / "sdk/include/psdk", source / "sdk/include/crt", source / "sdk/include/ndk", source / "sdk/include",
                source / "sdk/include/reactos", source / "sdk/include/ddk"]
    flags = ["-O2", "-nostdinc", "-isystem", gcc_include, "-fgnu89-inline", "-w", "-D_WIN32_WINNT=0x600", "-DWINVER=0x600", "-D_WIN32_IE=0x0A00",
             "-D__REACTOS__", "-DUNICODE", "-D_UNICODE", "-D_M_AMD64", "-D__WINESRC__", "-D_WINE", "-D__ROS_LONG64__", "-D_COMCTL32_",
             f"-ffile-prefix-map={source}=reactos", f"-ffile-prefix-map={repo}=raven", f"-ffile-prefix-map={output}=component",
             *["-I" + str(path) for path in includes]]
    support = repo / "native/upstream/reactos-controls"
    objects = output / "objects"
    shutil.rmtree(objects, ignore_errors=True)
    objects.mkdir()
    sources = sorted((source / "dll/win32/comctl32").glob("*.c")) + [support / "crt.c", support / "debug.c", support / "guids.c"]

    def compile(path):
        name = path.stem if path.parent == support else "comctl32_" + path.stem
        freestanding = ["-ffreestanding", "-fno-builtin"] if path.name == "crt.c" else []
        run(["x86_64-w64-mingw32-gcc", "-c", *flags, *freestanding, path, "-o", objects / (name + ".o")])
        return objects / (name + ".o")

    with ThreadPoolExecutor(max_workers=2) as pool:
        compiled = list(pool.map(compile, sources))
    run([output / "spec2def", "-a=x86_64", "-n=comctl32.dll", "-d=" + str(output / "comctl32.def"), source / "dll/win32/comctl32/comctl32.spec"])
    # Programs import this version 6 function by ordinal; the pinned specification leaves the implemented function unexported.
    with (output / "comctl32.def").open("a") as definition:
        definition.write(" LoadIconWithScaleDown @381\n")
    wrapper = output / "resource-preprocessor.sh"
    wrapper.write_text("#!/bin/sh\nexec x86_64-w64-mingw32-gcc -E -xc -DRC_INVOKED -nostdinc -isystem " + gcc_include + " " +
                       " ".join("-I" + str(path) for path in includes[1:] + [generated / "reactos"]) + ' -w "$@"\n')
    wrapper.chmod(0o755)
    run(["x86_64-w64-mingw32-windres", "--preprocessor=" + str(wrapper), "-O", "coff", "-DLANGUAGE_EN_US", "-D__REACTOS__", "-D_WIN32_IE=0x0A00",
         "-D__WINESRC__", "-D_M_AMD64", "-I" + str(source / "dll/win32/comctl32"), "-I" + str(generated / "reactos"),
         "-i", source / "dll/win32/comctl32/rsrc.rc", "-o", objects / "comctl32.res.o"])
    run(["x86_64-w64-mingw32-gcc", "-shared", "-nostdlib", "-Wl,--entry,DllMain,--image-base,0x1f0000000,--no-insert-timestamp",
         "-o", output / "comctl32.dll", *compiled, objects / "comctl32.res.o", output / "comctl32.def",
         "-luser32", "-lgdi32", "-ladvapi32", "-lkernel32", "-lntdll", "-limm32", "-lusp10", "-luxtheme", "-lwinmm",
         "-lole32", "-loleaut32", "-lshlwapi", "-luuid", "-lgcc"])
    # The user32 component: upstream user-mode sources on a bridge that stands in for the kernel services.
    user_support = repo / "native/upstream/reactos-user32"
    user_root = source / "win32ss/user/user32"
    user_includes = [user_support / "shim", source / "win32ss/include", user_root / "include", *includes[1:]]
    user_flags = ["-O2", "-nostdinc", "-isystem", gcc_include, "-fgnu89-inline", "-w", "-D_WIN32_WINNT=0x600", "-DWINVER=0x600",
                  "-D__REACTOS__", "-DUNICODE", "-D_UNICODE", "-D_M_AMD64", "-D__ROS_LONG64__", "-DUSE_PSEH",
                  f"-ffile-prefix-map={source}=reactos", f"-ffile-prefix-map={repo}=raven", f"-ffile-prefix-map={output}=component",
                  *["-I" + str(path) for path in user_includes]]
    user_sources = [user_root / name for name in USER32_SOURCES] + [source / "win32ss/user/rtl/text.c",
                    user_support / "bridge.c", user_support / "register.c", support / "crt.c", support / "debug.c"]

    def compile_user(path):
        name = "user32_" + (path.parent.name + "_" if path.parent.name in ("windows", "controls", "rtl") else "") + path.stem
        freestanding = ["-ffreestanding", "-fno-builtin"] if path.name == "crt.c" else []
        run(["x86_64-w64-mingw32-gcc", "-c", *user_flags, *freestanding, path, "-o", objects / (name + ".o")])
        return objects / (name + ".o")

    with ThreadPoolExecutor(max_workers=2) as pool:
        user_objects = list(pool.map(compile_user, user_sources))
    run([output / "spec2def", "-a=x86_64", "-n=user32.dll", "-d=" + str(output / "user32.def"), user_root / "user32.spec"])
    public = {match.group(1) for match in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s|=|@|$)", (output / "user32.def").read_text(), re.M)}
    defined = {line.split()[-1] for line in run(["x86_64-w64-mingw32-nm", "-g", "--defined-only", *user_objects]).stdout.splitlines()
               if len(line.split()) == 3 and line.split()[1] in "TtDdBbRr"}
    # FrameRect and FillRect keep the measured host behavior (error codes for invalid brushes and device contexts).
    exported = sorted((public & defined) - {"EXPORTS", "NAME", "FrameRect", "FillRect"})
    (output / "raven-user32.def").write_text("NAME raven-user32.dll\nEXPORTS\n" + "".join(" " + name + "\n" for name in exported) + " RavenInitControls\n")
    run(["x86_64-w64-mingw32-gcc", "-shared", "-nostdlib", "-Wl,--entry,DllMain,--image-base,0x1f4000000,--no-insert-timestamp",
         "-o", output / "raven-user32.dll", *user_objects, output / "raven-user32.def",
         "-luser32", "-lgdi32", "-ladvapi32", "-lkernel32", "-lntdll", "-limm32", "-lusp10", "-lgcc"])
    result = dict(revision=REVISION, archive_sha256=ARCHIVE_SHA256, commands=records,
                  component_sha256={name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in ("comctl32.dll", "raven-user32.dll")},
                  user32_exports=exported,
                  source_hashes={path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in sorted(source.rglob("*")) if path.is_file() and not path.is_relative_to(overlay)})
    (output / "provenance.json").write_text(json.dumps(result, indent=2) + "\n")
    print(output / "comctl32.dll")


if __name__ == "__main__":
    main()

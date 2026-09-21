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


# The ReactOS revision the common controls component is built from: one archive serves both.
REVISION = "dacf2a6c47fa562799f9c8a41ab6d5c558556558"
ARCHIVE_SHA256 = "5373bbbb60541cb2a49e0acb53360e1218d4f5d56c31f9187b341b9fc16daa69"
PREFIXES = ("sdk/include/", "sdk/lib/pseh/", "sdk/tools/hpp/", "sdk/tools/spec2def/", "sdk/lib/3rdparty/zlib/", "sdk/lib/3rdparty/libwine/",
            "dll/win32/cabinet/", "dll/win32/msi/", "dll/win32/sxs/", "dll/win32/ole32/", "dll/win32/coml2/")
# Interface headers the installer sources include, generated from the public IDL files with what they import.
IDLS = ("objidlbase", "commoncontrols", "fusion", "msxml2", "oaidl", "ocidl", "objidl", "unknwn", "wtypes", "propidl", "urlmon", "shobjidl", "servprov", "docobj", "oleidl",
        "exdisp", "activscp", "shldisp", "mshtml", "xmldom", "imnact", "msctf", "shtypes", "oleacc", "comcat", "mscoree", "wincodec", "dispex",
        "atliface", "winsxs")
ZLIB = ("adler32.c", "crc32.c", "deflate.c", "inflate.c", "inffast.c", "inftrees.c", "trees.c", "zutil.c")
# The structured storage of ole32 and its base layer, coml2: compound files, their streams and property sets.
STORAGE = ("ole32/storage32.c", "ole32/stg_prop.c", "ole32/stg_stream.c", "ole32/filelockbytes.c", "ole32/dictionary.c",
           "coml2/memlockbytes.c", "coml2/stg_prop.c", "coml2/storage32.c")
COMPONENTS = ("cabinet.dll", "sxs.dll", "msi.dll", "raven-storage.dll")


def main():
    parser = argparse.ArgumentParser(description="Build the pinned ReactOS Windows Installer components: msi, cabinet, sxs and structured storage")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--arch", choices=("x64", "x86"), default="x64", help="build the 64-bit components, or the 32-bit ones for PE32 programs")
    args = parser.parse_args()
    x86 = args.arch == "x86"
    triple = "i686-w64-mingw32" if x86 else "x86_64-w64-mingw32"
    spec_arch = "-a=i386" if x86 else "-a=x86_64"
    entry_point = "_DllMain@12" if x86 else "DllMain"
    link_extra = ["-Wl,--kill-at"] if x86 else []
    bases = dict(cabinet=0x1e000000, sxs=0x1e200000, msi=0x1e400000, storage=0x1ec00000) if x86 else dict(
        cabinet=0x1e0000000, sxs=0x1e2000000, msi=0x1e4000000, storage=0x1ec000000)
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
    for tool in ("clang", triple + "-gcc", "widl", "bison"):
        if not shutil.which(tool):
            raise RuntimeError(f"required installer build tool is missing: {tool}")
    records = []

    def run(command, cwd=None):
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
        records.append(dict(command=[str(part) for part in command], returncode=result.returncode))
        if result.returncode:
            raise RuntimeError(result.stderr or "installer build command failed: " + " ".join(map(str, command)))
        return result

    def decorated(object_files):
        """Defined global functions of the objects by plain name, with their stdcall argument bytes on 32 bits (None for the others)."""
        names = {}
        for line in run([triple + "-nm", "-g", "--defined-only", *object_files]).stdout.splitlines():
            parts = line.split()
            if len(parts) != 3 or parts[1] not in "Tt":
                continue
            symbol = parts[2]
            if x86:
                match = re.fullmatch(r"_(\w+)@(\d+)", symbol)
                if match:
                    names[match.group(1)] = int(match.group(2))
                elif symbol.startswith("_"):
                    names.setdefault(symbol[1:], None)
            else:
                names[symbol] = None
        return names

    # Raven's corrections to upstream behavior are kept as reviewable patches and recorded in the provenance.
    support = repo / "native/upstream/reactos-installer"
    patches = sorted((support / "patches").glob("*.patch"))
    for patch in patches:
        run(["patch", "-p1", "--forward", "--silent", "-i", patch], source)
    generated = output / "generated"
    shutil.rmtree(generated, ignore_errors=True)
    (generated / "psdk").mkdir(parents=True)
    (generated / "reactos").mkdir()
    run(["clang", "-O2", "-w", source / "sdk/tools/hpp/hpp.c", "-o", output / "hpp"])
    run(["clang", "-O1", "-w", source / "sdk/tools/spec2def/spec2def.c", "-o", output / "spec2def"])
    for name in ("winnt", "ntdef", "devioctl"):
        run([output / "hpp", name + ".template.h", generated / "psdk" / (name + ".h")], source / "sdk/include/xdk")
    widl = ["widl", "-m32" if x86 else "-m64", "-I", source / "sdk/include/psdk", "-I", source / "sdk/include", "-I", generated / "psdk"]
    idls = set()

    def idl(name):
        path = source / "sdk/include/psdk" / (name + ".idl")
        if name in idls or not path.exists():
            return
        idls.add(name)
        for dependency in re.findall(r'import\s+"([^"]+)\.idl"', path.read_text()):
            idl(dependency)
        run([*widl, "-h", "-H", generated / "psdk" / (name + ".h"), path])

    for name in IDLS:
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
    # The Wine-compat header overlay sits one directory below its psdk siblings upstream; Wine modules see it first.
    overlay = source / "sdk/include/reactos/wine"
    shutil.copytree(source / "sdk/include/wine", overlay, dirs_exist_ok=True)
    gcc_include = run([triple + "-gcc", "-print-file-name=include"]).stdout.strip()
    includes = [generated, generated / "psdk", source / "sdk/lib/pseh/include", source / "sdk/include/vcruntime", overlay, source / "sdk/include/psdk",
                source / "sdk/include/crt", source / "sdk/include/ndk", source / "sdk/include", source / "sdk/include/reactos", source / "sdk/include/ddk"]
    # A function the headers do not declare would return a truncated int: none is allowed. The sources use the old CRT names, which the
    # oldnames library supplies upstream.
    flags = ["-O2", "-nostdinc", "-isystem", gcc_include, "-fgnu89-inline", "-Werror=implicit-function-declaration", "-Werror=int-conversion",
             "-Dwcsdup=_wcsdup", "-Dwcsicmp=_wcsicmp", "-Dwcsnicmp=_wcsnicmp", "-Dwcsupr=_wcsupr", "-Dwcslwr=_wcslwr",
             "-D_WIN32_WINNT=0x600", "-DWINVER=0x600", "-D_WIN32_IE=0x0A00", "-D__REACTOS__", "-DUNICODE", "-D_UNICODE",
             "-D_M_IX86" if x86 else "-D_M_AMD64", "-D__WINESRC__", "-D_WINE", *([] if x86 else ["-D__ROS_LONG64__"]),
             # 32-bit handlers read the exception through the frame based PSEH of ReactOS, as the guarded blocks themselves do.
             *(["-D_exception_code()=_SEH2_GetExceptionCode()", "-D_exception_info()=_SEH2_GetExceptionInformation()"] if x86 else []),
             f"-ffile-prefix-map={source}=reactos", f"-ffile-prefix-map={repo}=raven", f"-ffile-prefix-map={output}=component"]
    objects = output / "objects"
    shutil.rmtree(objects, ignore_errors=True)
    objects.mkdir()

    def compile(path, name, extra=(), wine_module=True):
        target = objects / (name + ".o")
        paths = includes if wine_module else [path for path in includes if path != overlay]
        run([triple + "-gcc", "-c", *flags, *extra, *["-I" + str(path) for path in paths], path, "-o", target])
        return target

    def link(name, base, object_files, definition, libraries, implib=None):
        run([triple + "-gcc", "-shared", "-nostdlib", f"-Wl,--entry,{entry_point},--image-base,{base:#x},--no-insert-timestamp", *link_extra,
             *([f"-Wl,--out-implib,{implib}"] if implib and not x86 else []), "-o", output / name, *object_files, definition, *libraries])
        # A 32-bit import library keeps the stdcall decorations its callers link against, for the plain names the library exports.
        if implib and x86:
            stdcall = output / (Path(name).stem + "-import.def")
            stdcall.write_text(re.sub(r"^(\s*)(\w+)=\2(@\d+)", r"\1\2\3", Path(definition).read_text(), flags=re.M))
            run([triple + "-dlltool", "-d", stdcall, "-l", implib, "-k"])

    debug = compile(repo / "native/upstream/reactos-controls/debug.c", "debug")
    # 32-bit code registers its exception frames on the thread's chain: the frame based PSEH support of ReactOS is built into each component.
    pseh = []
    if x86:
        pseh_root = source / "sdk/lib/pseh"
        for name in ("framebased-gcchack.c", "framebased-gcchack-asm.S", "framebased.S", "../framebased.c"):
            target = objects / ("pseh_" + Path(name).name.replace(".", "_") + ".o")
            language = ["-x", "assembler-with-cpp"] if name.endswith(".S") else [*flags, *["-I" + str(path) for path in includes]]
            run([triple + "-gcc", "-c", *language, "-I" + str(pseh_root / "include"), "-I" + str(pseh_root / "include/pseh"), pseh_root / "i386" / name,
                 "-o", target])
            pseh.append(target)
        debug = [debug, *pseh]
    else:
        debug = [debug]
    # cabinet.dll: cabinet files, their compression and extraction, on zlib.
    zlib_include = source / "sdk/include/reactos/libs/zlib"
    zlib = [compile(source / "sdk/lib/3rdparty/zlib" / name, "zlib_" + Path(name).stem, ["-I" + str(zlib_include)]) for name in ZLIB]
    cabinet_root = source / "dll/win32/cabinet"
    with ThreadPoolExecutor(max_workers=2) as pool:
        cabinet = list(pool.map(lambda name: compile(cabinet_root / name, "cabinet_" + Path(name).stem,
                                                     ["-DHAVE_ZLIB", "-I" + str(cabinet_root), "-I" + str(zlib_include)]),
                                ("cabinet_main.c", "fci.c", "fdi.c", "stubs.c")))
    run([output / "spec2def", spec_arch, "-n=cabinet.dll", "-d=" + str(output / "cabinet.def"), cabinet_root / "cabinet.spec"])
    link("cabinet.dll", bases["cabinet"], [*zlib, *cabinet, *debug], output / "cabinet.def", ["-lmsvcrt", "-lkernel32", "-lntdll", "-lgcc"],
         output / "libcabinet.a")
    # sxs.dll: the side-by-side assembly cache.
    sxs_root = source / "dll/win32/sxs"
    run([output / "spec2def", spec_arch, "-n=sxs.dll", "-d=" + str(output / "sxs.def"), "-s=" + str(generated / "sxs_stubs.c"), sxs_root / "sxs.spec"])
    sxs = [compile(sxs_root / name, "sxs_" + Path(name).stem, ["-I" + str(sxs_root)]) for name in ("cache.c", "name.c", "sxs.c", "guid.c")]
    sxs.append(compile(generated / "sxs_stubs.c", "sxs_stubs"))
    link("sxs.dll", bases["sxs"], [*sxs, *debug], output / "sxs.def", ["-loleaut32", "-lole32", "-lmsvcrt", "-lkernel32", "-lntdll", "-luuid", "-lgcc"],
         output / "libsxs.a")
    # msi.dll: the Windows Installer engine, its SQL and condition grammars, and the RPC stubs of its custom action server.
    msi_root = source / "dll/win32/msi"
    run(["bison", "-o", generated / "cond.tab.c", "-d", msi_root / "cond.y"])
    run(["bison", "-o", generated / "sql.tab.c", "-d", msi_root / "sql.y"])
    msi_widl = [*widl, "-I", msi_root, "--prefix-server=s_"]
    for name in ("msiserver", "winemsi"):
        run([*msi_widl, "-h", "-H", generated / (name + ".h"), msi_root / (name + ".idl")])
        run([*msi_widl, "-u", "-U", generated / (name + "_i.c"), msi_root / (name + ".idl")])
    run([*msi_widl, "-c", "-C", generated / "winemsi_c.c", msi_root / "winemsi.idl"])
    run([*msi_widl, "-s", "-S", generated / "winemsi_s.c", msi_root / "winemsi.idl"])
    run([output / "spec2def", spec_arch, "-n=msi.dll", "-d=" + str(output / "msi.def"), "-s=" + str(generated / "msi_stubs.c"), msi_root / "msi.spec"])
    msi_sources = sorted(msi_root.glob("*.c")) + [generated / name for name in ("cond.tab.c", "sql.tab.c", "msiserver_i.c", "winemsi_c.c",
                                                                                 "winemsi_s.c", "msi_stubs.c")]
    msi_flags = ["-DMSIRUNMODE=MSIRUNMODE_T", "-I" + str(msi_root)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        msi = list(pool.map(lambda path: compile(path, "msi_" + path.stem, msi_flags, wine_module=False), msi_sources))
    msi.append(compile(source / "sdk/lib/3rdparty/libwine/register.c", "wine_register", ["-I" + str(msi_root)]))
    # Its strings, bitmaps, registration script and version: installers check that version before they run.
    wrapper = output / "resource-preprocessor.sh"
    wrapper.write_text("#!/bin/sh\nexec " + triple + "-gcc -E -xc -DRC_INVOKED -nostdinc -isystem " + gcc_include + " " +
                       " ".join("-I" + str(path) for path in [msi_root, *includes, generated / "reactos"] if path != overlay) + ' -w "$@"\n')
    wrapper.chmod(0o755)
    run([triple + "-windres", "--preprocessor=" + str(wrapper), "-O", "coff", "-DLANGUAGE_EN_US", "-D__REACTOS__", "-D__WINESRC__",
         "-D_M_IX86" if x86 else "-D_M_AMD64", "-I" + str(msi_root), "-i", msi_root / "msi.rc", "-o", objects / "msi.res.o"])
    msi.append(objects / "msi.res.o")
    msi.append(compile(support / "support.c", "installer_support"))
    link("msi.dll", bases["msi"], [*msi, *debug], output / "msi.def",
         ["-L" + str(output), "-lsxs", "-lcabinet", *[f"-l{library}" for library in ("advapi32", "comctl32", "gdi32", "ole32", "oleaut32", "shell32",
          "shlwapi", "rpcrt4", "urlmon", "user32", "version", "wininet", "imagehlp", "msvcrt", "kernel32", "ntdll", "odbccp32", "crypt32",
          "wintrust", "uuid", "gcc")]])
    # raven-storage.dll: what ole32 exports of structured storage, which the runtime's ole32 hands to it.
    ole_root = source / "dll/win32/ole32"
    for name in ("dcom", "irot"):
        run([*widl, "-I", ole_root, "-h", "-H", generated / (name + ".h"), ole_root / (name + ".idl")])
    storage_flags = ["-D_OLE32_", "-DCOM_NO_WINDOWS_H", "-DENTRY_PREFIX=OLE32_", "-DWINE_REGISTER_DLL", "-I" + str(ole_root)]
    storage = [compile(source / "dll/win32" / name, "storage_" + name.replace("/", "_")[:-2], [*storage_flags, "-I" + str((source / "dll/win32" / name).parent)])
               for name in STORAGE]
    storage.append(compile(support / "storage.c", "storage_support"))
    run([output / "spec2def", spec_arch, "-n=ole32.dll", "-d=" + str(output / "ole32.def"), ole_root / "ole32.spec"])
    public = {match.group(1) for match in re.finditer(r"^\s*([A-Za-z_][A-Za-z0-9_]*)(?:\s|=|@|$)", (output / "ole32.def").read_text(), re.M)}
    defined = decorated(storage)
    exported = sorted((public & set(defined)) - {"EXPORTS", "NAME", "LIBRARY"})
    (output / "raven-storage.def").write_text("NAME raven-storage.dll\nEXPORTS\n" + "".join(
        " " + name + ("@" + str(defined[name]) if x86 and defined[name] is not None else "") + "\n" for name in exported))
    link("raven-storage.dll", bases["storage"], [*storage, *debug], output / "raven-storage.def",
         ["-lole32", "-loleaut32", "-ladvapi32", "-luser32", "-lmsvcrt", "-lkernel32", "-lntdll", "-luuid", "-lgcc"])
    result = dict(revision=REVISION, archive_sha256=ARCHIVE_SHA256, arch=args.arch, commands=records,
                  component_sha256={name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in COMPONENTS},
                  storage_exports=exported,
                  patches={patch.name: hashlib.sha256(patch.read_bytes()).hexdigest() for patch in patches},
                  source_hashes={path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                                 for path in sorted(source.rglob("*")) if path.is_file() and not path.is_relative_to(overlay)})
    (output / "provenance.json").write_text(json.dumps(result, indent=2) + "\n")
    for name in COMPONENTS:
        print(output / name)


if __name__ == "__main__":
    main()

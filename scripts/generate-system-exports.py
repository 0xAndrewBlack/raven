#!/usr/bin/env python3
"""Generate native/nt/system_exports.inc: the public export names of Windows system libraries.

Names come from the import libraries shipped with mingw-w64 (public-domain/ZPL headers and
definition files), so Raven never copies a Windows binary or another runtime's source.

usage: generate-system-exports.py OUTPUT.inc [ARGUMENTS.inc]

With a second path it also writes the stdcall argument words of every function, read from the decorated symbol names (_Name@bytes) of the
32-bit import libraries.
"""

from pathlib import Path
import re
import subprocess
import sys

LIBRARIES = """advapi32 bcrypt comctl32 comdlg32 crypt32 dbghelp dwmapi gdi32 imm32 kernel32 ole32 oleaut32 psapi
sensapi setupapi shell32 shlwapi user32 uxtheme version wininet winmm wintrust ws2_32 wsock32
bcryptprimitives cfgmgr32 dhcpcsvc dnsapi hid imagehlp iphlpapi ntdll ktmw32 msimg32 mswsock ncrypt netapi32 opengl32 glu32 powrprof pdh runtimeobject winspool ravenhost secur32 shcore userenv wevtapi winhttp wtsapi32
atlthunk oleacc urlmon odbccp32""".split()
# Real exports whose names begin with an underscore, which the generic filter drops.
# The interlocked functions are compiler intrinsics in the import libraries, yet kernel32 exports them and programs import them by name.
INTERLOCKED = {"InterlockedIncrement": 1, "InterlockedDecrement": 1, "InterlockedExchange": 2, "InterlockedExchangeAdd": 2,
               "InterlockedCompareExchange": 3, "InterlockedCompareExchange64": 5}
EXTRA = {"runtimeobject": ["RoActivateInstance", "RoGetActivationFactory", "RoInitialize", "RoUninitialize", "RoOriginateError", "RoOriginateErrorW",
                           "RoGetAgileReference", "RoRegisterActivationFactories", "RoRevokeActivationFactories", "RoGetApartmentIdentifier"], "ws2_32": ["__WSAFDIsSet", "AcceptEx", "ConnectEx", "DisconnectEx", "GetAcceptExSockaddrs"], "wsock32": ["__WSAFDIsSet"], "comctl32": ["_TrackMouseEvent"], "kernel32": ["QueryUnbiasedInterruptTimePrecise", "QueryInterruptTimePrecise", "_hread", "_hwrite", "_lclose", "_lcreat", "_llseek", "_lopen", "_lread", "_lwrite", "FlsGetValue2", *INTERLOCKED]}
EXTRA_WORDS = {"kernel32": {**INTERLOCKED, "FlsGetValue2": 1, "QueryUnbiasedInterruptTimePrecise": 1, "QueryInterruptTimePrecise": 1}, "ws2_32": {"__WSAFDIsSet": 2, "AcceptEx": 8, "ConnectEx": 7, "DisconnectEx": 4, "GetAcceptExSockaddrs": 8}, "wsock32": {"__WSAFDIsSet": 2}}
# Libraries whose file does not end in .dll.
FILE_NAMES = {"winspool": "winspool.drv"}
DIRECTORY = Path("/usr/x86_64-w64-mingw32/lib")
DIRECTORY32 = Path("/usr/i686-w64-mingw32/lib")


# Libraries whose names are listed here rather than read from an import library: the host services Raven's own components import, and
# Windows libraries mingw-w64 ships no import library for.
NAMES_ONLY = {"ravenhost": ["RavenFontClose", "RavenFontGlyphs", "RavenFontInfo", "RavenFontMetrics", "RavenFontName", "RavenFontOpen",
                            "RavenFontOutline", "RavenFontRender", "RavenFontScan", "RavenFontTable", "RavenTrace"]}
# atlthunk.dll, the window procedure thunks of Windows 10, has no import library in mingw-w64; its four functions are listed here.
NAMES_ONLY["atlthunk"] = ["AtlThunk_AllocateData", "AtlThunk_DataToCode", "AtlThunk_FreeData", "AtlThunk_InitData"]
NAMES_ONLY_WORDS = {"AtlThunk_AllocateData": 0, "AtlThunk_DataToCode": 1, "AtlThunk_FreeData": 1, "AtlThunk_InitData": 3, "RavenFontClose": 1, "RavenFontGlyphs": 4, "RavenFontInfo": 2, "RavenFontMetrics": 3, "RavenFontName": 4, "RavenFontOpen": 3,
                    "RavenFontOutline": 4, "RavenFontRender": 10, "RavenFontScan": 2, "RavenFontTable": 5, "RavenTrace": 1}


def exports(library):
    if library in NAMES_ONLY:
        return sorted(NAMES_ONLY[library])
    output = subprocess.run(["x86_64-w64-mingw32-nm", "-g", "--defined-only", str(DIRECTORY / f"lib{library}.a")],
                            check=True, capture_output=True, text=True).stdout
    names = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "TD" and not parts[2].startswith(("_", ".")) and "@" not in parts[2]:
            names.add(parts[2])
    return sorted(names | set(EXTRA.get(library, [])))


def stdcall_words(library):
    """Argument words by function name from the decorated symbols of the 32-bit import library (_Name@bytes)."""
    if library in NAMES_ONLY:
        return {name: NAMES_ONLY_WORDS[name] for name in NAMES_ONLY[library]}
    output = subprocess.run(["i686-w64-mingw32-nm", "-g", "--defined-only", str(DIRECTORY32 / f"lib{library}.a")],
                            check=True, capture_output=True, text=True).stdout
    words = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "TD":
            match = re.fullmatch(r"_(\w+)@(\d+)", parts[2])
            if match and int(match.group(2)) % 4 == 0:
                words[match.group(1)] = int(match.group(2)) // 4
    for name, count in EXTRA_WORDS.get(library, {}).items():
        words.setdefault(name, count)
    return words


def main():
    out = ["// Generated by scripts/generate-system-exports.py from mingw-w64 import libraries. Do not edit.\n"]
    for library in LIBRARIES:
        names = exports(library)
        out.append(f'static constexpr std::string_view {library}_exports[]{{\n')
        for start in range(0, len(names), 6):
            out.append("\t" + ",".join(f'"{name}"' for name in names[start:start + 6]) + ",\n")
        out.append("};\n")
    out.append("static constexpr std::pair<std::string_view, std::span<const std::string_view>> libraries[]{\n")
    for library in LIBRARIES:
        out.append(f'\t{{"{FILE_NAMES.get(library, library + ".dll")}", {library}_exports}},\n')
    out.append("};\n")
    Path(sys.argv[1]).write_text("".join(out))
    if len(sys.argv) > 2:
        arguments = ["// Generated by scripts/generate-system-exports.py from the mingw-w64 32-bit import libraries. Do not edit.\n"]
        for library in LIBRARIES:
            words = stdcall_words(library)
            arguments.append(f'static constexpr std::pair<std::string_view, uint8_t> {library}_words[]{{\n')
            items = sorted(words.items())
            for start in range(0, len(items), 6):
                arguments.append("\t" + ",".join(f'{{"{name}",{count}}}' for name, count in items[start:start + 6]) + ",\n")
            arguments.append("};\n")
        arguments.append("static constexpr std::pair<std::string_view, std::span<const std::pair<std::string_view, uint8_t>>> argument_tables[]{\n")
        for library in LIBRARIES:
            arguments.append(f'\t{{"{FILE_NAMES.get(library, library + ".dll")}", {library}_words}},\n')
        arguments.append("};\n")
        Path(sys.argv[2]).write_text("".join(arguments))


main()

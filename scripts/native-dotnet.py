#!/usr/bin/env python3
"""Install the .NET Framework 4.8 through Raven from Microsoft's offline installer and run a console and a WinForms program on it.

In a fresh prefix a .NET program first meets no runtime and must show the message Windows shows then. The offline installer unpacks
its packages as it does on Windows (/x), our msiexec installs the full framework and the patch that brings it to 4.8, and the same
program then runs, followed by a WinForms window whose screenshot is kept.

usage: native-dotnet.py RAVEN NDP48_INSTALLER PROGRAMS_DIR EVIDENCE_DIR
"""

from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
import importlib.util
_spec = importlib.util.spec_from_file_location("native_redist", Path(__file__).with_name("native-redist.py"))
native_redist = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native_redist)

MISSING_TITLE = ".NET Framework Initialization Error"


def window_titles():
    probe = subprocess.run(["wlrctl", "toplevel", "list"], env=native_redist.environment(), capture_output=True, text=True, timeout=10)
    return probe.stdout if probe.returncode == 0 else ""


def missing_runtime(raven, prefix, program, evidence):
    """Starts the program with no runtime installed and waits for Windows' message; the screenshot goes into the evidence."""
    env = native_redist.environment() | {"RAVEN_PREFIX": str(prefix)}
    with (evidence / "missing.log").open("wb") as log:
        process = subprocess.Popen([str(raven), "--run-process", "--execution=native", "--timeout-ms=600000", "--desktop=wayland", str(program)],
                                   env=env, stdout=log, stderr=log)
        try:
            deadline = time.time() + 600
            while time.time() < deadline and process.poll() is None:
                if MISSING_TITLE in window_titles():
                    time.sleep(2)
                    subprocess.run(["grim", str(evidence / "missing.png")], env=native_redist.environment(), timeout=30)
                    return
                time.sleep(1)
            raise RuntimeError(f"no '{MISSING_TITLE}' message without the runtime (status {process.poll()})")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def step(raven, prefix, program, arguments, evidence, name, watch=None, timeout=1800):
    code = native_redist.run(raven, prefix, program, arguments, evidence / f"{name}.log", watch=watch, timeout=timeout)
    if code not in (0, 3010):
        raise RuntimeError(f"{name}: {program.name} ended with status {code}")


def main():
    raven, installer, programs, evidence = map(Path, sys.argv[1:5])
    msiexec = raven.parent / "msiexec.exe"
    evidence.mkdir(parents=True, exist_ok=True)
    prefix = evidence / "prefix"
    shutil.rmtree(prefix, ignore_errors=True)
    folder = prefix / "drive_c" / "dotnet"
    folder.mkdir(parents=True)
    for name in ("hello64.exe", "forms64.exe"):
        shutil.copy(programs / name, folder / name)
    log = (evidence / "compositor.log").open("wb")
    compositor = native_redist.start_compositor(log)
    try:
        missing_runtime(raven, prefix, folder / "hello64.exe", evidence)
        step(raven, prefix, installer, ["/x:C:\\ndp", "/q"], evidence, "unpack")
        step(raven, prefix, msiexec, ["/i", "C:\\ndp\\netfx_Full_x64.msi", "/qn"], evidence, "full")
        step(raven, prefix, msiexec, ["/p", "C:\\ndp\\netfx_Patch_x64.msp", "/qn", "EXTUI=1"], evidence, "patch")
        code = native_redist.run(raven, prefix, folder / "hello64.exe", [], evidence / "hello.log", timeout=300)
        said = (folder / "hello-out.txt").read_text() if (folder / "hello-out.txt").exists() else ""
        if code != 42 or "Hello from .NET 4.0.30319" not in said:
            raise RuntimeError(f"the console program did not run on the installed runtime (status {code}, '{said.strip()}')")
        step(raven, prefix, folder / "forms64.exe", [], evidence, "forms", watch=evidence / "forms.png", timeout=300)
        shown = (folder / "forms-out.txt").read_text() if (folder / "forms-out.txt").exists() else ""
        if not shown.startswith("Raven .NET|WinForms on .NET 4.0.30319"):
            raise RuntimeError(f"the WinForms window did not show (wrote '{shown.strip()}')")
        print(f"PASS: missing runtime reported, .NET Framework 4.8 installed, {said.strip()}, WinForms window shown")
    finally:
        if compositor:
            compositor.terminate()
            compositor.wait(timeout=10)


if __name__ == "__main__":
    main()

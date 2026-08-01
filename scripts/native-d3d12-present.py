#!/usr/bin/env python3
"""Present a Direct3D 12 swap chain through vkd3d-proton, DXVK's DXGI and Raven to a Wayland window and compare what the compositor shows.

testdata/d3d12/window12.exe draws a vertex-coloured triangle into the back buffers of a flip model swap chain on a direct queue and
presents sixty frames. It copies the last back buffer into a read-back buffer before presenting it. This script runs it on an isolated
headless compositor, captures the output with grim and requires that the read-back frame matches the reference rasterizer and that the
captured window shows that frame pixel for pixel. With the extra argument "gpu" the host's default Vulkan driver and a GLES compositor
are used and the run must not be on a software driver.

usage: native-d3d12-present.py RAVEN WINDOW12_EXE VKD3D_PE64_DIRECTORY DXVK_PE64_DIRECTORY WORKDIR [gpu]
"""

from pathlib import Path
import os
import shutil
import subprocess
import sys
import time

from PIL import Image

SIZE = 256
GPU = len(sys.argv) > 6 and sys.argv[6] == "gpu"
RUNTIME = Path(f"/run/user/{os.getuid()}/raven-labwc-{'gpu' if GPU else 'runtime'}")


def environment():
    return {"PATH": "/usr/bin:/bin", "XDG_RUNTIME_DIR": str(RUNTIME), "WAYLAND_DISPLAY": "wayland-0"}


def start_compositor(log):
    if (RUNTIME / "wayland-0").exists():
        probe = subprocess.run(["wlrctl", "toplevel", "list"], env=environment(), capture_output=True, timeout=10)
        if probe.returncode == 0:
            return None
        (RUNTIME / "wayland-0").unlink(missing_ok=True)
        (RUNTIME / "wayland-0.lock").unlink(missing_ok=True)
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = environment() | {"WLR_BACKENDS": "headless", "WLR_RENDERER": "gles2" if GPU else "pixman", "WLR_HEADLESS_OUTPUTS": "1"}
    process = subprocess.Popen(["labwc"], env=env, stdout=log, stderr=log)
    for _ in range(50):
        if (RUNTIME / "wayland-0").exists():
            time.sleep(0.5)
            return process
        time.sleep(0.1)
    raise RuntimeError("isolated compositor did not start")


def main():
    raven, workload, vkd3d, dxvk, work = map(Path, sys.argv[1:6])
    shutil.rmtree(work, ignore_errors=True)
    run, prefix = work / "run", work / "prefix"
    run.mkdir(parents=True)
    for name in ("d3d12.dll", "d3d12core.dll"):
        shutil.copy(vkd3d / name, run / name)
    shutil.copy(dxvk / "dxgi.dll", run / "dxgi.dll")
    shutil.copy(workload, run / "window12.exe")
    with open(work / "compositor.log", "wb") as log:
        compositor = start_compositor(log)
        env = os.environ | environment() | {"RAVEN_PREFIX": str(prefix)}
        env["PATH"] = os.environ["PATH"]
        lavapipe = Path("/usr/share/vulkan/icd.d/lvp_icd.json")
        if "VK_DRIVER_FILES" not in env and lavapipe.exists() and not GPU:
            env["VK_DRIVER_FILES"] = str(lavapipe)
        process = subprocess.Popen([str(raven), "--run-process", "--execution=native", "--timeout-ms=100000", "--desktop=wayland", str(run / "window12.exe")],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, cwd=run)
        status = prefix / "drive_c" / "window12.txt"
        try:
            deadline = time.time() + 90
            while time.time() < deadline and process.poll() is None and not status.exists():
                time.sleep(0.5)
            if not status.exists() or status.read_text() != "OK":
                raise SystemExit(f"workload did not present all frames: {status.read_text() if status.exists() else 'missing'}")
            time.sleep(1)
            capture = work / "capture.png"
            subprocess.run(["grim", str(capture)], env=environment(), check=True, timeout=20)
        finally:
            process.terminate()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
            if compositor:
                compositor.terminate()
    drive = prefix / "drive_c"
    check = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("check-d3d11-triangle.py")), str(drive / "window12_last.raw")],
                           capture_output=True, text=True, timeout=120)
    sys.stdout.write(check.stdout)
    if check.returncode:
        raise SystemExit(check.stderr.strip() or "read-back frame does not match the reference")
    raw = (drive / "window12_last.raw").read_bytes()
    expected = Image.frombytes("RGBA", (SIZE, SIZE), raw).convert("RGB")
    screen = Image.open(capture).convert("RGB")
    clear = tuple(expected.getpixel((0, 0)))
    origin = next(((x, y) for y in range(screen.height) for x in range(screen.width) if screen.getpixel((x, y)) == clear), None)
    if origin is None:
        raise SystemExit("the compositor output holds no pixel of the clear colour: the swap chain never reached the screen")
    shown = screen.crop((origin[0], origin[1], origin[0] + SIZE, origin[1] + SIZE))
    a, b = shown.tobytes(), expected.tobytes()
    differing = sum(1 for index in range(0, len(b), 3) if a[index:index + 3] != b[index:index + 3])
    print(f"compositor capture at {origin}: {differing} of {SIZE * SIZE} pixels differ from the read-back frame")
    if differing:
        shown.save(work / "shown.png")
        raise SystemExit("the window on screen does not show the frame the GPU rendered")
    print("a Direct3D 12 frame rendered by vkd3d-proton and Raven's Vulkan bridge is on screen and matches the GPU read-back")


if __name__ == "__main__":
    main()

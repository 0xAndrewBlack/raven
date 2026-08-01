#!/usr/bin/env python3
"""Compare the time a key takes to reach a Windows program under Raven and under Wine.

testdata/latency/latency.exe records the wall clock time at which each key reaches its window procedure. The host sends thirty keys with
wtype to an isolated headless compositor and notes the time just before starting each wtype process, so every figure also contains the cost
of starting wtype and of the compositor delivering the key; that cost is the same for both runtimes, which is why the difference between the
two is the meaningful number. The table gives the median and the 90th percentile in milliseconds. Wine's Wayland driver did not receive keys from wtype or wlrctl on the
headless compositor, so on this setup only Raven can be measured (its row says 0 keys for Wine otherwise).

usage: benchmark-input.py RAVEN WINE TESTDATA WORKDIR [REPEATS]
"""

from pathlib import Path
import os
import shutil
import statistics
import subprocess
import sys
import time

EPOCH_DIFFERENCE = 116444736000000000


def one_run(runtime, raven, wine, program, prefix):
    runtime_dir = Path(f"/run/user/{os.getuid()}/raven-labwc-bench")
    runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name in ("wayland-0", "wayland-0.lock"):
        (runtime_dir / name).unlink(missing_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"], "TMPDIR": os.environ.get("TMPDIR", "/var/tmp"), "XDG_RUNTIME_DIR": str(runtime_dir),
           "WAYLAND_DISPLAY": "wayland-0"}
    compositor = subprocess.Popen(["labwc"], env=env | {"WLR_BACKENDS": "headless", "WLR_RENDERER": "pixman", "WLR_HEADLESS_OUTPUTS": "1"},
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if (runtime_dir / "wayland-0").exists():
                break
            time.sleep(0.1)
        time.sleep(0.5)
        if runtime == "raven":
            command = [str(raven), "--run-process", "--execution=native", "--timeout-ms=100000", "--desktop=wayland", str(program)]
            env_run = env | {"RAVEN_PREFIX": str(prefix)}
        else:
            command = [str(wine), str(program)]
            env_run = env | {"WINEPREFIX": str(prefix), "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "mscoree=;mshtml="}
        process = subprocess.Popen(command, env=env_run, cwd=program.parent, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready = prefix / "drive_c" / "latency.txt"
            deadline = time.time() + 120
            while time.time() < deadline and process.poll() is None and not ready.exists():
                time.sleep(0.1)
            if not ready.exists():
                return None
            time.sleep(1.5)
            # Give the window the keyboard focus by its title, then click it (the compositor places the window itself).
            subprocess.run(["wlrctl", "toplevel", "focus", "title:Key latency"], env=env, capture_output=True, timeout=10)
            subprocess.run(["wlrctl", "pointer", "move", "-4000", "-4000"], env=env, check=True, timeout=10)
            subprocess.run(["wlrctl", "pointer", "move", "640", "360"], env=env, check=True, timeout=10)
            time.sleep(0.3)
            subprocess.run(["wlrctl", "pointer", "click", "left"], env=env, check=True, timeout=10)
            time.sleep(0.5)
            sent = []
            for _ in range(30):
                sent.append(time.time_ns())
                subprocess.run(["wtype", "a"], env=env, check=True, timeout=10)
                time.sleep(0.15)
            time.sleep(0.5)
            if not (prefix / "drive_c" / "latency.bin").exists():
                return None
            data = (prefix / "drive_c" / "latency.bin").read_bytes()
            stamps = [(int.from_bytes(data[index:index + 8], "little") - EPOCH_DIFFERENCE) * 100 for index in range(0, len(data) - 15, 16)]
            if len(stamps) < 20:
                return None
            # The first key sent after a window gets the focus can be lost by the compositor's virtual keyboard; the keys that did arrive are the
            # last ones sent, so they are paired from the end.
            return [(received - before) / 1e6 for received, before in zip(stamps, sent[len(sent) - len(stamps):])]
        finally:
            process.terminate()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
            if runtime == "wine":
                server = Path("/usr/lib/x86_64-linux-gnu/wine/wineserver")
                subprocess.run([str(server), "-k"], env=env_run, capture_output=True, timeout=60)
    finally:
        compositor.terminate()
        compositor.wait(10)


def main():
    raven, wine, testdata, work = (Path(value).resolve() for value in sys.argv[1:5])
    repeats = int(sys.argv[5]) if len(sys.argv) > 5 else 3
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    program = work / "program" / "latency.exe"
    program.parent.mkdir()
    shutil.copy(testdata / "latency" / "latency.exe", program)
    warm = work / "wine-warm"
    subprocess.run([str(wine), "wineboot", "-u"], env={"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"], "WINEPREFIX": str(warm), "WINEDEBUG": "-all"},
                   capture_output=True, timeout=300)
    subprocess.run(["/usr/lib/x86_64-linux-gnu/wine/wineserver", "-k"], env={"PATH": "/usr/bin:/bin", "WINEPREFIX": str(warm)}, capture_output=True, timeout=60)
    results = {"raven": [], "wine": []}
    for runtime in ("raven", "wine"):
        for index in range(repeats):
            prefix = work / f"prefix-{runtime}-{index}"
            if runtime == "wine":
                shutil.copytree(warm, prefix, symlinks=True)
            values = one_run(runtime, raven, wine, program, prefix)
            if values:
                results[runtime].extend(values)
    print(f"{'runtime':8} {'median ms':>10} {'p90 ms':>8}  keys")
    for runtime, values in results.items():
        if values:
            values.sort()
            print(f"{runtime:8} {statistics.median(values):10.1f} {values[int(len(values) * 0.9) - 1]:8.1f}  {len(values)}")
        else:
            print(f"{runtime:8} {'-':>10} {'-':>8}  0")


if __name__ == "__main__":
    main()

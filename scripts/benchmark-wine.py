#!/usr/bin/env python3
"""Compare Raven with Wine on the same programs, host and Vulkan driver: wall time, CPU time and peak memory.

Each workload runs REPEATS times under both runtimes in a fresh prefix. Wall time is measured around the launched command. CPU time and
peak memory come from the kernel's accounting for that command and the children it waited for. Wine's server detaches from the command,
so its CPU time and memory are not in Wine's figures; the table shows the median of the runs and the numbers are lower bounds for Wine.

Workloads:
  startup   a program that returns immediately
  sqlite    sqlite3.exe computing a recursive query over several million rows (CPU bound)
  d3d11     testdata/d3d11/triangle.exe through DXVK on lavapipe (graphics API throughput and start up cost)

usage: benchmark-wine.py RAVEN WINE_BINARY TESTDATA DXVK_PE64_DIRECTORY STARTUP_EXE WORKDIR [REPEATS]
"""

from pathlib import Path
import os
import resource
import shutil
import statistics
import subprocess
import sys
import time

QUERY = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<8000000) SELECT count(*) FROM c;\n"


def isolated(command, env, stdin_text=None, cwd=None):
    """Measure in a fresh Python child so that ru_maxrss describes this command alone."""
    code = (
        "import json,sys,subprocess,resource,time\n"
        "spec=json.loads(sys.stdin.read())\n"
        "start=time.perf_counter()\n"
        "p=subprocess.Popen(spec['command'],env=spec['env'],cwd=spec['cwd'],stdin=subprocess.PIPE if spec['stdin'] else subprocess.DEVNULL,"
        "stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\n"
        "out,_=p.communicate(spec['stdin'].encode() if spec['stdin'] else None,timeout=600)\n"
        "wall=time.perf_counter()-start\n"
        "r=resource.getrusage(resource.RUSAGE_CHILDREN)\n"
        "print(json.dumps({'wall':wall,'cpu':r.ru_utime+r.ru_stime,'rss':r.ru_maxrss/1024.0,'code':p.returncode,'out':out.decode(errors='replace')[-400:]}))\n"
    )
    import json
    spec = json.dumps({"command": command, "env": env, "stdin": stdin_text, "cwd": cwd})
    result = subprocess.run([sys.executable, "-I", "-c", code], input=spec, capture_output=True, text=True, timeout=700)
    data = json.loads(result.stdout.strip().splitlines()[-1])
    return data["wall"], data["cpu"], data["rss"], data["code"], data["out"]


def main():
    raven, wine, testdata, dxvk, startup, work = (Path(value).resolve() for value in sys.argv[1:7])
    repeats = int(sys.argv[7]) if len(sys.argv) > 7 else 5
    # Wine's server sits beside the launcher or, on Debian style installations, in the library directory.
    server = next((path for path in (wine.with_name("wineserver"), Path("/usr/lib/x86_64-linux-gnu/wine/wineserver"), Path("/usr/lib/wine/wineserver"))
                   if path.exists()), wine.with_name("wineserver"))
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    lavapipe = "/usr/share/vulkan/icd.d/lvp_icd.json"
    base = {"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"], "TMPDIR": os.environ.get("TMPDIR", str(work)), "VK_DRIVER_FILES": lavapipe,
            "XDG_RUNTIME_DIR": os.environ.get("XDG_RUNTIME_DIR", "/run/user/1000"), "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "mscoree=;mshtml=;d3d11,dxgi,d3d10core=n"}
    d3d = work / "d3d"
    d3d.mkdir()
    for name in ("d3d11.dll", "dxgi.dll", "d3d10core.dll"):
        shutil.copy(dxvk / name, d3d / name)
    shutil.copy(testdata / "d3d11" / "triangle.exe", d3d / "triangle.exe")
    sqlite = testdata / "sqlite3.exe"
    shutil.copy(startup, work / "startup.exe")
    # Wine initialises a prefix on first use, which takes seconds; Raven needs no such step. Both are measured on a ready prefix, so a
    # fresh copy of an already initialised Wine prefix is used for every run.
    warm = work / "wine-warm"
    warm_env = dict(base, WINEPREFIX=str(warm))
    subprocess.run([str(wine), "wineboot", "-u"], env=warm_env, capture_output=True, timeout=300)
    subprocess.run([str(server), "-k"], env=warm_env, capture_output=True, timeout=60)
    rows = []
    for name, program, stdin_text in (("startup", work / "startup.exe", None), ("sqlite", sqlite, QUERY), ("d3d11", d3d / "triangle.exe", None)):
        for runtime in ("raven", "wine"):
            samples = []
            for index in range(repeats):
                prefix = work / f"prefix-{runtime}-{name}-{index}"
                shutil.rmtree(prefix, ignore_errors=True)
                if runtime == "wine":
                    shutil.copytree(warm, prefix, symlinks=True)
                env = dict(base)
                program_args = [str(program)] + ([":memory:"] if name == "sqlite" else [])
                if runtime == "raven":
                    env["RAVEN_PREFIX"] = str(prefix)
                    command = [str(raven), "--run-process", "--execution=native", "--timeout-ms=500000"] + (["--stdio=inherit"] if stdin_text else []) + [str(program)]
                    if name == "sqlite":
                        command += ["--", ":memory:"]
                else:
                    env["WINEPREFIX"] = str(prefix)
                    command = [str(wine)] + program_args
                try:
                    samples.append(isolated(command, env, stdin_text, str(program.parent)))
                finally:
                    if runtime == "wine":
                        subprocess.run([str(server), "-k"], env=env, capture_output=True, timeout=60)
            ok = [s for s in samples if s[3] == 0]
            if not ok:
                rows.append((name, runtime, None, None, None, f"failed: exit {samples[-1][3]}: {samples[-1][4][-120:]!r}"))
                continue
            rows.append((name, runtime, statistics.median(s[0] for s in ok), statistics.median(s[1] for s in ok), statistics.median(s[2] for s in ok),
                         f"{len(ok)}/{repeats} runs ok"))
    print(f"{'workload':9} {'runtime':6} {'wall s':>8} {'cpu s':>8} {'peak MiB':>9}  note")
    for name, runtime, wall, cpu, rss, note in rows:
        if wall is None:
            print(f"{name:9} {runtime:6} {'-':>8} {'-':>8} {'-':>9}  {note}")
        else:
            print(f"{name:9} {runtime:6} {wall:8.4f} {cpu:8.4f} {rss:9.1f}  {note}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Trace rays through a Direct3D 12 ray tracing pipeline on vkd3d-proton and Raven and compare the read-back pixels with a reference.

testdata/d3d12/raytrace.exe (or rayquery.exe, which traces inline with RayQuery in a compute shader) builds a bottom level acceleration structure with one triangle and a top level one with one instance, creates a
ray tracing pipeline from DXIL shaders (rt.hlsl: ray generation, closest hit and miss), traces one orthographic ray per pixel with
DispatchRays and writes the picture it read back. The triangle has the geometry and vertex colours of the rasterized workloads, so
check-d3d11-triangle.py compares the pixels with the same reference rasterizer. Nothing is drawn by the rasterizer: a miss, a wrong hit
or a missing barycentric weight fails the comparison.

The host driver has to offer VK_KHR_acceleration_structure and VK_KHR_ray_tracing_pipeline. Of the drivers on the development machine only
the software rasterizer does, so this test always runs on it; when the driver offers no ray tracing the test is skipped (exit code 77).

usage: native-d3d12-raytrace.py RAVEN RAYTRACE_EXE VKD3D_PE64_DIRECTORY DXVK_PE64_DIRECTORY WORKDIR
"""

from pathlib import Path
import os
import shutil
import subprocess
import sys


def main():
    raven, workload, vkd3d, dxvk, work = map(Path, sys.argv[1:6])
    shutil.rmtree(work, ignore_errors=True)
    run, prefix = work / "run", work / "prefix"
    run.mkdir(parents=True)
    for name in ("d3d12.dll", "d3d12core.dll"):
        shutil.copy(vkd3d / name, run / name)
    shutil.copy(dxvk / "dxgi.dll", run / "dxgi.dll")
    stem = workload.stem
    shutil.copy(workload, run / f"{stem}.exe")
    env = os.environ | {"RAVEN_PREFIX": str(prefix)}
    lavapipe = Path("/usr/share/vulkan/icd.d/lvp_icd.json")
    if "VK_DRIVER_FILES" not in env and lavapipe.exists():
        env["VK_DRIVER_FILES"] = str(lavapipe)
    result = subprocess.run([str(raven), "--run-process", "--execution=native", "--timeout-ms=250000", str(run / f"{stem}.exe")],
                            capture_output=True, text=True, timeout=280, env=env, cwd=run)
    drive = prefix / "drive_c"
    report = (drive / f"{stem}.txt").read_text() if (drive / f"{stem}.txt").exists() else "missing"
    if not result.returncode and report.startswith("SKIP"):
        print("skipped:", report)
        raise SystemExit(77)
    if result.returncode or report != "OK":
        raise SystemExit(f"ray tracing workload did not finish: exit {result.returncode}, report {report!r}, {result.stderr[-300:]!r}")
    check = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("check-d3d11-triangle.py")), str(drive / f"{stem}.raw")],
                           capture_output=True, text=True, timeout=120)
    sys.stdout.write(check.stdout)
    if check.returncode:
        raise SystemExit(check.stderr.strip() or "the Direct3D 12 triangle does not match the reference")
    print("Direct3D 12 ray tracing (" + stem + ") ran through vkd3d-proton and Raven's Vulkan bridge and the traced triangle matches the reference")


if __name__ == "__main__":
    main()

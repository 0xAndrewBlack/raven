#!/usr/bin/env python3
"""Trace rays through a Direct3D 12 ray tracing pipeline on vkd3d-proton and Raven and compare the read-back pixels with a reference.

testdata/d3d12/raytrace.exe (or rayquery.exe, which traces inline with RayQuery in a compute shader) builds a bottom level acceleration structure with one triangle and a top level one with one instance, creates a
ray tracing pipeline from DXIL shaders (rt.hlsl: ray generation, closest hit and miss), traces one orthographic ray per pixel with
DispatchRays and writes the picture it read back. The triangle has the geometry and vertex colours of the rasterized workloads, so
check-d3d11-triangle.py compares the pixels with the same reference rasterizer. Nothing is drawn by the rasterizer: a miss, a wrong hit
or a missing barycentric weight fails the comparison.

Three more scenes use the same script by the name of their executable: rtanyhit.exe (an any hit shader cuts the triangle along the weight of its
second vertex and the miss shader gets the background from a callable shader) and rtprocedural.exe (one box, and an intersection shader makes
a yellow disc of radius one half of it).

The host driver has to offer VK_KHR_acceleration_structure and VK_KHR_ray_tracing_pipeline. Of the drivers on the development machine only
the software rasterizer does, so this test always runs on it; when the driver offers no ray tracing the test is skipped (exit code 77).

usage: native-d3d12-raytrace.py RAVEN RAYTRACE_EXE VKD3D_PE64_DIRECTORY DXVK_PE64_DIRECTORY WORKDIR
"""

from pathlib import Path
import os
import shutil
import subprocess
import sys


def check_disc(data):
    """The disc of radius one half, centred in the frame: yellow inside, the clear colour outside, a band of two pixels around its edge skipped."""
    if len(data) != 256 * 256 * 4:
        raise SystemExit(f"read back {len(data)} bytes, expected {256 * 256 * 4}")
    inside = outside = 0
    for y in range(256):
        for x in range(256):
            radius = (((x + 0.5) / 128 - 1) ** 2 + (1 - (y + 0.5) / 128) ** 2) ** 0.5
            if abs(radius - 0.5) * 128 < 2:
                continue
            got = tuple(data[(y * 256 + x) * 4:(y * 256 + x) * 4 + 4])
            expected = (255, 255, 0, 255) if radius < 0.5 else (26, 26, 76, 255)
            if max(abs(a - b) for a, b in zip(got, expected)) > 2:
                raise SystemExit(f"pixel {x},{y}: got {got}, expected {expected}")
            inside += radius < 0.5
            outside += radius >= 0.5
    print(f"disc matches the reference: {inside} interior pixels, {outside} clear pixels")


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
    if stem == "rtprocedural":
        check_disc((drive / f"{stem}.raw").read_bytes())
        print("Direct3D 12 ray tracing (" + stem + ") ran an intersection shader through vkd3d-proton and Raven's Vulkan bridge and drew the disc")
        return
    arguments = ["256", "256", "26", "26", "76", "1.0", "0.5"] if stem == "rtanyhit" else []
    check = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("check-d3d11-triangle.py")), str(drive / f"{stem}.raw"), *arguments],
                           capture_output=True, text=True, timeout=120)
    sys.stdout.write(check.stdout)
    if check.returncode:
        raise SystemExit(check.stderr.strip() or "the Direct3D 12 triangle does not match the reference")
    print("Direct3D 12 ray tracing (" + stem + ") ran through vkd3d-proton and Raven's Vulkan bridge and the traced triangle matches the reference")


if __name__ == "__main__":
    main()

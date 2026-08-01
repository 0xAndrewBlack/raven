#!/usr/bin/env python3
"""Compare the pixels testdata/d3d11/textured.exe read back with an independent software rendering of its scene.

The scene is two axis aligned quads sampled with nearest filtering from an 8 by 8 checkerboard (255,64,64 and 240,240,240), each multiplied
by a tint, over a (26, 26, 76) clear colour. The near quad (z 0.2) is drawn first and the far quad (z 0.7) second, so the depth test has to
hide the part of the far quad behind the near one. Pixels within 1.5 pixels of a quad edge and of a texel boundary are skipped; every
other pixel must match within 2.

usage: check-d3d11-textured.py TEXTURED_RAW
"""

import sys

SIZE = 256
CLEAR = (26, 26, 76, 255)
# (x0, y0, x1, y1) in clip space, tint
NEAR = ((-0.6, -0.4, 0.2, 0.6), (1.0, 1.0, 1.0))
FAR = ((-0.2, -0.7, 0.7, 0.3), (0.3, 0.8, 1.0))


def texel(column, row):
    return (255, 64, 64) if (row + column) % 2 == 0 else (240, 240, 240)


def to_pixels(rect):
    x0, y0, x1, y1 = rect
    return ((x0 + 1) * 0.5 * SIZE, (1 - y1) * 0.5 * SIZE, (x1 + 1) * 0.5 * SIZE, (1 - y0) * 0.5 * SIZE)


def sample(rect, tint, xc, yc):
    left, top, right, bottom = to_pixels(rect)
    if not (left < xc < right and top < yc < bottom):
        return None
    u, v = (xc - left) / (right - left), (yc - top) / (bottom - top)
    near_edge = min(xc - left, right - xc, yc - top, bottom - yc) < 1.5
    boundary = any(abs(value * 8 - round(value * 8)) < 0.02 for value in (u, v))
    column, row = min(int(u * 8), 7), min(int(v * 8), 7)
    color = tuple(round(channel * t) for channel, t in zip(texel(column, row), tint)) + (255,)
    return color, near_edge or boundary


def main():
    data = open(sys.argv[1], "rb").read()
    if len(data) != SIZE * SIZE * 4:
        raise SystemExit(f"expected {SIZE * SIZE * 4} bytes, got {len(data)}")
    checked = skipped = covered = 0
    worst = 0
    for y in range(SIZE):
        for x in range(SIZE):
            xc, yc = x + 0.5, y + 0.5
            near, far = sample(*NEAR, xc, yc), sample(*FAR, xc, yc)
            # Edge pixels of either quad are skipped; elsewhere the nearer quad wins.
            if (near and near[1]) or (far and far[1]):
                skipped += 1
                continue
            expected = near[0] if near else far[0] if far else CLEAR
            covered += bool(near or far)
            got = tuple(data[(y * SIZE + x) * 4:(y * SIZE + x) * 4 + 4])
            error = max(abs(a - b) for a, b in zip(got, expected))
            worst = max(worst, error)
            if error > 2:
                raise SystemExit(f"pixel {x},{y}: got {got}, expected {expected}")
            checked += 1
    print(f"textured scene matches the reference: {checked} pixels checked ({covered} inside a quad), {skipped} edge or texel boundary pixels skipped, worst error {worst}")


if __name__ == "__main__":
    main()

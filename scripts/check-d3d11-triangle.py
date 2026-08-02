#!/usr/bin/env python3
"""Compare the pixels testdata/d3d11/triangle.exe read back from its render target with an independent reference rasterizer.

The reference covers pixel centres with barycentric weights and interpolates the three vertex colours; pixels within one pixel of an
edge are skipped because edge coverage rules differ between implementations. Every other pixel must match within 2 of 255, and the
clear colour must fill everything outside the triangle.

usage: check-d3d11-triangle.py TRIANGLE_RAW [WIDTH HEIGHT RED GREEN BLUE [SCALE [CUT]]]
The defaults are the 256 by 256 frame cleared to (0.1, 0.1, 0.3); the clear colour is given as 0 to 255 values. SCALE multiplies the
x and y of every vertex, for a program whose geometry shader shrinks the triangle. CUT is the weight of the second vertex above which
the triangle is gone, for a ray tracing any hit shader that ignores those hits; pixels within 0.03 of that weight are skipped.
"""

import sys

WIDTH = int(sys.argv[2]) if len(sys.argv) > 2 else 256
HEIGHT = int(sys.argv[3]) if len(sys.argv) > 3 else 256
CLEAR = tuple(int(v) for v in sys.argv[4:7]) + (255,) if len(sys.argv) > 6 else tuple(round(v * 255) for v in (0.1, 0.1, 0.3, 1.0))
SCALE = float(sys.argv[7]) if len(sys.argv) > 7 else 1.0
CUT = float(sys.argv[8]) if len(sys.argv) > 8 else None
CUT_MARGIN = 0.03
VERTICES = [((-0.8 * SCALE, -0.8 * SCALE), (255, 0, 0)), ((0.0, 0.8 * SCALE), (0, 0, 255)), ((0.8 * SCALE, -0.8 * SCALE), (0, 255, 0))]


def to_pixels(point):
    return ((point[0] + 1) * 0.5 * WIDTH, (1 - point[1]) * 0.5 * HEIGHT)


def weights(px, py):
    (x0, y0), (x1, y1), (x2, y2) = (to_pixels(v[0]) for v in VERTICES)
    area = (x1 - x0) * (y2 - y0) - (x2 - x0) * (y1 - y0)
    w1 = ((px - x0) * (y2 - y0) - (x2 - x0) * (py - y0)) / area
    w2 = ((x1 - x0) * (py - y0) - (px - x0) * (y1 - y0)) / area
    return 1 - w1 - w2, w1, w2


def edge_distance(px, py):
    """Signed distance in pixels to the nearest edge line: positive inside the triangle."""
    points = [to_pixels(v[0]) for v in VERTICES]
    area = (points[1][0] - points[0][0]) * (points[2][1] - points[0][1]) - (points[2][0] - points[0][0]) * (points[1][1] - points[0][1])
    sign = 1 if area > 0 else -1
    nearest = None
    for i in range(3):
        (ax, ay), (bx, by) = points[i], points[(i + 1) % 3]
        length = ((bx - ax) ** 2 + (by - ay) ** 2) ** 0.5
        distance = sign * ((bx - ax) * (py - ay) - (by - ay) * (px - ax)) / length
        nearest = distance if nearest is None else min(nearest, distance)
    return nearest


def main():
    data = open(sys.argv[1], "rb").read()
    if len(data) != WIDTH * HEIGHT * 4:
        raise SystemExit(f"expected {WIDTH * HEIGHT * 4} bytes, got {len(data)}")
    inside = outside = skipped = 0
    worst = 0
    for y in range(HEIGHT):
        for x in range(WIDTH):
            w = weights(x + 0.5, y + 0.5)
            got = tuple(data[(y * WIDTH + x) * 4:(y * WIDTH + x) * 4 + 4])
            distance = edge_distance(x + 0.5, y + 0.5)
            if distance < -1.5:
                expected = CLEAR
                outside += 1
            elif distance > 1.5:
                if CUT is not None and w[1] > CUT - CUT_MARGIN:
                    if w[1] <= CUT + CUT_MARGIN:
                        skipped += 1
                        continue
                    expected = CLEAR
                    outside += 1
                else:
                    expected = tuple(round(sum(w[i] * VERTICES[i][1][c] for i in range(3))) for c in range(3)) + (255,)
                    inside += 1
            else:
                skipped += 1
                continue
            error = max(abs(a - b) for a, b in zip(got, expected))
            worst = max(worst, error)
            if error > 2:
                raise SystemExit(f"pixel {x},{y}: got {got}, expected {expected}")
    centre = tuple(data[(HEIGHT // 2 * WIDTH + WIDTH // 2) * 4:(HEIGHT // 2 * WIDTH + WIDTH // 2) * 4 + 4])
    print(f"triangle matches the reference: {inside} interior pixels, {outside} clear pixels, {skipped} edge pixels skipped, worst error {worst}")
    print(f"corner pixel {tuple(data[0:4])}, centre pixel {centre}")


if __name__ == "__main__":
    main()

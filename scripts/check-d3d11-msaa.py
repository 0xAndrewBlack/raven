#!/usr/bin/env python3
"""Check a resolved four sample rendering of the vertex-coloured triangle against an independent software rendering.

Pixels well inside the triangle and well outside it must match the reference exactly (within 2); pixels on the edge must be partly covered, so
many of them are neither the clear colour nor the colour the triangle has at the pixel centre. A single sample rendering would have none.

usage: check-d3d11-msaa.py MSAA_RAW
"""

import sys

SIZE = 256
CLEAR = (26, 26, 76, 255)
VERTICES = [((-0.8, -0.8), (255, 0, 0)), ((0.0, 0.8), (0, 0, 255)), ((0.8, -0.8), (0, 255, 0))]


def to_pixels(point):
    return ((point[0] + 1) * 0.5 * SIZE, (1 - point[1]) * 0.5 * SIZE)


def weights(px, py):
    (x0, y0), (x1, y1), (x2, y2) = (to_pixels(v[0]) for v in VERTICES)
    area = (x1 - x0) * (y2 - y0) - (x2 - x0) * (y1 - y0)
    w1 = ((px - x0) * (y2 - y0) - (x2 - x0) * (py - y0)) / area
    w2 = ((x1 - x0) * (py - y0) - (px - x0) * (y1 - y0)) / area
    return 1 - w1 - w2, w1, w2


def edge_distance(px, py):
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
    if len(data) != SIZE * SIZE * 4:
        raise SystemExit(f"expected {SIZE * SIZE * 4} bytes, got {len(data)}")
    exact = partial = 0
    for y in range(SIZE):
        for x in range(SIZE):
            distance = edge_distance(x + 0.5, y + 0.5)
            got = tuple(data[(y * SIZE + x) * 4:(y * SIZE + x) * 4 + 4])
            w = weights(x + 0.5, y + 0.5)
            ideal = tuple(round(sum(w[i] * VERTICES[i][1][c] for i in range(3))) for c in range(3)) + (255,)
            if abs(distance) > 1.5:
                expected = ideal if distance > 0 else CLEAR
                if max(abs(a - b) for a, b in zip(got, expected)) > 2:
                    raise SystemExit(f"pixel {x},{y}: got {got}, expected {expected}")
                exact += 1
            elif abs(distance) < 0.5:
                # On the edge: a coverage blend is neither of the two flat answers.
                if max(abs(a - b) for a, b in zip(got, CLEAR)) > 6 and max(abs(a - b) for a, b in zip(got, ideal)) > 6:
                    partial += 1
    if partial < 50:
        raise SystemExit(f"only {partial} edge pixels are partly covered: the rendering was not multisampled")
    print(f"multisampled triangle matches the reference: {exact} interior and exterior pixels exact, {partial} partly covered edge pixels")


if __name__ == "__main__":
    main()

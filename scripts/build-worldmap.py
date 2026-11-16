#!/usr/bin/env python3
"""Refresh the land outline of the FIREWALL tab's world map (webui/static/data/world.json).

Reads a Natural Earth 110m land mask (public domain) as GeoJSON from the path it is
given, simplifies every ring with Douglas-Peucker to a tolerance of 0.4 degrees,
drops rings with a perimeter under 1.5 degrees, rounds to tenths of a degree and
writes {"scale": 10, "shapes": [[lon0, lat0, lon1, lat1, ...], ...]}: one flat list
of integers per ring (outer rings and holes alike; app.js fills them even-odd), the
closing point not repeated.

The result is committed: the chamber is offline by design, and nothing is fetched
at build or run time. This script only refreshes it, from a file you downloaded:
https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_land.geojson

Usage:
  python3 scripts/build-worldmap.py <ne_110m_land.geojson> [<out.json>]
"""
import json
import math
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "webui", "static", "data", "world.json")
SCALE = 10
TOLERANCE = 0.4         # degrees
MIN_PERIMETER = 1.5     # degrees


def _distance(p, a, b):
    """Distance of p from the segment a-b (from a when the segment is a point)."""
    dx, dy = b[0] - a[0], b[1] - a[1]
    if dx == 0 and dy == 0:
        return math.hypot(p[0] - a[0], p[1] - a[1])
    t = max(0.0, min(1.0, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy)))
    return math.hypot(p[0] - a[0] - t * dx, p[1] - a[1] - t * dy)


def simplify(points, tolerance):
    """Douglas-Peucker, iterative (a ring of thousands of points must not hit the recursion limit)."""
    if len(points) < 3:
        return list(points)
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        first, last = stack.pop()
        far, far_index = 0.0, None
        for i in range(first + 1, last):
            d = _distance(points[i], points[first], points[last])
            if d > far:
                far, far_index = d, i
        if far_index is not None and far > tolerance:
            keep[far_index] = True
            stack.extend(((first, far_index), (far_index, last)))
    return [p for p, k in zip(points, keep) if k]


def _perimeter(ring):
    return sum(math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(ring, ring[1:] + ring[:1]))


def _rings(geometry):
    if geometry["type"] == "Polygon":
        yield from geometry["coordinates"]
    elif geometry["type"] == "MultiPolygon":
        for polygon in geometry["coordinates"]:
            yield from polygon


def shape(ring):
    """A ring as flat tenths of a degree, or None when it is too small to keep."""
    points = simplify([(float(p[0]), float(p[1])) for p in ring], TOLERANCE)
    if len(points) > 1 and points[0] == points[-1]:
        points.pop()
    flat, last = [], None
    for lon, lat in points:
        q = (int(round(lon * SCALE)), int(round(lat * SCALE)))
        if q != last:
            flat.extend(q)
            last = q
    if len(flat) > 2 and flat[:2] == flat[-2:]:
        del flat[-2:]
    if len(flat) < 6 or _perimeter([(flat[i] / SCALE, flat[i + 1] / SCALE) for i in range(0, len(flat), 2)]) < MIN_PERIMETER:
        return None
    return flat


def build(source):
    shapes = []
    for feature in source["features"]:
        if feature.get("geometry"):
            for ring in _rings(feature["geometry"]):
                flat = shape(ring)
                if flat:
                    shapes.append(flat)
    return {"scale": SCALE, "shapes": shapes}


def main(argv):
    if len(argv) not in (2, 3):
        print("usage: python3 scripts/build-worldmap.py <ne_110m_land.geojson> [<out.json>]", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        data = build(json.load(f))
    out = argv[2] if len(argv) == 3 else OUT
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    # One ring per line: a refresh shows as a readable diff
    body = ",\n".join(json.dumps(ring, separators=(",", ":")) for ring in data["shapes"])
    with open(out, "w", encoding="utf-8") as f:
        f.write('{"scale": %d, "shapes": [\n%s\n]}\n' % (data["scale"], body))
    print(f"{out}: {len(data['shapes'])} rings, {sum(len(r) for r in data['shapes']) // 2} points, "
          f"{os.path.getsize(out)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

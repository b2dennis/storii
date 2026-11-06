"""Renders the storii icon (a keyhole on a rounded square) as PNGs, no dependencies:
python3 assets/make_icons.py [--square|--mac] OUTDIR SIZE...
(--square: full-bleed and opaque, for iOS, which rounds it itself; --mac: inset on Apple's macOS icon grid)"""
import math, struct, sys, zlib

SQUARE = "--square" in sys.argv
MAC = "--mac" in sys.argv
MAC_MARGIN = 100 / 1024  # the macOS grid: an 824 px body on a 1024 px canvas

BG = (88, 86, 214)
FG = (255, 255, 255)

def inside(x, y):
    """Coverage test in unit coordinates (0..1). Returns 'bg', 'fg' or None."""
    if MAC:
        x, y = (x - MAC_MARGIN) / (1 - 2 * MAC_MARGIN), (y - MAC_MARGIN) / (1 - 2 * MAC_MARGIN)
        if not (0 <= x <= 1 and 0 <= y <= 1):
            return None
    r = 0.0001 if SQUARE else 0.22
    cx, cy = min(max(x, r), 1 - r), min(max(y, r), 1 - r)
    if (x - cx) ** 2 + (y - cy) ** 2 > r * r:
        return None
    # keyhole: circle plus a tapering slot below it
    if (x - 0.5) ** 2 + (y - 0.42) ** 2 <= 0.13 ** 2:
        return "fg"
    if 0.45 <= y <= 0.74:
        half = 0.045 + (y - 0.45) * 0.17
        if abs(x - 0.5) <= half:
            return "fg"
    return "bg"

def render(size, ss=4):
    rows = []
    for py in range(size):
        row = bytearray([0])
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    k = inside((px + (sx + .5) / ss) / size, (py + (sy + .5) / ss) / size)
                    if k:
                        c = BG if k == "bg" else FG
                        acc[0] += c[0]; acc[1] += c[1]; acc[2] += c[2]; acc[3] += 255
            n = ss * ss
            a = acc[3] / n
            if a:
                row += bytes([round(acc[0] / (acc[3] / 255)), round(acc[1] / (acc[3] / 255)), round(acc[2] / (acc[3] / 255)), round(a)])
            else:
                row += bytes(4)
        rows.append(bytes(row))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a not in ("--square", "--mac")]
    out = args[0]
    for s in map(int, args[1:]):
        open(f"{out}/icon-{s}.png", "wb").write(render(s, ss=2 if s > 256 else 4))

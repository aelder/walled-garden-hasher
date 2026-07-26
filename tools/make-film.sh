#!/bin/sh
# Cut a video into ASCII frames for the hashrate window.
#
#   tools/make-film.sh input.mp4 [fps] [width]
#
# Writes numbered frames to ~/.config/vh22/film, which is where vh22-top looks
# unless VH22_FILM says otherwise. Needs ffmpeg and python3.
#
# No frames ship with this repository, and none will. Point it at something you
# have the right to use: the player does not care what it is playing.
set -eu

src=${1:-}
fps=${2:-24}
width=${3:-100}
out=${VH22_FILM:-$HOME/.config/vh22/film}

if [ -z "$src" ] || [ ! -f "$src" ]; then
	echo "usage: $0 <video> [fps] [width]" >&2
	exit 2
fi
command -v ffmpeg >/dev/null || { echo "ffmpeg is not installed" >&2; exit 1; }

# A terminal cell is about twice as tall as it is wide, so the height is halved
# to stop the picture stretching. The player scales to fit whatever the plot
# area is, so this only decides how much detail there is to scale down from.
height=$(( width * 3 / 4 / 2 ))

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "cutting $src at ${fps} fps, ${width}x${height}…"
ffmpeg -loglevel error -i "$src" -vf "fps=$fps,scale=${width}:${height}" \
	"$tmp/%06d.pgm"

mkdir -p "$out"
rm -f "$out"/*.txt

python3 - "$tmp" "$out" <<'EOF'
import glob, os, sys

tmp, out = sys.argv[1], sys.argv[2]
ramp = " .:-=+*#%@"          # densest last, so brightness reads at a glance

def pgm(path):
    """Binary PGM: P5, then width height and maxval as whitespace-separated
    tokens that may or may not share a line, then one byte per pixel."""
    data = open(path, "rb").read()
    tok, off = [], 2
    while len(tok) < 3:
        while data[off:off + 1].isspace():
            off += 1
        if data[off:off + 1] == b"#":
            off = data.index(b"\n", off) + 1
            continue
        end = off
        while not data[end:end + 1].isspace():
            end += 1
        tok.append(int(data[off:end]))
        off = end
    return tok[0], tok[1], data[off + 1:]

n = 0
for n, path in enumerate(sorted(glob.glob(os.path.join(tmp, "*.pgm"))), 1):
    w, h, px = pgm(path)
    rows = ["".join(ramp[min(len(ramp) - 1, p * len(ramp) // 256)]
                    for p in px[y * w:(y + 1) * w])
            for y in range(h)]
    with open(os.path.join(out, "%06d.txt" % n), "w") as fh:
        fh.write("\n".join(rows) + "\n")
print("%d frames -> %s" % (n, out))
EOF

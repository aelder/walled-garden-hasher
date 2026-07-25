#!/bin/sh
# A/B a compile-time switch against the current default.
#
#   tools/compare.sh "-DVH22_PMULL_ASM=0" "clang's DUP+PMULL2" [lanes] [seconds]
#
# Both variants are rebuilt from scratch, self-tested, then run back to back at
# the same lane count so thermal drift affects them roughly equally.
set -e
FLAG="$1"
LABEL="${2:-variant}"
LANES="${3:-64}"
SECS="${4:-8}"
OUT=build/compare
mkdir -p "$OUT"

if pgrep -x ccminer >/dev/null 2>&1; then
	echo "refusing to measure: a ccminer process is competing for CPU" >&2
	exit 1
fi

build() {
	tag="$1"; extra="$2"
	${CXX:-clang++} -O3 -mcpu="${MCPU:-native}" -std=c++17 -Iinclude -Iref \
		-fno-stack-protector -fomit-frame-pointer $extra \
		tools/bench.cpp src/verushash.cpp src/clhash_wave.cpp \
		-o "$OUT/bench-$tag" -lpthread
	${CXX:-clang++} -O3 -mcpu="${MCPU:-native}" -std=c++17 -Iinclude -Iref \
		-fno-stack-protector -fomit-frame-pointer $extra \
		tools/selftest.cpp src/verushash.cpp src/clhash_wave.cpp ref/ref.cpp \
		-o "$OUT/selftest-$tag" -lpthread
}

build base ""
build var "$FLAG"

for tag in base var; do
	if ! "$OUT/selftest-$tag" | tail -1 | grep -q "0 failures"; then
		echo "refusing to measure: $tag failed the differential harness" >&2
		exit 1
	fi
done

echo "lanes=$LANES seconds=$SECS  (both variants self-tested clean)"
printf 'baseline           : '
"$OUT/bench-base" --lanes "$LANES" --seconds "$SECS" | tail -1
printf '%-19s: ' "$LABEL"
"$OUT/bench-var" --lanes "$LANES" --seconds "$SECS" | tail -1

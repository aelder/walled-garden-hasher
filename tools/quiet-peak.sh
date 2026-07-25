#!/bin/sh
# Quiet-machine peak run for the vh22 engine.
#
# Peak is the goal, so the protocol is deliberately identical to the run that
# recorded 30.47 MH/s: one 8-second pass at 64 lanes across 10 threads. Not
# repeated -- repeating heats the part, and every extra run makes the next peak
# worse.
#
# Machine state is captured either side of the run because peak is a property
# of the machine as much as of the code, and a number without its conditions
# cannot be compared to anything later.
#
#   DELAY=30 tools/quiet-peak.sh
set -u
cd "$(dirname "$0")/.."

DELAY="${DELAY:-30}"
SECONDS_RUN="${SECONDS_RUN:-8}"
THREADS="${THREADS:-10}"
LANES="${LANES:-64}"

mkdir -p ../results
out="../results/peak-vh22-$(date +%Y%m%d-%H%M%S).txt"

sleep "$DELAY"

{
	echo "binary sha256: $(shasum -a 256 build/vh22-bench | cut -d' ' -f1)"
	echo "config: ${LANES} lanes, ${THREADS} threads, ${SECONDS_RUN}s, CPU only"
	echo "flags:  -O3 -mcpu=native"
	echo
	echo "--- load average at start ---"
	sysctl -n vm.loadavg
	echo "--- top consumers at start ---"
	ps -Ao %cpu,comm -r | head -6
	echo
} > "$out"

if pgrep -x ccminer >/dev/null 2>&1; then
	echo "ABORTED: a ccminer process is competing for CPU" >> "$out"
	afplay /System/Library/Sounds/Basso.aiff 2>/dev/null
	echo "$out"
	exit 1
fi

./build/vh22-bench --peak --lanes "$LANES" --threads "$THREADS" \
	--seconds "$SECONDS_RUN" >> "$out" 2>&1
status=$?

{
	echo
	echo "--- load average at end ---"
	sysctl -n vm.loadavg
} >> "$out"

if [ "$status" -eq 0 ]; then
	# Two chimes, spaced, so it carries from a minimised window.
	afplay /System/Library/Sounds/Glass.aiff 2>/dev/null
	sleep 1
	afplay /System/Library/Sounds/Glass.aiff 2>/dev/null
else
	afplay /System/Library/Sounds/Basso.aiff 2>/dev/null
fi

echo "$out"
exit "$status"

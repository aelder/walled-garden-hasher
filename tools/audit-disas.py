#!/usr/bin/env python3
"""Disassembly audit (§10).

Write the hot loop in intrinsics, then read the disassembly. The two things
clang will silently ruin are AESE/AESMC adjacency and the EXT/PMULL pairing --
both are correctness-neutral and performance-fatal, so neither shows up in the
differential harness. This checks them mechanically.

  usage: audit-disas.py build/src/clhash_wave.o [more.o ...]
"""
import re
import subprocess
import sys

LINE = re.compile(r"^\s*[0-9a-f]+:\s+(\S+)\s*(.*)$")


def mnemonic(op):
    """Strip the vector arrangement suffix: aese.16b -> aese."""
    return op.split(".")[0]


def disassemble(path):
    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", path],
        capture_output=True, text=True, check=True).stdout
    ops = []
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            ops.append((mnemonic(m.group(1)), m.group(2)))
    return ops


def reg(operand):
    return operand.strip().split(".")[0]


def audit(path):
    ops = disassemble(path)
    counts = {}
    for op, _ in ops:
        counts[op] = counts.get(op, 0) + 1

    problems = []

    # 1. AESE must be immediately followed by AESMC on the same register.
    #    Firestorm fuses the pair into 2 uops at 3-cycle latency and 4/cycle
    #    throughput only when they are adjacent with matching operands.
    #    Striping four independent lanes (aese v0/v1/v2/v3 then aesmc ...)
    #    is the tempting schedule and it breaks fusion.
    paired = broken = 0
    for i, (op, args) in enumerate(ops):
        if op != "aese":
            continue
        dst = reg(args.split(",")[0])
        nxt = ops[i + 1] if i + 1 < len(ops) else ("", "")
        if nxt[0] == "aesmc" and reg(nxt[1].split(",")[0]) == dst:
            paired += 1
        else:
            broken += 1
            problems.append(
                "aese %s at +%d not followed by matching aesmc (next: %s %s)"
                % (dst, i, nxt[0], nxt[1]))

    # 2. PMULL2 is reported as 5-6 cycles at 2/cycle against PMULL's 3 at
    #    4/cycle on Firestorm, which is why the notes say to avoid it. That is
    #    NOT what M5 measures -- see arch.h -- so this is reported, not
    #    flagged. Re-measure before changing it on new silicon.

    # 3. The table-based AES fallback shows up as tbl/tbx over 4-register
    #    tables. A handful of single-table tbl is the reduction shuffle.
    if counts.get("tbx", 0):
        problems.append("tbx emitted: likely the sse2neon software S-box path")

    print("%s" % path)
    print("  aese/aesmc fused pairs: %d   broken: %d" % (paired, broken))
    print("  pmull %d   pmull2 %d   ext %d   tbl %d   sqrdmulh %d   eor %d" % (
        counts.get("pmull", 0), counts.get("pmull2", 0), counts.get("ext", 0),
        counts.get("tbl", 0), counts.get("sqrdmulh", 0), counts.get("eor", 0)))
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:12]
    print("  top: " + ", ".join("%s=%d" % kv for kv in top))
    for p in problems:
        print("  PROBLEM: %s" % p)
    print()
    return len(problems)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    bad = sum(audit(p) for p in sys.argv[1:])
    if bad:
        print("%d problem(s) found" % bad)
    else:
        print("clean")
    sys.exit(1 if bad else 0)

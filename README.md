# vh22 — native AArch64 VerusHash 2.2

A greenfield C++ implementation of VerusHash 2.2 built directly on ARM crypto
intrinsics, rather than routing x86 intrinsics through `sse2neon`. Written
against *VerusHash 2.2 — Native Apple Silicon Port: Engineering Notes*; section
references below (§N) are to that document.

```
make test        # differential harness against ref/ (written from the spec)
make bench       # throughput
make crosscheck  # end-to-end diff against the deployed sse2neon build
python3 tools/audit-disas.py build/src/*.o   # §10 codegen checks
```

`make test` and `make bench` are self-contained. `make crosscheck` builds the
upstream sources in `../verus`, which include sse2neon as a submodule, so a
fresh clone needs it once:

```
git submodule update --init verus/sse2neon
```

## Layout

| Path | What |
|---|---|
| `include/vh22/arch.h` | Every NEON primitive, one per instruction we actually want |
| `include/vh22/haraka.h` | Fused Haraka256/512, keyed and truncated variants |
| `include/vh22/clhash_bodies.h` | The eight CLHash step bodies |
| `src/clhash_wave.cpp` | N-way interleaved, case-bucketed kernel |
| `src/verushash.cpp` | Template setup, key expansion, per-nonce driver |
| `ref/` | Intrinsic-free specification. Slow on purpose |
| `tools/` | Harnesses, benchmark, disassembly audit, A/B script |

## Results

M5 (4P + 6E, 128 KB L1D), clang 21, `-O3 -mcpu=native`, against the tuned
`sse2neon` production miner on the same machine and the same work:

| | production | vh22 | |
|---|---|---|---|
| 1 thread | 3.85 MH/s | **4.97 MH/s** | +29% |
| 10 threads | 26.21 MH/s | **29.28 MH/s** | +12% |

Full-machine convergence is expected: at 10 threads the machine is power- and
bandwidth-limited, so per-core engine quality stops being the binding
constraint.

### Peak

`vh22-bench --peak` reports the fastest sampled window rather than the run
average. Best recorded, 8 s, 64 lanes, 10 threads, CPU only:

```
PEAK      30.47 MH/s   (best 100 ms window)
          30.33 MH/s   (best 500 ms)
          30.20 MH/s   (best 1 s)
average   29.69 MH/s   (239415296 hashes in 8.06 s)
```

The 1 s figure tracking the 100 ms one is what says the peak is an operating
point and not a scheduling burst caught by a short window. The timeline was
flat across the full 8 s, so this is short of thermal throttling.

**Peak is a property of the machine's state as much as the code, so it needs
its conditions quoted with it.** That run was at load average 1.74 on a
session-cold machine. The identical binary measured 28.6-29.1 MH/s later the
same session at load 3.10 with accumulated heat -- a 5% spread with no code
change. Comparisons between builds must be interleaved A/B pairs inside one
short window; absolute peaks across sessions are not comparable.

Correctness: 70255 differential checks against `ref/`, 2800 against the
upstream build, 0 failures.

## What the notes got right

**§7 — the branch problem is the whole game.** Measured against an
identity-order control with everything else identical: case-bucketed dispatch
is worth **+45% at 16 lanes and +69% at 64**. And without bucketing, 64 lanes
is *slower* than 16 — exactly the predicted fight between interleaving and
misprediction, since a pipeline flush discards in-flight work from every lane
at once. Bucketing removes the conflict; only then does lane count scale.

**§8 — don't prefetch.** Worth doubting, because the reasoning assumes an
L1-resident key and at 64 lanes the working set is 565 KB. Measured anyway:
removing all software prefetch is **+6.5%**, consistently, at every lane and
thread count. Four `prfm` per lane per step is 128 extra memory-pipe operations
per hash, and the addresses are known only one step ahead — too late to cover
an L2 hit, early enough to compete with the loads that matter.

**§4 — `SQRDMULH`.** One instruction where `sse2neon` spends five. The x86 wrap
at `a = b = -32768` is real but is handled by re-verifying candidates on the
exact path, so the mining loop carries no fixup at all.

**§5 — fused AES chains, and the pairing rule.** Pinning `AESE`/`AESMC`
adjacency with inline asm is +1.1% and takes the broken-pair count in the
finalisation Haraka from 5 to 0. `tools/audit-disas.py` checks this
mechanically, because it is correctness-neutral and so invisible to the
harness.

**§9 — the reduction shuffle indices are provably in [0,15]**, so `sse2neon`'s
defensive `AND #0x8F` is dropped. The reference latches if that bound is ever
violated; it never has been.

## Where measurement disagreed with the notes

**§2/§12 — "PMULL2: measurably worse; do not use".** Not on M5. Forcing
`EXT`+`PMULL` via asm is *slower* than clang's `DUP`+`PMULL2` at every point
from the latency-bound single stream (+0.7%) to the 64-lane wave (+2.6%). Both
are two instructions; whatever the M1 penalty was, it is gone. The notes are
explicit that their timings are M1-era and must be re-measured — this is one of
the places that changed.

**§6 — "N ≈ 12–14 before you're fighting for capacity".** That is the L1
capacity limit, and it is not where the optimum is. Throughput rises
monotonically to 64 lanes (565 KB, firmly in L2) and only turns over past 96.
Low lane counts do not have enough independent work in flight to hide even L1
latency plus the dependency chains, so L1 residency is the wrong thing to
optimise for.

**§8 — set-conflict padding.** Predicted to matter, reasoning from regions
exactly 8192 B apart whose bases differ only in high address bits. But
`VERUSKEYSIZE` is 8832 = 138 cache lines, not a power of two, so consecutive
lane bases already walk through the sets. Measured residual is +0.75% at 64 B
of padding, and everything from 384 B up is clearly worse.

## Beyond the notes

**Unpredictable *value* branches cost far more than unpredictable *loop counts*.**
Making case 3's `dividend & 1` coin flip branchless is **+8.4%** — implying
roughly 19 cycles per mispredict, in line with §7's estimate. But giving case
6's 1..8 iteration loop a constant trip count of eight *lost* 3.8%: the surplus
iterations cost more than the exit branch does, so variable-bound counted loops
are being predicted well. That asymmetry says where to stop looking.

**Case 6 restructured.** Only its mulhrs reads the accumulator, so the key XOR,
the carry-less product and the 64/32 division all hoist off the chain. And
`mulhrs(x, 0)` is exactly 0 in both the x86 and the SQRDMULH definition, which
collapses its two branches into one straight-line step.

**`CL()` of the four `pbuf_copy` vectors is loop-invariant per hash** and is
precomputed, rather than recomputed inside cases 1, 2 and 3.

**§7(b) partial predication was not pursued.** The notes suggest merging cases
`0x00/0x04/0x08/0x1c` into one predicated body to cut the dispatch to five
targets. That pays when the dispatch is an unpredictable indirect branch; with
bucketing it is already predictable loop control, so predication would add
`BSL` selects to every lane to save a handful of predictable dispatches per
wave. The measured cost of case-6's speculative work points the same way.

## GPU cost-sieve: measured dead on this engine

The prior campaign's `codex/gpu-nonce-sieve` is a *work-cost* sieve, not a
share-probability one: the GPU forecasts how expensive each nonce's walk will
be, and the CPU completes only the cheapest fraction. Every nonce is an equally
likely ticket, so completing more cheap ones per second is a real gain. It was
found net-negative on an M2 Max because the 38-core GPU sustained ~40 Mcand/s
of depth-4 forecasts against a ~76 Mcand/s CPU demand.

`tools/sieve_oracle.cpp` measures the *ceiling* on this engine: the forecast is
computed on the CPU and not counted against the clock, exactly as if an
infinitely fast, perfectly accurate GPU had supplied it free. No real sieve can
beat these numbers.

| forecast depth | keep | per-hash gain | forecasts needed, 10 threads |
|---|---|---|---|
| 4 | 0.30 | +3 to +7% | 171 Mcand/s |
| 8 | 0.30 | +4.6% | 173 Mcand/s |
| 32 (perfect) | 0.30 | +8.5% | 179 Mcand/s |
| 32 (perfect) | 0.10 | +18.1% | 588 Mcand/s |
| 4 | 0.50 | +2.0% | 102 Mcand/s |

Two things moved against it, and this engine caused both.

**The leverage shrank.** A sieve's entire value is the variance of per-nonce
cost. The cost model weights case 3 at 13 and case 6 at 10 per mod-branch --
and those were largely *branch mispredict* costs. Case 3 is now branchless and
case 6 is restructured, so the spread they created is gone. The model still
predicts the cheapest 30% are 33% below mean cost at depth 4; the measured
gain is a fifth of that.

**The demand grew.** The engine is ~30% faster per core, so it consumes
candidates that much faster.

The supply side is not close. A depth-4 forecast is ~1/8 of a full hash, so
171 Mcand/s is ~21 MH/s of full-hash-equivalent GPU work. The additive Metal
worker measures the same GPU at ~1.2 MH/s. That is a shortfall of roughly 18x,
and the M2 Max figures corroborate the model: 40 Mcand/s at depth 4 is ~5 MH/s
equivalent against a ~3.1 MH/s measured additive worker there.

A CPU-side sieve is worse still: at keep 0.30 each completed hash needs 3.33
forecasts, so a depth-4 forecast costs 13.3 steps against a 32-step walk --
about 42% overhead to buy 7%.

The same GPU used *additively* already banks +4-5% on M5 with no orchestration,
no starvation risk, and no CPU-side complexity. That is where the GPU belongs.

## A correctness note worth keeping

Upstream's case 4 opens with `const __m128i *rc = prand;`, which **shadows the
global Haraka round-constant table** — its AES rounds use key material, exactly
as case 5 does. This tree originally read the fixed constants in *both* the
engine and the reference, so 70255 differential checks passed on a wrong
implementation.

A reference transcribed from the same misreading as the implementation agrees
with it perfectly. `make crosscheck` exists because of this: it diffs against
the build that is actually mining, which shares no authorship with either.

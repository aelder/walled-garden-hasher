# Engineering notes

Implementation details, protocol decisions, and measurements for the native
Apple silicon engine are recorded below. User installation and operation are
covered in [`../README.md`](../README.md) and [`../INSTALL.md`](../INSTALL.md).

## Design

The engine is a C++ implementation of VerusHash 2.2 using ARM
crypto intrinsics directly. It does not route x86 intrinsics through
`sse2neon`. The production miner links only project-owned code; upstream Verus
and `sse2neon` sources are present solely for the independent cross-check.

The main components are:

| Path | Responsibility |
|---|---|
| `include/vh22/arch.h` | NEON primitives and explicit instruction choices |
| `include/vh22/haraka.h` | Fused Haraka-256/512 and keyed/truncated variants |
| `include/vh22/clhash_bodies.h` | Eight CLHash step bodies |
| `src/clhash_wave.cpp` | N-way interleaved, case-bucketed kernel |
| `src/verushash.cpp` | Template setup, key expansion, and nonce driver |
| `ref/` | Intrinsic-free reference implementation |

### Case bucketing

Verus CLHash selects one of eight step bodies from data. Dispatching each lane
independently creates an unpredictable branch that flushes unrelated work from
the pipeline. The native engine groups lanes by case, making dispatch loop
control predictable while retaining enough independent work to cover latency.

Against an identity-order control, case-bucketed dispatch measured 45% faster
at 16 lanes and 69% faster at 64 lanes. Without bucketing, 64 lanes were slower
than 16; with bucketing, throughput continued to improve through 64 lanes.

### ARM instruction choices

- `SQRDMULH` replaces the longer translated sequence for the signed high-half
  multiply. The `-32768 * -32768` saturation difference is handled when a
  candidate is re-verified on the exact path.
- Fused AES chains keep `AESE` and `AESMC` adjacent. The disassembly audit
  checks this property because functional tests cannot detect a scheduling
  regression.
- Reduction shuffle indices are proven to remain in `[0, 15]`, allowing the
  defensive mask used by the translated implementation to be removed.
- On the tested M5, clang's `DUP` plus `PMULL2` sequence outperformed a forced
  `EXT` plus `PMULL` sequence. Older M1-era guidance did not hold on this CPU.
- Software prefetching reduced performance. At 64 lanes, four `prfm`
  operations per lane and step competed with useful memory operations without
  covering enough latency.

### Other measured changes

- Making case 3's value-dependent coin flip branchless improved throughput by
  8.4%.
- Forcing case 6 to a constant eight iterations reduced throughput by 3.8%; the
  extra work cost more than its variable loop-exit branch.
- Case 6 hoists the key XOR, carry-less product, and division away from the
  accumulator dependency chain.
- The CL transform of the four copied preimage vectors is computed once per
  hash rather than in cases 1, 2, and 3.
- Set-conflict padding provided only a 0.75% residual gain at 64 bytes and
  regressed at larger values. `VERUSKEYSIZE` already walks cache sets because
  it is 8832 bytes rather than a power of two.

## Stratum and share construction

`net/` implements the Verus PBaaS stratum protocol and contains a small JSON
parser for the required nested objects, arrays, strings, and numbers.

For solution version 7 with a descriptor, canonical header fields are not part
of the hashed preimage. The previous hash, merkle root, sapling root, nBits,
and 32-byte nonce are zeroed; identifying data is carried in the solution's
nonce space.

The engine varies the final 15 solution bytes used by VerusHashHalf: 11 bytes
of nonce space followed by the counting nonce. These begin at solution byte
1329 because the final partial block is preimage bytes 1472 through 1486 and
the solution follows a three-byte CompactSize prefix. The submission must
splice those bytes into the solution returned to the pool. Sending the
unchanged solution from `mining.notify` produces a well-formed share for a
different preimage and is rejected.

The same values are also written to the header: the counting nonce at word 30
and the per-worker tag at word 32. The solution remains authoritative for the
hash.

### Connection behavior

- Connect, handshake, first-job, and silence intervals are bounded.
- Reconnect backoff doubles from one second to 30 seconds and resets after a
  session reaches Ready.
- A reconnect discards the old job, target, and extranonce.
- Unanswered shares become stale because their outcome cannot be known.
- `client.reconnect` is honored.
- Stopped or disconnected work is reported as stalled, not mining.

## Correctness strategy

Release verification uses four complementary gates:

| Gate | Detects |
|---|---|
| `make test` | Engine differences from the intrinsic-free specification reference |
| `make crosscheck` | Shared misreadings in the engine and local reference |
| `make stratum-test` | Share construction, submission, and accounting errors |
| `tools/audit-disas.py` | Performance-sensitive code-generation regressions |

The mock pool validates submit parameter count, nonce length, the `fd4005`
CompactSize prefix, and hex encoding. It also reconstructs the preimage from
the submitted nonce and solution, hashes it, and checks both the solved digest
and target. A negative test submits the unmodified solution and requires the
re-derived digest to differ.

This combination caught an interpretation error that passed 70,255 checks
against the local reference. Upstream case 4 shadows the global Haraka
round-constant table with key material. The native engine and local reference
both initially used the global table; the deployed-implementation cross-check
detected the difference.

Recorded validation result: 70,255 differential checks and 2,800 upstream
cross-checks with zero failures.

## Performance

### Sustained comparison

Measured on an M5 with four performance and six efficiency cores, 128 KB L1D,
clang 21, and `-O3 -mcpu=native`. The comparison used the tuned production
`sse2neon` miner on the same machine and work.

| Threads | Production | Native engine | Change |
|---:|---:|---:|---:|
| 1 | 3.85 MH/s | **4.97 MH/s** | +29% |
| 10 | 26.21 MH/s | **29.28 MH/s** | +12% |

At ten threads, power and memory bandwidth become limiting, so the full-machine
gain is smaller than the single-thread engine gain.

### Peak protocol

`vh22-bench --peak` reports sampled peak windows in addition to the run
average. The best recorded CPU-only result used eight seconds, 64 lanes, and
ten threads:

```text
PEAK      30.47 MH/s   (best 100 ms window)
          30.33 MH/s   (best 500 ms)
          30.20 MH/s   (best 1 s)
average   29.69 MH/s   (239415296 hashes in 8.06 s)
```

A separate cold run measured 30.42 MH/s peak and 29.59 MH/s average. The 1 s
window tracking the 100 ms result indicates a short operating point rather
than a scheduler burst.

Peak results depend heavily on machine state. The quoted run began at load
average 1.74 on a session-cold machine. The same binary later measured
28.6–29.1 MH/s at load 3.10 with accumulated heat. Absolute peaks are comparable
only under matched thermal conditions; the benchmark protocol uses interleaved
A/B pairs within one short window.

`tools/quiet-peak.sh` automates the cold eight-second protocol and records
machine state before and after the run.

## GPU cost-sieve result

`tools/sieve_oracle.cpp` measures the ceiling of a work-cost sieve: it assumes
an infinitely fast, perfectly accurate external forecast and does not charge
forecast time to the CPU result.

| Forecast depth | Keep | Per-hash gain | Forecast demand, 10 threads |
|---:|---:|---:|---:|
| 4 | 0.30 | +3% to +7% | 171 Mcand/s |
| 8 | 0.30 | +4.6% | 173 Mcand/s |
| 32, perfect | 0.30 | +8.5% | 179 Mcand/s |
| 32, perfect | 0.10 | +18.1% | 588 Mcand/s |
| 4 | 0.50 | +2.0% | 102 Mcand/s |

The native CPU optimizations reduced the cost variance that made a sieve
valuable while increasing candidate demand. A depth-4 forecast needs roughly
one eighth of a full hash, so 171 Mcand/s represents about 21 MH/s of
full-hash-equivalent GPU work. The measured additive Metal worker reached
about 1.2 MH/s on the same GPU. An additive worker therefore remains more
useful than a cost sieve for this engine.

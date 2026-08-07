# Contributing

Contributions are welcome, especially reproducible correctness fixes,
performance measurements, and improvements to the terminal interface.

## Development environment

The project targets Apple silicon and uses AArch64 crypto intrinsics, so its
full build and test suite must run on an Apple silicon Mac.

```bash
git clone --recurse-submodules https://github.com/aelder/walled-garden-hasher.git
cd walled-garden-hasher
make
```

The default compiler is `clang++`, with C++17, `-O3`, and `-mcpu=native`.
Override Make variables on the command line when testing another configuration,
for example `make MCPU=apple-m2`.

## Required checks

Run all four gates before submitting a pull request:

```bash
make test
make crosscheck
make stratum-test
python3 tools/audit-disas.py build/src/*.o
```

Each gate covers a different failure class:

- `make test` compares the native engine with the intrinsic-free reference.
- `make crosscheck` compares it with the independently written deployed Verus
  implementation.
- `make stratum-test` validates the share path against a mock pool.
- The disassembly audit catches instruction-selection and scheduling changes
  that do not affect correctness.

For engine performance changes, include the exact hardware, compiler version,
flags, lanes, threads, duration, and thermal/load conditions. Use interleaved
A/B runs rather than comparing peaks from different sessions.

## Change guidelines

- The shipping miner remains dependency-free.
- Files under `third_party/` are reserved for the independent cross-check and
  are excluded from the shipping miner.
- Behavior changes require updates to the intrinsic-free reference and coverage
  from the independent cross-check.
- Changes to stratum messages, nonce construction, share accounting, timeouts,
  or reconnect behavior require corresponding mock-pool coverage.
- User-visible changes include updates to `README.md`, `INSTALL.md`, and
  `CHANGELOG.md` where applicable.
- C++ changes follow the formatting style of the surrounding code.

## Pull requests

Keep each pull request focused and describe:

1. What changed and why.
2. Which failure or performance hypothesis it addresses.
3. The commands used to verify it.
4. Benchmark conditions and before/after results, when relevant.

CI runs the four gates on Apple silicon. Tagged releases are packaged only
after those gates pass.

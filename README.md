# The Walled Garden Hasher

[![CI](https://github.com/aelder/walled-garden-hasher/actions/workflows/ci.yml/badge.svg)](https://github.com/aelder/walled-garden-hasher/actions/workflows/ci.yml)

A CPU-only VerusHash 2.2 miner built specifically for Apple silicon. It ships as
one dependency-free binary with a native ARM engine, a Verus PBaaS stratum
client, and the `vh22-top` terminal interface.

The hashing engine uses ARM crypto intrinsics directly instead of translating
x86 intrinsics through `sse2neon`. On an M5 MacBook Air it measured 4.97 MH/s
on one thread and 29.28 MH/s sustained on ten threads. See
[`docs/ENGINEERING.md`](docs/ENGINEERING.md) for the benchmark conditions,
architecture, and correctness notes.

> [!CAUTION]
> Mining keeps the selected CPU cores busy, increasing heat and power draw.
> Battery runtime will decrease during sustained mining.

## Requirements

- An Apple silicon Mac
- A terminal at least 60 columns by 19 rows; truecolor is recommended
- Xcode Command Line Tools when building from source

There are no third-party runtime dependencies. Intel Macs are not supported.

## Quick start

### Download a release

Download the macOS ARM64 archive and matching SHA-256 file from
[GitHub Releases](https://github.com/aelder/walled-garden-hasher/releases), then
follow the verification and installation steps in [`INSTALL.md`](INSTALL.md).
Release binaries are currently unsigned and not notarized.

### Build from source

```bash
git clone https://github.com/aelder/walled-garden-hasher.git
cd walled-garden-hasher
make top
```

`make top` builds and launches `build/vh22-top`. The miner asks for a payout
address, rig name, and pool on first run.

Only the payout address, rig name, and pool settings are stored. The application
does not create or store a wallet, private key, or seed phrase.

## Interface

`vh22-top` is a keyboard-driven terminal dashboard with live hashrate, share
counts, per-core load, pool state, and bounded reconnect behavior. Mining is
available only after the selected pool is verified and has supplied work.

| Key | Action |
|---|---|
| `↑` / `↓` | Move between controls |
| `←` / `→` | Adjust threads and lanes |
| `Enter` | Select, start, or stop |
| `?` | Show the in-app key guide |
| `+` / `-` | Change refresh rate |
| `i` | Set the payout address |
| `e` / `n` / `d` | Edit, add, or delete a pool in the pool list |
| `q` | Quit |

If a pool stops supplying work, the status changes from `MINING` to `STALLED`
and the hashrate falls to zero.

## Configuration

| Path or variable | Purpose |
|---|---|
| `~/.config/vh22/config` | Payout identity and pools; written with mode `0600` |
| `~/.config/vh22/news.md` | Optional ticker copy |
| `VH22_NEWS` | Override the ticker file path |
| `~/.config/vh22/film` | Optional animation frames |
| `VH22_FILM` | Override the animation directory |

Run `build/vh22-top --help` for the command-line summary. Configuration is
managed inside the interface rather than with command-line flags.

## Development commands

```bash
make                 # build the miner and development binaries
make test            # differential checks against the from-spec reference
make stratum-test    # exercise the share path against the mock pool
make bench           # run the throughput benchmark
```

The independent cross-check uses the vendored Verus sources and the `sse2neon`
submodule:

```bash
git submodule update --init third_party/verus/sse2neon
make crosscheck
python3 tools/audit-disas.py build/src/*.o
```

The four release gates are `make test`, `make crosscheck`, `make stratum-test`,
and the disassembly audit. CI runs all four on Apple silicon before a tagged
release is packaged.

## Repository layout

| Path | Contents |
|---|---|
| `include/vh22/` | ARM primitives, Haraka, and CLHash step bodies |
| `src/` | Native hashing engine |
| `net/` | PBaaS stratum client and JSON parser |
| `ui/` | Terminal interface and ticker copy |
| `ref/` | Slow, intrinsic-free correctness reference |
| `tools/` | Tests, benchmarks, code-generation audit, and utilities |
| `third_party/` | Sources used only by the independent cross-check |

More detail is available in:

- [`INSTALL.md`](INSTALL.md) — release verification, installation, and first run
- [`docs/ENGINEERING.md`](docs/ENGINEERING.md) — architecture, protocol, and performance notes
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development workflow and release gates
- [`CHANGELOG.md`](CHANGELOG.md) — release history
- [`third_party/README.md`](third_party/README.md) — third-party source provenance

## License

The miner is licensed under GPL-3.0-or-later. See [`LICENSE`](LICENSE).

Files under `third_party/` retain their upstream Apache-2.0 and MIT notices and
are compiled only for `make crosscheck`; they are not linked into the miner.

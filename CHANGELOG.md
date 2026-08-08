# Changelog

Notable user-visible changes are recorded here. The project follows semantic
versioning for release tags.

## Unreleased

### Changed

- Added prominent beta, no-warranty, hardware-load, and mining-risk notices to
  the documentation and future release archives.

## 1.1.0 — 2026-08-07

### Added

- One-screen `?` help for all dashboard controls.
- Homebrew installation through `aelder/tap/vh22-top`, including the full
  ticker data.
- Optional terminal animation support through `VH22_FILM` or
  `~/.config/vh22/film`.
- User-selectable 100 ms, 300 ms, and frozen graph refresh modes.

### Changed

- The dashboard automatically reduces its repaint rate while mining to leave
  more CPU time for hashing; keyboard input still repaints immediately.
- Release and source-install documentation now matches the published archive
  names and repository layout.

## 1.0.0 — 2026-07-25

Initial public release.

### Added

- Native Apple silicon VerusHash 2.2 engine.
- Dependency-free Verus PBaaS stratum client.
- `vh22-top` terminal dashboard with per-core load, hashrate history, pool
  status, and accepted/stale/rejected share counts.
- Persistent payout identity and pool configuration stored with mode `0600`.
- Bounded connection phases and automatic reconnect with exponential backoff.
- Differential, independent cross-check, mock-pool, and disassembly-audit
  release gates on Apple silicon CI.
- Tagged macOS ARM64 release archives with SHA-256 checksum files.

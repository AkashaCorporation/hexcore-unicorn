# Changelog

All notable changes to `hexcore-unicorn` will be documented in this file.

## [1.3.0] - 2026-04-20 — "Project Perseus — Zero-Copy Hook Delivery"

### Added

- **SAB (SharedArrayBuffer) Zero-Copy Hook Delivery** — New `hookAddSAB` API exposes a SPSC lock-free ring backed by a `SharedArrayBuffer`. C++ `CodeHookSabCB` writes 40-byte records (PC, instruction bytes, registers) directly into the SAB via `Int32Array` backing, eliminating the per-hook-fire TSFN transition. JS consumer reads records with backpressure semantics.
- **ABI Guarantees via `static_assert`** — Compile-time contracts in `unicorn_wrapper.cpp` catch any compiler that produces a layout incompatible with the JavaScript Int32Array reader in `hexcore-common`:
  - `sizeof(RingHeader) == 64` (cache-line alignment)
  - `alignof(RingHeader) == 64`
  - `sizeof(CodeHookSabSlot) == 32` (TS layout contract)
  - `sizeof(std::atomic<uint32_t>) == sizeof(uint32_t)` (ABI compatibility)
- **Split-path dispatch** — Preserves existing `emuStop()` semantics. Legacy TSFN path still available via flag; SAB is opt-in per hook via `hookAddSAB` instead of `hookAdd`.
- **Native `breakpointAdd` / `breakpointDel`** — Step-over-breakpoint support: when `start(addr)` resumes from a native breakpoint, the dance `breakpointDel → emuStart(count=1) → breakpointAdd` ensures `continue()` doesn't immediately re-fire the same breakpoint.

### Measured impact

- **1.34× throughput improvement** on heavy-hooking workloads (malware API tracing)
- **100% delivery vs ~35% legacy** under backpressure
- **7/7 SAB hook tests + SAB benchmark passing** in the integration suite

### Notes

- Perseus is the codename for the SPSC zero-copy IPC layer; Project Azoth (clean-room dynamic analysis engine) builds on top of it
- Full CPU-state `BigUint64Array` typed view (target: 10M+ inst/sec) still deferred to v4.0.0
- Legacy TSFN `hookAdd` path remains stable and unchanged — no breaking API changes

## [1.2.3] - 2026-03-26

### Fixed

- **GetRegisterSize Lookup Table** — Full per-register size lookup for x86/x64 (200+ registers: GPR 8/16/32/64-bit, XMM 128-bit, YMM 256-bit, ZMM 512-bit, FP, MMX, segment, control/debug), ARM64 (B/H/S/D/Q/X/W), and ARM32. `RegRead` returns correctly-sized buffers; `RegWrite` accepts Buffer for wide registers.
- **MemMap 32-bit Truncation** — All `Uint32Value()` calls for memory sizes replaced with BigInt-aware parsing. Enables mapping regions > 4GB.
- **StateRestore Memory Cleanup** — `StateRestore()` now calls `uc_mem_unmap()` on all existing regions before remapping from snapshot. Eliminates stale region persistence.
- **StateSave Data Loss** — When `uc_mem_read` fails, buffer is still stored (zeroed) with an `error` field for diagnostics.
- **Auto-Map Limit** — `InvalidMemHookCB` enforces `MAX_AUTO_MAPS = 1000` with atomic counter. Prevents address space exhaustion.
- **CodeHook Sequence Numbers** — `CodeHookCB` stamps atomic `sequenceNumber` for out-of-order delivery detection.
- **Copyright Headers** — Replaced Microsoft copyright with HikariSystem in all source files.

## [1.2.1] - 2026-02-15

### Fixed

- **Hook memory leaks** — replaced 5 raw `new`/`delete` hook callback allocations with `std::unique_ptr` RAII pattern to prevent leaks when exceptions occur before manual `delete`.
- **Prebuild loader** — `index.js` now tries both underscore and hyphen naming conventions for prebuilt binaries.

## [1.2.0] - 2026-02-14

### Added

- Published to npm.

### Fixed

- **Prebuild naming mismatch** — loader tries multiple naming conventions.
- **`.vscodeignore`** — added `!prebuilds/**` force-include.

## [1.1.0] - 2026-02-08

### Added

- Native breakpoints with O(1) lookup.
- Shared memory support (zero-copy, GC safe) via `memMapPtr`.
- State snapshotting (save/restore full CPU + RAM state).

## [1.0.0] - 2026-01-31

### Added

- Initial release.
- Complete Unicorn Engine N-API bindings.
- All architectures: x86, x86-64, ARM, ARM64, MIPS, SPARC, PPC, M68K, RISC-V.
- Memory operations, register operations, hook system.
- Async emulation with Promises.
- Context save/restore.
- 29/29 tests passing.

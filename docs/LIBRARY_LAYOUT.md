# Library Layout and Monorepo Scope (post-M11e)

This document records current monorepo layout and future binding/library direction.

## Current monorepo layout

Repository root crates:
- `sar-core`
- `sar-archive`
- `sar-cli`
- `sar-crypto`
- `sar-compression`
- `sar-fec`
- `sar-cdc`
- `sar-delta`
- `sar-fragmentation`
- `sar-sparse`
- `sar-loss-tolerant`
- `sar-stream`
- `sar-transport`
- `sar-partition` (deferred)

## Current ownership highlights
- `sar-archive` is the high-level archive crate.
- `sar-core` remains narrow/low-level wire+status+limits.
- `sar-cli` owns extraction/filesystem policy behavior.
- Streaming/session and transport are separated as `sar-stream` and `sar-transport`.

## Future library/binding layout
- Stable C ABI and Python module work is future **M14** scope.
- Packaging/release automation is future **M15** scope.
- Swift/iOS and Kotlin/Java Android packages are future **M16** scope.

This repository currently has no stable C ABI, no Python module, and no mobile package artifacts.

## Non-goal reminder
This document does not assume or require a separate repository/submodule split.
All statements reflect the current single-monorepo structure.

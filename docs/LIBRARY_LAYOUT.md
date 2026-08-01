<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Library Layout and Monorepo Scope

This document records current monorepo layout and future binding/library direction.
Updated through M12c.2.

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
- `sar-partition` (deferred placeholder)

Other top-level directories:
- `fuzz/` — libFuzzer fuzz workspace (M12b). A separate Cargo workspace containing fuzz targets
  for `sar-core`, `sar-archive`, `sar-stream`, and `sar-transport`. The fuzz workspace is not
  part of the main workspace build and is not published. Fuzz targets are not user-facing APIs.
- `tools/` — documentation tooling scripts (`generate_api_md.py`, `check_api_schema.py`).
- `test-vectors/` — SAR conformance test vectors.
- `docs/` — project documentation, API inventory, and generated docs.

## Generated artifacts (must not be committed by hand)

The following files are generated and must only be updated via their respective tooling commands.
Do not hand-edit them:

- `docs/API.md` — generated from `docs/machine-readable/MACHINE_READABLE_API.json` by
  `python tools/generate_api_md.py`. Always regenerate after editing the JSON inventory.

## Current ownership highlights
- `sar-archive` is the high-level archive crate.
- `sar-core` remains narrow/low-level wire+status+limits.
- `sar-cli` owns extraction/filesystem policy behavior.
- Streaming/session and transport are separated as `sar-stream` and `sar-transport`.

## Future library/binding layout
- Stable C ABI and Python module work is future **M14** scope.
  The planned path inside this monorepo is `ffi/c/`. It does not exist yet.
- Python/PyO3 binding is future **M14** scope.
  The planned path is `bindings/python/`. It does not exist yet.
- Packaging/release automation is future **M15** scope.
- Swift/iOS and Kotlin/Java Android packages are future **M16** scope.
  The planned paths are `bindings/swift/` and `bindings/android/`. They do not exist yet.

This repository currently has no stable C ABI, no Python module, and no mobile package artifacts.

No foreign-language binding directories have been created in the repository.
Do not create `ffi/`, `bindings/`, or related paths until the relevant milestone work begins.

## Non-goal reminder
This document does not assume or require a separate repository/submodule split.
All statements reflect the current single-monorepo structure.

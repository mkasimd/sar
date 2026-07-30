<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Compatibility Notes (M12c.1)

This document records current compatibility expectations for the SAR Rust reference implementation.

`specification.md` remains authoritative for SAR Protocol v1.0 wire-format requirements.

## Current compatibility expectations

* Where functionality is implemented, the goal is SAR Protocol v1.0 wire-format compatibility.
* Implemented archive, stream-session, and transport behavior should preserve the protocol invariants documented in `specification.md`.
* Conformance vectors under `test-vectors/` provide reproducible behavior checks for implemented and non-deferred cases.
* Unsupported, reserved, malformed, ambiguous, or out-of-profile inputs are expected to fail closed.

## What is not guaranteed yet

* The public Rust API surface is still experimental/pre-stable.
* No stable API guarantee is made for the Rust crates.
* No stable ABI guarantee is made.
* Cross-implementation interoperability is not yet demonstrated as complete.
* Full conformance certification is not claimed.

## Milestone boundary notes

* API inventory/generated API synchronization hardening belongs to M12c.2, not this M12c.1 pass.
* C ABI design/implementation remains future M14 scope.
* Python bindings remain future M14 scope.
* Packaging/release automation remains future M15 scope.
* Mobile bindings remain future M16 scope.
* Certification/compliance claims remain out of scope for the current implementation status.

## Deferred functionality

* Partition/multi-volume support remains deliberately deferred in implementation (`sar-partition` placeholder crate).
* Any future partition/multi-volume implementation must follow `specification.md` and update conformance/profile documentation accordingly.

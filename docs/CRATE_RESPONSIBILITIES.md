<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR Crate Responsibilities

This document records the current crate ownership boundaries in the monorepo after M12a-audit-cp.

## `sar-core`

Owns canonical wire format, status/error, limits, and low-level parse/write helpers.

Includes:

* Global Header/LFH/Central Dictionary/Footer/TLV wire structures and parsing/writing.
* Flag/entry-mode/status/error definitions and mapping.
* Resource-limit model and checked parsing/arithmetic helpers.
* Low-level sparse-map wire helpers.

Does not own:

* high-level archive reader/writer APIs
* archive audit/reporting policy
* transform orchestration
* archive-level recovery orchestration
* stream/session semantics
* transport behavior
* crypto/KMS/key-provider APIs
* delta/patch APIs
* CLI filesystem behavior

## `sar-archive`

Owns high-level archive/container behavior.

Includes:

* `ArchiveReader`/`ArchiveWriter` and options.
* Archive verification, listing, and inspection.
* Archive structural audit and machine-readable audit reports.
* Explicit inert archive/container audit for SAR-shaped bytes.
* Ordinary archive-entry validation and payload verification.
* Archive-level transform orchestration.
* Stream archive parser/profile APIs.
* Archive-level recovery/repair orchestration.
* Integration across compression/crypto/FEC/CDC/delta/fragment/sparse crates.

Boundary rule:

* `sar-archive` must not process stream/session semantics.
* `sar-archive` may classify raw LFH `EntryMode` bits for archive safety policy.
* `sar-archive` must not interpret `DATA_WRITE`, `SESSION_*`, stream lifecycle, sequence continuity, or transport semantics.
* `sar-archive` must not depend on `sar-stream`.

## `sar-cli`
Owns user-facing command behavior and extraction policy.

Includes:
- create/extract/list/verify/inspect/repair command surface.
- filesystem mutation behavior during extraction.
- metadata restoration policy gates and safe extraction defaults.

## `sar-crypto`
Owns crypto/KMS/key-provider/secret-buffer APIs.

Includes:
- KMS metadata and key-provider abstractions.
- secret-buffer types.
- cryptographic helper APIs used by archive/transport integration.

## `sar-delta`
Owns delta/patch algorithm APIs.

Includes:
- delta metadata and algorithm registry handling.
- implemented patch-application algorithms.

## `sar-stream`

Owns stateful streaming/session semantics and stream transcript validation.

Includes:

* Stateful Streaming Mode activation rules.
* Session lifecycle handling for implemented session-control messages.
* `SESSION_INIT` validation and active-session establishment.
* Implemented `SESSION_*` message validation.
* Stream ID binding and per-stream state.
* Sequence continuity and replay/gap detection.
* Heartbeat validation.
* Capability/status/acknowledgement handling where implemented.
* LOSS_TOLERANT streaming/session policy integration where applicable.
* Strict serialized stream transcript validation.
* Optional exact-byte stream transcript recording.
* Stream transcript validation reports.

Boundary rule:

* `sar-stream` owns semantic interpretation of `SESSION_CONTROL`, `OP_CODE`, `DATA_WRITE`, `SESSION_*`, Stream ID lifecycle, sequence continuity, heartbeat behavior, and stream/session state.
* `sar-stream` may use `sar-core` wire structures and parse/write helpers.
* `sar-stream` must not require `sar-archive` to interpret stream/session semantics.
* `sar-stream` transcript recording records exact input bytes; it must not reserialize or canonicalize transcripts.
* `sar-stream` transcript validation must not weaken archive/container parsing rules in `sar-archive`.
* Live transport behavior belongs in `sar-transport`, not `sar-stream`.

Does not own:

* high-level archive reader/writer APIs
* archive extraction policy
* archive audit/reporting policy
* archive-level recovery/repair orchestration
* TCP/QUIC socket/listener/client implementation
* CLI behavior
* C ABI, Python, Swift, Kotlin, Java, or mobile binding layout

## Supporting crates
- `sar-compression`: compression codecs and bounded helpers.
- `sar-fec`: FEC algorithm and metadata helpers.
- `sar-cdc`: CDC metadata/chunk map support.
- `sar-fragmentation`: fragment semantics/reassembly helpers.
- `sar-sparse`: sparse semantic validation/reconstruction helpers.
- `sar-loss-tolerant`: loss-tolerant policy helpers.
- `sar-transport`: TCP/QUIC transport bindings over `sar-stream`.
- `sar-partition`: deferred placeholder crate.

## Re-export policy note
No compatibility re-export policy is implied by this document.
Ownership is determined by the current crate boundary and public surface in source/API inventory.

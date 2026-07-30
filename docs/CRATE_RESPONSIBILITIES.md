<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# SAR Crate Responsibilities

This document records the current crate ownership boundaries in the monorepo updated through M12c.2.

## Implementation/profile policy versus wire-format behavior

Throughout this document, "wire-format behavior" refers to requirements defined in `specification.md`
for the SAR v1.0 wire format. "Implementation policy" refers to this implementation's choices that
are stricter than, or not mandated by, the wire format.

Key distinction:
- `specification.md` defines what bytes are valid SAR archives and how compliant implementations
  must parse and validate them.
- Implementation policy (resource limits, rejection thresholds, safe-extraction defaults) may be
  stricter than the wire format requires. Such policies are described here and in the API inventory
  but must not be described as universal SAR wire-format behavior unless the spec says so.
- Profile policies (e.g., `ComplianceProfile` restrictions) constrain which spec-legal archives are
  accepted by a given profile. Profile restrictions are stricter than the base wire format.

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

Implementation policy notes (not wire-format behavior):

* `ResourceLimits` values (e.g., `max_archive_size`, `max_entry_count`, `max_decoded_entry_size`) are implementation policy. The SAR wire format does not mandate specific numeric limits; the limits in `ResourceLimits` are enforcement points chosen by this implementation to prevent resource exhaustion. Callers may configure tighter or looser limits within safe ranges.
* Reserved-value and unsupported-algorithm rejection behavior is fail-closed by implementation policy. The SAR wire format assigns reserved ranges but may not prescribe specific error codes; this implementation maps them to `SarError::ReservedValue` or `SarError::Unsupported` as implementation-defined fail-closed behavior.
* Strict-mode rejection of reserved flags, unknown LFH fields, or unsupported algorithm IDs is implementation policy, not a universal SAR v1.0 interoperability requirement for all compliant readers.

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
* Archive-level recovery/repair orchestration (`recovery` module): in-memory Data Recovery TLV inspection, repair planning, and repair execution.
* Conformance test infrastructure (`conformance` module): test vector manifest types, conformance check runner, and manifest discovery (M12a). These APIs are accessible via `sar_archive::conformance::*` but are not re-exported at the crate root; they are marked `internal_public` in the API inventory.
* Integration across compression/crypto/FEC/CDC/delta/fragment/sparse crates.

Boundary rule:

* `sar-archive` must not process stream/session semantics.
* `sar-archive` may classify raw LFH `EntryMode` bits for archive safety policy.
* `sar-archive` must not interpret `DATA_WRITE`, `SESSION_*`, stream lifecycle, sequence continuity, or transport semantics.
* `sar-archive` must not depend on `sar-stream`.

Implementation policy notes (not wire-format behavior):

* The recovery/repair APIs are currently in-memory APIs accepting complete archive byte slices. This is an implementation limitation, not a SAR wire-format constraint. Streaming repair remains future work.
* `plan_archive_repair` requires explicit, block-aligned byte erasures. This alignment constraint is an implementation restriction due to an open spec question (see `docs/SPEC_QUESTIONS.md`), not a universal wire-format rule.
* Archive-level repair uses `ResourceLimits` (`max_archive_size`, `max_recovery_protected_range`, `max_repair_working_set`) as the primary protection against oversized repair working sets. This is implementation policy, not a SAR wire-format requirement.
* Safe extraction defaults and metadata restoration policy gates are implementation/CLI policy, not SAR v1.0 wire-format requirements.

## `sar-cli`
Owns user-facing command behavior and extraction policy.

Includes:
- create/extract/list/verify/inspect/repair command surface.
- filesystem mutation behavior during extraction.
- metadata restoration policy gates and safe extraction defaults.

Implementation policy notes (not wire-format behavior):

* Safe extraction defaults (e.g., refusing to extract absolute paths, symlink traversal limits, permission restoration gates) are CLI implementation policy, not SAR v1.0 wire-format requirements.
* Filesystem metadata restoration (timestamps, permissions, ownership) is gated by CLI policy flags. The SAR wire format encodes metadata fields; whether and how to restore them during extraction is implementation policy.
* The repair workflow (`sar repair`) enforces resource limits via `max_archive_size` and `max_repair_working_set` before performing any in-memory repair. This is implementation policy, not a wire-format constraint.

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

Implementation policy notes for supporting crates:

* **`sar-compression`**: The `max_output_size` decompression bound is implementation policy (caller-configured). The SAR wire format defines the `Uncompressed Size` field; enforcement of decompression bomb limits is implementation behavior.
* **`sar-fec`**: The internal 256 MiB ceiling on XOR and Reed-Solomon parity allocations is implementation policy. The SAR wire format does not mandate specific parity size limits.
* **`sar-fec`**: The `max_fec_value_bytes` and `max_repair_working_set` limits are implementation-defined resource controls. The wire format defines the FEC TLV structure; enforcement limits are this implementation's policy.
* **`sar-loss-tolerant`**: The `allow_lossy` flag never bypasses `ResourceLimits` or AEAD authentication failures. Suppressing AEAD errors via loss-tolerant semantics is explicitly prohibited by implementation policy and is not optional. The SAR spec does not permit loss-tolerant semantics to override authentication.
* **`sar-fragmentation`**: Fragment gap filling (with zeros) under `allow_lossy` is bounded by `max_loss_tolerant_gap`. This is implementation policy, not a SAR wire-format requirement.
* **`sar-partition`**: This crate is an empty deferred placeholder. No partition/multi-volume logic exists. `PartitionDescriptor` wire types remain in `sar-core` to reserve namespace. The deferred status is an implementation decision; partition/multi-volume semantics are defined in the spec.

## Re-export policy note
No compatibility re-export policy is implied by this document.
Ownership is determined by the current crate boundary and public surface in source/API inventory.

Public modules that are not re-exported at the crate root (e.g., `sar_archive::conformance::*`,
`sar_archive::transform::*`, `sar_cdc::validate::*`) are still part of the crate's public API
surface. APIs in those modules are marked `internal_public` in the API inventory to distinguish
them from the primary re-exported surface. No stability guarantee attaches to either category
while the implementation remains pre-stable.

## M12c.2 audit note
The API inventory (`docs/MACHINE_READABLE_API.json`) was audited in M12c.2.
All public APIs are pre-stable. No stable API/ABI guarantee is made.
See `docs/COMPATIBILITY.md` for the current pre-stable status statement.

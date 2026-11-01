<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Compatibility Notes

This document describes the current compatibility expectations and guarantees for
the SAR Rust reference implementation.

It is a documentation of current status, not a stability promise. No stable
API/ABI guarantees are made while the implementation remains pre-stable.

## Wire-format compatibility

SAR wire-format compatibility is a design goal for the implemented portions of
the format.

The reference implementation targets **SAR Protocol v1.0** as defined by
`specification.md`. `specification.md` is the authoritative source of truth for
wire-format behavior, validation rules, transform ordering, streaming/session
semantics, and transport bindings.

Current wire-format compatibility status:

* The implemented wire-format encoding and decoding paths target v1.0
  compatibility for the implemented feature set.
* Wire-format bytes written by the current implementation are intended to be
  parseable by a compliant SAR v1.0 reader implementing the same feature subset.
* No multi-implementation interoperability has been demonstrated yet. Wire-format
  compatibility claims remain aspirational until cross-implementation testing
  is completed.
* Some algorithm IDs and extension IDs are recognized by the parser but are not
  implemented; inputs using these IDs are rejected fail-closed rather than
  silently ignored.
* Partition/multi-volume format semantics are not implemented (see Deferred
  Functionality below).
* Deterministic cryptographic reference vectors
  (`test-vectors/crypto-reference/`) show agreement with independent
  third-party primitive libraries and an independent byte-layout derivation of
  Global Header, LFH and AAD. This is not second-implementation SAR archive
  interoperability.
* No complete Section 12 Compliance Profile is claimed; the `ComplianceProfile`
  presets in `sar-archive` are repository policy presets, not automatically
  Section 12 profiles.
* Standard Profile CDC resolution is incomplete; non-literal CDC Algo IDs are
  rejected with `SAR_ERR_UNSUPPORTED`.
* SAR-over-QUIC binding code exists, but complete directional `TLS_EXPORTER`
  interoperability is not claimed. ASYMMETRIC_WRAP (KMS Mode `0x03`) is not
  claimed as a fully implemented KMS mode.
* `max_loss_tolerant_gap` and `--max-loss-tolerant-gap` are retained but
  currently inactive, and never authorize zero-filling a fragment gap.
* Central Dictionary (Sections 7.1 and 7.2, SAR-M13b3-PARTITION-P0-IMPLEMENTATION-001):
  Empty Areas are no longer indexed (Entry Count and Offsets exclude them).
  Indexed archives written earlier by this implementation that contain Empty
  Areas listed their offsets in the Central Dictionary; they are nonconforming
  and `ArchiveReader::verify()` / `audit()` now reject them with
  `SAR_ERR_MALFORMED`. Sequential reading with `next_entry()` is unaffected,
  and `NO_INDEX` archives are unaffected. Archives written without
  `HAS_DATA_AREA_CRC32` keep their previous bytes. The legacy Rust names
  `CentralDictionary.file_count` (Entry Count), `CentralDictionary.global_crc32`
  (Data Area CRC32) and `GlobalFlags::HAS_GLOBAL_CRC32` (`HAS_DATA_AREA_CRC32`,
  bit 16) are retained unchanged; renaming them is recorded as a separate
  recommendation.

If `specification.md` and any other document conflict, `specification.md` wins.

## Rust public API stability

The public Rust API is **pre-stable** and **experimental**.

No stable API/ABI guarantee is made for the current implementation.

Public APIs may change before stabilization. See `docs/machine-readable/MACHINE_READABLE_API.json`
for the current API inventory. API inventory work and any stabilization decisions
belong to M12c.2 and later milestones.

Contributors and consumers should not depend on current API shapes remaining
unchanged. Changes that affect public API surfaces should update
`docs/machine-readable/MACHINE_READABLE_API.json` and regenerate `docs/API.md` as described in
`CONTRIBUTING.md`.

## C ABI compatibility

No stable C ABI exists. C ABI design, implementation, and stabilization are
planned for M14.

`ffi/c/` is a future planned path inside this monorepo. It does not exist yet
and is not part of the current stable API surface.

## Python bindings compatibility

No Python bindings exist. Python/PyO3 packaging is planned for M14.

`bindings/python/` is a future planned path inside this monorepo. It does not
exist yet.

## Mobile bindings compatibility

No Swift/iOS or Kotlin/Java Android bindings exist. Mobile bindings are planned
for M16.

`bindings/swift/` and `bindings/android/` are future planned paths inside this
monorepo. They do not exist yet.

## Certification and compliance

No certification or regulatory compliance is claimed.

The implementation is not certified under any standard, profile, or regulatory
framework. Certification work, if it occurs, is a future activity beyond M15/M16.

## Packaging and release automation

No stable release artifacts or release automation exist.

Packaging and release artifact automation are planned for M15. Until then,
consumers must build from source.

## Deferred functionality

The following functionality is explicitly deferred and not part of the current
implementation:

### Partition/multi-volume support

Partition Set support is not implemented. SAR-M13b3-PARTITION-P1-IMPLEMENTATION-001
adds validation of **one individual physical Partition** only: Partition Manifest
Version 1 codec (`sar-core`), a `ValidatedPartition` result (`sar-archive`, unforgeable: private fields, produced only by inspection) with status enums in `sar-partition` and an
explicit `ArchiveWriter::with_partition_manifest` /
`ArchiveReader::inspect_partition` path (`sar-archive`). A locally valid Partition
is not a complete or authenticated Partition Set. SAR-M13b3-PARTITION-P2-IMPLEMENTATION-001
adds metadata-only Partition Set validation (`sar_partition::assess_partition_set`,
`sar_archive::ValidatedPartitionSet`): identity, canonical order, completeness,
predecessor links, equivalent replicas, Global Header and KMS-configuration
consistency and limits. Results are not pinned to their sources and do not
authenticate the logical set. SAR-M13b3-PARTITION-P3-IMPLEMENTATION-001 adds a plaintext multi-Partition
**writer** (`sar_archive::PartitionSetWriter`) producing complete Sets of separate
members from caller-directed boundaries; it does not split Entries, reconstruct
or extract across Partitions, or support encryption. Cross-Partition
fragmentation/CDC, per-Partition KMS orchestration and Partition Set
extraction are not implemented (M13-BOUNDARY-003 remains open).

All generic archive, stream, recovery, transcript, CLI and Central Dictionary
entry points still reject `PARTITIONED_ARCHIVE` with `SAR_ERR_UNSUPPORTED`.

### C ABI

C ABI design, headers, sources, examples, and tests are deferred to M14.

### Python bindings

Python/PyO3 packaging, examples, and tests are deferred to M14.

### Mobile bindings

Swift/iOS and Kotlin/Java Android bindings are deferred to M16.

### Packaging and release automation

Monorepo packaging layout, CI release automation, release artifact generation,
and versioning rule formalization are deferred to M15.

### Certification and compliance

Certification under any standard, profile, or framework is not planned for any
current milestone. It remains a potential post-M16 or separate activity.

### Cold-storage and tape profiles

Cold-storage and tape profile conformance vectors are deferred. No SAR v1.0
interoperable cold-storage mechanism exists yet. See `test-vectors/profiles/README.md`
for the current placeholder status.

### External security audit

Internal security audit and remediation work is planned for M13. No independent
external security audit has started or been completed.

### Fragment gap and sparse overlap conformance vectors

Fragment gap, sparse overlap, unsafe filesystem metadata, and resource-limit
conformance vectors remain deferred. See `docs/CONFORMANCE.md` for the current
known gaps list.

## Milestone alignment

* M12b: fuzzing and malicious corpus — **complete**
* M12c.1: documentation and public-claims hardening — **complete**
* M12c.2: API inventory and crate-boundary hardening — **complete**
* M12c.3: security posture documentation — future
* M13: security audit and remediation — future
* M14: C ABI and Python module — future
* M15: packaging and release automation — future
* M16: Swift/iOS and Kotlin/Java Android packages — future

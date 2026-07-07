# Conformance Statement

This document reflects the current repository state after the Milestone 8 implementation.

## Implemented

- **Milestones 1–3 archive format and I/O**
  - global header parsing/writing
  - local file header parsing/writing
  - central dictionary and footer parsing/writing
  - TLV parsing/writing with 8-byte alignment checks
  - archive reader/writer for indexed and `NO_INDEX` archives
- **Milestone 4 compression and transform pipeline**
  - STORE (`0x00`)
  - DEFLATE (`0x01`)
  - ZSTD (`0x02`)
  - transform-plan helpers used by `sar-core`
- **Milestone 5 crypto/KMS/hashes/AEAD/AAD**
  - SHA-256 and BLAKE3
  - AES-256-GCM and XChaCha20-Poly1305 entry encryption
  - PBKDF2-HMAC-SHA256 KMS parsing/derivation
  - Argon2id KMS parsing/derivation
  - `ASYMMETRIC_WRAP` structural KMS mode plus callback-based unwrap hooks
  - authenticated-data binding for archive flags + LFH bytes
- **Milestones 6–7 FEC**
  - XOR FEC codec (`0x14`)
  - Reed-Solomon FEC codec (`0x11`)
  - Selective FEC metadata in LFH
  - FEC metadata validation during archive verify/inspect
  - CLI create/list/verify/inspect/extract coverage for current Selective FEC archives
- **Milestone 8 sparse file support**
  - `parse_sparse_map` / `write_sparse_map` for 32-bit and 64-bit sparse map formats
  - `validate_sparse_extents` — overlap and bounds checking
  - `apply_sparse_reconstruction` — scatter-gather into zero-filled logical-size buffer
  - `EntryMetadata.sparse_extents` populated from LFH sparse map bytes
- **Milestone 8 fragment reassembly**
  - `FragmentDescriptor`, `FragmentEntry` types
  - `validate_fragment_group` — bounds and overlap consistency
  - `reconstruct_fragments` — sort by index, scatter-gather by Fragment Descriptor absolute offset
  - Loss-tolerant semantics: returns `(data, is_degraded=true)` for gap with LOSS_TOLERANT; returns `FragmentGap` error without it
  - `EntryMetadata` fragment fields populated from LFH
- **Milestone 8 archive-level Data Recovery TLV support**
  - `inspect_recovery_metadata` — parse CD for RECOVERY TLVs (type IDs 0x10–0x1F), compute protected range
  - `plan_archive_repair` — validate erasures within protected range and against FEC block boundaries
  - `repair_archive` — XOR and RS erasure repair on protected range when erasures are block-aligned
  - `RecoveryMetadata`, `RecoveryPlan`, `RepairReport`, `ErasureInput` public types
  - Returns `RecoveryUnavailable` for unaligned erasures and documents spec gap in SPEC_QUESTIONS.md
- **Milestone 8 CLI additions**
  - `sar repair <archive> <output> --fec [--erasures erasures.json]` command
  - `sar extract … --allow-lossy` flag for LOSS_TOLERANT entries
  - `sar verify … --recovery` flag for recovery metadata validation
  - `sar inspect … --json` now reports `global_ec`, `fragmentation`, `sparse_files`, per-entry fragment/sparse/loss-tolerant fields, and `recovery_tlvs`
- **Tests currently present**
  - unit and integration tests across `sar-core`, `sar-fec`, `sar-crypto`, and `sar-cli`
  - CLI round-trip tests for indexed and `NO_INDEX` flows
  - CLI compression tests
  - CLI encryption tests
  - CLI FEC tests for XOR and Reed-Solomon
  - M8: fragment reassembly tests, sparse map tests, loss-tolerant tests, recovery orchestration tests, CLI M8 integration tests

## Partial

- **Compliance profiles**
  - `validate_archive_profile()` exists, but current logic is limited and does not represent complete post–Milestone 8 conformance checking.
  - `ComplianceProfile::Standard` reports that validation is not fully implemented.
- **Archive-level FEC/global EC**
  - archive verification validates recovery TLV structure when present
  - `inspect_recovery_metadata` fully parses protected range and TLV summaries
  - `plan_archive_repair` validates erasures within protected range and block boundaries
  - `repair_archive` applies XOR/RS repair for block-aligned erasures
  - returns `RecoveryUnavailable` for non-block-aligned erasures (spec gap; see SPEC_QUESTIONS.md)
  - CLI `repair` command implemented with temp-file safety pattern
- **Fragment reassembly**
  - fragment metadata fields fully parsed and surfaced in `EntryMetadata`
  - `reconstruct_fragments` and `validate_fragment_group` are fully implemented
  - full archival fragment reassembly requires the caller to supply `FragmentEntry` payloads — `ArchiveReader` does not yet stitch together multi-fragment files automatically
- **Loss-tolerant extraction**
  - LOSS_TOLERANT flag parsed and surfaced in `EntryMetadata`
  - `reconstruct_fragments` respects LOSS_TOLERANT and returns degraded flag
  - CLI `--allow-lossy` flag accepted; warns when LOSS_TOLERANT entries are present
  - full automatic loss-tolerant extraction path through `ArchiveReader` not yet wired up
- **Asymmetric-wrap KMS**
  - public KMS structures and callback-based resolution exist
  - there is no built-in asymmetric wrapping implementation in the workspace
- **CLI encrypted introspection**
  - `verify` and `extract` accept passwords
  - `list` and `inspect` do not currently accept passwords, so encrypted archives are not fully supported by those commands

## Unsupported

- full signature generation/verification
- CDC processing and CDC map interpretation
- delta patch application and reconstruction
- partition set reconstruction
- streaming/session APIs
- transport-layer APIs
- stable C ABI / FFI layer

## Planned

- later milestone crates (`sar-cdc`, `sar-delta`, `sar-fragmentation`, `sar-partition`, `sar-sparse`, `sar-loss-tolerant`, `sar-stream`, `sar-transport`) remain placeholders
- automatic end-to-end multi-fragment file assembly in `ArchiveReader`
- end-to-end loss-tolerant extraction path through `ArchiveReader`
- broader standard-profile conformance validation
- richer interoperability/vector testing for signed, fragmented, partitioned, sparse, CDC, delta, and streaming cases
- **Milestone 12:** stable FFI / C ABI for C, C++, and other language bindings

## Known Gaps

- The repository does **not** currently satisfy full Standard Compliance Profile requirements.
- Public flag and format definitions cover more protocol surface than the currently implemented behaviors.
- `sar-core::profile` still reflects an older subset of behavior and should not be treated as a definitive conformance oracle.
- `ArchiveReader` does not yet automatically stitch together multi-fragment logical files; callers must collect `FragmentEntry` payloads and call `reconstruct_fragments` directly.
- Full end-to-end loss-tolerant extraction through `ArchiveReader` is not yet integrated; the `--allow-lossy` CLI flag warns but does not perform automatic degraded reconstruction.
- Archive-level repair for non-block-aligned erasures returns `RecoveryUnavailable`; the spec does not define a normative byte-to-block mapping for this case.
- Tests cover current implemented flows, but cross-implementation interoperability vectors, malicious corpus coverage, and future-milestone behaviors are still missing.
- No C ABI, headers, `extern "C"` exports, `cdylib` targets, or binding generators are implemented in this pass.

# Conformance Statement

This document reflects the current repository state after the Milestones 6–7 remediation/fix work visible in source.

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
- **Tests currently present**
  - unit and integration tests across `sar-core`, `sar-fec`, `sar-crypto`, and `sar-cli`
  - CLI round-trip tests for indexed and `NO_INDEX` flows
  - CLI compression tests
  - CLI encryption tests
  - CLI FEC tests for XOR and Reed-Solomon

## Partial

- **Compliance profiles**
  - `validate_archive_profile()` exists, but current logic is limited and does not represent complete post–Milestones 6–7 conformance checking.
  - `ComplianceProfile::Standard` reports that validation is not fully implemented.
- **Archive-level FEC/global EC**
  - archive verification validates recovery TLV structure when present
  - there is no full archive repair orchestration or CLI repair command
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
- fragmentation reassembly
- partition set reconstruction
- sparse file reconstruction
- streaming/session APIs
- transport-layer APIs
- stable C ABI / FFI layer
- dedicated FEC repair command surface in the CLI

## Planned

- later milestone crates (`sar-cdc`, `sar-delta`, `sar-fragmentation`, `sar-partition`, `sar-sparse`, `sar-loss-tolerant`, `sar-stream`, `sar-transport`) remain placeholders
- broader standard-profile conformance validation
- richer interoperability/vector testing for signed, fragmented, partitioned, sparse, CDC, delta, and streaming cases
- **Milestone 12:** stable FFI / C ABI for C, C++, and other language bindings

## Known Gaps

- The repository does **not** currently satisfy full Standard Compliance Profile requirements.
- Public flag and format definitions cover more protocol surface than the currently implemented behaviors.
- `sar-core::profile` still reflects an older subset of behavior and should not be treated as a definitive conformance oracle.
- Current CLI FEC support is limited to create/inspect/list/verify/extract of archives that already encode Selective FEC metadata; there is no explicit `repair` workflow.
- Tests cover current implemented flows, but cross-implementation interoperability vectors, malicious corpus coverage, and future-milestone behaviors are still missing.
- No C ABI, headers, `extern "C"` exports, `cdylib` targets, or binding generators are implemented in this pass.

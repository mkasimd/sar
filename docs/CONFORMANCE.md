# Conformance Statement

This document reflects the current repository state after the Milestone 8 closeout and
maintainability cleanup pass.

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
  - `validate_sparse_extents` — overlap, bounds, and arithmetic overflow checking
  - `apply_sparse_reconstruction` — scatter-gather into zero-filled logical-size buffer; rejects excess or insufficient payload bytes
  - `EntryMetadata.sparse_extents` populated from LFH sparse map bytes
  - `ArchiveReader::read_all_logical_files` applies sparse reconstruction automatically using **LFH `Uncompressed Size`** as the final logical file size
  - Trailing sparse holes beyond the final extent are reconstructed as `0x00` bytes up to `Uncompressed Size`
  - Empty Areas (`Name Length == 0`, `IS_FRAGMENT == 0`) are excluded from logical file output and do not participate in sparse reconstruction, hashing, delta, or fragmentation
- **Milestone 8 fragment reassembly**
  - `FragmentDescriptor`, `FragmentEntry` types (with named fields, no tuple structs)
  - `LfhFragmentDescriptor` named struct in `LocalFileHeader` (replaces `Option<(u64, u32)>` tuple)
  - `validate_fragment_group` — bounds and overlap consistency
  - `reconstruct_fragments` — sort by index, scatter-gather by Fragment Descriptor absolute offset
  - Loss-tolerant semantics: returns `(data, is_degraded=true)` for gap with LOSS_TOLERANT; returns `FragmentGap` error without it
  - `EntryMetadata` fragment fields populated from LFH
  - `ArchiveReader::read_all_logical_files` assembles fragment groups automatically
  - `LogicalFile` type exposes `name`, `data`, `fragment_id`, `is_degraded`
- **Milestone 8 archive-level Data Recovery TLV support**
  - `inspect_recovery_metadata` — parse CD for RECOVERY TLVs (type IDs 0x10–0x1F), compute protected range, enforce configured `ResourceLimits`
  - `plan_archive_repair` — validate erasures within protected range and against FEC block boundaries
  - `repair_archive` — XOR and RS erasure repair on protected range when erasures are block-aligned and within repair working-set limits
  - `RecoveryMetadata`, `RecoveryPlan`, `RepairReport`, `ErasureInput` public types
  - Returns `RecoveryUnavailable` for unaligned erasures and documents spec gap in SPEC_QUESTIONS.md
- **Stage 2 resource-limit hardening**
  - unified `ResourceLimits` model threaded through archive reader, LFH parsing, TLV parsing, sparse reconstruction, fragment reassembly, and recovery/repair helpers
  - configured limits are enforced before dangerous allocations for global flags, KMS payloads, LFH headers, payload buffers, TLV values/counts, Central Dictionary regions, sparse maps, fragment groups, and repair working buffers
  - resource-limit failures return `SAR_ERR_LIMIT_EXCEEDED`
- **Stage 3 pipeline memory accounting and expansion-bomb protection**
  - effective limit enforced as `min(max_decoded_entry_size, max_in_memory_buffer, max_total_pipeline_memory)` before any reconstruction buffer is allocated
  - sparse expansion-bomb protection: `apply_sparse_reconstruction` and `read_all_logical_files` reject entries where `Uncompressed Size` exceeds configured limits **before** any allocation; the attack shape `tiny payload + huge Uncompressed Size + sparse extent near end` returns `SAR_ERR_LIMIT_EXCEEDED`, not `SAR_ERR_INVALID_MAP`
  - fragmented sparse expansion bombs rejected via the same path using fragment-0's `Uncompressed Size`
  - decompression output bounded by `max_decoded_entry_size` via `sar-compression`'s `max_output_size` parameter
  - fragment group span bounded by `max_fragment_group_span` before assembly allocation
  - fragment descriptor arithmetic overflow detected before any buffer is allocated
  - loss-tolerant gap fill bounded by `max_loss_tolerant_gap`
  - FEC/recovery working sets bounded by `max_fec_value_bytes` and `max_repair_working_set`
  - all `u64 → usize` conversions go through `ResourceLimits::allocation_len` which performs checked conversion and limit checks atomically
  - runtime memory budget not implemented by design; configured `ResourceLimits` are the deterministic protection
  - `pipeline_memory_tests` test file added covering: sparse expansion-bomb reject, sparse bounded success, general memory-bound limits, sparse trailing hole tests, fragmentation tests, compression expansion tests, FEC/recovery working-set tests
- **Milestone 8 CLI additions**
  - `sar repair <archive> <output> --fec [--erasures erasures.json]` command
  - `sar extract` supports sparse and fragmented extraction with temp-file finalization
  - `sar extract … --allow-lossy` flag permits LOSS_TOLERANT degraded output and reports it
  - `sar verify … --recovery` flag for recovery metadata validation
  - `sar inspect … --json` reports `global_ec`, `fragmentation`, `sparse_files`, per-entry fragment/sparse/loss-tolerant fields, and `recovery_tlvs`
  - M8 final pass: sparse reconstruction across fragment groups — Sparse Map MUST appear on fragment index 0 and applies to the entire reassembled group; non-zero index with sparse map returns `SAR_ERR_INVALID_MAP`; this error is never suppressed by `allow_lossy`
  - M8 final pass: `ArchiveWriter::write_sparse_entry` — writer-side sparse creation with LFH sparse map, `Uncompressed Size = logical_size`, gathered-payload write, overlap/bounds/length validation, round-trip through `ArchiveReader::read_all_logical_files`
  - M8 final pass: `ArchiveWriterOptions::sparse` field — sets `SPARSE_FILES` global flag at creation time; `write_sparse_entry` requires this flag
  - M8 final pass: CRC32 verification — `read_all_logical_files` verifies CRC32 (when `PER_FILE_CRC` set) over the fully reconstructed logical file (including sparse holes and trailing zeros), not over raw payload bytes; applies to both non-fragment and fragment-group paths
- **Stage 4 CLI and file extraction resource-safety**
  - `sar extract`, `sar verify`, and `sar repair` accept shared `ResourceLimits` override flags while keeping safe defaults when omitted
  - CLI sparse extraction validates the apparent sparse size against `max_decoded_entry_size`, creates a temp file, sets final length, seeks to each sparse extent, and writes only gathered payload bytes
  - CLI sparse extraction does not allocate `Uncompressed Size` bytes in memory and does not allocate zero buffers for sparse holes
  - fragmented sparse extraction enforces fragment count/span and sparse output limits under the same `ResourceLimits` model
  - CLI repair pre-checks archive-size limits before `fs::read`, enforces `max_repair_working_set`, and does not finalize outputs after limit failures
  - CLI resource-limit failures are surfaced clearly as `SAR_ERR_LIMIT_EXCEEDED`
  - All SAR-owned public multi-field tuple types in protocol/domain code replaced with named-field structs
  - `LfhFragmentDescriptor { absolute_offset, fragment_size }` replaces the former `(u64, u32)` tuple in `LocalFileHeader.fragment_descriptor`
  - `EntryMode` uses a private named `bits` field with explicit constructors/accessors; `SarStatusParseError` remains an opaque single-field error newtype
  - No `.0` / `.1` tuple access remains in SAR-owned protocol domain logic (only inside opaque newtype impls)
- **Tests currently present**
  - unit and integration tests across `sar-core`, `sar-fec`, `sar-crypto`, and `sar-cli`
  - CLI round-trip tests for indexed and `NO_INDEX` flows
  - CLI compression tests
  - CLI encryption tests
  - CLI FEC tests for XOR and Reed-Solomon
  - M8: fragment reassembly tests, sparse map tests, loss-tolerant tests, recovery orchestration tests, CLI M8 integration tests
  - M8 closeout: `logical_file_tests` — fragment group reconstruction, missing fragment errors, loss-tolerant degraded output, sparse zero-fill with correct `Uncompressed Size`, overlapping sparse extents, large-hole allocation cap, cursor reset
  - M8 closeout: `sparse_tests` — descriptor parsing, scatter-gather, trailing/leading/middle holes, excess/short payload rejection, zero-length descriptors
  - M8 closeout: `sparse_conformance_tests` — spec-mandated trailing-hole and multi-hole vectors, compression+sparse pipeline, fragmentation+sparse ordering, allocation cap, malformed sparse map, loss-tolerant non-suppression
  - M8 closeout: `empty_area_tests` — empty-area filtering in `read_all_logical_files`, empty areas not in fragment groups, empty areas not in sparse reconstruction
  - M8 closeout: `sparse_hash_crc_tests` — `file_crc32`/`content_hash` preserved in `EntryMetadata`; CRC32 over reconstructed file passes; CRC32 over payload-only fails; reconstructed-file includes holes; different sparse maps produce different reconstructed output
  - M8 closeout: `cli_sparse_tests` — CLI extraction of sparse holes, trailing holes, malformed sparse maps, inspection of sparse archives
  - Stage 4: `cli_resource_limit_tests` — default huge sparse-output rejection, explicit sparse expansion-bomb rejection, fragmented sparse span-limit rejection, sparse extraction success with a tight in-memory buffer, repair working-set rejection, and no-final-output guarantees
  - M8 final pass: `sparse_fragment_tests` — sparse map on fragment-0 applies to whole group; sparse map on non-zero fragment index returns `SAR_ERR_INVALID_MAP`; allow_lossy does not suppress `SAR_ERR_INVALID_MAP`; three-fragment scatter-gather via sparse map; trailing holes preserved across fragment boundaries; missing fragment without allow_lossy fails; missing fragment with allow_lossy+LOSS_TOLERANT succeeds with is_degraded=true; degraded sparse+fragment output is marked
  - M8 final pass: `sparse_writer_tests` — writer creates sparse entry with leading/middle/trailing holes; round-trips through reader; rejects overlapping extents; rejects extent beyond logical_size; rejects payload length mismatch (short and excess); requires sparse flag; edge cases (single full extent, empty extents, indexed archive)
  - Stage 3: `pipeline_memory_tests` — 25 tests covering sparse expansion-bomb reject and bounded-success, general memory-bound limits (max_decoded_entry_size, max_in_memory_buffer, max_total_pipeline_memory), sparse trailing-hole limit enforcement, fragment descriptor overflow, huge fragment group span, loss-tolerant gap limit, fragmented sparse expansion bomb, decompression output limit, compressed bomb limit, FEC/recovery working-set limits, failed-repair non-output guarantee

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
- **Sparse logical-size derivation**
  - Logical size for sparse reconstruction is taken from the LFH `Uncompressed Size` field, which the spec defines as the full logical file size including trailing holes
  - Trailing holes after the final sparse extent are filled with zero bytes
  - Sparse payload bytes (sum of extent lengths) may be smaller than `Uncompressed Size`; the difference is the trailing hole region
- **Loss-tolerant extraction**
  - LOSS_TOLERANT flag parsed and surfaced in `EntryMetadata`
  - `reconstruct_fragments` respects LOSS_TOLERANT and returns degraded flag
  - `ArchiveReader::read_all_logical_files(allow_lossy: bool)` wires LOSS_TOLERANT through the high-level path
  - AEAD authentication failures are never suppressed by `allow_lossy`
  - Format errors are never suppressed by `allow_lossy`
  - End-to-end streaming/session semantics for loss-tolerant output remain out of scope until Milestone 10
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
- archive-level repair for non-block-aligned erasures (spec gap — no normative byte-to-block mapping defined)

## Planned

- later milestone crates (`sar-cdc`, `sar-delta`, `sar-fragmentation`, `sar-partition`, `sar-sparse`, `sar-loss-tolerant`, `sar-stream`, `sar-transport`) remain placeholders
- broader standard-profile conformance validation
- richer interoperability/vector testing for signed, fragmented, partitioned, sparse, CDC, delta, and streaming cases
- **Milestone 10:** streaming/session APIs
- **Milestone 12:** stable FFI / C ABI for C, C++, and other language bindings

## Known Gaps

- The repository does **not** currently satisfy full Standard Compliance Profile requirements.
- Public flag and format definitions cover more protocol surface than the currently implemented behaviors.
- `sar-core::profile` still reflects an older subset of behavior and should not be treated as a definitive conformance oracle.
- Archive-level repair for non-block-aligned erasures returns `RecoveryUnavailable`; the spec does not define a normative byte-to-block mapping for this case.
- Content Hash verification is not implemented. The archive format stores a 32-byte content hash when `DEDUPLICATION` is set, but does not encode the hash algorithm identifier in the LFH or any other fixed-format field. The spec refers to "e.g., BLAKE3" without normatively specifying the algorithm field encoding. Verification cannot be performed without knowing the algorithm. This is an **implementation gap** (not a spec gap): once the spec normatively defines the algorithm encoding, verification can be added. See also `docs/SPEC_QUESTIONS.md`.
- Tests cover current implemented flows, but cross-implementation interoperability vectors, malicious corpus coverage, and future-milestone behaviors are still missing.
- No C ABI, headers, `extern "C"` exports, `cdylib` targets, or binding generators are implemented in this pass.

---

## Milestone 9a — Content-Defined Chunking (CDC)

**Status: Partial (updated CDC TLV registry aligned; CDC metadata parsing/validation present; recipe resolution, recipe-hash verification, Rabin, BuzHash, and `create --cdc` CLI not implemented)**

### Implemented

- **CDC global flag:** `CDC_SUPPORT` (Bit 5) is parsed, exposed in `GlobalFlags`, and tracked in `VerificationReport.cdc_support`.
- **CDC algorithm ID in LFH:** parsed when `CDC_SUPPORT` active; validated against algorithm registry; stored in `EntryMetadata.cdc_algo_id`. When `ArchiveWriter` is created with CDC Central Dictionary metadata, normal entry-writing APIs emit `LITERAL_MODE (0x00)` so LFHs remain consistent with `CDC_SUPPORT`.
- **Supported algorithms:** `LITERAL_MODE (0x00)` and `FASTCDC (0x02)`.
- **FASTCDC algorithm:** deterministic two-level gear-hash chunking with configurable `min_size`/`avg_size`/`max_size`; SHA-256 per-chunk hashes; no zero-length chunks; final chunk may be smaller than `min_size` at EOF. This implementation is useful locally, but the spec still does **not** define or encode enough normative FastCDC parameters for a portable boundary-regeneration or cross-writer chunk-equivalence claim.
- **Updated CDC metadata registry:** `0x31` remains `DATA_HASH/BLAKE3` and is **not** treated as CDC metadata. `0x40` is `CDC_MAP`, `0x41` is `CDC_EXT_PROVIDER`, `0x42–0x4E` are rejected with `SAR_ERR_RESERVED_VALUE`, and `0x4F` is accepted as implementation-defined `CDC_CUSTOM`.
- **CDC_MAP (`0x40`):** content validated via `parse_entry_cdc_map`; for M9a the stored archive catalog is authoritative for parsing and interpretation, so readers validate stored records directly and do **not** regenerate FASTCDC boundaries merely to parse or use the map. Different writers may therefore emit different valid maps for the same logical file, provided the stored metadata is self-consistent.
- **CDC_EXT_PROVIDER (`0x41`):** parsed as inert UTF-8 URI metadata only. No network access, provider resolution, or chunk fetching is implemented in M9a, and portable external-CAS recipe resolution is not claimed until the provider protocol, hash algorithm, record layout, and CDC transformation domain are specified.
- **CDC_CUSTOM (`0x4F`):** parsed/preserved as opaque implementation-defined CDC metadata; no custom schema is interpreted by this implementation.
- **Recipe Mode:** `validate_recipe_payload` enforces 32-byte hash alignment and resource limits; `recipe_hashes` extracts the hash list.
- **CDC_MAP write:** `make_cdc_map_tlv` serializes a `CdcMap` to a `Tlv` with type_id `0x40`.
- **CDC_EXT_PROVIDER write:** `make_cdc_ext_provider_tlv` serializes inert provider metadata to a `Tlv` with type_id `0x41`.
- **ResourceLimits:** `max_cdc_chunk_count` (default 1,000,000) and `max_cdc_metadata_bytes` (default 50 MiB) fields; enforced in all CDC parse paths.
- **CDC interaction tests:** CDC with STORE, compressed, sparse, fragmented entries; AEAD not bypassed; resource limits enforced.
- **CLI `inspect --json`:** `cdc_support` flag, `cdc_metadata_tlvs`, and legacy `cdc_map_tlvs` at archive level; `cdc_algo_id` per entry.
- **CLI `verify --cdc`:** validates CDC algorithm IDs and CDC metadata TLVs structurally; reports `cdc_support` and entry count; and does **not** claim regenerated-boundary verification. In M9a this check is limited to structural validation, bounds/resource-limit validation, reserved/unsupported ID handling, metadata consistency, and other checks possible from stored records.
- **Documentation:** `docs/API.md`, `docs/CONFORMANCE.md`, `docs/SECURITY.md`, `docs/SPEC_QUESTIONS.md`, `README.md` updated.

### Not implemented in M9a

- `sar create --cdc fastcdc` CLI flag (archive creation with CDC annotation is not exposed in the create command).
- Rabin fingerprinting (`0x01`) and BuzHash (`0x03`) algorithms — fail with `SarError::Unsupported`.
- Custom CDC algorithm IDs (`0xF0–0xFF`) — fail with `SarError::Unsupported`.
- Reserved CDC algorithm IDs (`0x04–0xEF`) — fail with `SarError::ReservedValue`.
- External provider resolution / CAS access for `CDC_EXT_PROVIDER` (`0x41`) — not implemented in M9a; recipe reconstruction against external providers remains unsupported.
- Recipe-mode archive writing through `ArchiveWriter` — not implemented; `ArchiveWriter` only keeps CDC metadata/LFH handling consistent for literal-mode entry writing.
- Delta encoding (VCDIFF, BSDIFF, patch application, base archive resolution) — out of scope for M9a.
- Boundary-regeneration CDC verification against logical file content — unavailable; M9a validates stored CDC metadata structurally but does not claim portable regeneration of FASTCDC boundaries.

### Spec gaps documented in SPEC_QUESTIONS.md

- CDC_MAP record field widths (not specified by spec)
- Recipe hash algorithm (not named in spec)
- FastCDC parameters — min/avg/max chunk sizes (not defined by spec)
- CDC transformation domain (not explicitly stated by spec)
- CDC interaction with LOSS_TOLERANT and FEC (not addressed by spec)

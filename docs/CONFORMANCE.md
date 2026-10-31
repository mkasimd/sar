<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# Conformance Profile (M1-M12a-audit-cp)

This document describes **reference implementation coverage** and **known gaps** after M12a-audit-cp.

This is an **implemented profile** report, not a claim of full standard conformance.

**No complete Section 12 Compliance Profile is currently claimed.** The names in
the `sar-archive` `ComplianceProfile` enum are repository policy presets, not
automatically the normative Section 12 profiles. Aligning them is M13b.4 work.
Capabilities required by Section 12 that are still incomplete include
stream-level CDC and fragment-group reconstruction with final Content Hash
verification (streaming profiles; archive-level CDC resolution exists but is
not by itself a Standard Profile claim) and directional
`TLS_EXPORTER` bootstrap (SAR-over-QUIC).

## M12a-audit-cp: archive audit primitives and transcript recording

- `sar-archive` now exposes explicit archive-audit APIs for deterministic structural auditing and machine-readable reports.
- Default archive behavior is unchanged: parsing still rejects `SESSION_CONTROL` and nonzero `OP_CODE` entries unless inert audit mode is explicitly enabled.
- Inert archive audit mode reports `SESSION_CONTROL`/nonzero-`OP_CODE` entries structurally and does not execute stream-session semantics.
- `sar-archive` payload audit policies support metadata-only inspection, decode-when-available behavior, and require-decode behavior for ordinary archive entries.
- `sar-stream` owns strict stream transcript semantic validation and optional exact-byte transcript recording; recording is opt-in and does not weaken validation.
- No `sar-audit` crate is introduced in this pass.

## M12a-stream-cp: Serialized SAR stream transcript conformance vectors

### What is a serialized SAR stream transcript?

A **serialized SAR stream transcript** is a deterministic byte sequence shaped like a primary SAR stream:

```
Global Header (with NO_INDEX flag)
optional KMS extension
SESSION_INIT / SESSION_CAPABILITIES / SESSION_CONTROL entries
ordinary stream entries where applicable (sequence-numbered LFH + payload)
```

These fixtures use `.sar` file extension but must be called **serialized SAR stream transcripts**
(not ordinary static archives) in documentation and manifests.

Key properties:
- They do **not** require live TCP/QUIC transport; they are parsed in-memory by `sar-stream`.
- Additional QUIC control streams (which do not begin with SAR magic) are not covered by this pass.
- The same bytes can be **valid** in stream-session context and **rejected** by a static-archive profile.
- This pass is M12a-stream-cp - **M12b fuzzing is not started by this pass**.

### Stream transcript vector directory structure

```
test-vectors/
  valid/stream-session/
    session-init/            - minimal transcript: Global Header + SESSION_INIT
    session-capabilities/    - SESSION_INIT + SESSION_CAPABILITIES entry
    ordered-data/            - SESSION_INIT + two DATA_WRITE entries
    heartbeat/               - SESSION_INIT + SESSION_HEARTBEAT (zero payload)
    sequence-wrap/           - sequence number wraps from 0xFFFF to 0x0000
  invalid/stream-session/
    data-before-session-init/         - DATA_WRITE before SESSION_INIT → SAR_ERR_STREAM_STATE
    duplicate-session-init/           - two SESSION_INIT for same stream → SAR_ERR_STREAM_STATE
    bad-session-init-payload-length/  - SESSION_INIT with truncated payload → SAR_ERR_INVALID_LENGTH
    reserved-session-init-flags/      - SESSION_INIT with reserved flag bits set → SAR_ERR_RESERVED_VALUE
    sequence-gap/                     - sequence jump by 2 → SAR_ERR_STREAM_STATE
    sequence-replay/                  - same sequence number twice → SAR_ERR_STREAM_STATE
    wrong-stream-id/                  - entry stream_id ≠ session stream_id → SAR_ERR_STREAM_STATE
    heartbeat-with-payload/           - SESSION_HEARTBEAT with nonzero payload → SAR_ERR_INVALID_LENGTH
    reserved-session-opcode/          - opcode in 0x8..=0xF range → SAR_ERR_RESERVED_VALUE
    session-control-without-no-index/ - SESSION_CONTROL without NO_INDEX
    zero-stream-id/                   - SESSION_INIT with Stream ID 0
  profiles/static-archive/
    reject-session-control/  - same session-init fixture, rejected by static-archive profile
```

### Conformance runner routing

Stream transcript semantic validation runs in
`crates/sar-stream/tests/stream_transcript_conformance_tests.rs`.

`sar-archive` conformance tests skip `stream:transcript` semantic checks and keep
archive-safe behavior: default archive parsing rejects entries with
`SESSION_CONTROL` set or nonzero `OP_CODE`.

### Profile rejection manifest

`test-vectors/profiles/static-archive/reject-session-control/` references the same binary
fixture as `valid/stream-session/session-init/`.  The manifest `kind` is `"profile"` and
`profile_expectations.static-archive` is `"reject"`.

This demonstrates that stream transcript bytes are **structurally valid SAR** but
**profile-invalid** for a static-archive consumer.

### Stream transcript strict invalid coverage

The strict stream transcript conformance set now includes:

| Case | Expected status |
|------|-----------------|
| `session-control-without-no-index` | `SAR_ERR_FLAG_CONFLICT` |
| `zero-stream-id` | `SAR_ERR_STREAM_STATE` |

---

## M12a: Conformance vector foundation

### Vector directory structure

```
test-vectors/
  README.md                    - vector layout, manifest format, how-to guide
  manifest.schema.json         - JSON Schema for all conformance manifests
  profiles/README.md           - per-profile descriptions and cold-storage status
  valid/
    minimal/                   - minimal archive vectors (store-no-index, indexed)
    no-index/                  - forward-only (NO_INDEX) archive
    indexed/                   - indexed archive
    compression/               - STORE, DEFLATE, ZSTD compression
    crypto/                    - AES-256-GCM, XChaCha20-Poly1305 (requires key provider)
    fec/                       - real XOR/Reed-Solomon selective FEC fixtures and shared metadata fixture
    fragmentation/             - canonical fragment-group vectors (WP-4); overlap withdrawn, gap-exceeds-loss-limit historical, loss-tolerant-gap deferred
    sparse/                    - sparse map fixture plus deferred sparse+delta reference
    cdc/                       - CDC literal mode fixture plus deferred FASTCDC reference
    delta/                     - real STORE_PATCH, VCDIFF, and SAR BSDIFF v1 fixtures
    stream-session/            - stream transcript fixtures (session-init, capabilities, ordered-data, heartbeat, sequence-wrap)
    filesystem-metadata/       - permissions, owner, timestamps, symlink, directory,
                                  combined, field-presence-inactive
  invalid/
    structure/                 - truncated GH, truncated LFH, invalid magic
    flags/                     - unknown global flag bits, flag conflicts (partial)
    algorithms/                - unsupported compression, unsupported crypto
    crypto/                    - bad AEAD tag (requires key provider)
    recovery/                  - deterministic archive-level Recovery TLV negative fixtures
    fec/                       - (deferred)
    fragmentation/             - duplicate index, missing Index 0/terminal, interior gap, name mismatch, Class G conflict, physical order, CRC authority
    sparse/                    - (deferred: sparse overlap/extent vectors)
    cdc/                       - (deferred)
    delta/                     - deterministic patch-algo/base-hash/truncation/limit fixtures
    stream-session/            - deterministic invalid stream transcript fixtures (see M12a-stream-cp section)
    filesystem-metadata/       - (deferred: unsafe path/symlink vectors)
    resource-limits/           - (deferred)
  profiles/
    static-archive/            - profile-specific acceptance/rejection
    package/                   - (partial: loss-tolerant rejection)
    stream-package/            - NO_INDEX acceptance
    backup/                    - (partial)
    telemetry/                 - (deferred)
    live-media/                - (deferred)
    cold-storage/              - placeholder (deferred, see profiles/README.md)
```

### Manifest format

Every vector has a `manifest.json` with schema version 1. Required fields:
`schema_version`, `id`, `title`, `description`, `kind`, `expected`, `compression`, `crypto`.
Optional: `file`, `profiles`, `features`, `entries`, `base_files`, `profile_expectations`,
`limits`, `notes`, `deferred`, `requires_key_provider`, `generated_by`.

Stable status identifiers: `expected.status` must be one of the 50 names assigned
in specification Section 10.2 (`SAR_OK`, `SAR_WARN_*`, `SAR_ERR_*`), as
implemented by `sar_core::error::SarStatus`. Retired names (for example
`SAR_ERR_INVALID_ALIGNMENT` and `SAR_ERR_DECRYPT_FAILED`), unknown names, and
aliases are rejected by `validate_manifest_schema()`.

A recognized `SAR_WARN_*` name does not mean the runner can verify a warning
outcome. The runner currently executes only `valid=true`/`SAR_OK` and
`valid=false`/`SAR_ERR_*` cases; warning-outcome verification needs a runner
result model and manifest schema extension owned by the responsible feature
package.

### Implemented profile validator

`sar_archive::conformance` module provides:
- `ConformanceManifest`: serde-deserializable manifest type matching the schema
- `validate_manifest_schema()`: schema-level field validation
- `run_conformance_check()`: end-to-end check for a manifest + binary file
- `sar_error_matches_expected_status()`: exact comparison of `SarError::status().name()` with the expected status; near-miss statuses (for example `InvalidLength` for `SAR_ERR_MALFORMED`) do not match
- `discover_manifests()`: recursive walker returning sorted manifest paths

`sar_archive::profile::ComplianceProfile` provides 8 profile variants with
`canonical_name()` and `from_canonical_name()` methods.

### Running conformance tests

```bash
cargo test -p sar-archive --test conformance_tests
cargo test -p sar-archive --test conformance_manifest_tests
cargo test -p sar-stream --test stream_transcript_conformance_tests
```

`conformance_tests.rs` currently provides 9 end-to-end checks:
- `all_manifests_parse_and_schema_validates` - all manifests parse and pass schema checks
- `valid_non_deferred_vectors_parse_ok` - all valid non-deferred vectors parse successfully
- `invalid_non_deferred_vectors_are_rejected` - all invalid non-deferred vectors are rejected
- `deferred_vectors_have_no_binary_file` - deferred manifests have no unexpected binary
- `profile_expectations_use_known_profile_names` - profile names match ComplianceProfile
- `manifest_ids_are_unique` - no duplicate manifest IDs
- `conformance_summary` - summary report
- `bad_aead_tag_auth_failure` - AEAD auth failure with key provider
- `crypto_vectors_parse_structurally_with_key_provider` - crypto vectors with key material

`conformance_manifest_tests.rs` adds targeted manifest-audit checks, including:
- `non_deferred_valid_vectors_must_not_be_placeholders` - canonical valid vectors must not use placeholder language
- `non_deferred_invalid_vectors_must_not_be_placeholders` - non-deferred invalid vectors must not use placeholder language
- `deferred_vectors_do_not_reference_binary_fixtures` - deferred manifests must omit binary file references
- `known_deferred_feature_tags_are_not_canonical_unless_real` - deferred/generated-later feature tags must not remain canonical
- `raw_manifest_shapes_match_schema_contract` - raw JSON manifests match the schema contract for top-level fields and shapes
- `invalid_recovery_vectors_are_real_and_recovery_tagged` - invalid recovery fixtures must be real and tagged with `recovery:*`
- `invalid_delta_vectors_are_real_and_delta_tagged` - invalid delta fixtures must be real and tagged with `delta:*`
- `stream_transcript_vectors_use_stream_tags_and_correct_paths` - stream transcript vectors live under `valid/stream-session/` or `invalid/stream-session/` and use `stream:*` feature tags
- `stream_transcript_profile_rejection_manifests_are_not_byte_invalid` - profile rejection manifests do not claim bytes are structurally invalid
- `minimum_required_valid_stream_transcript_vectors_present` - the four minimum valid stream transcript vectors are present and non-deferred
- `minimum_required_invalid_stream_transcript_vectors_present` - the eight minimum invalid stream transcript vectors are present and non-deferred

### Regenerating binary fixtures

```bash
cargo run --example generate_vectors -p sar-archive
```

All fixtures are deterministic (fixed salts, iteration counts, payloads).

### Known gaps in M12a / M12a-stream-cp

- Canonical fragment-group fixtures are generated by `generate_vectors` and checked through the shared streaming fragment-group collector (strict `read_all_logical_files`). The valid-reassembly fixture uses `NO_INDEX` and claims only the `backup` profile. The LOSS_TOLERANT degraded-output fixture remains deferred because the harness cannot express degraded output or warnings.
- Sparse+delta combined fixture remains deferred/reference-only.
- FASTCDC `CDC_MAP` fixture remains deferred/reference-only.
- Archive-level Recovery TLV coverage is now backed by real generated indexed fixtures (`test-vectors/valid/recovery/archive-xor/recovery_tlv_archive_xor.sar`, `test-vectors/valid/recovery/archive-rs/recovery_tlv_archive_rs.sar`).
- Deterministic invalid recovery and delta vectors are now backed by real fixtures (`test-vectors/invalid/recovery/*`, `test-vectors/invalid/delta/*`) with authoritative `expected.status`.
- Stream transcript vectors are now present (`test-vectors/valid/stream-session/*`, `test-vectors/invalid/stream-session/*`) with strict semantic validation in `sar-stream` tests.
- Some invalid vectors remain deferred (obsolete fragment overlap and loss-limit vectors, sparse overlaps, unsafe metadata, resource limits).
- Entry-level profile checks (per-entry algorithm gating, stream binding) not yet implemented.
- Cold-storage/tape profile vectors deferred (no SAR v1.0 interoperable mechanism yet).
- Full signature implementation/audit posture remains future work.
- No standalone conformance CLI (not in scope for M12a).
- The validator checks global-flag-level and structural correctness; entry-level profile
  enforcement gaps are documented in profile manifests.
- Crypto manifests intentionally include test-only passwords/salts for public conformance testing; no real secrets are committed.

### Relationship to M12b fuzzing

The official vectors in `test-vectors/` are the **canonical** small reproducible set.
M12b will add:
- A separate fuzzing corpus (not checked into the main tree)
- Malformed/adversarial vectors generated by fuzz targets
- cargo-fuzz / libFuzzer / AFL harnesses

The M12a manifest format and stable status identifiers are designed to be extended
by M12b fuzzing infrastructure without changing the M12a schema.

---

## Implemented profile coverage (M1-M11)

### Archive structure and indexing
- Global Header, LFH, Central Dictionary, Footer parsing/writing.
- Indexed archives and `NO_INDEX` archive flows.
- Fail-closed validation for malformed, reserved, and unsupported values.

### Transform pipeline and compression
- Transform ordering enforcement in high-level archive paths.
- Compression algorithms: `STORE`, `DEFLATE`, `ZSTD`.
- Bounded decode/transform memory via `ResourceLimits`.

### Crypto / KMS / authentication
- Hash support used by current implementation profiles (`SHA-256`, `BLAKE3`).
- AEAD support (`AES-256-GCM`, `XChaCha20-Poly1305`).
- Deterministic reference vectors (`test-vectors/crypto-reference/`, generated by
  `tools/generate_crypto_reference_vectors.py`, tested by
  `crates/sar-archive/tests/crypto_reference_vector_tests.rs`) cover
  PBKDF2-HMAC-SHA256 and Argon2id v0x13 at mandatory-range boundaries, HKDF-SHA256
  Entry-key derivation, complete Global Header + LFH AAD, AES-256-GCM and
  XChaCha20-Poly1305 with fixed test-only keys and nonces, SHA-256/BLAKE3-256
  Content Hashes including fragmented and sparse logical content, and
  authentication/hash-mismatch errors. Evidence level: published-KAT checks of
  the reference libraries plus agreement with independent third-party libraries
  and an independent byte-layout derivation. This is **not** second-implementation
  SAR archive interoperability, which has not been demonstrated.
- Writer nonce uniqueness is enforced per writer (one KMS Master Secret and one
  `Encr Algo ID`); an exhausted unique-nonce draw aborts with
  `SAR_ERR_NONCE_REUSE`. Uniqueness across separate writers that share a Master
  Secret is the caller's responsibility.
- KMS parsing/validation for implemented modes.
- Password-based encryption/decryption flows in CLI create/extract/verify.
- AEAD authentication enforced before plaintext release.
- TLS_EXPORTER KMS payloads are validated with the canonical
  `parse_tls_exporter_kms_payload` when an archive Global Header is read
  (`ArchiveReader`) and on header receipt in the non-TCP `sar-transport` path;
  malformed, reserved and unsupported combinations are rejected before any
  Entry is processed (M13b WP-7C). Directional session bootstrap and exporter
  acquisition remain M13b.4.
- ASYMMETRIC_WRAP: payload parsing/validation and a caller-supplied unwrap
  callback only. SAR ships no RSA-OAEP, X25519-HPKE or ML-KEM construction, so
  the Wrap Algo IDs are unsupported unless a `KeyProvider` supplies them. A
  claim of KMS Mode 0x03 would require RSA-OAEP-2048 (Section 5.3.4), which is
  not provided. KMS Mode `0x03` is therefore **not claimed** as a fully
  implemented KMS mode.
- Directional `TLS_EXPORTER` bootstrap (Section 18.6) is not implemented:
  `sar-transport` has no TLS-role Key Usage selection or spec-labelled
  exporter bootstrap, so complete SAR-over-QUIC `TLS_EXPORTER` interoperability
  is not claimed.
- Physical Entry parsing/decoding (`ArchiveReader::next_entry`, `verify`) and
  final logical Entry Content Hash verification are distinct. Only the
  fully reconstructing reader paths (`ArchiveReader::read_all_logical_files`,
  `sar extract`) verify the Content Hash over the final logical Entry. The
  stateful stream parser and transport do not yet verify it (M13b.4).
- `sar verify` checks structure, index consistency and per-Entry decoding
  (including AEAD authentication of encrypted Entries). It does **not** provide
  the final logical Content Hash coverage of the reconstructing reader paths.
- CLI passwords: `--password` > `SAR_PASSWORD` > interactive prompt. Argument
  and environment sources are discouraged (visible to other processes).

### FEC and recovery
- Selective FEC metadata handling and validation.
- XOR and Reed-Solomon file-level FEC support.
- Archive-level recovery metadata inspection/planning/repair for currently supported cases.
- Conformance fixtures keep LFH Selective FEC and archive-level Recovery TLV taxonomy separate:
  - `valid/fec/xor/` and `valid/fec/rs/` for LFH Selective FEC (`fec:*` tags)
  - `valid/recovery/archive-xor/` and `valid/recovery/archive-rs/` for archive-level Central Dictionary Recovery TLVs (`recovery:*` tags)

### Sparse, fragmentation, and loss-tolerant behavior
- Sparse map parse/write (Sparse Logical Size followed by extents; 32-bit or 64-bit per `64BIT_SIZE`), validation, and bounded reconstruction to the Sparse Logical Size, including all-hole Entries and complete fragmented sparse groups.
- Fragment group validation and reassembly.
- `LOSS_TOLERANT` degraded-output behavior for missing-fragment cases only.
- Authentication/structural failures are never bypassed by lossy flags.

The committed M12a fixture set currently includes a real sparse reconstruction binary,
real LFH selective-FEC binaries, and real indexed archive-level Recovery TLV binaries,
plus canonical fragment-group binaries (WP-4: reassembly and structural/metadata/CRC-authority failures). It does not claim LOSS_TOLERANT degraded-output or fragmented-sparse fixture coverage.

### CDC and delta
- CDC metadata/TLV structures and current CDC map handling.
- Delta metadata parsing and patch application for implemented algorithms (`STORE_PATCH`, `VCDIFF`, SAR BSDIFF v1).

Writer-side generated VCDIFF/SAR BSDIFF v1 fixtures are now present after
`M12a-M9b-cp: Delta patch generation corrective pass`, alongside the original
`STORE_PATCH` fixture coverage.

M13b WP-7 delta pipeline (spec §6.1.2, §8.4, §13.1):
- LFH `Uncompressed Size` of an unfragmented delta Entry is the decoded patch
  representation size; for a fragment it is that fragment's decoded
  contribution. The patch output length is determined by the patch and is never
  compared with an LFH size. This is a deliberate wire-compatibility change:
  archives written with the superseded semantics (LFH size = patch output size)
  are unsupported and there is no fallback. The `valid/delta/{vcdiff,bsdiff}`
  and `invalid/delta/*` fixtures were regenerated accordingly.
- The patch is applied once to the complete patch representation, after
  fragment concatenation and before CDC and sparse reconstruction.
- Archive-level CDC Recipe Mode (spec §§8.5, 13.1, 20, 21; M13b.2): a
  non-literal CDC Algo ID marks the payload as a Recipe of 32-byte hashes.
  `ArchiveReader::next_logical_entry`/`read_all_logical_files` resolve it
  against the single local `CDC_MAP` v1 catalog (SHA-256 `0x30`, BLAKE3-256
  `0x31`; `0x32` is `SAR_ERR_UNSUPPORTED`, unassigned IDs are
  `SAR_ERR_RESERVED_VALUE`), verify every chunk against its Recipe hash, then
  continue with sparse reconstruction and final CRC32/Content Hash checks.
  Unresolved chunks are `SAR_ERR_RECIPE_UNRESOLVABLE`, corrupt chunks
  `SAR_ERR_HASH_MISMATCH`, conflicting duplicate records or ambiguous
  catalogs `SAR_ERR_METADATA_CONFLICT`, and an incomplete fragmented Recipe is
  `SAR_ERR_FRAGMENT_GAP` even under LOSS_TOLERANT. Recipe Mode does not
  require `DEDUPLICATION`. `next_entry`, listing, audit and `verify` stay
  structural and never read chunks or call a resolver.
- `sar inspect` is an inventory (spec §22.6): it reports each CDC TLV after
  per-TLV validation (map header, record layout, algorithm, conflicting
  records, provider URI) and fails on a malformed one, but it does not
  enforce cross-TLV catalog selection or `Partition_Index = 0`; `verify`
  enforces those and reading rejects them when a Recipe is resolved.
- External resolution requires an explicit `ArchiveReader::with_cdc_resolver`
  (hash algorithm plus `CdcChunkResolver`); `CDC_EXT_PROVIDER` URIs are inert
  metadata and no network client exists. Not implemented: stream/session CDC
  reconstruction (the stream parser still returns `SAR_ERR_UNSUPPORTED`,
  M13b.4) and cross-Partition lookup (M13b.3). Archive-level CDC capability
  is not a complete Section 12 Standard Profile claim.
- `max_loss_tolerant_gap` (`ResourceLimits`, `FragmentLimits`,
  `--max-loss-tolerant-gap`) is retained but currently inactive: nothing
  consults it, and it does not authorize zero-filling fragment gaps.
- An incomplete fragment group that needs a group-wide stage returns
  `SAR_ERR_FRAGMENT_GAP`, including under `LOSS_TOLERANT`.
- Memory: patch input plus patch output are bounded by
  `max_total_pipeline_memory`, and patch output by `max_decoded_entry_size`,
  checked before the output buffer is allocated.
- CDC memory model: Recipe resolution is charged, against
  `max_total_pipeline_memory`, for the Recipe, catalog bookkeeping, output and
  the bytes the fragment-group collector still retains; map parsing is charged
  for the TLV, record vector and transient duplicate index; fragment
  concatenation is charged at twice the group payload plus the bytes the collector
  still retains for other groups. Not modeled (cannot
  be enforced by the reader): allocator overhead beyond the per-record
  estimates, and the buffer an external resolver allocates before returning
  (the reader only bounds the size it accepts afterwards).
- Tests: `crates/sar-archive/tests/delta_pipeline_tests.rs`; fuzzing:
  `delta_bsdiff_apply` and `delta_vcdiff_apply` (bounded local runs only).

### Archive-level recovery (M13b WP-7B)
- `repair_archive` re-validates caller-constructed `RecoveryPlan` values with
  checked arithmetic and enforces `max_repair_working_set` before each
  allocation stage against a conservative peak-live-memory model (input
  archive, TLV, merged ranges, erasure index, codec padded output plus
  estimated scratch, recovered buffer plus repaired output). Codec scratch
  (RS: symbol buffers, GF matrices, Vandermonde, index vectors) and the
  Central Dictionary parse stage are estimates, not exact; the shared
  Central Dictionary parser may allocate more than modelled.
- Tests: `crates/sar-archive/tests/recovery_resource_tests.rs`; fuzzing:
  `archive_repair` (replay and short bounded run only; no sustained campaign).
- Decompression: `max_output_size` bounds decoded output only, not
  decoder-internal memory; zstd frame windows above 128 MiB are rejected.

### Streaming/session and transport
- Streaming parser/state model and session semantics (`sar-stream`).
- SAR-over-TCP and SAR-over-QUIC transport binding code (`sar-transport`). Complete directional `TLS_EXPORTER` interoperability for QUIC is not yet claimed.
- Deterministic stream transcript fixtures and session lifecycle conformance vectors (M12a-stream-cp).

### Metadata API and filesystem metadata
- LFH metadata API completeness from M11a/M11b.
- Filesystem metadata decode/encode coverage in archive APIs.
- Metadata surface includes permissions, owner, timestamps, hidden attribute, and symlink target where present.

### CLI metadata behavior (M11e)
- `sar create --preserve-permissions`
- `sar create --preserve-owner`
- `sar create --preserve-times`
- `sar create --symlinks skip|follow|archive`
- `sar extract --preserve-permissions`
- `sar extract --preserve-times`
- `sar extract --preserve-owner`
- `sar extract --allow-symlinks`
- Unix extraction is anchored to a descriptor-held extraction root (M13b.3 Package A): no operation re-resolves validated parent paths, regular-file metadata is applied before atomic publication, and temporary names are short and random. Runtime validation: Linux (full workspace); the Package A backend was run natively on FreeBSD 15.1 (later packages were not natively re-run there); macOS native runtime is unverified; Windows and other non-Unix targets have no secure extraction backend and refuse extraction (see the extraction matrix below).
- Unix extraction detects destination path collisions (M13b.3 Package C): distinct Full Logical Entry Paths that reach the same destination object, as determined by the destination filesystem (device and inode), fail with `SAR_ERR_PATH_COLLISION` without renaming, merging or rewriting either Entry. SAR does not fold case or normalize Unicode itself, so detection follows the real filesystem behavior. Identical repeated paths are not collisions. Case-insensitive and normalizing destinations were not available on the validation hosts; those cases are covered by capability-probed tests that skip elsewhere, and by deterministic hard-link alias simulation. The ledger is individually bounded by `max_total_pipeline_memory` (not an aggregate accounting of all archive-reader and CLI allocations); capacity is reserved before publication and committed afterwards, so a ledger limit failure cannot follow a successful publication. A concurrent external process aliasing objects between the final check and the rename is not excluded.
- Unix extraction implements the specified final logical state for repeated Full Logical Entry Paths and directory/non-directory transitions (M13b.3 Package D; specification Section 6.1.5): the last complete Entry in canonical order determines the final object, a non-directory Entry replaces an earlier directory together with its earlier descendants, a later descendant turns an earlier file or symlink into an implicit directory without metadata, a directory Entry keeps compatible descendants, and the last explicit directory Entry determines directory metadata (metadata recorded for a removed directory is discarded). This is separate from the conservative destination deletion policy: a run only ever removes objects it created itself, proven by the identities in the collision ledger (each recorded as created by the run or merely encountered). A pre-existing directory, a pre-existing non-directory in the way of a descendant, and any unrecognized entry inside a run-created directory are never deleted; the extraction fails with `SAR_ERR_ALREADY_EXISTS` before removing anything (an empty pre-existing directory is also refused; there is no force option). A pre-existing symlink in a path component remains `SAR_ERR_PATH_ESCAPE`, and distinct logical paths reaching one object remain `SAR_ERR_PATH_COLLISION`. Replacing a pre-existing regular file or symlink by a file or symlink Entry overwrites it by atomic rename, as before. Directory replacement is performed descriptor-relative: the verified directory is renamed aside to a private `.sar-tmp-*` name, the replacement is renamed into place (the directory is renamed back if that fails), and the aside subtree is then removed through the verified descriptor without following symlinks. Removal depth is bounded (64 levels; deeper trees are refused intact with `SAR_ERR_LIMIT_EXCEEDED`). Failure and cleanup behavior of these intermediate states is specified in the Package E bullet below. Required bookkeeping capacity is verified before the first destructive step.
- Unix extraction failure and cleanup contract (M13b.3 Package E). Ordinary extraction remains fail-fast and is **not transactional or all-or-nothing**: after a failure, Entries and directories already published, objects created or replaced by the run, and restored directory metadata are not rolled back, and pre-existing destination objects are never deleted to reconstruct the earlier filesystem. A failed run never reports success, exits nonzero, and keeps the primary SAR status unchanged (for example `SAR_ERR_PATH_ESCAPE`, `SAR_ERR_PATH_COLLISION`, `SAR_ERR_ALREADY_EXISTS`, `SAR_ERR_LIMIT_EXCEEDED`, I/O and integrity failures); `--allow-lossy` does not permit skipping Entries or ignoring filesystem errors. When the destination may have been changed (including creating a missing extraction root), the CLI adds the note that extraction is incomplete and partial changes may remain; when run-owned temporary objects could not be restored or removed it adds a separate `cleanup error` line per object that names the random `.sar-tmp-*` name and the destination path but never extracted content. Both notes are CLI-internal diagnostics: no wire status or public API was added, and the status line printed for the primary error is unchanged. Run-owned temporary objects (staging files, staging symlinks, mode-probe files, moved-aside directories) are tracked in a bounded per-run record (8 objects at once; the limit is checked before the object is created and fails with `SAR_ERR_LIMIT_EXCEEDED`) with the parent directory descriptor and the identity captured at creation. Cleanup acts only on tracked objects, through that descriptor, and only while the name still reaches the recorded identity; the extraction root is never scanned and a `.sar-tmp-*` name alone never establishes ownership. A substituted symlink or other unrecognized object is left in place and reported, never followed or deleted.
  - (A) Failed staged-file publication: the unpublished staging file is removed by identity (or left and reported if it was substituted or removal fails). Recoverable.
  - (B) Failed directory replacement: the moved-aside directory is renamed back only if its original name is free and the object under the temporary name is still the recorded directory (checked through the parent descriptor without following symlinks); otherwise, or on rename failure, it (or whatever now holds that name) stays under its `.sar-tmp-*` name and the failed restoration is reported. Recoverable only when restoration succeeds.
  - (C) Cleanup failure after successful replacement publication: the published object is kept; recognized run-created content of the moved-aside subtree is removed, unrecognized or substituted content and the directories holding it are retained, and the extraction fails (`SAR_ERR_ALREADY_EXISTS` for unrecognized content, otherwise the underlying error) with the remainder reported. Incomplete cleanup is never reported as success.
  - (D) A returned error after a file or symlink was unlinked to make room for a directory leaves the earlier object removed; no compensating recreation is attempted, and the change is reported as partial.
  - (E) Abrupt termination (crash, `SIGKILL`, power loss) has no cleanup and no rollback guarantee: staging files, a directory moved aside between the two renames (the old directory then exists only under its `.sar-tmp-*` name), the remaining aside subtree of an interrupted removal, and any partial extraction result can survive, and no later run recognizes or recovers them. There is no persistent journal or cross-process recovery.
  - Final directory metadata restoration is applied after all Entries; if it fails, all published Entries remain, metadata of directories restored earlier is not reverted, and the failure is reported as partial.
  - Identity pinning (PR #104, correcting an inode-reuse defect found by CI): a recorded device/inode identity is meaningful for cleanup only while the object is held open, so staging symlinks are pinned with an `O_PATH|O_NOFOLLOW` descriptor on Linux, Android and FreeBSD; where a symlink cannot be pinned, cleanup conservatively leaves the temporary name unresolved and reports it. The `M13-EXTRACT-001` acceptance criteria still hold. Targeted FreeBSD validation of the pinning is an outstanding follow-up and has not been executed.
  - Residual limit: POSIX offers no unlink-by-identity, so a hostile process with write access to the destination that substitutes a tracked temporary name between the identity check and the `unlinkat` can cause that one random-named object to be removed; it cannot redirect the removal outside the destination directory or follow a symlink. A successful run retains no temporary object it created. Validated on Linux; FreeBSD and macOS runtime posture is as stated in the extraction matrix below, and non-Unix targets refuse extraction, so none of these contracts applies there.
- CLI extraction composes the Full Logical Entry Path from the separately encoded LFH Path String and Name String (`Path/Name`, or Name alone when the Path String is absent or empty; specification Section 6.1.5), for regular files, directories, symlinks and fragmented Entries (Index 0 supplies the fields), and uses it for the collision ledger, replacement state and pending directory metadata. A Name String that is empty or contains `/` is rejected as `SAR_ERR_MALFORMED` rather than normalized, and the composed path is validated component-wise (`..`/absolute/drive/UNC paths are `SAR_ERR_PATH_ESCAPE`; empty or `.` components are `SAR_ERR_MALFORMED`). `sar create` now writes `Path`/`Name` separately (`with_path`). Earlier nonconforming archives produced by the CLI, which carried the whole path in a slash-bearing Name String, may now fail extraction with `SAR_ERR_MALFORMED`; there is deliberately no automatic legacy-path rewriting or reinterpretation, and re-creating the archive with the current CLI is required. Directory listings inspected during replacement are bounded incrementally by the ledger's claimed-object count, so an adversarial directory is refused after at most that many entries are read. Replacement ownership additionally requires that each object below a replaced directory is the run-created object recorded for that exact logical child, so hard links or aliases of run-created objects are never removed, and the subtree is re-verified after the directory is moved aside. Archive-reader-level validation of the Name/Path syntax (`sar-archive`) remains future work.
- `sar list --metadata`
- `sar inspect --json` metadata-rich output

## Extraction conformance matrix (M13b.3 Package F)

Scope: `sar extract` in `sar-cli`, the only materializer. Section 22.4 requires confinement that lexical validation cannot provide, so extraction is implemented only where a descriptor-relative backend exists.

### Platform security support

| Platform | Extraction backend | Runtime evidence | Claim |
| --- | --- | --- | --- |
| Linux | Unix descriptor-relative backend (`root_unix.rs`) | Full workspace tests run natively | Implemented and runtime-tested |
| FreeBSD | Same Unix backend | Package A backend tests passed natively on FreeBSD 15.1; Packages B-E were not natively re-run | Package A backend runtime-tested; later-package behavior is not equivalent to a native full-suite run |
| macOS | Same Unix backend (intended) | None | Native runtime unverified (waived for scoped closure, `SAR-M13b3-EXTRACTION-CLOSURE-DECISION-001`); APFS case-insensitivity and normalization behavior untested |
| Windows and other non-Unix | None | Type-checked only (`x86_64-pc-windows-gnu`, host C compiler substituted for the C dependency); never executed natively | Secure extraction not implemented; extraction refused |

On targets without `cfg(unix)`, `sar extract` (including the `-x` shorthand) fails with `SAR_ERR_PATH_ESCAPE` because confinement cannot be established (Section 22.4), before the archive is opened or the destination is created. `create`, `list`, `inspect`, `verify` and `repair` are unaffected. There is no silent insecure fallback, and a cross-compilation check proves compilation, not native filesystem correctness. Future Windows support requires a separately scoped secure implementation (handle-relative operations, reserved-name, alternate-data-stream and reparse-point handling) and native validation; it is not part of M13b.3.

Integration tests that depend on a successful CLI extraction are `#[cfg(unix)]`, so a native non-Unix run does not report the intentional refusal as a failure; non-extraction tests run on every platform, and `cli_platform_guard_tests.rs` asserts the refusal on non-Unix targets.

### Guarantees and evidence

"Tested" means exercised on Linux unless stated otherwise.

| Guarantee | Status on Unix | Evidence | Not covered |
| --- | --- | --- | --- |
| Root confinement | Implemented, tested; root symlink resolved once | `root_unix.rs` race-injection tests; `cli_metadata_tests.rs` symlinked-root test | macOS runtime; POSIX check/use windows where no atomic identity operation exists |
| Hostile path and symlink-target classification | `SAR_ERR_PATH_ESCAPE` for escapes and unconfinable paths, `SAR_ERR_MALFORMED` for malformed syntax; targets evaluated lexically and stored verbatim | `cli_metadata_tests.rs`, `cli_full_logical_path_tests.rs` | Archive-reader-level Name/Path validation (sar-archive) is separate future work |
| Full Logical Entry Path composition | Implemented (Path String and Name String, fragments via Index 0) | `cli_full_logical_path_tests.rs` | |
| Filesystem-based collision detection | Implemented by device/inode identity, no SAR-side folding | `cli_path_collision_tests.rs`, `root_unix.rs` tests, hard-link alias simulation | Case-folding and Unicode-normalizing destination tests are capability-probed and were not executed on the development host; concurrent aliasing between the final check and the rename is not excluded |
| Canonical replacement semantics (Section 6.1.5) | Implemented | `cli_replacement_semantics_tests.rs` | |
| Protection of unrelated pre-existing content | Only run-created objects are ever removed; pre-existing directories and unrecognized content fail with `SAR_ERR_ALREADY_EXISTS`; pre-existing files and symlinks are replaced by rename | `cli_replacement_semantics_tests.rs`, `cli_partial_extraction_tests.rs` | No force option |
| Private staging and metadata ordering | Short random O_EXCL staging names, metadata applied to the open descriptor before publication, directories created 0700, directory metadata after children | `root_unix.rs`, `cli_metadata_tests.rs` | |
| Temporary artifact tracking | Bounded per-run record, cleanup by identity through directory descriptors | `root_unix.rs` cleanup tests | Residual: POSIX has no unlink-by-identity |
| Partial-result and cleanup diagnostics | Primary status kept; CLI adds an incomplete-extraction note and separate cleanup-error lines | `cli_partial_extraction_tests.rs`, `extract.rs` tests | |
| Non-Unix refusal | Implemented (policy guard) | `policy.rs` unit test (Linux); `cli_platform_guard_tests.rs` compiled for non-Unix only | Never executed natively |

### Accepted limitations

- Extraction is fail-fast and is **not** all-or-nothing; there is no rollback.
- There is no persistent crash-recovery journal; a crash can leave staging files, moved-aside directories and partial results.
- Portable POSIX check/use races remain where atomic identity operations are unavailable.
- Native macOS runtime evidence is incomplete.
- Case-folding and Unicode-normalizing filesystem tests have not been executed on the development host.
- No Windows or other non-Unix secure-extraction claim is made.

### Explicitly unsupported or out of scope

- Secure extraction on Windows and other non-Unix targets (refused).
- Best-effort or skip-on-failure extraction modes (not provided; `--allow-lossy` does not skip Entries).
- `HIDDEN_ATTR` restoration: not provided and not required. Specification Section 6.2.4 makes materialization of `HIDDEN_ATTR` optional and caller-selected; ordinary extraction does not apply it on any platform, and this non-materialization is not an error, incomplete result or unsupported feature. The `sar-archive` writer API can encode the bit, readers expose it as metadata, and `sar list` reports it, but the CLI `sar create` does not set it. Any future restoration is a separately scoped opt-in capability that must follow the Section 22.4 confinement model; none is implemented (`M13-EXTRACT-008`, resolved).
- `FORCE_SYNC`, `OP_CODE`, `SESSION_CONTROL` and `ATOMIC_WRITE` Entry Mode handling in extraction: `FORCE_SYNC` (bypass of local conflict resolution) does not apply to ordinary archive extraction, which follows the Section 6.1.5 final state; `OP_CODE` and `SESSION_CONTROL` apply only to Stateful Streaming Mode (Section 6.3, M13b.4) and are rejected by the archive reader with `SAR_ERR_UNSUPPORTED` by default; `ATOMIC_WRITE` (Section 18.4.1) is satisfied for ordinary Unix extraction by staging, integrity verification and atomic publication, independent of the bit.
- Cross-Partition extraction and Partition metadata handling, and stream/session materialization (M13b.4).
- The `repair` command's output is not part of extraction. On Unix it uses an exclusively created random staging file in the output directory, verified through its descriptor and published by a descriptor-relative rename; POSIX check/use races remain where atomic identity operations are unavailable, there is no crash recovery or rollback, and non-Unix targets refuse the repair output operation (`M13-EXTRACT-007`, resolved by PRs #102 and #104; Linux-validated, with native macOS/Windows and targeted FreeBSD runtime unverified).
- Archive-reader validation of encoded Name String and Path String syntax (specification Section 6.1.5, `SAR_ERR_MALFORMED`) is not implemented; these rules are enforced only by the CLI at extraction time (`M13-PARSER-018`).

## Known gaps

- This repository is **not yet a complete conformance suite**.
- Many invalid/negative vectors are deferred (see M12a gaps above).
- Full signature implementation/audit posture remains future work.
- Some algorithms are structurally represented but intentionally unsupported in the implemented profile.
- Delta/base-hash algorithm signaling remains limited by current spec ambiguity handling.
- Profile validation helpers are useful but are not a complete standalone conformance oracle.
- Platform-specific metadata restoration behavior remains policy-gated and best-effort where supported.
- No stable C ABI/Python/mobile binding surface is implemented in M1-M12b (future milestones).
- Partition Set conformance coverage is deferred; `sar-partition` is a placeholder. Partition Set semantics are specified in `specification.md` Section 19.1; no Partition Set implementation or test vectors exist.
- Cold-storage and tape profile vectors remain deferred (see `test-vectors/profiles/README.md`).
- Independent conformance certification is not claimed.

## M12b: fuzzing and hardening

M12b bounded local fuzzing was completed after M12a. Fuzzing does not replace
conformance vectors but provides complementary malformed-input coverage.

Key M12b contributions to the conformance posture:

- `fuzz/seeds/` contains hand-curated seed inputs for 13 malicious corpus
  categories (see `fuzz/CORPUS.md` for the taxonomy).
- One confirmed fuzz finding (stream transcript integer overflow) was fixed,
  promoted into a regression test, and validated.
- Extended local bounded campaigns were run against parser, archive reader,
  audit, stream transcript, stateful writer, stateful parser, and stateful
  transport fuzz targets.
- Exhaustive fuzzing coverage is **not** claimed. Independent security audit
  completion is **not** claimed. Future campaigns may continue in parallel
  with later milestones.
- Generated fuzz corpora and crash artifacts are not committed.

See `fuzz/README.md`, `fuzz/CORPUS.md`, and `fuzz/RUNS.md` for full details.

## M12c.1: documentation and public-claims hardening

M12c.1 audited and updated public documentation to ensure no unsupported claims
are present. Key changes:

- Stale "long-term fuzzing not complete" language corrected to reflect M12b
  completion status with explicit "not exhaustive" caveats.
- `docs/COMPATIBILITY.md` added to document wire-format compatibility goals,
  Rust API pre-stable status, and deferred functionality including
  partition/multi-volume support, C ABI, Python bindings, mobile bindings,
  packaging, and certification.
- Fuzzing coverage summary and limitations added to `fuzz/README.md`.
- `docs/SPEC_QUESTIONS.md` updated to record M12b resolution status and
  M12c.1 scope note.
- No production-readiness, exhaustive-fuzzing, independent-audit, certification,
  compliance, or stable API/ABI claims are made.

## M12c.2: API inventory and crate-boundary hardening

M12c.2 audited the machine-readable API inventory and crate-boundary documentation.
Key changes:

- `docs/machine-readable/MACHINE_READABLE_API.json` updated: added missing public APIs for the
  `sar-archive` recovery module (`ErasureRange`, `ProtectedRange`, `EntryErasure`,
  `ErasureInput`, `RecoveryMetadata`, `RecoveryPlan`, `RepairReport`,
  `inspect_recovery_metadata`, `plan_archive_repair`, `repair_archive`) and
  conformance module types/functions.
- Binding readiness metadata corrected: `c_abi`, `python`, `swift_ios`,
  `kotlin_java_android`, and `cpp_via_c_abi` changed from `candidate`/`unstable`
  to `deferred` to accurately reflect that no binding work exists.
- Pre-stable status notes added to the inventory top-level notes.
- `docs/API.md` regenerated from updated inventory.
- `docs/CRATE_RESPONSIBILITIES.md` updated: added recovery/conformance module
  boundaries, added implementation/profile policy versus wire-format behavior
  section, and added supporting-crate policy notes.
- `docs/LIBRARY_LAYOUT.md` updated: added fuzz workspace, generated-artifact
  notes, and future binding path reminders.
- Open spec questions remain open and unresolved.
- No SAR wire-format changes. No public API stabilization claims.

## Milestone alignment

- M12b: fuzzing and malicious corpus — **complete**
- M12c.1: documentation and public-claims hardening — **complete**
- M12c.2: API inventory and crate-boundary hardening — **complete**
- M12c.3: security posture documentation — future
- M13: security audit and remediation — future
- M14: C ABI and Python module — future
- M15: packaging and release automation — future
- M16: Swift/iOS and Kotlin/Java Android packages — future

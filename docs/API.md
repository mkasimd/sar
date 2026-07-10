# API Inventory (post–Milestone 11a source audit)

This document is derived from the current Rust workspace source. `specification.md` is used only for terminology and conformance context.

Current scope:

- Milestones 1–3: archive format, parser/writer, indexed and `NO_INDEX` archive flows
- Milestone 4: compression registry and transform pipeline foundation
- Milestone 5: crypto, KMS parsing, password-based CEK resolution, hashes, AEAD integration
- Milestones 6–7: Selective FEC metadata, XOR FEC, Reed-Solomon FEC, CLI FEC create/inspect/verify/extract flows
- Milestone 8: sparse file map parsing/reconstruction, fragment reassembly, loss-tolerant semantics, archive-level Data Recovery TLV inspection/planning/repair, CLI repair/verify-recovery/allow-lossy
- Milestone 9a: CDC metadata/TLV parsing and validation
- Milestone 9b: delta metadata and patch application (`STORE_PATCH`, `VCDIFF`, `BSDIFF`)
- Milestone 10a: stateless forward-only SAR byte-stream parser/writer state model
- Milestone 10d: SAR-over-TCP binding (`sar-transport::tcp`)
- Milestone 10e: SAR-over-QUIC binding (`sar-transport::quic`, `quic` feature flag)
- Milestone 11a: LFH Metadata API Completeness — expanded `EntryInput`, expanded `EntryMetadata`, `FieldPresence<T>`, all metadata structs, entry kind representation, complete metadata round-trip
- Milestone 11b: Filesystem Metadata Encode/Decode — `FieldPresence`-typed path/permissions/owner/timestamps in `EntryMetadata`, directory payload validation, IS_SYMLINK→HAS_SYMLINKS validation, strict UTF-8, path/name length validation, deterministic round-trip tests
- Milestone 12: future FFI / C ABI only; not implemented yet

Feature flags: the `sar-transport` crate exposes a `quic` Cargo feature flag.  When enabled, it adds `sar-transport::quic` with real QUIC/TLS networking via `quinn 0.11`, `rustls 0.23`, and `tokio 1`.  All other crates define no feature flags.

## Workspace summary

| Crate | Purpose | Status |
| --- | --- | --- |
| `sar-core` | Archive format, reader/writer, validation, transform integration | implemented with partial roadmap surface |
| `sar-compression` | Compression registry and bounded encode/decode helpers | implemented |
| `sar-crypto` | Hashing, AEAD, KMS types/parsing, key-provider abstraction | implemented with some planned algorithms |
| `sar-fec` | XOR and Reed-Solomon FEC codecs and metadata parsing | implemented |
| `sar-cli` | Human-facing CLI over `sar-core` | implemented with some command-surface gaps |
| `sar-cdc` | Future CDC support placeholder | placeholder |
| `sar-delta` | Patch algorithm registry, delta LFH field types and validation (M9b); `STORE_PATCH`, `VCDIFF`, and `BSDIFF` application implemented | implemented |
| `sar-fragmentation` | Future fragmentation support placeholder | placeholder |
| `sar-partition` | Future partition support placeholder | placeholder |
| `sar-sparse` | Future sparse-file support placeholder | placeholder |
| `sar-loss-tolerant` | Future loss-tolerant mode placeholder | placeholder |
| `sar-stream` | In-memory Stateful Streaming Mode session layer over `sar-core` structural parsing | implemented |
| `sar-transport` | Transport abstraction + deterministic in-memory TCP-like/QUIC-like harness over `sar-stream`; SAR-over-TCP binding (M10d); SAR-over-QUIC binding (M10e, `quic` feature) | implemented |

## `sar-core`

### Purpose

`sar-core` is the main Rust API surface for reading, writing, verifying, and structurally validating SAR archives. It owns the on-wire format structs, status/error mapping, global/LFH flag rules, TLV handling, archive reader/writer flows, and transform integration with compression, crypto, and FEC crates.

### Implemented milestone coverage

- Milestones 1–3: global header, LFH, central dictionary, footer, TLV parsing/writing, archive read/write
- Milestone 4: compression-aware transform plans and archive integration
- Milestone 5: AEAD + KMS integration, AAD construction hooks, key-provider integration
- Milestones 6–7: Selective FEC metadata validation and writer integration
- Milestone 8: sparse file map module, fragment reassembly module, archive-level recovery module

### Public modules

- `archive`
- `error`
- `fec`
- `flags`
- `format`
- `fragment`  *(new in M8)*
- `io`
- `metadata`  *(new in M11a)*
- `profile`
- `recovery`  *(new in M8)*
- `sparse`    *(new in M8)*
- `stream`    *(new in M10a)*
- `tlv`
- `transform`

### Main public APIs

#### High-level archive APIs

- `ArchiveReader<R>`
  - `new(reader)`
  - `with_options(reader, ArchiveReaderOptions)`
  - `with_key_provider(Box<dyn KeyProvider>)`
  - `read_global_header()`
  - `next_entry()`
  - `verify()`
  - `metadata()`
- `ArchiveWriter<W>`
  - `new(writer, ArchiveWriterOptions)`
  - `new_with_cd_metadata(writer, ArchiveWriterOptions, Vec<Tlv>)`
  - `new_with_compression(writer, ArchiveWriterOptions, CompressionSettings)`
  - `new_with_compression_and_key_provider(writer, ArchiveWriterOptions, CompressionSettings, Option<Box<dyn KeyProvider>>)`
  - `add_entry(EntryInput)`
  - `write_sparse_entry(name, gathered_payload, SparseWriteOptions)` *(new in M8 final pass)*
  - `finish()`
- `StreamArchiveParser`
  - `new()`
  - `with_options(ArchiveReaderOptions)`
  - `with_key_provider(Box<dyn KeyProvider>)`
  - `push_bytes(&[u8])`
  - `finalize_input()`
  - `step() -> Result<StreamStep<StreamEvent>, SarError>`
- `StreamParseState`, `StreamStep<T>`, `StreamEvent`, `StreamArchiveSummary`
- `StreamWriteState` + `ArchiveWriter::stream_state()`

#### Important public types

- `ArchiveWriterOptions`
  - `no_index: bool`
  - `sparse: bool` *(new in M8 final pass)* — set `SPARSE_FILES` global flag; required before calling `write_sparse_entry`
  - `encryption: Option<EncryptionSettings>`
  - `fec: Option<FecSettings>`
  - `lfh_size_field_policy: LfhSizeFieldPolicy` *(new in M11a.1)* — LFH size-field encoding policy (`Auto`, `Force32`, `Force64`)
  - `with_path: bool` *(new in M11a)* — sets `HAS_PATH` global flag; allows `EntryInput::path`
  - `with_permissions: bool` *(new in M11a)* — sets `HAS_PERMS` global flag; allows `EntryInput::permissions`
  - `with_uid_gid: bool` *(new in M11a)* — sets `EXT_UID_GID` global flag; allows `EntryInput::uid_gid`
  - `with_timestamps: bool` *(new in M11a)* — sets `EXT_TIME` global flag; allows `EntryInput::timestamps`
  - `with_per_file_crc: bool` *(new in M11a)* — sets `PER_FILE_CRC` global flag; allows `EntryInput::file_crc32`
  - `with_content_hash: bool` *(new in M11a)* — sets `DEDUPLICATION` global flag; allows `EntryInput::content_hash`
  - `with_symlinks: bool` *(new in M11a)* — sets `HAS_SYMLINKS` global flag; allows `EntryInput::kind = Symlink`
- `SparseWriteOptions` *(new in M8 final pass)*
  - `logical_size: u64` — full apparent file size including holes; written to LFH `Uncompressed Size`
  - `extents: Vec<SparseExtent>` — ordered, non-overlapping sparse extents
- `ArchiveReaderOptions`
  - `limits: ResourceLimits`
  - `delta_base: Option<Vec<u8>>` — explicit base bytes for BSDIFF/VCDIFF patch application; no automatic discovery
- `ResourceLimits`
  - `max_archive_size`
  - `max_entry_count`
  - `max_lfh_header_bytes`
  - `max_path_bytes`
  - `max_global_flags_bytes`
  - `max_kms_payload_bytes`
  - `max_tlv_bytes`
  - `max_tlv_count`
  - `max_cd_bytes`
  - `max_decoded_entry_size`
  - `max_in_memory_buffer`
  - `max_total_pipeline_memory`
  - `max_sparse_map_bytes`
  - `max_sparse_descriptors`
  - `max_fragment_count`
  - `max_fragment_group_span`
  - `max_loss_tolerant_gap`
  - `max_fec_value_bytes`
  - `max_recovery_protected_range`
  - `max_repair_working_set`
  - `use_runtime_memory_budget`
  - `max_bsdiff_control_bytes` — maximum BSDIFF Control Block size in decoded patch payload (default: 64 MiB)
  - `max_bsdiff_diff_bytes` — maximum BSDIFF Diff Block size in decoded patch payload (default: 1 GiB)
  - `max_bsdiff_extra_bytes` — maximum BSDIFF Extra Block size in decoded patch payload (default: 1 GiB)
  - `max_bsdiff_control_triples` — maximum number of BSDIFF control triples (default: 4 000 000)
  - `max_vcdiff_window_count` — maximum number of VCDIFF windows per patch (default: 1 000 000)
  - `max_vcdiff_instruction_count` — maximum number of VCDIFF instructions per window (default: 10 000 000)
  - `max_vcdiff_output_size` — maximum total VCDIFF reconstructed output size; 0 = defer to `max_decoded_entry_size` (default: 0)
  - CLI defaults currently rely on `ResourceLimits::default()` unless the caller or CLI flags override them; the most relevant Stage 4 defaults are `max_archive_size = 16 GiB`, `max_decoded_entry_size = 1 GiB`, `max_in_memory_buffer = 1 GiB`, `max_fragment_group_span = 1 GiB`, and `max_repair_working_set = 2 GiB`
- `CompressionSettings`
  - `store()` helper
- `EncryptionSettings`
  - `algo_id`
  - `kms_params: KmsParams`
- `FecSettings`
  - `default_xor()`
  - `default_rs()`
- `LfhSizeFieldPolicy` *(new in M11a.1)*
  - `Auto` *(default)* — writer uses 32-bit LFH size fields when values fit `u32`; promotes to 64-bit before header emission when required
  - `Force32` — writer emits 32-bit LFH size fields and fails closed if any required size exceeds `u32::MAX`
  - `Force64` — writer emits 64-bit LFH size fields and sets global `SIZE_64BIT`
- `EntryInput`, `EntryReader`, `EntryMetadata`, `EntryWritten`
  - `EntryInput::file(name, payload)` *(new in M11a)* — ergonomic constructor for a regular file entry
  - `EntryInput` fields *(new in M11a)*: `kind: Option<EntryKind>`, `path: Option<String>`, `permissions: Option<u16>`, `uid_gid: Option<u32>`, `timestamps: Option<EntryTimestampMetadata>`, `is_hidden: bool`, `stream_id: Option<u16>`, `sequence_no: Option<u16>`, `file_crc32: Option<u32>`, `content_hash: Option<EntryHashMetadata>`
  - `EntryMetadata` fields *(new in M11a)*: `kind: EntryKind`, `path: Option<String>`, `permissions: Option<u16>`, `uid_gid: Option<u32>`, `timestamps: Option<EntryTimestampMetadata>`, `is_hidden: bool`, `compression_presence: FieldPresence<EntryCompressionMetadata>`, `encryption_presence: FieldPresence<EntryEncryptionMetadata>`, `fec_presence: FieldPresence<EntryFecMetadata>`, `fragment_presence: FieldPresence<EntryFragmentMetadata>`, `cdc: Option<EntryCdcMetadata>`, `delta: Option<EntryDeltaMetadata>`, `sparse: Option<EntrySparseMetadata>`, `file_crc32: Option<u32>`, `content_hash: Option<EntryHashMetadata>`, `raw_entry_mode: u16`
  - *(new in M11b)* `EntryMetadata` adds `path_presence: FieldPresence<String>`, `permissions_presence: FieldPresence<EntryPermissionMetadata>`, `owner_presence: FieldPresence<EntryOwnerMetadata>`, `timestamps_presence: FieldPresence<EntryTimestampMetadata>` — these expose the three-state presence model for filesystem metadata fields
- `ArchiveSummary`, `VerificationReport`, `ArchiveMetadata`

#### Format and parser APIs

- Header structs: `GlobalHeader`, `LocalFileHeader`, `CentralDictionary`, `Footer`, `KmsData`, `PartitionDescriptor`
  - `LocalFileHeader.fragment_descriptor` is typed as `Option<LfhFragmentDescriptor>` (named-field struct; replaced the former `Option<(u64, u32)>` tuple in M8 closeout)
- `LfhFragmentDescriptor { absolute_offset: u64, fragment_size: u32 }` — fragment descriptor stored inline in a `LocalFileHeader`
- Parser/writer helpers:
  - `parse_global_header(input, limits)`, `write_global_header`
  - `parse_lfh(input, flags, limits)`, `write_lfh`, `compute_lfh_size`, `lfh_to_bytes`, `lfh_bytes_for_aad(flags, lfh_bytes, fec_algo_id, fec_value_len) -> Result<Vec<u8>, SarError>`, `fec_size_field_offset`
  - `parse_central_dictionary(input, flags, limits)`, `write_central_dictionary`
  - `parse_footer`, `write_footer`
  - `global_header_flags_bytes`
  - `parse_lfh` and `write_lfh` select LFH size width strictly from global `SIZE_64BIT` (`4+4` bytes when unset, `8+8` bytes when set)
  - 32-bit LFH writes fail closed on values above `u32::MAX` (no truncation)
  - `compute_lfh_size` includes the physical `4-byte` vs `8-byte` LFH size-field width selected by global `SIZE_64BIT`
  - Reader paths accept either valid layout for indexed and `NO_INDEX` archives and enforce `ResourceLimits` before allocation
- TLV helpers:
  - `Tlv`
  - `parse_tlvs(input, limits)`, `write_tlvs`

#### Flags, status, and validation APIs

- `GlobalFlags`
- `EntryMode`
  - `ENCRYPTED`, `COMPRESSED`, `FRAGMENT`, `LAST_FRAGMENT`, `LOSS_TOLERANT`
  - `IS_SYMLINK` *(new in M11a)* — bit 0; entry is a symbolic link
  - `IS_DIRECTORY` *(new in M11a)* — bit 1; entry is a directory
  - `HIDDEN_ATTR` *(new in M11a)* — bit; entry is marked hidden
  - `from_bits(bits)`
  - `bits()`
  - `is_encrypted()`
  - `is_compressed()`
  - `is_fragment()`
  - `is_last_fragment()`
  - `is_loss_tolerant()`  *(new in M8)*
  - `is_symlink()`  *(new in M11a)*
  - `is_directory()`  *(new in M11a)*
- `validate_global_flags()`
- `validate_entry_mode_against_global()`
- `SarStatus`, `SarStatusParseError`, `SarError`
- `SarStatus::code()`, `SarStatus::name()`
- `SarError::status()`

#### Transform pipeline APIs

- Traits: `EncoderTransform`, `DecoderTransform`
- Concrete compression transforms:
  - `CompressionEncoderTransform`
  - `CompressionDecoderTransform`
- Plans and helpers:
  - `EncodingPlan`, `DecodingPlan`
  - `EncodingPlanV2`, `DecodingPlanV2`
  - `EntryCryptoContext`
  - `encode_payload`, `decode_payload`
  - `encode_payload_v2`, `decode_payload_v2`

#### FEC-facing public APIs in `sar-core`

- `FecSummary`
- `classify_recovery_tlv_id()`
- `validate_recovery_tlv(type_id, value, limits)`
- `validate_lfh_fec_algo_id()`
- `parse_lfh_fec_value(algo_id, fec_value, limits)`

### Low-level/internal-public helpers

These items are public today, but they are better treated as integration helpers than as a stable external API commitment:

- `io::ParseCursor<'a>`
- `io::BinaryWriter`
- `profile::validate_archive_profile()` and `ComplianceProfile`
- direct transform plan structs used by `ArchiveReader` / `ArchiveWriter`

### Error behavior

- Structural failures map into `SarError` and `SarStatus` values such as `SAR_ERR_TRUNCATED`, `SAR_ERR_MALFORMED`, `SAR_ERR_INVALID_LENGTH`, `SAR_ERR_BOUNDS`, and `SAR_ERR_FLAG_CONFLICT`.
- Configured resource-limit failures map to `SAR_ERR_LIMIT_EXCEEDED`.
- Compression, crypto, and FEC failures are normalized into SAR-specific errors.
- Encrypted archives require a `KeyProvider`; missing credentials return `SAR_ERR_KEY_MISSING`.
- Wrong passwords or invalid tags fail before plaintext is released and surface as `SAR_ERR_AUTH_FAILED` / `SAR_ERR_DECRYPT_FAILED` depending on path.

### Example — low-level iteration

```rust
use std::fs::File;
use std::io::BufReader;
use sar_core::{ArchiveReader, ArchiveWriter, ArchiveWriterOptions, EntryInput};

let file = File::create("archive.sar")?;
let mut writer = ArchiveWriter::new(file, ArchiveWriterOptions::default())?;
writer.add_entry(EntryInput::file("hello.txt", b"hello".to_vec()))?;
writer.finish()?;

let mut reader = ArchiveReader::new(BufReader::new(File::open("archive.sar")?))?;
reader.read_global_header()?;
while let Some(entry) = reader.next_entry()? {
    println!("{}", entry.metadata.name);
}
# Ok::<(), sar_core::SarError>(())
```

### Example — high-level extraction (fragment + sparse aware)

```rust
use std::fs::File;
use std::io::BufReader;
use sar_core::ArchiveReader;

let mut reader = ArchiveReader::new(BufReader::new(File::open("archive.sar")?))?;
// read_all_logical_files: assembles fragment groups, applies sparse zero-fill.
// Pass allow_lossy=false to require complete data; pass true to accept degraded output.
let files = reader.read_all_logical_files(false)?;
for file in files {
    println!("{}: {} bytes (degraded={})", file.name, file.data.len(), file.is_degraded);
}
# Ok::<(), sar_core::SarError>(())
```

### Unsupported or planned in `sar-core`

Not implemented in this pass, even though some flags or structural fields already exist:

- signature cryptography and signature verification
- CDC map processing
- delta application for `ZSTD_PATCH` and custom patch algorithms
- partition reassembly logic
- transport-layer Stateful Streaming bindings and real network I/O
- stable FFI / C ABI (Milestone 12)

### M11a metadata API notes

**New public module: `metadata`**

`sar_core::metadata` exposes the following types (all re-exported at crate root):

- `FieldPresence<T>` — three-state presence enum:
  - `Absent` — Global Flag not set; field physically missing from the wire
  - `PresentInactive(T)` — Global Flag set but Entry Mode bit unset; field present on wire but semantically inactive
  - `PresentActive(T)` — Global Flag set and Entry Mode bit set; field present and active
  - Helper: `is_absent()`, `is_present()`, `is_active()`, `value() -> Option<&T>`
- `EntryKind` — `RegularFile`, `Directory`, `Symlink`, `EmptyArea`
- `EntryPermissionMetadata { mode: u16 }`
- `EntryOwnerMetadata { uid_gid: u32 }` (use `uid()` / `gid()` accessors; low 16 bits = UID, high 16 bits = GID)
- `EntryTimestampMetadata { mtime: u64, atime: u64, ctime: u64 }`
- `EntryCompressionMetadata { algo_id: u8 }`
- `EntryEncryptionMetadata { algo_id: u8, iv_nonce: [u8; 24] }`
- `EntryFecMetadata { algo_id: u8 }`
- `EntryCdcMetadata { algo_id: u8 }`
- `EntryDeltaMetadata { algo_id: u8, base_hash: [u8; 32] }`
- `EntryFragmentMetadata { fragment_id: u32, fragment_index: u32, absolute_offset: u64, fragment_size: u32 }`
- `EntrySparseMetadata { logical_size: u64, extents: Vec<SparseExtent> }`
- `EntryHashMetadata { algo_id: u8, hash: [u8; 32] }`

**Global Flags vs Entry Mode semantics**

Global Flags determine which LFH fields are physically present on the wire.
Entry Mode bits determine whether physically present fields are semantically active for a particular entry.

When a Global Flag is set but the corresponding Entry Mode bit is unset, the field is *physically present but semantically inactive*.  The reader surfaces this as `FieldPresence::PresentInactive(T)`.

The four `FieldPresence`-typed fields in `EntryMetadata` cover the LFH fields that have both a Global Flag and an Entry Mode toggle:

| Field | Global Flag | Entry Mode bit |
|---|---|---|
| `compression_presence` | `COMPRESSED` | `IS_COMPRESSED` |
| `encryption_presence` | `ENCRYPTED` | `IS_ENCRYPTED` |
| `fec_presence` | `SELECTIVE_FEC` | n/a (uses `fec_algo_id != 0`) |
| `fragment_presence` | `FILE_FRAGMENTATION` | `IS_FRAGMENT` |

Fields with only a Global Flag (no Entry Mode toggle) use `Option<T>`: `cdc`, `delta`, `sparse`, `file_crc32`, `content_hash`.

Fields that have a Global Flag but no per-entry Entry Mode toggle (always physically present if the flag is set) now use `FieldPresence<T>` to distinguish *absent* from *physically present*: `permissions_presence`, `owner_presence`, `timestamps_presence`.

The `path_presence` field uses `FieldPresence<String>` and additionally surfaces `PresentInactive("")` for the case where `HAS_PATH` is set but the LFH path length is zero (field present on wire, no path for this entry).

**Writer validation**

The writer validates metadata against enabled Global Flags before writing.  Requesting metadata that requires a flag that is not set fails with `SarError::FlagConflict`.  No metadata is silently dropped.

Examples of validated fields:
- `EntryInput::path` requires `ArchiveWriterOptions::with_path = true`
- `EntryInput::permissions` requires `ArchiveWriterOptions::with_permissions = true`
- `EntryInput::uid_gid` requires `ArchiveWriterOptions::with_uid_gid = true`
- `EntryInput::timestamps` requires `ArchiveWriterOptions::with_timestamps = true`
- `EntryInput::file_crc32` requires `ArchiveWriterOptions::with_per_file_crc = true`
- `EntryInput::content_hash` requires `ArchiveWriterOptions::with_content_hash = true`
- `EntryInput::kind = Symlink` requires `ArchiveWriterOptions::with_symlinks = true`

`LfhSizeFieldPolicy` is an implementation writer policy for this crate/API surface; it is not a new normative SAR wire-format rule. Readers continue to parse either valid LFH size layout based on the global `SIZE_64BIT` flag.

**M11a writer limitations**

- Fragment, sparse, FEC, CDC, and delta metadata passed in `EntryInput` are not yet wired to the corresponding LFH field writers.  These fields are accepted in the API but have no effect on the on-wire format for this milestone.
- Encryption IV and FEC value derivation continue to be handled internally by the writer pipeline.
- No filesystem restoration is performed.
- No CLI metadata flags are added.
- No UID/GID, permission, or timestamp restoration occurs.

**M11a non-goals**

The following are explicitly out of scope for M11a:
- CLI metadata flags
- Filesystem restoration (symlink extraction, UID/GID restoration, permission restoration, timestamp restoration)
- Crate-boundary refactor
- New conformance vector suite
- C ABI or Python bindings
- New transport behavior
- New CDC/delta/FEC semantics

### M11b filesystem metadata encode/decode notes

**New `FieldPresence` fields on `EntryMetadata`**

| Field | Global Flag | Semantics |
|---|---|---|
| `path_presence` | `HAS_PATH` | `Absent` = flag not set; `PresentInactive("")` = flag set, path_len=0; `PresentActive(s)` = flag set, non-empty path |
| `permissions_presence` | `HAS_PERMS` | `Absent` = flag not set; `PresentActive(EntryPermissionMetadata)` = flag set |
| `owner_presence` | `EXT_UID_GID` | `Absent` = flag not set; `PresentActive(EntryOwnerMetadata)` = flag set |
| `timestamps_presence` | `EXT_TIME` | `Absent` = flag not set; `PresentActive(EntryTimestampMetadata)` = flag set |

`PresentInactive` is not used for permissions, owner, or timestamps because these fields have no Entry Mode toggle — they are always active when the Global Flag is set.

Zero values for permissions/UID/GID/timestamps are preserved and never collapsed to `Absent`.

**Directory entry payload rule**

When `EntryMode::IS_DIRECTORY` is set, the payload MUST be zero bytes.  The writer rejects directory entries with non-empty payload (`SarError::Malformed`).  The reader rejects LFH entries where `IS_DIRECTORY` is set and `payload_size != 0` (`SarError::Malformed`).

**IS_SYMLINK → HAS_SYMLINKS validation**

The reader calls `validate_entry_mode_against_global` for each LFH.  If `IS_SYMLINK` is set in Entry Mode but the `HAS_SYMLINKS` Global Flag is absent, parsing fails with `SarError::FlagConflict`.  The writer also validates `EntryInput` before writing and rejects symlink entries if `with_symlinks` is not set.

**Symlink representation**

Symlink entries use `EntryInput::kind = Some(EntryKind::Symlink)` and carry the symlink target as the entry payload (UTF-8 encoded path string).  `EntryMetadata::entry_kind` is `EntryKind::Symlink` on read-back.  No symlinks are created on the host filesystem; the target string is only decoded and exposed through the metadata API.

**String encoding**

Name and path strings MUST be valid UTF-8.  The reader strictly rejects invalid UTF-8 bytes with `SarError::Malformed` (changed from lossy conversion in M11b).  The writer already requires `String` inputs, which are always valid UTF-8.

**Path and name length validation**

The writer validates that path length and name length each fit in a `u16` LFH field (max 65535 bytes).  Oversized strings are rejected with `SarError::Overflow` before writing.

**Writer fail-closed behavior**

Providing metadata that requires a Global Flag that is not set → `SarError::FlagConflict`.  No metadata is silently dropped.  This applies to path (`HAS_PATH`), permissions (`HAS_PERMS`), UID/GID (`EXT_UID_GID`), timestamps (`EXT_TIME`), and symlink entries (`HAS_SYMLINKS`).

**NO_INDEX archives**

All filesystem metadata (path, permissions, UID/GID, timestamps, symlinks, directories, hidden) encodes and parses identically in `NO_INDEX` archives.  No Central Directory is required for LFH metadata interpretation.

**Compressed/encrypted entries**

LFH metadata fields are always in the LFH header before the payload transforms.  Metadata remains parseable without decompressing or decrypting the payload.  Metadata fields are not encrypted.  AEAD/authentication ordering is unchanged.

**Fragment/sparse entries**

Fragment descriptors and sparse map fields coexist with filesystem metadata fields in the LFH.  Field order follows the SAR specification exactly.  The `write_sparse_entry` helper does not accept `EntryInput` (writer limitation); sparse entries created via that path carry only the fields set by the sparse helper.

**M11b non-goals**

- No filesystem restoration (chmod, chown, utime, symlink creation, directory creation, hidden attribute setting).
- No CLI metadata flags.
- No new wire-format fields, magic bytes, or end markers.
- No path canonicalization for extraction.
- Extraction safety (path traversal prevention, symlink extraction policy) belongs to M11d.

### M10a stream model notes

- `StreamArchiveParser` implements **stateless** SAR byte-stream parsing only.
- Parsing is forward-only and supports partial input via `StreamStep::NeedMore`.
- Entry Mode controls semantic applicability only; Global Flags still determine physical LFH field presence.
- Session `OP_CODE` bits and `SESSION_CONTROL` entries are parsed structurally only in M10a (no session lifecycle semantics).
- M10a parser currently supports forward-only `NO_INDEX` streaming paths.

### M10b session-layer notes in `sar-stream`

- `sar-stream` adds the **in-memory only** Stateful Streaming Mode state layer on top of `sar-core` parsing.
- Activation requires all of: `NO_INDEX`, non-zero `Stream ID`, and a valid `SESSION_INIT`.
- `SessionManager` tracks Stream ID → Session UUID binding, per-stream sequence continuity, peer capabilities, and session metadata.
- Sequence numbers increment by exactly 1 for every accepted entry and wrap from `0xFFFF` to `0x0000`; discontinuities fail with `SAR_ERR_STREAM_STATE`.
- Filesystem `OP_CODE`s (`DATA_WRITE`, `DELETE`, `RENAME`, `META_PROBE`, `SYNC_BARRIER`) and session `OP_CODE`s (`INIT`, `CLOSE`, `RESUME`, `HEARTBEAT`, `STATUS`, `ACK`, `METADATA`, `CAPABILITIES`) are validated as separate namespaces.
- `ATOMIC_WRITE` and `FORCE_SYNC` are surfaced as in-memory action flags only; no filesystem or transport side effects are performed by this crate.
- `LOSS_TOLERANT` can only surface degraded authenticated output as `SAR_WARN_INCOMPLETE`; it does not suppress auth, decompression, patch, or structural failures.
- No transport framing, QUIC/TCP binding, socket I/O, async runtime, retransmission, or background tasks are implemented in M10b.

### M10c transport-layer notes in `sar-transport`

- `sar-transport` depends on `sar-stream` (`sar-transport -> sar-stream -> sar-core`) and `sar-stream` does not depend on `sar-transport`.
- `SarTransportBinding`, `InMemoryTransport`, and `TransportHarness` provide deterministic in-memory transport policy/harness behavior only.
- TCP-like policy is non-interleaved and emits close/discard actions for invalid or unskippable stream errors.
- QUIC-like policy allows concurrent independent transport streams and emits stream-local reset/reject actions where possible.
- active SAR Stream ID uniqueness is enforced across the transport connection; duplicate active IDs fail closed.
- rejected Stream IDs remain unbound.
- `SESSION_CLOSE` unbinds Stream ID and allows later reuse.
- reverse `SESSION_STATUS` / `SESSION_ACK` are abstract transport actions and use `sar-stream` frame/event types (`SessionStatusFrame`, `SessionAckFrame`).
- heartbeat/watchdog hooks are explicit-time (`record_valid_activity`, `check_inactivity`, `maybe_emit_heartbeat`) with no background monitoring.
- M10c does not implement real TCP/QUIC sockets, async runtime integration, retransmission, congestion control, or TLS.

### M10d SAR-over-TCP binding in `sar-transport::tcp`

- `TcpSarConnection<S>` wraps any `Read + Write` stream (including `std::net::TcpStream`) and drives the M10c TCP-policy harness over real bytes.
- TCP listener/client entry points: `TcpSarConnection::connect(addr, config)` and `TcpSarConnection::accept(stream, config)`.
- Generic entry point for testing: `TcpSarConnection::from_stream(stream, config)`.
- `process_available(now_ms)` reads one bounded chunk, feeds it to the transport policy, serializes outbound control frames, and returns resulting actions.
- `write_all_sar_bytes(bytes)` writes a bounded chunk of raw SAR archive bytes to the stream.
- `close()` closes the connection gracefully.
- Uses a single fixed `TransportStreamId(0)` per TCP connection (one SAR session at a time, no byte-interleaving).
- When bidirectional control is active, `EmitSessionStatus` and `EmitSessionAck` actions are serialized as SAR LFH-encoded control entries and written to the outbound stream.  A single NO_INDEX global header is sent before the first outbound control frame; subsequent frames reuse the same session context.
- Heartbeat/watchdog is explicit-time: pass `now_ms` to `process_available`; no background timer.
- Uses `std::net` only (blocking I/O, no async runtime, no TLS, no QUIC).
- `TcpTransportConfig` holds `transport: TransportConfig`, `read_buffer_size`, and `write_buffer_size`; both buffer sizes are enforced before any allocation from network input.

### M10e SAR-over-QUIC binding in `sar-transport::quic` (`quic` feature)

- Requires the `quic` Cargo feature.  TCP/in-memory behavior is unchanged without this feature.
- QUIC networking uses **quinn 0.11** + **rustls 0.23** (ring provider) + **tokio 1** async runtime.  These deps are isolated to `sar-transport` and never leak into `sar-core`, `sar-stream`, `sar-crypto`, etc.
- **SAR-over-QUIC primary stream**: the primary SAR stream starts with `SAR!`, the SAR Global Header, optional KMS Data, and LFH entries.
- **Additional QUIC control stream**: an additional control stream starts directly with a canonical LFH-encoded `SESSION_CONTROL` entry for an already-active SAR Stream ID on the same QUIC connection; no `CTL!`, private envelope, UUID preheader, or extra association header is used.
- **TLS_EXPORTER SAR-AEAD selection**: KMS Mode `0x04 TLS_EXPORTER` selected by the SAR Global Header / KMS configuration is authoritative. `CAP_TLS_EXPORTER_AEAD` advertises support only and does not select the mode by itself.
- **TCP+TLS is not implemented.  STARTTLS is not implemented.  TLS_EXPORTER over plaintext TCP is not implemented.**

#### `QuicServerIdentity`

Carries explicit server TLS identity: DER-encoded certificate chain (`cert_chain_der: Vec<Vec<u8>>`) and DER-encoded private key (`private_key_der: Vec<u8>`).  A test-only `self_signed` helper is available for tests.

#### `QuicClientTrust`

Enum with two variants:
- `CustomCaDer(Vec<u8>)` — trust a custom CA certificate (DER bytes); the only production-safe variant.
- `InsecureSkipVerifyForTestsOnly` — skip certificate verification; intended only for tests and local diagnostics, never the default, and not for trusted production deployments.

#### `QuicTransportConfig`

Holds all per-connection limits: `max_connections`, `max_quic_streams_per_connection`, `max_active_sar_streams_per_connection`, `max_control_streams_per_sar_session`, `max_buffered_bytes`, `max_read_chunk`, `max_outbound_buffer_bytes`, `max_cert_chain_bytes`, `max_private_key_bytes`.

Also holds `pq_policy: TlsPqPolicy` (M10g) — see below.

#### `TlsPqPolicy` (M10g)

```rust
pub enum TlsPqPolicy {
    ClassicalAllowed,  // CLASSICAL_ALLOWED
    PreferPq,          // PREFER_PQ
    RequirePqOrHybrid, // REQUIRE_PQ_OR_HYBRID
    RequirePqOnly,     // REQUIRE_PQ_ONLY
}
```

Controls which TLS key agreement algorithm classes are offered and required on QUIC connections.  Aligns with Section 18.6.7 of the SAR specification.

| Variant | Spec name | Semantics |
|---|---|---|
| `ClassicalAllowed` | `CLASSICAL_ALLOWED` | Classical, hybrid PQ, and PQ-safe key agreement are all permitted.  Default when no PQ/hybrid group is available. |
| `PreferPq` | `PREFER_PQ` | PQ-safe or hybrid PQ key agreement is preferred; classical fallback is permitted.  Should be default when a PQ/hybrid group is available. |
| `RequirePqOrHybrid` | `REQUIRE_PQ_OR_HYBRID` | The TLS session MUST negotiate PQ-safe or hybrid key agreement.  Fails closed with `SAR_ERR_UNSUPPORTED` if unavailable. |
| `RequirePqOnly` | `REQUIRE_PQ_ONLY` | The TLS session MUST negotiate PQ-safe (non-hybrid) key agreement.  Fails closed with `SAR_ERR_UNSUPPORTED` if unavailable. |

**Current provider limitation:** the bundled `ring` TLS provider does not expose PQ-safe or hybrid key agreement groups (e.g. X25519MLKEM768).  `RequirePqOrHybrid` and `RequirePqOnly` return `SAR_ERR_UNSUPPORTED` at `QuicSarListener::bind` or `connect_quic` time.  `PreferPq` may fall back to classical.  Negotiated-group verification is not available with the current provider, so PQ/hybrid protection must not be claimed unless it can be verified.

**TLS_EXPORTER interaction:** TLS_EXPORTER SAR-AEAD inherits HNDL properties from the negotiated TLS session key agreement.  If classical-only key agreement was negotiated, TLS_EXPORTER SAR-AEAD MUST NOT be described as PQ-safe or HNDL-resistant.

Helper methods:

- `allows_classical_fallback() -> bool` — true for `ClassicalAllowed` and `PreferPq`.
- `requires_pq() -> bool` — true for `RequirePqOrHybrid` and `RequirePqOnly`.
- `requires_pq_only() -> bool` — true for `RequirePqOnly`.

#### `QuicServerConfig`

Holds `identity: QuicServerIdentity`, `transport: QuicTransportConfig`, and optional `alpn_protocols`.

#### `QuicClientConfig`

Holds `trust: QuicClientTrust`, `transport: QuicTransportConfig`, and optional `alpn_protocols`.

#### `QuicSarListener`

- `QuicSarListener::bind(server_config) -> Result<QuicSarListener, SarError>` — bind a QUIC listener on a random OS-assigned port.
- `local_addr() -> SocketAddr` — returns the bound address.
- `accept() -> Result<QuicSarConnection, SarError>` — accepts the next QUIC connection.

#### `QuicSarConnection`

- `QuicSarConnection` multiplexes multiple SAR sessions over one QUIC connection.
- `accept_stream() -> Result<QuicSarStream, SarError>` — accepts the next incoming bidirectional QUIC stream.
- `open_stream() -> Result<QuicSarStream, SarError>` — opens a new outgoing bidirectional QUIC stream.
- `close()` — gracefully closes the connection.
- `feed_stream_bytes(stream_id, bytes) -> Result<Vec<TransportAction>, SarError>` — feeds bytes for a specific QUIC stream into the M10c QUIC-policy harness and returns transport actions.
- `flush_pending_control_frames(stream)` — flushes any control-frame bytes buffered by `feed_stream_bytes` to the actual QUIC stream.
- `export_keying_material(label, context, len) -> Result<Vec<u8>, SarError>` — derives TLS exporter material from the active QUIC/TLS session.

#### `QuicSarStream`

- Represents a single bidirectional QUIC stream with its local `TransportStreamId`.
- `stream_id() -> TransportStreamId` — the local stream ID used with `feed_stream_bytes`.

#### `connect_quic`

```rust
pub async fn connect_quic(
    server_name: &str,
    addr: SocketAddr,
    config: QuicClientConfig,
) -> Result<QuicSarConnection, SarError>
```

Establishes a QUIC connection to a `QuicSarListener`.

#### Connection model summary

- A `QuicSarListener` accepts multiple `QuicSarConnection`s.
- Each `QuicSarConnection` may carry multiple simultaneous SAR sessions.
- Active SAR Stream IDs are scoped to a single QUIC connection and must be unique per connection.
- The same numeric SAR Stream ID may be active on different QUIC connections as independent sessions.
- A duplicate `SESSION_INIT` for an already-bound SAR Stream ID on the same QUIC connection is rejected with `SAR_ERR_STREAM_STATE`; the rejected Stream ID remains unbound.
- `SESSION_CLOSE` unbinds the SAR Stream ID on that QUIC connection.
- Additional QUIC control streams are associated only by QUIC connection + LFH `Stream ID`.
- Additional QUIC control streams start directly with LFH-encoded `SESSION_CONTROL` entries and must not begin with `SAR!` or `CTL!`.
- Baseline reverse-direction additional-control entries are `SESSION_ACK`, `SESSION_STATUS`, and `SESSION_CAPABILITIES` when bidirectional control is active.
- **TLS PQ/hybrid key agreement policy** (M10g, `TlsPqPolicy`): configures which TLS key agreement algorithm classes are offered and accepted on QUIC connections.  See `TlsPqPolicy` below.

---

## M8 APIs in `sar-core`

### `sar_core::archive` — high-level extraction types

#### `LogicalFile`

```rust
pub struct LogicalFile {
    pub name: String,
    pub fragment_id: Option<u32>,
    pub data: Vec<u8>,
    pub is_degraded: bool,
}
```

Returned by `ArchiveReader::read_all_logical_files`. For fragmented entries, fragments have been assembled at their declared absolute offsets. For sparse entries, holes are zero-filled. `is_degraded` is `true` when the payload is incomplete due to `LOSS_TOLERANT`-permitted missing fragments.

#### `ArchiveReader::read_all_logical_files(allow_lossy: bool) -> Result<Vec<LogicalFile>, SarError>`

Reads all entries, assembles fragment groups, applies sparse reconstruction, and returns fully reconstructed logical files. Resets the internal read cursor so it can be called after prior `next_entry` calls.

**Behavior:**
- Non-fragmented entries: returned as-is (with optional sparse reconstruction).
- Fragment groups: sorted by `fragment_index`, scattered by `descriptor.absolute_offset`.
  - **Sparse Map in a fragment group must appear only on the entry with `fragment_index == 0`**; presence on any other index returns `SarError::InvalidMap` immediately, even when `allow_lossy=true`.
  - The Sparse Map from fragment index 0 applies to the **entire reassembled group payload**.
  - Fragment reassembly always precedes sparse reconstruction (Fragment Reassembly → Logical Payload → Sparse Reconstruction → Final File).
- Missing fragments + `allow_lossy=false` → `SarError::FragmentGap`.
- Missing fragments + `allow_lossy=true` + `LOSS_TOLERANT` → degraded output, `is_degraded=true`.
- Overlapping fragment descriptors → `SarError::InvalidMap`.
- AEAD authentication failures are **never** suppressed by `allow_lossy`.
- Format errors are **never** suppressed by `allow_lossy`.
- **Sparse reconstruction uses LFH `Uncompressed Size` as the final logical file size.** Trailing holes after the final sparse extent are filled with zero bytes up to `Uncompressed Size`. Large logical sizes are capped by `ArchiveReaderOptions.limits.max_decoded_entry_size`. **The implementation rejects oversized logical sizes before allocation (sparse expansion-bomb protection).**
- **Sparse expansion-bomb protection**: a tiny stored payload combined with a huge `Uncompressed Size` and a sparse extent near the end (e.g., `Uncompressed Size=1025`, `max_decoded_entry_size=1024`, sparse map `{offset=1024, length=1}`, one stored byte) is rejected with `SAR_ERR_LIMIT_EXCEEDED` **before any large allocation is attempted**. This is not `SAR_ERR_INVALID_MAP` because the sparse map is structurally valid.
- **CRC32 verification** (when `PER_FILE_CRC` is set and the LFH `file_crc32` field is present): CRC32 is computed over the fully reconstructed logical file bytes, **including sparse holes**. A wrong CRC returns `SarError::CrcMismatch`. Verification applies after fragment reassembly and sparse reconstruction. Content-hash verification is not implemented; see Known Limitations below.
- **Empty Areas** (entries with `Name Length == 0` and `IS_FRAGMENT == 0`) are excluded from the returned list; they do not participate in sparse reconstruction, hashing, delta, or fragmentation.

### `sar_core::sparse`

Sparse file map parsing, writing, validation, and scatter-gather reconstruction.

#### Public types

- `SparseExtent { offset: u64, length: u64 }` — one contiguous extent in the logical file

#### Public functions

- `parse_sparse_map(bytes: &[u8], is_64bit: bool, limits: &ResourceLimits) -> Result<Vec<SparseExtent>, SarError>`
  — decodes the raw sparse map from an LFH; 8 bytes per entry in 32-bit mode, 16 bytes in 64-bit mode; returns `SarError::InvalidLength` when byte count is not a multiple of entry size
- `write_sparse_map(extents: &[SparseExtent], is_64bit: bool) -> Vec<u8>`
  — serializes extents back to the wire format
- `validate_sparse_extents(extents: &[SparseExtent], logical_size: u64, limits: &ResourceLimits) -> Result<(), SarError>`
  — checks that extents are sorted, non-overlapping, within `logical_size` bounds, and within configured sparse-descriptor limits; returns `SarError::InvalidMap` on violation, `SarError::Overflow` on arithmetic overflow
- `apply_sparse_reconstruction(payload: &[u8], extents: &[SparseExtent], logical_size: u64, limits: &ResourceLimits) -> Result<Vec<u8>, SarError>`
  — creates a zero-filled buffer of exactly `logical_size` bytes (the LFH `Uncompressed Size`) and writes each extent slice from `payload` at its declared offset; trailing holes beyond the final extent are filled with `0x00`; returns `SarError::InvalidMap` if an extent exceeds `logical_size` or if payload has excess bytes; returns `SarError::Truncated` if payload is too short for the declared extents

**Transformation ordering:**

Sparse reconstruction occurs after all prior transformations in this order:
1. Fragment Reassembly (if `FILE_FRAGMENTATION`)
2. Decryption (if `ENCRYPTED`) — authentication failure is never suppressed
3. Decompression (if `COMPRESSED`)
4. Delta Application (if `HAS_DELTA`) — `STORE_PATCH`, `VCDIFF`, and `BSDIFF` implemented; `ZSTD_PATCH`/custom unsupported
5. Sparse Reconstruction (if `SPARSE_FILES`)

The Sparse Map describes the layout of the **fully reconstructed logical payload**, not individual fragments or compressed bytes.

**Sparse Map placement in fragment groups:**

When both `SPARSE_FILES` and `FILE_FRAGMENTATION` are enabled, the Sparse Map MUST appear only in the entry with `Fragment Index == 0`. Presence on any other fragment index returns `SarError::InvalidMap` immediately and is **never** suppressed by `allow_lossy`.

#### `ArchiveWriter::write_sparse_entry` *(new in M8 final pass)*

```rust
pub fn write_sparse_entry(
    &mut self,
    name: &str,
    gathered_payload: &[u8],
    sparse: SparseWriteOptions,
) -> Result<(), SarError>
```

Writes a sparse entry to the archive. `gathered_payload` must have exactly `sum(extent.length)` bytes; the extents describe where each gathered byte maps in the final logical file. `sparse.logical_size` is written to LFH `Uncompressed Size` and must be at least `max(extent.offset + extent.length)` across all extents.

Validation before writing:
- `ArchiveWriterOptions::sparse` must be `true`; otherwise returns `SarError::Malformed`.
- Extents must be sorted, non-overlapping, and within `logical_size`; violations return `SarError::InvalidMap`.
- `gathered_payload.len()` must equal `sum(extent.length)`; mismatch returns `SarError::InvalidMap`.

Applies compression/encryption/FEC inherited from the writer options identically to `add_entry`.

#### Known Limitations

- **Content-hash verification** is not implemented. When `DEDUPLICATION` is set, the LFH carries a 32-byte `content_hash` field. The archive format does not encode the hash algorithm in any fixed LFH or global-header field; the spec refers to "e.g., BLAKE3" without normatively defining the algorithm encoding. Verification cannot be performed without knowing the algorithm. This is an implementation gap (not a spec gap); once the algorithm encoding is normatively defined, verification can be added. The `content_hash` bytes are parsed and preserved in `EntryMetadata.content_hash` for use by callers.
- **CRC32 is verified in `read_all_logical_files` only**, not in `next_entry`. Callers using `next_entry` directly must verify `EntryMetadata.file_crc32` manually if needed.
- `write_sparse_entry` does not yet support writing fragmented sparse entries (i.e., splitting a sparse logical file across multiple fragment-group LFHs). Use `add_entry` with manual fragment construction for that scenario.

### `sar_core::fragment`

Fragment group types and archival reassembly.

#### Public types

- `FragmentDescriptor { absolute_offset: u64, fragment_size: u32 }`
  — position of a fragment in the logical file (from the LFH Fragment Descriptor field)
- `FragmentEntry { fragment_index: u32, is_last_fragment: bool, is_loss_tolerant: bool, descriptor: FragmentDescriptor, payload: Vec<u8> }`
  — one fragment's decoded payload and metadata, ready for reassembly

#### Public functions

- `validate_fragment_group(fragments: &[FragmentEntry], logical_size: u64, limits: &ResourceLimits) -> Result<(), SarError>`
  — checks bounds (each fragment fits within `logical_size`), fragment-level overlaps, and configured fragment-count/span limits
- `reconstruct_fragments(fragments: Vec<FragmentEntry>, logical_size: u64, limits: &ResourceLimits) -> Result<(Vec<u8>, bool), SarError>`
  — sorts fragments by index, fills a `logical_size` zero buffer with each fragment's payload at `descriptor.absolute_offset`
  — if a gap exists and `is_loss_tolerant` is set on any fragment, fills gap with zeros and returns `(data, true)` (degraded), subject to `max_loss_tolerant_gap`
  — if a gap exists and no fragment has `is_loss_tolerant`, returns `SarError::FragmentGap`

### `sar_core::recovery`

Archive-level Data Recovery TLV inspection, planning, and repair.

#### Public types

- `ErasureRange { offset: u64, length: u64 }` — one erased byte range in the protected region
- `ProtectedRange { offset: u64, length: u64, algo_id: u8 }` — the archive-level FEC protected range
- `EntryErasure { entry_index: usize, ranges: Vec<ErasureRange> }` — per-entry erasures (for future use)
- `ErasureInput { entries: Vec<EntryErasure>, archive_ranges: Vec<ErasureRange> }` — erasure JSON input format
- `RecoveryMetadata { has_global_ec: bool, protected_range: Option<ProtectedRange>, recovery_tlvs: Vec<FecSummary>, repair_possible: bool, repair_unavailable_reason: Option<&'static str> }`
- `RecoveryPlan { erasures: ErasureInput, protected_range: ProtectedRange, algo_id: u8 }`
- `RepairReport { success: bool, repaired_ranges: Vec<ErasureRange>, degraded: bool, error: Option<String> }`

#### Public functions

- `inspect_recovery_metadata(archive_bytes: &[u8], limits: &ResourceLimits) -> Result<RecoveryMetadata, SarError>`
  — parses archive global header and CD, extracts RECOVERY TLVs (type IDs 0x10–0x1F), computes protected range `[GLOBAL_FLAGS_OFFSET, cd_offset)`
- `plan_archive_repair(archive_bytes: &[u8], erasures: ErasureInput, limits: &ResourceLimits) -> Result<RecoveryPlan, SarError>`
  — validates erasures within protected range and against FEC block boundaries
  — returns `SarError::RecoveryUnavailable` for unaligned erasures or missing TLV (see SPEC_QUESTIONS.md)
- `repair_archive(archive_bytes: &[u8], plan: &RecoveryPlan, limits: &ResourceLimits) -> Result<(Vec<u8>, RepairReport), SarError>`
  — applies XOR or Reed-Solomon erasure repair to the protected range, returns repaired archive bytes and a report, and enforces `max_recovery_protected_range` / `max_repair_working_set`
  — returns `SarError::EcFailed` if erasures exceed parity capacity
  — returns `SarError::RecoveryUnavailable` if repair is not supported for this TLV

#### Important constraints

- `repair_archive` never writes to the filesystem; the caller handles temp-file + rename
- Repair never guesses erasures; only explicit `ErasureInput` is accepted
- LOSS_TOLERANT does not bypass AEAD authentication
- FEC repair is applied to ciphertext bytes before AEAD authentication

### FFI / C ABI notes for `sar-core`

- Good future FFI candidates:
  - archive open/read/close wrappers built around `ArchiveReader`
  - archive create/add_entry/finish wrappers built around `ArchiveWriter`
  - archive verify / inspect summary wrappers
  - `SarStatus`-based status mapping
- Not FFI-ready as-is:
  - `ArchiveReader<R>` / `ArchiveWriter<W>` generics
  - `Box<dyn KeyProvider>` callbacks
  - `EncoderTransform` / `DecoderTransform` trait objects
  - helper structs exposing owned Rust collections directly

## `sar-compression`

### Purpose

`sar-compression` implements the current SAR compression registry and bounded stream encode/decode helpers.

### Implemented milestone coverage

- Milestone 4

### Main public APIs

- Constants:
  - `COMP_ALGO_STORE = 0x00`
  - `COMP_ALGO_DEFLATE = 0x01`
  - `COMP_ALGO_ZSTD = 0x02`
- `CompressionAlgorithm`
  - `from_id()`
  - `id()`
  - `name()`
- `CompressionOptions`
- `DecompressionOptions`
- `CompressionError`
- `encode_stream()`
- `decode_stream()`

### Error behavior

- Unknown assigned IDs return `Unsupported`.
- Reserved IDs return `ReservedValue`.
- Decoding is bounded by `DecompressionOptions.max_output_size`; overrun returns `LimitExceeded`.

### Unsupported or planned

- No additional compression algorithms beyond STORE/DEFLATE/ZSTD.
- No Cargo feature gating for individual backends.

### FFI / C ABI notes

- `ready` for registry constants and wrapper-friendly settings structs.
- `candidate` for stream helpers because the Rust API uses `Read`/`Write` trait objects and should become buffer-based or handle-based at the FFI boundary.

## `sar-crypto`

### Purpose

`sar-crypto` contains hash functions, AEAD helpers, KMS parameter types/parsers, and the `KeyProvider` abstraction used by `sar-core` and `sar-cli`.

### Implemented milestone coverage

- Milestone 5

### Public modules

- `aad`
- `aead`
- `algorithm`
- `error`
- `hash`
- `kms`
- `provider`
- `secret`

### Main public APIs

#### Registry and validation

- Hash IDs: `HASH_SHA256`, `HASH_BLAKE3`, `HASH_SHA3_256`
- Encryption IDs: `ENCR_PLAINTEXT`, `ENCR_AES256_GCM`, `ENCR_CHACHA20`, `ENCR_AES256_CBC`, `ENCR_XCHACHA20_POLY`, `ENCR_CHACHA20_POLY1305`
- KMS IDs: `KMS_PBKDF2`, `KMS_ARGON2`, `KMS_ASYMMETRIC_WRAP`, `KMS_TLS_EXPORTER`
- PBKDF2 PRF IDs and Argon2 variant IDs
- `AEAD_KEY_SIZE`, `AEAD_TAG_SIZE`
- `validate_encr_algo_id()`
- `validate_kms_mode_id()`

#### AEAD and AAD helpers

- `aead_encrypt()`
- `aead_decrypt()`
- `generate_nonce()`
- `validate_nonce_field()`
- `global_header_aad_bytes()`
- `build_aead_aad()`

#### Hashing APIs

- `Hasher` trait
- `sha256()`
- `blake3_hash()`
- `new_hasher()`
- `hash_data()`
- `ct_eq()`

#### KMS and key-provider APIs

- `Pbkdf2Params`
- `Argon2Params`
- `AsymmetricRecipient`
- `AsymmetricWrapParams`
- `KmsParams`
- `KmsContext`
- `parse_kms_payload()`
- `serialize_kms_payload()`
- `KeyProvider`
- `resolve_cek()`
- low-level public helpers currently exposed from submodules:
  - `kms::pbkdf2::derive_key()`
  - `kms::argon2::derive_key()`
  - `kms::asymmetric::unwrap_cek()`

#### Secret containers and errors

- `SecretBytes = Zeroizing<Vec<u8>>`
- `SecretString = Zeroizing<String>`
- `SarCryptoError`

### Error behavior

- Unsupported or reserved algorithm IDs fail closed.
- PBKDF2 parsing enforces salt and iteration minimums and a hard iteration ceiling.
- Argon2 parsing enforces minimum salt, memory, time, and parallelism values plus DoS ceilings.
- AEAD decryption validates tags before returning plaintext.

### Unsupported or planned

- SHA3-256 is declared but not implemented.
- Only AES-256-GCM and XChaCha20-Poly1305 are integrated into `sar-core` archive flows.
- `ASYMMETRIC_WRAP` is a structural/public KMS mode with callback-based unwrapping, not a built-in RSA/ECIES implementation.
- `KMS_TLS_EXPORTER` (`0x04`) is a spec-defined KMS mode identifier that is recognized and exported as a constant. It is **not** implemented in this release; `parse_kms_payload(KMS_TLS_EXPORTER, …)` and `validate_kms_mode_id(KMS_TLS_EXPORTER)` return `SAR_ERR_UNSUPPORTED`. Plaintext TCP streams that advertise this KMS mode are rejected with `SAR_ERR_UNSUPPORTED`.

### FFI / C ABI notes

- `ready`: algorithm constants, KMS config structs, status-like crypto error mapping.
- `candidate`: one-shot hash helpers, AEAD wrappers, KMS payload parse/serialize helpers.
- `unstable`: `KeyProvider`, `Hasher`, and callback-heavy or trait-object APIs.
- `not_applicable`: direct exposure of `SecretBytes` / `SecretString`; a C ABI should use explicit buffers plus explicit zero/free functions instead.

## `sar-fec`

### Purpose

`sar-fec` implements current FEC codecs and metadata parsing for Milestones 6–7.

### Implemented milestone coverage

- Milestone 6: XOR FEC (`0x14`)
- Milestone 7: Reed-Solomon FEC (`0x11`)

### Public modules

- `error`
- `registry`
- `rs`
- `types`
- `xor`

### Main public APIs

#### Registry and shared types

- `FEC_ALGO_REED_SOLOMON = 0x11`
- `FEC_ALGO_XOR = 0x14`
- `validate_fec_algo_id()`
- `parse_fec_value()`
- `FecValue`
- `Erasure`
- `FecRecoverInput<'a>`
- `FecOptions`
- `FecCodec`
- `XorMeta`, `RsMeta`, `FecMeta`
- `FecError`

#### XOR codec APIs

- `XorCodec`
  - `new(stripe_size, block_size_index)`
  - `from_fec_value(data)`
- `parse_xor_meta()`
- `validate_xor_fec_value()`

#### Reed-Solomon codec APIs

- `RsCodec`
  - `new(k, parity_count, symbol_size)`
  - `from_fec_value(data)`
- `parse_rs_meta()`
- `validate_rs_fec_value()`

### Error behavior

- FEC is explicit-erasure recovery only; callers must identify erasure positions.
- Unsupported assigned FEC IDs fail with `Unsupported`; reserved IDs fail with `ReservedValue`.
- Both codecs bound parity size to `256 MiB`.
- Reed-Solomon currently caps parity count to 32.

### Examples

- `XorCodec::new(4, 4)` corresponds to stripe size 4 and 4 KiB blocks.
- `RsCodec::new(4, 2, 256)` corresponds to `k=4`, `n-k=2`, and 256-byte symbols.

### Unsupported or planned

- No automatic archive repair command or archive-wide repair orchestration yet.
- No support for assigned-but-unimplemented FEC IDs such as `0x12`, `0x13`, `0x15`, `0x16`.

### FFI / C ABI notes

- `ready`: metadata structs (`XorMeta`, `RsMeta`), algorithm IDs, status mapping wrappers.
- `candidate`: codec constructor + encode/validate/recover wrappers with opaque handles or direct one-shot functions.
- `unstable`: exposing the trait `FecCodec` directly across FFI.

## `sar-cli`

### Purpose

`sar-cli` is the current command-line front end over `sar-core`.

### Implemented milestone coverage

- Milestones 3–8 for the currently implemented archive, compression, crypto, Selective FEC, sparse, fragment, recovery, and repair flows

### Actual command surface

#### `create`

Status: implemented

Usage:

```text
sar create <input> <output.sar> [--indexed|--no-index]
    [--compression store|deflate|zstd | -S | -z | -Z]
    [--compression-level 0..9 | -0..-9]
    [--encrypt aes256-gcm|xchacha20-poly] [--password PASSWORD]
    [--fec xor|rs]
```

Behavior:

- archives either one file or a directory tree
- defaults to STORE compression
- rejects `--indexed` together with `--no-index`
- rejects `--password` unless `--encrypt` is also set
- encryption currently uses PBKDF2-HMAC-SHA256 with a random 32-byte salt
- Selective FEC is per-entry only

#### `extract`

Status: implemented

Usage:

```text
sar extract <archive.sar> <output-dir> [--password PASSWORD] [--allow-lossy]
    [--max-archive-size BYTES]
    [--max-decoded-entry-size BYTES]
    [--max-in-memory-buffer BYTES]
    [--max-total-pipeline-memory BYTES]
    [--max-sparse-map-bytes BYTES]
    [--max-sparse-descriptors COUNT]
    [--max-fragment-count COUNT]
    [--max-fragment-group-span BYTES]
    [--max-loss-tolerant-gap BYTES]
```

Behavior:

- creates parent directories as needed
- rejects absolute paths and `..` traversal during extraction
- loads password from `--password`, then `SAR_PASSWORD`, then an interactive prompt if the archive is encrypted
- `--allow-lossy`: permits extraction of archives containing LOSS_TOLERANT entries; prints a warning if any such entries are present; does not currently perform automatic degraded fragment reassembly
- sparse extraction validates the final apparent size against `ResourceLimits.max_decoded_entry_size`, creates a temp file, sets the target file length, seeks to sparse extents, writes only gathered payload bytes, and renames to the final output only after success
- fragmented sparse extraction reuses the same `ResourceLimits` model for fragment span/count checks and sparse output checks
- resource-limit failures are printed as `resource-limit error (SAR_ERR_LIMIT_EXCEEDED)` and do not leave finalized output files behind

#### `list`

Status: partial

Usage:

```text
sar list <archive.sar>
```

Behavior:

- prints one line per entry: name, compression name, encoded size, uncompressed size
- works for unencrypted archives and current FEC archives
- does not currently accept `--password`, so encrypted archives cannot be listed successfully once entry decoding requires credentials

#### `verify`

Status: implemented

Usage:

```text
sar verify <archive.sar> [--password PASSWORD] [--recovery]
    [--max-archive-size BYTES]
    [--max-decoded-entry-size BYTES]
    [--max-in-memory-buffer BYTES]
    [--max-total-pipeline-memory BYTES]
    [--max-sparse-map-bytes BYTES]
    [--max-sparse-descriptors COUNT]
    [--max-fragment-count COUNT]
    [--max-fragment-group-span BYTES]
    [--max-loss-tolerant-gap BYTES]
```

Behavior:

- verifies archive structure and indexed offsets
- validates recovery TLV structure when archive-level FEC metadata exists
- decrypts entries when needed, so encrypted verification requires a password/key provider
- `--recovery`: additionally validates fragmentation metadata consistency, sparse extent validity, Data Recovery TLV structure, and reports `repair_possible` / unavailable reason; distinguishes file-level FEC metadata from archive-level recovery TLVs
- recovery-mode archive reads that require `fs::read` are pre-checked against `max_archive_size` before allocating the archive byte buffer

#### `inspect`

Status: partial

Usage:

```text
sar inspect <archive.sar> [--json]
```

Behavior:

- plaintext mode prints global version, flags, selective-FEC status, entry count, per-entry FEC summary lines, and recovery-TLV count
- JSON mode prints archive summary including `global_ec`, `fragmentation`, `sparse_files`, `repair_possible`, `recovery_tlvs` (archive-level TLV summaries), and per-entry `fec` (file-level selective FEC), `is_fragment`, `fragment_id`, `fragment_index`, `is_last_fragment`, `is_loss_tolerant`, `sparse_extent_count`
- current implementation can inspect unencrypted archives and FEC/fragment/sparse/recovery metadata
- it does not accept `--password`, so encrypted archives are not fully inspectable through the CLI today

#### `repair`

Status: implemented (M8)

Usage:

```text
sar repair <archive.sar> <output.sar> --fec [--erasures erasures.json]
    [--max-archive-size BYTES]
    [--max-decoded-entry-size BYTES]
    [--max-in-memory-buffer BYTES]
    [--max-total-pipeline-memory BYTES]
    [--max-sparse-map-bytes BYTES]
    [--max-sparse-descriptors COUNT]
    [--max-fragment-count COUNT]
    [--max-fragment-group-span BYTES]
    [--max-loss-tolerant-gap BYTES]
    [--max-recovery-protected-range BYTES]
    [--max-repair-working-set BYTES]
```

Behavior:

- `--fec` is required; prints error "repair requires --fec" if absent
- `--erasures <file>` is required; prints error "repair requires --erasures <file>" if absent
- parses erasures JSON into `ErasureInput`
- calls `inspect_recovery_metadata` to check archive EC support
- calls `plan_archive_repair`; if `RecoveryUnavailable`, prints message and does **not** create output file
- calls `repair_archive` on success
- pre-checks the archive file length against `max_archive_size` before reading the archive into memory
- writes repaired bytes to a temp sibling file (`<output>.tmp`) first
- verifies temp file structure (parses, checks structure)
- renames temp to final output only if verification passes
- if any step fails, including `SAR_ERR_LIMIT_EXCEEDED`, deletes temp file and does **not** create the final output file

#### `version`

Status: implemented

Usage:

```text
sar version
sar -V
```

Output format:

```text
sar-cli <crate-version> | sar-spec v1.0 | cd-v1
```

#### Shorthand aliases

Implemented:

```text
sar -c <input> -f <output.sar>
sar -x -f <archive.sar> -C <dir>
sar -t -f <archive.sar>
sar -v -f <archive.sar>
sar -V
```

Compression shorthands:

```text
sar create <input> <output.sar> -S
sar create <input> <output.sar> -z
sar create <input> <output.sar> -Z -9
```

### Error behavior

- success exits `0`
- failure exits `1` and prints `error (SAR_STATUS_NAME): ...` to stderr

### Unsupported or planned CLI surface

- no `--password` support for `list` or `inspect`
- no CLI support for signatures, CDC, delta, fragmentation partition sets, or streaming APIs
- automatic end-to-end loss-tolerant fragment extraction not yet wired through `ArchiveReader`

### FFI / C ABI notes

- good future FFI equivalents: create, extract, list, verify, inspect
- not FFI-ready as-is: terminal prompting, environment-variable password fallback, Rust-specific `CliKeyProvider`

## Placeholder crates

Each placeholder crate currently exposes exactly one public marker type, `NotImplemented`, and no usable protocol API.

### `sar-cdc`

- Purpose: reserved for future content-defined chunking support
- Status: placeholder
- Public API: `NotImplemented`
- FFI readiness: `not_applicable`

### `sar-delta`

- Purpose: patch algorithm registry, delta LFH field types and validation (M9b); `STORE_PATCH`, `VCDIFF`, and `BSDIFF` application implemented.
- Status: complete (M9b — registry, metadata, `STORE_PATCH`, `BSDIFF`, and `VCDIFF` implemented; `ZSTD_PATCH`/custom blocked)
- Public API (M9b):
  - `PatchAlgoId` — enum of assigned and custom patch algorithm identifiers: `StorePatch (0x00)`, `Vcdiff (0x01)`, `Bsdiff (0x02)`, `ZstdPatch (0x03)`, `Custom(u8)` (`0xF0–0xFF`)
  - `PatchError` — local error enum: `Unsupported`, `ReservedValue`, `PatchFailed`, `BaseMissing`, `LimitExceeded`
  - `validate_patch_algo_id(u8) -> Result<PatchAlgoId, PatchError>` — validates a raw byte against the SAR patch algorithm registry; returns `ReservedValue` for `0x04–0xEF`, `Unsupported` for `0xF0–0xFF`, and the corresponding `PatchAlgoId` for all assigned IDs
  - `patch_algo_name(u8) -> &'static str` — returns a display name for any raw algorithm byte
  - `apply_store_patch(patch_payload: &[u8], expected_len: u64) -> Result<Vec<u8>, PatchError>` — applies `STORE_PATCH` (identity): returns the patch payload if its length equals `expected_len`, otherwise returns `PatchFailed`
  - `apply_bsdiff(base: &[u8], patch: &[u8], expected_target_size: u64, limits: &BsdiffLimits) -> Result<Vec<u8>, PatchError>` — applies a SAR BSDIFF v1 (`SARBSD01`) patch; caller supplies base bytes explicitly
  - `apply_vcdiff(base: &[u8], patch: &[u8], expected_target_size: u64, limits: &VcdiffLimits) -> Result<Vec<u8>, PatchError>` — applies a VCDIFF (RFC 3284) patch; caller supplies base bytes explicitly
  - `bsdiff::BsdiffLimits` — resource limits for BSDIFF patch application (`max_patch_size`, `max_control_bytes`, `max_diff_bytes`, `max_extra_bytes`, `max_control_triples`, `max_target_size`)
  - `vcdiff::VcdiffLimits` — resource limits for VCDIFF patch application (`max_patch_size`, `max_window_count`, `max_instruction_count`, `max_output_size`)
  - `decode_bsdiff_int(bytes: &[u8]) -> Result<i64, PatchError>` — decodes a classic bsdiff sign-magnitude 8-byte integer
  - Constants: `PATCH_ALGO_STORE_PATCH (0x00u8)`, `PATCH_ALGO_VCDIFF (0x01u8)`, `PATCH_ALGO_BSDIFF (0x02u8)`, `PATCH_ALGO_ZSTD_PATCH (0x03u8)`, `PATCH_ALGO_CUSTOM_MIN (0xF0u8)`, `PATCH_ALGO_CUSTOM_MAX (0xFFu8)`
- All of the above are re-exported from `sar-core` for consumer convenience.
- FFI readiness: `not_applicable` (no C ABI in this milestone)

**Implemented in STORE_PATCH pass:**

- `STORE_PATCH` (`0x00`) application: decoded patch payload is the complete reconstructed target; no base reads; no instruction stream; output length must equal LFH `Uncompressed Size` or `SAR_ERR_PATCH_FAILED` is returned
- All-zero `Delta Base Hash` accepted for `STORE_PATCH` (treated as "no base required"); nonzero hash preserved verbatim in metadata
- `ResourceLimits` enforced before allocation; `SAR_ERR_LIMIT_EXCEEDED` returned if `Uncompressed Size` exceeds `max_decoded_entry_size`
- `STORE_PATCH` + compression, encryption, sparse, and fragmentation all handled correctly through the existing transformation pipeline

**Implemented in M9b Delta pass (BSDIFF + VCDIFF):**

- `BSDIFF` (`0x02`) SAR BSDIFF v1 profile: magic `SARBSD01`, sign-magnitude header fields, uncompressed Control/Diff/Extra blocks, control triples `(diff_len, extra_len, seek_adjust)`. Base reads beyond end use `0x00`. Base seek before 0 → `SAR_ERR_PATCH_FAILED`. Explicit base bytes required.
- `VCDIFF` (`0x01`) RFC 3284: standard header/window/instruction decoding, VCD_SOURCE and VCD_TARGET windows, ADD/COPY/RUN instructions, default code table (s_near=4, s_same=3). Explicit base bytes required.
- VCDIFF streams that require secondary compressors return `SAR_ERR_UNSUPPORTED`.
- `ArchiveReaderOptions.delta_base: Option<Vec<u8>>` — caller supplies base bytes; no automatic discovery, no network access, no CAS access.
- All-zero `Delta Base Hash` for BSDIFF/VCDIFF → `SAR_ERR_BASE_MISSING`.
- Missing `delta_base` for BSDIFF/VCDIFF → `SAR_ERR_BASE_MISSING`.
- `ResourceLimits` enforced for BSDIFF (control/diff/extra block sizes, triple count) and VCDIFF (window count, instruction count, output size).
- `BSDIFF`/`VCDIFF` + compression and encryption handled correctly through the existing transformation pipeline.
- Legacy classic `BSDIFF40` decode support is not implemented; payloads with `BSDIFF40` magic return `SAR_ERR_PATCH_FAILED`.
- `ZSTD_PATCH` (`0x03`) → `SAR_ERR_UNSUPPORTED` (dictionary protocol not specified).

**Not implemented:**

- `ZSTD_PATCH` application (dictionary/protocol not specified by spec)
- Custom patch algorithms
- Delta Base Hash verification (hash algorithm not specified by spec; field is opaque)
- Automatic base object resolution (location model not specified by spec)

### `sar-fragmentation`

- Purpose: reserved for future fragmentation support
- Status: placeholder
- Public API: `NotImplemented`
- FFI readiness: `not_applicable`

### `sar-partition`

- Purpose: reserved for future partition support
- Status: placeholder
- Public API: `NotImplemented`
- FFI readiness: `not_applicable`

### `sar-sparse`

- Purpose: reserved for future sparse-file support
- Status: placeholder
- Public API: `NotImplemented`
- FFI readiness: `not_applicable`

### `sar-loss-tolerant`

- Purpose: reserved for future loss-tolerant modes
- Status: placeholder
- Public API: `NotImplemented`
- FFI readiness: `not_applicable`

### `sar-stream`

- Purpose: in-memory Stateful Streaming Mode session semantics layered over `sar-core`
- Status: implemented for Milestone 10b session semantics only
- Public APIs:
  - `SessionManager`, `SessionManagerConfig`
  - `SessionEntry`, `ProcessResult`
  - `SessionEvent`, `SessionAction`
  - `ActiveSession`, `SessionMetadataState`
  - `FilesystemAction`, `FilesystemEntryAction`, `FilesystemDeleteAction`, `FilesystemRenameAction`, `FilesystemSyncBarrierAction`
  - `SessionInitFrame`, `SessionResumeFrame`, `SessionStatusFrame`, `SessionAckFrame`, `SessionMetadataFrame`, `SessionCapabilitiesFrame`
  - `SessionFlags`, `CapabilityFlags`, `AckFlags`, `SessionOpCode`, `FilesystemOpCode`
- FFI readiness: `candidate`
- Notes:
  - strictly in-memory only; no transport abstraction or network I/O
  - requires `NO_INDEX` + non-zero `Stream ID` + valid `SESSION_INIT` before stateful activation
  - sequence continuity is enforced for all accepted entries, including heartbeats and control frames
  - `CapabilityFlags` now includes `CAP_TLS_EXPORTER_AEAD` (bit 6, spec-defined); this bit passes `validate()`, is not advertised by TCP bindings, and advertises support only rather than selecting TLS_EXPORTER SAR-AEAD

### `sar-transport`

- Purpose: transport abstraction and deterministic in-memory transport harness layered over `sar-stream`; SAR-over-TCP binding (M10d); SAR-over-QUIC binding (M10e, `quic` feature)
- Status: implemented for Milestone 10c policy/harness scope + Milestone 10d TCP binding + Milestone 10e QUIC binding + Milestone 10i TLS_EXPORTER post-binding enforcement
- Public APIs:
  - `TransportBindingKind`, `TransportConfig`, `TransportStreamId`, `TransportStreamState`, `TransportAction`
  - `SarTransportBinding`
  - `InMemoryTransport`, `InMemoryTransport::with_key_provider` *(M10i)*
  - `TcpPolicy`, `QuicPolicy`
  - `TransportHarness`
  - `tcp::TcpTransportConfig` *(M10d, experimental)*
  - `tcp::TcpSarConnection<S>` *(M10d, experimental)*
  - `tcp::STREAM_ID` *(M10d, experimental)*
  - `quic::QuicTransportConfig` *(M10e, experimental, `quic` feature)*
  - `quic::QuicServerConfig` *(M10e, experimental, `quic` feature)*
  - `quic::QuicClientConfig` *(M10e, experimental, `quic` feature)*
  - `quic::QuicServerIdentity` *(M10e, experimental, `quic` feature)*
  - `quic::QuicClientTrust` *(M10e, experimental, `quic` feature)*
  - `quic::QuicSarListener` *(M10e, experimental, `quic` feature)*
  - `quic::QuicSarConnection` *(M10e, experimental, `quic` feature)*
  - `quic::QuicSarStream` *(M10e, experimental, `quic` feature)*
  - `quic::connect_quic` *(M10e, experimental, `quic` feature)*
- FFI readiness: `not_applicable` for generic/network types; `candidate` for policy/harness types
- Notes:
  - M10d TCP binding: `TcpSarConnection<S>` wraps any `Read + Write` stream and drives the M10c TCP policy
  - M10d TCP binding is **plaintext SAR-over-TCP only**; TCP+TLS is not implemented; STARTTLS is not implemented
  - TCP binding uses `std::net` (blocking, no async runtime, no TLS, no QUIC)
  - TCP streams do not permit byte-interleaved SAR sessions; sequential sessions allowed after `SESSION_CLOSE`
  - invalid unskippable stream bytes close the connection (`CloseConnection` action)
  - TCP clients that send TLS handshake bytes or any non-SAR bytes before a valid SAR Global Header are rejected/closed
  - `SESSION_STATUS`/`SESSION_ACK` serialization to outbound bytes requires bidirectional control to be enabled
  - heartbeat/watchdog is explicit-time with `now_ms` parameter; no background timer
  - TLS is not implemented for TCP; for untrusted networks, SAR AEAD and/or external transport security (e.g. WireGuard, IPsec) is required
  - KMS Mode `0x04 TLS_EXPORTER` is defined by the spec but is **not** supported over plaintext TCP; the connection is rejected with `SAR_ERR_UNSUPPORTED` if a peer uses this mode
  - TCP must not and does not advertise `CAP_TLS_EXPORTER_AEAD` in its local capability set
  - **M10e QUIC binding** (`quic` feature): `QuicSarListener` accepts multiple concurrent QUIC connections; `QuicSarConnection` multiplexes multiple SAR sessions over one QUIC connection; `QuicSarStream` drives the M10c QUIC-policy harness over a single QUIC bidirectional stream
  - `QuicServerIdentity` requires explicit DER certificate chain + DER private key; no implicit or self-signed fallback in production
  - `QuicClientTrust::CustomCaDer` supports custom CA certificate trust; `QuicClientTrust::InsecureSkipVerifyForTestsOnly` is intended only for tests and local diagnostics, never the default, and not for trusted production deployments
  - QUIC/TLS protects transport bytes; SAR AEAD is additionally available at the SAR layer
  - QUIC transport-only mode is supported; `CAP_TLS_EXPORTER_AEAD` is advertised only when `QuicTransportConfig::advertise_tls_exporter_aead` is `true`; advertising this flag does not force or select TLS_EXPORTER AEAD
  - same numeric SAR Stream ID may be active on different QUIC connections as independent sessions; duplicate active IDs on the same QUIC connection fail closed with `SAR_ERR_STREAM_STATE`
  - additional QUIC control streams are limited to LFH-direct `SESSION_CONTROL` traffic; they do not establish new SAR sessions; they are associated only by QUIC connection + LFH `Stream ID`; `SESSION_INIT` and filesystem entries on these streams are rejected by default
  - same bidirectional QUIC stream supports reverse `SESSION_ACK` / `SESSION_STATUS`; additional QUIC control streams also support baseline reverse-direction `SESSION_ACK`, `SESSION_STATUS`, and `SESSION_CAPABILITIES` when bidirectional control is active
  - `connect_quic(server_name, addr, config)` is the async client entry point
  - QUIC networking uses `quinn 0.11` + `rustls 0.23`/ring + `tokio 1`; these deps are isolated to `sar-transport` behind the `quic` feature
  - TCP/in-memory behavior is unchanged when the `quic` feature is disabled
  - Additional QUIC control streams do not use `CTL!`, UUID preheaders, private envelopes, or extra association metadata
  - **M10i TLS_EXPORTER post-binding enforcement**: after `SESSION_INIT` activates a KMS Mode `0x04 TLS_EXPORTER` session, every subsequent SAR entry on the primary stream and on all attached additional QUIC control streams MUST carry `EntryMode::ENCRYPTED`; unencrypted entries are rejected with `SAR_ERR_AUTH_FAILED`; `LOSS_TOLERANT` does not suppress this enforcement
  - `InMemoryTransport::with_key_provider(Arc<dyn KeyProvider>)` injects a CEK provider for inline `StreamArchiveParser` AEAD decryption; used in production to supply TLS-exporter-derived key material and in tests to inject a fixed-key mock
  - `TlsPqPolicy`: `ClassicalAllowed` (default with ring), `PreferPq`, `RequirePqOrHybrid`, `RequirePqOnly`.  PQ/hybrid policy affects TLS negotiation and fail-closed behavior before exporter use; it does not alter SAR wire encoding
  - No TLS exporter output, derived SAR AEAD keys, private keys, or TLS secrets are logged or placed in KMS data.

## Foreign-Language Interface Readiness

No foreign-language interfaces are implemented yet.

Planned interface milestones:

Milestone 12: General developer interfaces

- 12a: Stable C ABI.
- 12b: Python module.

Milestone 13: Mobile platform interfaces

- 13a: Swift package, iOS-compatible.
- 13b: Kotlin/Java package, Android-compatible.

C++ support:

- C++ consumers are expected to use the stable C ABI directly.
- A dedicated C++ wrapper is not a baseline requirement.

Candidate high-level operations:

- create archive
- extract archive
- list archive
- inspect archive
- verify archive
- compression configuration
- encryption/KMS configuration
- FEC verification/repair
- error/status mapping
- streaming archive read/write APIs
- SAR-over-QUIC transport for streaming and remote archive access

### C ABI readiness

- The future C ABI should be representable with opaque handles such as archive-reader, archive-writer, verification-report, and streaming-session handles rather than exposing Rust generic types directly.
- Ownership and lifetime rules are not documented strongly enough yet for a stable ABI; Milestone 12a should define handle lifetime, entry/result lifetime, and whether buffers remain valid until the next call, until explicit free, or until handle teardown.
- High-level operations are good candidates for explicit create/free style entry points, including reader/writer open-close, result-free, and SAR-owned string/buffer release helpers.
- Buffer strategy is still an open design choice: some operations fit caller-provided buffers, while inspect/list/error text may need SAR-owned allocations with explicit free functions.
- `SarStatus` already provides a strong foundation for stable error/status return codes, but the exported code set and error-to-string contract are not frozen yet.
- Version negotiation is still required for any future stable ABI, including ABI version constants, feature discovery, and reject-on-mismatch behavior.
- Thread-safety expectations are not yet defined clearly enough for foreign callers; Milestone 12a should document whether handles are thread-confined, thread-safe, or safe only under external synchronization.
- KMS and key-provider callbacks need a callback-safe C ABI contract covering invocation context, reentrancy, cancellation, error propagation, and how secret inputs/outputs are passed.
- Secret handling across FFI needs explicit zeroization and allocator-boundary rules so keys, passwords, and decrypted material do not leak across create/free or callback boundaries.
- Rust APIs that are unsuitable for direct C ABI exposure include `ArchiveReader<R>`, `ArchiveWriter<W>`, `Box<dyn KeyProvider>`, `EncoderTransform`, `DecoderTransform`, `FecCodec`, terminal-prompt behavior, environment-variable password fallback, and other generic-, trait-, or lifetime-heavy surfaces.

### Python readiness

- The archive lifecycle and summary operations can plausibly be represented as high-level Python functions and reader/writer classes.
- Python should not be committed yet to either a C-ABI wrapper or a direct PyO3/maturin module; the C ABI offers broader reuse, while direct Rust bindings may reach a usable Python surface earlier.
- Path-like object handling looks practical because high-level archive APIs are path-oriented, but future bindings still need clear normalization rules for `str`, `bytes`, and `os.PathLike`.
- Bytes and buffer ownership are not settled yet; future bindings should prefer copies into Python `bytes`/buffer objects unless an explicit borrowed-buffer contract is proven safe.
- `SarStatus` and related errors look mappable into Python exceptions, but the public exception hierarchy is still an open design choice.
- Archive readers and writers are good candidates for context-manager support once close/finalize semantics are frozen.
- Long-running operations such as create, extract, verify, FEC work, and future transport/streaming flows should likely release the GIL while native work is in progress.
- Password and KMS callback support is not binding-ready yet because callback threading, blocking behavior, and exception/error translation must be designed first.
- Secret material may end up in Python-managed memory if passwords, keys, or decrypted bytes are exposed as ordinary Python objects; that risk needs explicit documentation and minimization.
- Wheel and packaging work is intentionally deferred, but future milestones will need platform wheel decisions, bundled native library policy, and build backend choices.
- First Python exposures should focus on create, extract, list, inspect, verify, compression/encryption/FEC option objects, and status/error mapping before lower-level transform internals.

### Swift/iOS readiness

- Swift can likely consume a future stable interface through an imported C header, but that depends on Milestone 12a first defining a clean C ABI.
- Opaque handles are a suitable model for Swift ownership wrappers as long as create/free and invalidation rules are explicit.
- `SarStatus`-style results appear capable of mapping cleanly into Swift `Error`, but the conversion contract and human-readable error text policy are not yet fixed.
- Any SAR-owned strings or buffers exposed to Swift must have explicit free functions and allocator-boundary rules.
- File-path-oriented APIs should prefer UTF-8 C strings at the ABI boundary, with Swift wrappers handling `String` and `URL` conversion above that layer.
- Future streaming APIs will probably require callback-oriented or pull/push handle designs rather than direct translation of Rust traits.
- KMS and password callbacks are not ready yet; Swift interoperability will need clear rules for callback lifetime, escaping closures, threading, and cancellation.
- Secret material may cross into Swift-managed memory if passwords, keys, or plaintext are surfaced as Swift `String`, `Data`, or closure-captured values; that should be minimized and documented.
- Long-running operations should likely support cancellation hooks that Swift can integrate with task or operation cancellation.
- Thread-safety guarantees are still too informal for Swift consumers and need to be made explicit before mobile bindings.
- Future packaging will need XCFramework and Swift Package decisions after the native ABI surface is stable.
- Intended Apple targets are likely iOS device, iOS simulator, macOS, Mac Catalyst, and possibly visionOS, but target support should remain a later Milestone 13 decision.

### Kotlin/Java/Android readiness

- A Kotlin/Java interface could be built either through JNI over the stable C ABI or through a dedicated native Android wrapper, but that decision should wait until the C ABI is settled.
- Opaque handles are a plausible representation for long-lived native resources if Java/Kotlin ownership, finalization, and explicit close semantics are defined carefully.
- `SarStatus` values can likely map into Java/Kotlin exceptions, but the exception taxonomy and checked-vs-unchecked policy are still open.
- Byte arrays, direct buffers, and file paths all look representable, but the binding must define when data is copied, when direct buffers are allowed, and how path encoding is normalized on Android and JVM hosts.
- Long-running operations such as create, extract, verify, FEC, and future transport flows likely need cancellation and progress callbacks.
- KMS and password callbacks are not ready for Kotlin/Java yet because JNI callback safety, thread attachment, exception propagation, and blocking behavior are unresolved.
- Secret material may cross into JVM-managed memory if passwords, keys, or plaintext are carried in `String`, `byte[]`, or buffer objects; that risk should be minimized and documented explicitly.
- Likely Android ABI targets include `arm64-v8a`, `armeabi-v7a`, and `x86_64`, but final support policy is a Milestone 13 packaging decision.
- Future packaging will need AAR distribution decisions, native library loading policy, and JVM/Android compatibility guidance.

### Open design questions

- Should Milestone 12 prefer a small C ABI first and have Python, Swift, Kotlin/Java, and C++ build on top of it wherever practical?
- Which high-level operations should be considered baseline-stable first: create/extract/list/inspect/verify only, or also streaming, FEC repair, and SAR-over-QUIC?
- Which result types should be handle-based versus copied into caller-provided buffers?
- How should callback-based KMS and password resolution propagate errors, cancellation, and secret zeroization requirements across language boundaries?
- What thread-safety and cancellation guarantees are required before mobile-facing bindings are credible?

---

## M9a APIs — Content-Defined Chunking (CDC)

### Overview

Milestone 9a adds CDC metadata parsing, CDC metadata writing, CDC validation, the required FASTCDC algorithm, resource limits, and CLI support for `inspect --json` (reports `cdc_support`, `cdc_metadata_tlvs`, and per-entry `cdc_algo_id`) and `verify --cdc` (performs structural CDC validation when active).

Delta encoding (VCDIFF, BSDIFF, patch application, base archive resolution) is **not** implemented in M9a.

---

## M9b APIs — Delta Metadata, Patch Algorithm Registry, BSDIFF, and VCDIFF

Milestone 9b adds:

- `PatchAlgoId` enum in `sar-delta` (and re-exported from `sar-core`): `StorePatch`, `Vcdiff`, `Bsdiff`, `ZstdPatch`, `Custom(u8)`
- `validate_patch_algo_id(u8) -> Result<PatchAlgoId, PatchError>`: validates a raw algorithm byte against the SAR patch algorithm registry; returns `SarError::ReservedValue` for `0x04–0xEF`, `SarError::Unsupported` for `0xF0–0xFF`, and the `PatchAlgoId` for all assigned IDs
- `EntryMetadata.patch_algo_id: Option<u8>` — present when `HAS_DELTA` is set; raw byte preserved; validated against registry during `next_entry()`
- `EntryMetadata.delta_base_hash: Option<[u8; 32]>` — present when `HAS_DELTA` is set; treated as opaque 32 bytes; serialized as lowercase hex string in JSON output
- CLI `inspect --json`: reports `has_delta` at archive level; reports `patch_algo_id`, `delta_base_hash`, and `patch_algorithm` name per entry

**STORE_PATCH application (added in STORE_PATCH pass):**

- `apply_store_patch(patch_payload: &[u8], expected_len: u64) -> Result<Vec<u8>, PatchError>` in `sar-delta` (re-exported from `sar-core`)
- `STORE_PATCH` (`0x00`) wired into `next_entry()`: decoded patch payload becomes the complete reconstructed target; length must equal LFH `Uncompressed Size`; returns `SAR_ERR_PATCH_FAILED` on mismatch
- All-zero `Delta Base Hash` treated as "no base required" for `STORE_PATCH`; nonzero hash preserved verbatim; base lookup not performed for any algorithm
- `ResourceLimits` enforced before allocation; `SAR_ERR_LIMIT_EXCEEDED` returned if `Uncompressed Size` exceeds `max_decoded_entry_size`
- `LOSS_TOLERANT` does not suppress `SAR_ERR_PATCH_FAILED`

**BSDIFF and VCDIFF application (added in M9b Delta pass):**

- `apply_bsdiff(base: &[u8], patch: &[u8], expected_target_size: u64, limits: &BsdiffLimits) -> Result<Vec<u8>, PatchError>` — SAR BSDIFF v1 (`SARBSD01`) patcher; explicit base required
- `apply_vcdiff(base: &[u8], patch: &[u8], expected_target_size: u64, limits: &VcdiffLimits) -> Result<Vec<u8>, PatchError>` — RFC 3284 VCDIFF patcher; explicit base required
- `bsdiff::BsdiffLimits` / `vcdiff::VcdiffLimits` — per-algorithm resource limits (re-exported from `sar-core`)
- `ArchiveReaderOptions.delta_base: Option<Vec<u8>>` — caller supplies base bytes; no automatic discovery
- `BSDIFF` (`0x02`) and `VCDIFF` (`0x01`) wired into `next_entry()`: all-zero `Delta Base Hash` → `SAR_ERR_BASE_MISSING`; missing `delta_base` → `SAR_ERR_BASE_MISSING`
- New `ResourceLimits` fields: `max_bsdiff_control_bytes`, `max_bsdiff_diff_bytes`, `max_bsdiff_extra_bytes`, `max_bsdiff_control_triples`, `max_vcdiff_window_count`, `max_vcdiff_instruction_count`, `max_vcdiff_output_size`

**Not implemented (M9b):**

- `ZSTD_PATCH` application — dictionary/protocol not specified by spec (`SAR_ERR_UNSUPPORTED` returned)
- Custom patch algorithms — not negotiated
- Delta Base Hash verification — hash algorithm not specified by spec; field treated as opaque bytes
- Automatic base object resolution — location model not specified by spec; caller supplies base explicitly
- Per-entry `IS_DELTA` opt-out bit — not defined in spec

### `sar-cdc` crate

A standalone `sar-cdc` crate provides the CDC algorithm and data model, independent of archive I/O.

#### CDC algorithm IDs

| Constant           | Value  | Description                    | Status         |
|--------------------|--------|--------------------------------|----------------|
| `CDC_ALGO_LITERAL` | `0x00` | Literal mode (no chunking)     | Supported       |
| `CDC_ALGO_RABIN`   | `0x01` | Rabin fingerprinting           | Not implemented |
| `CDC_ALGO_FASTCDC` | `0x02` | FastCDC (required baseline)    | Supported       |
| `CDC_ALGO_BUZHASH` | `0x03` | BuzHash                        | Not implemented |
| `0x04–0xEF`        | —      | Reserved                       | Rejected        |
| `0xF0–0xFF`        | —      | Custom/vendor                  | Rejected        |

Unsupported algorithm IDs (0x01, 0x03) return `SarError::Unsupported`. Reserved IDs (0x04–0xEF) return `SarError::ReservedValue`. Custom IDs (0xF0–0xFF) return `SarError::Unsupported`.

#### CDC_MAP v1 hash algorithm registry

`Hash_Algorithm_ID` in the CDC_MAP header uses the SAR hash algorithm registry.
Do not confuse this with the LFH `CDC Algo ID` (chunking algorithm).
FASTCDC controls chunk *boundaries*; `Hash_Algorithm_ID` controls how chunk *hashes* are computed.

| ID   | Name     | Status for CDC_MAP                              |
|------|----------|-------------------------------------------------|
| 0x30 | SHA-256  | supported                                       |
| 0x31 | BLAKE3   | **required** (must be supported for M9a)        |
| 0x32 | SHA3-256 | assigned, unsupported → `SAR_ERR_UNSUPPORTED`   |
| other| —        | reserved → `SAR_ERR_RESERVED_VALUE`             |

#### Public types

```rust
pub struct CdcChunk {
    pub offset: u64,
    pub length: u64,
    pub hash: Option<[u8; 32]>,
}

pub struct CdcMetadata {
    pub algorithm_id: u8,
    pub min_size: u32,
    pub avg_size: u32,
    pub max_size: u32,
    pub chunks: Vec<CdcChunk>,
}

/// CDC_MAP v1 header (16 bytes on the wire).
pub struct CdcMapHeader {
    pub map_version: u8,         // MUST be 0x01
    pub hash_algorithm_id: u8,   // SAR hash registry ID
    pub flags: u16,              // MUST be 0 for v1
    pub record_count: u32,
    pub record_size: u16,        // MUST be 48 for v1
    pub reserved: [u8; 6],      // MUST be 0
}

/// CDC_MAP v1 record (48 bytes on the wire).
pub struct CdcMapRecord {
    pub hash: [u8; 32],          // 32 bytes — hash using Hash_Algorithm_ID
    pub partition_id: u32,        // 4 bytes LE
    pub absolute_offset: u64,     // 8 bytes LE — from archive start
    pub compressed_size: u32,     // 4 bytes LE — stored payload size
}

/// Parsed CDC_MAP catalog.
pub struct CdcMap {
    pub hash_algorithm_id: u8,   // from the v1 header
    pub records: Vec<CdcMapRecord>,
}

pub const CDC_MAP_HEADER_SIZE: usize = 16;
pub const CDC_MAP_RECORD_LEN: usize = 48;   // 32 + 4 + 8 + 4
pub const CDC_MAP_V1_RECORD_SIZE: u16 = 48;
pub const CDC_MAP_VERSION_V1: u8 = 0x01;
```

#### FASTCDC algorithm

`sar-cdc` implements FASTCDC via `sar_cdc::fastcdc::chunk_data(data: &[u8], opts: &FastCdcOptions) -> Vec<CdcChunk>`.

Default parameters:
- `min_size = 2048` (2 KiB)
- `avg_size = 8192` (8 KiB)
- `max_size = 65536` (64 KiB)

**Note:** The spec does not define or encode the required FastCDC parameters. The above defaults are conservative and may not produce interoperable chunk boundaries with other implementations. Treat the current FASTCDC implementation as implementation-defined/local-profile behavior rather than a portable standard-profile interoperability guarantee. Different writers may therefore produce different valid CDC maps for the same logical file. See `docs/SPEC_QUESTIONS.md` for details.

Properties:
- Deterministic: identical input always produces identical chunk boundaries.
- No zero-length chunks.
- Final chunk may be smaller than `min_size` only at EOF.
- Chunks include hash (computed over the chunk's logical bytes; not tied to CDC_MAP `Hash_Algorithm_ID`).
- Two-level masking: phase 1 from `min_size` to `avg_size` uses `mask_s`; phase 2 from `avg_size` to `max_size` uses `mask_l`.
- Gear table: 256 entries, `xorshift64*` PRNG seeded at `0x9e3779b97f4a7c15`.

#### CDC validation functions

```rust
// Validates a cdc_algo_id byte; returns Err for reserved or unsupported IDs.
pub fn validate_cdc_algo_id(id: u8) -> Result<(), CdcError>

// Validates a Hash_Algorithm_ID for CDC_MAP headers.
pub fn validate_cdc_map_hash_algo_id(id: u8) -> Result<(), CdcError>

// Structural validation of raw CDC_MAP v1 TLV bytes (wraps parse_cdc_map).
pub fn validate_cdc_map_bytes(bytes: &[u8], max_records: usize) -> Result<(), CdcError>

// Validates a CdcMetadata struct (no zero-length chunks, no gaps, etc.).
pub fn validate_cdc_metadata(meta: &CdcMetadata, file_size: u64, ...) -> Result<(), CdcError>
```

#### CDC_MAP parse/write/verify

```rust
// Parse stored CDC_MAP v1 TLV binary payload (header + records) into CdcMap.
// Does not regenerate FASTCDC boundaries; operates on stored records only.
pub fn parse_cdc_map(bytes: &[u8], max_records: usize) -> Result<CdcMap, CdcError>

// Serialize CdcMap into CDC_MAP v1 TLV binary payload (header + records).
pub fn write_cdc_map(map: &CdcMap) -> Result<Vec<u8>, CdcError>

// Verify the stored hash of one CdcMapRecord against archive bytes.
// Uses hash_algorithm_id (from the CDC_MAP header), not the CDC chunking algorithm.
// Verification is over [absolute_offset, absolute_offset + compressed_size).
pub fn verify_cdc_map_record_hash(
    record: &CdcMapRecord,
    hash_algorithm_id: u8,
    archive_bytes: &[u8],
) -> Result<bool, CdcError>
```

For M9a, stored CDC metadata is authoritative for parsing and interpretation. Readers validate the stored `CDC_MAP` / catalog bytes directly and do **not** need to regenerate FASTCDC boundaries merely to parse or use the map.

CDC_MAP hash verification is over the exact stored byte range `[Absolute_Offset, Absolute_Offset + Compressed_Size)`. This is **not** FASTCDC boundary-regeneration verification.

External provider resolution and recipe reconstruction remain unsupported in M9a.

### `sar-core` CDC bridge module

`sar_core::cdc` re-exports CDC algorithm constants and provides bridge functions.

#### Public functions in `sar_core::cdc`

```rust
// Validates CDC algorithm ID; converts CdcError to SarError.
pub fn validate_cdc_algo_id(id: u8) -> Result<(), SarError>

// Parses an inert CDC_EXT_PROVIDER (0x41) URI TLV.
pub fn parse_cdc_ext_provider_tlv(tlv: &Tlv, limits: &ResourceLimits) -> Result<CdcExtProviderMetadata, SarError>

// Validates one CDC metadata TLV using the updated registry.
pub fn validate_cdc_metadata_tlv(tlv: &Tlv, limits: &ResourceLimits) -> Result<(), SarError>

// Extracts and parses the first CDC_MAP TLV (0x40) from a TLV slice.
pub fn parse_entry_cdc_map(tlvs: &[Tlv], limits: &ResourceLimits) -> Result<Option<CdcMap>, SarError>

// Serializes a CdcMap into a Tlv with type_id = 0x40.
pub fn make_cdc_map_tlv(map: &CdcMap, limits: &ResourceLimits) -> Result<Tlv, SarError>

// Serializes CDC_EXT_PROVIDER metadata into a Tlv with type_id = 0x41.
pub fn make_cdc_ext_provider_tlv(uri: &str, limits: &ResourceLimits) -> Result<Tlv, SarError>

// Validates a Recipe payload (ordered 32-byte chunk hashes).
// Returns the number of hashes on success.
pub fn validate_recipe_payload(payload: &[u8], limits: &ResourceLimits) -> Result<usize, SarError>

// Extracts the ordered list of 32-byte chunk hashes from a Recipe payload.
pub fn recipe_hashes(payload: &[u8]) -> Vec<[u8; 32]>
```

### CDC ResourceLimits

Two fields in `ResourceLimits` bound CDC parsing:

| Field                    | Default   | Description                            |
|--------------------------|-----------|----------------------------------------|
| `max_cdc_chunk_count`    | 1,000,000 | Maximum records in a recipe or CDC_MAP |
| `max_cdc_metadata_bytes` | 52,428,800| Maximum CDC metadata bytes (50 MiB)    |

Helper methods:
- `limits.check_cdc_chunk_count(count)` — returns `SarError::LimitExceeded` when `count > max_cdc_chunk_count`.
- `limits.check_cdc_metadata_bytes(len)` — returns `SarError::LimitExceeded` when `len > max_cdc_metadata_bytes`.

### CDC in `EntryMetadata`

```rust
pub struct EntryMetadata {
    // ... existing fields ...
    /// CDC algorithm ID from LFH. None when CDC_SUPPORT global flag is not set.
    pub cdc_algo_id: Option<u8>,
}
```

### CDC in `VerificationReport`

```rust
pub struct VerificationReport {
    // ... existing fields ...
    /// True when the CDC_SUPPORT global flag is active.
    pub cdc_support: bool,
    /// Count of entries that have a cdc_algo_id.
    pub cdc_entry_count: u64,
}
```

### CDC interaction with other features

| Feature                 | Interaction                                                                       |
|-------------------------|-----------------------------------------------------------------------------------|
| Compression             | CDC metadata describes logical (decompressed) bytes. Decompression is not bypassed.|
| Encryption              | AEAD authentication is never bypassed by CDC. CDC_MAP TLVs are in Central Dictionary (not encrypted payload). |
| Sparse files            | CDC and SPARSE_FILES flags coexist. Sparse reconstruction is not affected by CDC. |
| Fragmentation           | CDC metadata is compatible with fragmented entries. Fragment reassembly precedes CDC. |
| FEC                     | CDC_MAP TLVs are parsed after FEC recovery. CDC does not bypass FEC validation.   |
| LOSS_TOLERANT           | CDC structural validation is still performed; recipe hash verification is skipped for degraded entries. |

### Updated CDC TLV registry

- `0x31` is `DATA_HASH/BLAKE3`, not CDC metadata.
- `0x40` is `CDC_MAP` (v1 header + records format; self-describing via `Hash_Algorithm_ID`).
- `0x41` is `CDC_EXT_PROVIDER` and is exposed as inert UTF-8 URI metadata only.
- `0x42–0x4E` are reserved CDC metadata TLVs and return `SarError::ReservedValue`.
- `0x4F` is `CDC_CUSTOM` and is parsed/preserved only as implementation-defined opaque metadata.

### CDC transformation domain

CDC chunk boundaries and recipe hashes are treated in this implementation as operating on logical reconstructed file bytes (after fragment reassembly, sparse reconstruction, decryption, and decompression). This is the conservative local profile used for stored metadata interpretation, but the spec does not explicitly state the domain, so portable boundary regeneration and external recipe resolution cannot yet be claimed. See `docs/SPEC_QUESTIONS.md`.

### CDC interoperability semantics

- **Parseable/interpretable CDC metadata:** readers can parse and use stored CDC metadata records directly when they are well-formed and self-consistent. `CDC_MAP` is self-describing via `Hash_Algorithm_ID`.
- **Structural CDC verification:** checks possible from stored records only, such as metadata parsing, bounds/resource-limit checks, reserved/unsupported ID handling, and internal consistency.
- **CDC_MAP hash verification:** verifying that stored chunk hashes match the bytes at `[Absolute_Offset, Absolute_Offset + Compressed_Size)`. Supported for BLAKE3 (0x31) and SHA-256 (0x30) when archive bytes are available. This is **not** FASTCDC boundary-regeneration verification.
- **Boundary-regeneration CDC verification:** re-running a CDC algorithm and proving the stored boundaries/hashes match. M9a does **not** claim this portably because the required FASTCDC parameters and transformation domain are not fully normative or encoded.
- **Cross-writer deterministic CDC chunking:** multiple implementations independently producing the same boundaries for the same logical file. M9a does **not** require this for `CDC_MAP` parsing.
- **External CAS recipe resolution:** reconstructing recipe-mode content from an external provider. M9a does **not** implement or claim this portably.

### CDC CLI behavior

- `inspect <archive.sar> --json` — includes `cdc_support` (bool), `cdc_metadata_tlvs` (array), and legacy `cdc_map_tlvs` (array) at archive level; each entry includes `cdc_algo_id` (u8) when CDC_SUPPORT is active.
- `verify <archive.sar> --cdc` — reports `cdc_support` and `cdc_entries` count; validates CDC algorithm IDs and CDC metadata TLVs structurally when active.
- `verify <archive.sar> --cdc` does **not** claim it regenerated and verified FASTCDC boundaries. Until parameters and transformation domain are normative or encoded, verification is limited to checks possible from stored records.
- `verify <archive.sar> --cdc` reports recipe-hash / external-provider verification as unavailable, not passed.
- Reserved or unsupported CDC algorithm IDs produce clear error output.
- Resource-limit failures produce `SarError::LimitExceeded` with a descriptive message.

### ArchiveWriter CDC behavior

- `ArchiveWriter::new_with_cd_metadata(...)` auto-enables `OPT_PRESENT` and `CDC_SUPPORT` when CDC metadata TLVs are supplied for an indexed archive.
- When `CDC_SUPPORT` is active in `ArchiveWriter`, normal entry-writing APIs emit LFH `cdc_algo_id = 0x00` (`LITERAL_MODE`) so archives are internally consistent.
- `ArchiveWriter` does **not** implement recipe-mode archive writing or external-provider resolution in M9a.

### Not implemented in M9a

- Delta encoding (VCDIFF, BSDIFF, patch application, base archive resolution)
- Rabin fingerprinting (0x01) and BuzHash (0x03) CDC algorithms
- Custom CDC algorithm IDs (0xF0–0xFF)
- External provider resolution for `CDC_EXT_PROVIDER` (`0x41`)
- Portable boundary-regeneration verification across writers
- Streaming CDC chunking APIs
- `sar create --cdc fastcdc` CLI flag for creating CDC-annotated archives

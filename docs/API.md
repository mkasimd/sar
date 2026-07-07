# API Inventory (post–Milestone 8 source audit)

This document is derived from the current Rust workspace source. `specification.md` is used only for terminology and conformance context.

Current scope:

- Milestones 1–3: archive format, parser/writer, indexed and `NO_INDEX` archive flows
- Milestone 4: compression registry and transform pipeline foundation
- Milestone 5: crypto, KMS parsing, password-based CEK resolution, hashes, AEAD integration
- Milestones 6–7: Selective FEC metadata, XOR FEC, Reed-Solomon FEC, CLI FEC create/inspect/verify/extract flows
- Milestone 8: sparse file map parsing/reconstruction, fragment reassembly, loss-tolerant semantics, archive-level Data Recovery TLV inspection/planning/repair, CLI repair/verify-recovery/allow-lossy
- Milestone 12: future FFI / C ABI only; not implemented yet

Feature flags: no workspace crate in the current tree defines Cargo feature flags.

## Workspace summary

| Crate | Purpose | Status |
| --- | --- | --- |
| `sar-core` | Archive format, reader/writer, validation, transform integration | implemented with partial roadmap surface |
| `sar-compression` | Compression registry and bounded encode/decode helpers | implemented |
| `sar-crypto` | Hashing, AEAD, KMS types/parsing, key-provider abstraction | implemented with some planned algorithms |
| `sar-fec` | XOR and Reed-Solomon FEC codecs and metadata parsing | implemented |
| `sar-cli` | Human-facing CLI over `sar-core` | implemented with some command-surface gaps |
| `sar-cdc` | Future CDC support placeholder | placeholder |
| `sar-delta` | Future delta support placeholder | placeholder |
| `sar-fragmentation` | Future fragmentation support placeholder | placeholder |
| `sar-partition` | Future partition support placeholder | placeholder |
| `sar-sparse` | Future sparse-file support placeholder | placeholder |
| `sar-loss-tolerant` | Future loss-tolerant mode placeholder | placeholder |
| `sar-stream` | Future streaming API placeholder | placeholder |
| `sar-transport` | Future transport integration placeholder | placeholder |

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
- `profile`
- `recovery`  *(new in M8)*
- `sparse`    *(new in M8)*
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
  - `new_with_compression(writer, ArchiveWriterOptions, CompressionSettings)`
  - `new_with_compression_and_key_provider(writer, ArchiveWriterOptions, CompressionSettings, Option<Box<dyn KeyProvider>>)`
  - `add_entry(EntryInput)`
  - `write_sparse_entry(name, gathered_payload, SparseWriteOptions)` *(new in M8 final pass)*
  - `finish()`

#### Important public types

- `ArchiveWriterOptions`
  - `no_index: bool`
  - `sparse: bool` *(new in M8 final pass)* — set `SPARSE_FILES` global flag; required before calling `write_sparse_entry`
  - `encryption: Option<EncryptionSettings>`
  - `fec: Option<FecSettings>`
- `SparseWriteOptions` *(new in M8 final pass)*
  - `logical_size: u64` — full apparent file size including holes; written to LFH `Uncompressed Size`
  - `extents: Vec<SparseExtent>` — ordered, non-overlapping sparse extents
- `ArchiveReaderOptions`
  - `max_decoded_entry_size: u64` (default `1 GiB`)
- `CompressionSettings`
  - `store()` helper
- `EncryptionSettings`
  - `algo_id`
  - `kms_params: KmsParams`
- `FecSettings`
  - `default_xor()`
  - `default_rs()`
- `EntryInput`, `EntryReader`, `EntryMetadata`, `EntryWritten`
- `ArchiveSummary`, `VerificationReport`, `ArchiveMetadata`

#### Format and parser APIs

- Header structs: `GlobalHeader`, `LocalFileHeader`, `CentralDictionary`, `Footer`, `KmsData`, `PartitionDescriptor`
  - `LocalFileHeader.fragment_descriptor` is typed as `Option<LfhFragmentDescriptor>` (named-field struct; replaced the former `Option<(u64, u32)>` tuple in M8 closeout)
- `LfhFragmentDescriptor { absolute_offset: u64, fragment_size: u32 }` — fragment descriptor stored inline in a `LocalFileHeader`
- Parser/writer helpers:
  - `parse_global_header`, `write_global_header`
  - `parse_lfh`, `write_lfh`, `compute_lfh_size`, `lfh_to_bytes`, `lfh_bytes_for_aad`, `fec_size_field_offset`
  - `parse_central_dictionary`, `write_central_dictionary`
  - `parse_footer`, `write_footer`
  - `global_header_flags_bytes`
- TLV helpers:
  - `Tlv`
  - `parse_tlvs`, `write_tlvs`

#### Flags, status, and validation APIs

- `GlobalFlags`
- `EntryMode`
  - `is_encrypted()`
  - `is_compressed()`
  - `is_fragment()`
  - `is_last_fragment()`
  - `is_loss_tolerant()`  *(new in M8)*
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
- `validate_recovery_tlv()`
- `validate_lfh_fec_algo_id()`
- `parse_lfh_fec_value()`

### Low-level/internal-public helpers

These items are public today, but they are better treated as integration helpers than as a stable external API commitment:

- `io::ParseCursor<'a>`
- `io::BinaryWriter`
- `profile::validate_archive_profile()` and `ComplianceProfile`
- direct transform plan structs used by `ArchiveReader` / `ArchiveWriter`

### Error behavior

- Structural failures map into `SarError` and `SarStatus` values such as `SAR_ERR_TRUNCATED`, `SAR_ERR_MALFORMED`, `SAR_ERR_INVALID_LENGTH`, `SAR_ERR_BOUNDS`, and `SAR_ERR_FLAG_CONFLICT`.
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
writer.add_entry(EntryInput { name: "hello.txt".into(), payload: b"hello".to_vec() })?;
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
- delta application
- partition reassembly logic
- streaming session APIs (Milestone 10)
- stable FFI / C ABI (Milestone 12)

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
- **Sparse reconstruction uses LFH `Uncompressed Size` as the final logical file size.** Trailing holes after the final sparse extent are filled with zero bytes up to `Uncompressed Size`. Large logical sizes are capped by `ArchiveReaderOptions::max_decoded_entry_size`.
- **CRC32 verification** (when `PER_FILE_CRC` is set and the LFH `file_crc32` field is present): CRC32 is computed over the fully reconstructed logical file bytes, **including sparse holes**. A wrong CRC returns `SarError::CrcMismatch`. Verification applies after fragment reassembly and sparse reconstruction. Content-hash verification is not implemented; see Known Limitations below.
- **Empty Areas** (entries with `Name Length == 0` and `IS_FRAGMENT == 0`) are excluded from the returned list; they do not participate in sparse reconstruction, hashing, delta, or fragmentation.

### `sar_core::sparse`

Sparse file map parsing, writing, validation, and scatter-gather reconstruction.

#### Public types

- `SparseExtent { offset: u64, length: u64 }` — one contiguous extent in the logical file

#### Public functions

- `parse_sparse_map(bytes: &[u8], is_64bit: bool) -> Result<Vec<SparseExtent>, SarError>`
  — decodes the raw sparse map from an LFH; 8 bytes per entry in 32-bit mode, 16 bytes in 64-bit mode; returns `SarError::InvalidLength` when byte count is not a multiple of entry size
- `write_sparse_map(extents: &[SparseExtent], is_64bit: bool) -> Vec<u8>`
  — serializes extents back to the wire format
- `validate_sparse_extents(extents: &[SparseExtent], logical_size: u64) -> Result<(), SarError>`
  — checks that extents are sorted, non-overlapping, and within `logical_size` bounds; returns `SarError::InvalidMap` on violation, `SarError::Overflow` on arithmetic overflow
- `apply_sparse_reconstruction(payload: &[u8], extents: &[SparseExtent], logical_size: u64) -> Result<Vec<u8>, SarError>`
  — creates a zero-filled buffer of exactly `logical_size` bytes (the LFH `Uncompressed Size`) and writes each extent slice from `payload` at its declared offset; trailing holes beyond the final extent are filled with `0x00`; returns `SarError::InvalidMap` if an extent exceeds `logical_size` or if payload has excess bytes; returns `SarError::Truncated` if payload is too short for the declared extents

**Transformation ordering:**

Sparse reconstruction occurs after all prior transformations in this order:
1. Fragment Reassembly (if `FILE_FRAGMENTATION`)
2. Decryption (if `ENCRYPTED`) — authentication failure is never suppressed
3. Decompression (if `COMPRESSED`)
4. Delta Application (if `HAS_DELTA`) — not yet implemented
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

- `validate_fragment_group(fragments: &[FragmentEntry], logical_size: u64) -> Result<(), SarError>`
  — checks bounds (each fragment fits within `logical_size`) and fragment-level overlaps
- `reconstruct_fragments(fragments: Vec<FragmentEntry>, logical_size: u64) -> Result<(Vec<u8>, bool), SarError>`
  — sorts fragments by index, fills a `logical_size` zero buffer with each fragment's payload at `descriptor.absolute_offset`
  — if a gap exists and `is_loss_tolerant` is set on any fragment, fills gap with zeros and returns `(data, true)` (degraded)
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

- `inspect_recovery_metadata(archive_bytes: &[u8]) -> Result<RecoveryMetadata, SarError>`
  — parses archive global header and CD, extracts RECOVERY TLVs (type IDs 0x10–0x1F), computes protected range `[GLOBAL_FLAGS_OFFSET, cd_offset)`
- `plan_archive_repair(archive_bytes: &[u8], erasures: ErasureInput) -> Result<RecoveryPlan, SarError>`
  — validates erasures within protected range and against FEC block boundaries
  — returns `SarError::RecoveryUnavailable` for unaligned erasures or missing TLV (see SPEC_QUESTIONS.md)
- `repair_archive(archive_bytes: &[u8], plan: &RecoveryPlan) -> Result<(Vec<u8>, RepairReport), SarError>`
  — applies XOR or Reed-Solomon erasure repair to the protected range, returns repaired archive bytes and a report
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
- KMS IDs: `KMS_PBKDF2`, `KMS_ARGON2`, `KMS_ASYMMETRIC_WRAP`
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
```

Behavior:

- creates parent directories as needed
- rejects absolute paths and `..` traversal during extraction
- loads password from `--password`, then `SAR_PASSWORD`, then an interactive prompt if the archive is encrypted
- `--allow-lossy`: permits extraction of archives containing LOSS_TOLERANT entries; prints a warning if any such entries are present; does not currently perform automatic degraded fragment reassembly

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
```

Behavior:

- verifies archive structure and indexed offsets
- validates recovery TLV structure when archive-level FEC metadata exists
- decrypts entries when needed, so encrypted verification requires a password/key provider
- `--recovery`: additionally validates fragmentation metadata consistency, sparse extent validity, Data Recovery TLV structure, and reports `repair_possible` / unavailable reason; distinguishes file-level FEC metadata from archive-level recovery TLVs

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
```

Behavior:

- `--fec` is required; prints error "repair requires --fec" if absent
- `--erasures <file>` is required; prints error "repair requires --erasures <file>" if absent
- parses erasures JSON into `ErasureInput`
- calls `inspect_recovery_metadata` to check archive EC support
- calls `plan_archive_repair`; if `RecoveryUnavailable`, prints message and does **not** create output file
- calls `repair_archive` on success
- writes repaired bytes to a temp file (`<output>.sar.tmp`) first
- verifies temp file structure (parses, checks structure)
- renames temp to final output only if verification passes
- if any step fails, deletes temp file and does **not** create the final output file

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

- Purpose: reserved for future delta support
- Status: placeholder
- Public API: `NotImplemented`
- FFI readiness: `not_applicable`

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

- Purpose: reserved for future streaming APIs
- Status: placeholder
- Public API: `NotImplemented`
- FFI readiness: `not_applicable`

### `sar-transport`

- Purpose: reserved for future transport integration
- Status: placeholder
- Public API: `NotImplemented`
- FFI readiness: `not_applicable`

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

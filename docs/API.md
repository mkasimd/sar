# SAR Rust API — M11a

> **Milestone**: M11a — LFH Metadata API Completeness  
> **Status**: API-surface and metadata-preservation focused.  
> **Non-goals for M11a**: CLI metadata flags, filesystem restoration, symlink/UID/GID/permission/timestamp restoration, C ABI, Python bindings, new CDC/FEC/delta wire semantics.

---

## Crates

| Crate | Role |
|---|---|
| `sar-core` | Core library: archive reading, writing, all public types |
| `sar-cli` | Minimal CLI: `list` and `info` subcommands (no metadata flags in M11a) |

---

## SAR Wire Format

All integers are **little-endian**.

### Archive Header (13 bytes)

```
4 bytes  magic        = b"SAR1"
1 byte   version      = 1
4 bytes  global_flags (u32 LE)
4 bytes  entry_count  (u32 LE)
```

### LFH (Local File Header) — per entry

Fields are conditionally present in every LFH based on **GlobalFlags** (archive-wide):

```
2 bytes         name_len           (u16 LE)
name_len bytes  name               (UTF-8)

[if PATH ∈ GlobalFlags]
  2 bytes         path_len         (u16 LE)
  path_len bytes  path             (UTF-8)

4 bytes   entry_mode               (u32 LE)
8 bytes   payload_size             (u64 LE) — uncompressed size

[if STREAM_ID ∈ GlobalFlags]   8 bytes stream_id          (u64 LE)
[if SEQ_NO ∈ GlobalFlags]      8 bytes sequence_no         (u64 LE)
[if PERMISSIONS ∈ GlobalFlags] 4 bytes permissions         (u32 LE, Unix mode)
[if OWNER ∈ GlobalFlags]       4+4 bytes uid, gid          (u32 LE each)
[if TIMESTAMPS ∈ GlobalFlags]  each timestamp = i64 secs + u32 nsecs (LE)
                               order: mtime, atime, ctime (20 bytes each, 60 total)
[if HIDDEN ∈ GlobalFlags]      1 byte hidden_value         (0=not hidden, 1=hidden)
[if COMPRESSION ∈ GlobalFlags] 1 byte algorithm + 8 bytes compressed_size (u64 LE)
[if ENCRYPTION ∈ GlobalFlags]  1 byte algorithm + 8 bytes key_id          (u64 LE)
[if CDC ∈ GlobalFlags]         1 byte algorithm + 4+4+4 bytes min/avg/max_chunk (u32 LE each)
[if FEC ∈ GlobalFlags]         1 byte algorithm + 4 bytes block_size + 1+1 data/parity shards
[if DELTA ∈ GlobalFlags]       1 byte algorithm + 8+8 bytes base_stream_id + base_seq_no
[if FRAGMENT ∈ GlobalFlags]    4+4 bytes fragment_index/count + 8 bytes fragment_id
[if SPARSE ∈ GlobalFlags]      4 bytes hole_count (u32 LE); for each hole: 8+8 bytes offset+length
[if CRC32 ∈ GlobalFlags]       4 bytes crc32                (u32 LE)
[if HASH ∈ GlobalFlags]        1 byte algorithm + 1 byte hash_len + hash_len bytes hash

Payload:
  If COMPRESSION ∈ GlobalFlags AND COMPRESSION_ACTIVE ∈ entry_mode:
    compressed_size bytes (pre-compressed by caller; library does not compress)
  Else:
    payload_size bytes
```

### End of Archive

```
8 bytes  b"SAREND!!"
```

---

## GlobalFlags (`GlobalFlags` struct)

`GlobalFlags` is an archive-wide bitfield that controls which LFH fields are **physically present** in every entry.

| Constant | Bit | Controls |
|---|---|---|
| `GlobalFlags::PATH` | `1 << 0` | path field in LFH |
| `GlobalFlags::STREAM_ID` | `1 << 1` | stream_id field |
| `GlobalFlags::SEQ_NO` | `1 << 2` | sequence_no field |
| `GlobalFlags::PERMISSIONS` | `1 << 3` | permissions field |
| `GlobalFlags::OWNER` | `1 << 4` | uid + gid fields |
| `GlobalFlags::TIMESTAMPS` | `1 << 5` | mtime/atime/ctime fields |
| `GlobalFlags::HIDDEN` | `1 << 6` | hidden_value field |
| `GlobalFlags::COMPRESSION` | `1 << 7` | compression algorithm + compressed_size |
| `GlobalFlags::ENCRYPTION` | `1 << 8` | encryption algorithm + key_id |
| `GlobalFlags::CDC` | `1 << 9` | CDC algorithm + chunk sizes |
| `GlobalFlags::FEC` | `1 << 10` | FEC algorithm + shards |
| `GlobalFlags::DELTA` | `1 << 11` | delta algorithm + base ref |
| `GlobalFlags::FRAGMENT` | `1 << 12` | fragment index/count/id |
| `GlobalFlags::SPARSE` | `1 << 13` | sparse hole list |
| `GlobalFlags::CRC32` | `1 << 14` | CRC32 checksum |
| `GlobalFlags::HASH` | `1 << 15` | content hash |

`GlobalFlags` supports `|`, `&`, `!`, `|=`, `&=` operators.

---

## EntryMode (`EntryMode` struct)

`EntryMode` is a per-entry bitfield stored in each LFH. It controls:

1. **Entry kind** (bits 0–2):

| Constant | Value | Meaning |
|---|---|---|
| `EntryMode::KIND_FILE` | `0` | Regular file |
| `EntryMode::KIND_DIRECTORY` | `1` | Directory |
| `EntryMode::KIND_SYMLINK` | `2` | Symbolic link |
| `EntryMode::KIND_EMPTY_AREA` | `3` | Empty / reserved area |

2. **Semantic activation** (one bit per conditional field):

| Constant | Bit | Activates |
|---|---|---|
| `EntryMode::PATH_ACTIVE` | `1 << 3` | path field semantically active |
| `EntryMode::STREAM_ID_ACTIVE` | `1 << 4` | stream_id active |
| `EntryMode::SEQ_NO_ACTIVE` | `1 << 5` | sequence_no active |
| `EntryMode::PERMISSIONS_ACTIVE` | `1 << 6` | permissions active |
| `EntryMode::OWNER_ACTIVE` | `1 << 7` | owner active |
| `EntryMode::TIMESTAMPS_ACTIVE` | `1 << 8` | timestamps active |
| `EntryMode::HIDDEN_ACTIVE` | `1 << 9` | hidden flag active |
| `EntryMode::COMPRESSION_ACTIVE` | `1 << 10` | compression active |
| `EntryMode::ENCRYPTION_ACTIVE` | `1 << 11` | encryption active |
| `EntryMode::CDC_ACTIVE` | `1 << 12` | CDC active |
| `EntryMode::FEC_ACTIVE` | `1 << 13` | FEC active |
| `EntryMode::DELTA_ACTIVE` | `1 << 14` | delta active |
| `EntryMode::FRAGMENT_ACTIVE` | `1 << 15` | fragment active |
| `EntryMode::SPARSE_ACTIVE` | `1 << 16` | sparse active |
| `EntryMode::CRC32_ACTIVE` | `1 << 17` | CRC32 active |
| `EntryMode::HASH_ACTIVE` | `1 << 18` | hash active |

---

## GlobalFlags vs EntryMode Semantics

This distinction is **critical** and must be preserved by all implementations:

| Scenario | GlobalFlag | EntryMode bit | Field in wire? | `FieldPresence` value |
|---|---|---|---|---|
| Field not configured | unset | unset | **No** | `Absent` |
| Field configured, entry doesn't use it | **set** | unset | **Yes** (zeros/defaults) | `PresentInactive(T)` |
| Field configured and entry uses it | **set** | **set** | **Yes** (real value) | `PresentActive(T)` |

**Rule**: If a GlobalFlag is set, the field bytes are present in the LFH of **every** entry in the archive, even if that particular entry does not activate the field. The writer writes zero/default values and leaves the EntryMode active bit unset. The reader parses the bytes and returns `PresentInactive`.

**Do not** silently discard physically present but semantically inactive metadata.

---

## `FieldPresence<T>` — Metadata Presence Model

```rust
pub enum FieldPresence<T> {
    /// Field not physically present (GlobalFlag not set).
    Absent,
    /// Physically present, but semantically inactive for this entry.
    PresentInactive(T),
    /// Physically present and semantically active.
    PresentActive(T),
}
```

Helper methods:

| Method | Returns |
|---|---|
| `is_absent()` | `true` if `Absent` |
| `is_present()` | `true` if `PresentInactive` or `PresentActive` |
| `is_active()` | `true` if `PresentActive` |
| `value()` | `Option<&T>` — `Some` if present (either state) |
| `active_value()` | `Option<&T>` — `Some` only if `PresentActive` |
| `into_active_value()` | `Option<T>` — consumes, `Some` only if `PresentActive` |
| `map(f)` | Transforms the inner `T`, preserving presence state |

---

## `EntryKind`

```rust
pub enum EntryKind {
    RegularFile,
    Directory,
    Symlink,
    EmptyArea,
    Reserved(u32),  // unknown/unsupported kind bits
}
```

`EntryKind` is decoded from the low 3 bits of `EntryMode`.

---

## Algorithm Enums

All algorithm enums implement `From<u8>` and `Into<u8>` / `From<AlgoEnum> for u8`.

| Enum | Variants |
|---|---|
| `CompressionAlgorithm` | `None=0`, `Deflate=1`, `Zstd=2`, `Lz4=3`, `Brotli=4`, `Unknown(u8)` |
| `EncryptionAlgorithm` | `None=0`, `Aes256Gcm=1`, `ChaCha20Poly1305=2`, `Unknown(u8)` |
| `CdcAlgorithm` | `None=0`, `FastCdc=1`, `RollSum=2`, `Unknown(u8)` |
| `FecAlgorithm` | `None=0`, `ReedSolomon=1`, `Unknown(u8)` |
| `DeltaAlgorithm` | `None=0`, `Bsdiff=1`, `ZstdDelta=2`, `Unknown(u8)` |
| `HashAlgorithm` | `Sha256=0`, `Blake3=1`, `Sha512=2`, `Unknown(u8)` |

---

## `EntryInput` — Writer Input Type

`EntryInput` is used to supply an entry to `ArchiveWriter`. All metadata fields beyond `name` and `payload` are optional.

```rust
pub struct EntryInput {
    pub name: String,
    pub path: Option<String>,
    pub payload: Vec<u8>,
    pub kind: EntryKind,
    pub permissions: Option<EntryPermissionMetadata>,
    pub owner: Option<EntryOwnerMetadata>,
    pub timestamps: Option<EntryTimestampMetadata>,
    pub hidden: Option<bool>,
    pub stream_id: Option<u64>,
    pub sequence_no: Option<u64>,
    pub fragment: Option<EntryFragmentMetadata>,
    pub sparse: Option<EntrySparseMetadata>,
    pub fec: Option<EntryFecMetadata>,
    pub cdc: Option<EntryCdcMetadata>,
    pub delta: Option<EntryDeltaMetadata>,
    pub encryption: Option<EntryEncryptionMetadata>,
    pub compression: Option<EntryCompressionMetadata>,
    pub crc32: Option<u32>,
    pub content_hash: Option<EntryHashMetadata>,
}
```

### Constructors

| Constructor | Description |
|---|---|
| `EntryInput::file(name, payload)` | Regular file entry — simplest case |
| `EntryInput::directory(name)` | Directory entry with empty payload |
| `EntryInput::symlink(name, target)` | Symlink entry; `target` is the link target bytes |
| `EntryInput::empty_area(name)` | Empty-area / reserved entry |

### `required_global_flags()`

Returns the `GlobalFlags` that must be set in the writer for this entry to be fully encoded. The writer calls this automatically during `add_entry` and returns `SarError::EntryMetadataRequiresFlag` if any required flag is missing.

### Input sub-structs

| Struct | Fields |
|---|---|
| `EntryPermissionMetadata` | `mode: u32` |
| `EntryOwnerMetadata` | `uid: u32`, `gid: u32` |
| `EntryTimestampMetadata` | `mtime`, `atime`, `ctime: EntryTimestamp` |
| `EntryTimestamp` | `secs: i64`, `nsecs: u32` |
| `EntryCompressionMetadata` | `algorithm: CompressionAlgorithm`, `compressed_size: u64` |
| `EntryEncryptionMetadata` | `algorithm: EncryptionAlgorithm`, `key_id: u64` |
| `EntryCdcMetadata` | `algorithm: CdcAlgorithm`, `min/avg/max_chunk_size: u32` |
| `EntryFecMetadata` | `algorithm: FecAlgorithm`, `block_size: u32`, `data_shards: u8`, `parity_shards: u8` |
| `EntryDeltaMetadata` | `algorithm: DeltaAlgorithm`, `base_stream_id: u64`, `base_sequence_no: u64` |
| `EntryFragmentMetadata` | `fragment_index: u32`, `fragment_count: u32`, `fragment_id: u64` |
| `EntrySparseMetadata` | `holes: Vec<SparseHole>` |
| `SparseHole` | `offset: u64`, `length: u64` |
| `EntryHashMetadata` | `algorithm: HashAlgorithm`, `hash: Vec<u8>` |

---

## `EntryMetadata` — Reader Output Type

`EntryMetadata` is returned by `ArchiveReader` for each entry. All conditional fields use `FieldPresence<T>`.

```rust
pub struct EntryMetadata {
    pub name: String,
    pub path: FieldPresence<String>,
    pub kind: EntryKind,
    pub permissions: FieldPresence<EntryPermissionMetadata>,
    pub owner: FieldPresence<EntryOwnerMetadata>,
    pub timestamps: FieldPresence<EntryTimestampMetadata>,
    pub hidden: FieldPresence<bool>,
    pub stream_id: FieldPresence<u64>,
    pub sequence_no: FieldPresence<u64>,
    pub fragment: FieldPresence<EntryFragmentMetadata>,
    pub sparse: FieldPresence<EntrySparseMetadata>,
    pub fec: FieldPresence<EntryFecMetadata>,
    pub cdc: FieldPresence<EntryCdcMetadata>,
    pub delta: FieldPresence<EntryDeltaMetadata>,
    pub encryption: FieldPresence<EntryEncryptionMetadata>,
    pub compression: FieldPresence<EntryCompressionMetadata>,
    pub crc32: FieldPresence<u32>,
    pub content_hash: FieldPresence<EntryHashMetadata>,
    /// Raw EntryMode u32 from LFH (for diagnostics and round-trip verification).
    pub entry_mode_raw: u32,
    /// Uncompressed payload size in bytes.
    pub payload_size: u64,
}
```

Sub-structs in `EntryMetadata` are the same types as in `EntryInput` (see table above).

---

## `ArchiveWriter`

```rust
pub struct ArchiveWriter { /* private */ }

impl ArchiveWriter {
    /// Create a writer. `global_flags` determines which LFH fields are physically present.
    pub fn new(global_flags: GlobalFlags) -> Self;

    /// Add an entry.
    ///
    /// Returns `Err(SarError::EntryMetadataRequiresFlag)` if the entry supplies a metadata
    /// field whose corresponding GlobalFlag is not set in this writer.
    pub fn add_entry(&mut self, entry: EntryInput) -> Result<(), SarError>;

    /// Serialize and write the complete archive to `writer`.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), SarError>;

    pub fn global_flags(&self) -> GlobalFlags;
    pub fn entry_count(&self) -> u32;
}
```

### Writer behavior

- For each GlobalFlag that is set, the corresponding LFH field is written for **every** entry.
- If an entry does not supply a given metadata field, the writer writes zero/default bytes and does **not** set the corresponding EntryMode active bit.
- If an entry supplies a metadata field but the GlobalFlag is not set, `add_entry` returns `SarError::EntryMetadataRequiresFlag`. Metadata is never silently dropped.
- The writer does **not** perform actual compression, encryption, CDC, FEC, or delta encoding. Callers must pre-process the payload and supply the resulting bytes plus metadata.
- Symlink target, directory marker, and empty-area entries are representable but produce no special filesystem behavior (M11a is API-surface only).

### Writer limitations (M11a)

- No actual compression is applied; `EntryCompressionMetadata.compressed_size` must match `payload.len()` when compression is active.
- No actual encryption, CDC chunking, FEC encoding, or delta encoding is applied.
- No filesystem metadata is restored during any extraction operation (extraction is not part of M11a).

---

## `ArchiveReader`

```rust
pub struct ArchiveReader<R: Read> { /* private */ }

impl<R: Read> ArchiveReader<R> {
    /// Parse the archive header.
    pub fn new(reader: R) -> Result<Self, SarError>;

    pub fn global_flags(&self) -> GlobalFlags;
    pub fn entry_count(&self) -> u32;

    /// Read the next entry.
    ///
    /// Returns `Ok(None)` after all entries have been read (also verifies the end magic).
    pub fn next_entry(&mut self) -> Result<Option<(EntryMetadata, Vec<u8>)>, SarError>;
}

impl<R: Read> Iterator for ArchiveReader<R> {
    type Item = Result<(EntryMetadata, Vec<u8>), SarError>;
}
```

### Reader behavior

- Reads LFH fields in wire order, conditional on GlobalFlags.
- Checks the corresponding EntryMode active bit for each physically present field.
- Returns `FieldPresence::Absent` when the GlobalFlag is not set.
- Returns `FieldPresence::PresentInactive(value)` when GlobalFlag is set but the active bit is unset.
- Returns `FieldPresence::PresentActive(value)` when both GlobalFlag and active bit are set.
- The reader never silently discards metadata: path, permissions, owner, timestamps, hidden, stream_id, sequence_no, fragment, sparse, FEC, CDC, delta, encryption, compression, CRC32, and hash are all exposed.
- `entry_mode_raw` preserves the raw u32 value for diagnostics and round-trip verification.

---

## `SarError`

```rust
pub enum SarError {
    Io(std::io::Error),
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidUtf8(std::string::FromUtf8Error),
    EntryMetadataRequiresFlag { field: &'static str, required_flag: u32 },
    InvalidEntryKind(u32),
    TruncatedInput,
    InvalidEndMagic,
    NameTooLong(usize),
    PathTooLong(usize),
    HashTooLong(usize),
    SparseTooManyHoles(usize),
}
```

`SarError` implements `std::error::Error` and `std::fmt::Display`.

---

## CLI

```
sar-cli list <archive>   — print entry names
sar-cli info <archive>   — print global flags and entry count
```

No metadata flags are supported in the CLI in M11a.

---

## Non-goals for M11a

The following are explicitly out of scope for M11a:

- CLI metadata flags
- Filesystem restoration (extraction, creation)
- Symlink extraction or UID/GID/permission/timestamp restoration on disk
- Crate-boundary refactoring
- New conformance test vector suite
- C ABI or Python bindings
- New CDC, delta, or FEC wire semantics
- Split-library profile implementation

---

## Spec-gaps and conflicts

| Item | Notes |
|---|---|
| Actual compression/encryption | M11a only stores pre-computed bytes; no algorithm is applied by the library. |
| Standard compliance | Not claimed. The SAR format defined here is the authoritative specification for this implementation. |
| Entry count overflow | `entry_count` is a `u32`; archives with more than 2³² entries are not supported. |
| Symlink policy | Symlink entries are representable but no extraction policy is enforced. |

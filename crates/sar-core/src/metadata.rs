//! Expanded LFH metadata types for M11a.
//!
//! These types represent the complete set of metadata that can be stored in or
//! read from a Local File Header.  They are designed to be stable, binding-friendly
//! (future C/Python FFI), and to make the distinction between absent, present-but-
//! inactive, and present-and-active fields explicit.
//!
//! # Global Flags vs Entry Mode semantics
//!
//! Global Flags determine which LFH fields are **physically present** on the wire.
//! Entry Mode bits determine whether a physically-present field is **semantically
//! active** for a given entry.
//!
//! [`FieldPresence<T>`] captures this three-state model:
//!
//! | State | Meaning |
//! |-------|---------|
//! | `Absent` | The global flag is not set; the field is not present in the LFH. |
//! | `PresentInactive(T)` | The global flag is set (field is on the wire) but the entry-mode bit is clear (field semantically ignored). |
//! | `PresentActive(T)` | The global flag is set and the entry-mode bit is set (field semantically used). |

use serde::Serialize;

use crate::fec::FecSummary;
use crate::fragment::FragmentDescriptor;
use crate::sparse::SparseExtent;

// ---------------------------------------------------------------------------
// Field presence model
// ---------------------------------------------------------------------------

/// Three-state metadata field presence model.
///
/// Distinguishes between a field being physically absent (global flag not set),
/// physically present but semantically inactive (entry mode bit unset), and
/// physically present and semantically active.
///
/// This type is intended to be usable by future C/Python bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldPresence<T> {
    /// Field is not physically present in the LFH (global flag not set).
    Absent,
    /// Field is physically present in the LFH but semantically inactive
    /// (the corresponding entry-mode bit is unset).  The raw wire value is
    /// preserved in the inner value.
    PresentInactive(T),
    /// Field is physically present and semantically active.
    PresentActive(T),
}

impl<T> FieldPresence<T> {
    /// Returns `true` when the field is not physically present.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// Returns `true` when the field is physically present (either active or
    /// inactive).
    #[must_use]
    pub fn is_present(&self) -> bool {
        !self.is_absent()
    }

    /// Returns `true` when the field is physically present and semantically
    /// active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::PresentActive(_))
    }

    /// Returns a reference to the inner value when present (active or inactive).
    #[must_use]
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Absent => None,
            Self::PresentInactive(v) | Self::PresentActive(v) => Some(v),
        }
    }
}

// ---------------------------------------------------------------------------
// Entry kind
// ---------------------------------------------------------------------------

/// Semantic kind of an archive entry, derived from Entry Mode bits 0 and 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EntryKind {
    /// Regular file entry (IS_SYMLINK = 0, IS_DIRECTORY = 0, name non-empty).
    RegularFile,
    /// Directory entry (IS_DIRECTORY = 1).
    Directory,
    /// Symbolic link entry (IS_SYMLINK = 1).  Payload is the target path
    /// string.  No filesystem restoration is performed in M11a.
    Symlink,
    /// Empty area entry (name length == 0, IS_FRAGMENT = 0).  Used for
    /// pre-allocated padding; payload bytes are arbitrary.
    EmptyArea,
}

impl EntryKind {
    /// Derives the entry kind from Entry Mode bits and name state.
    ///
    /// Decision order (spec §6.2, §15.1, §15.3):
    /// 1. If name is empty and `IS_FRAGMENT` is not set → `EmptyArea`.
    /// 2. If `IS_DIRECTORY` is set → `Directory`.
    /// 3. If `IS_SYMLINK` is set → `Symlink`.
    /// 4. Otherwise → `RegularFile`.
    #[must_use]
    pub fn from_mode_and_name(entry_mode: crate::flags::EntryMode, name_is_empty: bool) -> Self {
        if name_is_empty && !entry_mode.is_fragment() {
            return Self::EmptyArea;
        }
        if entry_mode.is_directory() {
            return Self::Directory;
        }
        if entry_mode.is_symlink() {
            return Self::Symlink;
        }
        Self::RegularFile
    }
}

// ---------------------------------------------------------------------------
// Per-field metadata structs
// ---------------------------------------------------------------------------

/// POSIX permission metadata (16-bit mode).
///
/// Present when the `HAS_PERMS` global flag is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EntryPermissionMetadata {
    /// Raw 16-bit POSIX permission mode.
    pub mode: u16,
}

/// Owner UID/GID metadata.
///
/// Present when the `EXT_UID_GID` global flag is set.
/// The 32-bit field stores the 16-bit UID in the low half and 16-bit GID in
/// the high half (as packed by the on-wire format).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EntryOwnerMetadata {
    /// Raw packed 32-bit UID/GID field (low 16 = UID, high 16 = GID).
    pub uid_gid: u32,
}

impl EntryOwnerMetadata {
    /// Returns the 16-bit UID portion.
    #[must_use]
    pub const fn uid(self) -> u16 {
        (self.uid_gid & 0xFFFF) as u16
    }

    /// Returns the 16-bit GID portion.
    #[must_use]
    pub const fn gid(self) -> u16 {
        ((self.uid_gid >> 16) & 0xFFFF) as u16
    }
}

/// Timestamp metadata (mtime, atime, ctime as 64-bit Unix seconds).
///
/// Present when the `EXT_TIME` global flag is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EntryTimestampMetadata {
    /// Modification time (seconds since Unix epoch).
    pub mtime: u64,
    /// Last access time (seconds since Unix epoch).
    pub atime: u64,
    /// Status change time (seconds since Unix epoch).
    pub ctime: u64,
}

/// Compression algorithm metadata.
///
/// Used in [`FieldPresence`] to represent compression field presence and
/// the raw/effective algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EntryCompressionMetadata {
    /// Raw `Comp Algo ID` value from the LFH.  When `FieldPresence::PresentInactive`,
    /// this is the raw byte even though the effective algorithm is STORE (0x00).
    pub algo_id: u8,
    /// Human-readable algorithm name.
    pub algorithm_name: &'static str,
}

/// Encryption algorithm metadata.
///
/// Used in [`FieldPresence`] to represent encryption field presence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryEncryptionMetadata {
    /// Raw `Encr Algo ID` byte from the LFH.
    pub algo_id: u8,
    /// IV/nonce (24 bytes).  All-zero when entry mode IS_ENCRYPTED is not set.
    pub iv_nonce: [u8; 24],
}

/// FEC (Forward Error Correction) metadata.
///
/// Used in [`FieldPresence`] to represent FEC field presence.
/// When `FieldPresence::PresentInactive`, `algo_id == 0` and `summary` is
/// `None` (the entry carries FEC fields but has no FEC encoding).
/// When `FieldPresence::PresentActive`, `algo_id != 0` and `summary` is
/// `Some(...)`.
#[derive(Debug, Clone, Serialize)]
pub struct EntryFecMetadata {
    /// Raw `FEC Algo ID` byte from the LFH (0 = no FEC for this entry).
    pub algo_id: u8,
    /// Parsed FEC summary.  `None` when `algo_id == 0`.
    pub summary: Option<FecSummary>,
}

/// CDC (Content-Defined Chunking) metadata.
///
/// Present when the `CDC_SUPPORT` global flag is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EntryCdcMetadata {
    /// CDC algorithm ID from the LFH.
    /// `0x00` = Literal Mode (payload is literal data).
    /// Values > 0 = Recipe Mode (payload is ordered chunk hashes).
    pub algo_id: u8,
}

/// Delta/patch algorithm metadata.
///
/// Present when the `HAS_DELTA` global flag is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryDeltaMetadata {
    /// Patch algorithm ID from the LFH.
    pub patch_algo_id: u8,
    /// Delta base hash (32 bytes, opaque).  All-zero = no base required.
    #[serde(
        serialize_with = "serialize_hash_hex"
    )]
    pub base_hash: [u8; 32],
}

fn serialize_hash_hex<S>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
    s.serialize_str(&hex)
}

/// Fragment membership metadata.
///
/// Used in [`FieldPresence`] to represent fragment field presence.
/// When `FieldPresence::PresentInactive`, the global `FILE_FRAGMENTATION`
/// flag is set and the fields are on the wire, but `IS_FRAGMENT` is not set
/// for this entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryFragmentMetadata {
    /// Fragment group identifier.
    pub fragment_id: u32,
    /// Zero-based fragment sequence index.
    pub fragment_index: u32,
    /// Fragment descriptor (absolute offset + declared size).
    pub descriptor: Option<FragmentDescriptor>,
    /// `true` when the `LAST_FRAGMENT` entry mode bit is set.
    pub is_last: bool,
    /// `true` when the `LOSS_TOLERANT` entry mode bit is set.
    pub is_loss_tolerant: bool,
}

/// Sparse file metadata.
///
/// Present when the `SPARSE_FILES` global flag is set and the sparse map is
/// non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntrySparseMetadata {
    /// Parsed sparse extents describing non-hole data regions.
    pub extents: Vec<SparseExtent>,
}

/// Combined CRC32 and content-hash metadata.
///
/// Fields are independently optional depending on which global flags are set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryHashMetadata {
    /// Per-file CRC32.  `Some` when the `PER_FILE_CRC` global flag is set and
    /// the field is non-zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crc32: Option<u32>,
    /// Content hash (32 bytes).  `Some` when the `DEDUPLICATION` global flag
    /// is set.
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_hash_hex_opt"
    )]
    pub content_hash: Option<[u8; 32]>,
}

fn serialize_hash_hex_opt<S>(value: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            s.serialize_some(&hex)
        }
        None => s.serialize_none(),
    }
}

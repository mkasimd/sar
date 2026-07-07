use bitflags::bitflags;

use crate::error::SarError;

bitflags! {
    /// Global SAR flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GlobalFlags: u32 {
        /// Use 64-bit size/offset fields.
        const SIZE_64BIT = 1 << 0;
        /// Omit Central Dictionary and Footer.
        const NO_INDEX = 1 << 1;
        /// CD metadata TLV section present.
        const OPT_PRESENT = 1 << 2;
        /// Partition descriptor present.
        const PARTITIONED_ARCHIVE = 1 << 3;
        /// File fragmentation fields present in LFH.
        const FILE_FRAGMENTATION = 1 << 4;
        /// Content-defined chunking fields present.
        const CDC_SUPPORT = 1 << 5;
        /// Compression field present in LFH.
        const COMPRESSED = 1 << 8;
        /// Delta field present in LFH.
        const HAS_DELTA = 1 << 9;
        /// Encryption field present in LFH and KMS extension in global header.
        const ENCRYPTED = 1 << 10;
        /// Global CRC32 present in CD.
        const HAS_GLOBAL_CRC32 = 1 << 16;
        /// Per-file CRC32 field present in LFH.
        const PER_FILE_CRC = 1 << 17;
        /// Signature metadata present.
        const SIGNED = 1 << 18;
        /// Global EC parity metadata present.
        const HAS_GLOBAL_EC = 1 << 19;
        /// Per-entry FEC fields present in LFH.
        const SELECTIVE_FEC = 1 << 20;
        /// Path length/string fields present in LFH.
        const HAS_PATH = 1 << 24;
        /// POSIX perms present in LFH.
        const HAS_PERMS = 1 << 25;
        /// Symlink support.
        const HAS_SYMLINKS = 1 << 26;
        /// UID/GID fields present.
        const EXT_UID_GID = 1 << 27;
        /// Timestamp fields present.
        const EXT_TIME = 1 << 28;
        /// Dedup content hash field present.
        const DEDUPLICATION = 1 << 29;
        /// Sparse map fields present.
        const SPARSE_FILES = 1 << 30;
    }
}

/// Entry mode bits from LFH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryMode(pub u16);

impl EntryMode {
    /// Returns true when entry payload is encrypted.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        self.0 & (1 << 2) != 0
    }

    /// Returns true when entry payload is compressed.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// Returns true when entry is marked as fragment.
    #[must_use]
    pub const fn is_fragment(self) -> bool {
        self.0 & (1 << 5) != 0
    }

    /// Returns true when entry is marked as last fragment.
    #[must_use]
    pub const fn is_last_fragment(self) -> bool {
        self.0 & (1 << 6) != 0
    }
}

/// Validates global flag consistency.
pub fn validate_global_flags(flags: GlobalFlags) -> Result<(), SarError> {
    if flags.contains(GlobalFlags::SIGNED) && !flags.contains(GlobalFlags::OPT_PRESENT) {
        return Err(SarError::FlagConflict(
            "SIGNED requires OPT_PRESENT and DATA_HASH metadata",
        ));
    }

    if flags.contains(GlobalFlags::NO_INDEX)
        && flags.intersects(
            GlobalFlags::OPT_PRESENT
                | GlobalFlags::HAS_GLOBAL_CRC32
                | GlobalFlags::HAS_GLOBAL_EC
                | GlobalFlags::SIGNED,
        )
    {
        return Err(SarError::FlagConflict(
            "NO_INDEX conflicts with OPT_PRESENT/HAS_GLOBAL_CRC32/HAS_GLOBAL_EC/SIGNED",
        ));
    }

    Ok(())
}

/// Validates entry-mode flags against global flags.
pub fn validate_entry_mode_against_global(
    global_flags: GlobalFlags,
    entry_mode: EntryMode,
) -> Result<(), SarError> {
    if entry_mode.is_compressed() && !global_flags.contains(GlobalFlags::COMPRESSED) {
        return Err(SarError::FlagConflict(
            "IS_COMPRESSED requires global COMPRESSED",
        ));
    }

    if entry_mode.is_encrypted() && !global_flags.contains(GlobalFlags::ENCRYPTED) {
        return Err(SarError::FlagConflict(
            "IS_ENCRYPTED requires global ENCRYPTED",
        ));
    }

    if entry_mode.is_fragment() && !global_flags.contains(GlobalFlags::FILE_FRAGMENTATION) {
        return Err(SarError::FlagConflict(
            "IS_FRAGMENT requires global FILE_FRAGMENTATION",
        ));
    }

    if entry_mode.is_last_fragment() && !entry_mode.is_fragment() {
        return Err(SarError::FlagConflict("LAST_FRAGMENT requires IS_FRAGMENT"));
    }

    Ok(())
}

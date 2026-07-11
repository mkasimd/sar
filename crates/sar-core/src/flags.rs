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
pub struct EntryMode {
    bits: u16,
}

impl EntryMode {
    /// Entry payload contains a symlink target path string (bit 0).
    pub const IS_SYMLINK: u16 = 1 << 0;
    /// Entry is a directory; Payload Data MUST be 0 (bit 1).
    pub const IS_DIRECTORY: u16 = 1 << 1;
    /// Entry payload is encrypted.
    pub const ENCRYPTED: u16 = 1 << 2;
    /// Entry payload is compressed.
    pub const COMPRESSED: u16 = 1 << 3;
    /// Entry should be treated as hidden by filesystem integrations.
    pub const HIDDEN_ATTR: u16 = 1 << 4;
    /// Entry is a fragment.
    pub const FRAGMENT: u16 = 1 << 5;
    /// Entry is the last fragment in its group.
    pub const LAST_FRAGMENT: u16 = 1 << 6;
    /// Entry supports degraded loss-tolerant reconstruction.
    pub const LOSS_TOLERANT: u16 = 1 << 7;
    /// Session-control opcode context toggle.
    pub const SESSION_CONTROL: u16 = 1 << 13;
    /// Request atomic visibility for the final filesystem state.
    pub const ATOMIC_WRITE: u16 = 1 << 14;
    /// Request conflict-resolution bypass / forced synchronization.
    pub const FORCE_SYNC: u16 = 1 << 15;

    const RESERVED: u16 = 1 << 12;

    /// Creates an entry mode from raw wire bits.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Returns the raw wire bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.bits
    }

    /// Returns true when entry payload is encrypted.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        self.bits & Self::ENCRYPTED != 0
    }

    /// Returns true when entry payload is compressed.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        self.bits & Self::COMPRESSED != 0
    }

    /// Returns true when entry is a directory.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.bits & Self::IS_DIRECTORY != 0
    }

    /// Returns true when entry is a symbolic link.
    #[must_use]
    pub const fn is_symlink(self) -> bool {
        self.bits & Self::IS_SYMLINK != 0
    }

    /// Returns true when entry is marked as fragment.
    #[must_use]
    pub const fn is_fragment(self) -> bool {
        self.bits & Self::FRAGMENT != 0
    }

    /// Returns true when entry is marked as last fragment.
    #[must_use]
    pub const fn is_last_fragment(self) -> bool {
        self.bits & Self::LAST_FRAGMENT != 0
    }

    /// Returns true when entry permits degraded (loss-tolerant) reconstruction.
    #[must_use]
    pub const fn is_loss_tolerant(self) -> bool {
        self.bits & Self::LOSS_TOLERANT != 0
    }

    /// Returns true when opcode context is `SESSION_CONTROL`.
    #[must_use]
    pub const fn is_session_control(self) -> bool {
        self.bits & Self::SESSION_CONTROL != 0
    }

    /// Returns true when hidden-attribute bit is set.
    #[must_use]
    pub const fn is_hidden_attr(self) -> bool {
        self.bits & Self::HIDDEN_ATTR != 0
    }

    /// Returns true when atomic-write bit is set.
    #[must_use]
    pub const fn is_atomic_write(self) -> bool {
        self.bits & Self::ATOMIC_WRITE != 0
    }

    /// Returns true when force-sync bit is set.
    #[must_use]
    pub const fn is_force_sync(self) -> bool {
        self.bits & Self::FORCE_SYNC != 0
    }

    /// Returns the raw 4-bit `OP_CODE` field value.
    #[must_use]
    pub const fn op_code(self) -> u8 {
        ((self.bits >> 8) & 0x0f) as u8
    }
}

/// Validates global flag consistency.
pub fn validate_global_flags(flags: GlobalFlags) -> Result<(), SarError> {
    if flags.contains(GlobalFlags::HAS_GLOBAL_EC) && !flags.contains(GlobalFlags::OPT_PRESENT) {
        return Err(SarError::FlagConflict(
            "HAS_GLOBAL_EC requires OPT_PRESENT and RECOVERY TLV metadata",
        ));
    }

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
    if entry_mode.bits() & EntryMode::RESERVED != 0 {
        return Err(SarError::ReservedValue(
            "entry mode reserved bit 12 must be zero",
        ));
    }

    if entry_mode.is_symlink() && !global_flags.contains(GlobalFlags::HAS_SYMLINKS) {
        return Err(SarError::FlagConflict(
            "IS_SYMLINK requires global HAS_SYMLINKS",
        ));
    }

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

    if entry_mode.is_loss_tolerant() && !entry_mode.is_fragment() {
        return Err(SarError::FlagConflict("LOSS_TOLERANT requires IS_FRAGMENT"));
    }

    Ok(())
}

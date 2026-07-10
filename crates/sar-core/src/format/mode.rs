use std::fmt::{Debug, Formatter};
use std::ops::{BitOr, BitOrAssign};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EntryMode(u32);

impl EntryMode {
    pub const KIND_MASK: Self = Self(0b111);
    pub const KIND_FILE: Self = Self(0);
    pub const KIND_DIRECTORY: Self = Self(1);
    pub const KIND_SYMLINK: Self = Self(2);
    pub const KIND_EMPTY_AREA: Self = Self(3);

    pub const PATH_ACTIVE: Self = Self(1 << 3);
    pub const STREAM_ID_ACTIVE: Self = Self(1 << 4);
    pub const SEQ_NO_ACTIVE: Self = Self(1 << 5);
    pub const PERMISSIONS_ACTIVE: Self = Self(1 << 6);
    pub const OWNER_ACTIVE: Self = Self(1 << 7);
    pub const TIMESTAMPS_ACTIVE: Self = Self(1 << 8);
    pub const HIDDEN_ACTIVE: Self = Self(1 << 9);
    pub const COMPRESSION_ACTIVE: Self = Self(1 << 10);
    pub const ENCRYPTION_ACTIVE: Self = Self(1 << 11);
    pub const CDC_ACTIVE: Self = Self(1 << 12);
    pub const FEC_ACTIVE: Self = Self(1 << 13);
    pub const DELTA_ACTIVE: Self = Self(1 << 14);
    pub const FRAGMENT_ACTIVE: Self = Self(1 << 15);
    pub const SPARSE_ACTIVE: Self = Self(1 << 16);
    pub const CRC32_ACTIVE: Self = Self(1 << 17);
    pub const HASH_ACTIVE: Self = Self(1 << 18);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

impl Debug for EntryMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "EntryMode(0x{:08x})", self.0)
    }
}

impl From<u32> for EntryMode {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<EntryMode> for u32 {
    fn from(value: EntryMode) -> Self {
        value.0
    }
}

impl BitOr for EntryMode {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for EntryMode {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

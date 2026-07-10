use std::fmt::{Debug, Formatter};
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct GlobalFlags(u32);

impl GlobalFlags {
    pub const PATH: Self = Self(1 << 0);
    pub const STREAM_ID: Self = Self(1 << 1);
    pub const SEQ_NO: Self = Self(1 << 2);
    pub const PERMISSIONS: Self = Self(1 << 3);
    pub const OWNER: Self = Self(1 << 4);
    pub const TIMESTAMPS: Self = Self(1 << 5);
    pub const HIDDEN: Self = Self(1 << 6);
    pub const COMPRESSION: Self = Self(1 << 7);
    pub const ENCRYPTION: Self = Self(1 << 8);
    pub const CDC: Self = Self(1 << 9);
    pub const FEC: Self = Self(1 << 10);
    pub const DELTA: Self = Self(1 << 11);
    pub const FRAGMENT: Self = Self(1 << 12);
    pub const SPARSE: Self = Self(1 << 13);
    pub const CRC32: Self = Self(1 << 14);
    pub const HASH: Self = Self(1 << 15);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl Debug for GlobalFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GlobalFlags(0x{:08x})", self.0)
    }
}

impl From<u32> for GlobalFlags {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<GlobalFlags> for u32 {
    fn from(value: GlobalFlags) -> Self {
        value.0
    }
}

impl BitOr for GlobalFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for GlobalFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for GlobalFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for GlobalFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl Not for GlobalFlags {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

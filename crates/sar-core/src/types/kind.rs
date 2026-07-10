use crate::format::mode::EntryMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    RegularFile,
    Directory,
    Symlink,
    EmptyArea,
    Reserved(u32),
}

impl EntryKind {
    pub fn to_mode_bits(self) -> u32 {
        match self {
            Self::RegularFile => EntryMode::KIND_FILE.bits(),
            Self::Directory => EntryMode::KIND_DIRECTORY.bits(),
            Self::Symlink => EntryMode::KIND_SYMLINK.bits(),
            Self::EmptyArea => EntryMode::KIND_EMPTY_AREA.bits(),
            Self::Reserved(bits) => bits & EntryMode::KIND_MASK.bits(),
        }
    }

    pub fn from_mode_bits(bits: u32) -> Self {
        match bits & EntryMode::KIND_MASK.bits() {
            0 => Self::RegularFile,
            1 => Self::Directory,
            2 => Self::Symlink,
            3 => Self::EmptyArea,
            other => Self::Reserved(other),
        }
    }
}

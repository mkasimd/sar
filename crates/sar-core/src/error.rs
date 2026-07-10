use std::fmt::{Display, Formatter};

#[derive(Debug)]
#[non_exhaustive]
pub enum SarError {
    Io(std::io::Error),
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidUtf8(std::string::FromUtf8Error),
    EntryMetadataRequiresFlag {
        field: &'static str,
        required_flag: u32,
    },
    InvalidEntryKind(u32),
    TruncatedInput,
    InvalidEndMagic,
    NameTooLong(usize),
    PathTooLong(usize),
    HashTooLong(usize),
    SparseTooManyHoles(usize),
}

impl Display for SarError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::InvalidMagic => write!(f, "invalid SAR archive magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported SAR archive version: {version}")
            }
            Self::InvalidUtf8(err) => write!(f, "invalid UTF-8 in archive metadata: {err}"),
            Self::EntryMetadataRequiresFlag {
                field,
                required_flag,
            } => write!(
                f,
                "entry field '{field}' requires global flag 0x{required_flag:08x}"
            ),
            Self::InvalidEntryKind(kind) => write!(f, "invalid entry kind value: {kind}"),
            Self::TruncatedInput => write!(f, "truncated SAR archive input"),
            Self::InvalidEndMagic => write!(f, "invalid SAR end-of-archive magic"),
            Self::NameTooLong(len) => write!(f, "entry name exceeds u16 length limit: {len} bytes"),
            Self::PathTooLong(len) => write!(f, "entry path exceeds u16 length limit: {len} bytes"),
            Self::HashTooLong(len) => write!(f, "entry hash exceeds u8 length limit: {len} bytes"),
            Self::SparseTooManyHoles(count) => {
                write!(f, "entry sparse hole count exceeds u32 limit: {count}")
            }
        }
    }
}

impl std::error::Error for SarError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidUtf8(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SarError {
    fn from(value: std::io::Error) -> Self {
        if value.kind() == std::io::ErrorKind::UnexpectedEof {
            Self::TruncatedInput
        } else {
            Self::Io(value)
        }
    }
}

impl From<std::string::FromUtf8Error> for SarError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::InvalidUtf8(value)
    }
}

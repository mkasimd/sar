use std::{fs, path::Path};

use sar_core::{EntryKind, ResourceLimits, SarError};

pub(crate) mod create;
pub(crate) mod extract;
pub(crate) mod inspect;
pub(crate) mod list;
pub(crate) mod repair;
pub(crate) mod verify;
pub(crate) mod version;

pub(crate) fn entry_kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::RegularFile => "regular_file",
        EntryKind::Directory => "directory",
        EntryKind::Symlink => "symlink",
        EntryKind::EmptyArea => "empty_area",
    }
}

pub(crate) fn read_file_with_archive_limit(
    path: &Path,
    limits: &ResourceLimits,
) -> Result<Vec<u8>, SarError> {
    let archive_len = fs::metadata(path)?.len();
    limits.check_archive_size(archive_len)?;
    fs::read(path).map_err(SarError::Io)
}

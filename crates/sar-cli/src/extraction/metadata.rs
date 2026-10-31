// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use sar_core::SarError;

use crate::extraction::{
    paths::SafeRelativePath, policy::ExtractMetadataOptions, root::ExtractionRoot,
};

#[cfg(unix)]
const UID_MASK: u32 = 0xFFFF;
#[cfg(unix)]
const GID_SHIFT: u32 = 16;

#[derive(Debug, Clone)]
pub(crate) struct PendingDirectoryMetadata {
    pub(crate) relative_path: SafeRelativePath,
    pub(crate) permissions: Option<u16>,
    pub(crate) owner: Option<u32>,
    pub(crate) timestamps: Option<[u64; 3]>,
}

/// Restores directory metadata after all children, deepest paths first. Ties
/// are broken by path so the order is deterministic.
pub(crate) fn finalize_directory_metadata(
    root: &ExtractionRoot,
    pending_directories: HashMap<String, PendingDirectoryMetadata>,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    let mut pending: Vec<_> = pending_directories.into_iter().collect();
    pending.sort_by(|(left_key, left), (right_key, right)| {
        right
            .relative_path
            .depth()
            .cmp(&left.relative_path.depth())
            .then_with(|| left_key.cmp(right_key))
    });
    for (_, entry) in pending {
        root.apply_directory_metadata(
            &entry.relative_path,
            entry.permissions,
            entry.owner,
            entry.timestamps,
            metadata,
        )?;
    }
    Ok(())
}

/// Applies owner, timestamps and permissions (in that order) to an open file
/// or directory descriptor. Nothing is re-resolved by pathname.
#[cfg(unix)]
pub(crate) fn apply_fd_metadata(
    fd: impl rustix::fd::AsFd,
    permissions: Option<u16>,
    owner: Option<u32>,
    timestamps: Option<[u64; 3]>,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    let fd = fd.as_fd();
    if metadata.preserve_owner
        && let Some(owner) = owner
    {
        let uid = rustix::process::Uid::from_raw(owner & UID_MASK);
        let gid = rustix::process::Gid::from_raw((owner >> GID_SHIFT) & UID_MASK);
        rustix::fs::fchown(fd, Some(uid), Some(gid))
            .map_err(std::io::Error::from)
            .map_err(SarError::Io)?;
    }
    if metadata.preserve_times
        && let Some([mtime, atime, _ctime]) = timestamps
    {
        let atime = i64::try_from(atime)
            .map_err(|_| SarError::Overflow("atime does not fit host timestamp range"))?;
        let mtime = i64::try_from(mtime)
            .map_err(|_| SarError::Overflow("mtime does not fit host timestamp range"))?;
        let times = rustix::fs::Timestamps {
            last_access: rustix::fs::Timespec {
                tv_sec: atime,
                tv_nsec: 0,
            },
            last_modification: rustix::fs::Timespec {
                tv_sec: mtime,
                tv_nsec: 0,
            },
        };
        rustix::fs::futimens(fd, &times)
            .map_err(std::io::Error::from)
            .map_err(SarError::Io)?;
    }
    if metadata.preserve_permissions
        && let Some(mode) = permissions
    {
        let raw = rustix::fs::RawMode::from(mode & 0o0777);
        rustix::fs::fchmod(fd, rustix::fs::Mode::from_raw_mode(raw))
            .map_err(std::io::Error::from)
            .map_err(SarError::Io)?;
    }
    Ok(())
}

// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs, path::Path};

use filetime::{FileTime, set_file_times};
use sar_core::SarError;

use crate::extraction::{
    paths::{SafeRelativePath, resolve_existing_directory_path},
    policy::ExtractMetadataOptions,
};

const UID_MASK: u32 = 0xFFFF;
const GID_SHIFT: u32 = 16;

#[derive(Debug, Clone)]
pub(crate) struct PendingDirectoryMetadata {
    pub(crate) relative_path: SafeRelativePath,
    pub(crate) permissions: Option<u16>,
    pub(crate) owner: Option<u32>,
    pub(crate) timestamps: Option<[u64; 3]>,
}

pub(crate) fn apply_file_metadata(
    path: &Path,
    permissions: Option<u16>,
    owner: Option<u32>,
    timestamps: Option<[u64; 3]>,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => return Ok(()),
        Ok(meta) if meta.is_dir() => {
            return Err(SarError::Malformed(
                "refusing to apply file metadata to directory",
            ));
        }
        Ok(_) => {}
        Err(err) => return Err(SarError::Io(err)),
    }
    apply_owner(path, owner, metadata)?;
    apply_timestamps(path, timestamps, metadata)?;
    apply_permissions(path, permissions, metadata)
}

pub(crate) fn finalize_directory_metadata(
    output_dir: &Path,
    pending_directories: HashMap<String, PendingDirectoryMetadata>,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    let mut pending: Vec<_> = pending_directories.into_values().collect();
    pending.sort_by_key(|entry| std::cmp::Reverse(entry.relative_path.depth()));
    for entry in pending {
        let path = resolve_existing_directory_path(output_dir, &entry.relative_path)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => continue,
            Ok(meta) if !meta.is_dir() => {
                return Err(SarError::Malformed(
                    "refusing to apply directory metadata to non-directory",
                ));
            }
            Ok(_) => {}
            Err(err) => return Err(SarError::Io(err)),
        }
        apply_owner(&path, entry.owner, metadata)?;
        apply_timestamps(&path, entry.timestamps, metadata)?;
        apply_permissions(&path, entry.permissions, metadata)?;
    }
    Ok(())
}

fn apply_permissions(
    path: &Path,
    permissions: Option<u16>,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    if !metadata.preserve_permissions {
        return Ok(());
    }
    let Some(mode) = permissions else {
        return Ok(());
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(u32::from(mode & 0o0777)))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err(SarError::Unsupported(
            "permission restoration is only supported on Unix-like platforms",
        ))
    }
}

fn apply_owner(
    path: &Path,
    owner: Option<u32>,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    if !metadata.preserve_owner {
        return Ok(());
    }
    let Some(owner) = owner else {
        return Ok(());
    };

    #[cfg(unix)]
    {
        let uid = rustix::process::Uid::from_raw(owner & UID_MASK);
        let gid = rustix::process::Gid::from_raw((owner >> GID_SHIFT) & UID_MASK);
        rustix::fs::chown(path, Some(uid), Some(gid))
            .map_err(std::io::Error::from)
            .map_err(SarError::Io)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (path, owner);
        Err(SarError::Unsupported(
            "owner restoration is only supported on Unix-like platforms",
        ))
    }
}

fn apply_timestamps(
    path: &Path,
    timestamps: Option<[u64; 3]>,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    if !metadata.preserve_times {
        return Ok(());
    }
    let Some([mtime, atime, _ctime]) = timestamps else {
        return Ok(());
    };

    let atime_i64 = i64::try_from(atime)
        .map_err(|_| SarError::Overflow("atime does not fit host timestamp range"))?;
    let mtime_i64 = i64::try_from(mtime)
        .map_err(|_| SarError::Overflow("mtime does not fit host timestamp range"))?;
    set_file_times(
        path,
        FileTime::from_unix_time(atime_i64, 0),
        FileTime::from_unix_time(mtime_i64, 0),
    )
    .map_err(SarError::Io)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::{collections::HashMap, fs};

    use tempfile::tempdir;

    use super::{PendingDirectoryMetadata, apply_file_metadata, finalize_directory_metadata};
    use crate::extraction::{paths::SafeRelativePath, policy::ExtractMetadataOptions};

    #[test]
    fn apply_file_metadata_skips_symlink_path() {
        let td = tempdir().expect("tmp");
        let target = td.path().join("target.txt");
        fs::write(&target, b"target").expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).expect("chmod target");
        let link = td.path().join("link.txt");
        symlink(&target, &link).expect("link");

        apply_file_metadata(
            &link,
            Some(0o600),
            None,
            None,
            ExtractMetadataOptions {
                preserve_permissions: true,
                ..Default::default()
            },
        )
        .expect("metadata application should skip symlink");

        let mode = fs::metadata(&target)
            .expect("target metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o777);
    }

    #[test]
    fn finalize_directory_metadata_rejects_non_directory_target() {
        let td = tempdir().expect("tmp");
        let output = td.path().join("out");
        fs::create_dir_all(&output).expect("mkdir out");
        fs::write(output.join("leaf"), b"file").expect("write leaf");

        let mut pending = HashMap::new();
        pending.insert(
            "leaf".to_string(),
            PendingDirectoryMetadata {
                relative_path: SafeRelativePath::from_components(vec!["leaf".to_string()])
                    .expect("safe path"),
                permissions: Some(0o700),
                owner: None,
                timestamps: None,
            },
        );

        let err = finalize_directory_metadata(
            &output,
            pending,
            ExtractMetadataOptions {
                preserve_permissions: true,
                ..Default::default()
            },
        )
        .expect_err("non-directory should be rejected");
        assert!(matches!(err, sar_core::SarError::Malformed(_)));
    }
}

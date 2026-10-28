// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use sar_archive::{
    ArchiveReader, ArchiveReaderOptions, EntryReader, fragment_group::CollectedEntry,
};
use sar_core::{EntryKind, GlobalFlags, ResourceLimits, SarError};

use crate::{
    extraction::{
        metadata::{PendingDirectoryMetadata, apply_file_metadata, finalize_directory_metadata},
        paths::{
            SafeRelativePath, ensure_safe_directory_path, prepare_output_file_path,
            validate_relative_archive_path,
        },
        policy::{ExtractMetadataOptions, validate_extract_metadata_support},
        staging::{
            compute_sparse_crc32, verify_crc32, write_bytes_via_temp, write_sparse_payload_via_temp,
        },
    },
    password::{CliKeyProvider, load_password},
};

pub(crate) fn extract_archive(
    archive: PathBuf,
    output_dir: PathBuf,
    password: Option<String>,
    allow_lossy: bool,
    limits: ResourceLimits,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    validate_extract_metadata_support(metadata)?;
    fs::create_dir_all(&output_dir)?;
    let mut reader = ArchiveReader::with_options(
        BufReader::new(File::open(&archive)?),
        ArchiveReaderOptions {
            limits,
            delta_base: None,
        },
    )?;
    let header = reader.read_global_header()?;
    if header.flags.contains(sar_core::GlobalFlags::ENCRYPTED) {
        let password = load_password(password)?;
        reader = reader.with_key_provider(Box::new(CliKeyProvider::new(Some(password))));
    }

    let mut pending_directories = HashMap::<String, PendingDirectoryMetadata>::new();

    // The archive reader validates fragment groups (physical order, Class G
    // invariants, Index-0 Name/Path authority, neutral non-terminal integrity
    // fields) and yields logical Entries in canonical order as soon as they
    // are not blocked by an incomplete earlier group.
    while let Some(item) = reader.next_logical_entry()? {
        let group = match item {
            CollectedEntry::Entry(entry) => {
                extract_non_fragment_entry(
                    &output_dir,
                    &entry,
                    header.flags,
                    &limits,
                    metadata,
                    &mut pending_directories,
                )?;
                continue;
            }
            CollectedEntry::Group(group) => group,
        };

        let name = group.name.clone();
        let terminal_crc32 = group.terminal_crc32;
        let index0 = group.index0.clone();
        // Incomplete sparse groups fail with FRAGMENT_GAP, and the Index-0 Sparse
        // Map is checked against the contributions before any concatenation.
        let sparse = group.validate_sparse(&limits)?.cloned();

        let (raw, is_degraded) = group.reconstruct(&limits)?;
        if is_degraded && !allow_lossy {
            return Err(SarError::FragmentGap(
                "fragment group has gaps; use allow_lossy to permit degraded output",
            ));
        }
        if is_degraded {
            eprintln!(
                "warning: '{}' extracted with degraded (incomplete) content; \
                 only the contiguous fragment prefix from Fragment Index 0 was recovered (LOSS_TOLERANT). \
                 This output MUST NOT be used for integrity-critical purposes.",
                name
            );
        }

        let rel = validate_relative_archive_path(&name)?;
        let out_path = prepare_output_file_path(&output_dir, &rel)?;
        // The authoritative CRC32 is the LAST_FRAGMENT value; degraded output
        // is never reported as integrity-verified.
        if let Some(sparse) = sparse.as_ref() {
            // The logical file (holes included) is never materialized in memory:
            // the CRC is streamed over zero runs and the output is written by
            // extent into a sparse temporary file.
            if header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    terminal_crc32,
                    compute_sparse_crc32(&raw, &sparse.extents, sparse.logical_size, &limits)?,
                    "file CRC32 mismatch on reconstructed fragment-group logical file",
                )?;
            }
            write_sparse_payload_via_temp(
                &out_path,
                &raw,
                &sparse.extents,
                sparse.logical_size,
                &limits,
            )?;
        } else {
            if !is_degraded && header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    terminal_crc32,
                    crc32fast::hash(&raw),
                    "file CRC32 mismatch on reconstructed fragment-group logical file",
                )?;
            }
            write_bytes_via_temp(&out_path, &raw)?;
        }
        apply_file_metadata(
            &out_path,
            index0.as_ref().and_then(|m| m.permissions).map(|v| v.mode),
            index0.as_ref().and_then(|m| m.owner).map(|v| v.uid_gid),
            index0
                .as_ref()
                .and_then(|m| m.timestamps)
                .map(|v| [v.mtime, v.atime, v.ctime]),
            metadata,
        )?;
    }

    finalize_directory_metadata(&output_dir, pending_directories, metadata)?;
    Ok(())
}

fn extract_non_fragment_entry(
    output_dir: &Path,
    entry: &EntryReader,
    global_flags: GlobalFlags,
    limits: &ResourceLimits,
    metadata: ExtractMetadataOptions,
    pending_directories: &mut HashMap<String, PendingDirectoryMetadata>,
) -> Result<(), SarError> {
    let rel = validate_relative_archive_path(&entry.metadata.name)?;
    match entry.metadata.entry_kind {
        EntryKind::Directory => {
            let out_path = ensure_safe_directory_path(output_dir, &rel)?;
            record_directory_metadata(pending_directories, &rel, entry);
            let _ = out_path;
            Ok(())
        }
        EntryKind::Symlink => extract_symlink_entry(output_dir, &rel, entry, metadata),
        EntryKind::RegularFile => {
            let out_path = prepare_output_file_path(output_dir, &rel)?;
            if let Some(sparse) = entry.metadata.sparse.as_ref() {
                let extents = &sparse.extents;
                let actual_crc =
                    compute_sparse_crc32(&entry.payload, extents, sparse.logical_size, limits)?;
                if global_flags.contains(GlobalFlags::PER_FILE_CRC) {
                    verify_crc32(
                        entry.metadata.file_crc32,
                        actual_crc,
                        "file CRC32 mismatch on reconstructed logical file",
                    )?;
                }
                write_sparse_payload_via_temp(
                    &out_path,
                    &entry.payload,
                    extents,
                    sparse.logical_size,
                    limits,
                )?;
            } else {
                if global_flags.contains(GlobalFlags::PER_FILE_CRC) {
                    verify_crc32(
                        entry.metadata.file_crc32,
                        crc32fast::hash(&entry.payload),
                        "file CRC32 mismatch on reconstructed logical file",
                    )?;
                }
                write_bytes_via_temp(&out_path, &entry.payload)?;
            }
            apply_file_metadata(
                &out_path,
                entry.metadata.permissions.map(|value| value.mode),
                entry.metadata.owner.map(|value| value.uid_gid),
                entry
                    .metadata
                    .timestamps
                    .map(|value| [value.mtime, value.atime, value.ctime]),
                metadata,
            )
        }
        EntryKind::EmptyArea => Ok(()),
    }
}

fn record_directory_metadata(
    pending_directories: &mut HashMap<String, PendingDirectoryMetadata>,
    rel: &SafeRelativePath,
    entry: &EntryReader,
) {
    pending_directories.insert(
        rel.display(),
        PendingDirectoryMetadata {
            relative_path: rel.clone(),
            permissions: entry.metadata.permissions.map(|value| value.mode),
            owner: entry.metadata.owner.map(|value| value.uid_gid),
            timestamps: entry
                .metadata
                .timestamps
                .map(|value| [value.mtime, value.atime, value.ctime]),
        },
    );
}

fn extract_symlink_entry(
    output_dir: &Path,
    rel: &SafeRelativePath,
    entry: &EntryReader,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    if !metadata.allow_symlinks {
        return Err(SarError::Unsupported(
            "symlink extraction requires --allow-symlinks",
        ));
    }

    let target = entry
        .metadata
        .symlink_target
        .as_deref()
        .ok_or(SarError::Malformed(
            "symlink entry is missing target metadata",
        ))?;
    let _ = validate_relative_archive_path(target)?;

    let out_path = prepare_output_file_path(output_dir, rel)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        if let Ok(existing) = fs::symlink_metadata(&out_path) {
            if existing.file_type().is_dir() {
                return Err(SarError::Malformed(
                    "refusing to replace existing directory with symlink",
                ));
            }
            fs::remove_file(&out_path)?;
        }
        symlink(target, &out_path)?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = (output_dir, rel, entry);
        Err(SarError::Unsupported(
            "symlink extraction is only supported on Unix-like platforms",
        ))
    }
}

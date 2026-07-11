use std::{
    collections::HashMap,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use sar_archive::{ArchiveReader, ArchiveReaderOptions, EntryReader};
use sar_core::{EntryKind, GlobalFlags, ResourceLimits, SarError, sparse::SparseExtent};
use sar_fragmentation::{FragmentEntry, reconstruct_fragments};

use crate::{
    extraction::{
        metadata::{PendingDirectoryMetadata, apply_file_metadata, finalize_directory_metadata},
        paths::{SafeRelativePath, ensure_safe_directory_path, prepare_output_file_path, validate_relative_archive_path},
        policy::{ExtractMetadataOptions, validate_extract_metadata_support},
        staging::{compute_sparse_crc32, verify_crc32, write_bytes_via_temp, write_sparse_payload_via_temp},
    },
    password::{CliKeyProvider, load_password},
};

#[derive(Debug)]
struct FragGroup {
    name: String,
    entries: Vec<EntryReader>,
    sparse_extents: Option<Vec<SparseExtent>>,
    sparse_uncompressed_size: u64,
    file_crc32: Option<u32>,
    permissions: Option<u16>,
    owner: Option<u32>,
    timestamps: Option<[u64; 3]>,
}

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

    let mut frag_order = Vec::new();
    let mut frag_groups = HashMap::<u32, FragGroup>::new();
    let mut pending_directories = HashMap::<String, PendingDirectoryMetadata>::new();

    while let Some(entry) = reader.next_entry()? {
        if entry.metadata.name.is_empty() && !entry.metadata.is_fragment {
            continue;
        }

        if entry.metadata.is_fragment {
            let fid = entry.metadata.fragment_id.ok_or(SarError::Malformed(
                "IS_FRAGMENT set but fragment_id is absent",
            ))?;
            let has_sparse = entry.metadata.sparse_extents.is_some();
            if has_sparse && entry.metadata.fragment_index != Some(0) {
                return Err(SarError::InvalidMap(
                    "sparse map present on non-zero fragment index; Sparse Map MUST appear only in fragment with Fragment Index = 0",
                ));
            }

            let group = frag_groups.entry(fid).or_insert_with(|| {
                frag_order.push(fid);
                FragGroup {
                    name: entry.metadata.name.clone(),
                    entries: Vec::new(),
                    sparse_extents: None,
                    sparse_uncompressed_size: 0,
                    file_crc32: None,
                    permissions: entry.metadata.permissions.map(|value| value.mode),
                    owner: entry.metadata.owner.map(|value| value.uid_gid),
                    timestamps: entry
                        .metadata
                        .timestamps
                        .map(|value| [value.mtime, value.atime, value.ctime]),
                }
            });
            limits.check_fragment_count(
                group
                    .entries
                    .len()
                    .checked_add(1)
                    .ok_or(SarError::Overflow("fragment count"))?,
            )?;

            if entry.metadata.fragment_index == Some(0) {
                if has_sparse {
                    group.sparse_extents = entry.metadata.sparse_extents.clone();
                    group.sparse_uncompressed_size = entry.metadata.uncompressed_size;
                }
                group.file_crc32 = entry.metadata.file_crc32;
                group.permissions = entry.metadata.permissions.map(|value| value.mode);
                group.owner = entry.metadata.owner.map(|value| value.uid_gid);
                group.timestamps = entry
                    .metadata
                    .timestamps
                    .map(|value| [value.mtime, value.atime, value.ctime]);
            }

            group.entries.push(entry);
            continue;
        }

        extract_non_fragment_entry(
            &output_dir,
            &entry,
            header.flags,
            &limits,
            metadata,
            &mut pending_directories,
        )?;
    }

    for fid in frag_order {
        let FragGroup {
            name,
            entries: group_entries,
            sparse_extents,
            sparse_uncompressed_size,
            file_crc32,
            permissions,
            owner,
            timestamps,
        } = frag_groups.remove(&fid).ok_or(SarError::Malformed(
            "fragment group ID vanished during reconstruction",
        ))?;

        let mut assembled_size = 0u64;
        for entry in &group_entries {
            if let Some(desc) = &entry.metadata.fragment_descriptor {
                let end = desc
                    .absolute_offset
                    .checked_add(u64::from(desc.fragment_size))
                    .ok_or(SarError::Overflow("fragment descriptor end overflow"))?;
                assembled_size = assembled_size.max(end);
            }
        }

        let frag_entries: Vec<FragmentEntry> = group_entries
            .into_iter()
            .filter_map(|entry| {
                let desc = entry.metadata.fragment_descriptor?;
                Some(FragmentEntry {
                    fragment_index: entry.metadata.fragment_index.unwrap_or(0),
                    is_last_fragment: entry.metadata.is_last_fragment,
                    is_loss_tolerant: entry.metadata.is_loss_tolerant,
                    descriptor: desc,
                    payload: entry.payload,
                })
            })
            .collect();

        let (raw, is_degraded) =
            reconstruct_fragments(frag_entries, assembled_size, &limits.fragment_limits())?;
        if is_degraded && !allow_lossy {
            return Err(SarError::FragmentGap(
                "fragment group has gaps; use allow_lossy to permit degraded output",
            ));
        }
        if is_degraded {
            eprintln!(
                "warning: '{}' extracted with degraded (incomplete) content; \
                 missing fragments were replaced with zero bytes (LOSS_TOLERANT). \
                 This output MUST NOT be used for integrity-critical purposes.",
                name
            );
        }

        let rel = validate_relative_archive_path(&name)?;
        let out_path = prepare_output_file_path(&output_dir, &rel)?;
        if let Some(extents) = sparse_extents.as_ref() {
            let actual_crc =
                compute_sparse_crc32(&raw, extents, sparse_uncompressed_size, &limits)?;
            if header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    file_crc32,
                    actual_crc,
                    "file CRC32 mismatch on reconstructed fragment-group logical file",
                )?;
            }
            write_sparse_payload_via_temp(&out_path, &raw, extents, sparse_uncompressed_size, &limits)?;
        } else {
            if header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    file_crc32,
                    crc32fast::hash(&raw),
                    "file CRC32 mismatch on reconstructed fragment-group logical file",
                )?;
            }
            write_bytes_via_temp(&out_path, &raw)?;
        }
        apply_file_metadata(&out_path, permissions, owner, timestamps, metadata)?;
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
            if let Some(extents) = entry.metadata.sparse_extents.as_ref() {
                let actual_crc = compute_sparse_crc32(
                    &entry.payload,
                    extents,
                    entry.metadata.uncompressed_size,
                    limits,
                )?;
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
                    entry.metadata.uncompressed_size,
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

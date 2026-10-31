// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf};

use sar_archive::{
    ArchiveReader, ArchiveReaderOptions, EntryReader, fragment_group::CollectedEntry,
    verify_content_hash,
};
use sar_core::{EntryKind, GlobalFlags, ResourceLimits, SarError};

use crate::{
    extraction::{
        metadata::{PendingDirectoryMetadata, finalize_directory_metadata},
        paths::{SafeRelativePath, full_logical_entry_path, validate_symlink_target},
        policy::{ExtractMetadataOptions, validate_extract_metadata_support},
        root::ExtractionRoot,
        staging::{compute_sparse_crc32, stage_bytes, stage_sparse, verify_crc32},
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
    // The root is resolved exactly once; every later mutation is relative to it.
    let root = ExtractionRoot::open(&output_dir, limits)?;
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
                    &root,
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
        let terminal_content_hash = group.terminal_content_hash;
        let terminal_hash_algo_id = group.terminal_hash_algo_id;
        let index0 = group.index0.clone();
        // Incomplete sparse groups fail with FRAGMENT_GAP, and the Index-0 Sparse
        // Map is checked against the contributions before any concatenation.
        let sparse = group.validate_sparse(&limits)?.cloned();

        let options = ArchiveReaderOptions {
            limits,
            delta_base: None,
        };
        let (raw, is_degraded) = group.reconstruct(&options)?;
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

        // The terminal Content Hash is authoritative over the complete logical
        // Entry (holes included) and is never checked on degraded output, nor
        // masked by LOSS_TOLERANT.
        if !is_degraded {
            verify_content_hash(
                terminal_hash_algo_id,
                terminal_content_hash,
                &raw,
                sparse
                    .as_ref()
                    .map(|sparse| (sparse.extents.as_slice(), sparse.logical_size)),
            )?;
        }

        let rel = full_logical_entry_path(index0.as_ref().and_then(|m| m.path.as_deref()), &name)?;
        let permissions = index0.as_ref().and_then(|m| m.permissions).map(|v| v.mode);
        // The authoritative CRC32 is the LAST_FRAGMENT value; degraded output
        // is never reported as integrity-verified.
        let staged = if let Some(sparse) = sparse.as_ref() {
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
            stage_sparse(
                &root,
                &rel,
                &raw,
                &sparse.extents,
                sparse.logical_size,
                &limits,
            )?
        } else {
            if !is_degraded && header.flags.contains(GlobalFlags::PER_FILE_CRC) {
                verify_crc32(
                    terminal_crc32,
                    crc32fast::hash(&raw),
                    "file CRC32 mismatch on reconstructed fragment-group logical file",
                )?;
            }
            stage_bytes(&root, &rel, &raw)?
        };
        // Metadata is applied to the open staging file before publication.
        staged.apply_metadata(
            permissions,
            index0.as_ref().and_then(|m| m.owner).map(|v| v.uid_gid),
            index0
                .as_ref()
                .and_then(|m| m.timestamps)
                .map(|v| [v.mtime, v.atime, v.ctime]),
            metadata,
        )?;
        staged.publish()?;
        discard_replaced_directory_metadata(&mut pending_directories, &rel);
    }

    finalize_directory_metadata(&root, pending_directories, metadata)?;
    Ok(())
}

fn extract_non_fragment_entry(
    root: &ExtractionRoot,
    entry: &EntryReader,
    global_flags: GlobalFlags,
    limits: &ResourceLimits,
    metadata: ExtractMetadataOptions,
    pending_directories: &mut HashMap<String, PendingDirectoryMetadata>,
) -> Result<(), SarError> {
    let rel = full_logical_entry_path(entry.metadata.path.as_deref(), &entry.metadata.name)?;
    match entry.metadata.entry_kind {
        EntryKind::Directory => {
            root.create_directory(&rel)?;
            record_directory_metadata(pending_directories, &rel, entry);
            Ok(())
        }
        EntryKind::Symlink => {
            extract_symlink_entry(root, &rel, entry, metadata)?;
            discard_replaced_directory_metadata(pending_directories, &rel);
            Ok(())
        }
        EntryKind::RegularFile => {
            verify_content_hash(
                entry.metadata.hash_algo_id,
                entry.metadata.content_hash,
                &entry.payload,
                entry
                    .metadata
                    .sparse
                    .as_ref()
                    .map(|sparse| (sparse.extents.as_slice(), sparse.logical_size)),
            )?;
            let permissions = entry.metadata.permissions.map(|value| value.mode);
            let staged = if let Some(sparse) = entry.metadata.sparse.as_ref() {
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
                stage_sparse(
                    root,
                    &rel,
                    &entry.payload,
                    extents,
                    sparse.logical_size,
                    limits,
                )?
            } else {
                if global_flags.contains(GlobalFlags::PER_FILE_CRC) {
                    verify_crc32(
                        entry.metadata.file_crc32,
                        crc32fast::hash(&entry.payload),
                        "file CRC32 mismatch on reconstructed logical file",
                    )?;
                }
                stage_bytes(root, &rel, &entry.payload)?
            };
            staged.apply_metadata(
                permissions,
                entry.metadata.owner.map(|value| value.uid_gid),
                entry
                    .metadata
                    .timestamps
                    .map(|value| [value.mtime, value.atime, value.ctime]),
                metadata,
            )?;
            staged.publish()?;
            discard_replaced_directory_metadata(pending_directories, &rel);
            Ok(())
        }
        EntryKind::EmptyArea => Ok(()),
    }
}

/// A non-directory Entry replaces any directory at its path and removes that
/// directory's earlier descendants from the final logical state (specification
/// Section 6.1.5), so their explicit metadata no longer applies. A directory
/// that is later recreated implicitly starts without explicit metadata.
fn discard_replaced_directory_metadata(
    pending_directories: &mut HashMap<String, PendingDirectoryMetadata>,
    rel: &SafeRelativePath,
) {
    let key = rel.display();
    let prefix = format!("{key}/");
    pending_directories.retain(|path, _| *path != key && !path.starts_with(&prefix));
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
    root: &ExtractionRoot,
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
    validate_symlink_target(rel, target)?;

    root.create_symlink(rel, target)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{fs, path::Path};

    use sar_archive::{ArchiveWriter, ArchiveWriterOptions, EntryInput};
    use sar_core::{ResourceLimits, SarStatus};
    use tempfile::tempdir;

    use super::extract_archive;
    use crate::extraction::{policy::ExtractMetadataOptions, root::test_hooks};

    fn write_archive(path: &Path, entries: Vec<EntryInput>) {
        let mut file = fs::File::create(path).expect("archive file");
        let mut writer =
            ArchiveWriter::new(&mut file, ArchiveWriterOptions::default()).expect("writer");
        for entry in entries {
            writer.add_entry(entry).expect("entry");
        }
        writer.finish().expect("finish");
    }

    fn extract(archive: &Path, out: &Path) -> Result<(), sar_core::SarError> {
        extract_archive(
            archive.to_path_buf(),
            out.to_path_buf(),
            None,
            false,
            ResourceLimits::default(),
            ExtractMetadataOptions::default(),
        )
    }

    struct ClearHook;
    impl Drop for ClearHook {
        fn drop(&mut self) {
            test_hooks::clear();
        }
    }

    /// Makes the second archive path reach the first one's object, as a
    /// case-folding or normalizing destination filesystem would, so the full
    /// extraction pipeline reports the collision on any host filesystem.
    #[test]
    fn colliding_destination_objects_fail_extraction_with_status_700() {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("a.sar");
        write_archive(
            &archive,
            vec![
                EntryInput::file("Readme", b"owner".to_vec()),
                EntryInput::file("README", b"intruder".to_vec()),
            ],
        );
        let out = td.path().join("out");
        let (first, alias) = (out.join("Readme"), out.join("README"));
        test_hooks::install(move |point| {
            if point == "before-publish" && first.exists() && !alias.exists() {
                fs::hard_link(&first, &alias).expect("alias");
            }
        });
        let _guard = ClearHook;

        let err = extract(&archive, &out).expect_err("collision");

        assert_eq!(err.status(), SarStatus::ErrPathCollision);
        assert_eq!(fs::read(out.join("Readme")).expect("read"), b"owner");
        assert_eq!(fs::read(out.join("README")).expect("read"), b"owner");
    }

    #[test]
    fn repeated_identical_paths_still_extract_with_the_last_entry_winning() {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("a.sar");
        write_archive(
            &archive,
            vec![
                EntryInput::file("dup", b"first".to_vec()),
                EntryInput::file("dup", b"second".to_vec()),
            ],
        );
        let out = td.path().join("out");
        extract(&archive, &out).expect("repeated path is not a collision");
        assert_eq!(fs::read(out.join("dup")).expect("read"), b"second");
    }
}

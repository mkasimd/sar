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
        policy::{
            ExtractMetadataOptions, SECURE_EXTRACTION_BACKEND, require_secure_extraction_backend,
        },
        report::ExtractionFailure,
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
) -> Result<(), ExtractionFailure> {
    require_secure_extraction_backend(SECURE_EXTRACTION_BACKEND)?;
    // The root is resolved exactly once; every later mutation is relative to it.
    let root = ExtractionRoot::open(&output_dir, limits)?;
    // Extraction stays fail-fast. After a failure the primary error is kept
    // unchanged and the root reports what may remain in the destination.
    match extract_into(&root, archive, password, allow_lossy, limits, metadata) {
        Ok(()) => root.ensure_no_temporary_artifacts().map_err(Into::into),
        Err(error) => Err(ExtractionFailure {
            error,
            report: root.failure_report(),
        }),
    }
}

fn extract_into(
    root: &ExtractionRoot,
    archive: PathBuf,
    password: Option<String>,
    allow_lossy: bool,
    limits: ResourceLimits,
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
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
                    root,
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
                root,
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
            stage_bytes(root, &rel, &raw)?
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

    finalize_directory_metadata(root, pending_directories, metadata)?;
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
        let mut writer = ArchiveWriter::new(
            &mut file,
            ArchiveWriterOptions {
                with_symlinks: true,
                with_path: true,
                ..Default::default()
            },
        )
        .expect("writer");
        for entry in entries {
            writer.add_entry(entry).expect("entry");
        }
        writer.finish().expect("finish");
    }

    fn extract(archive: &Path, out: &Path) -> Result<(), sar_core::SarError> {
        extract_with_report(archive, out).map_err(|failure| failure.error)
    }

    fn extract_with_report(
        archive: &Path,
        out: &Path,
    ) -> Result<(), crate::extraction::report::ExtractionFailure> {
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

    #[test]
    fn many_entries_release_journal_slots_between_publications() {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("a.sar");
        let entries: Vec<EntryInput> = (0..64)
            .map(|i| nested("d", &format!("f{i}"), &[b'x'; 8]))
            .collect();
        write_archive(&archive, entries);
        let out = td.path().join("out");
        extract(&archive, &out).expect("more than eight entries extract");
        for i in 0..64 {
            assert_eq!(
                fs::read(out.join(format!("d/f{i}"))).expect("read"),
                [b'x'; 8]
            );
        }
        assert!(leftovers(&out).is_empty());
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(&current).expect("read_dir") {
                let entry = entry.expect("entry");
                if entry.file_name().to_string_lossy().starts_with(".sar-tmp-") {
                    found.push(entry.path().display().to_string());
                }
                if entry.file_type().expect("type").is_dir() {
                    pending.push(entry.path());
                }
            }
        }
        found
    }

    fn nested(path: &str, name: &str, data: &[u8]) -> EntryInput {
        EntryInput {
            path: Some(path.to_string()),
            ..EntryInput::file(name, data.to_vec())
        }
    }

    #[test]
    fn failure_before_the_first_publication_reports_no_change() {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("a.sar");
        write_archive(
            &archive,
            vec![
                symlink_entry("l", "a"),
                EntryInput::file("a", b"a".to_vec()),
            ],
        );
        let out = td.path().join("out");
        fs::create_dir(&out).expect("out");

        let failure = extract_with_report(&archive, &out).expect_err("symlinks are not enabled");

        assert_eq!(failure.error.status(), SarStatus::ErrUnsupported);
        assert!(!failure.report.partial_changes);
        assert!(failure.report.cleanup_failures.is_empty());
        assert!(failure.report.notes().is_empty());
        assert!(leftovers(&out).is_empty());
    }

    #[test]
    fn failure_after_one_entry_keeps_it_and_reports_partial_changes() {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("a.sar");
        write_archive(
            &archive,
            vec![
                EntryInput::file("a", b"a".to_vec()),
                symlink_entry("l", "a"),
            ],
        );
        let out = td.path().join("out");

        let failure = extract_with_report(&archive, &out).expect_err("unsupported symlink");

        assert_eq!(failure.error.status(), SarStatus::ErrUnsupported);
        assert!(failure.report.partial_changes);
        assert!(failure.report.cleanup_failures.is_empty());
        assert_eq!(fs::read(out.join("a")).expect("kept"), b"a");
        assert!(leftovers(&out).is_empty());
    }

    fn symlink_entry(name: &str, target: &str) -> EntryInput {
        EntryInput {
            name: name.to_string(),
            payload: target.as_bytes().to_vec(),
            kind: Some(sar_core::EntryKind::Symlink),
            ..Default::default()
        }
    }

    #[test]
    fn successful_replacement_leaves_no_run_owned_temporary_objects() {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("a.sar");
        write_archive(
            &archive,
            vec![
                nested("d/sub", "x", b"x"),
                EntryInput::file("d", b"replacement".to_vec()),
            ],
        );
        let out = td.path().join("out");

        extract(&archive, &out).expect("extracts");

        assert_eq!(fs::read(out.join("d")).expect("d"), b"replacement");
        assert!(leftovers(&out).is_empty());
    }

    #[test]
    fn cleanup_failure_after_replacement_is_an_error_that_keeps_the_published_object() {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("a.sar");
        write_archive(
            &archive,
            vec![
                nested("d/sub", "x", b"x"),
                EntryInput::file("d", b"replacement".to_vec()),
            ],
        );
        let out = td.path().join("out");
        let base = out.clone();
        test_hooks::install(move |point| {
            if point == "before-delete-replaced" {
                let aside = fs::read_dir(&base)
                    .expect("read_dir")
                    .map(|entry| entry.expect("entry").path())
                    .find(|path| path.is_dir())
                    .expect("moved-aside directory");
                fs::write(aside.join("foreign"), b"not ours").expect("foreign");
            }
        });
        let _guard = ClearHook;

        let failure = extract_with_report(&archive, &out).expect_err("incomplete cleanup");

        assert_eq!(failure.error.status(), SarStatus::ErrAlreadyExists);
        assert_eq!(fs::read(out.join("d")).expect("published"), b"replacement");
        assert!(failure.report.partial_changes);
        assert_eq!(failure.report.cleanup_failures.len(), 1);
        let notes = failure.report.notes();
        assert!(notes[0].contains("incomplete"));
        assert!(notes[1].starts_with("cleanup error"));
        assert!(!notes[1].contains("not ours"));
        let aside = leftovers(&out);
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert_eq!(
            fs::read(Path::new(&aside[0]).join("foreign")).expect("foreign kept"),
            b"not ours"
        );
    }

    #[test]
    fn failure_restoring_final_directory_metadata_keeps_published_entries() {
        let td = tempdir().expect("tmp");
        let archive = td.path().join("a.sar");
        let mut file = fs::File::create(&archive).expect("archive file");
        let mut writer = ArchiveWriter::new(
            &mut file,
            ArchiveWriterOptions {
                with_permissions: true,
                with_path: true,
                ..Default::default()
            },
        )
        .expect("writer");
        writer
            .add_entry(EntryInput {
                permissions: Some(0o644),
                ..nested("d", "f", b"data")
            })
            .expect("file");
        writer
            .add_entry(EntryInput {
                name: "d".to_string(),
                kind: Some(sar_core::EntryKind::Directory),
                permissions: Some(0o750),
                ..Default::default()
            })
            .expect("dir");
        writer.finish().expect("finish");
        drop(file);
        let out = td.path().join("out");
        let outside = td.path().join("outside");
        fs::create_dir(&outside).expect("outside");
        let (dir, target) = (out.join("d"), outside.clone());
        test_hooks::install(move |point| {
            if point == "before-directory-open" {
                fs::rename(&dir, dir.with_file_name("d.moved")).expect("move");
                std::os::unix::fs::symlink(&target, &dir).expect("swap");
            }
        });
        let _guard = ClearHook;

        let failure = extract_archive(
            archive,
            out.clone(),
            None,
            false,
            ResourceLimits::default(),
            ExtractMetadataOptions {
                preserve_permissions: true,
                ..Default::default()
            },
        )
        .expect_err("component replaced before metadata restoration");

        assert_eq!(failure.error.status(), SarStatus::ErrPathEscape);
        assert!(failure.report.partial_changes);
        assert_eq!(fs::read(out.join("d.moved/f")).expect("kept"), b"data");
        assert!(fs::read_dir(&outside).expect("outside").next().is_none());
        assert!(leftovers(&out).is_empty());
    }
}

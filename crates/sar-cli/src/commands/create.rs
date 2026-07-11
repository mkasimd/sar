use std::{
    collections::HashSet,
    env,
    fs::{self, File},
    path::{Path, PathBuf},
};

use sar_archive::{
    ArchiveWriter, ArchiveWriterOptions, CompressionSettings, EncryptionSettings, EntryInput,
    FecSettings,
};
use sar_core::{EntryKind, SarError};
use sar_crypto::{
    ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, KmsParams, PBKDF2_PRF_HMAC_SHA256, Pbkdf2Params,
};

use crate::{
    args::{
        CreateCommandOptions, CreateMetadataOptions, EncryptionChoice, FecChoice,
        SymlinkCreatePolicy,
    },
    password::{CliKeyProvider, PASSWORD_ENV, load_password},
};

pub(crate) fn create_archive(
    input: PathBuf,
    output: PathBuf,
    options: CreateCommandOptions,
) -> Result<(), SarError> {
    let CreateCommandOptions {
        no_index,
        compression,
        encrypt,
        password,
        fec,
        metadata,
    } = options;

    validate_create_metadata_support(metadata)?;

    if encrypt.is_none() && (password.is_some() || env::var_os(PASSWORD_ENV).is_some()) {
        return Err(SarError::Malformed(
            "create only accepts passwords when --encrypt is specified",
        ));
    }

    let encryption = if let Some(choice) = encrypt {
        let password = load_password(password)?;
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|_| SarError::Internal("random salt generation failed"))?;
        let settings = EncryptionSettings {
            algo_id: encryption_to_algo_id(choice),
            kms_params: KmsParams::Pbkdf2(Pbkdf2Params {
                prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
                salt: salt.to_vec(),
                iterations: 100_000,
                derived_key_length: 32,
            }),
        };
        Some((settings, password))
    } else {
        None
    };

    let writer_options = ArchiveWriterOptions {
        no_index,
        encryption: encryption.as_ref().map(|(settings, _)| settings.clone()),
        fec: fec.map(fec_to_settings),
        sparse: false,
        with_permissions: metadata.preserve_permissions,
        with_uid_gid: metadata.preserve_owner,
        with_timestamps: metadata.preserve_times,
        with_symlinks: metadata.symlink_policy == SymlinkCreatePolicy::Archive,
        ..Default::default()
    };

    let file = File::create(output)?;
    let mut writer = match encryption {
        Some((settings, password)) => ArchiveWriter::new_with_compression_and_key_provider(
            file,
            ArchiveWriterOptions {
                encryption: Some(settings),
                ..writer_options
            },
            CompressionSettings {
                algo_id: compression.algo_id,
                level: compression.level,
            },
            Some(Box::new(CliKeyProvider::new(Some(password)))),
        )?,
        None => ArchiveWriter::new_with_compression(
            file,
            writer_options,
            CompressionSettings {
                algo_id: compression.algo_id,
                level: compression.level,
            },
        )?,
    };

    let input_metadata = fs::symlink_metadata(&input)?;
    let input_name = input
        .file_name()
        .map(|name| PathBuf::from(name.to_os_string()))
        .ok_or(SarError::Malformed("input file name is missing"))?;

    if input_metadata.file_type().is_dir() {
        let canonical_root = input.canonicalize()?;
        let mut active_follow_dirs = HashSet::new();
        traverse_input_path(
            &mut writer,
            &canonical_root,
            &input,
            None,
            metadata,
            &mut active_follow_dirs,
        )?;
    } else {
        let canonical_root = if input_metadata.file_type().is_symlink() {
            input
                .canonicalize()
                .map_err(|_| SarError::Malformed("failed to resolve input symlink target"))?
        } else {
            input.clone()
        };
        let mut active_follow_dirs = HashSet::new();
        traverse_input_path(
            &mut writer,
            &canonical_root,
            &input,
            Some(&input_name),
            metadata,
            &mut active_follow_dirs,
        )?;
    }

    let summary = writer.finish()?;
    println!(
        "created archive: {} entries, indexed={} size={} bytes",
        summary.entry_count, summary.indexed, summary.archive_size
    );
    Ok(())
}

pub(crate) fn validate_create_metadata_support(
    metadata: CreateMetadataOptions,
) -> Result<(), SarError> {
    #[cfg(not(unix))]
    {
        if metadata.preserve_permissions {
            return Err(SarError::Unsupported(
                "permission preservation is only supported on Unix-like platforms",
            ));
        }
        if metadata.preserve_owner {
            return Err(SarError::Unsupported(
                "owner preservation is only supported on Unix-like platforms",
            ));
        }
        if metadata.preserve_times {
            return Err(SarError::Unsupported(
                "timestamp preservation is only supported on Unix-like platforms",
            ));
        }
    }

    #[cfg(unix)]
    let _ = metadata;

    Ok(())
}

fn traverse_input_path(
    writer: &mut ArchiveWriter<File>,
    canonical_root: &Path,
    source_path: &Path,
    archive_rel: Option<&Path>,
    metadata: CreateMetadataOptions,
    active_follow_dirs: &mut HashSet<PathBuf>,
) -> Result<(), SarError> {
    let fs_metadata = fs::symlink_metadata(source_path)?;
    let file_type = fs_metadata.file_type();

    if file_type.is_symlink() {
        return match metadata.symlink_policy {
            SymlinkCreatePolicy::Skip => Ok(()),
            SymlinkCreatePolicy::Archive => {
                add_symlink_entry(writer, source_path, archive_rel, &fs_metadata, metadata)
            }
            SymlinkCreatePolicy::Follow => add_followed_symlink(
                writer,
                canonical_root,
                source_path,
                archive_rel,
                metadata,
                active_follow_dirs,
            ),
        };
    }

    if file_type.is_dir() {
        if let Some(archive_rel) = archive_rel {
            let name = archive_name_from_path(archive_rel)?;
            writer.add_entry(build_entry_input(
                name,
                Vec::new(),
                EntryKind::Directory,
                &fs_metadata,
                metadata,
            )?)?;
        }

        let mut entries: Vec<_> = fs::read_dir(source_path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name().to_string_lossy().into_owned());

        for child in entries {
            let child_path = child.path();
            let child_rel = match archive_rel {
                Some(prefix) => prefix.join(child.file_name()),
                None => PathBuf::from(child.file_name()),
            };
            traverse_input_path(
                writer,
                canonical_root,
                &child_path,
                Some(&child_rel),
                metadata,
                active_follow_dirs,
            )?;
        }
        Ok(())
    } else if file_type.is_file() {
        let archive_rel =
            archive_rel.ok_or(SarError::Malformed("archive entry name is missing"))?;
        let name = archive_name_from_path(archive_rel)?;
        let payload = fs::read(source_path)?;
        writer.add_entry(build_entry_input(
            name,
            payload,
            EntryKind::RegularFile,
            &fs_metadata,
            metadata,
        )?)?;
        Ok(())
    } else {
        Err(SarError::Unsupported(
            "only regular files, directories, and symlinks are supported",
        ))
    }
}

fn add_symlink_entry(
    writer: &mut ArchiveWriter<File>,
    source_path: &Path,
    archive_rel: Option<&Path>,
    fs_metadata: &fs::Metadata,
    metadata: CreateMetadataOptions,
) -> Result<(), SarError> {
    let archive_rel = archive_rel.ok_or(SarError::Malformed("archive entry name is missing"))?;
    let name = archive_name_from_path(archive_rel)?;
    let target = fs::read_link(source_path)?;
    let target = target
        .to_str()
        .ok_or(SarError::Malformed("symlink target must be valid UTF-8"))?;
    writer.add_entry(build_entry_input(
        name,
        target.as_bytes().to_vec(),
        EntryKind::Symlink,
        fs_metadata,
        metadata,
    )?)?;
    Ok(())
}

fn add_followed_symlink(
    writer: &mut ArchiveWriter<File>,
    canonical_root: &Path,
    source_path: &Path,
    archive_rel: Option<&Path>,
    metadata: CreateMetadataOptions,
    active_follow_dirs: &mut HashSet<PathBuf>,
) -> Result<(), SarError> {
    let resolved = source_path
        .canonicalize()
        .map_err(|_| SarError::Malformed("failed to resolve symlink target"))?;
    if !resolved.starts_with(canonical_root) {
        return Err(SarError::Malformed(
            "refusing to follow symlink target outside the requested input root",
        ));
    }

    let target_metadata = fs::metadata(source_path)?;
    if target_metadata.file_type().is_dir() {
        if !active_follow_dirs.insert(resolved.clone()) {
            return Err(SarError::Malformed(
                "refusing to follow recursive symlink directory cycle",
            ));
        }
        let result = traverse_followed_directory(
            writer,
            canonical_root,
            &resolved,
            archive_rel,
            metadata,
            active_follow_dirs,
            &target_metadata,
        );
        active_follow_dirs.remove(&resolved);
        result
    } else if target_metadata.file_type().is_file() {
        let archive_rel =
            archive_rel.ok_or(SarError::Malformed("archive entry name is missing"))?;
        let name = archive_name_from_path(archive_rel)?;
        let payload = fs::read(source_path)?;
        writer.add_entry(build_entry_input(
            name,
            payload,
            EntryKind::RegularFile,
            &target_metadata,
            metadata,
        )?)?;
        Ok(())
    } else {
        Err(SarError::Unsupported(
            "followed symlink target is not a regular file or directory",
        ))
    }
}

fn traverse_followed_directory(
    writer: &mut ArchiveWriter<File>,
    canonical_root: &Path,
    resolved_dir: &Path,
    archive_rel: Option<&Path>,
    metadata: CreateMetadataOptions,
    active_follow_dirs: &mut HashSet<PathBuf>,
    dir_metadata: &fs::Metadata,
) -> Result<(), SarError> {
    if let Some(archive_rel) = archive_rel {
        let name = archive_name_from_path(archive_rel)?;
        writer.add_entry(build_entry_input(
            name,
            Vec::new(),
            EntryKind::Directory,
            dir_metadata,
            metadata,
        )?)?;
    }

    let mut entries: Vec<_> = fs::read_dir(resolved_dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name().to_string_lossy().into_owned());

    for child in entries {
        let child_rel = match archive_rel {
            Some(prefix) => prefix.join(child.file_name()),
            None => PathBuf::from(child.file_name()),
        };
        traverse_input_path(
            writer,
            canonical_root,
            &child.path(),
            Some(&child_rel),
            metadata,
            active_follow_dirs,
        )?;
    }
    Ok(())
}

fn archive_name_from_path(path: &Path) -> Result<String, SarError> {
    let name = path.to_string_lossy().replace('\\', "/");
    if name.is_empty() {
        return Err(SarError::Malformed("archive entry name is missing"));
    }
    Ok(name)
}

fn build_entry_input(
    name: String,
    payload: Vec<u8>,
    kind: EntryKind,
    fs_metadata: &fs::Metadata,
    metadata: CreateMetadataOptions,
) -> Result<EntryInput, SarError> {
    Ok(EntryInput {
        name,
        payload,
        kind: Some(kind),
        permissions: if metadata.preserve_permissions {
            Some(entry_permissions(fs_metadata)?)
        } else {
            None
        },
        uid_gid: if metadata.preserve_owner {
            Some(entry_owner(fs_metadata)?)
        } else {
            None
        },
        timestamps: if metadata.preserve_times {
            Some(entry_timestamps(fs_metadata)?)
        } else {
            None
        },
        ..Default::default()
    })
}

#[cfg(unix)]
fn entry_permissions(fs_metadata: &fs::Metadata) -> Result<u16, SarError> {
    use std::os::unix::fs::PermissionsExt;

    u16::try_from(fs_metadata.permissions().mode())
        .map_err(|_| SarError::Overflow("filesystem mode does not fit into SAR metadata"))
}

#[cfg(not(unix))]
fn entry_permissions(_fs_metadata: &fs::Metadata) -> Result<u16, SarError> {
    Err(SarError::Unsupported(
        "permission preservation is only supported on Unix-like platforms",
    ))
}

#[cfg(unix)]
fn entry_owner(fs_metadata: &fs::Metadata) -> Result<u32, SarError> {
    use std::os::unix::fs::MetadataExt;

    let uid = u16::try_from(fs_metadata.uid())
        .map_err(|_| SarError::Overflow("UID does not fit into SAR metadata"))?;
    let gid = u16::try_from(fs_metadata.gid())
        .map_err(|_| SarError::Overflow("GID does not fit into SAR metadata"))?;
    Ok(u32::from(uid) | (u32::from(gid) << 16))
}

#[cfg(not(unix))]
fn entry_owner(_fs_metadata: &fs::Metadata) -> Result<u32, SarError> {
    Err(SarError::Unsupported(
        "owner preservation is only supported on Unix-like platforms",
    ))
}

#[cfg(unix)]
fn entry_timestamps(fs_metadata: &fs::Metadata) -> Result<[u64; 3], SarError> {
    use std::os::unix::fs::MetadataExt;

    Ok([
        u64::try_from(fs_metadata.mtime())
            .map_err(|_| SarError::Unsupported("mtime is out of supported range"))?,
        u64::try_from(fs_metadata.atime())
            .map_err(|_| SarError::Unsupported("atime is out of supported range"))?,
        u64::try_from(fs_metadata.ctime())
            .map_err(|_| SarError::Unsupported("ctime is out of supported range"))?,
    ])
}

#[cfg(not(unix))]
fn entry_timestamps(_fs_metadata: &fs::Metadata) -> Result<[u64; 3], SarError> {
    Err(SarError::Unsupported(
        "timestamp preservation is only supported on Unix-like platforms",
    ))
}

fn fec_to_settings(fec: FecChoice) -> FecSettings {
    match fec {
        FecChoice::Xor => FecSettings::default_xor(),
        FecChoice::Rs => FecSettings::default_rs(),
    }
}

fn encryption_to_algo_id(encryption: EncryptionChoice) -> u8 {
    match encryption {
        EncryptionChoice::Aes256Gcm => ENCR_AES256_GCM,
        EncryptionChoice::XChaCha20Poly => ENCR_XCHACHA20_POLY,
    }
}

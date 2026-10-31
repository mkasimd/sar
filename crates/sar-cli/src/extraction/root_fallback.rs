// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Path-based extraction backend for non-Unix targets.
//!
//! This backend does NOT provide the descriptor-relative confinement of the
//! Unix backend. It exists to keep these targets compiling; its safety rests
//! on lexical validation plus best-effort symlink checks and is not claimed to
//! satisfy the specification's path-security requirements. Hardening it is
//! tracked separately from the Unix anchoring work.

use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use sar_core::SarError;

use crate::extraction::{
    metadata::apply_path_metadata, paths::SafeRelativePath, policy::ExtractMetadataOptions,
};

pub(crate) struct ExtractionRoot {
    path: PathBuf,
}

impl ExtractionRoot {
    pub(crate) fn open(path: &Path) -> Result<Self, SarError> {
        fs::create_dir_all(path)?;
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    fn ensure_directory(&self, components: &[String]) -> Result<PathBuf, SarError> {
        let mut current = self.path.clone();
        for component in components {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        return Err(SarError::PathEscape(
                            "refusing to traverse an existing symlink during extraction",
                        ));
                    }
                    if !metadata.is_dir() {
                        return Err(SarError::Malformed(
                            "path component exists but is not a directory",
                        ));
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&current)?;
                }
                Err(err) => return Err(SarError::Io(err)),
            }
        }
        Ok(current)
    }

    pub(crate) fn create_directory(&self, rel: &SafeRelativePath) -> Result<(), SarError> {
        self.ensure_directory(rel.components()).map(drop)
    }

    pub(crate) fn stage_file(&self, rel: &SafeRelativePath) -> Result<StagedFile, SarError> {
        let parent = self.ensure_directory(rel.parent_components())?;
        let final_path = parent.join(rel.file_name()?);
        if let Ok(existing) = fs::symlink_metadata(&final_path)
            && existing.file_type().is_dir()
        {
            return Err(SarError::Malformed(
                "refusing to replace existing directory with file output",
            ));
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| SarError::Internal("system randomness unavailable"))?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let temp_path = parent.join(format!(".sar-tmp-{suffix}"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        Ok(StagedFile {
            temp_path,
            final_path,
            file,
            published: false,
        })
    }

    pub(crate) fn create_symlink(
        &self,
        _rel: &SafeRelativePath,
        _target: &str,
    ) -> Result<(), SarError> {
        Err(SarError::Unsupported(
            "symlink extraction is only supported on Unix-like platforms",
        ))
    }

    pub(crate) fn apply_directory_metadata(
        &self,
        rel: &SafeRelativePath,
        permissions: Option<u16>,
        owner: Option<u32>,
        timestamps: Option<[u64; 3]>,
        options: ExtractMetadataOptions,
    ) -> Result<(), SarError> {
        let path = self.ensure_directory(rel.components())?;
        apply_path_metadata(&path, permissions, owner, timestamps, options)
    }
}

pub(crate) struct StagedFile {
    temp_path: PathBuf,
    final_path: PathBuf,
    file: File,
    published: bool,
}

impl StagedFile {
    pub(crate) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(crate) fn apply_metadata(
        &self,
        permissions: Option<u16>,
        owner: Option<u32>,
        timestamps: Option<[u64; 3]>,
        options: ExtractMetadataOptions,
    ) -> Result<(), SarError> {
        apply_path_metadata(&self.temp_path, permissions, owner, timestamps, options)
    }

    pub(crate) fn publish(mut self) -> Result<(), SarError> {
        fs::rename(&self.temp_path, &self.final_path)?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

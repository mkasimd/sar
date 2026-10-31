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
    cell::RefCell,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    rc::Rc,
};

use sar_core::{ResourceLimits, SarError};

use crate::extraction::{
    collision::{CollisionLedger, NodeId, ObjectId, ROOT_NODE},
    metadata::apply_path_metadata,
    paths::SafeRelativePath,
    policy::ExtractMetadataOptions,
};

/// Identity of an existing object: its canonical on-disk path, which hosts
/// with case-insensitive or normalizing filesystems report with the stored
/// spelling. Without a stable file-identity API this is a best effort; an
/// object whose identity cannot be established is not claimed.
fn object_id(path: &Path) -> Option<ObjectId> {
    fs::canonicalize(path).ok().map(ObjectId::CanonicalPath)
}

fn check_final_path(
    ledger: &RefCell<CollisionLedger>,
    path: &Path,
    node: NodeId,
) -> Result<(), SarError> {
    if fs::symlink_metadata(path).is_ok()
        && let Some(id) = object_id(path)
    {
        ledger.borrow().check(node, &id)?;
    }
    Ok(())
}

pub(crate) struct ExtractionRoot {
    path: PathBuf,
    ledger: Rc<RefCell<CollisionLedger>>,
}

impl ExtractionRoot {
    pub(crate) fn open(path: &Path, limits: ResourceLimits) -> Result<Self, SarError> {
        fs::create_dir_all(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            ledger: Rc::new(RefCell::new(CollisionLedger::new(limits))),
        })
    }

    fn ensure_directory(&self, components: &[String]) -> Result<(PathBuf, NodeId), SarError> {
        self.walk(components, true)
    }

    fn walk(&self, components: &[String], claim: bool) -> Result<(PathBuf, NodeId), SarError> {
        let mut current = self.path.clone();
        let mut node = ROOT_NODE;
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
            if claim && let Some(id) = object_id(&current) {
                let mut ledger = self.ledger.borrow_mut();
                ledger.check_candidate(node, component, &id)?;
                node = ledger.child(node, component)?;
                ledger.claim(node, id)?;
            }
        }
        Ok((current, node))
    }

    pub(crate) fn create_directory(&self, rel: &SafeRelativePath) -> Result<(), SarError> {
        self.ensure_directory(rel.components()).map(drop)
    }

    pub(crate) fn stage_file(&self, rel: &SafeRelativePath) -> Result<StagedFile, SarError> {
        let (parent, parent_node) = self.ensure_directory(rel.parent_components())?;
        let final_path = parent.join(rel.file_name()?);
        if fs::symlink_metadata(&final_path).is_ok()
            && let Some(id) = object_id(&final_path)
        {
            self.ledger
                .borrow()
                .check_candidate(parent_node, rel.file_name()?, &id)?;
        }
        let node = self
            .ledger
            .borrow_mut()
            .child(parent_node, rel.file_name()?)?;
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
            ledger: Rc::clone(&self.ledger),
            node,
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
        let (path, _) = self.walk(rel.components(), false)?;
        apply_path_metadata(&path, permissions, owner, timestamps, options)
    }
}

pub(crate) struct StagedFile {
    temp_path: PathBuf,
    final_path: PathBuf,
    ledger: Rc<RefCell<CollisionLedger>>,
    node: NodeId,
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
        check_final_path(&self.ledger, &self.final_path, self.node)?;
        // The identity the published object will have is predicted from the
        // canonical parent so capacity is reserved before the rename.
        let predicted = self
            .final_path
            .parent()
            .zip(self.final_path.file_name())
            .and_then(|(parent, name)| fs::canonicalize(parent).ok().map(|dir| dir.join(name)))
            .map(ObjectId::CanonicalPath);
        let reservation = match predicted.as_ref() {
            Some(id) => Some(self.ledger.borrow_mut().reserve(self.node, id)?),
            None => None,
        };
        if let Err(err) = fs::rename(&self.temp_path, &self.final_path) {
            if let Some(reservation) = reservation {
                self.ledger.borrow_mut().release(reservation);
            }
            return Err(err.into());
        }
        self.published = true;
        if let (Some(reservation), Some(predicted)) = (reservation, predicted) {
            // Prefer the observed spelling when it fits the reservation.
            let id = object_id(&self.final_path)
                .filter(|actual| actual.accounted_bytes() <= predicted.accounted_bytes())
                .unwrap_or(predicted);
            self.ledger.borrow_mut().commit(self.node, id, reservation);
        }
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

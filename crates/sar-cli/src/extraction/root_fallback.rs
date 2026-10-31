// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed extraction backend for targets without a secure backend.
//!
//! SAR extraction confinement (specification Section 22.4) is only implemented
//! with the Unix directory-descriptor-relative backend. This target has none,
//! and no path-based substitute can meet Section 22.4, so every extraction is
//! refused before the destination is touched. `ExtractionRoot` and
//! `StagedFile` are uninhabited: no value of either type can exist, which
//! makes a silent insecure fallback unrepresentable. A future Windows backend
//! needs a separately scoped secure implementation and native validation.

use std::{convert::Infallible, fs::File, path::Path};

use sar_core::{ResourceLimits, SarError};

use crate::extraction::{
    paths::SafeRelativePath,
    policy::{ExtractMetadataOptions, require_secure_extraction_backend},
    report::ExtractionReport,
};

pub(crate) struct ExtractionRoot(Infallible);

impl ExtractionRoot {
    pub(crate) fn open(_path: &Path, _limits: ResourceLimits) -> Result<Self, SarError> {
        require_secure_extraction_backend(false)?;
        Err(SarError::Internal(
            "secure extraction backend refusal was not enforced",
        ))
    }

    pub(crate) fn failure_report(&self) -> ExtractionReport {
        match self.0 {}
    }

    pub(crate) fn ensure_no_temporary_artifacts(&self) -> Result<(), SarError> {
        match self.0 {}
    }

    pub(crate) fn create_directory(&self, _rel: &SafeRelativePath) -> Result<(), SarError> {
        match self.0 {}
    }

    pub(crate) fn stage_file(&self, _rel: &SafeRelativePath) -> Result<StagedFile, SarError> {
        match self.0 {}
    }

    pub(crate) fn create_symlink(
        &self,
        _rel: &SafeRelativePath,
        _target: &str,
    ) -> Result<(), SarError> {
        match self.0 {}
    }

    pub(crate) fn apply_directory_metadata(
        &self,
        _rel: &SafeRelativePath,
        _permissions: Option<u16>,
        _owner: Option<u32>,
        _timestamps: Option<[u64; 3]>,
        _options: ExtractMetadataOptions,
    ) -> Result<(), SarError> {
        match self.0 {}
    }
}

pub(crate) struct StagedFile(Infallible);

impl StagedFile {
    pub(crate) fn file_mut(&mut self) -> &mut File {
        match self.0 {}
    }

    pub(crate) fn apply_metadata(
        &self,
        _permissions: Option<u16>,
        _owner: Option<u32>,
        _timestamps: Option<[u64; 3]>,
        _options: ExtractMetadataOptions,
    ) -> Result<(), SarError> {
        match self.0 {}
    }

    pub(crate) fn publish(self) -> Result<(), SarError> {
        match self.0 {}
    }
}

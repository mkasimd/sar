// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_core::SarError;

// Without a secure backend extraction is refused, so these are never read.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExtractMetadataOptions {
    pub(crate) preserve_permissions: bool,
    pub(crate) preserve_times: bool,
    pub(crate) preserve_owner: bool,
    pub(crate) allow_symlinks: bool,
}

/// Whether this build has an extraction backend that satisfies the
/// specification's path-security requirements (Section 22.4).
pub(crate) const SECURE_EXTRACTION_BACKEND: bool = cfg!(unix);

/// Refuses extraction where confinement cannot be established. Section 22.4
/// requires `SAR_ERR_PATH_ESCAPE` and no mutation in that case, so this runs
/// before the destination or the archive is touched.
pub(crate) fn require_secure_extraction_backend(available: bool) -> Result<(), SarError> {
    if available {
        Ok(())
    } else {
        Err(SarError::PathEscape(
            "secure extraction is not implemented on this platform; extraction confinement cannot be established",
        ))
    }
}

#[cfg(test)]
mod tests {
    use sar_core::SarStatus;

    use super::require_secure_extraction_backend;

    #[test]
    fn missing_secure_backend_is_a_path_escape_refusal() {
        let err = require_secure_extraction_backend(false).expect_err("must refuse");
        assert_eq!(err.status(), SarStatus::ErrPathEscape);
        assert!(require_secure_extraction_backend(true).is_ok());
    }
}

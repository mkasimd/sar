use sar_core::SarError;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExtractMetadataOptions {
    pub(crate) preserve_permissions: bool,
    pub(crate) preserve_times: bool,
    pub(crate) preserve_owner: bool,
    pub(crate) allow_symlinks: bool,
}

pub(crate) fn validate_extract_metadata_support(
    metadata: ExtractMetadataOptions,
) -> Result<(), SarError> {
    #[cfg(not(unix))]
    {
        if metadata.preserve_permissions {
            return Err(SarError::Unsupported(
                "permission restoration is only supported on Unix-like platforms",
            ));
        }
        if metadata.preserve_owner {
            return Err(SarError::Unsupported(
                "owner restoration is only supported on Unix-like platforms",
            ));
        }
        if metadata.allow_symlinks {
            return Err(SarError::Unsupported(
                "symlink extraction is only supported on Unix-like platforms",
            ));
        }
    }

    #[cfg(unix)]
    let _ = metadata;

    Ok(())
}

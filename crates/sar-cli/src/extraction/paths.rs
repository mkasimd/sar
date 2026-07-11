use std::{
    fs,
    path::{Path, PathBuf},
};

use sar_core::SarError;

#[derive(Debug, Clone)]
pub(crate) struct SafeRelativePath {
    components: Vec<String>,
}

impl SafeRelativePath {
    pub(crate) fn from_components(components: Vec<String>) -> Result<Self, SarError> {
        if components.is_empty() {
            return Err(SarError::Malformed("empty paths are not allowed"));
        }
        Ok(Self { components })
    }

    pub(crate) fn file_name(&self) -> Result<&str, SarError> {
        self.components
            .last()
            .map(String::as_str)
            .ok_or(SarError::Malformed("output file name is missing"))
    }

    pub(crate) fn parent_components(&self) -> &[String] {
        if self.components.len() <= 1 {
            &[]
        } else {
            &self.components[..self.components.len() - 1]
        }
    }

    pub(crate) fn components(&self) -> &[String] {
        &self.components
    }

    pub(crate) fn to_path_buf(&self) -> PathBuf {
        self.components.iter().collect()
    }

    pub(crate) fn depth(&self) -> usize {
        self.components.len()
    }

    pub(crate) fn display(&self) -> String {
        self.components.join("/")
    }
}

pub(crate) fn validate_relative_archive_path(name: &str) -> Result<SafeRelativePath, SarError> {
    if name.is_empty() {
        return Err(SarError::Malformed("empty paths are not allowed"));
    }
    if name.starts_with("//") || name.starts_with("\\\\") {
        return Err(SarError::Malformed(
            "UNC and verbatim paths are not allowed",
        ));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(SarError::Malformed("absolute paths are not allowed"));
    }
    if name.contains('\0') || name.contains('\\') {
        return Err(SarError::Malformed(
            "backslashes and NUL bytes are not allowed in archive paths",
        ));
    }

    let mut components = Vec::new();
    for component in name.split('/') {
        if component.is_empty() {
            return Err(SarError::Malformed("empty path components are not allowed"));
        }
        if component == "." {
            return Err(SarError::Malformed(
                "current-directory path components are not allowed",
            ));
        }
        if component == ".." {
            return Err(SarError::Malformed(
                "parent directory traversal is not allowed",
            ));
        }
        if component.len() >= 2
            && component.as_bytes()[1] == b':'
            && component.as_bytes()[0].is_ascii_alphabetic()
        {
            return Err(SarError::Malformed(
                "Windows drive-prefixed paths are not allowed",
            ));
        }
        components.push(component.to_string());
    }

    SafeRelativePath::from_components(components)
}

pub(crate) fn prepare_output_file_path(
    output_dir: &Path,
    rel: &SafeRelativePath,
) -> Result<PathBuf, SarError> {
    let parent = ensure_parent_directory_path(output_dir, rel.parent_components())?;
    let out_path = parent.join(rel.file_name()?);
    if let Ok(existing) = fs::symlink_metadata(&out_path)
        && existing.file_type().is_dir()
    {
        return Err(SarError::Malformed(
            "refusing to replace existing directory with file output",
        ));
    }
    Ok(out_path)
}

pub(crate) fn ensure_safe_directory_path(
    output_dir: &Path,
    rel: &SafeRelativePath,
) -> Result<PathBuf, SarError> {
    ensure_parent_directory_path(output_dir, rel.components())
}

pub(crate) fn resolve_existing_directory_path(
    output_dir: &Path,
    rel: &SafeRelativePath,
) -> Result<PathBuf, SarError> {
    let path = ensure_parent_directory_path(output_dir, rel.components())?;
    let meta = fs::symlink_metadata(&path)?;
    if meta.file_type().is_symlink() {
        return Err(SarError::Malformed(
            "refusing to apply directory metadata through symlink",
        ));
    }
    if !meta.is_dir() {
        return Err(SarError::Malformed(
            "refusing to apply directory metadata to non-directory",
        ));
    }
    Ok(path)
}

pub(crate) fn ensure_parent_directory_path(
    output_dir: &Path,
    components: &[String],
) -> Result<PathBuf, SarError> {
    let mut current = output_dir.to_path_buf();
    for component in components {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(SarError::Malformed(
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
                create_restrictive_directory(&current)?;
            }
            Err(err) => return Err(SarError::Io(err)),
        }
    }
    Ok(current)
}

fn create_restrictive_directory(path: &Path) -> Result<(), SarError> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

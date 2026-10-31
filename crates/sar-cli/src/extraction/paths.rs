// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

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
        // Defense in depth for the descriptor-relative walk: a component must
        // be a single plain name, never a separator, "." or "..".
        if components.iter().any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.contains(['/', '\0'])
        }) {
            return Err(SarError::Malformed(
                "path components must be single plain names",
            ));
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

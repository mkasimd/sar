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
        check_plain_components(components.iter().map(String::as_str))?;
        Ok(Self { components })
    }

    #[cfg_attr(not(unix), allow(dead_code))]
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

    #[cfg_attr(not(unix), allow(dead_code))]
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

/// Rejects anything that is not a single plain name. Parent traversal and
/// separators would leave the scope (`PATH_ESCAPE`); other forms are malformed.
pub(crate) fn check_plain_components<'a>(
    components: impl IntoIterator<Item = &'a str>,
) -> Result<(), SarError> {
    for component in components {
        if component == ".." || component.contains('/') {
            return Err(SarError::PathEscape(
                "path component would leave the extraction scope",
            ));
        }
        if component.is_empty() || component == "." || component.contains('\0') {
            return Err(SarError::Malformed(
                "path components must be single plain names",
            ));
        }
    }
    Ok(())
}

/// Lexically evaluates a symbolic-link target against the link's own
/// directory without touching the filesystem. The stored target is never
/// modified. `Malformed` is reserved for undecodable target text (empty or
/// NUL-containing); a well-formed target that leaves the scope or cannot be
/// confined is `PathEscape`.
pub(crate) fn validate_symlink_target(
    link: &SafeRelativePath,
    target: &str,
) -> Result<(), SarError> {
    if target.is_empty() {
        return Err(SarError::Malformed("symlink target is empty"));
    }
    if target.contains('\0') {
        return Err(SarError::Malformed("symlink target contains a NUL byte"));
    }
    let bytes = target.as_bytes();
    if target.starts_with('/') || target.starts_with('\\') {
        return Err(SarError::PathEscape(
            "absolute symlink targets cannot be confined to the extraction scope",
        ));
    }
    if target.contains('\\') {
        return Err(SarError::PathEscape(
            "symlink targets with platform-specific separators cannot be confined",
        ));
    }
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return Err(SarError::PathEscape(
            "drive-prefixed symlink targets cannot be confined to the extraction scope",
        ));
    }
    let mut depth = link.parent_components().len();
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                depth = depth.checked_sub(1).ok_or(SarError::PathEscape(
                    "symlink target escapes the extraction scope",
                ))?;
            }
            _ => {
                depth = depth
                    .checked_add(1)
                    .ok_or(SarError::Overflow("symlink target depth"))?;
            }
        }
    }
    Ok(())
}

/// Joins the encoded LFH Path String and Name String into the Full Logical
/// Entry Path (specification Section 6.1.5) without altering either field:
/// an absent or empty Path String yields the Name String, otherwise
/// `Path/Name`. A Name String that is empty or contains `/` is malformed, so
/// distinct (Path, Name) pairs can never compose to the same text. Every other
/// field-level rule is enforced on the composed path.
pub(crate) fn full_logical_entry_path(
    path: Option<&str>,
    name: &str,
) -> Result<SafeRelativePath, SarError> {
    if name.is_empty() {
        return Err(SarError::Malformed("LFH Name String is empty"));
    }
    if name.contains('/') {
        return Err(SarError::Malformed(
            "LFH Name String contains a path separator",
        ));
    }
    match path.filter(|path| !path.is_empty()) {
        Some(path) => validate_relative_archive_path(&format!("{path}/{name}")),
        None => validate_relative_archive_path(name),
    }
}

/// Display form of the Full Logical Entry Path, for listings only.
pub(crate) fn display_full_path(path: Option<&str>, name: &str) -> String {
    match path.filter(|path| !path.is_empty()) {
        Some(path) => format!("{path}/{name}"),
        None => name.to_string(),
    }
}

pub(crate) fn validate_relative_archive_path(name: &str) -> Result<SafeRelativePath, SarError> {
    if name.is_empty() {
        return Err(SarError::Malformed("empty paths are not allowed"));
    }
    if name.starts_with("//") || name.starts_with("\\\\") {
        return Err(SarError::PathEscape(
            "UNC and verbatim paths are not allowed",
        ));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(SarError::PathEscape("absolute paths are not allowed"));
    }
    if name.contains('\0') {
        return Err(SarError::Malformed(
            "NUL bytes are not allowed in archive paths",
        ));
    }
    if name.contains('\\') {
        return Err(SarError::PathEscape(
            "backslashes are not allowed in archive paths",
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
            return Err(SarError::PathEscape(
                "parent directory traversal is not allowed",
            ));
        }
        if component.len() >= 2
            && component.as_bytes()[1] == b':'
            && component.as_bytes()[0].is_ascii_alphabetic()
        {
            return Err(SarError::PathEscape(
                "Windows drive-prefixed paths are not allowed",
            ));
        }
        components.push(component.to_string());
    }

    SafeRelativePath::from_components(components)
}

#[cfg(test)]
mod tests {
    use sar_core::{SarError, SarStatus};

    use super::{validate_relative_archive_path, validate_symlink_target};

    fn link(path: &str) -> super::SafeRelativePath {
        validate_relative_archive_path(path).expect("link path")
    }

    #[test]
    fn symlink_targets_are_evaluated_lexically_from_the_link_directory() {
        let accepted = [
            ("l", "."),
            ("l", "x"),
            ("l", "sub/../ok"),
            ("a/l", "../b"),
            ("a/b/l", "../../c/d"),
            ("a/b/l", "../.."),
            ("l", "dangling/never/created"),
            ("l", "a//b/./c"),
            ("a/l", ".."),
        ];
        for (path, target) in accepted {
            validate_symlink_target(&link(path), target)
                .unwrap_or_else(|err| panic!("{path} -> {target}: {err:?}"));
        }
    }

    #[test]
    fn escaping_or_unconfinable_symlink_targets_are_path_escape() {
        let rejected = [
            ("l", ".."),
            ("l", "../x"),
            ("a/l", "../../x"),
            ("a/l", "b/../../../x"),
            ("l", "/etc/passwd"),
            ("l", "\\\\server\\share"),
            ("l", "a\\b"),
            ("l", "C:/x"),
            ("l", "c:x"),
        ];
        for (path, target) in rejected {
            let err = validate_symlink_target(&link(path), target).expect_err(target);
            assert_eq!(err.status(), SarStatus::ErrPathEscape, "{path} -> {target}");
        }
    }

    #[test]
    fn undecodable_symlink_targets_remain_malformed() {
        for target in ["", "a\0b"] {
            let err = validate_symlink_target(&link("l"), target).expect_err("malformed");
            assert!(matches!(err, SarError::Malformed(_)), "{target:?}");
        }
    }

    #[test]
    fn entry_path_classification() {
        for name in ["../x", "a/../x", "/abs", "//unc", "C:/x", "a\\b"] {
            let err = validate_relative_archive_path(name).expect_err(name);
            assert_eq!(err.status(), SarStatus::ErrPathEscape, "{name}");
        }
        for name in ["", "a//b", "./a", "a/./b", "a\0b"] {
            let err = validate_relative_archive_path(name).expect_err(name);
            assert_eq!(err.status(), SarStatus::ErrMalformed, "{name:?}");
        }
    }
}

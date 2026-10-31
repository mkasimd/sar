// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#[cfg(unix)]
pub(crate) mod collision;
pub(crate) mod metadata;
pub(crate) mod paths;
pub(crate) mod policy;
pub(crate) mod report;
#[cfg(not(unix))]
#[path = "root_fallback.rs"]
pub(crate) mod root;
#[cfg(unix)]
#[path = "root_unix.rs"]
pub(crate) mod root;
pub(crate) mod staging;

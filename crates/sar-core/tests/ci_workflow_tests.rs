// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

#[test]
fn ci_workflow_is_pull_request_only() {
    let workflow = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml");
    let content = fs::read_to_string(workflow).expect("workflow file");
    assert!(content.contains("pull_request"));
    assert!(!content.contains("\npush:"));
}

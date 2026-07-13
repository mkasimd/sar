// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

use sar_crypto::aad::{build_aead_aad, global_header_aad_bytes};

#[test]
fn global_header_aad_bytes_layout() {
    let bytes = global_header_aad_bytes(b"SAR!", 1, &[1, 2, 3, 4]);
    assert_eq!(bytes, vec![83, 65, 82, 33, 1, 0, 4, 0, 1, 2, 3, 4]);
}

#[test]
fn build_aead_aad_concatenates_sections() {
    assert_eq!(build_aead_aad(b"abc", b"def"), b"abcdef");
}

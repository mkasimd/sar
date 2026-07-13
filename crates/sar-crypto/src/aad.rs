// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

/// Build the global-header AAD section.
///
/// Layout: `magic(4) + version(1) + reserved(1) + flags_size(2) + flags_bytes(flags_size)`.
pub fn global_header_aad_bytes(magic: &[u8; 4], version: u8, flags_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + flags_bytes.len());
    out.extend_from_slice(magic);
    out.push(version);
    out.push(0x00);
    let flags_size = flags_bytes.len() as u16;
    out.extend_from_slice(&flags_size.to_le_bytes());
    out.extend_from_slice(flags_bytes);
    out
}

/// Build entry AEAD AAD bytes.
///
/// Layout: `global_flags_section || lfh_bytes`.
pub fn build_aead_aad(global_flags_section: &[u8], lfh_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(global_flags_section.len() + lfh_bytes.len());
    out.extend_from_slice(global_flags_section);
    out.extend_from_slice(lfh_bytes);
    out
}

// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

/// Build the 12-byte fixed prefix of a Global Header (magic, version, reserved,
/// flags size, flags).
///
/// This is **not** the Entry AEAD AAD prefix: Section 13.2.1 binds the complete
/// encoded Global Header.  Use the raw encoded header bytes with
/// [`build_aead_aad`] instead.
pub fn global_header_aad_bytes(magic: &[u8; 4], version: u8, flags_bytes: &[u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(magic);
    out.push(version);
    out.push(0x00);
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(flags_bytes);
    out
}

/// Build entry AEAD AAD bytes (specification Section 13.2.1).
///
/// Layout: `encoded_global_header || encoded_lfh`, where
///
/// * `encoded_global_header` is the complete Global Header exactly as encoded,
///   from byte zero to immediately before the first LFH (including the full
///   KMS Extension), and
/// * `encoded_lfh` is the LFH bytes from `Header Size` through the end of the
///   header, with only the conditional `FEC Size` / `FEC Value` exclusion
///   applied by the caller.
///
/// Neither input is reconstructed or normalized here.
pub fn build_aead_aad(encoded_global_header: &[u8], lfh_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded_global_header.len() + lfh_bytes.len());
    out.extend_from_slice(encoded_global_header);
    out.extend_from_slice(lfh_bytes);
    out
}

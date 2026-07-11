//! Vector generator for `test-vectors/`.
//!
//! Generates binary `.sar` fixture files for conformance testing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example generate_vectors -p sar-archive
//! ```
//!
//! The generator writes fixtures to `test-vectors/` relative to the workspace
//! root. It is **idempotent**: running it again overwrites existing fixtures
//! with identical bytes (generation is deterministic).
//!
//! # Generated fixtures
//!
//! See `test-vectors/README.md` for the full vector inventory.
//!
//! # Determinism
//!
//! All fixtures use fixed salts, iteration counts, and payloads so that the
//! output is bit-for-bit reproducible across builds on the same platform. The
//! AEAD nonces are derived from a fixed seed rather than `getrandom` to ensure
//! reproducibility.
//!
//! Crypto fixtures use test-only passwords and keys. **Do not use for real
//! data.**

#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::path::{Path, PathBuf};

use sar_archive::{
    ArchiveRecoverySettings, ArchiveWriter, ArchiveWriterOptions, CompressionSettings,
    DeltaWriteOptions, EncryptionSettings, EntryInput, FecSettings,
};
use sar_compression::{COMP_ALGO_DEFLATE, COMP_ALGO_STORE, COMP_ALGO_ZSTD};
use sar_core::{
    CDC_ALGO_LITERAL, EntryKind, GlobalFlags, SparseExtent,
    format::{
        CentralDictionary, Footer, GlobalHeader, LocalFileHeader, parse_central_dictionary,
        parse_footer, parse_global_header, parse_lfh, write_central_dictionary, write_footer,
        write_global_header, write_lfh,
    },
    tlv::Tlv,
};
use sar_crypto::{
    ENCR_AES256_GCM, ENCR_XCHACHA20_POLY, KmsContext, KmsParams, PBKDF2_PRF_HMAC_SHA256,
    SecretBytes, SecretString, error::SarCryptoError, kms::types::Pbkdf2Params,
    provider::KeyProvider,
};
use sar_delta::{
    PATCH_ALGO_BSDIFF, PATCH_ALGO_CUSTOM_MIN, PATCH_ALGO_STORE_PATCH, PATCH_ALGO_VCDIFF,
    PatchAlgoId,
};
use sar_fec::{FEC_ALGO_REED_SOLOMON, FEC_ALGO_XOR};

// ---------------------------------------------------------------------------
// Test password / key material (TEST-ONLY — do not use for real data)
// ---------------------------------------------------------------------------

const TEST_PASSWORD_AES: &str = "sar-test-password-aes";
const TEST_PASSWORD_XCHACHA: &str = "sar-test-password-xchacha";
const DELTA_VECTOR_PAYLOAD_LEN: usize = 64;
const ZERO_DELTA_BASE_HASH: [u8; 32] = [0u8; 32];
const PROMOTED_DELTA_BASE_HASH_WORD_0: u64 = 0x_bdaa_cafe_dead_beef_u64;
const PROMOTED_DELTA_BASE_HASH_WORD_1: u64 = 0x_1234_5678_9abc_def0_u64;

/// Fixed 32-byte salt for all PBKDF2 derivations in test vectors.
/// This is TEST-ONLY material.
const TEST_SALT_AES: [u8; 32] = [
    0x73, 0x61, 0x72, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x61, 0x65, 0x73, 0x2d, 0x73, 0x61, 0x6c,
    0x74, 0x2d, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

const TEST_SALT_XCHACHA: [u8; 32] = [
    0x73, 0x61, 0x72, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x78, 0x63, 0x68, 0x61, 0x63, 0x68, 0x61,
    0x2d, 0x73, 0x61, 0x6c, 0x74, 0x2d, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// ---------------------------------------------------------------------------
// Key provider for test vectors
// ---------------------------------------------------------------------------

struct StaticPasswordProvider {
    password: SecretString,
}

impl KeyProvider for StaticPasswordProvider {
    fn password_for(&self, _ctx: &KmsContext) -> Result<Option<SecretString>, SarCryptoError> {
        Ok(Some(self.password.clone()))
    }

    fn unwrap_key(
        &self,
        _ctx: &KmsContext,
        _wrapped: &[u8],
    ) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }

    fn external_key(&self, _ctx: &KmsContext) -> Result<Option<SecretBytes>, SarCryptoError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Helper: write bytes to a file under the vectors root
// ---------------------------------------------------------------------------

fn vectors_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    // crates/sar-archive → workspace root
    let workspace = Path::new(&manifest_dir)
        .parent()
        .expect("crates/")
        .parent()
        .expect("workspace root");
    workspace.join("test-vectors")
}

fn write_fixture(relative_path: &str, bytes: &[u8]) {
    let root = vectors_root();
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create dir");
    }
    std::fs::write(&path, bytes).expect("write fixture");
    println!("wrote {}", path.display());
}

fn skip_deferred_vector(relative_path: &str, reason: &str) {
    println!(
        "skipped {} ({reason})",
        vectors_root().join(relative_path).display()
    );
}

fn make_promoted_delta_base_hash() -> [u8; 32] {
    let mut base_hash = ZERO_DELTA_BASE_HASH;
    let first_word_end = std::mem::size_of::<u64>();
    let second_word_end = first_word_end + std::mem::size_of::<u64>();
    base_hash[..first_word_end].copy_from_slice(&PROMOTED_DELTA_BASE_HASH_WORD_0.to_le_bytes());
    base_hash[first_word_end..second_word_end]
        .copy_from_slice(&PROMOTED_DELTA_BASE_HASH_WORD_1.to_le_bytes());
    base_hash
}

// ---------------------------------------------------------------------------
// Generator helpers
// ---------------------------------------------------------------------------

fn make_payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i & 0xFF) as u8).collect()
}

fn write_store_archive(no_index: bool, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index,
            ..Default::default()
        },
    )
    .unwrap();
    for (name, payload) in entries {
        writer
            .add_entry(EntryInput::file(*name, payload.to_vec()))
            .unwrap();
    }
    writer.finish().unwrap();
    buf
}

fn write_compressed_archive(algo_id: u8, no_index: bool, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression(
        &mut buf,
        ArchiveWriterOptions {
            no_index,
            ..Default::default()
        },
        CompressionSettings {
            algo_id,
            level: None,
        },
    )
    .unwrap();
    for (name, payload) in entries {
        writer
            .add_entry(EntryInput::file(*name, payload.to_vec()))
            .unwrap();
    }
    writer.finish().unwrap();
    buf
}

fn write_encrypted_archive(algo_id: u8, salt: &[u8], password: &str, payload: &[u8]) -> Vec<u8> {
    let kms_params = KmsParams::Pbkdf2(Pbkdf2Params {
        prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
        salt: salt.to_vec(),
        iterations: 100_000,
        derived_key_length: 32,
    });
    let opts = ArchiveWriterOptions {
        no_index: false,
        encryption: Some(EncryptionSettings {
            algo_id,
            kms_params,
        }),
        ..Default::default()
    };
    let key_provider: Box<dyn KeyProvider> = Box::new(StaticPasswordProvider {
        password: SecretString::new(password.to_string()),
    });
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
        Cursor::new(&mut buf),
        opts,
        CompressionSettings::store(),
        Some(key_provider),
    )
    .unwrap();
    writer
        .add_entry(EntryInput::file("secret.bin", payload.to_vec()))
        .unwrap();
    writer.finish().unwrap();
    buf
}

fn write_fec_archive(fec: FecSettings, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: false,
            fec: Some(fec),
            ..Default::default()
        },
    )
    .unwrap();
    writer
        .add_entry(EntryInput::file("data.bin", payload.to_vec()))
        .unwrap();
    writer.finish().unwrap();
    buf
}

fn write_archive_recovery_archive(recovery: ArchiveRecoverySettings, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut buf,
        ArchiveWriterOptions {
            no_index: false,
            archive_recovery: Some(recovery),
            ..Default::default()
        },
    )
    .unwrap();
    writer
        .add_entry(EntryInput::file("data.bin", payload.to_vec()))
        .unwrap();
    writer.finish().unwrap();
    buf
}

fn mutate_global_flags(archive: &[u8], mutate: impl FnOnce(GlobalFlags) -> GlobalFlags) -> Vec<u8> {
    let mut out = archive.to_vec();
    let flags_size = usize::from(u16::from_le_bytes([out[6], out[7]]));
    let flags_start = 8usize;
    let flags_end = flags_start + flags_size;
    let mut low = [0u8; 4];
    low.copy_from_slice(&out[flags_start..flags_start + 4]);
    let flags = GlobalFlags::from_bits_truncate(u32::from_le_bytes(low));
    let updated = mutate(flags).bits().to_le_bytes();
    out[flags_start..flags_start + 4].copy_from_slice(&updated);
    debug_assert!(flags_end <= out.len());
    out
}

fn mutate_first_lfh(
    archive: &[u8],
    mutate: impl FnOnce(&mut LocalFileHeader),
) -> Result<Vec<u8>, String> {
    let limits = sar_core::ResourceLimits::default();
    let (gh, gh_len) = parse_global_header(archive, &limits)
        .map_err(|err| format!("parse global header: {err}"))?;
    let (mut lfh, lfh_len) = parse_lfh(&archive[gh_len..], &gh.flags, &limits)
        .map_err(|err| format!("parse lfh: {err}"))?;
    mutate(&mut lfh);
    let new_lfh = write_lfh(&gh.flags, &lfh).map_err(|err| format!("write lfh: {err}"))?;
    if new_lfh.len() != lfh_len {
        return Err("mutated LFH length changed unexpectedly".to_string());
    }
    let mut out = Vec::with_capacity(archive.len());
    out.extend_from_slice(&archive[..gh_len]);
    out.extend_from_slice(&new_lfh);
    out.extend_from_slice(&archive[gh_len + lfh_len..]);
    Ok(out)
}

fn mutate_indexed_recovery_tlvs(
    archive: &[u8],
    mutate: impl FnOnce(&mut Vec<Tlv>),
) -> Result<Vec<u8>, String> {
    let limits = sar_core::ResourceLimits::default();
    let (gh, _) = parse_global_header(archive, &limits)
        .map_err(|err| format!("parse global header: {err}"))?;
    if gh.flags.contains(GlobalFlags::NO_INDEX) {
        return Err("expected indexed archive".to_string());
    }
    if archive.len() < 8 {
        return Err("indexed archive too short for footer".to_string());
    }
    let footer =
        parse_footer(&archive[archive.len() - 8..]).map_err(|err| format!("footer: {err}"))?;
    let cd_start = usize::try_from(footer.cd_offset).map_err(|_| "cd offset usize".to_string())?;
    let cd_end = archive.len() - 8;
    if cd_start >= cd_end {
        return Err("cd offset out of range".to_string());
    }
    let (mut cd, _) = parse_central_dictionary(&archive[cd_start..cd_end], gh.flags, &limits)
        .map_err(|err| format!("parse central dictionary: {err}"))?;
    mutate(&mut cd.metadata);
    let rebuilt_cd = write_central_dictionary(
        &CentralDictionary {
            version: cd.version,
            file_count: cd.file_count,
            partition_info: cd.partition_info,
            global_crc32: cd.global_crc32,
            metadata: cd.metadata,
            offsets: cd.offsets,
        },
        gh.flags,
    )
    .map_err(|err| format!("write central dictionary: {err}"))?;
    let mut out = Vec::with_capacity(cd_start + rebuilt_cd.len() + 8);
    out.extend_from_slice(&archive[..cd_start]);
    out.extend_from_slice(&rebuilt_cd);
    out.extend_from_slice(&write_footer(Footer {
        cd_offset: footer.cd_offset,
    }));
    Ok(out)
}

fn mutate_first_recovery_tlv_type_raw(archive: &[u8], new_type_id: u8) -> Result<Vec<u8>, String> {
    let limits = sar_core::ResourceLimits::default();
    let (gh, _) = parse_global_header(archive, &limits)
        .map_err(|err| format!("parse global header: {err}"))?;
    if gh.flags.contains(GlobalFlags::NO_INDEX) {
        return Err("expected indexed archive".to_string());
    }
    if !gh.flags.contains(GlobalFlags::OPT_PRESENT) {
        return Err("expected OPT_PRESENT metadata".to_string());
    }
    if archive.len() < 8 {
        return Err("indexed archive too short for footer".to_string());
    }
    let footer =
        parse_footer(&archive[archive.len() - 8..]).map_err(|err| format!("footer: {err}"))?;
    let cd_start = usize::try_from(footer.cd_offset).map_err(|_| "cd offset usize".to_string())?;
    let cd_end = archive.len() - 8;
    let mut out = archive.to_vec();
    let mut cursor = cd_start + 8; // CD version + reserved
    cursor += if gh.flags.contains(GlobalFlags::SIZE_64BIT) {
        8
    } else {
        4
    };
    if gh.flags.contains(GlobalFlags::PARTITIONED_ARCHIVE) {
        cursor += 4;
    }
    if gh.flags.contains(GlobalFlags::HAS_GLOBAL_CRC32) {
        cursor += 4;
    }
    if cursor + 4 > cd_end {
        return Err("central dictionary metadata length field out of range".to_string());
    }
    let meta_size = u32::from_le_bytes(
        out[cursor..cursor + 4]
            .try_into()
            .map_err(|_| "metadata length decode".to_string())?,
    ) as usize;
    let meta_start = cursor + 4;
    if meta_size == 0 || meta_start >= cd_end {
        return Err("central dictionary metadata is empty".to_string());
    }
    out[meta_start] = new_type_id;
    Ok(out)
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut buf = Vec::new();
    while value > 0 {
        buf.push((value & 0x7F) as u8);
        value >>= 7;
    }
    buf.reverse();
    let last = buf.len() - 1;
    for byte in &mut buf[..last] {
        *byte |= 0x80;
    }
    buf
}

fn vcdiff_add_only_patch(add_data: &[u8]) -> Vec<u8> {
    let mut inst = Vec::new();
    inst.push(0x01);
    inst.extend_from_slice(&encode_varint(
        u64::try_from(add_data.len()).expect("add len"),
    ));

    let twl = encode_varint(u64::try_from(add_data.len()).expect("target len"));
    let mut body = Vec::new();
    body.extend_from_slice(&twl);
    body.push(0x00);
    body.extend_from_slice(&encode_varint(
        u64::try_from(add_data.len()).expect("add_run len"),
    ));
    body.extend_from_slice(&encode_varint(u64::try_from(inst.len()).expect("inst len")));
    body.extend_from_slice(&encode_varint(0));
    body.extend_from_slice(add_data);
    body.extend_from_slice(&inst);

    let mut patch = Vec::new();
    patch.extend_from_slice(b"\xD6\xC3\xC4\x00");
    patch.push(0x00);
    patch.push(0x00);
    patch.extend_from_slice(&encode_varint(u64::try_from(body.len()).expect("body len")));
    patch.extend_from_slice(&body);
    patch
}

fn encode_bsdiff_int(value: i64) -> [u8; 8] {
    let magnitude = value.unsigned_abs();
    let sign_bit: u8 = if value < 0 { 0x80 } else { 0x00 };
    let mut bytes = magnitude.to_le_bytes();
    bytes[7] = (bytes[7] & 0x7F) | sign_bit;
    bytes
}

fn bsdiff_single_triple_patch(base: &[u8], target: &[u8]) -> Vec<u8> {
    let diff: Vec<u8> = (0..target.len())
        .map(|i| target[i].wrapping_sub(base.get(i).copied().unwrap_or(0)))
        .collect();
    let ctrl = [
        encode_bsdiff_int(i64::try_from(target.len()).expect("target len")),
        encode_bsdiff_int(0),
        encode_bsdiff_int(0),
    ]
    .concat();
    let mut patch = Vec::new();
    patch.extend_from_slice(b"SARBSD01");
    patch.extend_from_slice(&encode_bsdiff_int(
        i64::try_from(ctrl.len()).expect("ctrl len"),
    ));
    patch.extend_from_slice(&encode_bsdiff_int(
        i64::try_from(diff.len()).expect("diff len"),
    ));
    patch.extend_from_slice(&encode_bsdiff_int(
        i64::try_from(target.len()).expect("new size"),
    ));
    patch.extend_from_slice(&ctrl);
    patch.extend_from_slice(&diff);
    patch
}

fn write_manual_delta_archive(
    name: &str,
    patch_algo_id: u8,
    delta_base_hash: [u8; 32],
    declared_uncompressed_size: u64,
    patch_payload: &[u8],
) -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
    let gh = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    let mut archive = write_global_header(&gh).expect("write global header");
    let mut lfh =
        LocalFileHeader::minimal_store(name.as_bytes().to_vec(), declared_uncompressed_size);
    lfh.patch_algo_id = Some(patch_algo_id);
    lfh.delta_base_hash = Some(delta_base_hash);
    lfh.payload_size = u64::try_from(patch_payload.len()).expect("patch payload len");
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("write lfh"));
    archive.extend_from_slice(patch_payload);
    archive
}

// ---------------------------------------------------------------------------
// Stream transcript helpers and constants
// ---------------------------------------------------------------------------

/// Fixed Stream ID used in all stream transcript fixtures.
const STREAM_ID_PRIMARY: u16 = 0x0042;

/// Fixed session UUID used in all stream transcript fixtures.
const SESSION_UUID_PRIMARY: [u8; 16] = [
    0x42, 0xde, 0xad, 0xbe, 0xef, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
];

/// Session flags with no bidirectional control/stream bits set.
const SESSION_FLAGS_NONE: u16 = 0x0000;

/// Session flags with reserved bits set — wire-invalid.
const SESSION_FLAGS_RESERVED: u16 = 0xff00;

/// Capability flags for a peer that advertises SESSION_ACK only.
const CAP_FLAGS_SESSION_ACK: u16 = 0x0001;

/// Stream transcript SESSION_INIT entry opcode index.
const SESSION_OPCODE_INIT: u8 = 0x0;
/// Stream transcript SESSION_HEARTBEAT entry opcode index.
const SESSION_OPCODE_HEARTBEAT: u8 = 0x3;
/// Stream transcript SESSION_CAPABILITIES entry opcode index.
const SESSION_OPCODE_CAPABILITIES: u8 = 0x7;
/// A reserved session opcode (must be 0x8..=0xF per spec).
const SESSION_OPCODE_RESERVED: u8 = 0x08;

/// Expected SESSION_INIT payload length in bytes.
const SESSION_INIT_PAYLOAD_LEN: usize = 18;

/// Intentionally wrong SESSION_INIT payload length used for the
/// bad-session-init-payload-length fixture.
const SESSION_INIT_BAD_PAYLOAD_LEN: usize = 5;

/// Intentionally wrong stream ID used for the wrong-stream-id fixture.
const STREAM_ID_WRONG: u16 = 0x0099;

/// Sequence number used for the sequence-wrap fixture (wraps from 0xFFFF → 0x0000).
const SEQUENCE_NO_WRAP_BEFORE_INIT: u16 = 0xFFFE;

/// Small DATA_WRITE payload used in ordered-data and sequence-wrap fixtures.
const DATA_PAYLOAD: &[u8] = b"test-data";

/// Heartbeat payload used in the heartbeat-with-payload invalid fixture.
const HEARTBEAT_BAD_PAYLOAD: &[u8] = b"bad";

/// Builds a SAR Global Header with NO_INDEX set (required for stream transcripts).
fn make_stream_global_header() -> Vec<u8> {
    let flags = GlobalFlags::NO_INDEX;
    let header = GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    };
    write_global_header(&header).unwrap()
}

/// Serializes a SESSION_INIT payload (16-byte UUID + 2-byte flags LE).
fn make_session_init_payload(uuid: [u8; 16], flags: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SESSION_INIT_PAYLOAD_LEN);
    payload.extend_from_slice(&uuid);
    payload.extend_from_slice(&flags.to_le_bytes());
    payload
}

/// Serializes a SESSION_CAPABILITIES payload (2-byte flags LE).
fn make_session_capabilities_payload(flags: u16) -> Vec<u8> {
    flags.to_le_bytes().to_vec()
}

/// Builds one LFH + payload blob for a SESSION_CONTROL entry.
/// `opcode` occupies bits [11:8] of entry_mode; SESSION_CONTROL bit 13 is always set.
fn make_session_control_lfh_and_payload(
    stream_id: u16,
    sequence_no: u16,
    opcode: u8,
    payload: Vec<u8>,
) -> Vec<u8> {
    let global_flags = GlobalFlags::NO_INDEX;
    let entry_mode_bits =
        (u16::from(opcode) << 8) | sar_core::EntryMode::SESSION_CONTROL;
    let payload_len = payload.len() as u64;
    let mut lfh = LocalFileHeader::minimal_store(b"ctl".to_vec(), payload_len);
    lfh.stream_id = stream_id;
    lfh.sequence_no = sequence_no;
    lfh.entry_mode = sar_core::EntryMode::from_bits(entry_mode_bits);
    lfh.payload_size = payload_len;
    lfh.uncompressed_size = payload_len;
    let mut out = write_lfh(&global_flags, &lfh).unwrap();
    out.extend_from_slice(&payload);
    out
}

/// Builds one LFH + payload blob for a DATA_WRITE filesystem entry.
fn make_fs_data_write_lfh_and_payload(
    stream_id: u16,
    sequence_no: u16,
    payload: &[u8],
) -> Vec<u8> {
    let global_flags = GlobalFlags::NO_INDEX;
    // OP_CODE=0x0 (DATA_WRITE), no SESSION_CONTROL bit
    let entry_mode_bits: u16 = 0x0000;
    let payload_len = payload.len() as u64;
    let mut lfh = LocalFileHeader::minimal_store(b"data".to_vec(), payload_len);
    lfh.stream_id = stream_id;
    lfh.sequence_no = sequence_no;
    lfh.entry_mode = sar_core::EntryMode::from_bits(entry_mode_bits);
    lfh.payload_size = payload_len;
    lfh.uncompressed_size = payload_len;
    let mut out = write_lfh(&global_flags, &lfh).unwrap();
    out.extend_from_slice(payload);
    out
}

/// Generates all stream transcript conformance fixtures.
fn generate_stream_transcript_vectors() {
    // ------------------------------------------------------------------
    // Valid: session-init
    // A minimal transcript: Global Header + one SESSION_INIT entry.
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        write_fixture("valid/stream-session/session-init/stream_session_init.sar", &bytes);
    }

    // ------------------------------------------------------------------
    // Valid: session-capabilities
    // SESSION_INIT followed by SESSION_CAPABILITIES.
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            1,
            SESSION_OPCODE_CAPABILITIES,
            make_session_capabilities_payload(CAP_FLAGS_SESSION_ACK),
        ));
        write_fixture(
            "valid/stream-session/session-capabilities/stream_session_capabilities.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Valid: ordered-data
    // SESSION_INIT followed by two DATA_WRITE entries.
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_PRIMARY,
            1,
            DATA_PAYLOAD,
        ));
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_PRIMARY,
            2,
            DATA_PAYLOAD,
        ));
        write_fixture(
            "valid/stream-session/ordered-data/stream_ordered_data.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Valid: heartbeat
    // SESSION_INIT followed by a SESSION_HEARTBEAT (zero-length payload).
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            1,
            SESSION_OPCODE_HEARTBEAT,
            Vec::new(),
        ));
        write_fixture(
            "valid/stream-session/heartbeat/stream_heartbeat.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Valid: sequence-wrap
    // SESSION_INIT at 0xFFFE, DATA at 0xFFFF, DATA at 0x0000 (wrap).
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            SEQUENCE_NO_WRAP_BEFORE_INIT,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0xFFFF,
            DATA_PAYLOAD,
        ));
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0x0000,
            DATA_PAYLOAD,
        ));
        write_fixture(
            "valid/stream-session/sequence-wrap/stream_sequence_wrap.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: data-before-session-init
    // A DATA_WRITE entry before any SESSION_INIT — no active session.
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            DATA_PAYLOAD,
        ));
        write_fixture(
            "invalid/stream-session/data-before-session-init/data_before_session_init.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: duplicate-session-init
    // Two SESSION_INIT entries for the same Stream ID without SESSION_CLOSE.
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            1,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        write_fixture(
            "invalid/stream-session/duplicate-session-init/duplicate_session_init.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: bad-session-init-payload-length
    // A SESSION_INIT entry with a truncated 5-byte payload (must be 18).
    // ------------------------------------------------------------------
    {
        let short_payload = vec![0x42u8; SESSION_INIT_BAD_PAYLOAD_LEN];
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            short_payload,
        ));
        write_fixture(
            "invalid/stream-session/bad-session-init-payload-length/bad_session_init_payload_length.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: reserved-session-init-flags
    // A SESSION_INIT entry with reserved flag bits set in the flags field.
    // ------------------------------------------------------------------
    {
        let reserved_flags_payload =
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_RESERVED);
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            reserved_flags_payload,
        ));
        write_fixture(
            "invalid/stream-session/reserved-session-init-flags/reserved_session_init_flags.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: sequence-gap
    // SESSION_INIT at seq=0, DATA at seq=2 (skips seq=1).
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_PRIMARY,
            2, // gap: seq=1 was skipped
            DATA_PAYLOAD,
        ));
        write_fixture(
            "invalid/stream-session/sequence-gap/sequence_gap.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: sequence-replay
    // SESSION_INIT at seq=0, DATA at seq=1, DATA at seq=1 again (replay).
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_PRIMARY,
            1,
            DATA_PAYLOAD,
        ));
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_PRIMARY,
            1, // replay of seq=1
            DATA_PAYLOAD,
        ));
        write_fixture(
            "invalid/stream-session/sequence-replay/sequence_replay.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: wrong-stream-id
    // SESSION_INIT for STREAM_ID_PRIMARY, then DATA for STREAM_ID_WRONG
    // (no session for that stream ID).
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_fs_data_write_lfh_and_payload(
            STREAM_ID_WRONG,
            0, // no session for STREAM_ID_WRONG
            DATA_PAYLOAD,
        ));
        write_fixture(
            "invalid/stream-session/wrong-stream-id/wrong_stream_id.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: heartbeat-with-payload
    // SESSION_HEARTBEAT with a non-empty payload (must be zero-length).
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            1,
            SESSION_OPCODE_HEARTBEAT,
            HEARTBEAT_BAD_PAYLOAD.to_vec(),
        ));
        write_fixture(
            "invalid/stream-session/heartbeat-with-payload/heartbeat_with_payload.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Invalid: reserved-session-opcode
    // SESSION_INIT followed by an entry with a reserved opcode (0x08..=0x0F).
    // ------------------------------------------------------------------
    {
        let mut bytes = make_stream_global_header();
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            0,
            SESSION_OPCODE_INIT,
            make_session_init_payload(SESSION_UUID_PRIMARY, SESSION_FLAGS_NONE),
        ));
        bytes.extend_from_slice(&make_session_control_lfh_and_payload(
            STREAM_ID_PRIMARY,
            1,
            SESSION_OPCODE_RESERVED,
            Vec::new(),
        ));
        write_fixture(
            "invalid/stream-session/reserved-session-opcode/reserved_session_opcode.sar",
            &bytes,
        );
    }

    // ------------------------------------------------------------------
    // Deferred: session-control-without-no-index
    // SESSION_INIT in an indexed archive — current implementation treats
    // it as inactive (StatefulInactive), not an error.
    // ------------------------------------------------------------------
    skip_deferred_vector(
        "invalid/stream-session/session-control-without-no-index/",
        "current implementation treats SESSION_CONTROL in non-NO_INDEX archive as \
         StatefulInactive (SAR_OK), not SAR_ERR_STREAM_STATE; deferred pending \
         spec clarification on strict rejection",
    );

    // ------------------------------------------------------------------
    // Deferred: zero-stream-id
    // SESSION_INIT with stream_id=0 — current implementation treats it as
    // inactive (StatefulInactive), not an error.
    // ------------------------------------------------------------------
    skip_deferred_vector(
        "invalid/stream-session/zero-stream-id/",
        "current implementation treats stream_id=0 SESSION_INIT as StatefulInactive \
         (SAR_OK), not SAR_ERR_STREAM_STATE; deferred pending spec clarification",
    );
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn main() {
    // -----------------------------------------------------------------------
    // Valid: minimal
    // -----------------------------------------------------------------------

    let minimal_no_index = write_store_archive(true, &[("hello.txt", b"Hello, SAR!")]);
    write_fixture(
        "valid/minimal/store-no-index/minimal_store_no_index.sar",
        &minimal_no_index,
    );

    let minimal_indexed = write_store_archive(false, &[("hello.txt", b"Hello, SAR!")]);
    write_fixture(
        "valid/indexed/store-indexed/indexed_store.sar",
        &minimal_indexed,
    );

    let no_index_two = write_store_archive(
        true,
        &[
            ("first.txt", b"first entry payload"),
            ("second.txt", b"second entry payload"),
        ],
    );
    write_fixture(
        "valid/no-index/two-entries/no_index_two_entries.sar",
        &no_index_two,
    );

    // -----------------------------------------------------------------------
    // Valid: 32-bit and 64-bit LFH size layout
    // -----------------------------------------------------------------------

    let size_32bit = write_store_archive(false, &[("file.bin", &make_payload(128))]);
    write_fixture("valid/minimal/size-32bit/lfh_32bit_size.sar", &size_32bit);

    // Force64 writes 64-bit size fields.
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                lfh_size_field_policy: sar_archive::LfhSizeFieldPolicy::Force64,
                ..Default::default()
            },
        )
        .unwrap();
        writer
            .add_entry(EntryInput::file("file.bin", make_payload(128)))
            .unwrap();
        writer.finish().unwrap();
        write_fixture("valid/minimal/size-64bit/lfh_64bit_size.sar", &buf);
    }

    // -----------------------------------------------------------------------
    // Valid: compression
    // -----------------------------------------------------------------------

    let payload = b"The quick brown fox jumps over the lazy dog. ".repeat(64);
    let store_bytes = write_compressed_archive(COMP_ALGO_STORE, false, &[("doc.txt", &payload)]);
    write_fixture("valid/compression/store/store_entry.sar", &store_bytes);

    let deflate_bytes =
        write_compressed_archive(COMP_ALGO_DEFLATE, false, &[("doc.txt", &payload)]);
    write_fixture(
        "valid/compression/deflate/deflate_entry.sar",
        &deflate_bytes,
    );

    let zstd_bytes = write_compressed_archive(COMP_ALGO_ZSTD, false, &[("doc.txt", &payload)]);
    write_fixture("valid/compression/zstd/zstd_entry.sar", &zstd_bytes);

    // -----------------------------------------------------------------------
    // Valid: crypto
    // -----------------------------------------------------------------------

    let crypto_payload = make_payload(256);

    let aes_bytes = write_encrypted_archive(
        ENCR_AES256_GCM,
        &TEST_SALT_AES,
        TEST_PASSWORD_AES,
        &crypto_payload,
    );
    write_fixture("valid/crypto/aes256-gcm/aes256_gcm_entry.sar", &aes_bytes);

    let xchacha_bytes = write_encrypted_archive(
        ENCR_XCHACHA20_POLY,
        &TEST_SALT_XCHACHA,
        TEST_PASSWORD_XCHACHA,
        &crypto_payload,
    );
    write_fixture(
        "valid/crypto/xchacha20-poly1305/xchacha20_poly1305_entry.sar",
        &xchacha_bytes,
    );

    // -----------------------------------------------------------------------
    // Invalid: bad AEAD tag — derived from AES-GCM vector by flipping tag
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Invalid: bad AEAD tag — NO_INDEX encrypted archive with corrupted AEAD tag
    // -----------------------------------------------------------------------

    {
        // Use a NO_INDEX encrypted archive so the file ends with the AEAD
        // authentication tag (ciphertext || 16-byte tag). Corrupting the last
        // 16 bytes then triggers SAR_ERR_AUTH_FAILED on decryption.
        let kms_params = KmsParams::Pbkdf2(Pbkdf2Params {
            prf_algo_id: PBKDF2_PRF_HMAC_SHA256,
            salt: TEST_SALT_AES.to_vec(),
            iterations: 100_000,
            derived_key_length: 32,
        });
        let opts = ArchiveWriterOptions {
            no_index: true, // NO_INDEX so file ends with payload (AEAD tag)
            encryption: Some(EncryptionSettings {
                algo_id: ENCR_AES256_GCM,
                kms_params,
            }),
            ..Default::default()
        };
        let key_provider: Box<dyn KeyProvider> = Box::new(StaticPasswordProvider {
            password: SecretString::new(TEST_PASSWORD_AES.to_string()),
        });
        let mut aes_no_index = Vec::new();
        let mut writer = ArchiveWriter::new_with_compression_and_key_provider(
            Cursor::new(&mut aes_no_index),
            opts,
            CompressionSettings::store(),
            Some(key_provider),
        )
        .unwrap();
        writer
            .add_entry(EntryInput::file("secret.bin", crypto_payload.to_vec()))
            .unwrap();
        writer.finish().unwrap();

        let mut bad_tag = aes_no_index;
        if bad_tag.len() >= 16 {
            let len = bad_tag.len();
            // In a NO_INDEX AES-256-GCM archive the file layout is:
            //   global_header | LFH | ciphertext (plaintext_len bytes) | AEAD tag (16 bytes)
            // Because there is no Central Dictionary or Footer (NO_INDEX), the last
            // 16 bytes of the file are always the AES-GCM authentication tag.
            // Flipping them causes AEAD decryption to return an authentication error.
            for b in bad_tag[len - 16..].iter_mut() {
                *b ^= 0xFF;
            }
        }
        write_fixture("invalid/crypto/bad-aead-tag/bad_aead_tag.sar", &bad_tag);
    }

    // -----------------------------------------------------------------------
    // Valid: FEC
    // -----------------------------------------------------------------------

    let fec_payload = make_payload(512);
    let xor_bytes = write_fec_archive(FecSettings::default_xor(), &fec_payload);
    write_fixture("valid/fec/xor/xor_fec_entry.sar", &xor_bytes);

    let rs_bytes = write_fec_archive(FecSettings::default_rs(), &fec_payload);
    write_fixture("valid/fec/rs/rs_fec_entry.sar", &rs_bytes);

    let archive_recovery_xor_bytes = write_archive_recovery_archive(
        ArchiveRecoverySettings {
            algo_id: FEC_ALGO_XOR,
            config0: 1,
            config1: 0,
            symbol_size: 0,
        },
        &make_payload(1024),
    );
    write_fixture(
        "valid/recovery/archive-xor/recovery_tlv_archive_xor.sar",
        &archive_recovery_xor_bytes,
    );

    let archive_recovery_rs_bytes = write_archive_recovery_archive(
        ArchiveRecoverySettings {
            algo_id: FEC_ALGO_REED_SOLOMON,
            config0: 4,
            config1: 2,
            symbol_size: 256,
        },
        &make_payload(1024),
    );
    write_fixture(
        "valid/recovery/archive-rs/recovery_tlv_archive_rs.sar",
        &archive_recovery_rs_bytes,
    );

    // -----------------------------------------------------------------------
    // Valid: fragmentation — valid contiguous two-fragment group
    // -----------------------------------------------------------------------

    // Fragmentation vectors remain deferred in this corrective pass. Do not
    // emit placeholder STORE archives that overclaim fragment metadata.
    skip_deferred_vector(
        "valid/fragmentation/valid-reassembly/fragmented_two_parts.sar",
        "real fragment-group fixtures require the streaming writer path",
    );
    skip_deferred_vector(
        "valid/fragmentation/loss-tolerant-gap/fragmented_loss_tolerant_gap.sar",
        "real LOSS_TOLERANT fragment-gap fixtures require fragment metadata and degraded reassembly behavior",
    );

    // -----------------------------------------------------------------------
    // Valid: sparse
    // -----------------------------------------------------------------------

    {
        // Sparse file with two extents: [0..32) and [64..96), logical size 128.
        let extents = vec![
            SparseExtent {
                offset: 0,
                length: 32,
            },
            SparseExtent {
                offset: 64,
                length: 32,
            },
        ];
        let gathered = make_payload(64); // 32 + 32 bytes of data

        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                sparse: true,
                ..Default::default()
            },
        )
        .unwrap();

        writer
            .write_sparse_entry(
                "sparse.bin",
                &gathered,
                sar_archive::SparseWriteOptions {
                    logical_size: 128,
                    extents,
                },
            )
            .unwrap();
        writer.finish().unwrap();
        write_fixture("valid/sparse/simple/sparse_simple.sar", &buf);
    }

    // Sparse + delta ordering remains reference-only in this corrective pass.
    // Do not emit a STORE fallback that lacks combined sparse + patch metadata.
    skip_deferred_vector(
        "valid/sparse/with-delta/sparse_with_store_patch.sar",
        "real sparse-plus-delta fixtures require combined patch and sparse metadata on one logical entry",
    );

    // -----------------------------------------------------------------------
    // Valid: CDC
    // -----------------------------------------------------------------------

    // CDC requires the CDC_SUPPORT global flag and CDC algo ID in LFH.
    // Use the streaming writer / raw format helper since ArchiveWriter does
    // not yet expose CDC directly. Write a minimal CDC Literal Mode archive
    // using the raw write_lfh path.
    {
        let payload = make_payload(DELTA_VECTOR_PAYLOAD_LEN);

        // GlobalFlags with CDC_SUPPORT
        let flags = GlobalFlags::NO_INDEX | GlobalFlags::CDC_SUPPORT;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let mut archive = write_global_header(&gh).unwrap();

        // Minimal LFH with the CDC literal-mode algorithm ID.
        let mut lfh = sar_core::format::LocalFileHeader::minimal_store(
            b"cdc_literal.bin".to_vec(),
            payload.len() as u64,
        );
        lfh.cdc_algo_id = Some(CDC_ALGO_LITERAL);

        archive.extend_from_slice(&write_lfh(&flags, &lfh).unwrap());
        archive.extend_from_slice(&payload);

        write_fixture("valid/cdc/literal-mode/cdc_literal_entry.sar", &archive);
    }

    // FASTCDC CDC_MAP remains deferred in this corrective pass. Do not reuse the
    // literal-mode archive as a placeholder.
    skip_deferred_vector(
        "valid/cdc/fastcdc-metadata/cdc_fastcdc_map.sar",
        "real FASTCDC CDC_MAP fixtures require explicit CDC metadata rather than literal-mode fallback bytes",
    );

    // -----------------------------------------------------------------------
    // Valid: delta — STORE_PATCH
    // -----------------------------------------------------------------------

    {
        let target = make_payload(DELTA_VECTOR_PAYLOAD_LEN);

        let flags = GlobalFlags::NO_INDEX | GlobalFlags::HAS_DELTA;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let mut archive = write_global_header(&gh).unwrap();

        let mut lfh =
            LocalFileHeader::minimal_store(b"store_patch.bin".to_vec(), target.len() as u64);
        lfh.patch_algo_id = Some(PATCH_ALGO_STORE_PATCH);
        lfh.delta_base_hash = Some(ZERO_DELTA_BASE_HASH);

        archive.extend_from_slice(&write_lfh(&flags, &lfh).unwrap());
        archive.extend_from_slice(&target);

        write_fixture("valid/delta/store-patch/store_patch_entry.sar", &archive);
    }

    // -----------------------------------------------------------------------
    // Valid: delta — VCDIFF
    // -----------------------------------------------------------------------

    {
        let base = make_payload(DELTA_VECTOR_PAYLOAD_LEN);
        let target: Vec<u8> = make_payload(DELTA_VECTOR_PAYLOAD_LEN)
            .into_iter()
            .map(|b| b.wrapping_add(1))
            .collect();

        // Delta base hash: non-zero opaque identity (SHA-256 of the base bytes
        // used by the reader to locate the base object; treated as opaque here).
        let base_hash = make_promoted_delta_base_hash();

        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: true,
                with_delta: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("vcdiff_target.bin", target);
        entry.delta = Some(DeltaWriteOptions {
            algorithm: PatchAlgoId::Vcdiff,
            base: base.clone(),
            delta_base_hash: base_hash,
        });
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();

        write_fixture("valid/delta/vcdiff/vcdiff_patch_entry.sar", &buf);
        write_fixture("valid/delta/vcdiff/base_file.bin", &base);
    }

    // -----------------------------------------------------------------------
    // Valid: delta — BSDIFF
    // -----------------------------------------------------------------------

    {
        let base = make_payload(DELTA_VECTOR_PAYLOAD_LEN);
        let target: Vec<u8> = make_payload(DELTA_VECTOR_PAYLOAD_LEN)
            .into_iter()
            .map(|b| b.wrapping_add(1))
            .collect();

        let base_hash = make_promoted_delta_base_hash();

        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: true,
                with_delta: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("bsdiff_target.bin", target);
        entry.delta = Some(DeltaWriteOptions {
            algorithm: PatchAlgoId::Bsdiff,
            base: base.clone(),
            delta_base_hash: base_hash,
        });
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();

        write_fixture("valid/delta/bsdiff/bsdiff_patch_entry.sar", &buf);
        write_fixture("valid/delta/bsdiff/base_file.bin", &base);
    }

    // -----------------------------------------------------------------------
    // Valid: filesystem metadata
    // -----------------------------------------------------------------------

    // Permissions
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_permissions: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("protected.txt", b"content".to_vec());
        entry.permissions = Some(0o644);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/permissions/permissions_entry.sar",
            &buf,
        );
    }

    // Owner (UID=1000, GID=1000)
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_uid_gid: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("owned.txt", b"content".to_vec());
        entry.uid_gid = Some((1000u32) | (1000u32 << 16));
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture("valid/filesystem-metadata/owner/owner_entry.sar", &buf);
    }

    // Timestamps (fixed deterministic values: Unix epoch + 1_700_000_000)
    {
        const FIXED_TIME: u64 = 1_700_000_000;
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_timestamps: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("timestamped.txt", b"content".to_vec());
        entry.timestamps = Some([FIXED_TIME, FIXED_TIME, FIXED_TIME]);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/timestamps/timestamps_entry.sar",
            &buf,
        );
    }

    // Symlink entry
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_symlinks: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("link_name", b"target_file.txt".to_vec());
        entry.kind = Some(EntryKind::Symlink);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture("valid/filesystem-metadata/symlink/symlink_entry.sar", &buf);
    }

    // Directory entry
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("subdir/", b"".to_vec());
        entry.kind = Some(EntryKind::Directory);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/directory/directory_entry.sar",
            &buf,
        );
    }

    // Combined: permissions + owner + timestamps
    {
        const FIXED_TIME: u64 = 1_700_000_000;
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_permissions: true,
                with_uid_gid: true,
                with_timestamps: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = EntryInput::file("full_meta.txt", b"content".to_vec());
        entry.permissions = Some(0o644);
        entry.uid_gid = Some((1000u32) | (1000u32 << 16));
        entry.timestamps = Some([FIXED_TIME, FIXED_TIME, FIXED_TIME]);
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/combined/combined_meta_entry.sar",
            &buf,
        );
    }

    // Field presence: HAS_PATH set but zero-length path (PresentInactive)
    {
        let mut buf = Vec::new();
        let mut writer = ArchiveWriter::new(
            &mut buf,
            ArchiveWriterOptions {
                no_index: false,
                with_path: true,
                ..Default::default()
            },
        )
        .unwrap();
        // path = None → PresentInactive (HAS_PATH set, zero-length path field)
        let entry = EntryInput::file("no_path_set.txt", b"content".to_vec());
        writer.add_entry(entry).unwrap();
        writer.finish().unwrap();
        write_fixture(
            "valid/filesystem-metadata/field-presence-inactive/field_presence_inactive.sar",
            &buf,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: structure — truncated Global Header
    // -----------------------------------------------------------------------

    // Valid SAR magic + truncated before version field.
    let truncated_gh: Vec<u8> = b"SAR!".to_vec(); // magic only, no version/flags
    write_fixture(
        "invalid/structure/truncated-gh/truncated_global_header.sar",
        &truncated_gh,
    );

    // Truncated LFH: valid global header + partial LFH (missing name/payload).
    {
        let flags = GlobalFlags::NO_INDEX;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let mut truncated_lfh = write_global_header(&gh).unwrap();
        // LFH Header Size = 17 (marker), then truncate.
        truncated_lfh.extend_from_slice(&17u32.to_le_bytes());
        // Stop here: the LFH is incomplete.
        write_fixture(
            "invalid/structure/truncated-lfh/truncated_lfh.sar",
            &truncated_lfh,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: wrong magic bytes
    // -----------------------------------------------------------------------

    {
        let valid = write_store_archive(true, &[("x.txt", b"x")]);
        let mut bad_magic = valid.clone();
        bad_magic[0] = 0x00;
        bad_magic[1] = 0x00;
        bad_magic[2] = 0x00;
        bad_magic[3] = 0x00;
        write_fixture(
            "invalid/structure/invalid-magic/invalid_magic.sar",
            &bad_magic,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: unknown global flags
    // -----------------------------------------------------------------------

    {
        // Set the upper 16 bits of the flags to all-ones (reserved).
        let mut bad_flags = write_store_archive(true, &[("x.txt", b"x")]);
        // Flags are at offset: magic(4) + version(1) + padding(1) + flags_size(2) = offset 8.
        // flags_size is typically 4 bytes; flags are at bytes 8..12.
        // Set bytes 10 and 11 (upper 16 bits of 32-bit flags) to 0xFF.
        if bad_flags.len() > 12 {
            bad_flags[10] = 0xFF;
            bad_flags[11] = 0xFF;
        }
        write_fixture(
            "invalid/flags/unknown-global-flag/unknown_global_flag.sar",
            &bad_flags,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: unsupported compression algorithm
    // -----------------------------------------------------------------------

    {
        // Build a valid NO_INDEX archive then set an unsupported compression algo byte.
        // COMPRESSED flag must be set; entry mode IS_COMPRESSED must also be set;
        // compression algo ID set to 0xFE (custom/unsupported range).

        let flags = GlobalFlags::NO_INDEX | GlobalFlags::COMPRESSED;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: None,
        };
        let mut archive = write_global_header(&gh).unwrap();

        let payload = b"compressed payload";
        let mut lfh =
            LocalFileHeader::minimal_store(b"compressed.bin".to_vec(), payload.len() as u64);
        // Set IS_COMPRESSED entry mode bit so the reader uses the compression path.
        lfh.entry_mode = sar_core::flags::EntryMode::from_bits(
            lfh.entry_mode.bits() | sar_core::flags::EntryMode::COMPRESSED,
        );
        lfh.comp_algo_id = Some(0xFE); // unsupported custom range

        archive.extend_from_slice(&write_lfh(&flags, &lfh).unwrap());
        archive.extend_from_slice(payload);

        write_fixture(
            "invalid/algorithms/unsupported-compression/unsupported_compression.sar",
            &archive,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: unsupported encryption algorithm
    // -----------------------------------------------------------------------

    {
        // Build a valid NO_INDEX encrypted archive structure with a KMS using
        // the correct minimum iterations, but set an unsupported encr_algo_id
        // in the LFH. The global header parses OK; the entry is rejected at
        // the encr_algo_id validation step with SAR_ERR_UNSUPPORTED.
        let flags = GlobalFlags::NO_INDEX | GlobalFlags::ENCRYPTED;
        let gh = GlobalHeader {
            version: 1,
            flags_bytes: flags.bits().to_le_bytes().to_vec(),
            flags,
            partition_descriptor: None,
            kms: Some(sar_core::format::KmsData {
                mode_id: 0x01, // PBKDF2
                payload: {
                    // Minimal KMS payload: PRF=1, salt_len=16, salt(16), iterations(4), dklen(2)
                    let mut p = vec![0x01u8, 0x10]; // PRF ID + salt_len
                    p.extend_from_slice(&[0xAAu8; 16]); // salt
                    p.extend_from_slice(&100_000u32.to_le_bytes()); // iterations >= 100,000
                    p.extend_from_slice(&32u16.to_le_bytes()); // dklen
                    p
                },
            }),
        };
        let mut archive = write_global_header(&gh).unwrap();

        let payload = b"encrypted payload";
        let mut lfh =
            LocalFileHeader::minimal_store(b"encrypted.bin".to_vec(), payload.len() as u64);
        // Set IS_ENCRYPTED entry mode so reader enters the encryption path.
        lfh.entry_mode = sar_core::flags::EntryMode::from_bits(
            lfh.entry_mode.bits() | sar_core::flags::EntryMode::ENCRYPTED,
        );
        lfh.encr_algo_id = Some(0xFE); // unsupported custom encryption algorithm

        archive.extend_from_slice(&write_lfh(&flags, &lfh).unwrap());
        archive.extend_from_slice(payload);

        write_fixture(
            "invalid/algorithms/unsupported-crypto/unsupported_crypto.sar",
            &archive,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: archive-level recovery metadata and flag states
    // -----------------------------------------------------------------------

    {
        let baseline_xor = write_archive_recovery_archive(
            ArchiveRecoverySettings {
                algo_id: FEC_ALGO_XOR,
                config0: 1,
                config1: 0,
                symbol_size: 0,
            },
            &make_payload(1024),
        );

        let has_global_ec_without_opt_present = mutate_global_flags(&baseline_xor, |flags| {
            (flags | GlobalFlags::HAS_GLOBAL_EC) & !GlobalFlags::OPT_PRESENT
        });
        write_fixture(
            "invalid/recovery/has-global-ec-without-opt-present/has_global_ec_without_opt_present.sar",
            &has_global_ec_without_opt_present,
        );

        let no_index_with_global_ec =
            mutate_global_flags(&baseline_xor, |flags| flags | GlobalFlags::NO_INDEX);
        write_fixture(
            "invalid/recovery/no-index-with-global-ec/no_index_with_global_ec.sar",
            &no_index_with_global_ec,
        );

        let recovery_tlv_without_global_ec = mutate_global_flags(&baseline_xor, |flags| {
            (flags | GlobalFlags::OPT_PRESENT) & !GlobalFlags::HAS_GLOBAL_EC
        });
        write_fixture(
            "invalid/recovery/recovery-tlv-without-global-ec/recovery_tlv_without_global_ec.sar",
            &recovery_tlv_without_global_ec,
        );

        let truncated_recovery_tlv = mutate_indexed_recovery_tlvs(&baseline_xor, |metadata| {
            for tlv in metadata {
                if tlv.type_id == FEC_ALGO_XOR && !tlv.value.is_empty() {
                    tlv.value.pop();
                    break;
                }
            }
        })
        .expect("truncate recovery tlv");
        write_fixture(
            "invalid/recovery/truncated-recovery-tlv/truncated_recovery_tlv.sar",
            &truncated_recovery_tlv,
        );

        let reserved_recovery_algo = mutate_first_recovery_tlv_type_raw(&baseline_xor, 0x10)
            .expect("reserved recovery algo");
        write_fixture(
            "invalid/recovery/reserved-recovery-algo/reserved_recovery_algo.sar",
            &reserved_recovery_algo,
        );

        let malformed_xor_recovery = mutate_indexed_recovery_tlvs(&baseline_xor, |metadata| {
            for tlv in metadata {
                if tlv.type_id == FEC_ALGO_XOR && !tlv.value.is_empty() {
                    tlv.value[0] = 0x00;
                    break;
                }
            }
        })
        .expect("malformed xor recovery");
        write_fixture(
            "invalid/recovery/zero-block-size/zero_block_size_recovery.sar",
            &malformed_xor_recovery,
        );
    }

    {
        let baseline_rs = write_archive_recovery_archive(
            ArchiveRecoverySettings {
                algo_id: FEC_ALGO_REED_SOLOMON,
                config0: 4,
                config1: 2,
                symbol_size: 256,
            },
            &make_payload(1024),
        );

        let unsupported_recovery_algo = mutate_first_recovery_tlv_type_raw(&baseline_rs, 0x12)
            .expect("unsupported recovery algo");
        write_fixture(
            "invalid/recovery/unsupported-recovery-algo/unsupported_recovery_algo.sar",
            &unsupported_recovery_algo,
        );

        let malformed_rs_recovery = mutate_indexed_recovery_tlvs(&baseline_rs, |metadata| {
            for tlv in metadata {
                if tlv.type_id == FEC_ALGO_REED_SOLOMON && tlv.value.len() >= 2 {
                    tlv.value[1] = 0x00;
                    break;
                }
            }
        })
        .expect("malformed rs recovery");
        write_fixture(
            "invalid/recovery/inconsistent-shard-count/inconsistent_shard_count_recovery.sar",
            &malformed_rs_recovery,
        );
    }

    {
        let beyond_parity_source = write_archive_recovery_archive(
            ArchiveRecoverySettings {
                algo_id: FEC_ALGO_XOR,
                config0: 2,
                config1: 0,
                symbol_size: 0,
            },
            &make_payload(2048),
        );
        write_fixture(
            "invalid/recovery/corrupt-beyond-repair/corrupt_beyond_repair.sar",
            &beyond_parity_source,
        );
    }

    // -----------------------------------------------------------------------
    // Invalid: delta malformed/unsupported/limit vectors
    // -----------------------------------------------------------------------

    {
        let base = make_payload(DELTA_VECTOR_PAYLOAD_LEN);
        let target: Vec<u8> = make_payload(DELTA_VECTOR_PAYLOAD_LEN)
            .into_iter()
            .map(|b| b.wrapping_add(1))
            .collect();
        let base_hash = make_promoted_delta_base_hash();

        let vcdiff_patch = vcdiff_add_only_patch(&target);
        let vcdiff_archive = write_manual_delta_archive(
            "vcdiff_invalid.bin",
            PATCH_ALGO_VCDIFF,
            base_hash,
            u64::try_from(target.len()).expect("target len"),
            &vcdiff_patch,
        );
        write_fixture(
            "invalid/delta/vcdiff-output-too-large/vcdiff_output_too_large.sar",
            &vcdiff_archive,
        );
        write_fixture("invalid/delta/vcdiff-output-too-large/base_file.bin", &base);

        let mut zero_hash_vcdiff = vcdiff_archive.clone();
        zero_hash_vcdiff = mutate_first_lfh(&zero_hash_vcdiff, |lfh| {
            lfh.delta_base_hash = Some(ZERO_DELTA_BASE_HASH);
        })
        .expect("zero hash vcdiff");
        write_fixture(
            "invalid/delta/all-zero-base-hash-for-vcdiff/all_zero_base_hash_vcdiff.sar",
            &zero_hash_vcdiff,
        );

        let mut reserved_patch_algo = vcdiff_archive.clone();
        reserved_patch_algo = mutate_first_lfh(&reserved_patch_algo, |lfh| {
            lfh.patch_algo_id = Some(0x04);
        })
        .expect("reserved patch algo");
        write_fixture(
            "invalid/delta/reserved-patch-algo/reserved_patch_algo.sar",
            &reserved_patch_algo,
        );

        let mut unsupported_patch_algo = vcdiff_archive.clone();
        unsupported_patch_algo = mutate_first_lfh(&unsupported_patch_algo, |lfh| {
            lfh.patch_algo_id = Some(PATCH_ALGO_CUSTOM_MIN);
        })
        .expect("unsupported patch algo");
        write_fixture(
            "invalid/delta/unknown-patch-algo/unsupported_patch_algo.sar",
            &unsupported_patch_algo,
        );

        let mut truncated_vcdiff = vcdiff_archive.clone();
        truncated_vcdiff.pop();
        write_fixture(
            "invalid/delta/vcdiff-truncated/vcdiff_truncated_patch.sar",
            &truncated_vcdiff,
        );

        let bsdiff_patch = bsdiff_single_triple_patch(&base, &target);
        let bsdiff_archive = write_manual_delta_archive(
            "bsdiff_invalid.bin",
            PATCH_ALGO_BSDIFF,
            base_hash,
            u64::try_from(target.len()).expect("target len"),
            &bsdiff_patch,
        );
        write_fixture(
            "invalid/delta/bsdiff-control-too-large/bsdiff_control_too_large.sar",
            &bsdiff_archive,
        );
        write_fixture(
            "invalid/delta/bsdiff-control-too-large/base_file.bin",
            &base,
        );

        let mut zero_hash_bsdiff = bsdiff_archive.clone();
        zero_hash_bsdiff = mutate_first_lfh(&zero_hash_bsdiff, |lfh| {
            lfh.delta_base_hash = Some(ZERO_DELTA_BASE_HASH);
        })
        .expect("zero hash bsdiff");
        write_fixture(
            "invalid/delta/all-zero-base-hash-for-bsdiff/all_zero_base_hash_bsdiff.sar",
            &zero_hash_bsdiff,
        );

        let mut truncated_bsdiff = bsdiff_archive.clone();
        truncated_bsdiff.pop();
        write_fixture(
            "invalid/delta/bsdiff-truncated/bsdiff_truncated_patch.sar",
            &truncated_bsdiff,
        );
    }

    // -----------------------------------------------------------------------
    // Stream transcript vectors (M12a-stream-cp)
    // -----------------------------------------------------------------------

    generate_stream_transcript_vectors();

    println!("\nGeneration complete.");
    println!("Run targeted M12a conformance tests to validate.");
}

//! CLI integration tests for Stage 4 resource-safety hardening.

use std::fs;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

use sar_core::{
    GlobalFlags,
    flags::EntryMode,
    format::{
        CentralDictionary, GlobalHeader, LfhFragmentDescriptor, LocalFileHeader,
        write_central_dictionary, write_global_header, write_lfh,
    },
    sparse::{SparseExtent, write_sparse_map},
    tlv::Tlv,
};

const DEFAULT_MAX_DECODED_ENTRY_SIZE: u64 = 1024 * 1024 * 1024;

fn sar() -> Command {
    Command::cargo_bin("sar-cli").expect("sar-cli binary")
}

fn write_sparse_archive(
    dir: &tempfile::TempDir,
    name: &str,
    payload: &[u8],
    extents: &[SparseExtent],
    uncompressed_size: u64,
) -> std::path::PathBuf {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("global header");

    let sparse_map_bytes = write_sparse_map(extents, false).expect("write sparse map ok");
    let mut lfh = LocalFileHeader::minimal_store(name.as_bytes().to_vec(), payload.len() as u64);
    lfh.uncompressed_size = uncompressed_size;
    lfh.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh).expect("lfh"));
    archive.extend_from_slice(payload);

    let archive_path = dir.path().join("sparse.sar");
    fs::write(&archive_path, &archive).expect("write archive");
    archive_path
}

fn write_two_fragment_sparse_archive(
    dir: &tempfile::TempDir,
    logical_size: u64,
) -> std::path::PathBuf {
    let flags = GlobalFlags::SPARSE_FILES | GlobalFlags::FILE_FRAGMENTATION | GlobalFlags::NO_INDEX;
    let mut archive = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");

    let extents = [
        SparseExtent {
            offset: 0,
            length: 2,
        },
        SparseExtent {
            offset: logical_size - 2,
            length: 2,
        },
    ];
    let sparse_map_bytes = write_sparse_map(&extents, false).expect("write sparse map ok");

    let mut lfh0 = LocalFileHeader::minimal_store(b"frag.bin".to_vec(), 2);
    lfh0.uncompressed_size = logical_size;
    lfh0.entry_mode = EntryMode::from_bits(1u16 << 5);
    lfh0.fragment_id = Some(42);
    lfh0.fragment_index = Some(0);
    lfh0.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 0,
        fragment_size: 2,
    });
    lfh0.sparse_map = sparse_map_bytes;
    archive.extend_from_slice(&write_lfh(&flags, &lfh0).expect("lfh0"));
    archive.extend_from_slice(b"AB");

    let mut lfh1 = LocalFileHeader::minimal_store(b"frag.bin".to_vec(), 2);
    lfh1.uncompressed_size = 2;
    lfh1.entry_mode = EntryMode::from_bits((1u16 << 5) | (1u16 << 6));
    lfh1.fragment_id = Some(42);
    lfh1.fragment_index = Some(1);
    lfh1.fragment_descriptor = Some(LfhFragmentDescriptor {
        absolute_offset: 2,
        fragment_size: 2,
    });
    archive.extend_from_slice(&write_lfh(&flags, &lfh1).expect("lfh1"));
    archive.extend_from_slice(b"CD");

    let archive_path = dir.path().join("fragmented.sar");
    fs::write(&archive_path, &archive).expect("write archive");
    archive_path
}

fn build_xor_tlv_value(protected_len: u64) -> Vec<u8> {
    let stripe_size = 1u8;
    let block_size = 256u64;
    let stripe_count = protected_len.div_ceil(block_size);
    let mut value = vec![stripe_size, 0x00];
    value.extend_from_slice(&protected_len.to_le_bytes());
    value.extend_from_slice(&(u32::try_from(stripe_count).expect("stripe count")).to_le_bytes());
    value.extend(vec![
        0u8;
        usize::try_from(stripe_count * block_size)
            .expect("parity len")
    ]);
    value
}

fn write_global_ec_archive(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let flags = GlobalFlags::HAS_GLOBAL_EC | GlobalFlags::OPT_PRESENT;
    let header = write_global_header(&GlobalHeader {
        version: 1,
        flags_bytes: flags.bits().to_le_bytes().to_vec(),
        flags,
        partition_descriptor: None,
        kms: None,
    })
    .expect("header");
    let cd_offset = u64::try_from(header.len()).expect("cd offset");
    let recovery_tlv = Tlv {
        type_id: 0x14,
        value: build_xor_tlv_value(cd_offset - 8),
    };
    let cd = CentralDictionary {
        version: 1,
        file_count: 0,
        partition_info: None,
        global_crc32: None,
        metadata: vec![recovery_tlv],
        offsets: Vec::new(),
    };
    let mut archive = header;
    archive.extend_from_slice(&write_central_dictionary(&cd, flags).expect("cd"));
    archive.extend_from_slice(&u64::to_le_bytes(cd_offset));

    let archive_path = dir.path().join("global-ec.sar");
    fs::write(&archive_path, &archive).expect("write archive");
    archive_path
}

#[test]
fn huge_apparent_sparse_file_fails_by_default_without_final_output() {
    let td = tempdir().expect("tmp");
    let extents = [SparseExtent {
        offset: DEFAULT_MAX_DECODED_ENTRY_SIZE,
        length: 1,
    }];
    let archive = write_sparse_archive(
        &td,
        "huge.bin",
        b"Z",
        &extents,
        DEFAULT_MAX_DECODED_ENTRY_SIZE + 1,
    );
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
        ])
        .assert()
        .failure()
        .stderr(contains("resource-limit error"))
        .stderr(contains("SAR_ERR_LIMIT_EXCEEDED"));

    assert!(
        !out_dir.join("huge.bin").exists(),
        "final sparse output must not be created after limit failure"
    );
}

#[test]
fn sparse_expansion_bomb_limit_failure_is_reported_clearly() {
    let td = tempdir().expect("tmp");
    let extents = [SparseExtent {
        offset: 31,
        length: 1,
    }];
    let archive = write_sparse_archive(&td, "bomb.bin", b"X", &extents, 32);
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
            "--max-decoded-entry-size",
            "16",
        ])
        .assert()
        .failure()
        .stderr(contains("resource-limit error"))
        .stderr(contains("decoded entry size exceeds configured limit"));

    assert!(
        !out_dir.join("bomb.bin").exists(),
        "final output must not exist after sparse expansion-bomb failure"
    );
}

#[test]
fn fragmented_sparse_extraction_respects_fragment_span_limit() {
    let td = tempdir().expect("tmp");
    let archive = write_two_fragment_sparse_archive(&td, 16);
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
            "--max-fragment-group-span",
            "3",
        ])
        .assert()
        .failure()
        .stderr(contains("resource-limit error"))
        .stderr(contains("fragment group span exceeds configured limit"));

    assert!(
        !out_dir.join("frag.bin").exists(),
        "fragmented sparse extraction must not leave a final output file on failure"
    );
}

#[test]
fn sparse_extract_succeeds_with_small_in_memory_buffer() {
    let td = tempdir().expect("tmp");
    let extents = [SparseExtent {
        offset: 20,
        length: 4,
    }];
    let archive = write_sparse_archive(&td, "small.bin", b"DATA", &extents, 24);
    let out_dir = td.path().join("out");

    sar()
        .args([
            "extract",
            archive.to_str().expect("str"),
            out_dir.to_str().expect("str"),
            "--max-in-memory-buffer",
            "8",
            "--max-decoded-entry-size",
            "24",
        ])
        .assert()
        .success();

    let extracted = fs::read(out_dir.join("small.bin")).expect("read extracted");
    assert_eq!(extracted.len(), 24);
    assert_eq!(&extracted[..20], &[0u8; 20]);
    assert_eq!(&extracted[20..24], b"DATA");
}

#[test]
fn repair_fails_safely_when_working_set_exceeds_limit() {
    let td = tempdir().expect("tmp");
    let archive = write_global_ec_archive(&td);
    let output = td.path().join("repaired.sar");
    let erasures_file = td.path().join("erasures.json");
    fs::write(&erasures_file, br#"{"entries":[],"archive_ranges":[]}"#).expect("write erasures");

    sar()
        .args([
            "repair",
            archive.to_str().expect("str"),
            output.to_str().expect("str"),
            "--fec",
            "--erasures",
            erasures_file.to_str().expect("str"),
            "--max-repair-working-set",
            "1",
        ])
        .assert()
        .failure()
        .stderr(contains("resource-limit error"))
        .stderr(contains("SAR_ERR_LIMIT_EXCEEDED"));

    assert!(
        !output.exists(),
        "repair must not create the final output when the working set limit is exceeded"
    );
}

use std::io::Cursor;

use sar_core::{
    ArchiveReader, ArchiveReaderOptions, ArchiveWriter, ArchiveWriterOptions, EntryInput,
    GlobalFlags, LfhSizeFieldPolicy, ResourceLimits, SarError, SparseExtent, SparseWriteOptions,
    format::{parse_global_header, parse_lfh},
};

fn parse_header_and_first_lfh(bytes: &[u8]) -> (sar_core::GlobalHeader, sar_core::LocalFileHeader) {
    let limits = ResourceLimits::unlimited();
    let (header, consumed) = parse_global_header(bytes, &limits).expect("global header");
    let (lfh, _) = parse_lfh(&bytes[consumed..], &header.flags, &limits).expect("lfh");
    (header, lfh)
}

#[test]
fn no_index_archive_with_force32_uses_32bit_lfh_sizes() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            lfh_size_field_policy: LfhSizeFieldPolicy::Force32,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("a.txt", b"abc".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let (header, lfh) = parse_header_and_first_lfh(&out);
    assert!(!header.flags.contains(GlobalFlags::SIZE_64BIT));
    assert_eq!(lfh.payload_size, 3);
}

#[test]
fn no_index_archive_with_force64_sets_global_flag_and_uses_64bit_sizes() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            lfh_size_field_policy: LfhSizeFieldPolicy::Force64,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("a.txt", b"abc".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let (header, lfh) = parse_header_and_first_lfh(&out);
    assert!(header.flags.contains(GlobalFlags::SIZE_64BIT));
    assert_eq!(lfh.payload_size, 3);
}

#[test]
fn indexed_archive_with_force32_uses_32bit_lfh_sizes() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: false,
            lfh_size_field_policy: LfhSizeFieldPolicy::Force32,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("a.txt", b"abc".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let (header, lfh) = parse_header_and_first_lfh(&out);
    assert!(!header.flags.contains(GlobalFlags::SIZE_64BIT));
    assert_eq!(lfh.payload_size, 3);
}

#[test]
fn indexed_archive_with_force64_uses_64bit_lfh_sizes() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: false,
            lfh_size_field_policy: LfhSizeFieldPolicy::Force64,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("a.txt", b"abc".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let (header, lfh) = parse_header_and_first_lfh(&out);
    assert!(header.flags.contains(GlobalFlags::SIZE_64BIT));
    assert_eq!(lfh.payload_size, 3);
}

#[test]
fn auto_policy_chooses_32bit_when_sizes_fit() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            lfh_size_field_policy: LfhSizeFieldPolicy::Auto,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("a.txt", b"abc".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let (header, _) = parse_header_and_first_lfh(&out);
    assert!(!header.flags.contains(GlobalFlags::SIZE_64BIT));
}

#[test]
fn auto_policy_chooses_64bit_when_large_logical_size_seen() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            lfh_size_field_policy: LfhSizeFieldPolicy::Auto,
            ..Default::default()
        },
    )
    .expect("writer");

    writer
        .write_sparse_entry(
            "s.bin",
            b"a",
            SparseWriteOptions {
                logical_size: u64::from(u32::MAX) + 1,
                extents: vec![SparseExtent {
                    offset: 0,
                    length: 1,
                }],
            },
        )
        .expect("sparse entry");
    writer.finish().expect("finish");

    let (header, lfh) = parse_header_and_first_lfh(&out);
    assert!(header.flags.contains(GlobalFlags::SIZE_64BIT));
    assert_eq!(lfh.uncompressed_size, u64::from(u32::MAX) + 1);
}

#[test]
fn force32_policy_fails_closed_for_large_logical_size() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            sparse: true,
            lfh_size_field_policy: LfhSizeFieldPolicy::Force32,
            ..Default::default()
        },
    )
    .expect("writer");

    let err = writer
        .write_sparse_entry(
            "s.bin",
            b"a",
            SparseWriteOptions {
                logical_size: u64::from(u32::MAX) + 1,
                extents: vec![SparseExtent {
                    offset: 0,
                    length: 1,
                }],
            },
        )
        .expect_err("must fail");

    assert!(matches!(err, SarError::Overflow(_)));
}

#[test]
fn reader_rejects_64bit_payload_over_limit_before_allocation() {
    let mut out = Vec::new();
    let mut writer = ArchiveWriter::new(
        &mut out,
        ArchiveWriterOptions {
            no_index: true,
            lfh_size_field_policy: LfhSizeFieldPolicy::Force64,
            ..Default::default()
        },
    )
    .expect("writer");
    writer
        .add_entry(EntryInput::file("a.txt", b"abc".to_vec()))
        .expect("entry");
    writer.finish().expect("finish");

    let mut options = ArchiveReaderOptions::default();
    options.limits.max_in_memory_buffer = 2;

    let mut reader = ArchiveReader::with_options(Cursor::new(out), options).expect("reader");
    reader.read_global_header().expect("header");
    let err = reader.next_entry().expect_err("must fail");
    assert!(matches!(err, SarError::LimitExceeded(_)));
}

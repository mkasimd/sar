use sar_core::{ArchiveReader, ArchiveWriter, EntryInput, EntryKind, EntryMode, GlobalFlags};

#[test]
fn simple_file_roundtrip() {
    let mut writer = ArchiveWriter::new(GlobalFlags::empty());
    writer
        .add_entry(EntryInput::file("hello.txt", b"content".to_vec()))
        .unwrap();

    let mut bytes = Vec::new();
    writer.write_to(&mut bytes).unwrap();

    let mut reader = ArchiveReader::new(bytes.as_slice()).unwrap();
    let (metadata, payload) = reader.next_entry().unwrap().unwrap();

    assert_eq!(metadata.name, "hello.txt");
    assert_eq!(payload, b"content");
    assert_eq!(
        metadata.entry_mode_raw & EntryMode::KIND_MASK.bits(),
        EntryMode::KIND_FILE.bits()
    );
    assert_eq!(metadata.kind, EntryKind::RegularFile);
    assert!(reader.next_entry().unwrap().is_none());
}

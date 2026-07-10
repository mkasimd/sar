use sar_core::{ArchiveReader, ArchiveWriter, EntryInput, EntryKind, FieldPresence, GlobalFlags};

#[test]
fn directory_roundtrip() {
    let (metadata, payload) = roundtrip(GlobalFlags::empty(), EntryInput::directory("dir/"));
    assert_eq!(metadata.kind, EntryKind::Directory);
    assert!(payload.is_empty());
}

#[test]
fn symlink_roundtrip() {
    let (metadata, payload) = roundtrip(
        GlobalFlags::empty(),
        EntryInput::symlink("link", b"target".to_vec()),
    );
    assert_eq!(metadata.kind, EntryKind::Symlink);
    assert_eq!(payload, b"target");
}

#[test]
fn empty_area_roundtrip() {
    let (metadata, payload) = roundtrip(GlobalFlags::empty(), EntryInput::empty_area("reserved"));
    assert_eq!(metadata.kind, EntryKind::EmptyArea);
    assert!(payload.is_empty());
}

#[test]
fn hidden_attribute_roundtrip() {
    let mut entry = EntryInput::file("hidden.txt", Vec::new());
    entry.hidden = Some(true);
    let (metadata, _) = roundtrip(GlobalFlags::HIDDEN, entry);
    assert_eq!(metadata.hidden, FieldPresence::PresentActive(true));
}

fn roundtrip(flags: GlobalFlags, entry: EntryInput) -> (sar_core::EntryMetadata, Vec<u8>) {
    let mut writer = ArchiveWriter::new(flags);
    writer.add_entry(entry).unwrap();

    let mut bytes = Vec::new();
    writer.write_to(&mut bytes).unwrap();

    let mut reader = ArchiveReader::new(bytes.as_slice()).unwrap();
    reader.next_entry().unwrap().unwrap()
}

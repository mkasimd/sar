#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EntryTimestamp {
    pub secs: i64,
    pub nsecs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryTimestampMetadata {
    pub mtime: EntryTimestamp,
    pub atime: EntryTimestamp,
    pub ctime: EntryTimestamp,
}

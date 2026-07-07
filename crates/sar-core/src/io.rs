use crate::error::SarError;

/// Checked byte-slice parser cursor.
#[derive(Debug, Clone)]
pub struct ParseCursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> ParseCursor<'a> {
    /// Creates a new cursor.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Returns current offset.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Returns remaining bytes.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// Reads exact number of bytes.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], SarError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(SarError::Overflow("cursor advance"))?;
        if end > self.input.len() {
            return Err(SarError::Truncated("insufficient bytes"));
        }
        let out = &self.input[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Reads u8.
    pub fn read_u8(&mut self) -> Result<u8, SarError> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Reads little-endian u16.
    pub fn read_u16_le(&mut self) -> Result<u16, SarError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads little-endian u24.
    pub fn read_u24_le(&mut self) -> Result<u32, SarError> {
        let bytes = self.read_bytes(3)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]))
    }

    /// Reads little-endian u32.
    pub fn read_u32_le(&mut self) -> Result<u32, SarError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads little-endian u64.
    pub fn read_u64_le(&mut self) -> Result<u64, SarError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

/// Checked writer for little-endian fields.
#[derive(Debug, Default)]
pub struct BinaryWriter {
    buf: Vec<u8>,
}

impl BinaryWriter {
    /// Creates an empty writer buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Appends u8.
    pub fn write_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Appends little-endian u16.
    pub fn write_u16_le(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends little-endian u24.
    pub fn write_u24_le(&mut self, value: u32) -> Result<(), SarError> {
        if value > 0x00FF_FFFF {
            return Err(SarError::InvalidLength("u24 value too large"));
        }
        let bytes = value.to_le_bytes();
        self.buf.extend_from_slice(&bytes[..3]);
        Ok(())
    }

    /// Appends little-endian u32.
    pub fn write_u32_le(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends little-endian u64.
    pub fn write_u64_le(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Consumes and returns the internal bytes.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

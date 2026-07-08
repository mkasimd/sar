use crate::{
    error::SarError,
    io::{BinaryWriter, ParseCursor},
    limits::ResourceLimits,
};

/// Global metadata TLV block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv {
    /// Type ID.
    pub type_id: u8,
    /// Value bytes.
    pub value: Vec<u8>,
}

impl Tlv {
    /// Returns encoded size including type/length/padding.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let base = 1usize + 4usize + self.value.len();
        base + (8 - (base % 8)) % 8
    }
}

fn classify_type(type_id: u8) -> Result<(), SarError> {
    match type_id {
        0x00 => Err(SarError::ReservedValue("TLV type 0x00 is reserved")),
        0x01..=0x04 => Ok(()),
        // RECOVERY TLV range 0x10..=0x1F: dispatched to fec module.
        0x10..=0x1F => crate::fec::classify_recovery_tlv_id(type_id),
        0x20..=0x2F => Err(SarError::Unsupported(
            "SIGNATURE TLV not implemented in M1-M3",
        )),
        0x30..=0x3F => Ok(()),
        0x40 | 0x41 | 0x4F => Ok(()),
        0x42..=0x4E => Err(SarError::ReservedValue("reserved CDC metadata TLV type")),
        0x50..=0xFF => Err(SarError::ReservedValue("reserved TLV type")),
        _ => Ok(()),
    }
}

/// Parses a sequence of TLV blocks with 8-byte alignment.
pub fn parse_tlvs(input: &[u8], limits: &ResourceLimits) -> Result<Vec<Tlv>, SarError> {
    let mut out = Vec::new();
    let mut cursor = ParseCursor::new(input);

    while cursor.remaining() > 0 {
        limits.check_tlv_count(
            out.len()
                .checked_add(1)
                .ok_or(SarError::Overflow("TLV count"))?,
        )?;
        let start = cursor.position();
        let type_id = cursor.read_u8()?;
        classify_type(type_id)?;
        let length = cursor.read_u32_le()?;
        if length == u32::MAX {
            return Err(SarError::ReservedValue("TLV length 0xFFFFFFFF is reserved"));
        }
        let length_usize = usize::try_from(length).map_err(|_| SarError::Overflow("TLV length"))?;
        limits.check_tlv_bytes(length_usize)?;
        let value = cursor.read_bytes(length_usize)?.to_vec();

        let consumed = cursor
            .position()
            .checked_sub(start)
            .ok_or(SarError::Overflow("TLV consumed length"))?;
        let rem = consumed % 8;
        let pad = if rem == 0 {
            0
        } else {
            8usize
                .checked_sub(rem)
                .ok_or(SarError::Overflow("TLV padding"))?
        };
        if pad > 0 {
            let padding = cursor.read_bytes(pad)?;
            if padding.iter().any(|byte| *byte != 0) {
                return Err(SarError::InvalidAlignment("non-zero TLV padding"));
            }
        }

        out.push(Tlv { type_id, value });
    }

    Ok(out)
}

/// Encodes TLV blocks with 8-byte alignment padding.
pub fn write_tlvs(tlvs: &[Tlv]) -> Result<Vec<u8>, SarError> {
    let mut writer = BinaryWriter::new();
    for tlv in tlvs {
        classify_type(tlv.type_id)?;
        let length = u32::try_from(tlv.value.len())
            .map_err(|_| SarError::Overflow("TLV value too large for u32 length"))?;
        if length == u32::MAX {
            return Err(SarError::ReservedValue("TLV length 0xFFFFFFFF is reserved"));
        }

        let mut block_writer = BinaryWriter::new();
        block_writer.write_u8(tlv.type_id);
        block_writer.write_u32_le(length);
        block_writer.write_bytes(&tlv.value);
        let mut block = block_writer.into_inner();
        let pad = (8 - (block.len() % 8)) % 8;
        block.extend(std::iter::repeat_n(0u8, pad));
        writer.write_bytes(&block);
    }
    Ok(writer.into_inner())
}

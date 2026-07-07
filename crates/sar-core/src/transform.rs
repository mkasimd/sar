use std::io::{Cursor, Read, Write};

use sar_compression::{
    COMP_ALGO_STORE, CompressionError, CompressionOptions, DecompressionOptions, decode_stream,
    encode_stream,
};

use crate::SarError;

/// Streaming encoder transform abstraction.
pub trait EncoderTransform {
    /// Returns transform algorithm identifier.
    fn algorithm_id(&self) -> u8;
    /// Encodes an input stream into output stream.
    fn encode_stream(
        &mut self,
        input: &mut dyn Read,
        output: &mut dyn Write,
    ) -> Result<(), SarError>;
}

/// Streaming decoder transform abstraction.
pub trait DecoderTransform {
    /// Returns transform algorithm identifier.
    fn algorithm_id(&self) -> u8;
    /// Decodes an input stream into output stream.
    fn decode_stream(
        &mut self,
        input: &mut dyn Read,
        output: &mut dyn Write,
    ) -> Result<(), SarError>;
}

/// Compression encoder transform for milestone 4.
#[derive(Debug, Clone, Copy)]
pub struct CompressionEncoderTransform {
    /// Compression algorithm identifier.
    pub algo_id: u8,
    /// Optional compression level hint.
    pub level: Option<u8>,
}

impl EncoderTransform for CompressionEncoderTransform {
    fn algorithm_id(&self) -> u8 {
        self.algo_id
    }

    fn encode_stream(
        &mut self,
        input: &mut dyn Read,
        output: &mut dyn Write,
    ) -> Result<(), SarError> {
        encode_stream(
            self.algo_id,
            input,
            output,
            CompressionOptions { level: self.level },
        )
        .map_err(map_compression_error)
    }
}

/// Compression decoder transform for milestone 4.
#[derive(Debug, Clone, Copy)]
pub struct CompressionDecoderTransform {
    /// Compression algorithm identifier.
    pub algo_id: u8,
    /// Maximum bytes allowed in decoded output.
    pub max_output_size: u64,
}

impl DecoderTransform for CompressionDecoderTransform {
    fn algorithm_id(&self) -> u8 {
        self.algo_id
    }

    fn decode_stream(
        &mut self,
        input: &mut dyn Read,
        output: &mut dyn Write,
    ) -> Result<(), SarError> {
        decode_stream(
            self.algo_id,
            input,
            output,
            DecompressionOptions {
                max_output_size: self.max_output_size,
            },
        )
        .map_err(map_compression_error)
    }
}

/// Encoding pipeline plan for current milestone.
#[derive(Debug, Clone, Copy)]
pub struct EncodingPlan {
    /// Whether entry mode has `IS_COMPRESSED`.
    pub is_compressed: bool,
    /// Compression algorithm id from LFH field.
    pub comp_algo_id: u8,
    /// Optional algorithm level hint.
    pub compression_level: Option<u8>,
}

/// Decoding pipeline plan for current milestone.
#[derive(Debug, Clone, Copy)]
pub struct DecodingPlan {
    /// Whether entry mode has `IS_COMPRESSED`.
    pub is_compressed: bool,
    /// Compression algorithm id from LFH field.
    pub comp_algo_id: u8,
    /// Expected decoded byte size.
    pub expected_output_size: u64,
    /// Maximum allowed output size.
    pub max_output_size: u64,
}

/// Applies milestone-4 encoding pipeline (`logical -> compression/STORE`).
pub fn encode_payload(logical_payload: &[u8], plan: EncodingPlan) -> Result<Vec<u8>, SarError> {
    let algo_id = if plan.is_compressed {
        plan.comp_algo_id
    } else {
        COMP_ALGO_STORE
    };
    let mut transform = CompressionEncoderTransform {
        algo_id,
        level: plan.compression_level,
    };
    let mut input = Cursor::new(logical_payload);
    let mut encoded = Vec::new();
    transform.encode_stream(&mut input, &mut encoded)?;
    Ok(encoded)
}

/// Applies milestone-4 decoding pipeline (`encoded -> decompression/STORE`).
pub fn decode_payload(encoded_payload: &[u8], plan: DecodingPlan) -> Result<Vec<u8>, SarError> {
    let algo_id = if plan.is_compressed {
        plan.comp_algo_id
    } else {
        COMP_ALGO_STORE
    };
    let max_output = plan.expected_output_size.min(plan.max_output_size);
    if plan.expected_output_size > plan.max_output_size {
        return Err(SarError::LimitExceeded(
            "entry uncompressed size exceeds configured decode limit",
        ));
    }

    let mut transform = CompressionDecoderTransform {
        algo_id,
        max_output_size: max_output,
    };
    let mut input = Cursor::new(encoded_payload);
    let mut decoded = Vec::new();
    transform.decode_stream(&mut input, &mut decoded)?;
    Ok(decoded)
}

fn map_compression_error(error: CompressionError) -> SarError {
    match error {
        CompressionError::Io(inner) => SarError::Io(inner),
        CompressionError::Unsupported(_) => SarError::Unsupported("compression algorithm"),
        CompressionError::ReservedValue(_) => {
            SarError::ReservedValue("compression algorithm id is reserved")
        }
        CompressionError::CompressionFailed(_) => SarError::CompressionFailed("compression failed"),
        CompressionError::DecompressionFailed(_) => {
            SarError::DecompressionFailed("decompression failed")
        }
        CompressionError::LimitExceeded => SarError::LimitExceeded("decompression output limit"),
    }
}

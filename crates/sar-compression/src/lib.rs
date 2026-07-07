#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SAR compression registry and streaming encode/decode helpers.

use std::io::{self, Read, Write};

use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use thiserror::Error;

/// STORE algorithm identifier.
pub const COMP_ALGO_STORE: u8 = 0x00;
/// DEFLATE algorithm identifier.
pub const COMP_ALGO_DEFLATE: u8 = 0x01;
/// ZSTD algorithm identifier.
pub const COMP_ALGO_ZSTD: u8 = 0x02;

/// Compression algorithm mapping for SAR registry values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// Raw payload bytes.
    Store,
    /// RFC1951 deflate stream.
    Deflate,
    /// Zstandard stream.
    Zstd,
}

impl CompressionAlgorithm {
    /// Resolves a registry ID to an algorithm or a registry error.
    pub fn from_id(id: u8) -> Result<Self, CompressionError> {
        match id {
            COMP_ALGO_STORE => Ok(Self::Store),
            COMP_ALGO_DEFLATE => Ok(Self::Deflate),
            COMP_ALGO_ZSTD => Ok(Self::Zstd),
            0x03..=0x05 | 0xF0..=0xFF => Err(CompressionError::Unsupported(id)),
            _ => Err(CompressionError::ReservedValue(id)),
        }
    }

    /// Returns the wire identifier for this algorithm.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::Store => COMP_ALGO_STORE,
            Self::Deflate => COMP_ALGO_DEFLATE,
            Self::Zstd => COMP_ALGO_ZSTD,
        }
    }

    /// Human-readable algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Store => "STORE",
            Self::Deflate => "DEFLATE",
            Self::Zstd => "ZSTD",
        }
    }
}

/// Compression options for encoding.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionOptions {
    /// Optional level hint.
    pub level: Option<u8>,
}

/// Decompression options for decoding.
#[derive(Debug, Clone, Copy)]
pub struct DecompressionOptions {
    /// Hard cap for decoded bytes to prevent decompression bombs.
    pub max_output_size: u64,
}

/// Compression/decompression failures mapped by SAR core.
#[derive(Debug, Error)]
pub enum CompressionError {
    /// Raw source/sink I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Assigned but unsupported registry value.
    #[error("unsupported compression algorithm id: 0x{0:02X}")]
    Unsupported(u8),
    /// Reserved or unassigned registry value.
    #[error("reserved compression algorithm id: 0x{0:02X}")]
    ReservedValue(u8),
    /// Encoding operation failed.
    #[error("compression failed: {0}")]
    CompressionFailed(String),
    /// Decoding operation failed.
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),
    /// Decoded output exceeded configured bound.
    #[error("decoded output exceeded configured limit")]
    LimitExceeded,
}

/// Encodes an input stream to output stream using the selected algorithm.
pub fn encode_stream(
    algo_id: u8,
    input: &mut dyn Read,
    output: &mut dyn Write,
    options: CompressionOptions,
) -> Result<(), CompressionError> {
    match CompressionAlgorithm::from_id(algo_id)? {
        CompressionAlgorithm::Store => {
            io::copy(input, output)?;
            Ok(())
        }
        CompressionAlgorithm::Deflate => {
            let level = Compression::new(u32::from(options.level.unwrap_or(6).min(9)));
            let mut encoder = DeflateEncoder::new(output, level);
            io::copy(input, &mut encoder)
                .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
            encoder
                .try_finish()
                .map_err(|e| CompressionError::CompressionFailed(e.to_string()))
        }
        CompressionAlgorithm::Zstd => {
            let level = i32::from(options.level.unwrap_or(3).min(9));
            let mut encoder = zstd::stream::Encoder::new(output, level)
                .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
            io::copy(input, &mut encoder)
                .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
            encoder
                .finish()
                .map(|_| ())
                .map_err(|e| CompressionError::CompressionFailed(e.to_string()))
        }
    }
}

/// Decodes an encoded input stream to output stream with bounded output.
pub fn decode_stream(
    algo_id: u8,
    input: &mut dyn Read,
    output: &mut dyn Write,
    options: DecompressionOptions,
) -> Result<(), CompressionError> {
    match CompressionAlgorithm::from_id(algo_id)? {
        CompressionAlgorithm::Store => copy_bounded(input, output, options.max_output_size),
        CompressionAlgorithm::Deflate => {
            let mut decoder = DeflateDecoder::new(input);
            copy_bounded(&mut decoder, output, options.max_output_size).map_err(|e| match e {
                CompressionError::Io(inner) => {
                    CompressionError::DecompressionFailed(inner.to_string())
                }
                other => other,
            })
        }
        CompressionAlgorithm::Zstd => {
            let mut decoder = zstd::stream::Decoder::new(input)
                .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;
            copy_bounded(&mut decoder, output, options.max_output_size).map_err(|e| match e {
                CompressionError::Io(inner) => {
                    CompressionError::DecompressionFailed(inner.to_string())
                }
                other => other,
            })
        }
    }
}

fn copy_bounded(
    input: &mut dyn Read,
    output: &mut dyn Write,
    max_output_size: u64,
) -> Result<(), CompressionError> {
    let mut buf = [0u8; 8192];
    let mut written = 0u64;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let n_u64 = u64::try_from(n).map_err(|_| {
            CompressionError::Io(io::Error::other("chunk size conversion overflow"))
        })?;
        written = written
            .checked_add(n_u64)
            .ok_or_else(|| CompressionError::Io(io::Error::other("decoded length overflow")))?;
        if written > max_output_size {
            return Err(CompressionError::LimitExceeded);
        }
        output.write_all(&buf[..n])?;
    }
    Ok(())
}

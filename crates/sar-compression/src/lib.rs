// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! SAR compression registry and streaming encode/decode helpers.

use std::cell::Cell;
use std::io::{self, Read, Write};

use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use thiserror::Error;

/// STORE algorithm identifier.
pub const COMP_ALGO_STORE: u8 = 0x00;
/// DEFLATE algorithm identifier.
pub const COMP_ALGO_DEFLATE: u8 = 0x01;
/// ZSTD algorithm identifier.
pub const COMP_ALGO_ZSTD: u8 = 0x02;

/// Largest zstd frame window (as a power of two, 128 MiB) the decoder accepts.
///
/// This equals the libzstd streaming default and is pinned explicitly so the
/// decoder-internal window allocation stays bounded independently of
/// [`DecompressionOptions::max_output_size`]. Frames that declare a larger window
/// fail with [`CompressionError::DecompressionFailed`].
pub const ZSTD_MAX_WINDOW_LOG: u32 = 27;

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
///
/// # Memory
///
/// `max_output_size` bounds only the number of decoded bytes delivered to the
/// output writer. It does **not** bound total process memory. SAR itself uses a
/// fixed 8 KiB copy buffer, but the underlying decoders keep internal state that is
/// outside this limit:
///
/// * DEFLATE (`flate2` with the pure-Rust `miniz_oxide` backend) keeps a 32 KiB
///   history window plus fixed-size Huffman tables and input buffering.
/// * ZSTD (`libzstd` through `zstd`) allocates a decoder context, the frame window
///   (up to `1 << ZSTD_MAX_WINDOW_LOG` = 128 MiB; frames declaring a larger window
///   are rejected), entropy tables and a block buffer. Window size is chosen by
///   the compressed frame, not by `max_output_size`.
///
/// These internal allocations are not measured or accounted by SAR; callers that
/// need a hard process memory bound must additionally apply OS or allocator limits.
#[derive(Debug, Clone, Copy)]
pub struct DecompressionOptions {
    /// Hard cap for decoded bytes delivered to the output (decompression-bomb
    /// guard). Does not bound decoder-internal memory.
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
    /// Encoder initialization failed; source and sink I/O failures are reported as `Io`.
    #[error("compression failed: {0}")]
    CompressionFailed(String),
    /// Compressed input is invalid; source and sink I/O failures are reported as `Io`.
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
            io::copy(input, &mut encoder)?;
            encoder.try_finish()?;
            Ok(())
        }
        CompressionAlgorithm::Zstd => {
            let level = i32::from(options.level.unwrap_or(3).min(9));
            let mut encoder = zstd::stream::Encoder::new(output, level)
                .map_err(|e| CompressionError::CompressionFailed(e.to_string()))?;
            io::copy(input, &mut encoder)?;
            encoder.finish()?;
            Ok(())
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
        CompressionAlgorithm::Store => {
            copy_bounded(input, output, options.max_output_size, CompressionError::Io)
        }
        CompressionAlgorithm::Deflate => {
            let source_failed = Cell::new(false);
            let mut source = SourceTracker::new(input, &source_failed);
            let mut decoder = DeflateDecoder::new(&mut source);
            copy_bounded(&mut decoder, output, options.max_output_size, |e| {
                decoder_read_error(&source_failed, e)
            })
        }
        CompressionAlgorithm::Zstd => {
            let source_failed = Cell::new(false);
            let mut source = SourceTracker::new(input, &source_failed);
            let mut decoder = zstd::stream::Decoder::new(&mut source)
                .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;
            decoder
                .window_log_max(ZSTD_MAX_WINDOW_LOG)
                .map_err(|e| CompressionError::DecompressionFailed(e.to_string()))?;
            copy_bounded(&mut decoder, output, options.max_output_size, |e| {
                decoder_read_error(&source_failed, e)
            })
        }
    }
}

/// Records whether the underlying source itself failed, so decoder errors caused by
/// source I/O are not confused with malformed compressed data.
struct SourceTracker<'a> {
    inner: &'a mut dyn Read,
    failed: &'a Cell<bool>,
}

impl<'a> SourceTracker<'a> {
    fn new(inner: &'a mut dyn Read, failed: &'a Cell<bool>) -> Self {
        Self { inner, failed }
    }
}

impl Read for SourceTracker<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).inspect_err(|_| self.failed.set(true))
    }
}

fn decoder_read_error(source_failed: &Cell<bool>, error: io::Error) -> CompressionError {
    if source_failed.get() {
        CompressionError::Io(error)
    } else {
        CompressionError::DecompressionFailed(error.to_string())
    }
}

fn copy_bounded(
    input: &mut dyn Read,
    output: &mut dyn Write,
    max_output_size: u64,
    map_read_error: impl Fn(io::Error) -> CompressionError,
) -> Result<(), CompressionError> {
    let mut buf = [0u8; 8192];
    let mut written = 0u64;
    loop {
        let n = input.read(&mut buf).map_err(&map_read_error)?;
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

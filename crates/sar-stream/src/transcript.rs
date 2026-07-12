use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use sar_core::{
    GlobalFlags, SarError,
    format::{parse_global_header, parse_lfh},
    limits::ResourceLimits,
};

use crate::{SessionEntry, SessionEvent, SessionManager, SessionManagerConfig};

/// Transcript recording configuration for stream transcript validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TranscriptRecording {
    /// Do not record transcript bytes.
    #[default]
    Disabled,
    /// Record exact received transcript bytes to a file path.
    ///
    /// When `overwrite` is `false`, validation fails if `path` already exists.
    Path {
        /// Destination path for transcript bytes.
        path: PathBuf,
        /// Whether an existing file may be overwritten.
        overwrite: bool,
    },
}

/// Options for strict stream transcript validation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamTranscriptValidationOptions {
    /// Transcript recording behavior.
    pub recording: TranscriptRecording,
}

/// Strict stream transcript validation report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamTranscriptValidationReport {
    /// Number of entries validated from the transcript.
    pub entry_count: u64,
}

/// Validates a serialized SAR stream transcript with default options.
///
/// Default behavior does not record transcript bytes.
pub fn validate_stream_transcript(
    bytes: &[u8],
) -> Result<StreamTranscriptValidationReport, SarError> {
    validate_stream_transcript_with_options(bytes, &StreamTranscriptValidationOptions::default())
}

/// Validates a serialized SAR stream transcript with explicit options.
///
/// Validation is strict and requires:
/// - `NO_INDEX` global flag
/// - nonzero Stream ID on each entry
/// - valid session control semantics (`SESSION_INIT`, sequence continuity, etc.)
///
/// When transcript recording is enabled, bytes are written to the configured
/// path before semantic validation runs. Therefore, an invalid transcript may
/// still be recorded exactly for audit/evidence purposes.
pub fn validate_stream_transcript_with_options(
    bytes: &[u8],
    options: &StreamTranscriptValidationOptions,
) -> Result<StreamTranscriptValidationReport, SarError> {
    match &options.recording {
        TranscriptRecording::Disabled => {}
        TranscriptRecording::Path { path, overwrite } => {
            let mut open = OpenOptions::new();
            open.write(true);
            if *overwrite {
                open.create(true).truncate(true);
            } else {
                open.create_new(true);
            }
            let mut file = open.open(path)?;
            file.write_all(bytes)?;
        }
    }
    validate_stream_transcript_internal(bytes)
}

/// Validates a serialized SAR stream transcript while writing exact input bytes to a sink.
pub fn validate_stream_transcript_with_sink<W: Write + ?Sized>(
    bytes: &[u8],
    sink: &mut W,
) -> Result<StreamTranscriptValidationReport, SarError> {
    sink.write_all(bytes)?;
    validate_stream_transcript_internal(bytes)
}

fn validate_stream_transcript_internal(
    bytes: &[u8],
) -> Result<StreamTranscriptValidationReport, SarError> {
    let limits = ResourceLimits::default();
    let (header, header_len) = parse_global_header(bytes, &limits)?;
    if !header.flags.contains(GlobalFlags::NO_INDEX) {
        return Err(SarError::FlagConflict(
            "strict stream transcript validation requires NO_INDEX",
        ));
    }

    let mut manager = SessionManager::new(SessionManagerConfig::default());
    manager.observe_global_header(&header)?;

    let mut entry_count = 0u64;
    let mut pos = header_len;
    while pos < bytes.len() {
        let (lfh, lfh_len) = parse_lfh(&bytes[pos..], &header.flags, &limits)?;
        pos = pos
            .checked_add(lfh_len)
            .ok_or(SarError::Overflow("transcript offset"))?;

        if lfh.stream_id == 0 {
            return Err(SarError::StreamState(
                "strict stream transcript validation requires nonzero Stream ID",
            ));
        }

        let payload_len =
            usize::try_from(lfh.payload_size).map_err(|_| SarError::Overflow("payload length"))?;
        if pos + payload_len > bytes.len() {
            return Err(SarError::Truncated("stream transcript payload truncated"));
        }
        let payload = bytes[pos..pos + payload_len].to_vec();
        pos = pos
            .checked_add(payload_len)
            .ok_or(SarError::Overflow("transcript offset"))?;

        let result = manager.process_entry(&SessionEntry::new(lfh, payload, false))?;
        if result
            .events
            .iter()
            .any(|event| matches!(event, SessionEvent::StatefulInactive { .. }))
        {
            return Err(SarError::StreamState(
                "strict stream transcript validation requires active stateful mode",
            ));
        }
        entry_count = entry_count
            .checked_add(1)
            .ok_or(SarError::Overflow("entry count"))?;
    }

    Ok(StreamTranscriptValidationReport { entry_count })
}

#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! In-memory Stateful Streaming Mode session semantics for SAR Protocol v1.0.

mod protocol;
mod session;
mod transcript;

pub use protocol::{
    AckFlags, CapabilityFlags, FilesystemOpCode, SessionAckFrame, SessionCapabilitiesFrame,
    SessionFlags, SessionInitFrame, SessionMetadataFrame, SessionOpCode, SessionResumeFrame,
    SessionStatusFrame,
};
pub use session::{
    ActiveSession, FilesystemAction, FilesystemDeleteAction, FilesystemEntryAction,
    FilesystemRenameAction, FilesystemSyncBarrierAction, ProcessResult, SessionAction,
    SessionEntry, SessionEvent, SessionManager, SessionManagerConfig, SessionMetadataState,
};
pub use transcript::{
    StreamTranscriptValidationOptions, StreamTranscriptValidationReport, TranscriptRecording,
    validate_stream_transcript, validate_stream_transcript_with_options,
    validate_stream_transcript_with_sink,
};

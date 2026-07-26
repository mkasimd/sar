// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! M12b.3: Stream transcript semantic validation fuzz target.
//!
//! Exercises `sar_stream::validate_stream_transcript_with_options` against
//! arbitrary byte input. Transcript recording is disabled so no files are
//! written to disk. Stream transcript semantic validation is delegated to
//! `sar-stream`; this fuzz target does not reimplement transcript rules. Does
//! not instantiate archive stream/session execution directly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_stream::{
    StreamTranscriptValidationOptions, TranscriptRecording,
    validate_stream_transcript_with_options,
};

fuzz_target!(|data: &[u8]| {
    let options = StreamTranscriptValidationOptions {
        recording: TranscriptRecording::Disabled,
    };

    let _ = validate_stream_transcript_with_options(data, &options);
});

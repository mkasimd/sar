// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Focused stream transcript declared-length boundary fuzz target.
//!
//! This target constructs compact stream transcript-like inputs from fuzzer data
//! while deliberately placing boundary values into declared length fields. It is
//! intended to exercise fail-closed handling for large declared sizes, payload
//! span arithmetic, truncation checks, and non-aligned payload lengths without
//! requiring multi-GB fuzz inputs.
//!
//! It complements `stream_transcript`, which mutates the entire transcript byte
//! buffer directly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sar_stream::{
    StreamTranscriptValidationOptions, TranscriptRecording, validate_stream_transcript_with_options,
};

const BASE_REPRODUCER: [u8; 62] = [
    83, 65, 82, 33, 1, 0, 4, 0, 19, 0, 0, 2, 50, 0, 0, 0, 32, 0, 4, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 246, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 65, 82, 0, 0, 128,
    8, 0, 2, 0, 48, 0, 0, 0,
];

const PAYLOAD_SIZE_OFFSET: usize = 30;

const INTERESTING_LENGTHS: [u64; 24] = [
    0,
    1,
    2,
    7,
    8,
    15,
    16,
    31,
    32,
    63,
    64,
    255,
    256,
    1023,
    1024,
    4095,
    4096,
    65_535,
    65_536,
    65_537,
    u32::MAX as u64 - 1,
    u32::MAX as u64,
    u32::MAX as u64 + 1,
    u64::MAX,
];

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    let b0 = data.get(offset).copied().unwrap_or(0);
    let b1 = data.get(offset + 1).copied().unwrap_or(0);
    u16::from_le_bytes([b0, b1])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];

    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(offset + index).copied().unwrap_or(0);
    }

    u64::from_le_bytes(bytes)
}

fn selected_declared_length(data: &[u8]) -> u64 {
    if data.is_empty() {
        return u64::MAX;
    }

    let selector = data[0] as usize;

    if selector < INTERESTING_LENGTHS.len() {
        INTERESTING_LENGTHS[selector]
    } else {
        read_u64_le(data, 1)
    }
}

fn payload_bytes(data: &[u8]) -> &[u8] {
    let start_selector = read_u16_le(data, 9) as usize;
    let available = data.len().saturating_sub(11);

    if available == 0 {
        return &[];
    }

    let start = 11 + (start_selector % available);
    let max_len = data.len().saturating_sub(start);
    let requested_len = read_u16_le(data, 7) as usize;
    let len = requested_len.min(max_len).min(4096);

    &data[start..start + len]
}

fn validate(bytes: &[u8]) {
    let options = StreamTranscriptValidationOptions {
        recording: TranscriptRecording::Disabled,
    };

    let _ = validate_stream_transcript_with_options(bytes, &options);
}

fuzz_target!(|data: &[u8]| {
    let declared_len = selected_declared_length(data);

    let mut transcript = BASE_REPRODUCER;
    transcript[PAYLOAD_SIZE_OFFSET..PAYLOAD_SIZE_OFFSET + 8]
        .copy_from_slice(&declared_len.to_le_bytes());

    validate(&transcript);

    let payload = payload_bytes(data);

    if !payload.is_empty() {
        let mut with_payload = Vec::with_capacity(transcript.len() + payload.len());
        with_payload.extend_from_slice(&transcript);
        with_payload.extend_from_slice(payload);

        validate(&with_payload);
    }
});

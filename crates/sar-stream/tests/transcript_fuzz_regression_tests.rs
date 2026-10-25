// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Regression tests for confirmed fuzz findings against stream transcript validation.

use sar_core::SarStatus;
use sar_stream::validate_stream_transcript;

/// M12b.4: reproducer (re-encoded for the canonical WP-3 LFH layout: the obsolete
/// 12-byte Fragment Descriptor after Fragment Index was removed and Header Size
/// lowered from 50 to 38; the original was 62 bytes) that previously caused an `attempt to add with overflow` panic
/// at `crates/sar-stream/src/transcript.rs` inside `validate_stream_transcript_internal`.
///
/// The crafted LFH contains a `payload_size` field (bytes 30–37, little-endian u64) set to
/// `0xFFFFFFFFFFFFF600` — a value that, when converted to `usize` and added to the current
/// buffer offset, wraps to a small number, bypassing the truncation guard.
/// The fix uses `checked_add` to compute `payload_end` and returns `SarError::Overflow`
/// instead of panicking.
#[test]
fn m12b4_overflow_in_payload_span_returns_err() {
    let bytes: [u8; 50] = [
        83, 65, 82, 33, 1, 0, 4, 0, 19, 0, 0, 2, 38, 0, 0, 0, 32, 0, 4, 0, 255, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 246, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0,
    ];
    let err = validate_stream_transcript(&bytes).expect_err(
        "malformed transcript with overflowing payload span must return Err, not panic",
    );
    assert_eq!(err.status(), SarStatus::ErrOverflow);
}

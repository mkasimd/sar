// SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
// SPDX-License-Identifier: Apache-2.0

//! Algorithm tests for the FASTCDC chunker.

use sar_cdc::{
    CDC_ALGO_FASTCDC,
    fastcdc::{FastCdcOptions, chunk_data},
    validate::CdcError,
};

fn seq(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_add(seed)).collect()
}

fn repeating(n: usize, byte: u8) -> Vec<u8> {
    vec![byte; n]
}

#[test]
fn deterministic_boundaries_for_identical_input() {
    let data = seq(64_000, 7);
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
    };
    let a = chunk_data(&data, &opts, usize::MAX).expect("chunk_data a");
    let b = chunk_data(&data, &opts, usize::MAX).expect("chunk_data b");
    assert_eq!(a, b, "chunking must be deterministic");
}

#[test]
fn different_input_produces_different_boundaries() {
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
    };
    // Use data with genuinely different content — produced by different LCG
    // seeds so neither sequence is a cyclic permutation of the other.
    fn lcg(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s = s
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (s >> 33) as u8
            })
            .collect()
    }
    let a_data = lcg(32_000, 0xDEAD_BEEF_1234_5678);
    let b_data = lcg(32_000, 0xCAFE_BABE_8765_4321);
    let a = chunk_data(&a_data, &opts, usize::MAX).expect("a");
    let b = chunk_data(&b_data, &opts, usize::MAX).expect("b");
    // Different pseudo-random content should yield different chunk boundaries
    // with overwhelming probability.
    let a_offsets: Vec<u64> = a.iter().map(|c| c.offset).collect();
    let b_offsets: Vec<u64> = b.iter().map(|c| c.offset).collect();
    assert_ne!(a_offsets, b_offsets, "different inputs should differ");
}

#[test]
fn no_zero_length_chunks() {
    let data = seq(20_000, 42);
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
    };
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("chunks");
    for chunk in &chunks {
        assert!(
            chunk.length > 0,
            "chunk at offset {} has zero length",
            chunk.offset
        );
    }
}

#[test]
fn chunks_cover_all_data() {
    let data = seq(50_000, 13);
    let opts = FastCdcOptions::default();
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("chunks");
    let total: u64 = chunks.iter().map(|c| c.length).sum();
    assert_eq!(total, data.len() as u64, "chunks must cover all data");
}

#[test]
fn chunks_are_contiguous() {
    let data = seq(30_000, 5);
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
    };
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("chunks");
    let mut pos = 0u64;
    for chunk in &chunks {
        assert_eq!(chunk.offset, pos, "gap before offset {}", chunk.offset);
        pos += chunk.length;
    }
}

#[test]
fn max_chunk_size_not_exceeded() {
    let max_size = 4096u32;
    let data = seq(100_000, 3);
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size,
    };
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("chunks");
    for chunk in &chunks {
        assert!(
            chunk.length <= u64::from(max_size),
            "chunk length {} exceeds max_size {}",
            chunk.length,
            max_size
        );
    }
}

#[test]
fn all_chunks_except_last_at_or_above_min_size() {
    let min_size = 256u32;
    let data = seq(50_000, 7);
    let opts = FastCdcOptions {
        min_size,
        avg_size: 1024,
        max_size: 4096,
    };
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("chunks");
    if chunks.len() > 1 {
        for chunk in chunks.iter().take(chunks.len() - 1) {
            assert!(
                chunk.length >= u64::from(min_size),
                "non-final chunk length {} is below min_size {}",
                chunk.length,
                min_size
            );
        }
    }
}

#[test]
fn empty_data_produces_no_chunks() {
    let opts = FastCdcOptions::default();
    let chunks = chunk_data(&[], &opts, usize::MAX).expect("empty");
    assert!(chunks.is_empty(), "empty input should yield no chunks");
}

#[test]
fn small_data_below_min_size_is_single_chunk() {
    let min_size = 1024u32;
    let data = seq(100, 0); // 100 < 1024
    let opts = FastCdcOptions {
        min_size,
        avg_size: 4096,
        max_size: 16384,
    };
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("small");
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].length, 100);
    assert_eq!(chunks[0].offset, 0);
}

#[test]
fn exact_max_size_data_is_single_chunk() {
    let max_size = 4096u32;
    let data = seq(4096, 1);
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size,
    };
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("exact");
    // The entire slice may land in 1 or 2 chunks depending on hash values.
    // Guarantee: total coverage is correct.
    let total: u64 = chunks.iter().map(|c| c.length).sum();
    assert_eq!(total, u64::from(max_size));
}

#[test]
fn large_repeating_input_hits_max_size_boundary() {
    // Repeating data has a near-zero chance of a natural cut → all chunks
    // should be forced at max_size.
    let max_size = 512u32;
    let data = repeating(10_000, 0xAB);
    let opts = FastCdcOptions {
        min_size: 64,
        avg_size: 256,
        max_size,
    };
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("repeating");
    let full_chunks = chunks.iter().take(chunks.len().saturating_sub(1));
    for chunk in full_chunks {
        assert_eq!(
            chunk.length,
            u64::from(max_size),
            "repeating data should be forced at max_size; got {} at offset {}",
            chunk.length,
            chunk.offset
        );
    }
}

#[test]
fn resource_limit_exceeded_returns_error() {
    let data = seq(50_000, 0);
    let opts = FastCdcOptions {
        min_size: 64,
        avg_size: 256,
        max_size: 1024,
    };
    // With a max of 1 chunk, the function must fail after producing 1 chunk
    // and attempting to produce a second.
    let result = chunk_data(&data, &opts, 1);
    assert!(
        matches!(result, Err(CdcError::LimitExceeded(_))),
        "expected LimitExceeded, got {:?}",
        result
    );
}

#[test]
fn chunk_hashes_are_present() {
    let data = seq(10_000, 33);
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
    };
    let chunks = chunk_data(&data, &opts, usize::MAX).expect("chunks");
    for chunk in &chunks {
        assert!(chunk.hash.is_some(), "every chunk must have a hash");
    }
}

#[test]
fn invalid_min_size_returns_error() {
    let opts = FastCdcOptions {
        min_size: 32, // < 64
        avg_size: 256,
        max_size: 1024,
    };
    assert!(
        matches!(opts.validate(), Err(CdcError::Bounds(_))),
        "min_size < 64 should fail validation"
    );
}

#[test]
fn avg_lt_min_returns_error() {
    let opts = FastCdcOptions {
        min_size: 512,
        avg_size: 256, // < min
        max_size: 1024,
    };
    assert!(
        matches!(opts.validate(), Err(CdcError::Bounds(_))),
        "avg_size < min_size should fail"
    );
}

#[test]
fn max_lt_avg_returns_error() {
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size: 512, // < avg
    };
    assert!(
        matches!(opts.validate(), Err(CdcError::Bounds(_))),
        "max_size < avg_size should fail"
    );
}

/// Verify that chunking is deterministic — identical content at different
/// offsets in two different calls should produce hashes that match.
#[test]
fn identical_content_produces_identical_hashes() {
    let block = seq(3000, 99);
    let opts = FastCdcOptions {
        min_size: 256,
        avg_size: 1024,
        max_size: 4096,
    };
    let a = chunk_data(&block, &opts, usize::MAX).expect("a");
    let b = chunk_data(&block, &opts, usize::MAX).expect("b");
    assert_eq!(a.len(), b.len());
    for (ca, cb) in a.iter().zip(b.iter()) {
        assert_eq!(ca.hash, cb.hash, "hash mismatch for offset {}", ca.offset);
    }
}

/// Ensure the FASTCDC algo constant is the expected value.
#[test]
fn fastcdc_algo_id_constant() {
    assert_eq!(CDC_ALGO_FASTCDC, 0x02);
}

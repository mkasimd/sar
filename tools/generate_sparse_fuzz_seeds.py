#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
# SPDX-License-Identifier: Apache-2.0
"""Deterministically generates the canonical Sparse Map fuzz seeds.

Sparse Map layout (specification.md Sections 6.1.2 and 17.1-17.2):

    Sparse Map = Sparse Logical Size || Sparse Extent[0] || ...

Every field is u32 LE when 64BIT_SIZE is unset and u64 LE when it is set.
LFH `Uncompressed Size` is the gathered-data length, not the logical size.

Global Flags are NO_INDEX | SPARSE_FILES, plus SIZE_64BIT and/or
FILE_FRAGMENTATION where noted.

Usage:
    python tools/generate_sparse_fuzz_seeds.py          # write seeds
    python tools/generate_sparse_fuzz_seeds.py --check  # verify committed seeds
"""

import argparse
import struct
import sys
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent.parent / "fuzz" / "seeds" / "sparse_map"

SIZE_64BIT = 1
NO_INDEX = 1 << 1
FILE_FRAGMENTATION = 1 << 4
SPARSE_FILES = 1 << 30
IS_FRAGMENT = 1 << 5
LAST_FRAGMENT = 1 << 6


def global_header(flags: int) -> bytes:
    return b"SAR!" + struct.pack("<HHI", 1, 4, flags)


def sparse_map(logical: int, extents, wide: bool) -> bytes:
    fmt = "<Q" if wide else "<I"
    out = struct.pack(fmt, logical)
    for offset, length in extents:
        out += struct.pack(fmt, offset) + struct.pack(fmt, length)
    return out


def lfh(flags, name, gathered, smap, mode=0, frag=None, usize=None):
    wide = bool(flags & SIZE_64BIT)
    size_fmt = "<Q" if wide else "<I"
    usize = len(gathered) if usize is None else usize
    body = struct.pack("<HHH", mode, 0, 0)
    body += struct.pack(size_fmt, usize) + struct.pack(size_fmt, len(gathered))
    if flags & FILE_FRAGMENTATION:
        body += struct.pack("<II", *frag)
    body += struct.pack("<H", len(name)) + struct.pack("<I", len(smap))
    body += name + smap
    return struct.pack("<I", 4 + len(body)) + body + gathered


BASE = NO_INDEX | SPARSE_FILES
WIDE = BASE | SIZE_64BIT
FRAG = BASE | FILE_FRAGMENTATION


def single(flags, smap, gathered, usize=None):
    return global_header(flags) + lfh(flags, b"s.bin", gathered, smap, usize=usize)


def fragments(*parts):
    out = global_header(FRAG)
    for index, last, smap, data in parts:
        mode = IS_FRAGMENT | (LAST_FRAGMENT if last else 0)
        out += lfh(FRAG, b"f.bin" if index == 0 else b"", data, smap, mode, (7, index))
    return out


HOLES = sparse_map(16, [(4, 4)], False)

SEEDS = {
    # Leading and trailing holes around one 4-byte extent.
    "sparse32_holes.bin": single(BASE, HOLES, b"ABCD"),
    "sparse64_holes.bin": single(WIDE, sparse_map(16, [(4, 4)], True), b"ABCD"),
    # Size-only map: all-hole Entry, zero gathered bytes.
    "sparse32_all_hole.bin": single(BASE, sparse_map(4096, [], False), b""),
    "sparse64_all_hole.bin": single(WIDE, sparse_map(4096, [], True), b""),
    "sparse32_zero_logical_size.bin": single(BASE, sparse_map(0, [], False), b""),
    # Sparse Map Size shorter than the Sparse Logical Size field.
    "sparse32_map_too_short.bin": single(BASE, b"\x10\x00\x00", b""),
    # Descriptor bytes that are not a multiple of the descriptor width.
    "sparse32_misaligned_descriptor.bin": single(BASE, HOLES + b"\x01\x02\x03", b"ABCD"),
    "sparse64_misaligned_descriptor.bin": single(
        WIDE, sparse_map(16, [(4, 4)], True) + b"\x01" * 8, b"ABCD"
    ),
    # Extent end exceeds the Sparse Logical Size.
    "sparse32_extent_beyond_logical_size.bin": single(
        BASE, sparse_map(6, [(4, 4)], False), b"ABCD"
    ),
    "sparse32_zero_length_extent.bin": single(BASE, sparse_map(8, [(4, 0)], False), b""),
    "sparse32_overlapping_extents.bin": single(
        BASE, sparse_map(16, [(0, 8), (4, 8)], False), b"A" * 16
    ),
    "sparse32_unordered_extents.bin": single(
        BASE, sparse_map(16, [(8, 4), (0, 4)], False), b"A" * 8
    ),
    # Checked arithmetic: offset + length wraps in 64 bits.
    "sparse64_extent_overflow.bin": single(
        WIDE, sparse_map(16, [(2**64 - 4, 8)], True), b"A" * 8
    ),
    # Maximum declared logical sizes with no gathered data.
    "sparse32_max_logical_size.bin": single(BASE, sparse_map(2**32 - 1, [], False), b""),
    "sparse64_max_logical_size.bin": single(WIDE, sparse_map(2**64 - 1, [], True), b""),
    # Gathered length differs from the extent-length sum.
    "sparse32_gathered_too_short.bin": single(BASE, HOLES, b"ABC"),
    "sparse32_gathered_too_long.bin": single(BASE, HOLES, b"ABCDE"),
    # Uncompressed Size is wrongly set to the logical size.
    "sparse32_usize_is_logical_size.bin": single(BASE, HOLES, b"ABCD", usize=16),
    # Complete fragmented group; Index 0 carries the map, terminal is empty.
    "sparse_frag_complete.bin": fragments(
        (0, False, HOLES, b"AB"), (1, False, b"", b"CD"), (2, True, b"", b"")
    ),
    "sparse_frag_empty_index0_contribution.bin": fragments(
        (0, False, HOLES, b""), (1, True, b"", b"ABCD")
    ),
    # Later fragment carries a Sparse Map (SAR_ERR_METADATA_CONFLICT).
    "sparse_frag_later_map.bin": fragments(
        (0, False, HOLES, b"AB"), (1, True, HOLES, b"CD")
    ),
    # Fragment Index 1 missing (SAR_ERR_FRAGMENT_GAP).
    "sparse_frag_gap.bin": fragments((0, False, HOLES, b"AB"), (2, True, b"", b"CD")),
    # Fragment Index 0 lacks the map while a later fragment has one.
    "sparse_frag_index0_no_map.bin": fragments(
        (0, False, b"", b"AB"), (1, True, HOLES, b"CD")
    ),
    # Contribution sum differs from the extent-length sum.
    "sparse_frag_contribution_mismatch.bin": fragments(
        (0, False, HOLES, b"AB"), (1, True, b"", b"C")
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    bad = False
    if not args.check:
        SEED_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in SEEDS.items():
        path = SEED_DIR / name
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                print(f"seed out of date: {path}", file=sys.stderr)
                bad = True
        else:
            path.write_bytes(data)
            print(f"wrote {path} ({len(data)} bytes)")
    if args.check and SEED_DIR.exists():
        extra = {p.name for p in SEED_DIR.iterdir()} - set(SEEDS)
        for name in sorted(extra):
            print(f"unexpected seed: {SEED_DIR / name}", file=sys.stderr)
            bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

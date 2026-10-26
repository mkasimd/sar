#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
# SPDX-License-Identifier: Apache-2.0
"""Deterministically generates the canonical fragmentation fuzz seeds.

Canonical SAR v1.0 fragment LFH layout (specification.md Sections 6.1-6.1.3)
for Global Flags NO_INDEX | FILE_FRAGMENTATION (32-bit sizes):

    Header Size u32 | Entry Mode u16 | Stream ID u16 | Sequence No u16 |
    Uncompressed Size u32 | Payload Size u32 |
    Fragment ID u32 | Fragment Index u32 |
    Name Length u16 | Name

There is no absolute offset or separate contribution-size field.

Usage:
    python tools/generate_fragment_fuzz_seeds.py          # write seeds
    python tools/generate_fragment_fuzz_seeds.py --check  # verify committed seeds
"""

import argparse
import struct
import sys
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent.parent / "fuzz" / "seeds" / "fec_fragmentation"

IS_FRAGMENT = 1 << 5
LAST_FRAGMENT = 1 << 6
FLAGS = 0x12  # NO_INDEX | FILE_FRAGMENTATION


def global_header() -> bytes:
    return b"SAR!" + struct.pack("<HHI", 1, 4, FLAGS)


def lfh(fragment_id: int, index: int, name: bytes, payload: bytes, last: bool) -> bytes:
    mode = IS_FRAGMENT | (LAST_FRAGMENT if last else 0)
    header_size = 4 + 2 + 2 + 2 + 4 + 4 + 4 + 4 + 2 + len(name)
    head = struct.pack(
        "<IHHHIIIIH",
        header_size,
        mode,
        0,
        0,
        len(payload),
        len(payload),
        fragment_id,
        index,
        len(name),
    )
    return head + name + payload


SEEDS = {
    # Fragment Index 1 is missing between 0 and the terminal index 2.
    "fragment_gap_missing_index.bin": global_header()
    + lfh(7, 0, b"frag.dat", b"AAA", False)
    + lfh(7, 2, b"frag.dat", b"BB", True),
    # Two fragments of one group share Fragment Index 0 (duplicate index).
    # Replaces the retired offset-based `fragment_overlap_offsets.bin`.
    "fragment_duplicate_index.bin": global_header()
    + lfh(9, 0, b"dup.bin", b"ABCD", False)
    + lfh(9, 0, b"dup.bin", b"WXYZ", True),
    # Physical Fragment Index order 0, 2, 1 (strictly increasing order required).
    "fragment_physical_order.bin": global_header()
    + lfh(5, 0, b"ord.bin", b"AA", False)
    + lfh(5, 2, b"", b"CC", True)
    + lfh(5, 1, b"", b"BB", False),
    # A later fragment repeats a Name that differs from Fragment Index 0.
    "fragment_name_mismatch.bin": global_header()
    + lfh(6, 0, b"one.bin", b"AA", False)
    + lfh(6, 1, b"two.bin", b"BB", True),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    bad = False
    for name, data in SEEDS.items():
        path = SEED_DIR / name
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                print(f"seed out of date: {path}", file=sys.stderr)
                bad = True
        else:
            path.write_bytes(data)
            print(f"wrote {path} ({len(data)} bytes)")
    obsolete = SEED_DIR / "fragment_overlap_offsets.bin"
    if args.check and obsolete.exists():
        print(f"obsolete seed present: {obsolete}", file=sys.stderr)
        bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

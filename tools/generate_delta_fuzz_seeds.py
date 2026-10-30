#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
# SPDX-License-Identifier: Apache-2.0
"""Deterministically generates seeds for the delta_bsdiff_apply and
delta_vcdiff_apply fuzz targets.

Seed layout: u16 little-endian base length | base bytes | patch bytes.

Usage:
    python tools/generate_delta_fuzz_seeds.py          # write seeds
    python tools/generate_delta_fuzz_seeds.py --check  # verify committed seeds
"""

import argparse
import struct
import sys
from pathlib import Path

SEED_DIR = Path(__file__).resolve().parent.parent / "fuzz" / "seeds" / "delta_apply"

BASE = b"0123456789abcdef"
TARGET = b"0123XXXX89abcdefTAIL"


def bs_int(v: int) -> bytes:
    raw = bytearray(struct.pack("<Q", abs(v)))
    if v < 0:
        raw[7] |= 0x80
    return bytes(raw)


def bsdiff(triples, diff: bytes, extra: bytes, new_size: int) -> bytes:
    ctrl = b"".join(bs_int(a) + bs_int(b) + bs_int(c) for a, b, c in triples)
    return (
        b"SARBSD01"
        + bs_int(len(ctrl))
        + bs_int(len(diff))
        + bs_int(new_size)
        + ctrl
        + diff
        + extra
    )


def varint(v: int) -> bytes:
    out = [v & 0x7F]
    v >>= 7
    while v:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    return bytes(reversed(out))


def vcdiff_add(target: bytes) -> bytes:
    inst = b"\x01" + varint(len(target))
    body = (
        varint(len(target))
        + b"\x00"
        + varint(len(target))
        + varint(len(inst))
        + varint(0)
        + target
        + inst
    )
    return b"\xd6\xc3\xc4\x00\x00" + b"\x00" + varint(len(body)) + body


def vcdiff_copy(length: int) -> bytes:
    # COPY (size follows, mode 0 VCD_SELF) from source offset 0.
    inst = b"\x13" + varint(length)
    addr = varint(0)
    body = (
        varint(length) + b"\x00" + varint(0) + varint(len(inst)) + varint(len(addr)) + inst + addr
    )
    return b"\xd6\xc3\xc4\x00\x00" + b"\x01" + varint(len(BASE)) + varint(0) + varint(len(body)) + body


def seed(base: bytes, patch: bytes) -> bytes:
    return struct.pack("<H", len(base)) + base + patch


def seeds() -> dict:
    diff = bytes((TARGET[i] - BASE[i]) & 0xFF for i in range(len(BASE)))
    valid_bs = bsdiff([(len(BASE), len(TARGET) - len(BASE), 0)], diff, TARGET[len(BASE):], len(TARGET))
    valid_vc = vcdiff_add(TARGET)
    return {
        "bsdiff_valid.bin": seed(BASE, valid_bs),
        "bsdiff_truncated.bin": seed(BASE, valid_bs[:-3]),
        "bsdiff_size_mismatch.bin": seed(BASE, bsdiff([(4, 0, 0)], b"\0" * 4, b"", 9)),
        "bsdiff_huge_new_size.bin": seed(BASE, bsdiff([(1, 0, 0)], b"\0", b"", 2**62)),
        "bsdiff_negative_seek.bin": seed(BASE, bsdiff([(1, 0, -100)], b"\0", b"", 1)),
        "bsdiff_bad_magic.bin": seed(BASE, b"BSDIFF40" + valid_bs[8:]),
        "vcdiff_valid_add.bin": seed(BASE, valid_vc),
        "vcdiff_valid_copy.bin": seed(BASE, vcdiff_copy(len(BASE))),
        "vcdiff_truncated.bin": seed(BASE, valid_vc[:-4]),
        "vcdiff_bad_magic.bin": seed(BASE, b"\xd6\xc3\xc5" + valid_vc[3:]),
        "vcdiff_huge_window.bin": seed(BASE, b"\xd6\xc3\xc4\x00\x00\x00" + varint(2**40)),
        "empty.bin": b"",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = seeds()
    if args.check:
        bad = [n for n, b in expected.items() if not (SEED_DIR / n).is_file() or (SEED_DIR / n).read_bytes() != b]
        if bad:
            print("stale or missing delta fuzz seeds:", ", ".join(sorted(bad)))
            return 1
        print(f"delta fuzz seeds up to date ({len(expected)} files)")
        return 0
    SEED_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in expected.items():
        (SEED_DIR / name).write_bytes(data)
    print(f"wrote {len(expected)} seeds to {SEED_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

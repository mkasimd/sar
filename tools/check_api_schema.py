#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
# SPDX-License-Identifier: Apache-2.0

"""
Validate docs/MACHINE_READABLE_API.json against docs/MACHINE_READABLE_API.schema.json.

Usage from repository root:

    python tools/check_api_schema.py

Custom paths:

    python tools/check_api_schema.py \
      --schema docs/MACHINE_READABLE_API.schema.json \
      --input docs/MACHINE_READABLE_API.json

This script requires the third-party `jsonschema` package:

    python -m pip install jsonschema
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = REPO_ROOT / "docs" / "MACHINE_READABLE_API.schema.json"
DEFAULT_INPUT = REPO_ROOT / "docs" / "MACHINE_READABLE_API.json"


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"error: file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: invalid JSON in {path}: {exc}") from None


def format_path(error_path: Any) -> str:
    parts = list(error_path)
    if not parts:
        return "$"

    out = "$"
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}"
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFAULT_SCHEMA,
        help="JSON schema file",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="JSON document to validate",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=50,
        help="maximum number of validation errors to print",
    )

    args = parser.parse_args(argv)

    try:
        import jsonschema
        from jsonschema import Draft202012Validator
    except ImportError:
        print(
            "error: missing dependency `jsonschema`.\n"
            "install it with:\n\n"
            "    python -m pip install jsonschema",
            file=sys.stderr,
        )
        return 2

    schema = load_json(args.schema)
    document = load_json(args.input)

    try:
        Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as exc:
        print(f"error: schema itself is invalid: {exc.message}", file=sys.stderr)
        print(f"schema path: {format_path(exc.path)}", file=sys.stderr)
        return 2

    validator = Draft202012Validator(schema)
    errors = sorted(
        validator.iter_errors(document),
        key=lambda e: list(e.path),
    )

    if errors:
        print(
            f"error: {args.input} does not match {args.schema}",
            file=sys.stderr,
        )

        for index, error in enumerate(errors[: args.max_errors], start=1):
            print(file=sys.stderr)
            print(f"{index}. {format_path(error.path)}", file=sys.stderr)
            print(f"   {error.message}", file=sys.stderr)

            if error.schema_path:
                print(f"   schema: {format_path(error.schema_path)}", file=sys.stderr)

        remaining = len(errors) - args.max_errors
        if remaining > 0:
            print(file=sys.stderr)
            print(f"... {remaining} more error(s) not shown", file=sys.stderr)

        return 1

    print(f"ok: {args.input} matches {args.schema}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

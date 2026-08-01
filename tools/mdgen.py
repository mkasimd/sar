#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for deterministic Markdown generators."""

from __future__ import annotations

import difflib
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]

UNICODE_REPLACEMENTS = {
    "\u2010": "-",
    "\u2011": "-",
    "\u2012": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2015": "-",
    "\u2212": "-",
    "\u2018": "'",
    "\u2019": "'",
    "\u201a": "'",
    "\u201b": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u201e": '"',
    "\u201f": '"',
    "\u2026": "...",
    "\u2190": "<-",
    "\u2192": "->",
    "\u2194": "<->",
    "\u21d2": "=>",
    "\u2260": "!=",
    "\u2264": "<=",
    "\u2265": ">=",
    "\u00d7": "x",
    "\u00a0": " ",
}


def to_ascii(value: Any) -> str:
    """Render a value as ASCII-only text."""
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (int, float)):
        text = str(value)
    elif isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=True, sort_keys=True)

    for old, new in UNICODE_REPLACEMENTS.items():
        text = text.replace(old, new)

    text = unicodedata.normalize("NFKD", text)
    return text.encode("ascii", "replace").decode("ascii")


def _escape_markdown_plain(text: str, *, table_cell: bool) -> str:
    """Escape Markdown syntax in text that is outside an inline-code span."""
    text = text.replace("\\", "\\\\")
    if table_cell:
        text = text.replace("|", "\\|")
    text = text.replace("[", "\\[")
    text = text.replace("]", "\\]")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    if table_cell:
        text = text.replace("\n", "<br>")
    return text


def _backtick_run_length(text: str, start: int) -> int:
    end = start
    while end < len(text) and text[end] == "`":
        end += 1
    return end - start


def _find_matching_backtick_run(text: str, start: int, length: int) -> int:
    """Return the next exact-length backtick run, or -1 when none exists."""
    index = start
    while index < len(text):
        index = text.find("`", index)
        if index < 0:
            return -1
        run_length = _backtick_run_length(text, index)
        if run_length == length:
            return index
        index += run_length
    return -1


def _escape_markdown_preserving_inline_code(
    value: Any,
    *,
    table_cell: bool,
) -> str:
    """Escape Markdown syntax while preserving existing inline-code contents."""
    text = to_ascii(value)
    output: list[str] = []
    plain_start = 0
    index = 0

    while index < len(text):
        if text[index] != "`":
            index += 1
            continue

        run_length = _backtick_run_length(text, index)
        closing = _find_matching_backtick_run(
            text,
            index + run_length,
            run_length,
        )
        if closing < 0:
            index += run_length
            continue

        output.append(
            _escape_markdown_plain(
                text[plain_start:index],
                table_cell=table_cell,
            )
        )

        delimiter = "`" * run_length
        code = text[index + run_length : closing].replace("\n", " ")
        if table_cell:
            # GFM table parsing still treats an unescaped pipe inside a code
            # span as a column separator.
            code = code.replace("|", "\\|")
        output.extend((delimiter, code, delimiter))

        index = closing + run_length
        plain_start = index

    output.append(
        _escape_markdown_plain(
            text[plain_start:],
            table_cell=table_cell,
        )
    )
    return "".join(output)


def md_escape_cell(value: Any) -> str:
    """Escape a Markdown table cell while preserving inline-code contents."""
    return _escape_markdown_preserving_inline_code(value, table_cell=True)


def md_escape_text(value: Any) -> str:
    """Escape Markdown prose while preserving existing inline-code contents."""
    return _escape_markdown_preserving_inline_code(value, table_cell=False)


def md_code(value: Any) -> str:
    """Render safe inline code."""
    text = to_ascii(value).replace("\n", " ")
    if "`" not in text:
        return f"`{text}`"
    return "`` " + text.replace("``", "` `") + " ``"


def heading(level: int, title: str) -> str:
    if level < 1 or level > 6:
        raise ValueError(f"invalid Markdown heading level: {level}")
    return f"{'#' * level} {to_ascii(title)}\n\n"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"error: input file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: invalid JSON in {path}: {exc}") from None

    if not isinstance(data, dict):
        raise SystemExit(f"error: top-level JSON value must be an object: {path}")

    return data


def validate_json_document(
    data: dict[str, Any],
    *,
    schema_path: Path,
    expected_schema_id: str,
) -> None:
    """Validate a JSON document and its schema identity."""
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError
    except ImportError:
        raise SystemExit(
            "error: jsonschema is required to validate generated-document inputs"
        ) from None

    schema = load_json(schema_path)
    schema_id = schema.get("$id")
    if schema_id != expected_schema_id:
        raise SystemExit(
            f"error: expected schema $id {expected_schema_id!r}, got {schema_id!r} "
            f"in {schema_path}"
        )

    document_schema_id = data.get("$schema")
    if document_schema_id != expected_schema_id:
        raise SystemExit(
            f"error: expected document $schema {expected_schema_id!r}, "
            f"got {document_schema_id!r}"
        )

    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise SystemExit(f"error: invalid JSON Schema in {schema_path}: {exc.message}") from None

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(data), key=lambda error: list(error.absolute_path))
    if not errors:
        return

    lines = [f"error: input does not match {schema_path}:"]
    for error in errors:
        location = "$"
        for component in error.absolute_path:
            if isinstance(component, int):
                location += f"[{component}]"
            else:
                location += f".{component}"
        lines.append(f"  {location}: {error.message}")
    raise SystemExit("\n".join(lines))


def normalize_markdown(markdown: str) -> str:
    """Remove trailing whitespace and enforce one final LF."""
    lines = [line.rstrip() for line in markdown.splitlines()]
    output = "\n".join(lines).rstrip() + "\n"
    try:
        output.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SystemExit(f"error: generated Markdown contains non-ASCII text: {exc}") from None
    return output


def write_or_check(
    *,
    output_path: Path,
    generated: str,
    check: bool,
    regenerate_command: str,
) -> int:
    """Write generated text, or fail with a diff when the output is stale."""
    if check:
        try:
            existing = output_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"error: generated file is missing: {output_path}", file=sys.stderr)
            return 1

        if existing != generated:
            print(
                f"error: {output_path} is stale; run `{regenerate_command}`",
                file=sys.stderr,
            )
            print(file=sys.stderr)
            print("diff:", file=sys.stderr)
            diff = difflib.unified_diff(
                existing.splitlines(keepends=True),
                generated.splitlines(keepends=True),
                fromfile=str(output_path),
                tofile=f"{output_path} (generated)",
                n=3,
            )
            sys.stderr.writelines(diff)
            return 1

        print(f"ok: {output_path} is up to date")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(generated, encoding="utf-8", newline="\n")
    try:
        display_path = output_path.relative_to(REPO_ROOT)
    except ValueError:
        display_path = output_path
    print(f"generated {display_path}")
    return 0

#!/usr/bin/env python3
# Copyright 2026 The Fractalyze Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================

"""Fractal commit lint — commit message linter enforcing Conventional Commits.

Enforces the commit message format from fractalyze/.github
COMMIT_MESSAGE_GUIDELINE.md.

Usage:
    fractal-commit-lint <commit-msg-file>
"""

import argparse
import re
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

VALID_TYPES = (
    "build",
    "chore",
    "ci",
    "docs",
    "feat",
    "fix",
    "perf",
    "refactor",
    "style",
    "test",
)

# <type>(<scope>)[!]: <summary>
# scope and ! are optional.
HEADER_RE = re.compile(
    r"^(?P<type>\w+)"
    r"(?:\((?P<scope>[^)]+)\))?"
    r"(?P<breaking>!)?"
    r":\s"
    r"(?P<summary>.+)$"
)

MERGE_RE = re.compile(r"^Merge (branch|pull request|tag)\b")
FIXUP_RE = re.compile(r"^(fixup|squash|amend)! ")
REVERT_RE = re.compile(r"^revert:\s")
SCISSORS = "# --- >8 ---"


@dataclass
class Diagnostic:
    line: int
    rule: str
    message: str


def format_diagnostic(d: Diagnostic) -> str:
    return f"fractal-commit-lint: line {d.line}: [{d.rule}] {d.message}"


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_commit_message(text: str) -> list[str]:
    """Strip comment lines and scissors, return remaining lines."""
    lines = []
    for raw_line in text.splitlines():
        if raw_line.strip() == SCISSORS:
            break
        if raw_line.startswith("#"):
            continue
        lines.append(raw_line)
    # Strip trailing blank lines.
    while lines and lines[-1].strip() == "":
        lines.pop()
    return lines


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate(lines: list[str]) -> list[Diagnostic]:
    """Validate a parsed commit message. Returns a list of diagnostics."""
    if not lines:
        return [Diagnostic(line=1, rule="header-format", message="commit message is empty")]

    header = lines[0]

    # Skip merge commits.
    if MERGE_RE.match(header):
        return []

    # Skip fixup/squash/amend commits.
    if FIXUP_RE.match(header):
        return []

    # Revert commits.
    if REVERT_RE.match(header):
        return _validate_revert(lines)

    return _validate_conventional(lines)


def _validate_revert(lines: list[str]) -> list[Diagnostic]:
    """Validate a revert commit message."""
    diags: list[Diagnostic] = []
    header = lines[0]

    # Header must match: revert: <original header>
    if not re.match(r"^revert:\s.+", header):
        diags.append(
            Diagnostic(
                line=1,
                rule="header-format",
                message="revert header must match 'revert: <original commit header>'",
            )
        )

    # Body must contain "This reverts commit <SHA>."
    body_text = "\n".join(lines[1:])
    if not re.search(r"This reverts commit [0-9a-f]+", body_text):
        diags.append(
            Diagnostic(
                line=2,
                rule="body-missing",
                message="revert body must contain 'This reverts commit <SHA>.'",
            )
        )

    return diags


def _validate_conventional(lines: list[str]) -> list[Diagnostic]:
    """Validate a conventional commit message."""
    diags: list[Diagnostic] = []
    header = lines[0]

    # --- header-format ---
    m = HEADER_RE.match(header)
    if not m:
        diags.append(
            Diagnostic(
                line=1,
                rule="header-format",
                message=(
                    "header must match '<type>(<scope>)[!]: <summary>'; "
                    "scope and ! are optional"
                ),
            )
        )
        return diags  # Can't validate further without a parsed header.

    commit_type = m.group("type")
    summary = m.group("summary")

    # --- header-type ---
    if commit_type not in VALID_TYPES:
        diags.append(
            Diagnostic(
                line=1,
                rule="header-type",
                message=(
                    f"unknown type '{commit_type}'; "
                    f"expected one of: {', '.join(VALID_TYPES)}"
                ),
            )
        )

    # --- header-length ---
    if len(header) > 80:
        diags.append(
            Diagnostic(
                line=1,
                rule="header-length",
                message=f"header is {len(header)} chars; max 80",
            )
        )

    # --- header-case ---
    if summary and summary[0].isupper():
        diags.append(
            Diagnostic(
                line=1,
                rule="header-case",
                message="summary must start with a lowercase letter",
            )
        )

    # --- header-period ---
    if summary and summary.endswith("."):
        diags.append(
            Diagnostic(
                line=1,
                rule="header-period",
                message="summary must not end with a period",
            )
        )

    # --- body checks (only if there's more than just the header) ---
    has_body_lines = len(lines) > 1

    if has_body_lines:
        # --- body-separator ---
        if lines[1].strip() != "":
            diags.append(
                Diagnostic(
                    line=2,
                    rule="body-separator",
                    message="must have a blank line between header and body",
                )
            )

    # Extract body text (skip blank separator line).
    body_lines = lines[2:] if len(lines) > 2 else []

    # Strip trailing footer block (lines matching "Token: value" or
    # "Token #value" or "BREAKING CHANGE: ...").
    footer_re = re.compile(r"^[\w-]+(?:\s#|:\s)")
    body_end = len(body_lines)
    for i in range(len(body_lines) - 1, -1, -1):
        if body_lines[i].strip() == "":
            body_end = i
            break
        if not footer_re.match(body_lines[i]):
            body_end = len(body_lines)
            break

    body_text = "\n".join(body_lines[:body_end]).strip()

    # --- body-missing ---
    if commit_type != "docs" and not body_text:
        diags.append(
            Diagnostic(
                line=1,
                rule="body-missing",
                message="body is required (except for 'docs' type)",
            )
        )

    # --- body-min-length ---
    if body_text and len(body_text) < 20:
        diags.append(
            Diagnostic(
                line=3,
                rule="body-min-length",
                message=f"body is {len(body_text)} chars; min 20",
            )
        )

    return diags


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fractal commit lint — commit message linter",
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Commit message file(s) to lint",
    )
    args = parser.parse_args(argv)

    exit_code = 0
    for filepath in args.files:
        try:
            with open(filepath, encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            print(f"fractal-commit-lint: {e}", file=sys.stderr)
            exit_code = 1
            continue

        lines = parse_commit_message(text)
        diags = validate(lines)

        for d in diags:
            print(format_diagnostic(d))

        if diags:
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

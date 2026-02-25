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

"""Fractal build lint — BUILD.bazel linter for ZKX.

Enforces:
  - build-target-sort: library targets must be alphabetically sorted by name.
  - build-test-name: test targets must be named {dirname}_unittests.

Usage:
    fractal-build-lint [--fix] [--rules=rule1,rule2] BUILD.bazel ...
"""

import argparse
import os
import re
import sys
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


@dataclass
class Diagnostic:
    file: str
    line: int
    rule: str
    message: str


def format_diagnostic(d: Diagnostic) -> str:
    return f"{d.file}:{d.line}: [{d.rule}] {d.message}"


# ---------------------------------------------------------------------------
# BUILD file parsing
# ---------------------------------------------------------------------------

# Library rules whose targets should be sorted alphabetically.
LIBRARY_RULES = frozenset({"cc_library", "zkx_cc_library"})

# Test rules whose naming convention should be checked.
TEST_RULES = frozenset({"cc_test", "zkx_cc_unittest"})

_TARGET_START_RE = re.compile(r"^(\w+)\s*\(")
_NAME_RE = re.compile(r'\bname\s*=\s*"([^"]+)"')
_SUPPRESS_RE = re.compile(r"#\s*fractal-build-lint:\s*disable=(\S+)")


def _is_suppressed(lines: list[str], line_idx: int, rule: str) -> bool:
    """Check if a rule is suppressed by a comment on the previous line."""
    if line_idx > 0:
        m = _SUPPRESS_RE.search(lines[line_idx - 1])
        if m and rule in m.group(1).split(","):
            return True
    return False


@dataclass
class TargetBlock:
    """A parsed Bazel target."""

    rule: str
    name: str
    start: int  # 0-based line index of the target call (inclusive)
    end: int  # 0-based line index (exclusive)


def _parse_targets(lines: list[str]) -> list[TargetBlock]:
    """Extract target blocks from BUILD file lines."""
    targets = []
    i = 0
    while i < len(lines):
        m = _TARGET_START_RE.match(lines[i])
        if m:
            rule = m.group(1)
            start = i
            depth = 0
            j = i
            while j < len(lines):
                depth += lines[j].count("(") - lines[j].count(")")
                if depth <= 0:
                    break
                j += 1
            end = j + 1

            block_text = "\n".join(lines[start:end])
            nm = _NAME_RE.search(block_text)
            name = nm.group(1) if nm else ""

            targets.append(TargetBlock(rule=rule, name=name, start=start, end=end))
            i = end
        else:
            i += 1
    return targets


# ---------------------------------------------------------------------------
# Rule: build-target-sort
# ---------------------------------------------------------------------------


def check_target_sort(
    filepath: str, lines: list[str], fix: bool
) -> tuple[list[Diagnostic], list[str]]:
    """Library targets must be alphabetically sorted by name."""
    rule = "build-target-sort"
    diags = []
    new_lines = list(lines)

    targets = _parse_targets(lines)
    lib_targets = [t for t in targets if t.rule in LIBRARY_RULES]

    if len(lib_targets) < 2:
        return diags, new_lines

    # Check if already sorted.
    names = [t.name for t in lib_targets]
    sorted_names = sorted(names)
    if names == sorted_names:
        return diags, new_lines

    # Report each out-of-order target.
    for i in range(1, len(lib_targets)):
        if lib_targets[i].name < lib_targets[i - 1].name:
            if _is_suppressed(lines, lib_targets[i].start, rule):
                continue
            diags.append(
                Diagnostic(
                    file=filepath,
                    line=lib_targets[i].start + 1,
                    rule=rule,
                    message=(
                        f'target "{lib_targets[i].name}" should come before '
                        f'"{lib_targets[i - 1].name}" '
                        f"(library targets must be sorted alphabetically)"
                    ),
                )
            )

    if not fix:
        return diags, new_lines

    # --- Auto-fix: sort library target blocks ---

    # Check that no non-library target is interleaved between the first and
    # last library targets.  If so, skip the fix to avoid mangling the file.
    first_lib = lib_targets[0]
    last_lib = lib_targets[-1]
    for t in targets:
        if t.rule not in LIBRARY_RULES and first_lib.start < t.start < last_lib.end:
            return diags, new_lines

    # Extract each library target's lines and sort by name.
    blocks = [lines[t.start : t.end] for t in lib_targets]
    paired = sorted(zip(names, blocks), key=lambda x: x[0])
    sorted_blocks = [b for _, b in paired]

    # Reconstruct: before + sorted blocks (with blank separators) + after.
    before = lines[: first_lib.start]
    after = lines[last_lib.end :]

    new_lines = list(before)
    for idx, block in enumerate(sorted_blocks):
        if idx > 0:
            new_lines.append("")
        new_lines.extend(block)
    new_lines.extend(after)

    return diags, new_lines


# ---------------------------------------------------------------------------
# Rule: build-test-name
# ---------------------------------------------------------------------------


def check_test_name(filepath: str, lines: list[str]) -> list[Diagnostic]:
    """Test targets must be named {dirname}_unittests."""
    rule = "build-test-name"
    diags = []

    targets = _parse_targets(lines)
    test_targets = [t for t in targets if t.rule in TEST_RULES]

    if not test_targets:
        return diags

    dirname = os.path.basename(os.path.dirname(os.path.abspath(filepath)))
    if not dirname:
        return diags

    expected = f"{dirname}_unittests"

    for t in test_targets:
        if t.name != expected:
            if _is_suppressed(lines, t.start, rule):
                continue
            diags.append(
                Diagnostic(
                    file=filepath,
                    line=t.start + 1,
                    rule=rule,
                    message=(
                        f'test target name "{t.name}" should be "{expected}" '
                        f"(expected {{dirname}}_unittests)"
                    ),
                )
            )

    return diags


# ---------------------------------------------------------------------------
# Rule registry & driver
# ---------------------------------------------------------------------------

ALL_RULES = ["build-target-sort", "build-test-name"]


def lint_file(
    filepath: str,
    fix: bool = False,
    selected_rules: set[str] | None = None,
) -> list[Diagnostic]:
    """Lint a single BUILD file."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return [Diagnostic(file=filepath, line=0, rule="io", message=str(e))]

    if not content.strip():
        return []

    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]

    rules = set(ALL_RULES)
    if selected_rules is not None:
        rules &= selected_rules

    all_diags: list[Diagnostic] = []
    current_lines = lines

    if "build-target-sort" in rules:
        diags, current_lines = check_target_sort(filepath, current_lines, fix)
        all_diags.extend(diags)

    if "build-test-name" in rules:
        all_diags.extend(check_test_name(filepath, current_lines))

    if fix and current_lines != lines:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(current_lines))
            if content.endswith("\n"):
                f.write("\n")

    return all_diags


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fractal build lint — BUILD.bazel linter for ZKX",
    )
    parser.add_argument("files", nargs="*", help="BUILD files to lint")
    parser.add_argument(
        "--fix", action="store_true", help="Auto-fix fixable violations"
    )
    parser.add_argument(
        "--rules",
        type=str,
        default=None,
        help="Comma-separated list of rules to run (default: all)",
    )
    args = parser.parse_args(argv)

    selected_rules = None
    if args.rules:
        selected_rules = set(args.rules.split(","))
        unknown = selected_rules - set(ALL_RULES)
        if unknown:
            print(
                f"fractal-build-lint: unknown rules: {', '.join(sorted(unknown))}",
                file=sys.stderr,
            )
            print(
                f"fractal-build-lint: available rules: {', '.join(ALL_RULES)}",
                file=sys.stderr,
            )
            return 1

    all_diags: list[Diagnostic] = []
    for filepath in args.files:
        all_diags.extend(
            lint_file(filepath, fix=args.fix, selected_rules=selected_rules)
        )

    for d in all_diags:
        print(format_diagnostic(d))

    return 1 if all_diags else 0


if __name__ == "__main__":
    raise SystemExit(main())

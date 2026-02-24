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

"""Fractal lint — custom style linter for ZKX.

Enforces project-specific rules from .gemini/styleguide.md that are not covered
by clang-format, cpplint, or clang-tidy.

Usage:
    fractal-lint [--fix] [--rules=rule1,rule2] file1.cc file2.h ...
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
# Suppression helpers
# ---------------------------------------------------------------------------

_SUPPRESS_RE = re.compile(r"fractal-lint:\s*disable=(\S+)")
_SUPPRESS_NEXT_RE = re.compile(r"fractal-lint:\s*disable-next-line=(\S+)")


def _is_suppressed(lines: list[str], line_idx: int, rule: str) -> bool:
    """Check if a rule is suppressed on this line or by the previous line."""
    line = lines[line_idx]
    m = _SUPPRESS_RE.search(line)
    if m and rule in m.group(1).split(","):
        return True
    if line_idx > 0:
        prev = lines[line_idx - 1]
        m = _SUPPRESS_NEXT_RE.search(prev)
        if m and rule in m.group(1).split(","):
            return True
    return False


# ---------------------------------------------------------------------------
# C++ parsing utilities
# ---------------------------------------------------------------------------


def _strip_strings_and_comments(line: str) -> str:
    """Replace string literal contents and comments with spaces.

    This is a rough approximation — good enough for pattern matching but does
    not handle raw strings or multi-line block comments.
    """
    result = []
    i = 0
    n = len(line)
    while i < n:
        if line[i] == '"' and (i == 0 or line[i - 1] != "\\"):
            result.append('"')
            i += 1
            while i < n and not (line[i] == '"' and line[i - 1] != "\\"):
                result.append(" ")
                i += 1
            if i < n:
                result.append('"')
                i += 1
        elif line[i] == "'" and (i == 0 or line[i - 1] != "\\"):
            result.append("'")
            i += 1
            while i < n and not (line[i] == "'" and line[i - 1] != "\\"):
                result.append(" ")
                i += 1
            if i < n:
                result.append("'")
                i += 1
        elif i + 1 < n and line[i] == "/" and line[i + 1] == "/":
            # Keep the // comment text as-is (some rules inspect comments).
            result.append(line[i:])
            break
        else:
            result.append(line[i])
            i += 1
    return "".join(result)


def _extract_includes(
    lines: list[str], skip_conditional: bool = False
) -> list[tuple[int, str]]:
    """Return (0-based line index, include path) for each #include.

    If skip_conditional is True, skip includes inside #if/#ifdef blocks
    (excluding the top-level header guard).
    """
    result = []
    ifdef_depth = 0
    # Detect header guard: #ifndef FOO_H_ at the top is depth 1, not a real
    # conditional.
    header_guard_depth = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#if"):
            ifdef_depth += 1
            # First #ifndef with _H_ pattern is likely a header guard.
            if ifdef_depth == 1 and re.match(r"#ifndef\s+\w+_H_$", stripped):
                header_guard_depth = 1
        elif stripped.startswith("#endif"):
            ifdef_depth = max(0, ifdef_depth - 1)
        elif stripped.startswith("#include"):
            # Effective depth: subtract 1 if inside header guard.
            effective_depth = ifdef_depth - header_guard_depth
            if not skip_conditional or effective_depth == 0:
                m = re.match(r'#include\s+["<]([^">]+)[">]', stripped)
                if m:
                    result.append((i, m.group(1)))
    return result


_CLASS_START_RE = re.compile(
    r"^\s*(?:template\s*<[^>]*>\s*)?"
    r"(class|struct)"
    r"\s+(?:\[\[[^\]]*\]\]\s+)?"  # Optional C++ attributes [[...]].
    r"(\w+)"
)
_STATIC_METHOD_RE = re.compile(
    r"^\s+static\s+(?!constexpr\b|const\b|inline\b)(.+?)\s+(\w+)\s*\("
)
_STATIC_METHOD_FULL_RE = re.compile(r"^\s+static\s+(.+?)\s+(\w+)\s*\(")


def _find_static_methods_in_header(
    lines: list[str],
) -> list[tuple[str, str]]:
    """Find (class_name, method_name) for static methods declared in headers."""
    results = []
    current_class = None
    brace_depth = 0
    class_brace_depth = None

    for line in lines:
        stripped = line.strip()
        # Track class/struct start.
        if current_class is None:
            m = _CLASS_START_RE.match(line)
            if m and "{" in line:
                current_class = m.group(2)
                class_brace_depth = brace_depth
                brace_depth += line.count("{") - line.count("}")
                continue
            elif m and ";" not in line:
                # Forward declaration has ; — class definition may be on next
                # lines.  We look for { on the same line above, but also handle
                # the case where { is on the next line via brace tracking.
                current_class = m.group(2)
                class_brace_depth = brace_depth
                brace_depth += line.count("{") - line.count("}")
                continue

        if current_class is not None:
            # Look for static method declarations.
            m = _STATIC_METHOD_FULL_RE.match(line)
            if m and ";" in line:
                method_name = m.group(2)
                results.append((current_class, method_name))

        # Update brace depth.
        brace_depth += line.count("{") - line.count("}")
        if (
            current_class is not None
            and class_brace_depth is not None
            and brace_depth <= class_brace_depth
        ):
            current_class = None
            class_brace_depth = None

    return results


def _find_pointer_members(
    lines: list[str],
) -> list[tuple[int, str]]:
    """Find raw pointer members in class/struct bodies.

    Returns (0-based line index, member declaration text).
    """
    results = []
    in_class = False
    brace_depth = 0
    class_brace_depth = None

    smart_ptrs = {"std::unique_ptr", "std::shared_ptr", "std::weak_ptr"}

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Track class/struct start.
        if not in_class:
            m = _CLASS_START_RE.match(line)
            if m and ("{" in line or ";" not in line):
                if ";" in line and "{" not in line:
                    continue  # Forward declaration.
                in_class = True
                class_brace_depth = brace_depth

        if in_class:
            # Look for raw pointer members: Type* name_; or Type *name_;
            # Skip lines in method bodies (deeper brace depth).
            member_depth = (class_brace_depth or 0) + 1
            if brace_depth == member_depth:
                # Match patterns like: SomeType* member_name_;
                pm = re.match(r"(\w[\w:<>]*)\s*\*\s+(\w+_)\s*[;=]", stripped)
                if not pm:
                    # Match: SomeType *member_name_;
                    pm = re.match(r"(\w[\w:<>]*)\s+\*(\w+_)\s*[;=]", stripped)
                if pm:
                    type_name = pm.group(1)
                    # Skip smart pointers and void*.
                    if type_name == "void":
                        continue
                    if any(type_name.startswith(sp) for sp in smart_ptrs):
                        continue

                    # Check for ownership comment on same or previous line.
                    # Accept any comment containing ownership-related words.
                    def _has_ownership_comment(text: str) -> bool:
                        comment_start = text.find("//")
                        if comment_start < 0:
                            return False
                        comment = text[comment_start:].lower()
                        return "owned" in comment or "owns" in comment

                    if _has_ownership_comment(line):
                        continue
                    if i > 0 and _has_ownership_comment(lines[i - 1]):
                        continue
                    results.append((i, stripped))

        # Update brace depth.
        brace_depth += line.count("{") - line.count("}")
        if (
            in_class
            and class_brace_depth is not None
            and brace_depth <= class_brace_depth
        ):
            in_class = False
            class_brace_depth = None

    return results


def _compute_scope_info(
    lines: list[str],
) -> list[tuple[bool, bool, int, int]]:
    """For each line, compute (in_anonymous_ns, in_class, brace_depth, ns_depth).

    ns_depth tracks how many namespace braces are open, so
    ``brace_depth == ns_depth`` means the line is at namespace scope
    (not inside a function or class body).

    Returns a list parallel to lines.
    """
    info = []
    brace_depth = 0
    ns_depth = 0
    anon_ns_depth = None
    class_depth = None
    # Stack of brace depths where namespaces were opened.
    ns_stack: list[int] = []

    for line in lines:
        stripped = line.strip()

        # Detect namespace start (named or anonymous).
        ns_match = re.match(r"^namespace\b", stripped)
        if ns_match and "{" in line:
            if re.match(r"^namespace\s*\{", stripped):
                anon_ns_depth = brace_depth
            ns_stack.append(brace_depth)

        # Detect class/struct start.
        if class_depth is None:
            m = _CLASS_START_RE.match(line)
            if m and ("{" in line or (";" not in line)):
                if ";" in line and "{" not in line:
                    pass  # Forward declaration.
                else:
                    class_depth = brace_depth

        in_anon = anon_ns_depth is not None and brace_depth > anon_ns_depth
        in_cls = class_depth is not None and brace_depth > class_depth
        ns_depth = len(ns_stack)
        info.append((in_anon, in_cls, brace_depth, ns_depth))

        # Update brace depth.
        brace_depth += line.count("{") - line.count("}")

        # Check if anonymous namespace or class ended.
        if anon_ns_depth is not None and brace_depth <= anon_ns_depth:
            anon_ns_depth = None
        if class_depth is not None and brace_depth <= class_depth:
            class_depth = None
        # Pop namespace stack when its brace closes.
        while ns_stack and brace_depth <= ns_stack[-1]:
            ns_stack.pop()

    return info


# ---------------------------------------------------------------------------
# Rule implementations
# ---------------------------------------------------------------------------


def check_abseil_string_view(
    filepath: str, lines: list[str], fix: bool
) -> tuple[list[Diagnostic], list[str]]:
    """Rule: abseil-string-view — prefer std::string_view."""
    rule = "abseil-string-view"
    diags = []
    new_lines = list(lines)

    for i, line in enumerate(lines):
        if _is_suppressed(lines, i, rule):
            continue
        cleaned = _strip_strings_and_comments(line)
        # Only check code portion (not comments).
        code_part = cleaned.split("//")[0] if "//" in cleaned else cleaned
        if "absl::string_view" in code_part:
            diags.append(
                Diagnostic(
                    file=filepath,
                    line=i + 1,
                    rule=rule,
                    message="Use std::string_view instead of absl::string_view",
                )
            )
            if fix:
                new_lines[i] = line.replace("absl::string_view", "std::string_view")

    return diags, new_lines


def check_nolint_type(filepath: str, lines: list[str]) -> list[Diagnostic]:
    """Rule: nolint-type — NOLINT must include (category)."""
    rule = "nolint-type"
    diags = []

    # Match NOLINT, NOLINTNEXTLINE, NOLINTBEGIN, NOLINTEND not followed by (.
    # Word boundary \b prevents matching "NOLINT" inside "NOLINTNEXTLINE".
    pat = re.compile(r"NOLINT(NEXTLINE|BEGIN|END)?\b\s*([^(:]|$)")
    # Also match the colon form: NOLINT: something (should use parentheses).
    colon_pat = re.compile(r"NOLINT(NEXTLINE|BEGIN|END)?\b\s*:")

    for i, line in enumerate(lines):
        if _is_suppressed(lines, i, rule):
            continue
        # Only check inside comments.
        comment_start = line.find("//")
        if comment_start < 0:
            # Check block comment start on this line.
            comment_start = line.find("/*")
        if comment_start < 0:
            continue
        comment = line[comment_start:]
        # Check colon form first (more specific message).
        if colon_pat.search(comment):
            diags.append(
                Diagnostic(
                    file=filepath,
                    line=i + 1,
                    rule=rule,
                    message=(
                        "NOLINT must use parentheses: "
                        "use NOLINT(category) instead of NOLINT: category"
                    ),
                )
            )
        elif pat.search(comment):
            diags.append(
                Diagnostic(
                    file=filepath,
                    line=i + 1,
                    rule=rule,
                    message=(
                        "NOLINT must specify category: "
                        "use NOLINT(category) instead of bare NOLINT"
                    ),
                )
            )

    return diags


def check_license_header(filepath: str, lines: list[str]) -> list[Diagnostic]:
    """Rule: license-header — every file must have a copyright header."""
    rule = "license-header"
    diags = []

    basename = os.path.basename(filepath)

    # Empty BUILD.bazel files are exempt.
    if basename == "BUILD.bazel" and (not lines or all(l.strip() == "" for l in lines)):
        return diags

    # Check first 20 lines for copyright notice.
    header_text = "\n".join(lines[:20])
    has_zkx = "Copyright" in header_text and "ZKX Authors" in header_text
    has_openxla = "Copyright" in header_text and "OpenXLA Authors" in header_text

    if not has_zkx and not has_openxla:
        diags.append(
            Diagnostic(
                file=filepath,
                line=1,
                rule=rule,
                message="Missing copyright header (expected ZKX or OpenXLA Authors)",
            )
        )

    return diags


def check_redundant_include(
    filepath: str, lines: list[str], fix: bool
) -> tuple[list[Diagnostic], list[str]]:
    """Rule: redundant-include — .cc must not re-include headers from .h."""
    rule = "redundant-include"
    diags = []
    new_lines = list(lines)

    if not filepath.endswith(".cc"):
        return diags, new_lines

    # Find the corresponding .h file.
    header_path = filepath[:-3] + ".h"
    if not os.path.isfile(header_path):
        return diags, new_lines

    try:
        with open(header_path, encoding="utf-8", errors="replace") as f:
            header_lines = f.readlines()
        header_lines = [l.rstrip("\n") for l in header_lines]
    except OSError:
        return diags, new_lines

    header_includes = {
        inc for _, inc in _extract_includes(header_lines, skip_conditional=True)
    }
    cc_includes = _extract_includes(lines, skip_conditional=True)

    # The .cc's own header include is not redundant.
    # Normalize: the .cc typically includes its own header as a relative path.
    own_header = None
    for _, inc in cc_includes:
        # Match if the include path ends with the .h filename.
        if header_path.endswith(inc) or inc.endswith(os.path.basename(header_path)):
            own_header = inc
            break

    removed_lines = set()
    for line_idx, inc in cc_includes:
        if _is_suppressed(lines, line_idx, rule):
            continue
        if inc == own_header:
            continue
        if inc in header_includes:
            diags.append(
                Diagnostic(
                    file=filepath,
                    line=line_idx + 1,
                    rule=rule,
                    message=f'Redundant #include "{inc}" (already in {os.path.basename(header_path)})',
                )
            )
            if fix:
                removed_lines.add(line_idx)

    if fix and removed_lines:
        new_lines = [l for i, l in enumerate(lines) if i not in removed_lines]

    return diags, new_lines


def check_static_annotation(filepath: str, lines: list[str]) -> list[Diagnostic]:
    """Rule: static-annotation — // static above static method defs in .cc."""
    rule = "static-annotation"
    diags = []

    if not filepath.endswith(".cc"):
        return diags

    # Find the corresponding .h file.
    header_path = filepath[:-3] + ".h"
    if not os.path.isfile(header_path):
        return diags

    try:
        with open(header_path, encoding="utf-8", errors="replace") as f:
            header_lines = f.readlines()
        header_lines = [l.rstrip("\n") for l in header_lines]
    except OSError:
        return diags

    static_methods = _find_static_methods_in_header(header_lines)
    if not static_methods:
        return diags

    # Build a set of "ClassName::MethodName" to look for.
    static_set = {f"{cls}::{meth}" for cls, meth in static_methods}

    # Compute scope info to distinguish definitions (namespace scope) from
    # calls (inside function bodies).
    scope_info = _compute_scope_info(lines)

    # Scan .cc for method definitions matching the pattern.
    for i, line in enumerate(lines):
        if _is_suppressed(lines, i, rule):
            continue
        stripped = line.strip()
        _, in_cls, _, _ = scope_info[i]
        if in_cls:
            continue

        for qualified in static_set:
            if qualified + "(" not in stripped and qualified + " (" not in stripped:
                continue

            # Distinguish definition from call: a definition starts with a
            # return type; a call is preceded by return/=/,/( etc.
            idx = stripped.find(qualified)
            prefix = stripped[:idx].rstrip()
            if prefix and prefix[-1] in ("(", ",", "=", ".", ">"):
                continue
            if prefix.startswith("return"):
                continue

            has_static_comment = False
            j = i - 1
            while j >= 0 and lines[j].strip() == "":
                j -= 1
            if j >= 0 and lines[j].strip() == "// static":
                has_static_comment = True
            if not has_static_comment:
                diags.append(
                    Diagnostic(
                        file=filepath,
                        line=i + 1,
                        rule=rule,
                        message=(
                            f"Missing '// static' comment above "
                            f"static method definition {qualified}()"
                        ),
                    )
                )
            break

    return diags


def check_pointer_ownership(filepath: str, lines: list[str]) -> list[Diagnostic]:
    """Rule: pointer-ownership — raw T* members need ownership annotation."""
    rule = "pointer-ownership"
    diags = []

    if not filepath.endswith(".h"):
        return diags

    members = _find_pointer_members(lines)
    for line_idx, decl in members:
        if _is_suppressed(lines, line_idx, rule):
            continue
        diags.append(
            Diagnostic(
                file=filepath,
                line=line_idx + 1,
                rule=rule,
                message=(
                    f"Raw pointer member needs ownership annotation: "
                    f"add '// not owned' or '// owned' — {decl}"
                ),
            )
        )

    return diags


def check_file_scope_static(filepath: str, lines: list[str]) -> list[Diagnostic]:
    """Rule: file-scope-static — use anonymous namespace instead of static."""
    rule = "file-scope-static"
    diags = []

    if not filepath.endswith(".cc"):
        return diags

    scope_info = _compute_scope_info(lines)

    # Pattern for file-scope static declarations.
    static_pat = re.compile(r"^static\s+(constexpr|const|inline\s+)?\s*\w")

    for i, line in enumerate(lines):
        if _is_suppressed(lines, i, rule):
            continue
        stripped = line.strip()

        # Skip static_assert.
        if stripped.startswith("static_assert"):
            continue

        # Skip static inside comments.
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        in_anon, in_cls, bdepth, nsdepth = scope_info[i]

        # Only flag static at namespace scope (not in anonymous namespace,
        # not in class, not inside a function body).
        if in_anon or in_cls:
            continue
        # Inside a function body: brace_depth exceeds namespace depth.
        if bdepth > nsdepth:
            continue

        if static_pat.match(stripped):
            diags.append(
                Diagnostic(
                    file=filepath,
                    line=i + 1,
                    rule=rule,
                    message=(
                        "Use anonymous namespace instead of file-scope 'static': "
                        "wrap in namespace { ... }"
                    ),
                )
            )

    return diags


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

ALL_RULES = [
    "abseil-string-view",
    "nolint-type",
    "license-header",
    "redundant-include",
    "static-annotation",
    "pointer-ownership",
    "file-scope-static",
]

CPP_EXTENSIONS = {".h", ".cc", ".cpp", ".cxx", ".hpp"}
BAZEL_NAMES = {"BUILD.bazel", "BUILD"}
BAZEL_EXTENSIONS = {".bzl"}


def _applicable_rules(filepath: str, selected_rules: set[str] | None) -> set[str]:
    """Determine which rules apply to this file."""
    ext = os.path.splitext(filepath)[1]
    basename = os.path.basename(filepath)

    applicable = set()

    if ext in CPP_EXTENSIONS:
        applicable.update(ALL_RULES)
    if basename in BAZEL_NAMES or ext in BAZEL_EXTENSIONS:
        applicable.add("license-header")

    if selected_rules is not None:
        applicable &= selected_rules

    return applicable


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def lint_file(
    filepath: str,
    fix: bool = False,
    selected_rules: set[str] | None = None,
) -> list[Diagnostic]:
    """Lint a single file. If fix=True, write auto-fixed content back."""
    rules = _applicable_rules(filepath, selected_rules)
    if not rules:
        return []

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return [Diagnostic(file=filepath, line=0, rule="io", message=str(e))]

    lines = content.split("\n")
    # Remove trailing empty string from split if file ends with newline.
    if lines and lines[-1] == "":
        lines = lines[:-1]

    all_diags: list[Diagnostic] = []
    current_lines = lines

    # --- abseil-string-view (fixable) ---
    if "abseil-string-view" in rules:
        diags, current_lines = check_abseil_string_view(filepath, current_lines, fix)
        all_diags.extend(diags)

    # --- nolint-type ---
    if "nolint-type" in rules:
        all_diags.extend(check_nolint_type(filepath, current_lines))

    # --- license-header ---
    if "license-header" in rules:
        all_diags.extend(check_license_header(filepath, current_lines))

    # --- redundant-include (fixable) ---
    if "redundant-include" in rules:
        diags, current_lines = check_redundant_include(filepath, current_lines, fix)
        all_diags.extend(diags)

    # --- static-annotation ---
    if "static-annotation" in rules:
        all_diags.extend(check_static_annotation(filepath, current_lines))

    # --- pointer-ownership ---
    if "pointer-ownership" in rules:
        all_diags.extend(check_pointer_ownership(filepath, current_lines))

    # --- file-scope-static ---
    if "file-scope-static" in rules:
        all_diags.extend(check_file_scope_static(filepath, current_lines))

    # Write back if fixes were applied.
    if fix and current_lines != lines:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(current_lines))
            if content.endswith("\n"):
                f.write("\n")

    return all_diags


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fractal lint — custom style linter for ZKX",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Files to lint",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Auto-fix fixable violations",
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
                f"fractal-lint: unknown rules: {', '.join(sorted(unknown))}",
                file=sys.stderr,
            )
            print(
                f"fractal-lint: available rules: {', '.join(ALL_RULES)}",
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

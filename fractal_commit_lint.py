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
import os
import posixpath
import re
import subprocess
import sys
from dataclasses import dataclass, field

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - exercised on 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

CONFIG_FILENAME = ".fractal-commit-lint.toml"

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
# Scope configuration
# ---------------------------------------------------------------------------


@dataclass
class ScopeConfig:
    """Repo-local scope policy loaded from .fractal-commit-lint.toml.

    Two ways a scope resolves to the paths its commits may touch:

    * directory mode (roots): a scope is any real directory under one of
      `roots`. `feat(hlo/evaluator)` -> `xla/hlo/evaluator` when roots=["xla"].
      No enumeration; a typo like `sevice` resolves to no directory and is
      rejected. Directory scopes are deepest-checked: a directory scope that
      is a strict ancestor of the changed files' common directory is rejected
      (scope-too-broad).
    * scopes (explicit exceptions): a curated name -> path-prefix(es) map for
      things directory mode can't express — abbreviations (`se` ->
      `xla/stream_executor`), root-level concept scopes (`primitive-types`),
      and deliberate multi-directory groupings (`cpu` -> backends/cpu +
      service/cpu). An explicit scope is blessed: it always satisfies the
      deepest check, so a merged `cpu` is never asked to narrow.

    exempt_paths are prefixes ignored by scope-path and deepest (cross-cutting
    files like WORKSPACE or vendored third_party trees). require_scope makes a
    scope mandatory. require_deepest_scope toggles the directory-mode depth
    check.
    """

    scopes: dict[str, list[str]]
    exempt_paths: list[str]
    require_scope: bool
    require_deepest_scope: bool = True
    roots: list[str] = field(default_factory=list)


def _as_prefix_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def load_scope_config(start_dir: str = ".") -> ScopeConfig | None:
    """Load scope policy from the nearest .fractal-commit-lint.toml.

    Returns None when no config file is present (scope checks then stay
    disabled, preserving the pre-config behaviour). Returns None with a
    warning when a config exists but no TOML parser is available.
    """
    path = os.path.join(start_dir, CONFIG_FILENAME)
    if not os.path.isfile(path):
        return None
    if tomllib is None:  # pragma: no cover - depends on interpreter
        print(
            f"fractal-commit-lint: {CONFIG_FILENAME} found but no TOML parser "
            "available; install 'tomli' on Python < 3.11 to enable scope checks",
            file=sys.stderr,
        )
        return None
    with open(path, "rb") as f:
        data = tomllib.load(f)

    raw_scopes = data.get("scopes", {})
    scopes = {name: _as_prefix_list(prefixes) for name, prefixes in raw_scopes.items()}
    return ScopeConfig(
        scopes=scopes,
        exempt_paths=_as_prefix_list(data.get("exempt_paths", [])),
        require_scope=bool(data.get("require_scope", False)),
        require_deepest_scope=bool(data.get("require_deepest_scope", True)),
        roots=_as_prefix_list(data.get("roots", [])),
    )


def staged_files() -> list[str]:
    """Return the paths staged for the in-progress commit.

    Empty when nothing is staged or git is unavailable (e.g. a CI mirror run
    that lints a message without an index) — callers skip the path check then.
    """
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "-z"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except Exception:  # pragma: no cover
        # text=True can raise UnicodeDecodeError (a ValueError, not OSError) on
        # non-UTF-8 filenames; fail soft so the linter never blocks a commit.
        return []
    return [p for p in out.split("\0") if p]


def _under_prefix(path: str, prefix: str) -> bool:
    prefix = prefix.rstrip("/")
    # An empty / "." / "/" prefix is the repository root and matches any path.
    if prefix in ("", "."):
        return True
    return path == prefix or path.startswith(prefix + "/")


def _strip_roots(path: str, roots: list[str]) -> str:
    """Drop a leading root prefix so a directory maps back to a scope name."""
    path = path.rstrip("/")
    for r in roots:
        r = r.rstrip("/")
        if path == r:
            return ""
        if path.startswith(r + "/"):
            return path[len(r) + 1:]
    return path


def resolve_scope(
    scope: str,
    config: ScopeConfig,
    is_dir,
) -> tuple[list[str] | None, bool]:
    """Resolve a scope to its path prefixes.

    Returns (prefixes, explicit). explicit=True means the scope came from the
    curated [scopes] map (blessed: exempt from the deepest check). A None
    prefixes means the scope resolved to nothing (unknown scope).
    """
    if scope in config.scopes:
        return config.scopes[scope], True
    for r in config.roots:
        cand = r.rstrip("/") + "/" + scope
        if is_dir(cand):
            return [cand], False
    if is_dir(scope):
        return [scope], False
    return None, False


def validate_scope(
    scope: str | None,
    config: ScopeConfig | None,
    files: list[str],
    is_dir=os.path.isdir,
) -> list[Diagnostic]:
    """Validate the header scope against the repo scope policy."""
    if config is None:
        return []

    if not scope:
        if config.require_scope:
            return [
                Diagnostic(line=1, rule="scope-required", message="a scope is required")
            ]
        return []

    prefixes, explicit = resolve_scope(scope, config, is_dir)
    if prefixes is None:
        hint = "a directory under " + ", ".join(config.roots) if config.roots else None
        choices = ", ".join(sorted(config.scopes))
        msg = f"unknown scope '{scope}'; expected "
        msg += " or ".join(filter(None, [hint, f"one of: {choices}" if choices else ""]))
        return [Diagnostic(line=1, rule="scope-enum", message=msg)]

    nonexempt = [
        f for f in files if not any(_under_prefix(f, e) for e in config.exempt_paths)
    ]

    # --- scope-path ---
    diags: list[Diagnostic] = []
    for path in nonexempt:
        if not any(_under_prefix(path, p) for p in prefixes):
            diags.append(
                Diagnostic(
                    line=1,
                    rule="scope-path",
                    message=(
                        f"file '{path}' is outside scope '{scope}' "
                        f"({', '.join(prefixes)})"
                    ),
                )
            )
    if diags:
        return diags  # Scope does not even cover the files; depth is moot.

    # --- scope-too-broad ---
    # Only directory scopes are depth-checked; explicit [scopes] entries are
    # blessed (a deliberate grouping like a merged `cpu` is never narrowed).
    if config.require_deepest_scope and not explicit and nonexempt:
        deepest_dir = posixpath.commonpath(nonexempt)
        if not is_dir(deepest_dir):
            deepest_dir = posixpath.dirname(deepest_dir)
        chosen_dir = prefixes[0].rstrip("/")
        if chosen_dir != deepest_dir and _under_prefix(deepest_dir, chosen_dir):
            suggest = _strip_roots(deepest_dir, config.roots) or deepest_dir
            diags.append(
                Diagnostic(
                    line=1,
                    rule="scope-too-broad",
                    message=(
                        f"scope '{scope}' is broader than necessary; all files "
                        f"fit deeper scope '{suggest}'"
                    ),
                )
            )
    return diags


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


def validate(
    lines: list[str],
    config: ScopeConfig | None = None,
    files: list[str] | None = None,
    is_dir=os.path.isdir,
) -> list[Diagnostic]:
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

    return _validate_conventional(lines, config, files or [], is_dir)


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


def _validate_conventional(
    lines: list[str],
    config: ScopeConfig | None = None,
    files: list[str] | None = None,
    is_dir=os.path.isdir,
) -> list[Diagnostic]:
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

    # --- scope-enum / scope-path / scope-too-broad / scope-required ---
    diags.extend(validate_scope(m.group("scope"), config, files or [], is_dir))

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

    try:
        config = load_scope_config()
    except Exception as e:  # malformed .fractal-commit-lint.toml, etc.
        print(f"fractal-commit-lint: error loading config: {e}", file=sys.stderr)
        return 1
    files = staged_files() if config is not None else []

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
        diags = validate(lines, config, files)

        for d in diags:
            print(format_diagnostic(d))

        if diags:
            exit_code = 1

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

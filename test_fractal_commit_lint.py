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

"""Tests for fractal_commit_lint."""

import os
import tempfile
import unittest
from unittest import mock

import fractal_commit_lint as fcl

# Fake directory tree for directory-mode resolution (no real FS needed).
DIRS = {
    "xla", "xla/hlo", "xla/hlo/ir", "xla/hlo/evaluator",
    "xla/backends", "xla/backends/cpu", "xla/backends/cpu/runtime",
    "xla/service", "xla/service/cpu", "xla/stream_executor",
}
is_dir = lambda p: p.rstrip("/") in DIRS  # noqa: E731


def rules(diags):
    return sorted(d.rule for d in diags)


def check(msg, config=None, files=None):
    return fcl.validate(fcl.parse_commit_message(msg), config, files, is_dir)


def body(header):
    return f"{header}\n\nA body that is long enough to pass the rule."


# Directory mode + curated exceptions (cpu merged, se aliased).
CFG = fcl.ScopeConfig(
    scopes={
        "cpu": ["xla/backends/cpu", "xla/service/cpu"],
        "se": ["xla/stream_executor"],
    },
    exempt_paths=["third_party"],
    require_scope=False,
    roots=["xla"],
)

# Explicit-enum-only config (no roots) — legacy mode.
ENUM = fcl.ScopeConfig(
    scopes={"hlo": ["xla/hlo"], "cpu": ["xla/backends/cpu"]},
    exempt_paths=[],
    require_scope=False,
)


class ConventionalRulesTest(unittest.TestCase):
    def test_valid_passes(self):
        self.assertEqual(check(body("feat(hlo): add a thing")), [])

    def test_unknown_type(self):
        self.assertIn("header-type", rules(check(body("frob(hlo): x"))))

    def test_uppercase_summary(self):
        self.assertIn("header-case", rules(check(body("feat(hlo): Add"))))

    def test_body_required(self):
        self.assertIn("body-missing", rules(check("feat(hlo): add a thing")))


class NoConfigTest(unittest.TestCase):
    def test_arbitrary_scope_passes(self):
        self.assertEqual(rules(check(body("feat(zk): add a thing"))), [])


class DirectoryModeTest(unittest.TestCase):
    def test_dir_scope_resolves_and_passes(self):
        diags = check(body("feat(hlo/evaluator): tweak"), CFG, ["xla/hlo/evaluator/e.cc"])
        self.assertEqual(rules(diags), [])

    def test_typo_rejected(self):
        # 'sevice' is no directory under xla/ and no [scopes] entry.
        diags = check(body("feat(sevice): x"), CFG, ["xla/service/cpu/c.cc"])
        self.assertIn("scope-enum", rules(diags))

    def test_too_broad_dir(self):
        # 'hlo' no longer matches when files sit deeper; the canonical scope is
        # the deepest common dir, so this is a plain mismatch naming it.
        diags = check(body("feat(hlo): tweak evaluator"), CFG, ["xla/hlo/evaluator/e.cc"])
        self.assertIn("scope-enum", rules(diags))
        msg = next(d.message for d in diags if d.rule == "scope-enum")
        self.assertIn("hlo/evaluator", msg)

    def test_span_siblings_uses_parent(self):
        diags = check(body("feat(hlo): cross-cut"), CFG,
                      ["xla/hlo/ir/a.cc", "xla/hlo/evaluator/b.cc"])
        self.assertEqual(rules(diags), [])

    def test_nonalias_mismatch(self):
        # A directory-derived scope that disagrees with the files is scope-enum;
        # scope-path is reserved for [scopes] alias violations (see below).
        diags = check(body("feat(hlo): x"), CFG, ["xla/service/cpu/c.cc"])
        self.assertIn("scope-enum", rules(diags))

    def test_exempt_path_ignored(self):
        diags = check(body("feat(hlo/evaluator): x"), CFG,
                      ["xla/hlo/evaluator/e.cc", "third_party/icicle/m.h"])
        self.assertEqual(rules(diags), [])


class BlessedExplicitTest(unittest.TestCase):
    def test_merged_cpu_not_narrowed(self):
        # cpu is an explicit grouping; even a runtime-only commit stays 'cpu'.
        diags = check(body("feat(cpu): x"), CFG, ["xla/backends/cpu/runtime/r.cc"])
        self.assertEqual(rules(diags), [])

    def test_cpu_covers_both_dirs(self):
        diags = check(body("feat(cpu): x"), CFG,
                      ["xla/backends/cpu/c.cc", "xla/service/cpu/d.cc"])
        self.assertEqual(rules(diags), [])

    def test_alias_resolves(self):
        diags = check(body("feat(se): x"), CFG, ["xla/stream_executor/s.cc"])
        self.assertEqual(rules(diags), [])

    def test_explicit_path_violation(self):
        diags = check(body("feat(cpu): x"), CFG, ["xla/hlo/ir/a.cc"])
        self.assertIn("scope-path", rules(diags))


class ExplicitEnumModeTest(unittest.TestCase):
    """No roots: only the [scopes] map resolves (legacy behaviour)."""

    def test_unknown_rejected(self):
        self.assertIn("scope-enum", rules(check(body("feat(zk): x"), ENUM, ["xla/hlo/a.cc"])))

    def test_known_passes(self):
        self.assertEqual(rules(check(body("feat(hlo): x"), ENUM, ["xla/hlo/ir/a.cc"])), [])

    def test_no_too_broad_without_roots(self):
        # Without roots there are no directory candidates, so explicit hlo is fine.
        self.assertEqual(rules(check(body("feat(hlo): x"), ENUM, ["xla/hlo/ir/a.cc"])), [])


class RequireScopeTest(unittest.TestCase):
    def test_missing_scope_ok_by_default(self):
        self.assertEqual(rules(check(body("feat: x"), CFG, ["xla/hlo/a.cc"])), [])

    def test_missing_scope_rejected_when_required(self):
        cfg = fcl.ScopeConfig(scopes=CFG.scopes, exempt_paths=[], require_scope=True,
                              roots=["xla"])
        self.assertIn("scope-required", rules(check(body("feat: x"), cfg, ["xla/hlo/a.cc"])))


class MergeRevertTest(unittest.TestCase):
    def test_merge_skipped(self):
        self.assertEqual(check("Merge branch 'main'", CFG, ["x"]), [])

    def test_revert_skipped(self):
        msg = "revert: feat(zk): x\n\nThis reverts commit abc123."
        self.assertEqual(rules(check(msg, CFG, ["whatever/x"])), [])


class RootPrefixTest(unittest.TestCase):
    def test_root_prefix_matches_any_path(self):
        for root in ("", ".", "/"):
            self.assertTrue(fcl._under_prefix("xla/hlo/x.cc", root))

    def test_normal_prefix_still_scoped(self):
        self.assertTrue(fcl._under_prefix("xla/hlo/x.cc", "xla/hlo"))
        self.assertFalse(fcl._under_prefix("xla/service/x.cc", "xla/hlo"))


class StagedFilesTest(unittest.TestCase):
    def test_unicode_decode_error_fails_soft(self):
        # text=True can raise UnicodeDecodeError (a ValueError, not OSError) on
        # non-UTF-8 filenames; staged_files must not crash the linter.
        err = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        with mock.patch("subprocess.run", side_effect=err):
            self.assertEqual(fcl.staged_files(), [])


class ConfigLoadErrorTest(unittest.TestCase):
    def test_malformed_toml_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".fractal-commit-lint.toml"), "w") as f:
                f.write("not valid toml [[[\n")
            with self.assertRaises(Exception):
                fcl.load_scope_config(d)

    def test_main_reports_malformed_config(self):
        with tempfile.TemporaryDirectory() as d:
            msg_path = os.path.join(d, "COMMIT_EDITMSG")
            with open(msg_path, "w") as f:
                f.write("feat: x\n\nA body that is long enough to pass.")
            with mock.patch.object(
                fcl, "load_scope_config", side_effect=ValueError("bad toml")
            ):
                self.assertEqual(fcl.main([msg_path]), 1)


# Canonical-derivation model: scope == camel_to_snake'd (and dictionary-mapped)
# directory of the changed files. CamelCase repo with a rename + a drop.
PRIME_DIRS = {
    "prime_ir", "prime_ir/Dialect", "prime_ir/Dialect/EllipticCurve",
    "prime_ir/Dialect/ModArith", "prime_ir/Dialect/Field",
    "prime_ir/src", "prime_ir/src/Field",
}
prime_is_dir = lambda p: p.rstrip("/") in PRIME_DIRS  # noqa: E731

PRIME = fcl.ScopeConfig(
    scopes={}, exempt_paths=[], require_scope=False, roots=["prime_ir"],
    dictionary={"EllipticCurve": "ec", "src": ""},
)


def pcheck(msg, files):
    return fcl.validate(fcl.parse_commit_message(msg), PRIME, files, prime_is_dir)


class CamelToSnakeTest(unittest.TestCase):
    def test_cases(self):
        c = fcl._camel_to_snake
        self.assertEqual(c("Field"), "field")
        self.assertEqual(c("ModArith"), "mod_arith")
        self.assertEqual(c("EllipticCurve"), "elliptic_curve")
        self.assertEqual(c("TensorExt"), "tensor_ext")
        self.assertEqual(c("IR"), "ir")
        self.assertEqual(c("HTTPServer"), "http_server")
        self.assertEqual(c("poly"), "poly")


class CanonicalDeriveTest(unittest.TestCase):
    def test_camel_snake_default_needs_no_dict(self):
        self.assertEqual(rules(pcheck(body("feat(dialect/mod_arith): x"),
                                      ["prime_ir/Dialect/ModArith/a.cc"])), [])

    def test_dictionary_rename(self):
        self.assertEqual(rules(pcheck(body("feat(dialect/ec): x"),
                                      ["prime_ir/Dialect/EllipticCurve/a.cc"])), [])

    def test_unrenamed_form_rejected(self):
        # With EllipticCurve->ec in the dictionary, the auto form isn't canonical.
        self.assertIn("scope-enum", rules(pcheck(
            body("feat(dialect/elliptic_curve): x"),
            ["prime_ir/Dialect/EllipticCurve/a.cc"])))

    def test_caps_rejected_structurally(self):
        # No scope-case rule: CamelCase simply can't match the lowercase canonical.
        self.assertIn("scope-enum", rules(pcheck(
            body("feat(Dialect/EllipticCurve): x"),
            ["prime_ir/Dialect/EllipticCurve/a.cc"])))

    def test_dropped_segment(self):
        # src -> "" drops, so prime_ir/src/Field derives to 'field'.
        self.assertEqual(rules(pcheck(body("feat(field): x"),
                                      ["prime_ir/src/Field/a.cc"])), [])


class DictionaryLoadTest(unittest.TestCase):
    def test_collision_warns_not_fails(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".fractal-commit-lint.toml"), "w") as f:
                f.write('[dictionary]\nEllipticCurve = "ec"\nEdwardsCurve = "ec"\n')
            with mock.patch("sys.stderr"):
                cfg = fcl.load_scope_config(d)  # must not raise
            self.assertEqual(cfg.dictionary["EdwardsCurve"], "ec")


if __name__ == "__main__":
    unittest.main()

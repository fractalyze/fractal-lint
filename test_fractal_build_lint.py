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

"""Tests for fractal_build_lint."""

import os
import tempfile
import unittest

import fractal_build_lint as fbl


def _write(d, name, text):
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _rules(diags):
    return sorted(d.rule for d in diags)


class BuildLintConfigTest(unittest.TestCase):
    def test_no_config_returns_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = fbl.load_build_config(d)
            self.assertEqual(cfg.library_rules, fbl.DEFAULT_LIBRARY_RULES)
            self.assertEqual(cfg.test_rules, fbl.DEFAULT_TEST_RULES)
            self.assertEqual(cfg.test_name_template, fbl.DEFAULT_TEST_NAME_TEMPLATE)
            self.assertEqual(cfg.rules, fbl.ALL_RULES)

    def test_config_overrides(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                fbl.CONFIG_FILENAME,
                'library_rules = ["prime_ir_cc_library"]\n'
                'test_rules = ["prime_ir_cc_test"]\n'
                'test_name_template = "{dirname}_test"\n'
                'rules = ["build-target-sort"]\n',
            )
            cfg = fbl.load_build_config(d)
            self.assertEqual(cfg.library_rules, frozenset({"prime_ir_cc_library"}))
            self.assertEqual(cfg.test_rules, frozenset({"prime_ir_cc_test"}))
            self.assertEqual(cfg.test_name_template, "{dirname}_test")
            self.assertEqual(cfg.rules, ["build-target-sort"])

    def test_unknown_rule_raises(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, fbl.CONFIG_FILENAME, 'rules = ["build-target-sort", "nope"]\n')
            with self.assertRaises(ValueError):
                fbl.load_build_config(d)

    def test_non_list_rule_set_raises(self):
        # A bare string would silently iterate into per-character "rules".
        for line in ('library_rules = "cc_library"', "test_rules = 3", "rules = true"):
            with tempfile.TemporaryDirectory() as d:
                _write(d, fbl.CONFIG_FILENAME, line + "\n")
                with self.assertRaises(ValueError):
                    fbl.load_build_config(d)

    def test_bad_test_name_template_raises(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, fbl.CONFIG_FILENAME, 'test_name_template = "{nope}_x"\n')
            with self.assertRaises(ValueError):
                fbl.load_build_config(d)
        with tempfile.TemporaryDirectory() as d:
            _write(d, fbl.CONFIG_FILENAME, "test_name_template = 5\n")
            with self.assertRaises(ValueError):
                fbl.load_build_config(d)


class TargetSortTest(unittest.TestCase):
    SRC = 'prime_ir_cc_library(name = "zzz")\nprime_ir_cc_library(name = "aaa")\n'

    def test_default_ignores_unknown_macro(self):
        # Default rule set does not include prime_ir_cc_library, so a misordered
        # custom macro is invisible — preserving pre-config behavior.
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "BUILD.bazel", self.SRC)
            self.assertEqual(fbl.lint_file(p), [])

    def test_config_enables_custom_macro(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "BUILD.bazel", self.SRC)
            cfg = fbl.BuildConfig(library_rules=frozenset({"prime_ir_cc_library"}))
            diags = fbl.lint_file(p, config=cfg)
            self.assertEqual(_rules(diags), ["build-target-sort"])

    def test_native_cc_library_checked_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(
                d,
                "BUILD.bazel",
                'cc_library(name = "zzz")\ncc_library(name = "aaa")\n',
            )
            self.assertEqual(_rules(fbl.lint_file(p)), ["build-target-sort"])


class ParserRobustnessTest(unittest.TestCase):
    """Parens/'#' inside strings or comments must not shift target boundaries."""

    def test_unbalanced_paren_in_string(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(
                d,
                "BUILD.bazel",
                'cc_library(name = "zzz", copts = ["-DX=foo("])\n'
                'cc_library(name = "aaa")\n',
            )
            self.assertEqual(_rules(fbl.lint_file(p)), ["build-target-sort"])

    def test_paren_in_comment(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(
                d,
                "BUILD.bazel",
                'cc_library(name = "zzz")  # note: foo( bar\n'
                'cc_library(name = "aaa")\n',
            )
            self.assertEqual(_rules(fbl.lint_file(p)), ["build-target-sort"])

    def test_triple_quoted_multiline_parens(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(
                d,
                "BUILD.bazel",
                'cc_library(name = "zzz")\n\n'
                "genrule(\n"
                '    name = "g",\n'
                '    cmd = """\n'
                "        echo (unbalanced ( parens ) here\n"
                '    """,\n'
                ")\n\n"
                'cc_library(name = "aaa")\n',
            )
            # The genrule block is parsed as one unit; both libs are still seen.
            self.assertEqual(_rules(fbl.lint_file(p)), ["build-target-sort"])


class TestNameTest(unittest.TestCase):
    def _build(self, d, rule, name):
        sub = os.path.join(d, "mymod")
        os.makedirs(sub)
        return _write(sub, "BUILD.bazel", f'{rule}(name = "{name}")\n')

    def test_template_applied(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._build(d, "prime_ir_cc_test", "WrongName")
            cfg = fbl.BuildConfig(test_rules=frozenset({"prime_ir_cc_test"}))
            diags = fbl.lint_file(p, config=cfg)
            self.assertEqual(_rules(diags), ["build-test-name"])
            self.assertIn("mymod_unittests", diags[0].message)

    def test_custom_template(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._build(d, "prime_ir_cc_test", "mymod_test")
            cfg = fbl.BuildConfig(
                test_rules=frozenset({"prime_ir_cc_test"}),
                test_name_template="{dirname}_test",
            )
            self.assertEqual(fbl.lint_file(p, config=cfg), [])

    def test_disabled_via_rules(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._build(d, "prime_ir_cc_test", "WrongName")
            cfg = fbl.BuildConfig(
                test_rules=frozenset({"prime_ir_cc_test"}),
                rules=["build-target-sort"],
            )
            self.assertEqual(fbl.lint_file(p, config=cfg), [])


if __name__ == "__main__":
    unittest.main()

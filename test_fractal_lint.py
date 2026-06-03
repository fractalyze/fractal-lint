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

"""Tests for fractal_lint config (enabled-rule subset)."""

import os
import tempfile
import unittest

import fractal_lint as fl


def _write(d, name, text):
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


# A .cc with no license header (license-header) using absl::string_view
# (abseil-string-view) — trips at least those two rules.
CC_SRC = "#include <string>\nvoid f(absl::string_view s) {}\n"


class LintConfigTest(unittest.TestCase):
    def test_no_config_all_rules(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(fl.load_lint_config(d).rules, fl.ALL_RULES)

    def test_config_subset(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, fl.CONFIG_FILENAME, 'rules = ["abseil-string-view"]\n')
            self.assertEqual(fl.load_lint_config(d).rules, ["abseil-string-view"])

    def test_unknown_rule_raises(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, fl.CONFIG_FILENAME, 'rules = ["nope"]\n')
            with self.assertRaises(ValueError):
                fl.load_lint_config(d)


class EnabledRulesTest(unittest.TestCase):
    def test_default_runs_all(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "x.cc", CC_SRC)
            found = {diag.rule for diag in fl.lint_file(p)}
            self.assertIn("abseil-string-view", found)
            self.assertIn("license-header", found)

    def test_enabled_subset_limits_rules(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "x.cc", CC_SRC)
            found = {
                diag.rule
                for diag in fl.lint_file(p, enabled_rules={"abseil-string-view"})
            }
            self.assertEqual(found, {"abseil-string-view"})

    def test_cli_rules_narrows_enabled(self):
        # --rules (selected) intersect config-enabled: empty result when disjoint.
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, "x.cc", CC_SRC)
            found = fl.lint_file(
                p,
                selected_rules={"license-header"},
                enabled_rules={"abseil-string-view"},
            )
            self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()

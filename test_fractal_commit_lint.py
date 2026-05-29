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

import unittest

import fractal_commit_lint as fcl


def rules(diags):
    return sorted(d.rule for d in diags)


def check(msg, config=None, files=None):
    return fcl.validate(fcl.parse_commit_message(msg), config, files)


CONFIG = fcl.ScopeConfig(
    scopes={
        "hlo": ["xla/hlo"],
        "cpu": ["xla/backends/cpu", "xla/service/cpu"],
    },
    exempt_paths=["WORKSPACE", "third_party/"],
    require_scope=False,
)


class ConventionalRulesTest(unittest.TestCase):
    def test_valid_commit_passes(self):
        msg = "feat(hlo): add a thing\n\nA body that is comfortably long enough."
        self.assertEqual(check(msg), [])

    def test_unknown_type(self):
        msg = "frobnicate(hlo): do stuff\n\nA body that is long enough to pass."
        self.assertIn("header-type", rules(check(msg)))

    def test_uppercase_summary(self):
        msg = "feat(hlo): Add a thing\n\nA body that is long enough to pass it."
        self.assertIn("header-case", rules(check(msg)))

    def test_body_required(self):
        self.assertIn("body-missing", rules(check("feat(hlo): add a thing")))

    def test_docs_needs_no_body(self):
        self.assertEqual(check("docs: tweak the readme wording"), [])


class ScopeConfigDisabledTest(unittest.TestCase):
    """Without a config, scope content is not validated (legacy behaviour)."""

    def test_arbitrary_scope_passes_without_config(self):
        msg = "feat(zk): add a thing\n\nA body that is long enough to pass here."
        self.assertEqual(rules(check(msg)), [])


class ScopeEnumTest(unittest.TestCase):
    def test_unknown_scope_rejected(self):
        msg = "feat(zk): add a thing\n\nA body that is long enough to pass it."
        diags = check(msg, CONFIG, ["xla/hlo/ir/hlo_opcode.cc"])
        self.assertIn("scope-enum", rules(diags))

    def test_known_scope_in_folder_passes(self):
        msg = "feat(hlo): add a thing\n\nA body that is long enough to pass it."
        diags = check(msg, CONFIG, ["xla/hlo/ir/hlo_opcode.cc"])
        self.assertEqual(rules(diags), [])

    def test_missing_scope_optional_by_default(self):
        msg = "feat: add a thing\n\nA body that is long enough to pass this."
        self.assertEqual(rules(check(msg, CONFIG, ["xla/hlo/x.cc"])), [])

    def test_missing_scope_rejected_when_required(self):
        cfg = fcl.ScopeConfig(scopes=CONFIG.scopes, exempt_paths=[], require_scope=True)
        msg = "feat: add a thing\n\nA body that is long enough to pass this."
        self.assertIn("scope-required", rules(check(msg, cfg, ["xla/hlo/x.cc"])))


class ScopePathTest(unittest.TestCase):
    def test_file_outside_scope_rejected(self):
        msg = "feat(hlo): add a thing\n\nA body that is long enough to pass it."
        diags = check(msg, CONFIG, ["xla/backends/cpu/runtime/ntt_thunk.cc"])
        self.assertIn("scope-path", rules(diags))

    def test_multiple_prefixes_for_one_scope(self):
        msg = "feat(cpu): add a thing\n\nA body that is long enough to pass it."
        files = ["xla/backends/cpu/runtime/ntt_thunk.cc", "xla/service/cpu/thunk_emitter.cc"]
        self.assertEqual(rules(check(msg, CONFIG, files)), [])

    def test_exempt_path_ignored(self):
        msg = "feat(hlo): add a thing\n\nA body that is long enough to pass it."
        files = ["xla/hlo/ir/hlo_opcode.cc", "third_party/icicle/msm.h"]
        self.assertEqual(rules(check(msg, CONFIG, files)), [])

    def test_prefix_is_path_boundary_not_substring(self):
        # 'xla/hlobby' must not match the 'xla/hlo' prefix.
        msg = "feat(hlo): add a thing\n\nA body that is long enough to pass it."
        diags = check(msg, CONFIG, ["xla/hlobby/x.cc"])
        self.assertIn("scope-path", rules(diags))

    def test_no_files_skips_path_check(self):
        # CI/amend with no resolvable staged set: enum still applies, path does not.
        msg = "feat(hlo): add a thing\n\nA body that is long enough to pass it."
        self.assertEqual(rules(check(msg, CONFIG, [])), [])


NESTED = fcl.ScopeConfig(
    scopes={
        "hlo": ["xla/hlo"],
        "evaluator": ["xla/hlo/evaluator"],
        "ir": ["xla/hlo/ir"],
    },
    exempt_paths=["WORKSPACE"],
    require_scope=False,
    require_deepest_scope=True,
)


class ScopeDeepestTest(unittest.TestCase):
    def body(self, header):
        return f"{header}\n\nA body that is long enough to pass the rule."

    def test_too_broad_when_deeper_fits(self):
        diags = check(
            self.body("feat(hlo): tweak the evaluator"),
            NESTED,
            ["xla/hlo/evaluator/eval.cc"],
        )
        self.assertIn("scope-too-broad", rules(diags))

    def test_message_suggests_deepest(self):
        diags = check(
            self.body("feat(hlo): tweak the evaluator"),
            NESTED,
            ["xla/hlo/evaluator/eval.cc"],
        )
        msg = next(d.message for d in diags if d.rule == "scope-too-broad")
        self.assertIn("evaluator", msg)
        self.assertNotIn("ir", msg)  # ir does not cover these files

    def test_deepest_scope_passes(self):
        diags = check(
            self.body("feat(evaluator): tweak it"),
            NESTED,
            ["xla/hlo/evaluator/eval.cc"],
        )
        self.assertEqual(rules(diags), [])

    def test_broad_scope_ok_when_files_span_subdirs(self):
        # Files in both evaluator/ and ir/ — only hlo covers all, so hlo is fine.
        diags = check(
            self.body("feat(hlo): cross-cutting change"),
            NESTED,
            ["xla/hlo/evaluator/eval.cc", "xla/hlo/ir/instr.cc"],
        )
        self.assertEqual(rules(diags), [])

    def test_opt_out_disables_too_broad(self):
        cfg = fcl.ScopeConfig(
            scopes=NESTED.scopes,
            exempt_paths=NESTED.exempt_paths,
            require_scope=False,
            require_deepest_scope=False,
        )
        diags = check(
            self.body("feat(hlo): tweak the evaluator"),
            cfg,
            ["xla/hlo/evaluator/eval.cc"],
        )
        self.assertEqual(rules(diags), [])


class MergeAndRevertTest(unittest.TestCase):
    def test_merge_skipped(self):
        self.assertEqual(check("Merge branch 'main' into feature", CONFIG, ["x"]), [])

    def test_revert_skipped_by_scope(self):
        msg = "revert: feat(zk): add a thing\n\nThis reverts commit abc123."
        self.assertEqual(rules(check(msg, CONFIG, ["whatever/x"])), [])


if __name__ == "__main__":
    unittest.main()

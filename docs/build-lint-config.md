# build-lint config (`.fractal-build-lint.toml`)

`fractal-build-lint` checks `BUILD.bazel` files for two conventions:

- **`build-target-sort`** — *library* targets must be alphabetically sorted by
  `name` within a file (auto-fixed, unless a non-library target is interleaved
  between the first and last library target, in which case the fix is skipped
  to avoid mangling the file).
- **`build-test-name`** — *test* targets must be named from the test-name
  template.

Which rule names count as "library" or "test", the test-name template, and
which rules run are repo-local. Drop a `.fractal-build-lint.toml` at the repo
root (resolved from the current working directory, like
`.fractal-commit-lint.toml`).

## Keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `library_rules` | list[str] | `["cc_library", "zkx_cc_library"]` | Rule names whose targets `build-target-sort` orders. |
| `test_rules` | list[str] | `["cc_test", "zkx_cc_unittest"]` | Rule names whose names `build-test-name` checks. |
| `test_name_template` | str | `"{dirname}_unittests"` | Expected test name; `{dirname}` = the BUILD file's directory basename. |
| `rules` | list[str] | all | Enabled-rule subset (whole-rule opt-out). |

With **no** config file the defaults above apply, so repos that predate the
config (and only use native/`zkx_*` rules) are unaffected.

To disable just `build-test-name`, either drop it from `rules` or set
`test_rules = []` (no rule matches → nothing to name-check) — the latter is the
finer-grained knob, leaving `build-target-sort` on.

## Examples

prime_ir — custom macros, sort + `{dirname}_unittests` naming:

```toml
library_rules = ["cc_library", "prime_ir_cc_library"]
test_rules = ["prime_ir_cc_test"]
test_name_template = "{dirname}_unittests"
```

A repo that wants only target sorting (its tests aren't dirname-derived):

```toml
library_rules = ["cc_library", "xla_cc_library"]
rules = ["build-target-sort"]
```

## Suppression

Per-target, on the line above the target call:

```python
# fractal-build-lint: disable=build-target-sort
xla_cc_library(name = "out_of_order_on_purpose")
```

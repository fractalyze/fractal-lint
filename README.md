# fractal-lint

Custom style linter for ZKX C++ code. Enforces project-specific rules not
covered by clang-format, cpplint, or clang-tidy.

## Rules

| Rule | Description | Fix |
| --- | --- | --- |
| `abseil-string-view` | Prefer `std::string_view` over `absl::string_view` | Yes |
| `nolint-type` | `NOLINT` must include `(category)` | No |
| `license-header` | Every file must have a copyright header | No |
| `redundant-include` | `.cc` must not re-include headers from `.h` | Yes |
| `static-annotation` | `// static` above static method defs in `.cc` | No |
| `pointer-ownership` | Raw `T*` members need ownership annotation | No |
| `file-scope-static` | Use anonymous namespace instead of `static` | No |

## Usage as pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/fractalyze/fractal-lint
  rev: v0.1.0
  hooks:
    - id: fractal-lint
```

## CLI usage

```bash
# Lint files
fractal-lint file1.cc file2.h

# Auto-fix fixable violations
fractal-lint --fix file1.cc

# Run specific rules only
fractal-lint --rules=abseil-string-view,nolint-type file1.cc
```

## Commit message linting (`fractal-commit-lint`)

Enforces Conventional Commits at the `commit-msg` stage: a valid type, a
lowercase summary with no trailing period and a header ≤ 80 chars, a blank
line before the body, and a non-empty body (except `docs`).

### Scope policy (optional)

By default the `<scope>` is free-form — any text passes. Drop a
`.fractal-commit-lint.toml` at the repo root to constrain it:

```toml
# Files a commit may touch are determined by its scope. A scope not listed
# here is rejected; a file outside its scope's folders is rejected.
exempt_paths = ["WORKSPACE", "third_party/"]  # cross-cutting, skipped by scope-path
require_scope = false                          # set true to make scope mandatory
require_deepest_scope = true                   # prefer the most specific scope (default)

[scopes]
hlo = "xla/hlo"
evaluator = "xla/hlo/evaluator"
cpu = ["xla/backends/cpu", "xla/service/cpu"]
gpu = ["xla/backends/gpu", "xla/service/gpu", "xla/codegen"]
```

This adds these rules, active only when the config file is present:

| Rule | Description |
| --- | --- |
| `scope-enum` | `<scope>` must be a key in `[scopes]` |
| `scope-path` | every staged file must live under one of the scope's prefixes (or `exempt_paths`) |
| `scope-too-broad` | if a strictly more specific declared scope also covers every file, use it (e.g. a commit touching only `xla/hlo/evaluator/` must be `evaluator`, not `hlo`); disable with `require_deepest_scope = false` |
| `scope-required` | a scope must be present (only when `require_scope = true`) |

The staged set comes from `git diff --cached`; when it can't be resolved
(a CI run linting a message with no index), `scope-path` is skipped while
`scope-enum` still applies. Repos without the config file are unaffected.

## Suppression

Suppress on the same line:

```c++
absl::string_view x;  // fractal-lint: disable=abseil-string-view
```

Suppress the next line:

```c++
// fractal-lint: disable-next-line=abseil-string-view
absl::string_view x;
```

## License

Apache 2.0

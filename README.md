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
`.fractal-commit-lint.toml` at the repo root to constrain it. Scopes resolve
two ways:

**Directory mode** (`roots`): a scope is any real directory under a root,
named with the root stripped — `feat(hlo/evaluator)` → `xla/hlo/evaluator`.
No enumeration; a typo like `sevice` resolves to no directory and is rejected.
A directory scope must be the *deepest* directory containing every touched
file, so a commit only under `xla/hlo/evaluator` can't be scoped `hlo`.

**Explicit `[scopes]`** (exceptions): a curated name → prefix(es) map for what
directory mode can't express — abbreviations (`se` → `xla/stream_executor`),
deliberate multi-directory groupings (`cpu` → `backends/cpu` + `service/cpu`),
and root-level concept scopes. Explicit scopes are *blessed*: they always
satisfy the depth check, so a merged `cpu` is never asked to narrow.

```toml
roots = ["xla"]                               # dirs whose children are valid scopes
exempt_paths = ["WORKSPACE", "third_party"]   # cross-cutting, skipped by scope checks
require_scope = false                          # set true to make scope mandatory
require_deepest_scope = true                   # depth-check directory scopes (default)

[scopes]
cpu = ["xla/backends/cpu", "xla/service/cpu"]  # deliberate merge — blessed
se = "xla/stream_executor"                     # abbreviation
primitive-types = ["xla/xla_data.proto", "xla/types.h"]  # root-level concept
```

Rules, active only when the config file is present:

| Rule | Description |
| --- | --- |
| `scope-enum` | `<scope>` must resolve to a directory under `roots` or a `[scopes]` key |
| `scope-path` | every staged file must live under the scope's directory/prefixes (or `exempt_paths`) |
| `scope-too-broad` | a *directory* scope must be the deepest directory covering all files (explicit scopes are exempt); disable with `require_deepest_scope = false` |
| `scope-required` | a scope must be present (only when `require_scope = true`) |

The staged set comes from `git diff --cached`; when it can't be resolved
(a CI run linting a message with no index), `scope-path`/`scope-too-broad` are
skipped while `scope-enum` still applies. Repos without the config file are
unaffected.

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

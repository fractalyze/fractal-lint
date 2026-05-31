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
`.fractal-commit-lint.toml` at the repo root to constrain it. A scope is valid
iff it equals the **canonical** scope *derived from the changed files*, or it
is a curated `[scopes]` alias. See [docs/scope-resolution.md](docs/scope-resolution.md).

**Derivation:** take the common directory of the changed files, strip a `roots`
prefix, transform each segment, drop empties, join with `/`:

```
prime_ir/Dialect/EllipticCurve/codegen.cc
  strip root "prime_ir"  → Dialect/EllipticCurve
  transform              → dialect/ec        (Dialect via camel_to_snake; EllipticCurve via dictionary)
```

Each segment is `dictionary[segment]` if mapped (a `""` value **drops** it), else
`camel_to_snake(segment)` (`ModArith` → `mod_arith`, `EllipticCurve` →
`elliptic_curve`, `IR` → `ir`). So the scope is always lowercase by
construction — `feat(Dialect/Field)` matches nothing and is rejected; no
separate case rule is needed. Most repos need no dictionary at all.

**Explicit `[scopes]`** aliases cover what derivation can't express —
abbreviations (`se` → `xla/stream_executor`), multi-directory groupings (`cpu` →
`backends/cpu` + `service/cpu`), root-level concept scopes. Aliases are
*blessed*: checked by scope-path only (their files must live under the prefixes).

```toml
roots = ["prime_ir"]                          # stripped before deriving
exempt_paths = ["WORKSPACE", "third_party"]   # cross-cutting, skipped by scope checks
require_scope = false                          # set true to make scope mandatory

[dictionary]                                   # raw segment → token; "" drops it
EllipticCurve = "ec"
src = ""
# Field, ModArith, Poly … need no entry — camel_to_snake handles them

[scopes]                                        # blessed aliases (groupings/abbrev)
cpu = ["xla/backends/cpu", "xla/service/cpu"]
se = "xla/stream_executor"
```

Rules, active only when the config file is present:

| Rule | Description |
| --- | --- |
| `scope-enum` | the scope must equal the canonical scope derived from the changed files, or be a `[scopes]` alias |
| `scope-path` | for a `[scopes]` alias, every staged file must live under one of its prefixes (or `exempt_paths`) |
| `scope-required` | a scope must be present (only when `require_scope = true`) |

The staged set comes from `git diff --cached`; when it can't be resolved
(a CI run linting a message with no index), a non-alias scope can't be derived
and the check is skipped. Repos without the config file are unaffected.

Dictionary values must be lowercase, and two segments mapping to the same token
are flagged as a load-time warning (the scope would no longer name one
component); neither fails the run.

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

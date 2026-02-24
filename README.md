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

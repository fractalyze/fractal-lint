# Commit scope resolution

`fractal-commit-lint` answers one question about a commit's scope: **is this a
valid scope, and do the changed files belong to it?** This document describes
the canonical-derivation model.

## The idea

A scope is a **semantic name, not a filesystem path**. Caps (`Field`) and
structural segments (`src`, `include`) are tells that a "scope" is really a
leaked directory. So instead of a pile of reject-rules (no-caps, no-`src`, …),
there is **one rule**:

> A scope is valid iff it equals the *canonical* scope for the changed files —
> or it is a curated `[scopes]` alias.

The canonical scope is derived from the directory the changed files live in:

```
common dir of changed files
  → strip a configured `roots` prefix
  → transform each path segment
  → drop empty segments, join with "/"
```

Segment transform: `dictionary[segment]` if the repo mapped it, else
`camel_to_snake(segment)`.

```
prime_ir/Dialect/EllipticCurve/codegen.cc
  strip root "prime_ir"      -> Dialect/EllipticCurve
  transform   Dialect->dialect (camel_to_snake)
              EllipticCurve->ec (dictionary)
  canonical   -> dialect/ec
```

`camel_to_snake` does the word-split and the lowercasing in one step
(`ModArith` → `mod_arith`, `EllipticCurve` → `elliptic_curve`, `Field` →
`field`, `IR` → `ir`), so most repos need **no dictionary at all**.

## Why this subsumes the alternatives

- **No `scope-case` rule.** The canonical scope is lowercase by construction
  (camel_to_snake + lowercase dictionary values), and the author must *match*
  it. `feat(Dialect/Field)` matches nothing → rejected. Caps can't appear.
- **No `reserved_scope_segments` rule.** Map a structural segment to the empty
  string to drop it: `src = ""`. `src/Field` → `field`. No hidden default list
  to override — a library that wants a `lib` scope simply doesn't map `lib`.
- **No raw directory passthrough.** The old `roots`/`is_dir(scope)` fallback
  accepted the dir name verbatim (`Dialect/Field`), which is the whole problem.
  Gone — scopes come only from the map or a clean derivation.

## The dictionary

```toml
roots = ["prime_ir"]

[dictionary]            # raw path segment -> scope token; "" drops the segment
EllipticCurve = "ec"    # abbreviation by taste
src = ""                # drop a structural segment
include = ""
# Field, ModArith, Poly, IR ... need no entry — camel_to_snake handles them
```

- **Values must be lowercase** (checked at config load; they feed the canonical
  form).
- **Collisions warn, never error.** If two segments map to the same token
  (`EllipticCurve = "ec"`, `EdwardsCurve = "ec"`) the scope no longer uniquely
  names a component. Validation still works (each commit derives from its own
  files), so this is a load-time *warning*, not a failure. Only dictionary
  value-uniqueness is checked (no filesystem scan).

## `[scopes]` aliases (unchanged)

The curated `[scopes]` map stays for what derivation can't express: deliberate
multi-directory groupings (`cpu = ["backends/cpu", "service/cpu"]`),
abbreviations that aren't a single dir, and root-level concept scopes. An alias
is *blessed*: it is checked by scope-path only (its files must live under its
prefixes) and is exempt from the deepest-directory check.

## Validation algorithm

```
files = changed files, minus exempt_paths
if no scope:                      ok unless require_scope
if scope in [scopes]:             ok iff every file is under the alias' prefixes  (scope-path)
else:                             derive canonical from commonpath(files)
                                  ok iff scope == canonical
                                  else: rejected — "expected '<canonical>' or a [scopes] alias"
if no files (e.g. CI title-only): non-alias scopes can't be verified -> skipped
```

The deepest-directory behaviour falls out for free: the canonical scope *is* the
deepest common directory, so a too-broad scope simply won't match.

## Migration

- Repos with lowercase directories (e.g. xla: `hlo`, `backends/gpu`) derive the
  same scopes as before — `camel_to_snake` is a no-op on already-snake names.
- Repos with CamelCase directories drop their `roots`-based path scopes in
  favour of derived snake_case (`dialect/field`) or keep short `[scopes]`
  aliases (`field`).
- `require_deepest_scope` is removed: deepest is now intrinsic to derivation;
  use a `[scopes]` alias to opt a grouping out of it.

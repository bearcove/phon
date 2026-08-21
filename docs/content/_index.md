+++
title = "phon"
description = "A typed binary exchange format and execution engine — one spec, three implementations."
+++

**phon** is a binary exchange format and execution engine: programs in different
languages serialize and deserialize values, evolve schemas over time, and speak
efficiently over RPC without paying the byte cost of self-describing formats on
every exchange.

This site is the specification. It is the source of truth: every requirement is
tagged `r[...]`, and each of the three implementations — Rust, TypeScript, and
Swift — carries `r[impl ...]` and `r[verify ...]` markers in its source. Coverage
is tracked mechanically against those markers.

## Read

- **[The spec](/spec/)** — base concepts, the type system, self-describing and
  compact modes, durable files, compatibility, validation, codegen, and the
  execution model (descriptors, IR, JIT).

## Track coverage

Coverage is computed from the `r[...]` references in each implementation. Select
one with `--impl rust|typescript|swift`:

```sh
ddc coverage status . --impl rust
ddc coverage nav . --impl typescript
ddc coverage rule compact.alignment . --impl swift
```

While `ddc serve` is running, the same views are live:

- `/_dodeca/coverage/` — browser navigation
- `/_dodeca/coverage/status.md`
- `/_dodeca/coverage/uncovered.md`
- `/_dodeca/coverage/untested.md`
- `/_dodeca/coverage/rule/<id>.md`

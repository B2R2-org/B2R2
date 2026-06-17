# AGENTS.md

Guidance for AI coding agents working in the B2R2 repository. Humans should read
[README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md) first; this file
distills the parts an agent must not get wrong.

## Linting

Run the linter locally before committing at the root of the repository:

```bash
dotnet tool restore
dotnet fslint src --strict
```

Always run the linter against the whole `src` directory, never against
individual modified files — the tool takes a directory as input.

## Coding style (strict — CI enforces it)

The full rules are in [CONTRIBUTING.md](CONTRIBUTING.md); the non-negotiables:

- **Line width = 80** columns, hard limit.
- **Indentation = 2 spaces**, never tabs.
- **LF** line endings on every file.
- Trim trailing whitespace.

F# specifics (see CONTRIBUTING.md for the complete list with examples):

- Documentation comments use `///` and go above the code; other comments use
  `(* ... *)`.
- Spacing around `=`, in tuples (`1, 2, 3`), and in list/array literals
  (`[ 1; 2; 3 ]`, `[| 1; 2; 3 |]`); `[]` not `[ ]`.
- Indexing has no inner spaces: `src[0]`, `src[1..3]`.
- Type annotations have a space after the colon: `(p: int)`.
- PascalCase members attach parens (`Func(a, b)`, `String.Replace()`);
  lowercase/curried use a space (`String.replace ()`).
- One blank line between top-level bindings; no blank lines inside a function
  body (if you want one, the function is too long — split it).
- Use `_` for unused self-identifiers, `this` only when needed; never `__`.
- Avoid parameter lists so long they must wrap onto a continuation line; if a
  signature does not fit on one line, the function has too many parameters —
  try to split it into smaller functions. Often the length comes from type
  annotations: drop them, and if it still compiles you are done; if not, add a
  single annotation at the first use site inside the function body instead, so
  the definition line stays short.

## Commit messages

Subject line format: `[Tag] Capitalized subject`, no trailing period, **≤ 50
characters**. Body is optional, wraps at 72 columns, and explains *why*. Common
tags include `[Intel]`, `[ARMv7]`, `[ARMv8]`, `[MIPS]`, `[IR]`, `[ELF]`, `[PE]`,
`[Mach]`, `[Build]`, `[CI]`, `[Doc]`, `[Test]`. Recent history also uses module
tags like `[BinIR]` and `[BinFile]` — match the area you touched.

## Notes for agents

Prefer small, focused functions — the style guide actively discourages long
function bodies.
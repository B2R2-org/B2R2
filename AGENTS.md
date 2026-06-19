# AGENTS.md

Guidance for AI coding agents working in the B2R2 repository. Humans should read
[README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md) first; this file
distills the parts an agent must not get wrong.

## Verifying changes (run after every change)

This is a test-driven project: everything is tested. After finishing any change,
run these three commands from the repository root, in order, and make sure all
three pass:

```bash
dotnet build
dotnet fslint src --strict
dotnet test
```

Always run them against the *whole* solution — never split linting or testing
per project or per file. Build the whole solution, lint the whole `src`
directory (the tool takes a directory as input), and run the whole test suite.
Run `dotnet tool restore` once beforehand if `fslint` is not yet installed.

Run each command **plainly, one per invocation** — do not chain them with `;`,
`&&`, or wrap them in `if ($?) { ... }`. The tool harness already surfaces each
command's exit code and output, so there is no need to echo a success marker;
chaining only splits into sub-statements that miss the permission allow-list and
trigger needless prompts.

Development proceeds test-first: add one unit test under the matching
`src/*.Tests` directory (each project's test directory; e.g. tests for
`src/<Project>` live in `src/<Project>.Tests`), then make it pass, re-running
the three commands each time.

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
- **`if`/`else` and `match` branch layout is all-or-nothing** (fslint does not
  catch this — keep it by hand). For an `if`/`elif`/`else`, either every branch
  body is inline on its `then`/`else` line, or every branch body sits on its own
  indented line below. Never mix: an inline `then` with a multi-line `else` (or
  vice versa) is wrong — put the inline side on its own line too. Inline form is
  allowed only when every such line fits in 80 columns.

  ```fsharp
  if length <= 0L then size, extents else grow ()   // ok: all inline, fits 80
  if length <= 0L then                               // ok: all multi-line
    size, extents
  else
    let added = ...
    ...
  if length <= 0L then size, extents                 // BAD: inline then,
  else                                               //      multi-line else
    let added = ...
  ```

  The same applies to `match`: either every case is a single `| pat -> expr`
  line, or every case puts its body on a new indented line. If one case must
  wrap, wrap them all.
- **Record literals are all-or-nothing too.** If every field fits on one line,
  write the record on a single line with `;` separators (`{ A = x; B = y }`).
  Otherwise put every field on its own line with no `;` separators — never the
  mixed form that groups some fields with `;` while spanning multiple lines.
  This holds for copy-and-update (`{ r with ... }`) as well. A nested record
  that itself fits one line stays inline (`Device = { Major = 1; Minor = 3 }`).

  ```fsharp
  { Major = 1; Minor = 3 }                  // ok: fits one line, semicolons
  { Owner = rwx                             // ok: one field per line, no ';'
    Group = rwx
    Others = rwx }
  { Owner = rwx; Group = rwx                // BAD: ';' grouping across lines
    Others = rwx }
  ```
- Use `_` for unused self-identifiers, `this` only when needed; never `__`.
- Avoid parameter lists so long they must wrap onto a continuation line; if a
  signature does not fit on one line, the function has too many parameters —
  try to split it into smaller functions. Often the length comes from type
  annotations: drop them, and if it still compiles you are done; if not, add a
  single annotation at the first use site inside the function body instead, so
  the definition line stays short.
- Order private helper functions in the sequence their caller first references
  them, so reading top-to-bottom follows the call flow. F# requires definition
  before use; when several helpers are mutually independent, the tie-break is
  the order they appear in the calling function (e.g. the helper for an earlier
  branch precedes the helper for a later one). Also keep members within a `let
  rec … and …` group separated by exactly one blank line and no comment — a
  comment between the members trips the linter.

## Commit messages

Subject line format: `[Tag] Capitalized subject`, no trailing period, **≤ 50
characters**. Body is optional, wraps at 72 columns, and explains *why*. Common
tags include `[Intel]`, `[ARMv7]`, `[ARMv8]`, `[MIPS]`, `[IR]`, `[ELF]`, `[PE]`,
`[Mach]`, `[Build]`, `[CI]`, `[Doc]`, `[Test]`. Recent history also uses module
tags like `[BinIR]` and `[BinFile]` — match the area you touched.

## Notes for agents

Prefer small, focused functions — the style guide actively discourages long
function bodies.
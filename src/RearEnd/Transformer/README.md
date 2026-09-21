Transformer REPL
================

Transformer is B2R2's interactive environment for binary analysis.  Its REPL
keeps each intermediate result as a named value and expresses a workflow as a
pipeline of transformations.  The result of one action can therefore be
inspected, reused, or transformed further without writing a separate program.

Transformer is part of B2R2.  See the repository [README](../../../README.md)
for the framework, supported formats, and supported architectures.

Running the REPL
----------------

From the repository root, start the interactive REPL with:

```
dotnet run -c Release --project src/RearEnd/Transformer -- repl
```

The `script` mode evaluates a saved REPL script without opening the TUI:

```
dotnet run -c Release --project src/RearEnd/Transformer -- script analysis.repl
```

At the prompt, `:help` lists the command-level help and `:actions` lists the
actions currently registered in the session.

Interaction
-----------

The TUI has a shell input area, a suggestion area, and a transcript/view area.
The shell accepts multiple lines.  Press `Enter` to insert a line break; append
`;;` and then press `Enter` to evaluate the input.  Script files contain the
same expressions without the interactive `;;` terminator.

| Key | Effect |
| --- | --- |
| `Tab` | Apply the selected completion. |
| `Shift+Tab` | Insert indentation spaces. |
| `Up` / `Down` | Browse input history or suggestions. |
| `Ctrl+N` / `Ctrl+P` | Select the next or previous completion. |
| `Ctrl+C` | Cancel a running action. |
| `Ctrl+D` | Leave the REPL when the input is empty. |
| `Esc` | Close an open panel or clear the current input. |
| `Shift+Up` / `Shift+Down` | Enter or leave transcript focus. |
| `Enter` or `F4` | Open the selected transcript result in view mode. |
| `PageUp` / `PageDown` | Scroll the active pane. |
| `Ctrl+Up` / `Ctrl+Down` | Move through transcript commands. |
| `Shift+Arrow` | Select text in view mode. |
| `Ctrl+F` | Find text in view mode. |
| `Ctrl+Enter` | Insert selected view text into the shell input. |
| `Alt+Arrow` | Resize the sidebar or transcript pane. |

Use the terminal's normal copy and paste shortcuts.  `:layout` can adjust the
sizes of the TUI panes.

Language
--------

An action name starts with `@`.  A pipeline passes the value on its left to the
action on its right with `|>`.  `let` retains a result under a name.

```
let target = @load path=examples/program
let matches =
  target
  |> @slice section=.text
  |> @grep pattern=837d..63 before=0 after=50
:show matches
```

Names refer to previously retained values.  Arguments have the form
`name=value`; hexadecimal addresses use `0x`, and strings use double quotes.
Lists use semicolons, for example `[ RDI=0x70000000; RDX=0x0 ]`.  A tuple such
as `(left, right)` supplies a pair to actions such as `@diff` and `@jaccard`.

`iter` applies an action to every element of a collection.  It can use an item
name in a final parameter expression.  `iteri` additionally supplies a
zero-based index.

```
:show matches |> iter @disasm
matches |> iter @strings (fun item -> min=4)
```

The REPL parses incomplete input in order to offer completions.  Its suggestions
are filtered by the syntactic position and by the kinds of values available at
that point.  A value that is not compatible with an action is reported before
the expression is evaluated.

REPL commands
-------------

| Command | Purpose |
| --- | --- |
| `:actions` | List registered actions and their usage forms. |
| `:show [name or expression]` | Display a retained value or evaluate and display an expression. |
| `:type [name or expression]` | Display an inferred REPL value kind. |
| `:inspect [name]` | List functions and sections of a binary value. |
| `:needs <context> [k=v]` | Show the concrete context required for execution. |
| `:values` | List retained values. |
| `:restore <id> [as <name>]` | Restore a historical value. |
| `:history` / `:log` | Show evaluated commands or execution history. |
| `:undo` / `:reset` | Undo the last value change or clear analysis values. |
| `:script save path=<path>` | Save recorded commands as a script. |
| `:script load path=<path>` | Reset the session and replay a script. |
| `:script record [on or off]` | Show or set script recording. |
| `:export <name> path=<path>` | Export a named value. |
| `:plugin load path=<dll>` | Load actions exported by a plugin assembly. |
| `:layout [k=v ...]` | Resize TUI panes. |
| `:quit` | Leave the REPL. |

Actions
-------

The tables below use square brackets for optional parameters.  The input is
the value immediately to the left of `|>` unless an action is listed as a
source action.

### Sources and binary data

| Action | Parameters | Description |
| --- | --- | --- |
| `@load` | `path=<path> [isa=<isa>]` or `hex=<hex> isa=<isa>` | Load a binary from a file or create one from bytes. |
| `@asm` | `code=<text> [isa=<isa>] [base=<addr>]` | Assemble source text into bytes. |
| `@random` | `min=<addr> max=<addr>` | Produce a random address in the half-open range. |
| `@user-stack` | none | Produce an address suitable for a user stack. |
| `@bytes` | none | Extract bytes from a binary or slice. |
| `@as-binary` | none | Turn a byte array into a binary value. |
| `@slice` | `section=<section>`, or `start=<addr> end=<addr>`, or `start=<addr> offset=<size>` | Select a binary section or address range. |
| `@save` | `path=<path>` | Save a binary or slice to a file. |

### Inspection and recovery

| Action | Parameters | Description |
| --- | --- | --- |
| `@grep` | `pattern=<hex-pattern> [context=<n>]`, or `[before=<n>] [after=<n>]` | Search a binary or slice for a hexadecimal byte pattern. |
| `@strings` | `[min=<n>] [pattern=<text>]` | Extract printable strings. |
| `@hexdump` | none | Render bytes as a hexadecimal dump. |
| `@disasm` | none | Disassemble a binary or slice. |
| `@lift` | none | Lift instructions to B2R2's intermediate representation. |
| `@llvm` | none | Render a binary through the LLVM representation. |
| `@list` | `sections`, `functions`, or `known-functions` | List sections, recovered functions, or functions known from binary metadata. |
| `@cfg` | `[entry=<addr>]` | Recover control-flow graphs, optionally for one entry address. |
| `@dot` | none | Render one control-flow graph as DOT text. |
| `@count` | none | Count collection elements. |
| `@pick` | `index=<n>` | Select a zero-based collection element. |
| `@print` | none | Print a value. |
| `@write` | `path=<path>` | Write text, text artifacts, or instructions to a file. |

### Comparison and fingerprints

| Action | Parameters | Description |
| --- | --- | --- |
| `@diff` | none | Compare a pair of compatible values. |
| `@winnowing` | `[n-gram-size=<n>] [window-size=<n>]` | Compute a winnowing fingerprint from bytes. |
| `@jaccard` | none | Compute the Jaccard similarity of a fingerprint pair. |
| `@dbscan` | `[eps=<n>] [min-points=<n>]` | Cluster a fingerprint collection with DBSCAN. |
| `@detect` | `path=<path>` | Search a directory with a fingerprint. |

### Binary rewriting

| Action | Parameters | Description |
| --- | --- | --- |
| `@edit insert` | `start=<addr> hex=<hex>` | Insert bytes at an address. |
| `@edit delete` | `start=<addr> end=<addr>` or `start=<addr> size=<size>` | Delete a range of bytes. |
| `@edit replace` | `start=<addr> end=<addr> hex=<hex>`, `start=<addr> size=<size> hex=<hex>`, or `start=<addr> asm=<text> [isa=<isa>]` | Replace bytes or instructions without growing the selected range. |
| `@edit force-replace` | `start=<addr> asm=<text> [isa=<isa>]` | Replace instructions while allowing a length-changing edit. |

For size-changing edits, Transformer does not update all dependent binary
layout metadata and does not guarantee the behavior of the resulting binary.

### Concrete execution

| Action | Parameters | Description |
| --- | --- | --- |
| `@make-concrete-executor` | none | Create a concrete executor for a binary or slice. |
| `@make-concrete-context` | `[stack=<addr>] [regs=<text>] [mem=<text>] [regions=<text>]` | Configure stack, registers, memory, and memory permissions. |
| `@arg` | `index=<n> value=<addr>` | Set a concrete argument value. |
| `@mem read` | `addr=<addr> size=<n>` | Read concrete memory. |
| `@mem write` | `addr=<addr> bytes=<hex>` | Write concrete memory. |
| `@regs` | `[name=<text>]` | Inspect concrete registers. |
| `@step` | `[count=<n>]` | Execute a fixed number of instructions. |
| `@trace` | `[count=<n>] [watch=<addr> size=<n>]` | Trace execution, optionally watching a memory range. |
| `@run-concrete` | `[entry=<addr>] [limit=<n>] [break=<addr>]` | Run concrete execution with optional limits and breakpoint. |

### Symbolic execution

These actions are available when a symbolic solver is loaded.

| Action | Parameters | Description |
| --- | --- | --- |
| `@make-symbolic-executor` | `[solver=<action>]` | Create a symbolic executor for a binary or slice. |
| `@make-symbolic-context` | `[pc=<addr>] [stack=<addr>] [regs=<text>] [mem=<text>] [sym-mem=<text>] [sym-regs=<text>] [regions=<text>]` | Configure concrete and symbolic execution state. |
| `@make-symbolic-arg` | `index=<n> name=<text> size=<n>` | Create a symbolic argument. |
| `@hook` | `<hook> addr=<addr>` | Model a supported external function at an address. |
| `@stop-at` | `addr=<addr>` | Stop symbolic execution at an address. |
| `@run-symbolic` | `cond=<fun> [precond=<text>] [max-depth=<n>] [max-states=<n>] [loop-bound=<n>] [prune=<choice>]` | Explore paths and solve for a condition. |
| `@model` | none | Render a symbolic run result and its satisfying model. |

An execution condition is an F#-like lambda.  For example,
`cond=(fun pp -> pp.at(0x401e5c))` asks symbolic execution to find a path that
reaches an address.  `cond=(fun _ -> mem.accessViolation())` asks it to find a
memory-access violation.

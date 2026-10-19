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
dotnet run -c Release --project src/RearEnd/Transformer
```

The explicit `repl` argument is equivalent. Transformer does not provide a
separate action-chain command-line interface: interactive commands and scripts
use the same REPL language, including action names prefixed with `@`.

The `script` mode evaluates a saved REPL script without opening the TUI:

```
dotnet run -c Release --project src/RearEnd/Transformer -- script analysis.repl
```

Press `F2` to open the control prompt.  Enter `help` for command help,
`help @<action>` for an action's usage and examples, or `actions` for concise
action summaries.

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
| `Up` / `Down` | Browse history, candidates, or input lines by context. |
| `Home` / `End` | Select the first or last candidate, history entry, or line by context. |
| `Ctrl+N` / `Ctrl+P` | Select the next or previous completion. |
| `Ctrl+A` / `Ctrl+E` | Move to the start or end of shell input. |
| `Ctrl+W` / `Ctrl+Backspace` | Delete the previous shell-input word. |
| `Ctrl+U` / `Ctrl+K` | Delete shell input before or after the cursor. |
| Click a suggestion | Apply the clicked completion. |
| `Ctrl+C` | Cancel a running action. |
| `Ctrl+D` | Leave the REPL when the input is empty. |
| `Esc` | Close an open panel or clear the current input. |
| `F1` | Open interactive help. |
| `F2` | Open the control prompt. |
| `F3` | Find text in the transcript or the current view. |
| `Shift+Up` / `Shift+Down` | Enter or leave transcript focus. |
| `Enter` or `F4` | Open the selected transcript result in view mode. |
| `PageUp` / `PageDown` | Scroll the active pane. |
| `Ctrl+Up` / `Ctrl+Down` | Move through transcript commands. |
| `Shift+Arrow` | Select text in view mode. |
| `Ctrl+F` | Find text in view mode. |
| `Ctrl+Enter` | Insert selected view text into the shell input. |
| `Alt+Arrow` | Resize the sidebar or suggestion area. |

Use the terminal's normal copy and paste shortcuts.  Use the F2 prompt's
`layout` command to adjust TUI pane sizes.

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
matches |> @print
```

Names refer to previously retained values.  The reserved name `it` refers to
the most recent successful result.  Arguments have the form
`name=value`; hexadecimal addresses use `0x`, and strings use double quotes.
Lists use semicolons, for example `[ RDI=0x70000000; RDX=0x0 ]`.  A tuple such
as `(left, right)` supplies a pair to actions such as `@compare` and
`@jaccard`.

`iter` applies an action to every element of a collection.  It can use an item
name in a final parameter expression.  `iteri` additionally supplies a
zero-based index.

```
matches |> iter @disasm |> @print
matches |> iter @extract-strings (fun item -> min=4)
```

The REPL parses incomplete input in order to offer completions.  Its suggestions
are filtered by the syntactic position and by the kinds of values available at
that point.  A value that is not compatible with an action is reported before
the expression is evaluated.

F2 controls
-----------

Press `F2` to open the control prompt and enter a control.

| Command | Purpose |
| --- | --- |
| `actions` | List concise registered-action summaries. |
| `help [@action]` | Display interactive help or one action's details. |
| `type [name or expression]` | Display an inferred REPL value kind. |
| `inspect [name]` | List functions and sections of a binary value. |
| `needs <context> [k=v]` | Show the concrete context required for execution. |
| `values` | List retained values. |
| `restore <id> [as <name>]` | Restore a historical value. |
| `history` / `log` | Show evaluated commands or execution history. |
| `undo` / `reset` | Undo the last value change or clear analysis values. |
| `script save path=<path>` | Save recorded commands as a script. |
| `script load path=<path>` | Reset the session and replay a script. |
| `script record [on or off]` | Show or set script recording. |
| `export <name> path=<path>` | Export a named value. |
| `plugin load path=<dll>` | Load actions exported by a plugin assembly. |
| `layout [k=v ...]` | Resize or reorder TUI panes. |
| `quit` | Leave the REPL. |

Actions
-------

The tables below use square brackets for optional parameters.  An action
consumes the value produced by the preceding pipeline stage; source actions
begin a pipeline.

For example, the following pipeline finds `mov`-containing nodes in the CFG of
the function named `main`:

```
let moves =
  target
  |> @list functions
  |> @filter symbol="main"
  |> @require-one
  |> @recover-cfg
  |> @list nodes
  |> @filter mnemonic="mov"
moves |> @print
```

### Sources and binary data

| Action | Parameters | Description |
| --- | --- | --- |
| `@load` | `path=<path> [isa=<isa>]`, `hex=<hex> isa=<isa>`, or ByteArray input | Load a file, create a raw image, or reconstruct a binary from extracted bytes. |
| `@asm` | `code=<text> [isa=<isa>] [base=<addr>]` | Assemble source text into bytes. |
| `@random` | `min=<int> max=<int>` | Produce an integer in `[min, max)`. |
| `@extract-bytes` | none | Extract bytes from a binary or slice. |
| `@slice` | `section=<section>`, or `start=<addr> end=<addr>`, or `start=<addr> offset=<size>` | Select a binary section or address range. |
| `@save` | `path=<path>` | Save a binary or slice to a file. |

### Inspection and recovery

| Action | Parameters | Description |
| --- | --- | --- |
| `@grep` | `pattern=<hex-pattern> [context=<n>]`, or `[before=<n>] [after=<n>]` | Search a binary or slice for a hexadecimal byte pattern. |
| `@extract-strings` | `[min=<n>] [pattern=<text>]` | Extract printable strings. |
| `@hexdump` | none | Render bytes as a hexadecimal dump. |
| `@disasm` | none | Disassemble a binary or slice. |
| `@lift` | none | Lift instructions to B2R2's intermediate representation. |
| `@export-llvm` | none | Export the LLVM representation of a binary. |
| `@list` | `sections`, `functions`, or `known-functions`; `nodes` | List binary sections/functions or CFG nodes. |
| `@recover-cfg` | `[entry=<addr>]` for a binary, none for a function | Recover CFGs from a binary or the CFG of one function. |
| `@export-dot` | none | Export one control-flow graph as DOT text. |
| `@count` | none | Count collection elements. |
| `@pick` | `index=<n>` | Select a zero-based collection element. |
| `@require-one` | none | Require a collection, list, or array to contain exactly one item. |
| `@filter` | `symbol=<name>` or `entry=<addr>`; `mnemonic=<name>` or `address=<addr>` | Filter function or CFG-node collections by a supported property. |
| `@print` | none | Render the value received from a pipeline in the transcript. |
| `@write` | `path=<path>` | Write text, text artifacts, or instructions to a file. |

### Comparison and fingerprints

| Action | Parameters | Description |
| --- | --- | --- |
| `@compare` | none | Compare a pair of compatible values. |
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
| `@make-concrete-executor` | `[stack=<addr>] [regs=<text>] [mem=<text>] [regions=<text>] [args=<text>] [buffers=<text>]` | Create and optionally configure a concrete executor. |
| `@read-memory` | `addr=<addr> size=<n>` | Read concrete memory. |
| `@write-memory` | `addr=<addr> bytes=<hex>` | Write concrete memory. |
| `@inspect-registers` | `[name=<text>]` | Inspect concrete registers. |
| `@step` | `[count=<n>]` | Execute a fixed number of instructions. |
| `@trace` | `[count=<n>] [watch=<addr> size=<n>]` | Trace execution, optionally watching a memory range. |
| `@run-concrete` | `entry=<addr> [stack=<addr>] [regs=[...]] [mem=[...]] [regions=[...]] [args=[...]] [buffers=[...]] [limit=<n>]` on a binary, or `[entry=<addr>] [limit=<n>] [break=<addr>]` on an executor | Configure and run concrete execution. |

For a one-off run, a binary can be passed directly to `@run-concrete`. The
`buffers` parameter names a region, its size and permissions, and the register
that receives its address, for example `buffers=[RDI=track:0x400:rw]`. Buffer
contents are not initialized. A synthetic stack is provided by default, and
the run stops before the outermost return. Use `@make-concrete-executor` when
the executor must be retained or configured without running it.

### Symbolic execution

These actions are available when a symbolic solver is loaded.

| Action | Parameters | Description |
| --- | --- | --- |
| `@make-symbolic-executor` | `[solver=<action>] [pc=<addr>] [stack=<addr>] [regs=<text>] [mem=<text>] [sym-mem=<text>] [sym-regs=<text>] [regions=<text>] [sym-args=<text>] [buffers=<text>] [avoid=[...]] [hooks=[...]]` | Create and optionally configure a symbolic executor. |
| `@run-symbolic` | `entry=<addr> [solver=<action>] [stack=<addr>] [regs=[...]] [mem=[...]] [sym-mem=[...]] [sym-regs=[...]] [regions=[...]] [sym-args=[...]] [buffers=[...]] [avoid=[...]] [hooks=[...]] (check=access-violation or cond=<fun>) [precond=<text>] [max-depth=<n>] [max-states=<n>] [loop-bound=<n>] [prune=<choice>]` on a binary, or `cond=<fun>` with optional limits, avoidance, and hooks on an executor | Configure and run symbolic execution. |

Direct symbolic execution selects `symb-z3`, creates a synthetic stack, maps
the requested buffers, and stops paths at the outermost return. For example,
the following pipeline needs no intermediate executor binding:

```text
target
|> @run-symbolic
  entry=functionEntry
  sym-regs=[ ESI=idx:4; RDX=ind:8 ]
  buffers=[ RDI=track:0x400:rw ]
  check=access-violation
|> @print
```

Here, `sym-regs=[ESI=idx:4; RDX=ind:8]` names two symbolic register inputs. The
`check=access-violation` query tests memory accesses against the binary's
image permissions and the buffer and stack regions. Use
`@make-symbolic-executor` to retain a configured executor before running it.
Both creation and direct execution accept solver, state, and input options.

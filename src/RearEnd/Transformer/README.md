# Transformer REPL

Transformer is B2R2's interactive environment for binary analysis. Actions
compose with `|>`, and results can be bound to names for inspection and reuse.
For supported formats and architectures, see the
[B2R2 README](../../../README.md).

## Run

From the repository root:

```sh
dotnet run -c Release --project src/RearEnd/Transformer
```

The default console layout shows input and results in sequence. To show
suggestions, the transcript, and values in separate panes, use `Ctrl+G`, then
`layout pane`, or start there with:

```sh
dotnet run -c Release --project src/RearEnd/Transformer -- repl --layout pane
```

To run a saved script without the TUI:

```sh
dotnet run -c Release --project src/RearEnd/Transformer -- script analysis.repl
```

There is no separate action CLI. Both interactive input and scripts use the
same REPL language.

## Interact

`Enter` inserts a new line. Type `;;` and press `Enter` to execute the input.
Scripts omit `;;`. `Tab` applies a completion; suggestions depend on the
current input and the kinds of values available.

| Key | Action |
| --- | --- |
| `Tab` / `Shift+Tab` | Complete / insert indentation. |
| `Ctrl+N` / `Ctrl+P` | Select the next / previous completion. |
| `Ctrl+G` | Open the control prompt. |
| `Ctrl+R` | Execute the current input. |
| `Ctrl+T` | Switch between input and the last transcript or view position. |
| `Ctrl+F` | Find in the transcript, or in the current view. |
| `Enter` in transcript | Open the selected result in view mode. |
| `Up` / `Down` | Move through input, history, or suggestions. |
| `Home` / `End` | Move to the first / last item or line. |
| `PageUp` / `PageDown` | Scroll the active pane. |
| `Ctrl+Up` / `Ctrl+Down` | Move through transcript commands. |
| `Ctrl+A` / `Ctrl+E` | Move to the start or end of the input. |
| `Ctrl+W` / `Ctrl+Backspace` | Delete the previous word. |
| `Ctrl+U` / `Ctrl+K` | Delete input before / after the cursor. |
| `Ctrl+L` | Clear the transcript. |
| `v`, arrows in transcript or view | Select text with the keyboard. |
| `i` in transcript or view | Send selected text to the input. |
| `Ctrl+Enter` in view (Windows) | Also send selected text to the input. |
| `Ctrl+C` | Copy the REPL selection or cancel a running action. |
| `Ctrl+D` | Exit when the input is empty. |
| `Esc` | Close an open panel or clear the input. |

Click a suggestion to apply its completion. In view, `Esc` cancels a selection
before returning to the transcript. In the transcript, `Esc` returns to input.
`Ctrl+R` and `;;` then `Enter` work on both Windows and macOS. On Windows,
`Ctrl+Enter` also executes the input.

Drag over REPL text and press `Ctrl+C` to copy only the selected text, without
pane borders or surrounding spaces. On macOS, the REPL uses `pbcopy`. Mac
Terminal handles `Command+V` for pasting. On Windows Terminal, the REPL sends
an OSC 52 clipboard request. In transcript or view, `v` and the arrow keys
select text for `i` to insert into the input.

The `Ctrl+G` prompt accepts `help`, `help @<action>`, and `actions`. Use
`help @<action>` for parameters and examples; `actions` lists all registered
actions. Other controls include `values`, `history`, `script save`, `script
load`, `plugin load`, `layout`, and `quit`. In pane layout, `layout resize`
starts keyboard resizing. Use arrows or `h/j/k/l` to move the dividers,
`Enter` to save, or `Esc` to cancel. `layout pane swap` (or `l p s`) swaps
the input and suggestion panes.

## Write a pipeline

Replace `<binary-path>` with a file path:

```text
binary = @load path=<binary-path>
binary |> @slice section=.text |> @disasm |> @print
```

`name = expression` retains a result. The reserved name `it` refers to the
most recent successful result. An action begins with `@`; `|>` passes the
previous result to the next action. `iter` applies an action to every item in
a collection, for example `matches |> iter @disasm |> @print`.

Actions cover loading and assembly (`@load`, `@asm`), inspection (`@slice`,
`@grep`, `@disasm`, `@lift`, `@list`, `@recover-cfg`), selection (`@filter`,
`@pick`, `@require-one`), editing (`@edit`), comparison (`@compare`), and
execution (`@run-symbolic`, `@run-concrete`). Use `Ctrl+G`, then `actions`, for the
complete list and `help @<action>` for exact syntax.

For example, a symbolic run can make two registers symbolic and provide a
memory region through a pointer register:

```text
binary
|> @run-symbolic
  entry=<function-address>
  sym-regs=[ ESI; RDX ]
  ptr-regs=[ RDI=0x400:rw ]
|> @print
```

By default, `@run-symbolic` searches for a memory access violation. To ask a
different question, supply `cond=`. A direct run uses a synthetic stack and
stops at the outermost return. `@make-symbolic-executor` retains a configured
executor when separate setup and execution are needed.

Concrete execution uses the same `ptr-regs` parameter:

```text
binary
|> @run-concrete
  entry=<function-address>
  regs=[ RSI=0x80000001; RDX=0x0 ]
  ptr-regs=[ RDI=0x400:rw ]
|> @print
```

`@run-concrete` stops before the outermost return and has a default limit of
1,000 instructions. Use `@make-concrete-executor` to retain execution state.

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

The default pane layout shows input, suggestions, a transcript, and values.
Press `F6` to switch to a console layout that shows input and results in
sequence, or start there with:

```sh
dotnet run -c Release --project src/RearEnd/Transformer -- repl --layout console
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
| `F1` | Open the guide. |
| `F2` | Open the control prompt. |
| `F3` | Find text in the transcript or current view. |
| `Ctrl+F` in view mode | Find text in the current view. |
| `F4` or `Enter` on a result | Open the full result in view mode. |
| `F6` | Switch between pane and console layouts. |
| `Up` / `Down` | Move through input, history, or suggestions. |
| `Home` / `End` | Move to the first / last item or line. |
| `PageUp` / `PageDown` | Scroll the active pane. |
| `Shift+Up` / `Shift+Down` | Enter / leave transcript focus. |
| `Ctrl+Up` / `Ctrl+Down` | Move through transcript commands. |
| `Ctrl+A` / `Ctrl+E` | Move to the start or end of the input. |
| `Ctrl+W` / `Ctrl+Backspace` | Delete the previous word. |
| `Ctrl+U` / `Ctrl+K` | Delete input before / after the cursor. |
| `Ctrl+L` | Clear the transcript. |
| `Shift+Arrow` in view mode | Select text. |
| `Ctrl+Enter` in view mode | Send selected text to the input. |
| `Alt+Arrow` | Resize the pane layout. |
| `Ctrl+C` | Copy selected text or cancel a running action. |
| `Ctrl+D` | Exit when the input is empty. |
| `Esc` | Close an open panel or clear the input. |

Click a suggestion to apply its completion. Use the terminal's usual paste
shortcut to paste text.

The `F2` prompt accepts `help`, `help @<action>`, and `actions`. Use
`help @<action>` for parameters and examples; `actions` lists all registered
actions. Other controls include `values`, `history`, `script save`, `script
load`, `plugin load`, `layout`, and `quit`.

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
execution (`@run-symbolic`, `@run-concrete`). Use `F2`, then `actions`, for the
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

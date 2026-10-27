(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.RearEnd.Transformer

/// Documentation shared by REPL commands and the interactive guide.
module ReplHelp =
  let guideLines =
    [ "REPL GUIDE"
      ""
      "Pipelines"
      "  <name> = <expression>           Bind an analysis result"
      "  <value> |> @<action> [args]      Transform the preceding value"
      "  <expression>                      Evaluate without binding"
      ""
      "Controls"
      "  F2                   Open the control command prompt"
      "  F6                   Switch between pane and console layouts"
      "  help                           Show this guide"
      "  help @<action>                 Show action usage and examples"
      "  actions                        List action documentation"
      "  values                         List retained values"
      "  history                        List evaluated commands"
      "  layout order=toggle            Swap shell and suggestions"
      "  layout pane|console            Switch the REPL layout"
      "  script save|load|record ...    Manage replay scripts"
      "  plugin load path=<dll>         Load a plugin"
      "  quit                           Leave the TUI"
      ""
      "Shell"
      "  Enter                          Insert a new line"
      "  ;; then Enter                  Execute the current input"
      "  Tab / Shift+Tab                Apply completion / insert spaces"
      "  Up / Down                      Browse history, suggestions, or lines"
      "  Ctrl+N / Ctrl+P                Select next / previous completion"
      "  Ctrl+A / Ctrl+E                Move to input start / end"
      "  Ctrl+W / Ctrl+Backspace        Delete the previous input word"
      "  Ctrl+U / Ctrl+K                Delete to input start / end"
      "  Ctrl+C             Copy selection or cancel an action"
      "  Ctrl+D                         Leave when input is empty"
      "  Click a suggestion             Apply that completion"
      "  Copy / paste                   Use the terminal's shortcuts"
      ""
      "Transcript and view"
      "  Shift+Up / Shift+Down          Enter / leave transcript focus"
      "  Enter or F4                    Open the selected result in view"
      "  PageUp / PageDown              Scroll the active pane"
      "  Ctrl+Up / Ctrl+Down            Move by command in transcript"
      "  Shift+Arrows                   Select text in view"
      "  F3                   Find text in transcript or view"
      "  Ctrl+F                         Find text in view"
      "  Ctrl+Enter           Insert view selection into input"
      "  Alt+Arrows                     Resize sidebar or suggestions"
      "  Esc                            Close a panel or clear input"
      ""
      "Mouse"
      "  Click F1-F4 / Run / Copy       Use the header controls"
      "  Click a value                 Insert a compatible binding"
      "  Double-click transcript text Select a word"
      "  Double-click a control item   Prepare that command"
      "  Right-click                  Cancel popup/find or close view"
      "  Drag text or a divider        Select text or resize a pane"
      "  Wheel                         Scroll the pointed pane" ]

  let actionLines registered =
    let metadata = (registered: RegisteredAction).Metadata
    ActionMetadata.documentationLines metadata

  let actionsLines registry =
    ActionRegistry.getAll registry
    |> List.collect (fun action -> actionLines action @ [ "" ])
    |> List.append
      [ "AVAILABLE ACTIONS"
        "Usage, parameters, and examples are listed for every action."
        "" ]

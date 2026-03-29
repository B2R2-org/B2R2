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

namespace B2R2.RearEnd.BinExplore.GUI

/// Represents the state of the main view.
type Model =
  { /// Currently loaded binary file.
    LoadedBinary: string option
    /// Path of the binary currently loading.
    LoadingBinaryPath: string option
    /// List of functions extracted from the loaded binary.
    Functions: FunctionItem list
    /// Search text used to filter the function list.
    FunctionFilter: string
    /// List of sections extracted from the loaded binary.
    Sections: SectionItem list
    /// Currently active (selected) tab.
    ActiveTab: Tab option
    /// List of currently open tabs in the main view, excluding the preview tab.
    OpenTabs: Tab list
    /// Currently open preview tab, if any.
    PreviewTab: Tab option
    /// Registered custom themes.
    CustomThemes: Map<ThemeId, Theme>
    /// Current theme mode.
    ThemeMode: ThemeMode
    /// Current UI theme.
    Theme: Theme
    /// Tab currently being dragged for reordering, if any.
    DraggingTab: Tab option
    /// Selected panel shown in the middle workspace column.
    WorkspacePanel: WorkspacePanel
    /// State of the shared hexdump workspace views.
    Hexdump: HexdumpState
    /// Flag indicating whether the user is currently panning in the CFG view.
    CFGIsPanning: bool
    /// Initial pointer position recorded when the user presses in the CFG view.
    CFGPressedPointer: (float * float) option
    /// Last pointer position used for CFG panning.
    CFGPanPointer: (float * float) option
    /// Width and height of the CFG viewport.
    CFGViewportSize: float * float
    /// Status bar information.
    StatusBarState: StatusBarState }

module Model =
  /// Returns all tabs to be displayed, including the preview tab if present.
  let getVisibleTabs model =
    match model.PreviewTab with
    | Some preview -> preview :: model.OpenTabs
    | _ -> model.OpenTabs

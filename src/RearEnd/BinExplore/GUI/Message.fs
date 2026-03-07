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

/// Represents messages that can be sent to the main view.
type Message =
  /// Message to open a binary file, carrying the file path.
  | OpenBinary of string
  /// Message emitted when binary loading has finished.
  | OpenBinaryCompleted of string
  /// Message emitted when binary loading failed.
  | OpenBinaryFailed of path: string * reason: string
  /// Message to close the currently loaded binary file.
  | CloseBinary
  /// Message to open a new tab for a specific function.
  | OpenTab of Tab
  /// Message to pin a tab, making it persist.
  | PinTab of Tab
  /// Message to close a specific tab.
  | CloseTab of Tab
  /// Message to switch to a specific tab, making it active.
  | SwitchTab of Tab
  /// Message to start dragging a tab for reordering.
  | StartTabDrag of Tab
  /// Message to reorder tabs using explicit dragged/target tab names.
  | ReorderTab of draggedTab: Tab * targetTab: Tab
  /// Message to end dragging of a tab.
  | EndTabDrag
  /// Message to register a custom theme.
  | RegisterCustomTheme of ThemeId * Theme
  /// Message to set the current UI theme mode.
  | SetThemeMode of ThemeMode
  /// Message to update function filter text.
  | UpdateFunctionFilter of string
  /// Message to switch the visible workspace panel.
  | SelectWorkspacePanel of WorkspacePanel
  /// Message to update the status message in the status bar.
  | UpdateStatus of string
  /// Message to exit the application.
  | ExitApplication

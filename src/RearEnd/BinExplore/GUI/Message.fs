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

open B2R2.RearEnd.Visualization
open B2R2.RearEnd.BinExplore

/// Represents messages that can be sent to the main view.
type Message =
  /// Message to open a binary file, carrying the file path.
  | OpenBinary of string
  /// Message emitted when binary loading has finished.
  | OpenBinaryCompleted of string
  /// Message emitted when binary loading failed.
  | OpenBinaryFailed of path: string * reason: string
  /// Message to close the current workspace.
  | CloseWorkspace
  /// Message to open a new tab for a specific function.
  | OpenCFGTab of fn: FunctionItem
  /// Message to open the shared hexdump in a tab, or activate it if already
  /// open.
  | OpenHexdumpTab
  /// Message to pin a tab, making it persist.
  | PinCFGTab of fn: FunctionItem
  /// Message to close a specific tab.
  | CloseTab of tabID: string
  /// Message to switch to a specific tab, making it active.
  | SwitchTab of tabID: string
  /// Message to start dragging a tab for reordering.
  | StartTabDrag of tabID: string
  /// Message to reorder tabs using explicit dragged/target tab names.
  | ReorderTab of draggedTabID: string * targetTabID: string
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
  /// Message to enable or disable CFG-to-hexdump synchronization.
  | SetHexSyncEnabled of bool
  /// Message to route CFG-specific updates to the active CFG state.
  | CFGMsg of CFGMessage
  /// Message to route hexdump-specific updates to the shared hexdump state.
  | HexdumpMsg of HexdumpMessage
  /// Message to update the status message in the status bar.
  | UpdateStatusMsg of string
  /// Message to update the file offset context (range and section) shown in the
  /// status bar.
  | UpdateStatusOffsetCtx of sOff: uint32 * eOff: uint32 * sects: string list
  /// Message to exit the application.
  | ExitApplication

and CFGPanSpace =
  | ViewportSpace
  | MinimapSpace of minimapScale: float

/// Represents messages that affect the active CFG view or CFG loading state.
and CFGMessage =
  /// Message emitted when CFG loading has completed.
  | LoadCompleted of tabID: string * CFGKind * cfg: VisGraph
  /// Message emitted when CFG loading failed.
  | LoadFailed of tabID: string * reason: string
  /// Message to update CFG zoom factor, carrying the zoom delta and the mouse
  /// position.
  | SetZoom of delta: float * x: float * y: float
  /// Message to start panning the CFG view, carrying the initial mouse
  /// position.
  | StartPan of x: float * y: float
  /// Message to update the CFG pan offset, carrying the current mouse position
  /// and its coordinate space.
  | MovePan of x: float * y: float * space: CFGPanSpace
  /// Message to end panning the CFG view.
  | EndPan
  /// Message to jump the CFG view to a specific graph coordinate.
  | JumpPan of gx: float * gy: float
  /// Message to select a disassembly token in the CFG, carrying node, line, and
  /// word indices.
  | SelectToken of nodeID: int * lineIdx: int * wordIdx: int
  /// Message to set the currently hovered edge in the CFG, carrying the edge
  /// ID or None if edge is not hovered anymore.
  | SetHoveredEdge of edgeID: int option
  /// Message to update the size of the CFG viewport, carrying the new width and
  /// height.
  | UpdateViewportSize of width: float * height: float
  /// Message to update the kind of CFG being displayed (e.g., Disassembly, IR,
  /// SSA, Call).
  | ChangeKind of CFGKind
  /// Message to toggle the minimap visibility in the CFG view, carrying the tab
  /// ID and the desired activation state.
  | ToggleMinimap of tabID: string * activate: bool

/// Represents messages that affect the shared hexdump document or one of its
/// active views.
and HexdumpMessage =
  /// Replaces the current hexdump highlight spans.
  | SetHighlightSpans of HexSpanStyle list
  /// Updates the viewport size of a specific hexdump view.
  | UpdateViewport of width: float * height: float
  /// Updates the measured font metrics of a specific hexdump view.
  | UpdateFontMetrics of charWidth: float * rowHeight: float
  /// Jumps the hexdump view to a specific byte range.
  | JumpToRange of byteIndex: int64 * length: int64
  /// Handles a scroll change emitted by the UI scroll viewer, carrying the
  /// current absolute offset and the raw delta.
  | HandleScrollChanged of offsetY: float * deltaY: float
  /// Sets the vertical scroll offset of a specific hexdump view in pixels.
  /// Use this for programmatic jumps such as "go to address".
  | SetScrollOffset of offsetY: float
  /// Sets the vertical scroll row of a specific hexdump view.
  | SetScrollRow of row: int64
  /// Scrolls a specific hexdump view by a row delta.
  | ScrollRows of delta: int64
  /// Sets whether the address column is shown for a specific hexdump view.
  | SetShowAddress of showAddress: bool
  /// Sets whether the ASCII column is shown for a specific hexdump view.
  | SetShowAscii of showAscii: bool
  /// Replaces the shared hexdump selection.
  | SetSelection of HexSelection option
  /// Starts a new selection anchored at the given byte index.
  | StartSelection of byteIndex: int64
  /// Extends the current selection to the given byte index.
  | UpdateSelection of byteIndex: int64
  /// Ends the current selection gesture.
  | EndSelection
  /// Sets the byte currently hovered in a specific hexdump view.
  | SetHoveredByte of byteIndex: int64 option

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

open B2R2.RearEnd.BinExplore

/// Represents the view state of the control flow graph (CFG), including
/// transformation and graph size information.
type CFGViewState =
  { /// The current zoom level of the CFG view, where 1.0 represents the default
    /// zoom.
    Zoom: float
    /// The horizontal pan offset of the CFG view, where 0.0 represents the
    /// default position.
    PanX: float
    /// The vertical pan offset of the CFG view, where 0.0 represents the
    /// default position.
    PanY: float
    /// The kind of CFG being displayed, which can be Disassembly, IR, SSA, or
    /// Call.
    CFGKind: CFGKind
    /// Indicates whether the minimap is currently shown in the CFG view.
    ShowMinimap: bool
    /// The minimum allowed zoom level for the CFG view, preventing excessive
    /// zooming out.
    MinimumZoom: float
    /// The width of the entire graph in its coordinate space.
    GraphWidth: float
    /// The height of the entire graph in its coordinate space.
    GraphHeight: float
    /// The minimum X coordinate of the graph.
    GraphMinX: float
    /// The minimum Y coordinate of the graph.
    GraphMinY: float
    /// The maximum X coordinate of the graph.
    GraphMaxX: float
    /// The maximum Y coordinate of the graph.
    GraphMaxY: float
    /// The ID of the currently hovered node, if any.
    HoveredEdge: int option }

[<RequireQualifiedAccess>]
module CFGViewState =
  /// The initial view state of the CFG, with default zoom, no panning, and
  /// zero graph size.
  let init =
    { Zoom = 1.0
      PanX = 0.0
      PanY = 0.0
      CFGKind = CFGKind.Disasm
      ShowMinimap = true
      MinimumZoom = 0.15
      GraphWidth = 0.0
      GraphHeight = 0.0
      GraphMinX = 0.0
      GraphMinY = 0.0
      GraphMaxX = 0.0
      GraphMaxY = 0.0
      HoveredEdge = None }
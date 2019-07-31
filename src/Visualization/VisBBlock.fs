(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.Visualization

open B2R2.BinGraph

/// The main vertex type used for visualization.
type VisBBlock (blk: BasicBlock, isDummy, ?hdl) =
  inherit BasicBlock ()

  let mutable layer = -1

  let mutable index = -1

  let pos = { X = 0.0; Y = 0.0 }

  let [<Literal>] tSpanOffset = 4.0

  let [<Literal>] padding = 4.0

  let visBlock =
    match hdl with
    | None -> blk.ToVisualBlock ()
    | Some hdl -> blk.ToVisualBlock (hdl)

  let maxLine = visBlock |> List.maxBy (VisualLine.lineWidth)

  let maxLineWidth = VisualLine.lineWidth maxLine |> float

  /// This number (7.5) is empirically obtained with the current font. For some
  /// reasons, we cannot precisely determine the width of each text even though
  /// we are using a fixed-width font. *)
  let width = if isDummy then 0.0 else maxLineWidth * 7.5 + padding * 2.0

  let numLines = visBlock |> List.length

  /// This number (14), as in the width case, is empirically obtained with the
  /// current font.
  let height =
    if isDummy then 0.0 else float numLines * 14.0 + tSpanOffset + padding * 2.0

  override __.PPoint with get () = blk.PPoint

  override __.Range with get () = blk.Range

  override __.IsDummyBlock () = isDummy

  override __.ToVisualBlock (_) = visBlock

  /// The width of the node.
  member __.Width with get () = width

  /// The height of the node.
  member __.Height with get () = height

  /// The layer that this node belongs to.
  member __.Layer with get () = layer and set (v) = layer <- v

  /// Relative index in a layer (from left to right).
  member __.Index with get () = index and set (v) = index <- v

  /// X-Y coordinate in the visualized graph.
  member __.Coordinate with get () = pos

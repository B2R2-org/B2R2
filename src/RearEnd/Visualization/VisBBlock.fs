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

namespace B2R2.RearEnd.Visualization

open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph

/// Represents a vertex of a graph laid out for visualization, pairing the
/// basic block it stands for with the geometry the layout gives it.
type VisBBlock(blk: IVisualizable, charWidth, charHeight, isDummy) =
  let mutable layer = -1

  let mutable index = -1

  let pos = { X = 0.0; Y = 0.0 }

  let [<Literal>] Padding = 4.0

  let [<Literal>] Border = 1.0

  let visualizableAsm =
    let block = blk.Visualize()
    if block.Length = 0 then
      [| [| { AsmWordKind = AsmWordKind.String
              AsmWordValue = $"# fake block @ {blk.BlockAddress:x}" } |] |]
    else
      block

  let lineWidth asmLine =
    asmLine |> Array.fold (fun width term -> width + AsmWord.Width term) 0

  let maxNumChars =
    visualizableAsm
    |> Array.maxBy lineWidth
    |> lineWidth
    |> float

  let mutable width =
    if isDummy then 0.0
    else maxNumChars * charWidth + Padding * 2.0 + Border * 2.0

  let numLines = visualizableAsm |> Array.length

  let height =
    if isDummy then 0.0
    else float numLines * charHeight + Padding * 2.0 + Border * 2.0

  new(blk, isDummy) =
    (* These numbers (7.5 and 14) are empirically obtained with the current
       font. For some reasons, we cannot precisely determine the width of each
       text even though we are using a fixed-width font. *)
    VisBBlock(blk, 7.5, 14.0, isDummy)

  /// Gets whether this node is a dummy, that is, a placeholder standing on a
  /// layer that a long edge merely passes through.
  member _.IsDummy with get() = isDummy

  /// Gets or sets the width of the node.
  member _.Width with get() = width and set(v) = width <- v

  /// Gets the height of the node.
  member _.Height with get() = height

  /// Gets or sets the layer that this node belongs to.
  member _.Layer with get() = layer and set(v) = layer <- v

  /// Gets or sets the index of this node within its layer, counted from the
  /// left.
  member _.Index with get() = index and set(v) = index <- v

  /// Gets the x-y coordinate of this node in the laid-out graph.
  member _.Coordinate with get() = pos

  /// Gets the address of the basic block that this node stands for.
  member _.BlockAddress with get() = blk.BlockAddress

  interface IVisualizable with
    member _.BlockAddress with get() = blk.BlockAddress

    member _.LineAddrRanges with get() = blk.LineAddrRanges

    member _.Visualize() = visualizableAsm
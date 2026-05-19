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

/// The main vertex type used for visualization.
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
    else block

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

  let addressable = blk :?> IAddressable

  new(blk, isDummy) =
    (* These numbers (7.5 and 14) are empirically obtained with the current
       font. For some reasons, we cannot precisely determine the width of each
       text even though we are using a fixed-width font. *)
    VisBBlock(blk, 7.5, 14.0, isDummy)

  member _.IsDummy with get() = isDummy

  /// The width of the node.
  member _.Width with get() = width and set(v) = width <- v

  /// The height of the node.
  member _.Height with get() = height

  /// The layer that this node belongs to.
  member _.Layer with get() = layer and set(v) = layer <- v

  /// Relative index in a layer (from left to right).
  member _.Index with get() = index and set(v) = index <- v

  /// X-Y coordinate in the visualized graph.
  member _.Coordinate with get() = pos

  member _.BlockAddress with get() = blk.BlockAddress

  interface IVisualizable with
    member _.BlockAddress with get() = blk.BlockAddress

    member _.LineAddrRanges with get() = blk.LineAddrRanges

    member _.Visualize() = visualizableAsm

  interface IAddressable with
    member _.PPoint with get() = addressable.PPoint

    member _.Range with get() = addressable.Range
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
/// basic block it stands for with the geometry the layout gives it. A dummy
/// carries a width of its own; anything else is measured by what it shows.
type VisBBlock private(blk: IVisualizable, charWidth, charHeight, dummy) =
  let [<Literal>] Padding = 4.0

  let [<Literal>] Border = 1.0

  let mutable layer = -1

  let mutable index = -1

  let pos = { X = 0.0; Y = 0.0 }

  let isDummy = Option.isSome dummy

  (* A dummy stands on a layer that a long edge merely passes through. It
     shows nothing and is measured by nothing, so the block it was made from
     is never rendered for one. *)
  let visualizableAsm =
    if isDummy then
      [||]
    else
      let block = blk.Visualize()
      if block.Length = 0 then
        [| [| { AsmWordKind = AsmWordKind.String
                AsmWordValue = $"# fake block @ {blk.BlockAddress:x}" } |] |]
      else
        block

  let width =
    match dummy with
    | Some dummyWidth ->
      dummyWidth
    | None ->
      let widest = VisBBlock.MaxLineWidth visualizableAsm
      float widest * charWidth + Padding * 2.0 + Border * 2.0

  let height =
    if isDummy then
      0.0
    else
      let lines = float visualizableAsm.Length
      lines * charHeight + Padding * 2.0 + Border * 2.0

  /// Creates a node for the given block, laid out for a font of the given
  /// character width and height.
  new(blk, charWidth, charHeight) =
    VisBBlock(blk, charWidth, charHeight, None)

  /// Creates a dummy node of the given width. A dummy is never shown, so the
  /// font it would be laid out for does not come into it.
  new(blk, dummyWidth: float) =
    VisBBlock(blk, 0.0, 0.0, Some dummyWidth)

  /// Gets whether this node is a dummy, that is, a placeholder standing on a
  /// layer that a long edge merely passes through.
  member _.IsDummy with get() = isDummy

  /// Gets the width of the node.
  member _.Width with get() = width

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

  /// Returns the width, in characters, of the widest of the given lines.
  static member private MaxLineWidth lines =
    let lineWidth line =
      Array.fold (fun width term -> width + AsmWord.Width term) 0 line
    Array.fold (fun widest line -> max widest (lineWidth line)) 0 lines

  interface IVisualizable with
    member _.BlockAddress with get() = blk.BlockAddress

    member _.LineAddrRanges with get() = blk.LineAddrRanges

    member _.Visualize() = visualizableAsm
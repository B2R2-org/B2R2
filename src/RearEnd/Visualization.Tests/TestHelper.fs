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

namespace B2R2.RearEnd.Visualization.Tests

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph

/// A minimal basic block standing in for a real one, showing the one line of
/// text it is made with, so that what it measures is the test's to say.
type FakeBlock(addr: Addr, text: string) =
  /// Creates a block whose one line names the address it stands at.
  new(addr) = FakeBlock(addr, $"blk{addr}")

  interface IVisualizable with
    member _.BlockAddress with get() = addr

    member _.LineAddrRanges with get() = [| { Min = addr; Max = addr } |]

    member _.Visualize() =
      [| [| { AsmWordKind = AsmWordKind.String; AsmWordValue = text } |] |]

  interface IAddressable with
    member _.PPoint with get() = ProgramPoint(addr, 0)

    member _.Range with get() = { Min = addr; Max = addr }

/// A block that is visualizable but not addressable, which is all that the
/// visualization asks of a block.
type PlainBlock(addr: Addr) =
  interface IVisualizable with
    member _.BlockAddress with get() = addr

    member _.LineAddrRanges with get() = [| { Min = addr; Max = addr } |]

    member _.Visualize() =
      let value = $"plain{addr}"
      [| [| { AsmWordKind = AsmWordKind.String; AsmWordValue = value } |] |]

/// A block that counts how many times it is asked to visualize itself, so
/// that work done on a block nothing shows can be told from work not done.
type CountingBlock(addr: Addr) =
  let mutable visualizeCount = 0

  /// Gets how many times this block has been visualized.
  member _.VisualizeCount with get() = visualizeCount

  interface IVisualizable with
    member _.BlockAddress with get() = addr

    member _.LineAddrRanges with get() = [| { Min = addr; Max = addr } |]

    member _.Visualize() =
      visualizeCount <- visualizeCount + 1
      let value = $"count{addr}"
      [| [| { AsmWordKind = AsmWordKind.String; AsmWordValue = value } |] |]

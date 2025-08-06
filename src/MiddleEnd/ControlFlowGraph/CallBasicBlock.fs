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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2
open B2R2.FrontEnd.BinLifter

/// Basic block type for a call graph (CallCFG).
type CallBasicBlock(addr, name, isExternal) =
  /// Return the `ICallBasicBlock` interface to access the internal
  /// representation of the basic block.
  member this.Internals with get() = this :> ICallBasicBlock

  member _.Name with get() = name

  member _.IsExternal with get() = isExternal

  override _.ToString() = $"{nameof CallBasicBlock}({addr:x})"

  interface ICallBasicBlock with
    member _.PPoint with get() = ProgramPoint(addr, 0)

    member _.Range = AddrRange(addr)

    member _.BlockAddress with get() = addr

    member _.Visualize() =
      [| [| { AsmWordKind = AsmWordKind.Address
              AsmWordValue = Addr.toString WordSize.Bit32 addr }
            { AsmWordKind = AsmWordKind.String
              AsmWordValue = ": " }
            { AsmWordKind = AsmWordKind.Value
              AsmWordValue = name } |] |]

and ICallBasicBlock =
  inherit IAddressable
  inherit IVisualizable

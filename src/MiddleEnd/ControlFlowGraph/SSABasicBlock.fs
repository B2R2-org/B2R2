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
open B2R2.Collections
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph

/// Basic block type for an SSA-based CFG (SSACFG). It holds an array of
/// (ProgramPoint * Stmt).
type SSABasicBlock private (ppoint, lastAddr, stmts: _[], funcAbs) =
  let mutable idom: IVertex<SSABasicBlock> option = None

  let mutable frontier: IVertex<SSABasicBlock> list = []

  /// (ProgramPoint * SSA.Stmt) array.
  let mutable stmts = stmts

  let computeNextPPoint (ppoint: ProgramPoint) = function
    | Def (v, Num bv) ->
      match v.Kind with
      | PCVar _ -> ProgramPoint (BitVector.ToUInt64 bv, 0)
      | _ -> ProgramPoint.Next ppoint
    | _ -> ProgramPoint.Next ppoint

  /// Return the `ISSABasicBlock` interface to access the internal
  /// representation of the basic block.
  member this.Internals with get() = this :> ISSABasicBlock

  /// Immediate dominator of this block.
  member _.ImmDominator with get() = idom and set(d) = idom <- d

  /// Dominance frontier of this block.
  member _.DomFrontier with get() = frontier and set(f) = frontier <- f

  override _.ToString () = $"{nameof SSABasicBlock}({ppoint})"

  interface ISSABasicBlock with
    member _.PPoint with get() = ppoint

    member _.Range with get() =
      if isNull funcAbs then AddrRange (ppoint.Address, lastAddr)
      else raise AbstractBlockAccessException

    member _.IsAbstract with get() = not (isNull funcAbs)

    member _.AbstractContent with get() =
      if isNull funcAbs then raise AbstractBlockAccessException
      else funcAbs

    member _.Statements with get() = stmts

    member _.LastStmt with get() = snd stmts[stmts.Length - 1]

    member _.PrependPhi varKind count =
      let var = { Kind = varKind; Identifier = -1 }
      let pp = ProgramPoint.GetFake ()
      stmts <- Array.append [| pp, Phi (var, Array.zeroCreate count) |] stmts

    member _.UpdateStatements stmts' =
      stmts <- stmts'

    member _.UpdatePPoints () =
      stmts
      |> Array.foldi (fun ppoint idx (_, stmt) ->
        let ppoint' = computeNextPPoint ppoint stmt
        stmts[idx] <- (ppoint', stmt)
        ppoint') ppoint
      |> ignore

    member _.BlockAddress with get() = ppoint.Address

    member _.Visualize () =
      if isNull funcAbs then
        stmts
        |> Array.map (fun (_, stmt) ->
          [| { AsmWordKind = AsmWordKind.String
               AsmWordValue = Pp.stmtToString stmt } |])
      else [||]

  static member CreateRegular (stmts, ppoint, lastAddr) =
    SSABasicBlock (ppoint, lastAddr, stmts, null)

  /// Create an abstract basic block located at `ppoint`.
  static member CreateAbstract (ppoint, abs: FunctionAbstraction<SSA.Stmt>) =
    assert (not (isNull abs))
    let rundown = abs.Rundown |> Array.map (fun s -> ProgramPoint.GetFake (), s)
    SSABasicBlock (ppoint, 0UL, rundown, abs)

/// Interafce for a basic block containing a sequence of SSA statements.
and ISSABasicBlock =
  inherit IAddressable
  inherit IAbstractable<SSA.Stmt>
  inherit ISSAAccessible
  inherit IVisualizable

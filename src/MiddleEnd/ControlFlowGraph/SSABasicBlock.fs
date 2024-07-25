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
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph

/// Basic block type for an SSA-based CFG (SSACFG). It holds an array of
/// LiftedSSAStmts (ProgramPoint * Stmt).
type SSABasicBlock private (ppoint, lastAddr, stmts: _[], funcAbs) =
  inherit PossiblyAbstractBasicBlock<Stmt> (ppoint, funcAbs)

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

  /// Return the SSA statements.
  member __.LiftedSSAStmts with get() = stmts and set(ss) = stmts <- ss

  /// Get the last SSA statement of the bblock.
  member __.LastStmt with get() = snd stmts[stmts.Length - 1]

  /// Immediate dominator of this block.
  member __.ImmDominator with get() = idom and set(d) = idom <- d

  /// Dominance frontier of this block.
  member __.DomFrontier with get() = frontier and set(f) = frontier <- f

  /// Prepend a Phi node to this SSA basic block.
  member __.PrependPhi varKind count =
    let var = { Kind = varKind; Identifier = -1 }
    let ppoint = ProgramPoint.GetFake ()
    stmts <- Array.append [| ppoint, Phi (var, Array.zeroCreate count) |] stmts

  /// Update program points. This must be called after updating SSA stmts.
  member __.UpdatePPoints () =
    stmts
    |> Array.foldi (fun ppoint idx (_, stmt) ->
      let ppoint' = computeNextPPoint ppoint stmt
      __.LiftedSSAStmts[idx] <- (ppoint', stmt)
      ppoint') ppoint
    |> ignore

  override __.Range with get() =
    if isNull funcAbs then AddrRange (ppoint.Address, lastAddr)
    else raise AbstractBlockAccessException

  override __.Visualize () =
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

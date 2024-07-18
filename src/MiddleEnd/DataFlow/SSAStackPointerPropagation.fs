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

namespace B2R2.MiddleEnd.DataFlow.SSA

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.DataFlow

type SSAStackPointerPropagation<'E when 'E: equality> (hdl) as this =
  inherit SSAVarBasedDataFlowAnalysis<StackPointerDomain.Lattice, 'E> (hdl)

  let evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> StackPointerDomain.add c1 c2
    | BinOpType.SUB -> StackPointerDomain.sub c1 c2
    | BinOpType.AND -> StackPointerDomain.``and`` c1 c2
    | _ -> StackPointerDomain.NotConstSP

  let rec evalExpr blk = function
    | Num bv -> StackPointerDomain.ConstSP bv
    | Var v -> this.GetRegValue v
    | Nil -> StackPointerDomain.NotConstSP
    | Load _ -> StackPointerDomain.NotConstSP
    | UnOp _ -> StackPointerDomain.NotConstSP
    | FuncName _ -> StackPointerDomain.NotConstSP
    | BinOp (op, _, e1, e2) ->
      let c1 = evalExpr blk e1
      let c2 = evalExpr blk e2
      evalBinOp op c1 c2
    | RelOp _ -> StackPointerDomain.NotConstSP
    | Ite _ -> StackPointerDomain.NotConstSP
    | Cast _ -> StackPointerDomain.NotConstSP
    | Extract _ -> StackPointerDomain.NotConstSP
    | Undefined _ -> StackPointerDomain.NotConstSP
    | ReturnVal (_, _, e) -> evalExpr blk e
    | _ -> Utils.impossible ()

  let isStackRelatedRegister regId =
    hdl.RegisterFactory.IsStackPointer regId
    || hdl.RegisterFactory.IsFramePointer regId

  let evalDef blk pp v e =
    match v.Kind with
    | RegVar (_, regid, _) when isStackRelatedRegister regid ->
      this.SetRegValue (pp, v, evalExpr blk e)
    | RegVar _ ->
      this.SetRegValue (pp, v, StackPointerDomain.NotConstSP)
    | TempVar _ ->
      this.SetRegValue (pp, v, evalExpr blk e)
    | _ -> ()

  let evalPhi ssaCFG blk pp dst srcIDs =
    match this.GetExecutedSources ssaCFG blk srcIDs with
    | [||] -> ()
    | executedSrcIDs ->
      match dst.Kind with
      | RegVar _ | TempVar _ ->
        executedSrcIDs
        |> Array.map (fun i -> { dst with Identifier = i } |> this.GetRegValue)
        |> Array.reduce this.Join
        |> fun merged -> this.SetRegValue (pp, dst, merged)
      | _ -> ()

  let evalJmp ssaCFG blk =
    this.MarkSuccessorsExecutable ssaCFG blk

  override _.Bottom with get() = StackPointerDomain.Undef

  override _.Join a b = StackPointerDomain.join a b

  override _.Transfer ssaCFG blk pp stmt =
    match stmt with
    | Def (var, e) -> evalDef blk pp var e
    | Phi (var, ns) -> evalPhi ssaCFG blk pp var ns
    | Jmp _ -> evalJmp ssaCFG blk
    | LMark _ | ExternalCall _ | SideEffect _ -> ()

  override _.IsSubsumable lhs rhs = StackPointerDomain.isSubsumable lhs rhs

  override _.UpdateMemFromBinaryFile _rt _addr = StackPointerDomain.Undef

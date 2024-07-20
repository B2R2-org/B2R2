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
open B2R2.MiddleEnd.DataFlow.Constants

type SSAStackPointerPropagation<'E when 'E: equality> (hdl) as this =
  inherit SSAVarBasedDataFlowAnalysis<StackPointerDomain.Lattice, 'E> (hdl)

  let initStackRegister () =
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.RegIDToRegType sp
      let str = hdl.RegisterFactory.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      this.SetRegValueWithoutPushing var
      <| StackPointerDomain.ConstSP (BitVector.OfUInt64 InitialStackPointer rt)
    | None -> ()

  let evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> StackPointerDomain.add c1 c2
    | BinOpType.SUB -> StackPointerDomain.sub c1 c2
    | BinOpType.AND -> StackPointerDomain.``and`` c1 c2
    | _ -> StackPointerDomain.NotConstSP

  let rec evalExpr = function
    | Num bv -> StackPointerDomain.ConstSP bv
    | Var v -> this.GetRegValue v
    | Nil -> StackPointerDomain.NotConstSP
    | Load _ -> StackPointerDomain.NotConstSP
    | UnOp _ -> StackPointerDomain.NotConstSP
    | FuncName _ -> StackPointerDomain.NotConstSP
    | BinOp (op, _, e1, e2) ->
      let c1 = evalExpr e1
      let c2 = evalExpr e2
      evalBinOp op c1 c2
    | RelOp _ -> StackPointerDomain.NotConstSP
    | Ite _ -> StackPointerDomain.NotConstSP
    | Cast _ -> StackPointerDomain.NotConstSP
    | Extract _ -> StackPointerDomain.NotConstSP
    | Undefined _ -> StackPointerDomain.NotConstSP
    | ReturnVal (_, _, e) -> evalExpr e
    | _ -> Utils.impossible ()

  let isStackRelatedRegister regId =
    hdl.RegisterFactory.IsStackPointer regId
    || hdl.RegisterFactory.IsFramePointer regId

  let evalDef var e =
    match var.Kind with
    | RegVar (_, regid, _) when isStackRelatedRegister regid ->
      this.SetRegValue (var, evalExpr e)
    | RegVar _ ->
      this.SetRegValue (var, StackPointerDomain.NotConstSP)
    | TempVar _ ->
      this.SetRegValue (var, evalExpr e)
    | _ -> ()

  let evalPhi ssaCFG blk dst srcIDs =
    match this.GetExecutedSources ssaCFG blk srcIDs with
    | [||] -> ()
    | executedSrcIDs ->
      match dst.Kind with
      | RegVar _ | TempVar _ ->
        executedSrcIDs
        |> Array.map (fun i -> { dst with Identifier = i } |> this.GetRegValue)
        |> Array.reduce this.Join
        |> fun merged -> this.SetRegValue (dst, merged)
      | _ -> ()

  let evalJmp ssaCFG blk =
    this.MarkSuccessorsExecutable ssaCFG blk

  do initStackRegister ()

  override _.Bottom with get() = StackPointerDomain.Undef

  override _.Join a b = StackPointerDomain.join a b

  override _.Transfer ssaCFG blk _pp stmt =
    match stmt with
    | Def (var, e) -> evalDef var e
    | Phi (var, ns) -> evalPhi ssaCFG blk var ns
    | Jmp _ -> evalJmp ssaCFG blk
    | LMark _ | ExternalCall _ | SideEffect _ -> ()

  override _.IsSubsumable lhs rhs = StackPointerDomain.isSubsumable lhs rhs

  override _.UpdateMemFromBinaryFile _rt _addr = StackPointerDomain.Undef

  /// Evaluate the given expression based on the current abstract state.
  member _.EvalExpr e = evalExpr e

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
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.Constants

/// Sparse conditional constant propagation algorithm, which is a modified
/// version of Wegman et al.
type SSAConstantPropagation<'E when 'E: equality>
  public (hdl: BinHandle) as this =
  inherit SSAVarBasedDataFlowAnalysis<ConstantDomain.Lattice, 'E> (hdl)

  let initStackRegister () =
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.RegIDToRegType sp
      let str = hdl.RegisterFactory.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      this.SetRegValueWithoutPushing var
      <| ConstantDomain.Const (BitVector.OfUInt64 InitialStackPointer rt)
    | None -> ()

  let evalLoad m rt addr =
    match addr with
    | ConstantDomain.Const addr ->
      let addr = BitVector.ToUInt64 addr
      this.GetMemValue m rt addr
    | _ -> ConstantDomain.NotAConst

  let evalUnOp op c =
    match op with
    | UnOpType.NEG -> ConstantDomain.neg c
    | UnOpType.NOT -> ConstantDomain.not c
    | _ -> ConstantDomain.NotAConst

  let evalBinOp op c1 c2 =
    match op with
    | BinOpType.ADD -> ConstantDomain.add c1 c2
    | BinOpType.SUB -> ConstantDomain.sub c1 c2
    | BinOpType.MUL -> ConstantDomain.mul c1 c2
    | BinOpType.DIV -> ConstantDomain.div c1 c2
    | BinOpType.SDIV -> ConstantDomain.sdiv c1 c2
    | BinOpType.MOD -> ConstantDomain.``mod`` c1 c2
    | BinOpType.SMOD -> ConstantDomain.smod c1 c2
    | BinOpType.SHL -> ConstantDomain.shl c1 c2
    | BinOpType.SHR -> ConstantDomain.shr c1 c2
    | BinOpType.SAR -> ConstantDomain.sar c1 c2
    | BinOpType.AND -> ConstantDomain.``and`` c1 c2
    | BinOpType.OR -> ConstantDomain.``or`` c1 c2
    | BinOpType.XOR -> ConstantDomain.xor c1 c2
    | BinOpType.CONCAT -> ConstantDomain.concat c1 c2
    | _ -> ConstantDomain.NotAConst

  let evalRelOp op c1 c2 =
    match op with
    | RelOpType.EQ -> ConstantDomain.eq c1 c2
    | RelOpType.NEQ -> ConstantDomain.neq c1 c2
    | RelOpType.GT -> ConstantDomain.gt c1 c2
    | RelOpType.GE -> ConstantDomain.ge c1 c2
    | RelOpType.SGT -> ConstantDomain.sgt c1 c2
    | RelOpType.SGE -> ConstantDomain.sge c1 c2
    | RelOpType.LT -> ConstantDomain.lt c1 c2
    | RelOpType.LE -> ConstantDomain.le c1 c2
    | RelOpType.SLT -> ConstantDomain.slt c1 c2
    | RelOpType.SLE -> ConstantDomain.sle c1 c2
    | _ -> ConstantDomain.NotAConst

  let evalCast op rt c =
    match op with
    | CastKind.SignExt -> ConstantDomain.signExt rt c
    | CastKind.ZeroExt -> ConstantDomain.zeroExt rt c
    | _ -> ConstantDomain.NotAConst

  let rec evalExpr blk = function
    | Num bv -> ConstantDomain.Const bv
    | Var v -> this.GetRegValue v
    | Load (m, rt, addr) ->
      evalExpr blk addr |> evalLoad m rt
    | UnOp (op, _, e) ->
      evalExpr blk e |> evalUnOp op
    | BinOp (op, _, e1, e2) ->
      let c1 = evalExpr blk e1
      let c2 = evalExpr blk e2
      evalBinOp op c1 c2
    | RelOp (op, _, e1, e2) ->
      let c1 = evalExpr blk e1
      let c2 = evalExpr blk e2
      evalRelOp op c1 c2
    | Ite (e1, _, e2, e3) ->
      let c1 = evalExpr blk e1
      let c2 = evalExpr blk e2
      let c3 = evalExpr blk e3
      ConstantDomain.ite c1 c2 c3
    | Cast (op, rt, e) ->
      let c = evalExpr blk e
      evalCast op rt c
    | Extract (e, rt, pos) ->
      let c = evalExpr blk e
      ConstantDomain.extract c rt pos
    | ReturnVal (_addr, _ret, e) -> evalExpr blk e
    | FuncName _ | Nil | Undefined _ -> ConstantDomain.NotAConst
    | _ -> Utils.impossible ()

  let evalDef blk var e =
    match var.Kind with
    | MemVar -> ()
    | _ -> this.SetRegValue (var, evalExpr blk e)

  let evalPhi cfg blk dst srcIDs =
    match this.GetExecutedSources cfg blk srcIDs with
    | [||] -> ()
    | executedSrcIDs ->
      match dst.Kind with
      | MemVar -> ()
      | _ ->
        executedSrcIDs
        |> Array.map (fun i -> { dst with Identifier = i } |> this.GetRegValue)
        |> Array.reduce this.Join
        |> fun merged -> this.SetRegValue (dst, merged)

  let evalJmp cfg blk =
    this.MarkSuccessorsExecutable cfg blk

  do initStackRegister ()

  override _.Bottom with get() = ConstantDomain.Undef

  override _.Join a b = ConstantDomain.join a b

  override _.Transfer ssaCFG blk _pp stmt =
    match stmt with
    | Def (var, e) -> evalDef blk var e
    | Phi (var, ns) -> evalPhi ssaCFG blk var ns
    | Jmp _ -> evalJmp ssaCFG blk
    | LMark _ | ExternalCall _ | SideEffect _ -> ()

  override _.IsSubsumable lhs rhs = ConstantDomain.isSubsumable lhs rhs

  override _.UpdateMemFromBinaryFile _rt _addr = ConstantDomain.Undef

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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow.SSASparseDataFlow

/// Performs stack pointer propagation analysis over an SSA CFG.
type SSAStackPointerPropagation(hdl: BinHandle) =
  let rec evalExpr (state: State<_>) = function
    | Num bv ->
      AddressDomain.Const bv
    | Var v ->
      state.GetRegValue v
    | ExprList _ ->
      AddressDomain.NotAConst
    | Load _ ->
      AddressDomain.NotAConst
    | UnOp _ ->
      AddressDomain.NotAConst
    | FuncName _ ->
      AddressDomain.NotAConst
    | BinOp(op, _, e1, e2) ->
      let c1 = evalExpr state e1
      let c2 = evalExpr state e2
      AddressDomain.evalBinOp op c1 c2
    | RelOp _ ->
      AddressDomain.NotAConst
    | Ite _ ->
      AddressDomain.NotAConst
    | Cast _ ->
      AddressDomain.NotAConst
    | Extract _ ->
      AddressDomain.NotAConst
    | Undefined _ ->
      AddressDomain.NotAConst
    | _ ->
      Terminator.impossible ()

  let isStackRelatedRegister regId =
    hdl.RegisterFactory.IsStackPointer regId
    || hdl.RegisterFactory.IsFramePointer regId

  let evalDef (state: State<_>) var e =
    match var.Kind with
    | RegVar(_, regid, _) when isStackRelatedRegister regid ->
      state.SetRegValue(var, evalExpr state e)
    | RegVar _ ->
      state.SetRegValue(var, AddressDomain.NotAConst)
    | TempVar _ ->
      state.SetRegValue(var, evalExpr state e)
    | _ ->
      ()

  let isPhiTarget (var: Variable) =
    match var.Kind with
    | RegVar _ | TempVar _ -> true
    | _ -> false

  let lattice = AddressDomain.createLattice ()

  let rec scheme =
    { new IScheme<AddressDomain.Lattice> with
        member _.EvalDef(var, e) = evalDef state var e
        member _.IsPhiTarget var = isPhiTarget var
        member _.ReadMemFromBinaryFile(_rt, _addr) =
          AddressDomain.NotAConst
        member _.GetBaseCase _ = AddressDomain.NotAConst
        member _.EvalExpr e = evalExpr state e }

  and state =
    let state = State<AddressDomain.Lattice>(hdl, lattice, scheme)
    state.SeedStackPointer(fun sp ->
      AddressDomain.StackAddr(BitVector.Zero sp.Length))
    state

  /// Returns the underlying state of this analysis.
  member _.State with get() = state

  interface IDataFlowComputable<SSAVarPoint,
                                AddressDomain.Lattice,
                                SSABasicBlock> with
    member _.Compute cfg = compute cfg state

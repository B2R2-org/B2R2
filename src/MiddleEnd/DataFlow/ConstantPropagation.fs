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
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph

/// Performs sparse constant propagation over the LowUIR representation.
type ConstantPropagation(hdl, vs, ?initialValueProvider) =
  let initialValueProvider =
    defaultArg initialValueProvider (RegisterInitialValueProvider.create hdl)

  /// Checks if no definition in the function reaches the given use of the
  /// given variable, which then holds what it held on entry.
  let readsEntryValue (state: LowUIRSparseDataFlow.State<_>) pp vk =
    match state.UseDefMap.TryGetValue { ProgramPoint = pp; VarKind = vk } with
    | true, defVp -> defVp.ProgramPoint.IsFake
    | false, _ -> false

  /// Loads a value of the given type from the given variable in memory, which
  /// holds what it held on entry: what the binary holds there if it is a
  /// global variable where only the loader writes, as ARM code loads the
  /// address of a table from its literal pool, or else the given base case.
  let loadEntryValue rt baseCase vk =
    match vk with
    | Global addr ->
      LoaderOnlyMemory.tryRead hdl addr rt
      |> Option.map ConstantDomain.Const
      |> Option.defaultValue baseCase
    | _ ->
      baseCase

  /// Loads a value of the given type from the given variable in memory, which
  /// has no type of its own.
  let loadVar (state: LowUIRSparseDataFlow.State<_>) pp rt vk =
    match state.GetAbsValueOfUse(pp, vk) with
    | ConstantDomain.Const bv when bv.Length < rt ->
      ConstantDomain.Const <| BitVector.ZExt(bv, rt)
    | ConstantDomain.Const bv when bv.Length > rt ->
      ConstantDomain.Const <| BitVector.Extract(bv, rt, 0)
    | c when readsEntryValue state pp vk ->
      loadEntryValue rt c vk
    | c ->
      c

  let rec evaluateExpr (state: LowUIRSparseDataFlow.State<_>) pp e =
    match e with
    | PCVar(Type = rt) ->
      let addr = (pp: ProgramPoint).Address
      let bv = BitVector(addr, rt)
      ConstantDomain.Const bv
    | Num(Value = bv) ->
      ConstantDomain.Const bv
    | Var _ | TempVar _ ->
      state.GetAbsValueOfUse(pp, VarKind.ofIRExpr e)
    | Load(Endian = _m; Type = rt; Addr = addr) ->
      let addrValue = state.EvaluateAddressExpr(pp, addr)
      match LowUIRAddress.tryGetMemoryVarKind addrValue, addrValue with
      | Some vk, _ -> loadVar state pp rt vk
      | None, AddressDomain.Undef -> ConstantDomain.Undef
      | None, _ -> ConstantDomain.NotAConst
    | UnOp(Op = op; Operand = e) ->
      evaluateExpr state pp e
      |> ConstantDomain.evalUnOp op
    | BinOp(Op = op; Left = e1; Right = e2) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      ConstantDomain.evalBinOp op c1 c2
    | RelOp(Op = op; Left = e1; Right = e2) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      ConstantDomain.evalRelOp op c1 c2
    | Ite(Cond = e1; TrueExpr = e2; FalseExpr = e3) ->
      let c1 = evaluateExpr state pp e1
      let c2 = evaluateExpr state pp e2
      let c3 = evaluateExpr state pp e3
      ConstantDomain.ite c1 c2 c3
    | Cast(Kind = op; Type = rt; Operand = e) ->
      let c = evaluateExpr state pp e
      ConstantDomain.evalCast op rt c
    | Extract(Operand = e; Type = rt; StartPos = pos) ->
      let c = evaluateExpr state pp e
      ConstantDomain.extract c rt pos
    | RoundCtrl(Body = body) ->
      evaluateExpr state pp body
    | FuncName _ | ExprList _ | Undefined _ ->
      ConstantDomain.NotAConst
    | _ ->
      Terminator.impossible ()

  let lattice = ConstantDomain.createLattice ()

  let rec scheme =
    { new LowUIRSparseDataFlow.IScheme<ConstantDomain.Lattice> with
        member _.GetBaseCase varKind =
          match RegisterInitialValueProvider.tryGetInitialVarValue
                  initialValueProvider varKind with
          | Some bv -> ConstantDomain.Const bv
          | None -> ConstantDomain.NotAConst
        member _.EvalExpr(pp, expr) = evaluateExpr state pp expr }

  and state =
    LowUIRSparseDataFlow.State(hdl, lattice, scheme)
    |> fun state ->
      for v in vs do state.MarkVertexAsPending v done
      state

  /// Returns the underlying state of this analysis.
  member _.State with get() = state

  interface IDataFlowComputable<VarPoint,
                                ConstantDomain.Lattice,
                                LowUIRBasicBlock> with
    member _.Compute cfg = LowUIRSparseDataFlow.compute cfg state

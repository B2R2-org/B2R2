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
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.DataFlow

type UntouchedValueAnalysis<'E when 'E: equality> () as this =
  inherit IncrementalDataFlowAnalysis<UntouchedValueDomain.Lattice, 'E> ()

  let evaluateVarPoint pp varKind =
    let varDef = this.GetVarDef { ProgramPoint = pp; VarKind = varKind }
    let vps = VarDefDomain.get varKind varDef
    if Set.isEmpty vps then (* initialize here *)
      UntouchedValueDomain.RegisterTag varKind
      |> UntouchedValueDomain.Untouched
    else
      let dfa = this :> IDataFlowAnalysis<_, _, _, _>
      vps
      |> Set.map (fun vp -> dfa.GetAbsValue vp)
      |> Seq.reduce UntouchedValueDomain.join

  let rec evaluateExpr pp e =
    match e.E with
    | Var _ | TempVar _ -> evaluateVarPoint pp (VarKind.ofIRExpr e)
    | Load (_, _, addr) ->
      match this.EvaluateExprIntoConst (pp, addr) with
      | ConstantDomain.Const bv ->
        let addr = BitVector.ToUInt64 bv
        evaluateVarPoint pp (VarKind.Memory (Some addr))
      | _ -> UntouchedValueDomain.Touched
    | Extract (e, _, _)
    | Cast (CastKind.ZeroExt, _, e)
    | Cast (CastKind.SignExt, _, e) -> evaluateExpr pp e
    | _ -> UntouchedValueDomain.Touched

  override __.Bottom = UntouchedValueDomain.Undef

  override __.Join (a, b) = UntouchedValueDomain.join a b

  override __.IsSubsumable (a, b) = UntouchedValueDomain.isSubsumable a b

  override __.Transfer (_g, _v, pp, stmt) =
    match stmt.S with
    | Put (dst, src) ->
      let varKind = VarKind.ofIRExpr dst
      let varPoint = { ProgramPoint = pp; VarKind = varKind }
      let v = evaluateExpr pp src
      Some (varPoint, v)
    | Store (_, addr, value) ->
      match this.EvaluateExprIntoConst (pp, addr) with
      | ConstantDomain.Const bv ->
        let varKind = VarKind.Memory (Some (BitVector.ToUInt64 bv))
        let varPoint = { ProgramPoint = pp; VarKind = varKind }
        let v = evaluateExpr pp value
        Some (varPoint, v)
      | _ -> None
    | _ -> None

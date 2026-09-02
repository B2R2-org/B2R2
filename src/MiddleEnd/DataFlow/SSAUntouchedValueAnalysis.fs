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

open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.SSASparseDataFlow
open B2R2.MiddleEnd.ControlFlowGraph
open type UntouchedValueDomain.UntouchedTag

/// Performs sparse data-flow analysis over SSA to identify untouched values in
/// a function.
type SSAUntouchedValueAnalysis(hdl: BinHandle) =
  let initRegisters (state: State<_>) =
    hdl.RegisterFactory.GetGeneralRegVars()
    |> Array.iter (fun regExpr ->
      let rid = hdl.RegisterFactory.GetRegisterID regExpr
      let rt = hdl.RegisterFactory.GetRegType rid
      let str = hdl.RegisterFactory.GetRegisterName rid
      let var = { Kind = RegVar(rt, rid, str); Identifier = 0 }
      let vkind = VarKind.ofSSAVarKind var.Kind
      state.SeedRegValue(var,
        UntouchedValueDomain.Untouched(RegisterTag vkind))
    )
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.GetRegType sp
      let str = hdl.RegisterFactory.GetRegisterName sp
      let var = { Kind = RegVar(rt, sp, str); Identifier = 0 }
      state.SeedRegValue(var, UntouchedValueDomain.Touched)
      state
    | None ->
      state

  let getBaseCase (v: Variable) =
    match v.Kind with
    | MemVar | PCVar _ ->
      UntouchedValueDomain.Touched
    | kind ->
      UntouchedValueDomain.Untouched(RegisterTag(VarKind.ofSSAVarKind kind))

  let rec evalExpr state = function
    | Var v ->
      (state: State<_>).GetRegValue v
    | Extract(e, _, _)
    | Cast(CastKind.ZeroExt, _, e)
    | Cast(CastKind.SignExt, _, e) ->
      evalExpr state e
    | _ -> (* Any other operations will be considered "touched". *)
      UntouchedValueDomain.Touched

  let evalDef (state: State<_>) var e =
    match var.Kind with
    | MemVar
    | PCVar _ -> () (* Just ignore PCVar as it will always be "touched". *)
    | _ -> state.SetRegValue(var, evalExpr state e)

  let evalPhi (state: State<_>) ssaCFG blk dst srcIDs =
    match state.GetExecutedSources(ssaCFG, blk, srcIDs) with
    | [||] ->
      ()
    | executedSrcIDs ->
      match dst.Kind with
      | MemVar | PCVar _ ->
        ()
      | _ ->
        executedSrcIDs
        |> Array.map (fun i ->
          { dst with Identifier = i } |> state.GetRegValue)
        |> Array.reduce UntouchedValueDomain.join
        |> fun merged -> state.SetRegValue(dst, merged)

  let evalJmp (state: State<_>) ssaCFG blk =
    state.MarkSuccessorsExecutable(ssaCFG, blk)

  let lattice = UntouchedValueDomain.createLattice ()

  let rec scheme =
    { new IScheme<UntouchedValueDomain.Lattice> with
        member _.Transfer(stmt, ssaCFG, blk) =
          match stmt with
          | Def(var, e) -> evalDef state var e
          | Phi(var, ns) -> evalPhi state ssaCFG blk var ns
          | Jmp _ -> evalJmp state ssaCFG blk
          | LMark _ | ExternalCall _ | SideEffect _ -> ()
        member _.ReadMemFromBinaryFile(_rt, _addr) =
          UntouchedValueDomain.Touched
        member _.GetBaseCase v = getBaseCase v
        member _.EvalExpr e = evalExpr state e }

  and state =
    State<UntouchedValueDomain.Lattice>(hdl, lattice, scheme)
    |> initRegisters

  /// Returns the underlying state of this analysis.
  member _.State with get() = state

  interface IDataFlowComputable<SSAVarPoint,
                                UntouchedValueDomain.Lattice,
                                SSABasicBlock> with
    member _.Compute cfg = compute cfg state

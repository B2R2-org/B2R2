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

open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.DataFlow
open type UntouchedValueDomain.UntouchedTag

type SSAUntouchedValuePropagation<'E when 'E: equality> (hdl) as this =
  inherit SSAVarBasedDataFlowAnalysis<UntouchedValueDomain.Lattice, 'E> (hdl)

  let initRegisters () =
    hdl.RegisterFactory.GetGeneralRegExprs ()
    |> List.iter (fun regExpr ->
      let rid = hdl.RegisterFactory.RegIDFromRegExpr regExpr
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let str = hdl.RegisterFactory.RegIDToString rid
      let var = { Kind = RegVar (rt, rid, str); Identifier = 0 }
      let vkind = VarKind.ofSSAVarKind var.Kind
      this.SetRegValueWithoutPushing var
      <| UntouchedValueDomain.Untouched (RegisterTag vkind)
    )
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.RegIDToRegType sp
      let str = hdl.RegisterFactory.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      this.SetRegValueWithoutPushing var UntouchedValueDomain.Touched
    | None -> ()

  let evalVar v =
    if this.IsRegSet v then this.GetRegValue v
    else
      if v.Identifier = 0 then
        let kind = VarKind.ofSSAVarKind v.Kind
        UntouchedValueDomain.Untouched (RegisterTag kind) (* Initialize here. *)
      else UntouchedValueDomain.Touched

  let rec evalExpr blk = function
    | Var v -> evalVar v
    | Extract (e, _, _)
    | Cast (CastKind.ZeroExt, _, e)
    | Cast (CastKind.SignExt, _, e) -> evalExpr blk e
    | _ -> (* Any other operations will be considered "touched". *)
      UntouchedValueDomain.Touched

  let evalDef blk pp var e =
    match var.Kind with
    | MemVar
    | PCVar _ -> () (* Just ignore PCVar as it will always be "touched". *)
    | _ -> this.SetRegValue (pp, var, evalExpr blk e)

  let evalPhi ssaCFG blk pp dst srcIDs =
    match this.GetExecutedSources ssaCFG blk srcIDs with
    | [||] -> ()
    | executedSrcIDs ->
      match dst.Kind with
      | MemVar | PCVar _ -> ()
      | _ ->
        executedSrcIDs
        |> Array.map (fun i -> { dst with Identifier = i } |> this.GetRegValue)
        |> Array.reduce this.Join
        |> fun merged -> this.SetRegValue (pp, dst, merged)

  let evalJmp ssaCFG blk =
    this.MarkSuccessorsExecutable ssaCFG blk

  do initRegisters ()

  override _.Bottom with get() = UntouchedValueDomain.Undef

  override _.Join a b = UntouchedValueDomain.join a b

  override _.Transfer ssaCFG blk pp stmt =
    match stmt with
    | Def (var, e) -> evalDef blk pp var e
    | Phi (var, ns) -> evalPhi ssaCFG blk pp var ns
    | Jmp _ -> evalJmp ssaCFG blk
    | LMark _ | ExternalCall _ | SideEffect _ -> ()

  override _.IsSubsumable lhs rhs = UntouchedValueDomain.isSubsumable lhs rhs

  override _.UpdateMemFromBinaryFile _rt _addr = UntouchedValueDomain.Undef

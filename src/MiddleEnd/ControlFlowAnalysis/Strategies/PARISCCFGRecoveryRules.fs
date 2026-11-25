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


namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2
open B2R2.ABI
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.Collections
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.CFGRecoveryCommon

[<AutoOpen>]
module private PARISCCFGRecoveryRules =
  /// Checks if the given value is what the given link register held on entry
  /// to the function.
  let isLinkOnEntry link value =
    match value with
    | UntouchedValueDomain.Untouched(UntouchedValueDomain.RegisterTag r) ->
      r = Regular link
    | _ ->
      false

  /// Finds the expression whose low two bits the jump to the given target
  /// clears, as every transfer of PA-RISC through a register does, where an
  /// address holds the privilege level, along with where it is read.
  let tryUnmask stmts target =
    stmts
    |> Array.tryPick (fun (stmt, pp) ->
      match stmt with
      | Put(Dst = dst; Src = BinOp(Op = BinOpType.AND; Left = e; Right = Num m))
        when dst = target && m.ToUInt64() &&& 0xffffffffUL = 0xfffffffcUL ->
        Some(e, pp)
      | _ ->
        None)

  /// Checks if the indirect jump that ends the given vertex goes to the value
  /// that the link register of the calling convention, RP, held on entry to
  /// the function, wherever the function has kept it since, such as in a
  /// stack slot.
  let jumpsToLink (ctx: CFGBuildingContext<_, _>) v =
    match ctx.BinHandle.Conventions.Calling.ReturnAddressLocation with
    | InRegister link ->
      let uva = ctx.UVA
      (uva :> IDataFlowComputable<_, _, _>).Compute ctx.CFG |> ignore
      let state = uva.State
      let stmts = state.GetStmtInfos v
      match stmts[stmts.Length - 1] with
      | InterJmp(Target = target), _ ->
        match tryUnmask stmts target with
        | Some(e, pp) -> isLinkOnEntry link (state.Scheme.EvalExpr(pp, e))
        | None -> false
      | _ ->
        false
    | OnStack ->
      false

  /// Checks if the given expression reads the given register.
  let reads (rid: RegisterID) e =
    let rset = RegisterSet()
    AST.updateRegsUses rset e
    rset.Contains(int rid)

  /// Finds the value that the given register holds past the given vertex, as
  /// the data flow tells.
  let tryFindOutgoingConst (state: LowUIRSparseDataFlow.State<_>) v rid =
    let toConst vp =
      match state.GetAbsValue vp with
      | ConstantDomain.Const bv -> Some(bv.ToUInt64())
      | _ -> None
    match state.PerVertexOutgoingDefs.TryGetValue v with
    | true, defs -> Map.tryFind (Regular rid) defs |> Option.bind toConst
    | false, _ -> None

  /// Checks if a call leaves the given address in its link: the instruction
  /// that a call returns past, its delay slot included, is a call.
  let isLinkOfCall (ctx: CFGBuildingContext<_, _>) addr =
    match ctx.BBLFactory.PeekInstruction(addr - 8UL) with
    | Ok ins -> ins.IsCall
    | Error _ -> false

  /// The registers that code may link by hand to call through a jump: RP, the
  /// link of a call, and GR31, the link of a call of millicode.
  let handLinks =
    [| PARISC.Register.GR2; PARISC.Register.GR31 |]
    |> Array.map PARISC.Register.toRegID

  /// The privilege level of user code, which an address that a branch links
  /// carries in its low two bits, as does a return address that code links
  /// by hand from one, while an address of data that code finds from the PC
  /// has it cleared.
  [<Literal>]
  let PrivUser = 3UL

  /// Finds the address that a link holds at the indirect jump that ends the
  /// given vertex, if the jump goes elsewhere than the link says, and the link
  /// holds an address of the code of the function past the jump, along with
  /// the privilege level as a return address does, that no call left there:
  /// GCC calls through a function pointer that way, without $$dyncall,
  /// linking RP by hand to the code past the call, and calls millicode out of
  /// the reach of a branch that way, linking GR31, so that the callee returns
  /// there. GCC finds a table from the PC by way of a link as well, but clears
  /// the privilege level.
  let tryFindHandLink (ctx: CFGBuildingContext<_, _>) v =
    let jmpIns = (v: IVertex<LowUIRBasicBlock>).VData.Internals.LastInstruction
    let cp = ctx.CP
    (cp :> IDataFlowComputable<_, _, _>).Compute ctx.CFG |> ignore
    let state = cp.State
    let stmts = state.GetStmtInfos v
    let isHandLink addr =
      addr > jmpIns.Address
      && isWithinFunction ctx ctx.FunctionAddress addr
      && not (isLinkOfCall ctx addr)
    let tryFindLink e link =
      if reads link e then
        None
      else
        tryFindOutgoingConst state v link
        |> Option.filter (fun value -> value &&& 3UL = PrivUser)
        |> Option.map (fun value -> value &&& ~~~3UL)
        |> Option.filter isHandLink
    match stmts[stmts.Length - 1] with
    | InterJmp(Target = target), _ ->
      match tryUnmask stmts target with
      | Some(e, _) -> Array.tryPick (tryFindLink e) handLinks
      | None -> None
    | _ ->
      None

/// Represents the rules of the CFG recovery for PA-RISC: the rules of every
/// architecture, except that an indirect jump returns where it goes to the
/// address that the caller left in RP. PA-RISC has no return instruction: a
/// return is a BV through RP, and GCC jumps through a table by way of RP as
/// well, once it has saved RP.
type internal PARISCCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.ReturnsThroughLink(ctx, v: IVertex<LowUIRBasicBlock>) =
    jumpsToLink ctx v

  override _.TryFindReturnOfJump(ctx, v) = tryFindHandLink ctx v

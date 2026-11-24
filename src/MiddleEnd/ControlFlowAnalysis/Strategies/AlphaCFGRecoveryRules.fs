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
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow

[<AutoOpen>]
module private AlphaCFGRecoveryRules =
  /// The word of ldah gp, n(t12), with the displacement n masked off.
  [<Literal>]
  let LdahGPFromT12 = 0x27bb0000UL

  /// The word of lda gp, n(gp), with the displacement n masked off.
  [<Literal>]
  let LdaGPFromGP = 0x23bd0000UL

  /// Checks if the word at the given address is the given one, with its
  /// displacement of 16 bits masked off.
  let isWordAt (ctx: CFGBuildingContext<_, _>) addr word =
    match ctx.BinHandle.TryReadUInt((addr: uint64), 4) with
    | Ok v -> v &&& 0xffff0000UL = word
    | Error _ -> false

  /// Checks if the two words before the given target compute gp from t12, as
  /// the prologue of a function does with the address of itself that its
  /// caller puts in t12.
  let followsGPPrologue ctx target =
    target >= 8UL
    && isWordAt ctx (target - 8UL) LdahGPFromT12
    && isWordAt ctx (target - 4UL) LdaGPFromGP

  /// Finds the variable that the given one masks the low two bits of, as a
  /// jump of Alpha does to its target.
  let unmask (state: LowUIRSparseDataFlow.State<_>) v =
    match state.TryGetSSADef v with
    | Some(SSA.Def(_, SSA.BinOp(BinOpType.AND, _, SSA.Var src, SSA.Num m)))
      when m.ToUInt64() = ~~~3UL ->
      src
    | _ ->
      v

  /// Finds the address of the slot that the given variable is loaded from,
  /// which the data flow finds constant, as the code reaches a slot of the GOT
  /// through gp. A load of Alpha takes its address from a temporary that the
  /// lifter sets to the base plus the displacement.
  let tryFindLoadedSlot (state: LowUIRSparseDataFlow.State<_>) v =
    match state.TryGetSSADef v with
    | Some(SSA.Def(_, SSA.Load(_, _, SSA.Var addr))) ->
      match state.TryGetAbsValueOfSSAVar addr with
      | Some(ConstantDomain.Const bv) -> Some(bv.ToUInt64())
      | _ -> None
    | _ ->
      None

  /// Reads the function that the given slot of the GOT leads to: the address
  /// that the loader rebases the slot to, or else the one that the binary
  /// holds there, which is the PLT entry of an import that the loader binds
  /// lazily, or the function itself in code that is not position-independent.
  let tryReadGOTSlot (hdl: BinHandle) slot =
    if not (LoaderOnlyMemory.isInGOT hdl.File slot) then
      None
    else
      match BinFileOps.tryResolveRelocationValue hdl.File slot with
      | Ok(BinRelocationValue.Rebased target) ->
        Some target
      | _ ->
        match hdl.TryReadUInt(slot, 8) with
        | Ok target -> Some target
        | Error _ -> None

  /// Finds the function that the indirect call ending the given vertex
  /// reaches through the slot of the GOT that the code loads its target from.
  let tryFindGOTCallee (ctx: CFGBuildingContext<_, _>) caller =
    let cp = ctx.CP
    (cp :> IDataFlowComputable<_, _, _>).Compute ctx.CFG |> ignore
    let state = cp.State
    match state.GetTerminatorInSSA(caller: IVertex<LowUIRBasicBlock>) with
    | SSA.Jmp(SSA.InterJmp(SSA.Var v)) ->
      unmask state v
      |> tryFindLoadedSlot state
      |> Option.bind (tryReadGOTSlot ctx.BinHandle)
      |> Option.filter (fun target ->
        target <> 0UL && ctx.BinHandle.File.IsExecutableAddr target)
    | _ ->
      None

/// Represents the rules of the CFG recovery for Alpha: the rules of every
/// architecture, except that a call or a jump past the prologue that computes
/// gp enters the function of the prologue. A caller that shares gp with its
/// callee skips the prologue, as the linker relaxes the call through the GOT
/// to a BSR past it, but the function starts at the prologue, where its FDE
/// starts too. A call through the GOT reaches what the slot that the code
/// loads its target from through gp leads to.
type internal AlphaCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.ToCalleeAddr(ctx, target) =
    if followsGPPrologue ctx target then target - 8UL else target

  override _.TryResolveIndirectCallee(ctx, caller) = tryFindGOTCallee ctx caller

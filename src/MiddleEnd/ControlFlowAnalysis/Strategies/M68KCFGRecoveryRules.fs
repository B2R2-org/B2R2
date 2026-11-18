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

open System.Collections.Generic
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.CFGRecoveryCommon
open B2R2.MiddleEnd.DataFlow

[<AutoOpen>]
module private M68KCFGRecoveryRules =
  /// Finds the address that the given variable holds as the code puts it into
  /// a register, through copies and through phis whose operands all hold it.
  /// A value that the code loads from memory may change on a way to the load
  /// that the recovery has yet to find, as a pointer that a stack slot holds
  /// once a callee writes it.
  let tryFindPutAddress (state: LowUIRSparseDataFlow.State<_>) v =
    let seen = HashSet<SSA.Variable>()
    let addrs = HashSet<uint64>()
    let rec collect v =
      if not (seen.Add v) then
        true
      else
        match state.TryGetSSADef v with
        | Some(SSA.Def(_, SSA.Num bv)) ->
          addrs.Add(bv.ToUInt64()) |> ignore
          true
        | Some(SSA.Def(_, SSA.Var src)) ->
          collect src
        | Some(SSA.Phi(_, ids)) ->
          ids |> Array.forall (fun id -> collect { v with Identifier = id })
        | _ ->
          false
    if collect v && addrs.Count = 1 then Some(Seq.head addrs) else None

  /// Finds the function that the indirect call ending the given vertex
  /// reaches, if the code puts its address into the register that the call
  /// goes through.
  let tryFindPutCallee (ctx: CFGBuildingContext<_, _>) caller =
    let cp = ctx.CP
    (cp :> IDataFlowComputable<_, _, _>).Compute ctx.CFG |> ignore
    let state = cp.State
    match state.GetTerminatorInSSA(caller: IVertex<LowUIRBasicBlock>) with
    | SSA.Jmp(SSA.InterJmp(SSA.Var v)) ->
      match tryFindPutAddress state v with
      | Some target
        when target <> 0UL && ctx.BinHandle.File.IsExecutableAddr target ->
        Some target
      | _ ->
        None
    | _ ->
      None

/// Represents the rules of the CFG recovery for m68k: the rules of every
/// architecture, except that a function that jumps to another one before the
/// recovery has found that one is built again to call it as its tail, as GCC
/// emits no call frame information for C code that would tell every function
/// up front, and that an indirect call reaches the function whose address the
/// code puts into the register that the call goes through, as GCC loads the
/// address of a function that it calls more than once into an address
/// register, through which a call takes two bytes rather than six.
type internal M68KCFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.TryResolveIndirectCallee(ctx, caller) =
    tryFindPutCallee ctx caller

  override this.FindFunctionsToRebuild builders =
    findFunctionsMissingTailCalls this builders

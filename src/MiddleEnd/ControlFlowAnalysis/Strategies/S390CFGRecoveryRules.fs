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

open B2R2.ABI
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow

[<AutoOpen>]
module private S390CFGRecoveryRules =
  /// Checks if the given value is what the given link register held on entry
  /// to the function.
  let isLinkOnEntry link value =
    match value with
    | UntouchedValueDomain.Untouched(UntouchedValueDomain.RegisterTag r) ->
      r = Regular link
    | _ ->
      false

  /// Checks if the indirect jump that ends the given vertex goes to the value
  /// that the link register of the calling convention, R14, held on entry to
  /// the function, wherever the function has kept it since, such as in a
  /// stack slot and then in another register.
  let jumpsToLink (ctx: CFGBuildingContext<_, _>) v =
    match ctx.BinHandle.Conventions.Calling.ReturnAddressLocation with
    | InRegister link ->
      let uva = ctx.UVA
      (uva :> IDataFlowComputable<_, _, _>).Compute ctx.CFG |> ignore
      let state = uva.State
      let stmts = state.GetStmtInfos v
      match stmts[stmts.Length - 1] with
      | InterJmp(Target = target), pp ->
        isLinkOnEntry link (state.Scheme.EvalExpr(pp, target))
      | _ ->
        false
    | OnStack ->
      false

/// Represents the rules of the CFG recovery for S390: the rules of every
/// architecture, except that an indirect jump returns where it goes to the
/// address that the caller left in R14. S390 has no return instruction, and
/// GCC reloads the saved R14 into another register to return through, while
/// both GCC and clang jump through a table by way of R14.
type internal S390CFGRecoveryRules<'FnCtx, 'GlCtx>() =
  inherit CFGRecoveryRules<'FnCtx, 'GlCtx>()

  override _.ReturnsThroughLink(ctx, v: IVertex<LowUIRBasicBlock>) =
    jumpsToLink ctx v

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

namespace B2R2.RearEnd.BinExplore

open System.Threading
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Adds cooperative cancellation between CFG recovery actions.
type internal CancellableStrategy<'FnCtx, 'GlCtx>(inner, token) =
  let inner: ICFGBuildingStrategy<'FnCtx, 'GlCtx> = inner

  let check () = (token: CancellationToken).ThrowIfCancellationRequested()

  interface ICFGBuildingStrategy<'FnCtx, 'GlCtx> with
    member _.ActionPrioritizer = inner.ActionPrioritizer

    member _.RecoveryTargets = inner.RecoveryTargets

    member _.CreateFunctionContext() =
      inner.CreateFunctionContext()

    member _.ResetFunctionContext ctx =
      inner.ResetFunctionContext ctx

    member _.CreateGlobalContext() =
      inner.CreateGlobalContext()

    member _.OnAction(ctx, queue, action) =
      check ()
      inner.OnAction(ctx, queue, action)

    member _.OnCreate ctx =
      inner.OnCreate ctx

    member _.OnFinish ctx =
      check ()
      inner.OnFinish ctx

    member _.OnCyclicDependency dependencies =
      check ()
      inner.OnCyclicDependency dependencies

    member _.FindCandidatesForPostProcessing builders =
      check ()
      inner.FindCandidatesForPostProcessing builders

  interface ICFGRevisingStrategy<'FnCtx, 'GlCtx> with
    member _.FindFunctionsToRebuild builders =
      check ()
      match inner with
      | :? ICFGRevisingStrategy<'FnCtx, 'GlCtx> as revising ->
        revising.FindFunctionsToRebuild builders
      | _ ->
        [||]

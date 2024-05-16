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

open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.SSA

/// The interface for a post-analysis, which is performed after a function CFG
/// is completely built. This interface wraps an analysis function, which can be
/// unwrapped and executed later.
type IPostAnalysis<'Fn> =
  /// Unwrap the post-analysis (`'Fn`).
  abstract Unwrap: PostAnalysisEnv<'FnCtx, 'GlCtx> -> 'Fn
with
  static member inline (<+>) (a: IPostAnalysis<_>, b: IPostAnalysis<_>) =
    { new IPostAnalysis<_> with
        member _.Unwrap env = a.Unwrap env >> b.Unwrap env }

/// The environment for a post-analysis.
and PostAnalysisEnv<'FnCtx,
                    'GlCtx when 'FnCtx :> IResettable
                            and 'FnCtx: (new: unit -> 'FnCtx)
                            and 'GlCtx: (new: unit -> 'GlCtx)> = {
  Context: CFGBuildingContext<IRBasicBlock, CFGEdgeKind, 'FnCtx, 'GlCtx>
  SSALifter: ISSALiftable<CFGEdgeKind>
  SSARoot: IVertex<SSABasicBlock>
}

module IPostAnalysis =
  /// Finalize the post-analysis, which ignores the output of the previous
  /// post-analysis.
  let finalize (a: IPostAnalysis<_>) =
    { new IPostAnalysis<_> with
        member _.Unwrap env = a.Unwrap env >> ignore }

  /// Run the combined post-analysis, which should take `unit` as input and
  /// returns `unit` as output.
  let inline run env (a: IPostAnalysis<_>): unit = a.Unwrap env ()

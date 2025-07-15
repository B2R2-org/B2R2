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

open B2R2.MiddleEnd.ControlFlowAnalysis

/// The interface for a CFG-based analysis, which is performed on a CFG. This
/// interface wraps an analysis function, which can be unwrapped and executed
/// later.
type ICFGAnalysis<'Fn> =
  /// Unwrap the CFG-based analysis (`'Fn`).
  abstract Unwrap: CFGAnalysisEnv<'FnCtx, 'GlCtx> -> 'Fn
with
  static member inline (<+>) (a: ICFGAnalysis<_>, b: ICFGAnalysis<_>) =
    { new ICFGAnalysis<_> with
        member _.Unwrap env = a.Unwrap env >> b.Unwrap env }

/// The environment for a CFG-based analysis.
and CFGAnalysisEnv<'FnCtx,
                    'GlCtx when 'FnCtx :> IResettable
                            and 'FnCtx: (new: unit -> 'FnCtx)
                            and 'GlCtx: (new: unit -> 'GlCtx)> = {
  Context: CFGBuildingContext<'FnCtx, 'GlCtx>
}

module ICFGAnalysis =
  /// An empty CFG-based analysis, which does nothing.
  let empty =
    { new ICFGAnalysis<_> with
        member _.Unwrap _ = ignore }

  /// Finalize the CFG-based analysis, which ignores the output of the previous
  /// CFG-based analysis.
  let finalize (a: ICFGAnalysis<_>) =
    { new ICFGAnalysis<_> with
        member _.Unwrap env = a.Unwrap env >> ignore }

  /// Run the combined CFG-based analysis, which should take `unit` as input and
  /// returns `unit` as output.
  let inline run env (a: ICFGAnalysis<_>): unit = a.Unwrap env ()

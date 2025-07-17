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
open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents the main interface for CFG recovery strategies.
type ICFGRecovery<'UsrCtx, 'GlbCtx when 'UsrCtx :> IResettable
                                    and 'UsrCtx: (new: unit -> 'UsrCtx)
                                    and 'GlbCtx: (new: unit -> 'GlbCtx)> =
  inherit ICFGBuildingStrategy<'UsrCtx, 'GlbCtx>
  inherit IIndirectJmpAnalyzable<'UsrCtx, 'GlbCtx>
  inherit ICallAnalyzable<'UsrCtx, 'GlbCtx>
  inherit IAnalysisResumable<'UsrCtx, 'GlbCtx>
  inherit IGraphCallback<'UsrCtx, 'GlbCtx>

  /// Returns the function summarizer for this CFG recovery strategy.
  abstract Summarizer: IFunctionSummarizable<'UsrCtx, 'GlbCtx>

/// Handles the analysis of indirect jumps and conditional jumps during CFG
/// recovery.
and IIndirectJmpAnalyzable<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                           and 'FnCtx: (new: unit -> 'FnCtx)
                                           and 'GlCtx: (new: unit -> 'GlCtx)> =
  abstract AnalyzeIndirectJump:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> Queue<ProgramPoint>
    -> ProgramPoint
    -> IVertex<LowUIRBasicBlock>
    -> Option<CFGResult>

  abstract AnalyzeIndirectCondJump:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> Queue<ProgramPoint>
    -> ProgramPoint
    -> IVertex<LowUIRBasicBlock>
    -> Option<CFGResult>

/// Handles the analysis of function calls with call-related CFG actions.
and ICallAnalyzable<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                    and 'FnCtx: (new: unit -> 'FnCtx)
                                    and 'GlCtx: (new: unit -> 'GlCtx)> =
  abstract AnalyzeCall:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> CallSite
    -> callee: Addr
    -> CalleeInfo
    -> isTailCall: bool
    -> CFGResult

/// Handles the resumption of CFG analysis with an CFG action `ResumeAnalysis`.
and IAnalysisResumable<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                       and 'FnCtx: (new: unit -> 'FnCtx)
                                       and 'GlCtx: (new: unit -> 'GlCtx)> =
  abstract ResumeAnalysis:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> ProgramPoint
    -> callback: CFGAction
    -> CFGResult

/// Represents a callback interface for graph operations in CFG recovery.
and IGraphCallback<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                    and 'FnCtx: (new: unit -> 'FnCtx)
                                    and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// Called when a new vertex is added to the CFG.
  abstract OnAddVertex:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> IVertex<LowUIRBasicBlock>
    -> unit

  /// Called when an edge is added to the CFG.
  abstract OnAddEdge:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    -> IVertex<LowUIRBasicBlock>
    -> IVertex<LowUIRBasicBlock>
    -> CFGEdgeKind
    -> unit

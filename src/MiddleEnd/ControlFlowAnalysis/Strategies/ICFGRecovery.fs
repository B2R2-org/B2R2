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
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents the main interface for CFG recovery strategies.
type ICFGRecovery<'FnCtx, 'GlCtx> =
  inherit ICFGBuildingStrategy<'FnCtx, 'GlCtx>
  inherit IIndirectJmpAnalyzable<'FnCtx, 'GlCtx>
  inherit IGraphCallback<'FnCtx, 'GlCtx>

  /// Returns the function summarizer for this CFG recovery strategy.
  abstract Summarizer: IFunctionSummarizable<'FnCtx, 'GlCtx>

/// Represents an interface for analyzing indirect jumps and conditional jumps
/// during CFG recovery.
and IIndirectJmpAnalyzable<'FnCtx, 'GlCtx> =
  /// Handles an indirect jump that no relocation resolves during the CFG
  /// building. It takes the building context, the program point being visited,
  /// and the vertex that ends with the jump. Returning None lets the building
  /// go on as is; returning Some result overrides the building result, which
  /// stops the building unless the result is MoveOn.
  abstract AnalyzeIndirectJump:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * ProgramPoint
    * IVertex<LowUIRBasicBlock>
    -> Option<CFGResult>

  /// Handles an indirect conditional jump during the CFG building, i.e., a
  /// conditional jump whose targets are neither constants nor PC-relative. It
  /// takes the same arguments as AnalyzeIndirectJump and returns its result in
  /// the same way.
  abstract AnalyzeIndirectCondJump:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * ProgramPoint
    * IVertex<LowUIRBasicBlock>
    -> Option<CFGResult>

/// Represents a callback interface for graph operations in CFG recovery.
and IGraphCallback<'FnCtx, 'GlCtx> =
  /// Handles a new vertex added to the CFG.
  abstract OnAddVertex:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * IVertex<LowUIRBasicBlock>
    -> unit

  /// Handles a new edge added to the CFG.
  abstract OnAddEdge:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * IVertex<LowUIRBasicBlock>
    * IVertex<LowUIRBasicBlock>
    * CFGEdgeKind
    -> unit

  /// Handles a vertex removed from the CFG.
  abstract OnRemoveVertex:
       CFGBuildingContext<'FnCtx, 'GlCtx>
    * IVertex<LowUIRBasicBlock>
    -> unit

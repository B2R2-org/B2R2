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

namespace B2R2.MiddleEnd.DataFlow

open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Data-flow analysis that runs under the abstract interpretation framework.
/// Abstract values are represented by 'AbsVal, which is stored in an abstract
/// location 'AbsLoc.
type IDataFlowAnalysis<'AbsLoc,
                       'AbsVal,
                       'State,
                       'V when 'AbsLoc: equality
                           and 'State :> IDataFlowState<'AbsLoc, 'AbsVal>
                           and 'V: equality> =
  /// Return an initial state for the data-flow analysis.
  abstract InitializeState: IVertex<'V> seq -> 'State

  /// Perform the dataflow analysis on the given CFG until a fixed point is
  /// reached.
  abstract Compute: cfg: IGraph<'V, CFGEdgeKind> -> 'State -> 'State

/// The state of the data-flow analysis, which contains a mapping from abstract
/// locations to abstract values.
and [<AllowNullLiteral>]
  IDataFlowState<'AbsLoc, 'AbsVal when 'AbsLoc: equality> =
  /// Get the abstract value (AbsVal) for the given abstract location.
  abstract GetAbsValue: 'AbsLoc -> 'AbsVal

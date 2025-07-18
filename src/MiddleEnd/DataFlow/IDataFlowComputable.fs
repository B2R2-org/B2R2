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

open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Represents a mapping from abstract locations to abstract values.
[<AllowNullLiteral>]
type IAbsValProvider<'AbsLoc, 'AbsVal when 'AbsLoc: equality> =
  /// Get the abstract value (AbsVal) for the given abstract location.
  abstract GetAbsValue: 'AbsLoc -> 'AbsVal

/// Data-flow analysis that runs under the abstract interpretation framework.
/// Abstract values are represented by 'AbsVal, which is stored in an abstract
/// location 'AbsLoc.
[<AllowNullLiteral>]
type IDataFlowComputable<'AbsLoc,
                         'AbsVal,
                         'Provider,
                         'V when 'AbsLoc: equality
                             and 'Provider :> IAbsValProvider<'AbsLoc, 'AbsVal>
                             and 'V: equality> =
  /// Perform the dataflow analysis on the given CFG until a fixed point is
  /// reached.
  abstract Compute: cfg: IDiGraph<'V, CFGEdgeKind> -> 'Provider

/// Represents an interface for a lattice used in abstract interpretation.
type ILattice<'AbsVal when 'AbsVal: equality> =
  /// The initial abstract value representing the bottom of the lattice. Our
  /// analysis starts with this value until it reaches a fixed point.
  abstract Bottom: 'AbsVal

  /// Joins two abstract values.
  abstract Join: 'AbsVal * 'AbsVal -> 'AbsVal

  /// The subsume operator, which checks if the first lattice subsumes the
  /// second. This is to know if the analysis should stop or not.
  abstract Subsume: 'AbsVal * 'AbsVal -> bool

/// Represents an interface for evaluating expressions in the given context.
[<AllowNullLiteral>]
type IExprEvaluatable<'Ctx, 'AbsVal when 'AbsVal: equality> =
  /// Returns the abstract value of the given expression in the specified
  /// context.
  abstract EvalExpr: context: 'Ctx * exp: Expr -> 'AbsVal

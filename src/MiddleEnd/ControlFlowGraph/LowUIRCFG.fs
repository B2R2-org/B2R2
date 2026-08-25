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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2.MiddleEnd.BinGraph

/// Represents a CFG where each node is an IR-level basic block. This is the
/// main data structure that we use to represent the control flow graph of a
/// function. This is the graph interface itself, so that a CFG is a mutable
/// graph or a persistent one without a caller having to know which.
type LowUIRCFG = IMutableDiGraph<LowUIRBasicBlock, CFGEdgeKind>

/// <summary>
/// Provides a way to create a
/// <see cref="T:B2R2.MiddleEnd.ControlFlowGraph.LowUIRCFG"/>.
/// </summary>
[<RequireQualifiedAccess>]
module LowUIRCFG =
  /// Creates an empty CFG of the given implementation type.
  let create t: LowUIRCFG = GraphFactory.create t

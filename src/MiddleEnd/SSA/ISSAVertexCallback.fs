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

namespace B2R2.MiddleEnd.SSA

open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow

/// Represents a callback the SSA lifter fires on each vertex of the graph it
/// lifts.
type ISSAVertexCallback =
  /// Fires on one vertex of the SSACFG, while the lifter promotes the graph,
  /// and therefore after every vertex of the graph has been created. The
  /// SSACFG, its dominance, and the stack pointer propagation analysis are
  /// all handed over so that stack local variables are cheap to compute. The
  /// dominance is that of the very SSACFG given, since the callback fires
  /// while the lifter still holds both. The vertices are promoted in turn and
  /// this fires on each of them before that one is promoted, so the graph it
  /// reads is one that is only partly promoted.
  abstract OnVertexCreation:
      SSACFG
    * IForwardDominance<SSABasicBlock>
    * SSASparseDataFlow.State<StackPointerDomain.Lattice>
    * SSAVertex
    -> unit

(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinGraph

/// The Lens interface, which is a converter from a graph to another graph. In
/// B2R2, An IR-level SCFG forms the basis, and we should apply different lenses
/// to obtain different graphs. For example, we can get disassembly-based CFG by
/// applying DisasmLens to the SCFG.
type ILens<'V when 'V :> BasicBlock and 'V: equality> =
  /// <summary>
  /// The main function of the ILens interface, which will essentially convert a
  /// given CFG into another graph.
  /// </summary>
  /// <param name="graph">The given CFG.</param>
  /// <param name="root">The list of root nodes of the CFG.</param>
  /// <returns>
  /// A converted graph along with its root node.
  /// </returns>
  abstract member Filter:
       graph: IRCFG
    -> roots: Vertex<IRBasicBlock> list
    -> corpus: BinCorpus
    -> ControlFlowGraph<'V, CFGEdgeKind> * Vertex<'V> list


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

open B2R2.MiddleEnd.ControlFlowGraph

/// <namespacedoc>
///   <summary>
///   Contains the two operations that put a CFG of B2R2's middle-end into SSA
///   form: lifting a LowUIR CFG into an SSA one, and promoting the stack slots
///   of such a graph into variables of their own. The graphs themselves belong
///   to <c>B2R2.MiddleEnd.ControlFlowGraph</c>, and the stack pointer
///   propagation that promotion reads belongs to
///   <c>B2R2.MiddleEnd.DataFlow</c>; what is here is the lifter and the
///   promoter that drive them, and the one interface through which that
///   propagation can be read while it lasts.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Represents a lifter that turns a LowUIR CFG into an SSACFG.
/// </summary>
type ISSALiftable =
  /// Lifts the given LowUIR CFG to an SSACFG, answering the dominance of the
  /// SSACFG alongside it. The dominator tree is what a reaching definition is
  /// read off, and the lifter is where it is computed, so a caller that wants
  /// one takes it from here rather than computing it a second time.
  abstract Lift: LowUIRCFG -> SSACFGWithDominance

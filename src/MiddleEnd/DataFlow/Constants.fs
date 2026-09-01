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

/// <namespacedoc>
///   <summary>
///   Contains the data-flow analyses that B2R2's middle-end runs over a CFG,
///   along with the pieces they are assembled from. An analysis pairs one of
///   the abstract domains (constant, stack pointer, untouched value, and
///   variable definition) with one of the fixpoint engines: a worklist engine
///   that iterates over whole vertices, a sparse engine over LowUIR that
///   builds its own def-use chains, and a sparse engine over an SSA CFG.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Provides constants used in data flow analyses.
/// </summary>
module B2R2.MiddleEnd.DataFlow.Constants

/// Defines the default stack pointer value used in data flow analyses.
let [<Literal>] InitialStackPointer = 0x80000000UL

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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open B2R2
open B2R2.MiddleEnd.ControlFlowGraph

/// Function is a chunk of code in a binary. Functions may overlap with each
/// other in rare cases. Function overlapping is rare because we will create a
/// new function when there is an incoming edge in the middle of a funcion,
type Function<'V,
              'E,
              'Abs when 'V :> IRBasicBlock<'Abs>
                    and 'V: equality
                    and 'E: equality
                    and 'Abs: null> (entryPoint, ircfg) =
  let mutable isNoRet = false

  /// Function entry point address.
  member _.EntryPoint with get(): Addr = entryPoint

  /// Function's control flow graph.
  member _.CFG with get(): IRCFG<'V, 'E, 'Abs> = ircfg

  /// Is this function a no-return function?
  member _.IsNoRet with get() = isNoRet and set(v) = isNoRet <- v

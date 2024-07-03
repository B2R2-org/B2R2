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

open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowAnalysis

/// This is a non-returning function identification strategy that can check
/// conditionally non-returning functions. We currently support only those
/// simple patterns that are handled by compilers, but we may have to extend
/// this as the compilers evolve.
type CondAwareNoretAnalysis () =
  let isNoReturn ctx = // FIXME
    false

  interface IPostAnalysis<CPState<SPValue> -> unit> with
    member _.Unwrap env =
      let ctx = env.Context
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
      <| $"{ctx.FunctionAddress:x}"
#endif
      fun spState ->
        if isNoReturn ctx then ctx.NonReturningStatus <- NoRet
        else ctx.NonReturningStatus <- NotNoRet

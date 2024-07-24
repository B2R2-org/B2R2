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

open B2R2
open B2R2.BinIR.SSA

/// A domain for untouched value analysis.
[<RequireQualifiedAccess>]
module UntouchedValueDomain =
  type Lattice =
    /// Touched means the value is redefined.
    | Touched
    /// This value is never defined within the function.
    | Untouched of UntouchedTag
    | Undef

  and UntouchedTag =
    | RegisterTag of VarKind
    | MemoryTag of Addr

  let subsume fromV toV =
    match fromV, toV with
    | a, b when a = b -> true
    | Untouched _, Undef
    | Touched, Undef
    | Touched, Untouched _ -> true
    | _ -> false

  let join c1 c2 =
    match c1, c2 with
    | Undef, c | c, Undef -> c
    | Untouched t1, Untouched t2 when t1 = t2 -> c1
    | Untouched _, Untouched _ -> Touched
    | _ -> Touched

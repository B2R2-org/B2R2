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

namespace B2R2.FrontEnd.BinLifter.Sparc64

open B2R2

module private RegisterSetLiteral =
  let [<Literal>] arrLen = 2

open RegisterSetLiteral

type Sparc64RegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  new () =
    Sparc64RegisterSet (RegisterSet.MakeInternalBitArray arrLen, Set.empty)

  override __.Tag = RegisterSetTag.Sparc64

  override __.ArrSize = arrLen

  override __.New arr s = new Sparc64RegisterSet (arr, s) :> RegisterSet

  override __.RegIDToIndex rid =
    match Register.ofRegID rid with
    | _ -> Utils.futureFeature ()

  override __.IndexToRegID _index: RegisterID =
    Utils.futureFeature ()

  override __.ToString () =
    sprintf "Sparc64RegisterSet<%x, %x>" __.BitArray.[0] __.BitArray.[1]

[<RequireQualifiedAccess>]
module Sparc64RegisterSet =
  let singleton rid = Sparc64RegisterSet().Add(rid)
  let empty = Sparc64RegisterSet () :> RegisterSet

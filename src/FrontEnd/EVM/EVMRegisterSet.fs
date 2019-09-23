(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>

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

namespace B2R2.FrontEnd.EVM

open B2R2

type EVMRegisterSet (bitArray: uint64 [], s: Set<RegisterID>) =
  inherit NonEmptyRegisterSet (bitArray, s)

  static let defaultSize = 2
  static let emptyArr = Array.init defaultSize (fun _ -> 0UL)
  static member EmptySet =
    new EVMRegisterSet (emptyArr, Set.empty) :> RegisterSet

  override __.Tag = RegisterSetTag.MIPS
  override __.ArrSize = defaultSize
  override __.New x s = new EVMRegisterSet (x, s) :> RegisterSet
  override __.Empty = EVMRegisterSet.EmptySet
  override __.EmptyArr = emptyArr
  override __.Project x =
    match Register.ofRegID x with
    | R.SP -> 0
    | R.GAS -> 1
    | _ -> -1

  override __.ToString () =
    sprintf "EVMReisterSet<%x, %x>" __.BitArray.[0] __.BitArray.[1]

[<RequireQualifiedAccess>]
module EVMRegisterSet =
  let singleton = RegisterSetBuilder.singletonBuilder EVMRegisterSet.EmptySet
  let empty = EVMRegisterSet.EmptySet

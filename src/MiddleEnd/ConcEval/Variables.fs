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

namespace B2R2.MiddleEnd.ConcEval

#if ! EMULATION
open System.Collections.Generic
#endif
open B2R2

type Variables (vars) =
#if EMULATION
  let vars: BitVector[] = vars

  new (cnt: int) = Variables (Array.zeroCreate cnt)
#else
  let vars: Dictionary<int, BitVector> = vars

  new (_cnt: int) = Variables (Dictionary ())
#endif


  member __.TryGet k =
#if EMULATION
    let v = vars[k]
    if isNull v then Error ErrorCase.InvalidRegister
    else Ok v
#else
    match vars.TryGetValue k with
    | true, v -> Ok v
    | false, _ -> Error ErrorCase.InvalidRegister
#endif

  member __.Get k = vars[k]

  member __.Set k v = vars[k] <- v

  member __.Unset k =
#if EMULATION
    vars[k] <- null
#else
    vars.Remove k |> ignore
#endif

  member __.Count () =
#if EMULATION
    vars.Length
#else
    vars.Count
#endif

  member __.ToArray () =
#if EMULATION
    vars |> Array.mapi (fun i v -> i, v)
#else
    vars |> Seq.map (fun (KeyValue (k, v))  -> k, v) |> Seq.toArray
#endif

  member __.Clone () =
#if EMULATION
    Variables (Array.copy vars)
#else
    Variables (Dictionary (vars))
#endif

module Variables =
  /// This is the maximum number of temporary variables per instruction. 64 is
  /// just a conservative number.
  let [<Literal>] MaxNumTemporaries = 64

  /// This is the maxinum number of register variables that an ISA can have.
  /// This is a conservative number.
  let [<Literal>] MaxNumVars = 1024

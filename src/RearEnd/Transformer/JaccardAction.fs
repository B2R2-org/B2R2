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

namespace B2R2.RearEnd.Transformer

open System
open B2R2

/// The `jaccard` action.
type JaccardAction () =
  let jaccard fp0 fp1 =
    match unbox<Fingerprint> fp0, unbox<Fingerprint> fp1 with
    | Fingerprint fp0, Fingerprint fp1 ->
      float (Set.intersect fp0 fp1 |> Set.count)
      / float (Set.union fp0 fp1 |> Set.count)

  interface IAction with
    member __.ActionID with get() = "jaccard"
    member __.Signature with get() = "FingerPrint[] -> int"
    member __.Description with get() = """
    Take in two fingerprints and returns the jaccard index between them.
"""
    member __.Transform args collection =
      if collection.Values.Length = 2 then
        { Values = [| jaccard collection.Values[0] collection.Values[1] |] }
      else invalidArg (nameof collection) "Two fingerprints should be given."

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

/// The `jaccard` action.
type JaccardAction () =
  let jaccard fp0 fp1 =
    match unbox<Fingerprint> fp0, unbox<Fingerprint> fp1 with
    | fp0, fp1 ->
      let s0 = List.fold (fun s (v, _) -> Set.add v s) Set.empty fp0.Patterns
      let s1 = List.fold (fun s (v, _) -> Set.add v s) Set.empty fp1.Patterns
      float (Set.intersect s0 s1 |> Set.count)
      / float (Set.union s0 s1 |> Set.count)

  interface IAction with
    member _.ActionID with get() = "jaccard"
    member _.Signature with get() = "Fingerprint collection -> int"
    member _.Description with get() = """
    Take in two fingerprints and returns the jaccard index between them.
"""
    member _.Transform args collection =
      if args.Length <> 0 then
        invalidArg (nameof args) "No arguments should be given."
      elif collection.Values.Length = 2 then
        { Values = [| jaccard collection.Values[0] collection.Values[1] |] }
      else invalidArg (nameof collection) "Two fingerprints should be given."

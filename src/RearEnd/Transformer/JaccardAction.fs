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

open System.Threading

/// The `jaccard` action.
type JaccardAction() =
  let jaccard cancellationToken fp0 fp1 =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    match unbox<Fingerprint> fp0, unbox<Fingerprint> fp1 with
    | fp0, fp1 ->
      let s0 = List.fold (fun s (v, _) -> Set.add v s) Set.empty fp0.Patterns
      let s1 = List.fold (fun s (v, _) -> Set.add v s) Set.empty fp1.Patterns
      float (Set.intersect s0 s1 |> Set.count)
      / float (Set.union s0 s1 |> Set.count)

  let transform cancellationToken (args: string list) collection =
    if args.Length <> 0 then
      invalidArg (nameof args) "No arguments should be given."
    elif collection.Values.Length = 2 then
      let value =
        jaccard cancellationToken collection.Values[0] collection.Values[1]
      { Values = [| value |] }
    else
      invalidArg (nameof collection) "Two fingerprints should be given."

  interface IAction with
    member _.ActionID with get() = "jaccard"
    member _.Signature with get() = "Fingerprint * Fingerprint -> float"
    member _.Description with get() =
      """
    Take a tuple of two fingerprints and return their Jaccard index.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

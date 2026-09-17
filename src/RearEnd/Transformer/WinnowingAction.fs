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
open System.Collections.Generic
open System.Threading
open B2R2

/// The `winnowing` action.
type WinnowingAction() =
  let computeFingerprint
    cancellationToken
    annot
    n
    wsz
    (ngrams: (int * int)[]) =
    let cancellationToken: CancellationToken = cancellationToken
    let deque = LinkedList<int>()
    let patterns = ResizeArray<int * int>()
    let mutable previousHash = 0
    for idx = 0 to ngrams.Length - 1 do
      cancellationToken.ThrowIfCancellationRequested()
      while deque.Count > 0 && deque.First.Value <= idx - wsz do
        deque.RemoveFirst()
      while deque.Count > 0
            && fst ngrams[deque.Last.Value] >= fst ngrams[idx] do
        deque.RemoveLast()
      deque.AddLast idx |> ignore
      if idx >= wsz - 1 then
        let selected = deque.First.Value
        let hash, _ = ngrams[selected]
        if hash <> previousHash then
          patterns.Add ngrams[selected]
          previousHash <- hash
        else
          ()
      else
        ()
    { Patterns = patterns |> Seq.toList
      NGramSize = n
      WindowSize = wsz
      Annotation = annot }

  let binaryAndAnnotation (input: obj) =
    match input with
    | :? Binary as bin ->
      bin, Binary.MakeAnnotation("Winnowing from ", bin)
    | :? BinarySlice as slice ->
      slice.ToBinary(), $"Winnowing from {slice}"
    | _ ->
      invalidArg (nameof input)
        "winnowing supports Binary or BinarySlice values."

  let winnowing cancellationToken n wsz input =
    let bin, annot = binaryAndAnnotation input
    let hdl = Binary.Handle bin
    let span = hdl.File.RawBytes.Span
    if span.Length < n + wsz then
      invalidArg (nameof input) "The input binary is too small."
    else
      Utils.buildNgram cancellationToken n span
      |> computeFingerprint cancellationToken annot n wsz
      |> box

  let transform cancellationToken args collection =
    let args: string list = args
    let n, wsz =
      match args with
      | [] ->
        4, 4
      | [ n ] ->
        Convert.ToInt32 n, 4
      | n :: w :: [] ->
        Convert.ToInt32 n, Convert.ToInt32 w
      | _ ->
        invalidArg (nameof args) "Too many arguments given."
    { Values =
        collection.Values
        |> Array.map (winnowing cancellationToken n wsz) }

  interface IAction with
    member _.ActionID with get() = "winnowing"
    member _.Signature with get() =
      "Binary | BinarySlice -> winnowing [n-gram-size=<n>] [window-size=<n>]"
      + " -> Fingerprint"
    member _.Description with get() =
      """
    Take in an input binary and returns its fingerprint, which is essentially a
    list of (hash * byte position) tuples.

      - n-gram-size: Size of n-gram. The default is 4.
      - window-size: Window size. The default is 4.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection

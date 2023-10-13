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

/// The `winnowing` action.
type WinnowingAction () =
  let rec min (span: Span<int * int>) (minHash, minPos) idx =
    if idx < span.Length then
      let curHash, curPos = span[idx]
      let minHash, minPos =
        if minHash > curHash then curHash, curPos
        elif minHash = curHash && minPos < curPos then curHash, curPos
        else minHash, minPos
      min span (minHash, minPos) (idx + 1)
    else (minHash, minPos)

  let rec computeFingerprint acc annot prev n wsz idx (ngrams: (int * int)[]) =
    if idx <= ngrams.Length - wsz then
      let span = ngrams.AsSpan (idx, wsz)
      let m = min span (Int32.MaxValue, Int32.MaxValue) 0
      if fst prev = fst m then
        computeFingerprint acc annot prev n wsz (idx + 1) ngrams
      else
        computeFingerprint (m :: acc) annot m n wsz (idx + 1) ngrams
    else { Patterns = List.rev acc
           NGramSize = n
           WindowSize = wsz
           Annotation = annot }

  let winnowing n wsz input =
    let bin = unbox<Binary> input
    let hdl = Binary.Handle bin
    let annot = Binary.MakeAnnotation "Winnowing from " bin
    let span = hdl.BinFile.Content.Span
    if span.Length < n + wsz then
      invalidArg (nameof input) "The input binary is too small."
    else
      Utils.buildNgram [] n span 0
      |> computeFingerprint [] annot (0, 0) n wsz 0
      |> box

  interface IAction with
    member __.ActionID with get() = "winnowing"
    member __.Signature with get() = "Binary * [n] * [wsz] -> Fingerprint"
    member __.Description with get() = """
    Take in an input binary and returns its fingerprint, which is essentially a
    list of (hash * byte position) tuples.

      - [n] : Size of n-gram. The default is 4.
      - [w] : Window size. The default is 4.
"""
    member __.Transform args collection =
      let n, wsz =
        match args with
        | [] -> 4, 4
        | n :: w :: [] -> Convert.ToInt32 n, Convert.ToInt32 w
        | _ -> invalidArg (nameof args) "Two many arguments given."
      { Values = collection.Values |> Array.map (winnowing n wsz) }

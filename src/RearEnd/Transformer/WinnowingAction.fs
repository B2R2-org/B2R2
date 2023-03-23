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
  let rec min (span: ByteSpan) (minVal, minPos) offset pos =
    if pos < span.Length then
      let curVal = span[pos]
      let minVal, minPos =
        if minVal > curVal then curVal, pos
        elif minVal = curVal && minPos < pos then curVal, pos
        else minVal, minPos
      min span (minVal, minPos) offset (pos + 1)
    else (minVal, offset + minPos)

  let rec iterNgram acc wsz (span: ByteSpan) idx =
    if idx <= span.Length - wsz then
      let m = min (span.Slice (idx, wsz)) (Byte.MaxValue, Int32.MaxValue) idx 0
      iterNgram (Set.add m acc) wsz span (idx + 1)
    else acc

  let winnowing wsz input =
    let bin = unbox<Binary> input
    let hdl = Binary.Handle bin
    let span = hdl.BinFile.Span
    if span.Length < wsz then
      min span (Byte.MaxValue, Int32.MaxValue) 0 0
      |> Set.singleton
      |> Fingerprint
      |> box
    else
      iterNgram Set.empty wsz span 0
      |> Fingerprint
      |> box

  interface IAction with
    member __.ActionID with get() = "winnowing"
    member __.Signature with get() = "Binary * [wsz] -> FingerPrint"
    member __.Description with get() = """
    Take in an input binary and returns its fingerprint, which is essentially a
    set of (byte * position) tuples.

      - [wsz] : Sliding window size to take n-gram. The default is 4.
"""
    member __.Transform args collection =
      let wsz =
        match args with
        | [] -> 4
        | n :: [] -> Convert.ToInt32 n
        | _ -> invalidArg (nameof args) "Two many arguments given."
      { Values = collection.Values |> Array.map (winnowing wsz) }

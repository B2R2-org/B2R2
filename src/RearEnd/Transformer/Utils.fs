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

module B2R2.RearEnd.Transformer.Utils

open System
open System.IO.Hashing
open B2R2.FrontEnd

let [<Literal>] MaxByteShow = 14

let byteArrayToHexStringArray (bs: byte[]) =
  bs |> Array.map (sprintf "%02x")

let makeSpanSummary (bs: ByteSpan) =
  if bs.Length > MaxByteShow then
    let s =
      bs.Slice(0, MaxByteShow).ToArray ()
      |> Array.map (sprintf "%02x")
      |> String.concat " "
    s + " ..."
  else
    bs.ToArray ()
    |> Array.map (sprintf "%02x")
    |> String.concat " "

let makeByteArraySummary (bs: byte[]) =
  makeSpanSummary (ReadOnlySpan bs)

let rec buildNgram acc n (span: ByteSpan) idx =
  if idx <= span.Length - n then
    let bs = span.Slice(idx, n).ToArray ()
    let h = XxHash32.Hash bs |> BitConverter.ToInt32
    buildNgram ((h, idx) :: acc) n span (idx + 1)
  else List.rev acc |> List.toArray

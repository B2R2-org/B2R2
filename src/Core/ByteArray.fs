(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.ByteArray

open System
open System.Text
open System.Globalization

let ofHexString (s: string) =
  Seq.windowed 2 s
  |> Seq.mapi (fun i j -> i, j)
  |> Seq.filter (fun (i, _) -> i % 2 = 0)
  |> Seq.map (fun (_, j) -> Byte.Parse(String(j),
                                       NumberStyles.AllowHexSpecifier))
  |> Array.ofSeq

let extractCString bytes offset =
  let rec loop (acc: StringBuilder) offset =
    match Array.get bytes offset with
    | 0uy -> acc.ToString ()
    | b -> loop (char b |> acc.Append) (offset + 1)
  if bytes.Length = 0 then "" else loop (StringBuilder()) offset

(* TODO: Implement Boyer-Moore algorithm to make this faster. *)
let findIdxs offset (pattern: byte []) (buf: byte []) =
  let bLen = Array.length buf
  let pEnd = Array.length pattern - 1
  let rec helper bPos pPos ret =
    if bPos < bLen then
      if buf.[bPos] = pattern.[pPos] then
        if pPos = pEnd then
          helper (bPos + 1) 0 ((offset + uint64 (bPos - pEnd)) :: ret)
        else
          helper (bPos + 1) (pPos + 1) ret
      else
        helper (bPos + 1) 0 ret
    else ret
  helper 0 0 []

let tryFindIdx offset (pattern: byte []) (buf: byte []) =
  let bLen = Array.length buf
  let pEnd = Array.length pattern - 1
  let rec helper bPos pPos =
    if bPos < bLen then
      if buf.[bPos] = pattern.[pPos] then
        if pPos = pEnd then (uint64 (bPos - pEnd)) + offset |> Some
        else helper (bPos + 1) (pPos + 1)
      else helper (bPos + 1 - pPos) 0
    else None
  helper 0 0

let toUInt32Arr (src: byte []) =
  let srcLen = Array.length src
  let dstLen =
    if srcLen % 4 = 0 then srcLen/4
    else (srcLen / 4) + 1
  let dst = Array.init dstLen (fun _ -> 0u)
  Buffer.BlockCopy (src, 0, dst, 0, srcLen)
  dst

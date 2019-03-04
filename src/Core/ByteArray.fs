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

let makeDelta1 pattern patlen =
  let delta1 = Array.create 256 patlen
  let iter i x = if i < patlen - 1 then delta1.[int x] <- patlen - 1 - i
  Array.iteri iter pattern
  delta1

let rec isPrefix (pattern: byte []) patlen pos i ret =
  if (i < patlen - pos) || ret = false then
    if pattern.[i] <> pattern.[pos + i] then
      isPrefix pattern patlen pos 0 false
    else isPrefix pattern patlen pos (i + 1) ret
  else ret

let rec getSuffixLength (pattern: byte []) patlen pos i =
  if pattern.[pos - i] = pattern.[patlen - 1 - i] && i < pos then
    getSuffixLength pattern patlen pos (i + 1)
  else i

let rec makeDelta2Loop1 pattern patlen p lastPrefixIndex (delta2: int []) =
  if p >= 0 then
    if isPrefix pattern patlen (p + 1) 0 true then
      delta2.[p] <- patlen
      makeDelta2Loop1 pattern patlen (p - 1) (p + 1) delta2
    else
      delta2.[p] <- lastPrefixIndex + (patlen - 1 - p)
      makeDelta2Loop1 pattern patlen (p - 1) lastPrefixIndex delta2
  else delta2

let rec makeDelta2Loop2 pattern patlen p (delta2: int []) =
  if p < patlen - 1 then
    let sfxlen = getSuffixLength pattern patlen p 0
    if pattern.[p - sfxlen] <> pattern.[patlen - 1 - sfxlen] then
      delta2.[patlen - 1 - sfxlen] <- patlen - 1 - p + sfxlen
    makeDelta2Loop2 pattern patlen (p + 1) delta2
  else delta2

let makeDelta2 pattern patlen =
  Array.zeroCreate patlen
  |> makeDelta2Loop1 pattern patlen (patlen - 1) (patlen - 1)
  |> makeDelta2Loop2 pattern patlen 0

let rec getMatch (pattern: byte []) (buf: byte []) (i, j) =
  if j >= 0 && (buf.[i] = pattern.[j]) then getMatch pattern buf (i - 1, j - 1)
  else i, j

let bmSearch pattern buf =
  let buflen = Array.length buf
  let patlen = Array.length pattern
  let delta1 = makeDelta1 pattern patlen
  let delta2 = makeDelta2 pattern patlen
  let rec matchPattern i ret =
    if i < buflen then
      let i, j = getMatch pattern buf (i, patlen - 1)
      if j < 0 then matchPattern (i + patlen + 1) (uint64 (i + 1) :: ret)
      else matchPattern (i + (max delta1.[int buf.[i]] delta2.[j])) ret
    else ret
  matchPattern (patlen - 1) []

let findIdxs offset pattern buf =
  bmSearch pattern buf |> List.map (fun x -> x + offset)

let toUInt32Arr (src: byte []) =
  let srcLen = Array.length src
  let dstLen =
    if srcLen % 4 = 0 then srcLen/4
    else (srcLen / 4) + 1
  let dst = Array.init dstLen (fun _ -> 0u)
  Buffer.BlockCopy (src, 0, dst, 0, srcLen)
  dst

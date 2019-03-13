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

let isPrefix (pattern: byte []) patlen pos =
    let slen = patlen - pos
    let rec loop idx =
        if idx < slen && pattern.[idx] = pattern.[pos + idx] then loop (idx + 1)
        else idx
    loop 0 = slen

let getSuffixLength (pattern: byte []) patlen pos =
    let rec loop idx =
        if idx < pos && pattern.[pos - idx] = pattern.[patlen - 1 - idx] then
            loop (idx + 1)
        else idx
    loop 0

let makeDelta2 (pattern: byte []) patlen =
    let delta2 = Array.zeroCreate patlen
    let mutable idx = patlen - 1
    let mutable last = patlen - 1
    while idx >= 0 do
        if isPrefix pattern patlen (idx + 1) then last <- idx + 1
        delta2.[idx] <- last + patlen - 1 - idx
        idx <- idx - 1
    idx <- 0
    while idx < patlen - 1 do
        let slen = getSuffixLength pattern patlen idx
        if pattern.[idx - slen] <> pattern.[patlen - 1 - slen] then
            delta2.[patlen - 1 - slen] <- patlen - 1 - idx + slen
        idx <- idx + 1
    delta2

let rec getMatch (pattern: byte []) (buf: byte []) struct (i, j) =
    if j >= 0 && buf.[i] = pattern.[j] then
        getMatch pattern buf struct (i - 1, j - 1)
    else struct (i, j)

let bmSearch pattern buf =
    let buflen = Array.length buf
    let patlen = Array.length pattern
    let delta1 = makeDelta1 pattern patlen
    let delta2 = makeDelta2 pattern patlen
    let rec searchOne i =
        if i < buflen then
            let struct (i, j) = getMatch pattern buf struct (i, patlen - 1)
            if j < 0 then Some (i + 1)
            else searchOne (i + (max delta1.[int buf.[i]] delta2.[j]))
        else None
    let rec searchAll idx ret =
        match searchOne idx with
        | Some j -> searchAll (j + patlen) (j :: ret)
        | None -> ret
    searchAll (patlen - 1) []

let findIdxs offset pattern buf =
    bmSearch pattern buf |> List.map (fun x -> (uint64 x) + offset)

let tryFindIdx offset pattern buf =
    let buflen = Array.length buf
    let patlen = Array.length pattern
    let delta1 = makeDelta1 pattern patlen
    let delta2 = makeDelta2 pattern patlen
    let rec searchOne i =
        if i < buflen then
            let struct (i, j) = getMatch pattern buf struct (i, patlen - 1)
            if j < 0 then Some ((uint64 i) + offset)
            else searchOne (i + (max delta1.[int buf.[i]] delta2.[j]))
        else None
    searchOne (patlen - 1)

let toUInt32Arr (src: byte []) =
    let srcLen = Array.length src
    let dstLen =
        if srcLen % 4 = 0 then srcLen/4
        else (srcLen / 4) + 1
    let dst = Array.init dstLen (fun _ -> 0u)
    Buffer.BlockCopy (src, 0, dst, 0, srcLen)
    dst

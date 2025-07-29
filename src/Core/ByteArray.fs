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

namespace B2R2

open System
open System.Text
open System.Globalization
open System.Runtime.InteropServices

/// <summary>
/// Represents an array of bytes, often used to read raw binary data. This is
/// just an alias for <c>byte[]</c>, but we define it here to provide several
/// useful functions to deal with byte arrays in the <see
/// cref='T:B2R2.ByteArrayModule'/> module.
/// </summary>
type ByteArray = byte[]

/// <summary>
/// Provides several useful functions to deal with byte arrays (i.e., <see
/// cref='T:B2R2.ByteArray'/>).
/// </summary>
module ByteArray =

  /// Convert a hex string to a byte array.
  [<CompiledName "OfHexString">]
  let ofHexString (s: string) =
    Seq.windowed 2 s
    |> Seq.mapi (fun i j -> i, j)
    |> Seq.filter (fun (i, _) -> i % 2 = 0)
    |> Seq.map (fun (_, j) ->
      Byte.Parse(String(j), NumberStyles.AllowHexSpecifier))
    |> Array.ofSeq

  /// Read int32 from the given byte array at the given offset.
  [<CompiledName "ReadInt32">]
  let readInt32 (bs: ByteArray) offset =
    try
      let span = ReadOnlySpan(bs, offset, 4)
      MemoryMarshal.Read<int> span |> Ok
    with _ ->
      Error ErrorCase.InvalidMemoryRead

  let rec private extractCStringFromSpanAux span (acc: StringBuilder) offset =
    if offset >= (span: ReadOnlySpan<byte>).Length then acc.ToString()
    else
      match span[offset] with
      | 0uy -> acc.ToString()
      | b -> extractCStringFromSpanAux span (char b |> acc.Append) (offset + 1)

  /// Extract a C-string (string that ends with a NULL char) from a byte array.
  [<CompiledName "ExtractCString">]
  let extractCString (bytes: ByteArray) offset =
    if bytes.Length = 0 || bytes.Length <= offset then ""
    else extractCStringFromSpanAux (ReadOnlySpan bytes) (StringBuilder()) offset

  /// Extract a C-string (string that ends with a NULL char) from a byte array.
  [<CompiledName "ExtractCStringFromSpan">]
  let extractCStringFromSpan (span: ReadOnlySpan<byte>) offset =
    if span.Length = 0 || span.Length <= offset then ""
    else extractCStringFromSpanAux span (StringBuilder()) offset

  let private makeDelta1 pattern patlen =
    let delta1 = Array.create 256 patlen
    let iter i x = if i < patlen - 1 then delta1[int x] <- patlen - 1 - i
    Array.iteri iter pattern
    delta1

  let private isPrefix (pattern: ByteArray) patlen pos =
    let slen = patlen - pos
    let rec loop idx =
      if idx < slen && pattern[idx] = pattern[pos + idx] then loop (idx + 1)
      else idx
    loop 0 = slen

  let private getSuffixLength (pattern: ByteArray) patlen pos =
    let rec loop idx =
      if idx < pos && pattern[pos - idx] = pattern[patlen - 1 - idx] then
        loop (idx + 1)
      else idx
    loop 0

  let private makeDelta2 (pattern: ByteArray) patlen =
    let delta2 = Array.zeroCreate patlen
    let mutable idx = patlen - 1
    let mutable last = patlen - 1
    while idx >= 0 do
      if isPrefix pattern patlen (idx + 1) then last <- idx + 1
      delta2[idx] <- last + patlen - 1 - idx
      idx <- idx - 1
    idx <- 0
    while idx < patlen - 1 do
      let slen = getSuffixLength pattern patlen idx
      if pattern[idx - slen] <> pattern[patlen - 1 - slen] then
        delta2[patlen - 1 - slen] <- patlen - 1 - idx + slen
      idx <- idx + 1
    delta2

  let rec private getMatch (pattern: ByteArray) (buf: ByteArray) (i, j) =
    if j >= 0 && buf[i] = pattern[j] then
      getMatch pattern buf (i - 1, j - 1)
    else struct (i, j)

  let rec private searchOne i (buf: ByteArray) pattern (d1: int[]) (d2: int[]) =
    if i < buf.Length then
      let struct (i, j) = getMatch pattern buf (i, pattern.Length - 1)
      if j < 0 then Some(i + 1)
      else searchOne (i + max d1[int buf[i]] d2[j]) buf pattern d1 d2
    else None

  let private bmSearch pattern buf =
    let patlen = Array.length pattern
    let delta1 = makeDelta1 pattern patlen
    let delta2 = makeDelta2 pattern patlen
    let rec searchAll idx ret =
      match searchOne idx buf pattern delta1 delta2 with
      | Some j -> searchAll (j + patlen) (j :: ret)
      | None -> ret
    searchAll (patlen - 1) []


  /// Find and return the offsets of all the matching byte positions. The final
  /// byte positions are adjusted by the given offset.
  [<CompiledName "FindIdxs">]
  let findIdxs offset pattern buf =
    bmSearch pattern buf |> List.map (fun x -> (uint64 x) + offset)

  /// Find a matching byte position. If there is no match, this function will
  /// return None.
  [<CompiledName "TryFindIdx">]
  let tryFindIdx offset pattern buf =
    let patlen = Array.length pattern
    let delta1 = makeDelta1 pattern patlen
    let delta2 = makeDelta2 pattern patlen
    searchOne (patlen - 1) buf pattern delta1 delta2
    |> Option.map (fun idx -> uint64 idx + offset)

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

/// Provides functions for encoding/decoding LEB128 integers. LEB128 is a
/// variable-length encoding scheme that is designed to compactly represent
/// integers.
[<RequireQualifiedAccess>]
module B2R2.LEB128

open System

/// Raised when LEB128 decoding fails. This occurs when the continuation bit
/// (MSB) is still set on the last permitted byte, meaning the encoded value
/// exceeds the maximum byte length for the target type (5 bytes for 32-bit,
/// 10 bytes for 64-bit).
exception DecodeException

[<AutoOpen>]
module private LEB128Helper =
  let rec decodeLoop acc (bs: ReadOnlySpan<byte>) offset b len =
    let offset' = offset + 1
    let acc = b :: acc
    if b &&& 0x80uy <> 0uy && offset = len - 1 then raise DecodeException
    elif b &&& 0x80uy = 0uy then List.rev acc, offset'
    else decodeLoop acc bs offset' bs[offset'] len

  let inline decode (bs: ReadOnlySpan<byte>) ([<InlineIfLambda>] cast) maxLen =
    let rec convLoop v offset = function
      | [] -> v
      | b :: rest ->
        let v' = v ||| (cast (b &&& 0x7fuy) <<< (offset * 7))
        convLoop v' (offset + 1) rest
    if bs.Length = 0 then invalidArg (nameof bs) "Invalid buffer length"
    else
      let len = if bs.Length > maxLen then maxLen else bs.Length
      let bs, offset = decodeLoop [] bs 0 bs[0] len
      convLoop (cast 0uy) 0 bs, offset

  let inline extendSign b offset currentValue bitmask maxLen =
    if b &&& 0x40uy <> 0uy then
      let shiftOffset = if offset < (maxLen - 1) then offset + 1 else offset
      bitmask <<< (7 * (shiftOffset)) ||| currentValue
    else
      currentValue

let [<Literal>] private Max32 = 5
let [<Literal>] private Max64 = 10

/// Decodes a LEB128-encoded unsigned integer into uint64. Returns a tuple of
/// (the decoded value, the number of bytes consumed).
[<CompiledName "DecodeUInt64">]
let decodeUInt64 span = decode span uint64 Max64

/// Decodes a LEB128-encoded unsigned integer into uint64 from a byte array.
/// Returns a tuple of (the decoded value, the number of bytes consumed).
[<CompiledName "DecodeUInt64Bytes">]
let decodeUInt64Bytes (bytes: byte[]) =
  decodeUInt64 (ReadOnlySpan<byte> bytes)

/// Decodes a LEB128-encoded unsigned integer into uint32. Returns a tuple of
/// (the decoded value, the number of bytes consumed).
[<CompiledName "DecodeUInt32">]
let decodeUInt32 span = decode span uint32 Max32

/// Decodes a LEB128-encoded unsigned integer into uint32 from a byte array.
/// Returns a tuple of (the decoded value, the number of bytes consumed).
[<CompiledName "DecodeUInt32Bytes">]
let decodeUInt32Bytes (bytes: byte[]) =
  decodeUInt32 (ReadOnlySpan<byte> bytes)

/// Decodes a LEB128-encoded signed integer into int64. Returns a tuple of
/// (the decoded value, the number of bytes consumed).
[<CompiledName "DecodeSInt64">]
let decodeSInt64 (span: ReadOnlySpan<byte>) =
  let v, len = decode span int64 Max64
  extendSign span[len - 1] (len - 1) v 0xFFFFFFFFFFFFFFFFL Max64, len

/// Decodes a LEB128-encoded signed integer into int64 from a byte array.
/// Returns a tuple of (the decoded value, the number of bytes consumed).
[<CompiledName "DecodeSInt64Bytes">]
let decodeSInt64Bytes (bytes: byte[]) =
  decodeSInt64 (ReadOnlySpan<byte> bytes)

/// Decodes a LEB128-encoded signed integer into int32. Returns a tuple of
/// (the decoded value, the number of bytes consumed).
[<CompiledName "DecodeSInt32">]
let decodeSInt32 (span: ReadOnlySpan<byte>) =
  let v, len = decode span int32 Max32
  extendSign span[len - 1] (len - 1) v 0xFFFFFFFF Max32, len

/// Decodes a LEB128-encoded signed integer into int32 from a byte array.
/// Returns a tuple of (the decoded value, the number of bytes consumed).
[<CompiledName "DecodeSInt32Bytes">]
let decodeSInt32Bytes (bytes: byte[]) =
  decodeSInt32 (ReadOnlySpan<byte> bytes)

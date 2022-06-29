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

/// Raised when LEB128 decoding failed, e.g., when the given input bytes has
/// incorrect encoding.
exception LEB128DecodeException

module private LEB128Helper =
  let rec decodeLoop acc (bs: ReadOnlySpan<byte>) offset b len =
    let offset' = offset + 1
    let acc = b :: acc
    if b &&& 0x80uy <> 0uy && offset = len - 1 then raise LEB128DecodeException
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

open LEB128Helper

type LEB128 =
  static member Max32 = 5
  static member Max64 = 10

  /// Decode a LEB128-encoded integer into uint64. This function returns a tuple
  /// of (the decoded uint64, and the count of how many bytes were read).
  static member DecodeUInt64 span =
    decode span uint64 LEB128.Max64

  /// Decode a LEB128-encoded integer into uint64. This function returns a tuple
  /// of (the decoded uint64, and the count of how many bytes were read).
  static member DecodeUInt64 (bytes: byte []) =
    LEB128.DecodeUInt64 (ReadOnlySpan<byte> bytes)

  /// Decode a LEB128-encoded integer into uint32. This function returns a tuple
  /// of (the decoded uint32, and the count of how many bytes were read).
  static member DecodeUInt32 span =
    decode span uint32 LEB128.Max32

  /// Decode a LEB128-encoded integer into uint32. This function returns a tuple
  /// of (the decoded uint32, and the count of how many bytes were read).
  static member DecodeUInt32 bytes =
    LEB128.DecodeUInt32 (ReadOnlySpan<byte> bytes)

  /// Decode a LEB128-encoded integer into int64. This function returns a tuple
  /// of (the decoded int64, and the count of how many bytes were read).
  static member DecodeSInt64 span =
    let v, len = decode span int64 LEB128.Max64
    let offset = len - 1
    extendSign span[offset] offset v 0xFFFFFFFFFFFFFFFFL LEB128.Max64, len

  /// Decode a LEB128-encoded integer into int64. This function returns a tuple
  /// of (the decoded int64, and the count of how many bytes were read).
  static member DecodeSInt64 bytes =
    LEB128.DecodeSInt64 (ReadOnlySpan<byte> bytes)

  /// Decode a LEB128-encoded integer into int32. This function returns a tuple
  /// of (the decoded int32, and the count of how many bytes were read).
  static member DecodeSInt32 span =
    let v, len = decode span int32 LEB128.Max32
    let offset = len - 1
    extendSign span[offset] offset v 0xFFFFFFFF LEB128.Max32, len

  /// Decode a LEB128-encoded integer into int32. This function returns a tuple
  /// of (the decoded int32, and the count of how many bytes were read).
  static member DecodeSInt32 bytes =
    LEB128.DecodeSInt32 (ReadOnlySpan<byte> bytes)

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

[<RequireQualifiedAccess>]
module B2R2.LEB128

/// Raised when LEB128 decoding failed, e.g., when the given input bytes has
/// incorrect encoding.
exception LEB128DecodeException

let [<Literal>] max32LEB128Length = 5
let [<Literal>] max64LEB128Length = 10

let inline private decodeLEB128 (bytes: byte []) cast maxLen =
  let rec decodeLoop offset value b len =
    let value' = value ||| (cast (b &&& 0x7fuy) <<< (offset * 7))
    let offset' = offset + 1
    if b &&& 0x80uy <> 0uy && offset = len - 1 then raise LEB128DecodeException
    elif b &&& 0x80uy = 0uy then value', offset'
    else decodeLoop offset' value' bytes.[offset'] len
  if bytes.Length = 0 then invalidArg "decodeLEB128" "Invalid buffer length"
  else
    let len = if bytes.Length > maxLen then maxLen else bytes.Length
    decodeLoop 0 (cast 0uy) bytes.[0] len

let inline private extendSign b offset currentValue bitmask maxLen =
  if b &&& 0x40uy <> 0uy then
    let shiftOffset = if offset < (maxLen - 1) then offset + 1 else offset
    bitmask <<< (7 * (shiftOffset)) ||| currentValue
  else
    currentValue

/// Decode a LEB128-encoded integer into uint64. This function returns a tuple
/// of (the decoded uint64, and the count of how many bytes were read).
[<CompiledName("DecodeUInt64")>]
let decodeUInt64 bytes =
  decodeLEB128 bytes uint64 max64LEB128Length

/// Decode a LEB128-encoded integer into uint32. This function returns a tuple
/// of (the decoded uint32, and the count of how many bytes were read).
[<CompiledName("DecodeUInt32")>]
let decodeUInt32 bytes =
  decodeLEB128 bytes uint32 max32LEB128Length

/// Decode a LEB128-encoded integer into int64. This function returns a tuple of
/// (the decoded int64, and the count of how many bytes were read).
[<CompiledName("DecodeSInt64")>]
let decodeSInt64 bytes =
  let v, len = decodeLEB128 bytes int64 max64LEB128Length
  let offset = len - 1
  extendSign bytes.[offset] offset v 0xFFFFFFFFFFFFFFFFL max64LEB128Length, len

/// Decode a LEB128-encoded integer into int32. This function returns a tuple of
/// (the decoded int32, and the count of how many bytes were read).
[<CompiledName("DecodeSInt32")>]
let decodeSInt32 bytes =
  let v, len = decodeLEB128 bytes int32 max32LEB128Length
  let offset = len - 1
  extendSign bytes.[offset] offset v 0xFFFFFFFF max32LEB128Length, len

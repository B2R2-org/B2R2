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

/// Provides the writing counterpart of the reads in FileHelper, so that a
/// field goes back on disk exactly where and how it was read from.
module internal B2R2.FrontEnd.BinFile.ByteWriter

open System
open System.Buffers.Binary
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

/// Writes a byte at the given offset of the given byte span.
let writeUInt8 (span: Span<byte>) offset (v: byte) = span[offset] <- v

/// Writes a 16-bit value at the given offset of the given byte span.
let writeUInt16 (span: Span<byte>) endian offset (v: uint16) =
  let dst = span.Slice(offset, 2)
  if endian = Endian.Little then
    BinaryPrimitives.WriteUInt16LittleEndian(dst, v)
  else
    BinaryPrimitives.WriteUInt16BigEndian(dst, v)

/// Writes a signed 16-bit value at the given offset of the given byte span.
let writeInt16 (span: Span<byte>) endian offset (v: int16) =
  writeUInt16 span endian offset (uint16 v)

/// Writes a 32-bit value at the given offset of the given byte span.
let writeUInt32 (span: Span<byte>) endian offset (v: uint32) =
  let dst = span.Slice(offset, 4)
  if endian = Endian.Little then
    BinaryPrimitives.WriteUInt32LittleEndian(dst, v)
  else
    BinaryPrimitives.WriteUInt32BigEndian(dst, v)

/// Writes a 64-bit value at the given offset of the given byte span.
let writeUInt64 (span: Span<byte>) endian offset (v: uint64) =
  let dst = span.Slice(offset, 8)
  if endian = Endian.Little then
    BinaryPrimitives.WriteUInt64LittleEndian(dst, v)
  else
    BinaryPrimitives.WriteUInt64BigEndian(dst, v)

/// Writes either the lower 32 bits or all 64 bits of the given value at the
/// given offset, whichever the word size calls for. This is the inverse of
/// readUIntByWordSize, and it truncates where that zero-extended.
let writeUIntByWordSize span endian wordSize offset (v: uint64) =
  if wordSize = WordSize.Bit32 then writeUInt32 span endian offset (uint32 v)
  else writeUInt64 span endian offset v

/// Writes either the lower 32 bits or all 64 bits of the given value, at the
/// first offset for a 32-bit word and at the second for a 64-bit one.
let writeUIntByWordSizeAndOffset span endian wordSize offset32 offset64 v =
  writeUIntByWordSize span
    endian
    wordSize
    (selectByWordSize wordSize offset32 offset64)
    v

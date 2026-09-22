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

module internal B2R2.FrontEnd.BinFile.FileHelper

open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinLifter
open System

/// Selects a number based on the word size.
let inline selectByWordSize wordSize v32 v64 =
  if wordSize = WordSize.Bit32 then v32 else v64

let private isWhitespaceByte b =
  b = 0x20uy || (b >= 0x09uy && b <= 0x0Duy)

/// Returns the range of the given bytes that holds the hex digits, i.e., the
/// bytes past the optional "0x" prefix and before the trailing whitespaces. The
/// end offset is exclusive.
let private getHexRange (bytes: byte[]) =
  let isPrefixed = bytes.Length >= 2 && bytes[0] = '0'B && bytes[1] = 'x'B
  let s = if isPrefixed then 2 else 0
  let mutable e = bytes.Length
  while e > s && isWhitespaceByte bytes[e - 1] do e <- e - 1
  struct (s, e)

let private toHexString (bytes: byte[]) s e =
  Text.Encoding.ASCII.GetString(bytes, s, e - s)

let private isHexByte b =
  (b >= '0'B && b <= '9'B)
  || (b >= 'A'B && b <= 'F'B)
  || (b >= 'a'B && b <= 'f'B)

/// Checks whether the given range of the given bytes is an even-length run of
/// hex digits. This works on the raw bytes so that a binary that is not a hex
/// dump is rejected at its first non-hex byte, without decoding the whole file.
let private isHexBytes (bytes: byte[]) s e =
  let length = e - s
  if length <= 0 || length % 2 <> 0 then
    false
  else
    let mutable i = s
    while i < e && isHexByte bytes[i] do i <- i + 1
    i = e

/// Converts a byte array containing an ASCII hex string into raw bytes.
let parseHexBytes bytes =
  let struct (s, e) = getHexRange bytes
  toHexString bytes s e |> ByteArray.ofHexString

/// Tries to parse a byte array containing an ASCII hex string into raw bytes.
let tryParseHexBytes bytes =
  let struct (s, e) = getHexRange bytes
  if isHexBytes bytes s e then
    toHexString bytes s e |> ByteArray.ofHexString |> Some
  else
    None

/// Reads either 32-bit or 64-bit value based on the word size from the given
/// offset of the given byte span. This function always returns a 64-bit value.
let readUIntByWordSize (span: ByteSpan) (reader: IBinReader) wordSize offset =
  if wordSize = WordSize.Bit32 then reader.ReadUInt32(span, offset) |> uint64
  else reader.ReadUInt64(span, offset)

/// Reads either 32-bit or 64-bit value based on the word size from either of
/// the given offset of the given byte span. This function always returns a
/// 64-bit value. The first offset is used for 32-bit and the second offset is
/// used for 64-bit.
let readUIntByWordSizeAndOffset span reader wordSize offset32 offset64 =
  readUIntByWordSize span
    reader
    wordSize
    (selectByWordSize wordSize offset32 offset64)

/// Reads a C string from the given byte span starting at the given offset, and
/// returns the string along with the offset right past its NUL terminator.
/// Raises IndexOutOfRangeException when the offset is outside the span or when
/// no terminator follows it, which is how the byte-by-byte read fails.
let readCStringWithNextOffset (span: ByteSpan) offset =
  if offset < 0 || offset >= span.Length then
    raise (IndexOutOfRangeException())
  else
    let tail = span.Slice offset
    let length = tail.IndexOf 0uy
    if length < 0 then
      raise (IndexOutOfRangeException())
    else
      let str = Text.Encoding.Latin1.GetString(tail.Slice(0, length))
      struct (str, offset + length + 1)

/// Reads a C string from the given byte span starting at the given offset.
let readCString (span: ByteSpan) offset =
  let struct (str, _) = readCStringWithNextOffset span offset
  str

/// Reads a C string from a fixed-width field of the given size, stopping at the
/// NUL terminator or at the field boundary. Mach-O name fields (sectname,
/// segname) fill the entire field without a terminator when the name is exactly
/// as wide as the field, so an unbounded read would spill into the next field.
let readCStringOfSize (span: ByteSpan) offset size =
  ByteArray.extractCStringFromSpan (span.Slice(offset, size)) 0

/// Reads LEB128 unsigned integer from the given byte span starting at the
/// given offset.
let readULEB128 (span: ByteSpan) offset =
  let v, cnt = LEB128.decodeUInt64 (span.Slice offset)
  v, offset + cnt

/// Reads LEB128 signed integer from the given byte span starting at the given
/// offset.
let readSLEB128 (span: ByteSpan) offset =
  let v, cnt = LEB128.decodeSInt64 (span.Slice offset)
  v, offset + cnt

/// Returns how many entries of a table of the given shape the file holds. A
/// header can count more entries than its file has room for, whether because
/// the file was truncated or because the count means something other than
/// itself; none of such a table can be trusted, so it is counted as empty
/// rather than read in part.
let countTableEntries (bytes: byte[]) (offset: uint64) entrySize count =
  let room = int64 bytes.Length - int64 offset
  if room >= int64 entrySize * int64 count then count else 0

/// Slices the given byte array into a read-only span of the specified length
/// starting at the given (already address-translated) file offset. Raises
/// InvalidAddrReadException when the requested region falls outside the array,
/// so that out-of-range reads surface a single, predictable exception.
let sliceBySafeOffset (bytes: byte[]) (offset: uint64) len =
  let bytesLen = uint64 bytes.Length
  if len >= 0 && offset <= bytesLen && uint64 len <= bytesLen - offset then ()
  else raise InvalidAddrReadException
  System.ReadOnlySpan(bytes, int offset, len)

/// Slices the given byte array using the given bounded pointer, reading len
/// bytes from the pointer's file offset. Raises InvalidAddrReadException when
/// the pointer is not file-backed (null or virtual) or when len exceeds the
/// readable extent of the pointed region.
let sliceByPointer (bytes: byte[]) (ptr: BinFilePointer) len =
  if len >= 0 && ptr.CanReadFileBytes && len <= ptr.ReadableAmount then ()
  else raise InvalidAddrReadException
  sliceBySafeOffset bytes (uint64 ptr.Offset) len

let addInvalidRange set saddr eaddr =
  if saddr = eaddr then set
  else IntervalSet.add (AddrRange.create saddr (eaddr - 1UL)) set

let addLastInvalidRange wordSize (set, saddr) =
  let laddr =
    if wordSize = WordSize.Bit32 then 0xFFFFFFFFUL else 0xFFFFFFFFFFFFFFFFUL
  IntervalSet.add (AddrRange.create saddr laddr) set

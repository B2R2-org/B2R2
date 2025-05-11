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

/// Selects a number based on the word size.
let inline selectByWordSize wordSize v32 v64 =
  if wordSize = WordSize.Bit32 then v32 else v64

/// Reads either 32-bit or 64-bit value based on the word size from the given
/// offset of the given byte span. This function always returns a 64-bit value.
let readUIntByWordSize (span: ByteSpan) (reader: IBinReader) wordSize offset =
  if wordSize = WordSize.Bit32 then reader.ReadUInt32 (span, offset) |> uint64
  else reader.ReadUInt64 (span, offset)

/// Reads either 32-bit or 64-bit value based on the word size from either of
/// the given offset of the given byte span. This function always returns a
/// 64-bit value. The first offset is used for 32-bit and the second offset is
/// used for 64-bit.
let readUIntByWordSizeAndOffset span reader wordSize offset32 offset64 =
  readUIntByWordSize span reader wordSize
    (selectByWordSize wordSize offset32 offset64)

let rec private cstrLoop (span: ByteSpan) acc pos =
  let byte = span[pos]
  if byte = 0uy then List.rev (0uy :: acc) |> List.toArray
  else cstrLoop span (byte :: acc) (pos + 1)

/// Reads a C string from the given byte span starting at the given offset.
let readCString (span: ByteSpan) offset =
  let bs = cstrLoop span [] offset
  ByteArray.extractCString bs 0

let addInvalidRange set saddr eaddr =
  if saddr = eaddr then set
  else IntervalSet.add (AddrRange (saddr, eaddr - 1UL)) set

let addLastInvalidRange wordSize (set, saddr) =
  let laddr =
    if wordSize = WordSize.Bit32 then 0xFFFFFFFFUL else 0xFFFFFFFFFFFFFFFFUL
  IntervalSet.add (AddrRange (saddr, laddr)) set

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

namespace B2R2.FrontEnd.BinFile.Mach

open B2R2.FrontEnd.BinLifter

/// Magic number for Mach-O header.
type Magic =
  /// The file is intended for use on a CPU with the same endianness as the
  /// computer on which the compiler is running (32-bit CPU).
  | MH_MAGIC = 0xFEEDFACEu
  /// The byte ordering scheme of the target machine is the reverse of the host
  /// CPU (32-bit CPU).
  | MH_CIGAM = 0xCEFAEDFEu
  /// The file is intended for use on a CPU with the same endianness as the
  /// computer on which the compiler is running (64-bit CPU).
  | MH_MAGIC_64 = 0xFEEDFACFu
  /// The byte ordering scheme of the target machine is the reverse of the host
  /// CPU (64-bit CPU).
  | MH_CIGAM_64 = 0xCFFAEDFEu
  /// The file is intended for use on multiple architectures (FAT binary). This
  /// value is used on a big-endian host.
  | FAT_MAGIC = 0xCAFEBABEu
  /// The file is intended for use on multiple architectures (FAT binary). This
  /// value is used on a little-endian host.
  | FAT_CIGAM = 0xBEBAFECAu

module internal Magic =
  let read (span: ByteSpan) (reader: IBinReader) =
    if span.Length >= 4 then reader.ReadUInt32 (span, 0) else 0ul
    |> LanguagePrimitives.EnumOfValue: Magic

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

namespace B2R2.FrontEnd.BinFile.ELF

open B2R2
open B2R2.FrontEnd.BinFile

/// Represents the format of a value in the DWARF exception header encoded as
/// the lower 4 bits of a byte.
type ExceptionHeaderValue =
  /// No value is present.
  | DW_EH_PE_omit = 0xff
  /// A literal pointer whose size is determined by the architecture.
  | DW_EH_PE_absptr = 0x00
  /// Unsigned value is encoded using the LEB128.
  | DW_EH_PE_uleb128 = 0x01
  /// A 2-byte unsigned value.
  | DW_EH_PE_udata2 = 0x02
  /// A 4-byte unsigned value.
  | DW_EH_PE_udata4 = 0x03
  /// A 8-byte unsigned value.
  | DW_EH_PE_udata8 = 0x04
  /// A signed value whose size is determined by the architecture.
  | DW_EH_PE_signed = 0x08
  /// Signed value is encoded using the LEB128.
  | DW_EH_PE_sleb128 = 0x09
  /// A 2-byte signed value.
  | DW_EH_PE_sdata2 = 0x0a
  /// A 4-byte signed value.
  | DW_EH_PE_sdata4 = 0x0b
  /// A 8-byte signed value.
  | DW_EH_PE_sdata8 = 0x0c

[<RequireQualifiedAccess>]
module internal ExceptionHeaderValue =
  /// Reads an encoded value.
  let read cls span reader venc offset =
    match venc with
    | ExceptionHeaderValue.DW_EH_PE_absptr ->
      let cv = FileHelper.readUIntByWordSize span reader cls offset
      struct (cv, if cls = WordSize.Bit32 then offset + 4 else offset + 8)
    | ExceptionHeaderValue.DW_EH_PE_uleb128 ->
      let v, cnt = LEB128.DecodeUInt64 (span.Slice offset)
      struct (v, offset + cnt)
    | ExceptionHeaderValue.DW_EH_PE_sleb128 ->
      let v, cnt = LEB128.DecodeSInt64 (span.Slice offset)
      struct (uint64 v, offset + cnt)
    | ExceptionHeaderValue.DW_EH_PE_udata2 ->
      let cv = reader.ReadUInt16 (span, offset)
      struct (uint64 cv, offset + 2)
    | ExceptionHeaderValue.DW_EH_PE_sdata2 ->
      let cv = reader.ReadInt16 (span, offset)
      struct (uint64 cv, offset + 2)
    | ExceptionHeaderValue.DW_EH_PE_udata4 ->
      let cv = reader.ReadUInt32 (span, offset)
      struct (uint64 cv, offset + 4)
    | ExceptionHeaderValue.DW_EH_PE_sdata4 ->
      let cv = reader.ReadInt32 (span, offset)
      struct (uint64 cv, offset + 4)
    | ExceptionHeaderValue.DW_EH_PE_udata8 ->
      let cv = reader.ReadUInt64 (span, offset)
      struct (cv, offset + 8)
    | ExceptionHeaderValue.DW_EH_PE_sdata8 ->
      let cv = reader.ReadInt64 (span, offset)
      struct (uint64 cv, offset + 8)
    | _ -> printfn "%A" venc; Terminator.futureFeature ()

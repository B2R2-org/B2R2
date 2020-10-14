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

open LanguagePrimitives
open B2R2
open B2R2.FrontEnd.BinFile

/// Raised when an unhandled encoding is encountered.
exception UnhandledEncoding

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
  /// Signed value is encoded using the LEB128.
  | DW_EH_PE_sleb128 = 0x09
  /// A 2-byte signed value.
  | DW_EH_PE_sdata2 = 0x0a
  /// A 4-byte signed value.
  | DW_EH_PE_sdata4 = 0x0b
  /// A 8-byte signed value.
  | DW_EH_PE_sdata8 = 0x0c

type ExceptionHeaderApplication =
  /// Value is used with no modification.
  | DW_EH_PE_absptr = 0x00
  /// Value is relative to the current program counter.
  | DW_EH_PE_pcrel = 0x10
  /// Value is relative to the beginning of the .eh_frame_hdr section.
  | DW_EH_PE_datarel = 0x30
  /// No value is present.
  | DW_EH_PE_omit = 0xff

module ExceptionHeaderEncoding =
  let parseULEB128 (reader: BinReader) offset =
    let span = reader.PeekSpan (offset)
    let v, cnt = LEB128.DecodeUInt64 span
    v, offset + cnt

  let parseSLEB128 (reader: BinReader) offset =
    let span = reader.PeekSpan (offset)
    let v, cnt = LEB128.DecodeSInt64 span
    v, offset + cnt

  let computeValue cls (reader: BinReader) venc offset =
    match venc with
    | ExceptionHeaderValue.DW_EH_PE_absptr ->
      FileHelper.readUIntOfType reader cls offset
    | ExceptionHeaderValue.DW_EH_PE_uleb128 ->
      let cv, offset = parseULEB128 reader offset
      struct (cv, offset)
    | ExceptionHeaderValue.DW_EH_PE_sleb128 ->
      let cv, offset = parseSLEB128 reader offset
      struct (uint64 cv, offset)
    | ExceptionHeaderValue.DW_EH_PE_udata2 ->
      let struct (cv, offset) = reader.ReadUInt16 offset
      struct (uint64 cv, offset)
    | ExceptionHeaderValue.DW_EH_PE_sdata2 ->
      let struct (cv, offset) = reader.ReadInt16 offset
      struct (uint64 cv, offset)
    | ExceptionHeaderValue.DW_EH_PE_udata4 ->
      let struct (cv, offset) = reader.ReadUInt32 offset
      struct (uint64 cv, offset)
    | ExceptionHeaderValue.DW_EH_PE_sdata4 ->
      let struct (cv, offset) = reader.ReadInt32 offset
      struct (uint64 cv, offset)
    | ExceptionHeaderValue.DW_EH_PE_udata8 ->
      reader.ReadUInt64 offset
    | ExceptionHeaderValue.DW_EH_PE_sdata8 ->
      let struct (cv, offset) = reader.ReadInt64 offset
      struct (uint64 cv, offset)
    | _ -> raise UnhandledEncoding

  let parseEncoding b =
    if b &&& 0xFFuy = 255uy then
      let v = EnumOfValue<int, ExceptionHeaderValue> 0xff
      let app = EnumOfValue<int, ExceptionHeaderApplication> 0xff
      v, app
    else
      let v = int (b &&& 0x0Fuy)
              |> EnumOfValue<int, ExceptionHeaderValue>
      let app = int (b &&& 0xF0uy)
                |> EnumOfValue<int, ExceptionHeaderApplication>
      v, app
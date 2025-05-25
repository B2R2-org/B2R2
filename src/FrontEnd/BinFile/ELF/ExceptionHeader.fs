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

/// Represents the application type of the value in the DWARF exception header
/// encoded as the upper 4 bits of a byte.
type ExceptionHeaderApplication =
  /// Value is relative to the current program counter.
  | DW_EH_PE_pcrel = 0x10
  /// Value is relative to the beginning of the .text section.
  | DW_EH_PE_textrel = 0x20
  /// Value is relative to the beginning of the .eh_frame_hdr section.
  | DW_EH_PE_datarel = 0x30
  /// Value is relative to the beginning of the function.
  | DW_EH_PE_funcrel = 0x40
  /// No value is present.
  | DW_EH_PE_omit = 0xff

[<RequireQualifiedAccess>]
module internal ExceptionHeader =
  open LanguagePrimitives

  /// Parses the encoding byte from the DWARF exception header.
  let parseEncoding b =
    if b = 0xFFuy then
      let v = ExceptionHeaderValue.DW_EH_PE_omit
      let app = ExceptionHeaderApplication.DW_EH_PE_omit
      struct (v, app)
    else
      let v = int (b &&& 0x0Fuy)
              |> EnumOfValue<int, ExceptionHeaderValue>
      let app = int (b &&& 0xF0uy)
                |> EnumOfValue<int, ExceptionHeaderApplication>
      struct (v, app)

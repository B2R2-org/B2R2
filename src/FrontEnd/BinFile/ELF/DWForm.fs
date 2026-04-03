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

/// Represents the form of a DWARF attribute value.
type DWForm =
  | DW_FORM_addr = 0x01us
  | DW_FORM_block2 = 0x03us
  | DW_FORM_block4 = 0x04us
  | DW_FORM_data2 = 0x05us
  | DW_FORM_data4 = 0x06us
  | DW_FORM_data8 = 0x07us
  | DW_FORM_string = 0x08us
  | DW_FORM_block = 0x09us
  | DW_FORM_block1 = 0x0aus
  | DW_FORM_data1 = 0x0bus
  | DW_FORM_flag = 0x0cus
  | DW_FORM_sdata = 0x0dus
  | DW_FORM_strp = 0x0eus
  | DW_FORM_udata = 0x0fus
  | DW_FORM_ref_addr = 0x10us
  | DW_FORM_ref1 = 0x11us
  | DW_FORM_ref2 = 0x12us
  | DW_FORM_ref4 = 0x13us
  | DW_FORM_ref8 = 0x14us
  | DW_FORM_ref_udata = 0x15us
  | DW_FORM_indirect = 0x16us
  | DW_FORM_sec_offset = 0x17us
  | DW_FORM_exprloc = 0x18us
  | DW_FORM_flag_present = 0x19us
  | DW_FORM_ref_sig8 = 0x20us
  | DW_FORM_strx = 0x1aus
  | DW_FORM_addrx = 0x1bus
  | DW_FORM_ref_sup4 = 0x1cus
  | DW_FORM_strp_sup = 0x1dus
  | DW_FORM_data16 = 0x1eus
  | DW_FORM_line_strp = 0x1fus
  | DW_FORM_implicit_const = 0x21us
  | DW_FORM_loclistx = 0x22us
  | DW_FORM_rnglistx = 0x23us
  | DW_FORM_ref_sup8 = 0x24us
  | DW_FORM_strx1 = 0x25us
  | DW_FORM_strx2 = 0x26us
  | DW_FORM_strx3 = 0x27us
  | DW_FORM_strx4 = 0x28us
  | DW_FORM_addrx1 = 0x29us
  | DW_FORM_addrx2 = 0x2aus
  | DW_FORM_addrx3 = 0x2bus
  | DW_FORM_addrx4 = 0x2cus
  | DW_FORM_GNU_addr_index = 0x1f01us
  | DW_FORM_GNU_str_index = 0x1f02us
  | DW_FORM_GNU_ref_alt = 0x1f20us
  | DW_FORM_GNU_strp_alt = 0x1f21us

[<RequireQualifiedAccess>]
module internal DWForm =
  open LanguagePrimitives

  let parse (v: uint16) = EnumOfValue<uint16, DWForm> v

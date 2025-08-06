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

/// Represents DWARF operation expressions.
type DWOperation =
  | DW_OP_lit0 = 0x30uy
  | DW_OP_lit1 = 0x31uy
  | DW_OP_lit2 = 0x32uy
  | DW_OP_lit3 = 0x33uy
  | DW_OP_lit4 = 0x34uy
  | DW_OP_lit5 = 0x35uy
  | DW_OP_lit6 = 0x36uy
  | DW_OP_lit7 = 0x37uy
  | DW_OP_lit8 = 0x38uy
  | DW_OP_lit9 = 0x39uy
  | DW_OP_lit10 = 0x3auy
  | DW_OP_lit11 = 0x3buy
  | DW_OP_lit12 = 0x3cuy
  | DW_OP_lit13 = 0x3duy
  | DW_OP_lit14 = 0x3euy
  | DW_OP_lit15 = 0x3fuy
  | DW_OP_lit16 = 0x40uy
  | DW_OP_lit17 = 0x41uy
  | DW_OP_lit18 = 0x42uy
  | DW_OP_lit19 = 0x43uy
  | DW_OP_lit20 = 0x44uy
  | DW_OP_lit21 = 0x45uy
  | DW_OP_lit22 = 0x46uy
  | DW_OP_lit23 = 0x47uy
  | DW_OP_lit24 = 0x48uy
  | DW_OP_lit25 = 0x49uy
  | DW_OP_lit26 = 0x4auy
  | DW_OP_lit27 = 0x4buy
  | DW_OP_lit28 = 0x4cuy
  | DW_OP_lit29 = 0x4duy
  | DW_OP_lit30 = 0x4euy
  | DW_OP_lit31 = 0x4fuy
  | DW_OP_addr = 0x03uy
  | DW_OP_const1u = 0x08uy
  | DW_OP_const1s = 0x09uy
  | DW_OP_const2u = 0x0auy
  | DW_OP_const2s = 0x0buy
  | DW_OP_const4u = 0x0cuy
  | DW_OP_const4s = 0x0duy
  | DW_OP_const8u = 0x0euy
  | DW_OP_const8s = 0x0fuy
  | DW_OP_constu = 0x10uy
  | DW_OP_consts = 0x11uy
  | DW_OP_fbreg = 0x91uy
  | DW_OP_reg0 = 0x50uy
  | DW_OP_reg1 = 0x51uy
  | DW_OP_reg2 = 0x52uy
  | DW_OP_reg3 = 0x53uy
  | DW_OP_reg4 = 0x54uy
  | DW_OP_reg5 = 0x55uy
  | DW_OP_reg6 = 0x56uy
  | DW_OP_reg7 = 0x57uy
  | DW_OP_reg8 = 0x58uy
  | DW_OP_reg9 = 0x59uy
  | DW_OP_reg10 = 0x5auy
  | DW_OP_reg11 = 0x5buy
  | DW_OP_reg12 = 0x5cuy
  | DW_OP_reg13 = 0x5duy
  | DW_OP_reg14 = 0x5euy
  | DW_OP_reg15 = 0x5fuy
  | DW_OP_reg16 = 0x60uy
  | DW_OP_reg17 = 0x61uy
  | DW_OP_reg18 = 0x62uy
  | DW_OP_reg19 = 0x63uy
  | DW_OP_reg20 = 0x64uy
  | DW_OP_reg21 = 0x65uy
  | DW_OP_reg22 = 0x66uy
  | DW_OP_reg23 = 0x67uy
  | DW_OP_reg24 = 0x68uy
  | DW_OP_reg25 = 0x69uy
  | DW_OP_reg26 = 0x6auy
  | DW_OP_reg27 = 0x6buy
  | DW_OP_reg28 = 0x6cuy
  | DW_OP_reg29 = 0x6duy
  | DW_OP_reg30 = 0x6euy
  | DW_OP_reg31 = 0x6fuy
  | DW_OP_regx = 0x90uy
  | DW_OP_breg0 = 0x70uy
  | DW_OP_breg1 = 0x71uy
  | DW_OP_breg2 = 0x72uy
  | DW_OP_breg3 = 0x73uy
  | DW_OP_breg4 = 0x74uy
  | DW_OP_breg5 = 0x75uy
  | DW_OP_breg6 = 0x76uy
  | DW_OP_breg7 = 0x77uy
  | DW_OP_breg8 = 0x78uy
  | DW_OP_breg9 = 0x79uy
  | DW_OP_breg10 = 0x7auy
  | DW_OP_breg11 = 0x7buy
  | DW_OP_breg12 = 0x7cuy
  | DW_OP_breg13 = 0x7duy
  | DW_OP_breg14 = 0x7euy
  | DW_OP_breg15 = 0x7fuy
  | DW_OP_breg16 = 0x80uy
  | DW_OP_breg17 = 0x81uy
  | DW_OP_breg18 = 0x82uy
  | DW_OP_breg19 = 0x83uy
  | DW_OP_breg20 = 0x84uy
  | DW_OP_breg21 = 0x85uy
  | DW_OP_breg22 = 0x86uy
  | DW_OP_breg23 = 0x87uy
  | DW_OP_breg24 = 0x88uy
  | DW_OP_breg25 = 0x89uy
  | DW_OP_breg26 = 0x8auy
  | DW_OP_breg27 = 0x8buy
  | DW_OP_breg28 = 0x8cuy
  | DW_OP_breg29 = 0x8duy
  | DW_OP_breg30 = 0x8euy
  | DW_OP_breg31 = 0x8fuy
  | DW_OP_bregx = 0x92uy
  | DW_OP_dup = 0x12uy
  | DW_OP_drop = 0x13uy
  | DW_OP_over = 0x14uy
  | DW_OP_pick = 0x15uy
  | DW_OP_swap = 0x16uy
  | DW_OP_rot = 0x17uy
  | DW_OP_deref = 0x06uy
  | DW_OP_deref_size = 0x94uy
  | DW_OP_xderef = 0x18uy
  | DW_OP_xderef_size = 0x95uy
  | DW_OP_push_object_address = 0x97uy
  | DW_OP_form_tls_address = 0x9buy
  | DW_OP_call_frame_cfa = 0x9cuy
  | DW_OP_abs = 0x19uy
  | DW_OP_and = 0x1auy
  | DW_OP_div = 0x1buy
  | DW_OP_minus = 0x1cuy
  | DW_OP_mod = 0x1duy
  | DW_OP_mul = 0x1euy
  | DW_OP_neg = 0x1fuy
  | DW_OP_not = 0x20uy
  | DW_OP_or = 0x21uy
  | DW_OP_plus = 0x22uy
  | DW_OP_plus_uconst = 0x23uy
  | DW_OP_shl = 0x24uy
  | DW_OP_shr = 0x25uy
  | DW_OP_shra = 0x26uy
  | DW_OP_xor = 0x27uy
  | DW_OP_bra = 0x28uy
  | DW_OP_eq = 0x29uy
  | DW_OP_ge = 0x2auy
  | DW_OP_gt = 0x2buy
  | DW_OP_le = 0x2cuy
  | DW_OP_lt = 0x2duy
  | DW_OP_ne = 0x2euy
  | DW_OP_skip = 0x2fuy
  | DW_OP_call2 = 0x98uy
  | DW_OP_call4 = 0x99uy
  | DW_OP_call_ref = 0x9auy
  | DW_OP_nop = 0x96uy
  | DW_OP_implicit_value = 0x9euy
  | DW_OP_stack_value = 0x9fuy
  | DW_OP_piece = 0x93uy
  | DW_OP_bit_piece = 0x9duy

[<RequireQualifiedAccess>]
module internal DWOperation =
  open LanguagePrimitives

  let parse (b: byte) = EnumOfValue<byte, DWOperation> b

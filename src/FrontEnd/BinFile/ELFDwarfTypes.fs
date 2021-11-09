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
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
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
    | _ -> printfn "%A" venc; raise UnhandledEncoding

  let parseEncoding b =
    if b &&& 0xFFuy = 255uy then
      let v = EnumOfValue<int, ExceptionHeaderValue> 0xff
      let app = EnumOfValue<int, ExceptionHeaderApplication> 0xff
      struct (v, app)
    else
      let v = int (b &&& 0x0Fuy)
              |> EnumOfValue<int, ExceptionHeaderValue>
      let app = int (b &&& 0xF0uy)
                |> EnumOfValue<int, ExceptionHeaderApplication>
      struct (v, app)

/// Dwarf instructions used for unwinding stack.
type DWCFAInstruction =
  | DW_CFA_set_loc = 0x01uy
  | DW_CFA_advance_loc = 0x40uy
  | DW_CFA_advance_loc1 = 0x02uy
  | DW_CFA_advance_loc2 = 0x03uy
  | DW_CFA_advance_loc4 = 0x04uy
  | DW_CFA_def_cfa = 0x0cuy
  | DW_CFA_def_cfa_sf = 0x12uy
  | DW_CFA_def_cfa_register = 0x0duy
  | DW_CFA_def_cfa_offset = 0x0euy
  | DW_CFA_def_cfa_offset_sf = 0x13uy
  | DW_CFA_def_cfa_expression = 0x0fuy
  | DW_CFA_undefined = 0x07uy
  | DW_CFA_same_value = 0x08uy
  | DW_CFA_offset = 0x80uy
  | DW_CFA_offset_extended = 0x05uy
  | DW_CFA_offset_extended_sf = 0x11uy
  | DW_CFA_val_offset = 0x14uy
  | DW_CFA_val_offset_sf = 0x15uy
  | DW_CFA_register = 0x09uy
  | DW_CFA_expression = 0x10uy
  | DW_CFA_val_expression = 0x16uy
  | DW_CFA_restore = 0xc0uy
  | DW_CFA_restore_extended = 0x06uy
  | DW_CFA_remember_state = 0x0auy
  | DW_CFA_restore_state = 0x0buy
  | DW_CFA_GNU_args_size = 0x2euy
  | DW_CFA_GNU_negative_offset_extended = 0x2fuy
  | DW_CFA_nop = 0x00uy

[<RequireQualifiedAccess>]
module DWCFAInstruction =
  let parse (b: byte) = EnumOfValue<byte, DWCFAInstruction> b

/// Dwarf opcodes.
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
module DWOperation =
  let parse (b: byte) = EnumOfValue<byte, DWOperation> b

module DWRegister =
  let private toIntelx86Register = function
    | 0uy -> Intel.Register.toRegID Intel.Register.EAX
    | 1uy -> Intel.Register.toRegID Intel.Register.ECX
    | 2uy -> Intel.Register.toRegID Intel.Register.EDX
    | 3uy -> Intel.Register.toRegID Intel.Register.EBX
    | 4uy -> Intel.Register.toRegID Intel.Register.ESP
    | 5uy -> Intel.Register.toRegID Intel.Register.EBP
    | 6uy -> Intel.Register.toRegID Intel.Register.ESI
    | 7uy -> Intel.Register.toRegID Intel.Register.EDI
    | 8uy -> Intel.Register.toRegID Intel.Register.EIP
    | _ -> Utils.futureFeature ()

  let private toIntelx64Register = function
    | 0uy -> Intel.Register.toRegID Intel.Register.RAX
    | 1uy -> Intel.Register.toRegID Intel.Register.RDX
    | 2uy -> Intel.Register.toRegID Intel.Register.RCX
    | 3uy -> Intel.Register.toRegID Intel.Register.RBX
    | 4uy -> Intel.Register.toRegID Intel.Register.RSI
    | 5uy -> Intel.Register.toRegID Intel.Register.RDI
    | 6uy -> Intel.Register.toRegID Intel.Register.RBP
    | 7uy -> Intel.Register.toRegID Intel.Register.RSP
    | 8uy -> Intel.Register.toRegID Intel.Register.R8
    | 9uy -> Intel.Register.toRegID Intel.Register.R9
    | 10uy -> Intel.Register.toRegID Intel.Register.R10
    | 11uy -> Intel.Register.toRegID Intel.Register.R11
    | 12uy -> Intel.Register.toRegID Intel.Register.R12
    | 13uy -> Intel.Register.toRegID Intel.Register.R13
    | 14uy -> Intel.Register.toRegID Intel.Register.R14
    | 15uy -> Intel.Register.toRegID Intel.Register.R15
    | 16uy -> Intel.Register.toRegID Intel.Register.RIP
    | 17uy -> Intel.Register.toRegID Intel.Register.XMM0
    | 18uy -> Intel.Register.toRegID Intel.Register.XMM1
    | 19uy -> Intel.Register.toRegID Intel.Register.XMM2
    | 20uy -> Intel.Register.toRegID Intel.Register.XMM3
    | 21uy -> Intel.Register.toRegID Intel.Register.XMM4
    | 22uy -> Intel.Register.toRegID Intel.Register.XMM5
    | 23uy -> Intel.Register.toRegID Intel.Register.XMM6
    | 24uy -> Intel.Register.toRegID Intel.Register.XMM7
    | 25uy -> Intel.Register.toRegID Intel.Register.XMM8
    | 26uy -> Intel.Register.toRegID Intel.Register.XMM9
    | 27uy -> Intel.Register.toRegID Intel.Register.XMM10
    | 28uy -> Intel.Register.toRegID Intel.Register.XMM11
    | 29uy -> Intel.Register.toRegID Intel.Register.XMM12
    | 30uy -> Intel.Register.toRegID Intel.Register.XMM13
    | 31uy -> Intel.Register.toRegID Intel.Register.XMM14
    | 32uy -> Intel.Register.toRegID Intel.Register.XMM15
    | _ -> Utils.futureFeature ()

  let private toAArch64Register = function
    | 0uy -> ARM64.Register.toRegID ARM64.Register.X0
    | 1uy -> ARM64.Register.toRegID ARM64.Register.X1
    | 2uy -> ARM64.Register.toRegID ARM64.Register.X2
    | 3uy -> ARM64.Register.toRegID ARM64.Register.X3
    | 4uy -> ARM64.Register.toRegID ARM64.Register.X4
    | 5uy -> ARM64.Register.toRegID ARM64.Register.X5
    | 6uy -> ARM64.Register.toRegID ARM64.Register.X6
    | 7uy -> ARM64.Register.toRegID ARM64.Register.X7
    | 8uy -> ARM64.Register.toRegID ARM64.Register.X8
    | 9uy -> ARM64.Register.toRegID ARM64.Register.X9
    | 10uy -> ARM64.Register.toRegID ARM64.Register.X10
    | 11uy -> ARM64.Register.toRegID ARM64.Register.X11
    | 12uy -> ARM64.Register.toRegID ARM64.Register.X12
    | 13uy -> ARM64.Register.toRegID ARM64.Register.X13
    | 14uy -> ARM64.Register.toRegID ARM64.Register.X14
    | 15uy -> ARM64.Register.toRegID ARM64.Register.X15
    | 16uy -> ARM64.Register.toRegID ARM64.Register.X16
    | 17uy -> ARM64.Register.toRegID ARM64.Register.X17
    | 18uy -> ARM64.Register.toRegID ARM64.Register.X18
    | 19uy -> ARM64.Register.toRegID ARM64.Register.X19
    | 20uy -> ARM64.Register.toRegID ARM64.Register.X20
    | 21uy -> ARM64.Register.toRegID ARM64.Register.X21
    | 22uy -> ARM64.Register.toRegID ARM64.Register.X22
    | 23uy -> ARM64.Register.toRegID ARM64.Register.X23
    | 24uy -> ARM64.Register.toRegID ARM64.Register.X24
    | 25uy -> ARM64.Register.toRegID ARM64.Register.X25
    | 26uy -> ARM64.Register.toRegID ARM64.Register.X26
    | 27uy -> ARM64.Register.toRegID ARM64.Register.X27
    | 28uy -> ARM64.Register.toRegID ARM64.Register.X28
    | 29uy -> ARM64.Register.toRegID ARM64.Register.X29
    | 30uy -> ARM64.Register.toRegID ARM64.Register.X30
    | 31uy -> ARM64.Register.toRegID ARM64.Register.SP
    | 64uy -> ARM64.Register.toRegID ARM64.Register.V0
    | 65uy -> ARM64.Register.toRegID ARM64.Register.V1
    | 66uy -> ARM64.Register.toRegID ARM64.Register.V2
    | 67uy -> ARM64.Register.toRegID ARM64.Register.V3
    | 68uy -> ARM64.Register.toRegID ARM64.Register.V4
    | 69uy -> ARM64.Register.toRegID ARM64.Register.V5
    | 70uy -> ARM64.Register.toRegID ARM64.Register.V6
    | 71uy -> ARM64.Register.toRegID ARM64.Register.V7
    | 72uy -> ARM64.Register.toRegID ARM64.Register.V8
    | 73uy -> ARM64.Register.toRegID ARM64.Register.V9
    | 74uy -> ARM64.Register.toRegID ARM64.Register.V10
    | 75uy -> ARM64.Register.toRegID ARM64.Register.V11
    | 76uy -> ARM64.Register.toRegID ARM64.Register.V12
    | 77uy -> ARM64.Register.toRegID ARM64.Register.V13
    | 78uy -> ARM64.Register.toRegID ARM64.Register.V14
    | 79uy -> ARM64.Register.toRegID ARM64.Register.V15
    | 80uy -> ARM64.Register.toRegID ARM64.Register.V16
    | 81uy -> ARM64.Register.toRegID ARM64.Register.V17
    | 82uy -> ARM64.Register.toRegID ARM64.Register.V18
    | 83uy -> ARM64.Register.toRegID ARM64.Register.V19
    | 84uy -> ARM64.Register.toRegID ARM64.Register.V20
    | 85uy -> ARM64.Register.toRegID ARM64.Register.V21
    | 86uy -> ARM64.Register.toRegID ARM64.Register.V22
    | 87uy -> ARM64.Register.toRegID ARM64.Register.V23
    | 88uy -> ARM64.Register.toRegID ARM64.Register.V24
    | 89uy -> ARM64.Register.toRegID ARM64.Register.V25
    | 90uy -> ARM64.Register.toRegID ARM64.Register.V26
    | 91uy -> ARM64.Register.toRegID ARM64.Register.V27
    | 92uy -> ARM64.Register.toRegID ARM64.Register.V28
    | 93uy -> ARM64.Register.toRegID ARM64.Register.V29
    | 94uy -> ARM64.Register.toRegID ARM64.Register.V30
    | 95uy -> ARM64.Register.toRegID ARM64.Register.V31
    | x -> Utils.futureFeature ()

  let private toMIPSRegister (n: byte) =
    MIPS.Register.toRegID (EnumOfValue (int n))

  let toRegID isa regnum =
    match isa.Arch with
    | Architecture.IntelX86 -> toIntelx86Register regnum
    | Architecture.IntelX64 -> toIntelx64Register regnum
    | Architecture.AARCH64 -> toAArch64Register regnum
    | Architecture.MIPS1
    | Architecture.MIPS2
    | Architecture.MIPS3
    | Architecture.MIPS32
    | Architecture.MIPS32R2
    | Architecture.MIPS32R6
    | Architecture.MIPS4
    | Architecture.MIPS5
    | Architecture.MIPS64
    | Architecture.MIPS64R2
    | Architecture.MIPS64R6 -> toMIPSRegister regnum
    | _ -> Utils.futureFeature ()

  let toRegisterExpr isa (regbay: RegisterBay) regnum =
    toRegID isa regnum |> regbay.RegIDToRegExpr

/// The CFA. Machine-independent representation of the current frame address.
/// For example, (esp+8) on x86.
type CanonicalFrameAddress =
  | RegPlusOffset of RegisterID * int
  | Expression of LowUIR.Expr
  | UnknownCFA

module CanonicalFrameAddress =
  let regPlusOffset isa regbay regnum offset =
    RegPlusOffset (DWRegister.toRegID isa regnum, offset)

  let toString (regbay: RegisterBay) = function
  | RegPlusOffset (rid, offset) ->
    regbay.RegIDToString rid + (offset.ToString ("+0;-#"))
  | Expression exp ->
    LowUIR.Pp.expToString exp
  | UnknownCFA -> "unknown"

/// How does a target value get stored on the stack frame.
type Action =
  /// Has no recoverable value in the previous frame.
  | Undefined
  /// The register has not been modified from the previous frame.
  | SameValue
  /// The previous value of this register is saved at the address CFA+N where
  /// CFA is the current CFA value and N is a signed offset.
  | Offset of int64
  /// The previous value of this register is the value CFA+N where CFA is the
  /// current CFA value and N is a signed offset.
  | ValOffset of int
  /// The previous value of this register is stored in another register numbered
  /// R.
  | Register of RegisterID
  /// The previous value is represented as the expression.
  | ActionExpr of LowUIR.Expr

module Action =
  let toString = function
    | Undefined -> "undef"
    | SameValue -> "samevalue"
    | Offset o -> "c" + (o.ToString ("+0;-#"))
    | ValOffset o -> "v" + (o.ToString ("+0;-#"))
    | Register rid -> "r(" + rid.ToString () + ")"
    | ActionExpr e -> "exp:" + LowUIR.Pp.expToString e

/// Either a return address or a normal register is stored on the stack.
type Target =
  | ReturnAddress
  | NormalReg of RegisterID

/// Rule that describes how a given register/return address has been saved on
/// the stack frame.
type Rule = Map<Target, Action>

module Rule =
  let getTarget isa returnAddressReg (reg: byte) =
    if returnAddressReg = reg then ReturnAddress
    else DWRegister.toRegID isa reg |> NormalReg

  let offset isa rr reg v =
    getTarget isa rr reg, Offset v

/// An entry (a row) of the call frame information table (unwinding table).
type UnwindingEntry = {
  /// Instruction location.
  Location: Addr
  /// CFA.
  CanonicalFrameAddress: CanonicalFrameAddress
  /// Unwinding rule.
  Rule: Rule
}

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

/// Represents call frame instructions used for virtually unwinding stack.
type CFAInstruction =
  /// Takes a single operand that represents a target address, and creates a
  /// new table row using the specified address as the location.
  | DW_CFA_set_loc = 0x01uy
  /// Takes a single operand (encoded with the opcode) that represents a
  /// constant delta, and creates a new table row with a location value that is
  /// computed by taking the current entry's location value and adding the value
  /// of delta * code_alignment_factor.
  | DW_CFA_advance_loc = 0x40uy
  /// Same as DW_CFA_advance_loc, but takes a ubyte value as an operand that
  /// represents a delta.
  | DW_CFA_advance_loc1 = 0x02uy
  /// Same as DW_CFA_advance_loc, but takes a 2-byte unsigned value as an
  /// operand that represents a delta.
  | DW_CFA_advance_loc2 = 0x03uy
  /// Same as DW_CFA_advance_loc, but takes a 4-byte unsigned value as an
  /// operand that represents a delta.
  | DW_CFA_advance_loc4 = 0x04uy
  /// Takes two unsigned LEB128 operands representing a register number and a
  /// non-factored offset, and defines the current CFA rule to use the provided
  /// register and offset.
  | DW_CFA_def_cfa = 0x0cuy
  /// Takes two operands: an unsigned LEB128 value representing a register
  /// number and a signed LEB128 factored offset, and defines the current CFA.
  | DW_CFA_def_cfa_sf = 0x12uy
  /// Takes a single unsigned LEB128 operand representing a register number, and
  /// defines the current CFA rule to use the provided register (but to keep the
  /// old offset). This operation is valid only if the current CFA rule is
  /// defined to use a register and offset.
  | DW_CFA_def_cfa_register = 0x0duy
  /// Takes a single unsigned LEB128 operand representing a (non-factored)
  /// offset, and defines the current CFA rule to use the provided offset (but
  /// to keep the old register).
  | DW_CFA_def_cfa_offset = 0x0euy
  /// Identical to DW_CFA_def_cfa_offset except that the operand is signed and
  /// factored.
  | DW_CFA_def_cfa_offset_sf = 0x13uy
  /// Takes a single operand encoded as a DW_FORM_exprloc value representing a
  /// DWARF expression, and establishes that expression as the means by which
  /// the current CFA is computed.
  | DW_CFA_def_cfa_expression = 0x0fuy
  /// Takes a single unsigned LEB128 operand that represents a register number,
  /// and sets the rule for the specified register to undefined.
  | DW_CFA_undefined = 0x07uy
  /// Takes a single unsigned LEB128 operand that represents a register number,
  /// and sets the rule for the specified register to "same value".
  | DW_CFA_same_value = 0x08uy
  /// Takes two operands: a register number (encoded with the opcode) and an
  /// unsigned LEB128 constant representing a factored offset. The required
  /// action is to change the rule for the register indicated by the register
  /// number to be an offset(N) rule where the value of N is factored offset *
  /// data_alignment_factor.
  | DW_CFA_offset = 0x80uy
  /// Takes two unsigned LEB128 operands representing a register number and a
  /// factored offset. This instruction is identical to DW_CFA_offset except for
  /// the encoding and size of the register operand.
  | DW_CFA_offset_extended = 0x05uy
  /// Takes two operands: an unsigned LEB128 value representing a register
  /// number and a signed LEB128 factored offset. This instruction is identical
  /// to DW_CFA_offset_extended except that the second operand is signed and
  /// factored. The resulting offset is factored_offset * data_alignment_factor.
  | DW_CFA_offset_extended_sf = 0x11uy
  /// Takes two unsigned LEB128 operands representing a register number and a
  /// factored offset. The required action is to change the rule for the
  /// register indicated by the register number to be a val_offset(N) rule where
  /// the value of N is factored_offset * data_alignment_factor.
  | DW_CFA_val_offset = 0x14uy
  /// Takes two operands: an unsigned LEB128 value representing a register
  /// number and a signed LEB128 factored offset. This instruction is identical
  /// to DW_CFA_val_offset except that the second operand is signed and
  /// factored. The resulting offset is factored_offset * data_alignment_factor.
  | DW_CFA_val_offset_sf = 0x15uy
  /// Takes two unsigned LEB128 operands representing register numbers. The
  /// required action is to set the rule for the first register to be
  /// register(R) where R is the second register.
  | DW_CFA_register = 0x09uy
  /// Takes two operands: an unsigned LEB128 value representing a register
  /// number, and a DW_FORM_block value representing a DWARF expression. The
  /// required action is to change the rule for the register indicated by the
  /// register number to be an expression(E) rule where E is the DWARF
  /// expression. That is, the DWARF expression computes the address. The value
  /// of the CFA is pushed on the DWARF evaluation stack prior to execution of
  /// the DWARF expression.
  | DW_CFA_expression = 0x10uy
  /// Takes two operands: an unsigned LEB128 value representing a register
  /// number, and a DW_FORM_block value representing a DWARF expression. The
  /// required action is to change the rule for the register indicated by the
  /// register number to be a val_expression(E) rule where E is the DWARF
  /// expression. That is, the DWARF expression computes the value of the given
  /// register. The value of the CFA is pushed on the DWARF evaluation stack
  /// prior to execution of the DWARF expression.
  | DW_CFA_val_expression = 0x16uy
  /// Takes a single operand (encoded with the opcode) that represents a
  /// register number. The required action is to change the rule for the
  /// indicated register to the rule assigned it by the initial_instructions in
  /// the CIE.
  | DW_CFA_restore = 0xc0uy
  /// Takes a single unsigned LEB128 operand that represents a register number.
  /// This instruction is identical to DW_CFA_restore except for the encoding
  /// and size of the register operand.
  | DW_CFA_restore_extended = 0x06uy
  /// Takes no operands. The required action is to push the set of rules for
  /// every register onto an implicit stack.
  | DW_CFA_remember_state = 0x0auy
  /// Takes no operands. The required action is to pop the set of rules off the
  /// implicit stack and place them in the current row.
  | DW_CFA_restore_state = 0x0buy
  /// Takes an unsigned LEB128 operand representing an argument size
  | DW_CFA_GNU_args_size = 0x2euy
  /// Takes two operands: an unsigned LEB128 value representing a register
  /// number and an unsigned LEB128 which represents the magnitude of the
  /// offset. This instruction is identical to DW_CFA_offset_extended_sf except
  /// that the operand is subtracted to produce the offset.
  | DW_CFA_GNU_negative_offset_extended = 0x2fuy
  /// No operation.
  | DW_CFA_nop = 0x00uy

[<RequireQualifiedAccess>]
module internal CFAInstruction =
  open LanguagePrimitives

  let parse (b: byte) = EnumOfValue<byte, CFAInstruction> b

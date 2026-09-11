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

/// <summary>
/// Writes an eBPF instruction as a mnemonic and the operands it names: the
/// registers it works on, the memory it reaches written as a register and how
/// far from what it holds to reach, and how far away the place a jump goes to
/// is.
///
/// A number is written as the bits of the word it was widened to rather than
/// with a sign, so that the assembler reading this back needs to know only how
/// wide the field it lands in is.
/// </summary>
module internal B2R2.FrontEnd.BPF.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let inline private buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Mnemonic, Opcode.toString ins.Opcode)

let inline private buildReg reg (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Variable, Register.toString reg)

let private oprToString opr delim (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.String, delim)
  match opr with
  | OprReg reg ->
    buildReg reg builder
  | OprImm imm ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 imm)
  | OprMem(baseReg, disp) ->
    builder.Accumulate(AsmWordKind.String, "[")
    buildReg baseReg builder
    builder.Accumulate(AsmWordKind.String, "+")
    builder.Accumulate(AsmWordKind.Value, HexString.ofInt32 disp)
    builder.Accumulate(AsmWordKind.String, "]")
  | OprAddr disp ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofInt64 disp)

let private buildOprs (ins: Instruction) builder =
  match ins.Operands with
  | NoOperand ->
    ()
  | OneOperand opr ->
    oprToString opr " " builder
  | TwoOperands(opr1, opr2) ->
    oprToString opr1 " " builder
    oprToString opr2 ", " builder
  | ThreeOperands(opr1, opr2, opr3) ->
    oprToString opr1 " " builder
    oprToString opr2 ", " builder
    oprToString opr3 ", " builder

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder
  buildOprs ins builder

// vim: set tw=80 sts=2 sw=2:

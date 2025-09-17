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

module internal B2R2.FrontEnd.PPC.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString =
  function
  | Op.ADDI -> "addi"
  | _ -> Terminator.futureFeature ()

let inline buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate(AsmWordKind.Mnemonic, str)

let inline buildOperand (opr: Operand) (builder: IDisasmBuilder) =
  match opr with
  | OprImm v ->
    builder.Accumulate(AsmWordKind.Value, "0x" + v.ToString "X")
  | OprReg reg ->
    builder.Accumulate(AsmWordKind.Variable, Register.toString reg)

let inline buildOperands (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | NoOperand -> ()
  | ThreeOperands(opr1, opr2, opr3) ->
    builder.Accumulate(AsmWordKind.String, " ")
    buildOperand opr1 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr2 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr3 builder

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder
  buildOperands ins builder

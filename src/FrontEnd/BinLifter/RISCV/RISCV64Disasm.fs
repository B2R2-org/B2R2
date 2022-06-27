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

module B2R2.FrontEnd.BinLifter.RISCV.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  | Op.ADD -> "add"
  | _ -> Utils.impossible ()

let inline buildOpcode ins (builder: DisasmBuilder<_>) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic str

let oprToString opr delim (builder: DisasmBuilder<_>) =
  match opr with
  | OpReg reg ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)

let buildOprs insInfo builder =
  match insInfo.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    oprToString opr " " builder
  | TwoOperands (opr1, opr2) ->
    oprToString opr1 " " builder
    oprToString opr2 ", " builder

let disasm insInfo (builder: DisasmBuilder<_>) =
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOprs insInfo builder

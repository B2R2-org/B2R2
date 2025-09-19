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
  | Op.ADDIS -> "addis"
  | Op.ADDPCIS -> "addpcis"
  | Op.ADD -> "add"
  | Op.ADD_DOT -> "add."
  | Op.ADDO -> "addo"
  | Op.ADDO_DOT -> "addo."
  | Op.SUBF -> "subf"
  | Op.SUBF_DOT -> "subf."
  | Op.SUBFO -> "subfo"
  | Op.SUBFO_DOT -> "subfo."
  | Op.ADDIC -> "addic"
  | Op.ADDIC_DOT -> "addic."
  | Op.SUBFIC -> "subfic"
  | Op.ADDC -> "addc"
  | Op.ADDC_DOT -> "addc."
  | Op.ADDCO -> "addco"
  | Op.ADDCO_DOT -> "addco."
  | Op.SUBFC -> "subfc"
  | Op.SUBFC_DOT -> "subfc."
  | Op.SUBFCO -> "subfco"
  | Op.SUBFCO_DOT -> "subfco."
  | Op.ADDE -> "adde"
  | Op.ADDE_DOT -> "adde."
  | Op.ADDEO -> "addeo"
  | Op.ADDEO_DOT -> "addeo."
  | Op.SUBFE -> "subfe"
  | Op.SUBFE_DOT -> "subfe."
  | Op.SUBFEO -> "subfeo"
  | Op.SUBFEO_DOT -> "subfeo."
  | Op.ADDME -> "addme"
  | Op.ADDME_DOT -> "addme."
  | Op.ADDMEO -> "addmeo"
  | Op.ADDMEO_DOT -> "addmeo."
  | Op.SUBFME -> "subfme"
  | Op.SUBFME_DOT -> "subfme."
  | Op.SUBFMEO -> "subfmeo"
  | Op.SUBFMEO_DOT -> "subfmeo."
  | Op.ADDEX -> "addex"
  | Op.SUBFZE -> "subfze"
  | Op.SUBFZE_DOT -> "subfze."
  | Op.SUBFZEO -> "subfzeo"
  | Op.SUBFZEO_DOT -> "subfzeo."
  | Op.ADDZE -> "addze"
  | Op.ADDZE_DOT -> "addze."
  | Op.ADDZEO -> "addzeo"
  | Op.ADDZEO_DOT -> "addzeo."
  | Op.NEG -> "neg"
  | Op.NEG_DOT -> "neg."
  | Op.NEGO -> "nego"
  | Op.NEGO_DOT -> "nego."
  | Op.MULLI -> "mulli"
  | Op.MULHW -> "mulhw"
  | Op.MULHW_DOT -> "mulhw."
  | Op.MULLW -> "mullw"
  | Op.MULLW_DOT -> "mullw."
  | Op.MULLWO -> "mullwo"
  | Op.MULLWO_DOT -> "mullwo."
  | Op.MULHWU -> "mulhwu"
  | Op.MULHWU_DOT -> "mulhwu."
  | Op.DIVW -> "divw"
  | Op.DIVW_DOT -> "divw."
  | Op.DIVWO -> "divwo"
  | Op.DIVWO_DOT -> "divwo."
  | Op.DIVWU -> "divwu"
  | Op.DIVWU_DOT -> "divwu."
  | Op.DIVWUO -> "divwuo"
  | Op.DIVWUO_DOT -> "divwuo."
  | Op.DIVWE -> "divwe"
  | Op.DIVWE_DOT -> "divwe."
  | Op.DIVWEO -> "divweo"
  | Op.DIVWEO_DOT -> "divweo."
  | Op.DIVWEU -> "divweu"
  | Op.DIVWEU_DOT -> "divweu."
  | Op.DIVWEUO -> "divweuo"
  | Op.DIVWEUO_DOT -> "divweuo."
  | Op.MODSW -> "modsw"
  | Op.MODUW -> "moduw"
  | Op.DARN -> "darn"
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
  | OprCY cy ->
    builder.Accumulate(AsmWordKind.Value, "0x" + cy.ToString "X")
  | OprL l ->
    builder.Accumulate(AsmWordKind.Value, "0x" + l.ToString "X")

let inline buildOperands (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | NoOperand -> ()
  | TwoOperands(opr1, opr2) ->
    builder.Accumulate(AsmWordKind.String, " ")
    buildOperand opr1 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr2 builder
  | ThreeOperands(opr1, opr2, opr3) ->
    builder.Accumulate(AsmWordKind.String, " ")
    buildOperand opr1 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr2 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr3 builder
  | FourOperands(opr1, opr2, opr3, opr4) ->
    builder.Accumulate(AsmWordKind.String, " ")
    buildOperand opr1 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr2 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr3 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr4 builder

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder
  buildOperands ins builder

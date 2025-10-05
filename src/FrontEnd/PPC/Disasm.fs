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
  | Op.B -> "b"
  | Op.BA -> "ba"
  | Op.BL -> "bl"
  | Op.BLA -> "bla"
  | Op.BC -> "bc"
  | Op.BCA -> "bca"
  | Op.BCL -> "bcl"
  | Op.BCLA -> "bcla"
  | Op.BCLR -> "bclr"
  | Op.BCLRL -> "bclrl"
  | Op.BCCTR -> "bcctr"
  | Op.BCCTRL -> "bcctrl"
  | Op.BCTAR -> "bctar"
  | Op.BCTARL -> "bctarl"
  | Op.LBZ -> "lbz"
  | Op.LBZX -> "lbzx"
  | Op.LBZU -> "lbzu"
  | Op.LBZUX -> "lbzux"
  | Op.LHZ -> "lhz"
  | Op.LHZX -> "lhzx"
  | Op.LHZU -> "lhzu"
  | Op.LHZUX -> "lhzux"
  | Op.LHA -> "lha"
  | Op.LHAX -> "lhax"
  | Op.LHAU -> "lhau"
  | Op.LHAUX -> "lhaux"
  | Op.LWZ -> "lwz"
  | Op.LWZX -> "lwzx"
  | Op.LWZU -> "lwzu"
  | Op.LWZUX -> "lwzux"
  | Op.LWA -> "lw"
  | Op.LWAX -> "lwax"
  | Op.LWAUX -> "lwaux"
  | Op.LD -> "ld"
  | Op.LDX -> "ldx"
  | Op.LDU -> "ldu"
  | Op.LDUX -> "ldux"
  | Op.STB -> "stb"
  | Op.STBX -> "stbx"
  | Op.STBU -> "stbu"
  | Op.STBUX -> "stbux"
  | Op.STH -> "sth"
  | Op.STHX -> "sthx"
  | Op.STHU -> "sthu"
  | Op.STHUX -> "sthux"
  | Op.STW -> "stw"
  | Op.STWX -> "stwx"
  | Op.STWU -> "stwu"
  | Op.STWUX -> "stwux"
  | Op.STD -> "std"
  | Op.STDX -> "stdx"
  | Op.STDU -> "stdu"
  | Op.STDUX -> "stdux"
  | Op.LQ -> "lq"
  | Op.STQ -> "stq"
  | Op.LHBRX -> "lhbrx"
  | Op.STHBRX -> "sthbrx"
  | Op.LWBRX -> "lwbrx"
  | Op.STWBRX -> "stwbrx"
  | Op.LDBRX -> "ldbrx"
  | Op.STDBRX -> "stdbrx"
  | Op.LMW -> "lmw"
  | Op.STMW -> "stmw"
  | Op.LSWI -> "lswi"
  | Op.LSWX -> "lswx"
  | Op.STSWI -> "stswi"
  | Op.STSWX -> "stswx"
  | _ -> Terminator.futureFeature ()

let inline buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate(AsmWordKind.Mnemonic, str)

let inline buildOperand (opr: Operand) (builder: IDisasmBuilder) =
  match opr with
  | OprImm imm ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 imm)
  | OprMem(disp, reg) ->
    if disp < 0 then
      builder.Accumulate(AsmWordKind.Value, "-" + HexString.ofInt64 (-disp))
    else
      builder.Accumulate(AsmWordKind.Value, HexString.ofInt64 disp)
    builder.Accumulate(AsmWordKind.String, "(")
    builder.Accumulate(AsmWordKind.Variable, Register.toString reg)
    builder.Accumulate(AsmWordKind.String, ")")
  | OprReg reg ->
    builder.Accumulate(AsmWordKind.Variable, Register.toString reg)
  | OprCY cy ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt32 (uint32 cy))
  | OprL l ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt32 (uint32 l))
  | OprAddr addr ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 addr)
  | OprBO bo ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt32 (uint32 bo))
  | OprBI bi ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt32 (uint32 bi))
  | OprBH bh ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt32 (uint32 bh))

let inline buildOperands (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    builder.Accumulate(AsmWordKind.String, " ")
    buildOperand opr builder
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

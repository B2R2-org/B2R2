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
  | Op.ADDI -> "addi"
  | Op.ADDIS -> "addis"
  | Op.ADDPCIS -> "addpcis"
  | Op.ADD -> "add"
  | Op.ADD_DOT -> "add."
  | Op.ADDO -> "addo"
  | Op.ADDO_DOT -> "addo."
  | Op.ADDIC -> "addic"
  | Op.SUBF -> "subf"
  | Op.SUBF_DOT -> "subf."
  | Op.SUBFO -> "subfo"
  | Op.SUBFO_DOT -> "subfo."
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
  | Op.ADDME -> "addme"
  | Op.ADDME_DOT -> "addme."
  | Op.ADDMEO -> "addmeo"
  | Op.ADDMEO_DOT -> "addmeo."
  | Op.SUBFE -> "subfe"
  | Op.SUBFE_DOT -> "subfe."
  | Op.SUBFEO -> "subfeo"
  | Op.SUBFEO_DOT -> "subfeo."
  | Op.SUBFME -> "subfme"
  | Op.SUBFME_DOT -> "subfme."
  | Op.SUBFMEO -> "subfmeo"
  | Op.SUBFMEO_DOT -> "subfmeo."
  | Op.ADDEX -> "addex"
  | Op.ADDZE -> "addze"
  | Op.ADDZE_DOT -> "addze."
  | Op.ADDZEO -> "addzeo"
  | Op.ADDZEO_DOT -> "addzeo."
  | Op.SUBFZE -> "subfze"
  | Op.SUBFZE_DOT -> "subfze."
  | Op.SUBFZEO -> "subfzeo"
  | Op.SUBFZEO_DOT -> "subfzeo."
  | Op.NEG -> "neg"
  | Op.NEG_DOT -> "neg."
  | Op.NEGO -> "nego"
  | Op.NEGO_DOT -> "nego."
  | Op.MULLI -> "mulli"
  | Op.MULLW -> "mullw"
  | Op.MULLW_DOT -> "mullw."
  | Op.MULLWO -> "mullwo"
  | Op.MULLWO_DOT -> "mullwo."
  | Op.MULHW -> "mulhw"
  | Op.MULHW_DOT -> "mulhw."
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
  | Op.LBZ -> "lbz"
  | Op.LBZU -> "lbzu"
  | Op.LBZX -> "lbzx"
  | Op.LBZUX -> "lbzux"
  | Op.LHZ -> "lhz"
  | Op.LHZU -> "lhzu"
  | Op.LHZX -> "lhzx"
  | Op.LHZUX -> "lhzux"
  | Op.LHA -> "lha"
  | Op.LHAU -> "lhau"
  | Op.LHAX -> "lhax"
  | Op.LHAUX -> "lhaux"
  | Op.LWZ -> "lwz"
  | Op.LWZU -> "lwzu"
  | Op.LWZX -> "lwzx"
  | Op.LWZUX -> "lwzux"
  | Op.LWA -> "lwa"
  | Op.LWAX -> "lwax"
  | Op.LWAUX -> "lwaux"
  | Op.LD -> "ld"
  | Op.LDU -> "ldu"
  | Op.LDX -> "ldx"
  | Op.LDUX -> "ldux"
  | Op.STB -> "stb"
  | Op.STBU -> "stbu"
  | Op.STBX -> "stbx"
  | Op.STBUX -> "stbux"
  | Op.STH -> "sth"
  | Op.STHU -> "sthu"
  | Op.STHX -> "sthx"
  | Op.STHUX -> "sthux"
  | Op.STW -> "stw"
  | Op.STWU -> "stwu"
  | Op.STWX -> "stwx"
  | Op.STWUX -> "stwux"
  | Op.STD -> "std"
  | Op.STDU -> "stdu"
  | Op.STDX -> "stdx"
  | Op.STDUX -> "stdux"
  | Op.LQ -> "lq"
  | Op.STQ -> "stq"
  | Op.LHBRX -> "lhbrx"
  | Op.LWBRX -> "lwbrx"
  | Op.STHBRX -> "sthbrx"
  | Op.STWBRX -> "stwbrx"
  | Op.LDBRX -> "ldbrx"
  | Op.STDBRX -> "stdbrx"
  | Op.LMW -> "lmw"
  | Op.STMW -> "stmw"
  | Op.LSWI -> "lswi"
  | Op.LSWX -> "lswx"
  | Op.STSWI -> "stswi"
  | Op.STSWX -> "stswx"
  | Op.CMPI -> "cmpi"
  | Op.CMP -> "cmp"
  | Op.CMPLI -> "cmpli"
  | Op.CMPL -> "cmpl"
  | Op.CMPRB -> "cmprb"
  | Op.CMPEQB -> "cmpeqb"
  | Op.TWI -> "twi"
  | Op.TW -> "tw"
  | Op.TDI -> "tdi"
  | Op.ISEL -> "isel"
  | Op.TD -> "td"
  | Op.ANDI_DOT -> "andi."
  | Op.ANDIS_DOT -> "andis."
  | Op.ORI -> "ori"
  | Op.ORIS -> "oris"
  | Op.XORI -> "xori"
  | Op.XORIS -> "xoris"
  | Op.AND -> "and"
  | Op.AND_DOT -> "and."
  | Op.XOR -> "xor"
  | Op.XOR_DOT -> "xor."
  | Op.NAND -> "nand"
  | Op.NAND_DOT -> "nand."
  | Op.OR -> "or"
  | Op.OR_DOT -> "or."
  | Op.NOR -> "nor"
  | Op.NOR_DOT -> "nor."
  | Op.ANDC -> "andc"
  | Op.ANDC_DOT -> "andc."
  | Op.EQV -> "eqv"
  | Op.EQV_DOT -> "eqv."
  | Op.ORC -> "orc"
  | Op.ORC_DOT -> "orc."
  | Op.EXTSB -> "extsb"
  | Op.EXTSB_DOT -> "extsb."
  | Op.CNTLZW -> "cntlzw"
  | Op.CNTLZW_DOT -> "cntlzw."
  | Op.EXTSH -> "extsh"
  | Op.EXTSH_DOT -> "extsh."
  | Op.CNTTZW -> "cnttzw"
  | Op.CNTTZW_DOT -> "cnttzw."
  | Op.CMPB -> "cmpb"
  | Op.POPCNTB -> "popcntb"
  | Op.POPCNTW -> "popcntw"
  | Op.PRTYD -> "prtyd"
  | Op.PRTYW -> "prtyw"
  | Op.EXTSW -> "extsw"
  | Op.EXTSW_DOT -> "extsw."
  | Op.CNTLZD -> "cntlzd"
  | Op.CNTLZD_DOT -> "cntlzd."
  | Op.POPCNTD -> "popcntd"
  | Op.CNTTZD -> "cnttzd"
  | Op.CNTTZD_DOT -> "cnttzd."
  | Op.BPERMD -> "bpermd"
  | Op.MULLD -> "mulld"
  | Op.MULLD_DOT -> "mulld."
  | Op.MULLDO -> "mulldo"
  | Op.MULLDO_DOT -> "mulldo."
  | Op.MULHD -> "mulhd"
  | Op.MULHD_DOT -> "mulhd."
  | Op.MULHDU -> "mulhdu"
  | Op.MULHDU_DOT -> "mulhdu."
  | Op.MADDHD -> "maddhd"
  | Op.MADDHDU -> "maddhdu"
  | Op.MADDLD -> "maddld"
  | Op.DIVD -> "divd"
  | Op.DIVD_DOT -> "divd."
  | Op.DIVDO -> "divdo"
  | Op.DIVDO_DOT -> "divdo."
  | Op.DIVDU -> "divdu"
  | Op.DIVDU_DOT -> "divdu."
  | Op.DIVDUO -> "divduo"
  | Op.DIVDUO_DOT -> "divduo."
  | Op.DIVDE -> "divde"
  | Op.DIVDE_DOT -> "divde."
  | Op.DIVDEO -> "divdeo"
  | Op.DIVDEO_DOT -> "divdeo."
  | Op.DIVDEU -> "divdeu"
  | Op.DIVDEU_DOT -> "divdeu."
  | Op.DIVDEUO -> "divdeuo"
  | Op.DIVDEUO_DOT -> "divdeuo."
  | Op.MODSD -> "modsd"
  | Op.MODUD -> "modud"
  | Op.RLWINM -> "rlwinm"
  | Op.RLWINM_DOT -> "rlwinm."
  | Op.RLWNM -> "rlwnm"
  | Op.RLWNM_DOT -> "rlwnm."
  | Op.RLWIMI -> "rlwimi"
  | Op.RLWIMI_DOT -> "rlwimi."
  | Op.RLDICL -> "rldicl"
  | Op.RLDICL_DOT -> "rldicl."
  | Op.RLDICR -> "rldicr"
  | Op.RLDICR_DOT -> "rldicr."
  | Op.RLDIC -> "rldic"
  | Op.RLDIC_DOT -> "rldic."
  | Op.RLDCL -> "rldcl"
  | Op.RLDCL_DOT -> "rldcl."
  | Op.RLDCR -> "rldcr"
  | Op.RLDCR_DOT -> "rldcr."
  | Op.RLDIMI -> "rldimi"
  | Op.RLDIMI_DOT -> "rldimi."
  | Op.SLW -> "slw"
  | Op.SLW_DOT -> "slw."
  | Op.SRW -> "srw"
  | Op.SRW_DOT -> "srw."
  | Op.SRAWI -> "srawi"
  | Op.SRAWI_DOT -> "srawi."
  | Op.SRAW -> "sraw"
  | Op.SRAW_DOT -> "sraw."
  | Op.SLD -> "sld"
  | Op.SLD_DOT -> "sld."
  | Op.SRD -> "srd"
  | Op.SRD_DOT -> "srd."
  | Op.SRADI -> "sradi"
  | Op.SRADI_DOT -> "sradi."
  | Op.SRAD -> "srad"
  | Op.SRAD_DOT -> "srad."
  | Op.EXTSWSLI -> "extswsli"
  | Op.EXTSWSLI_DOT -> "extswsli."
  | Op.CDTBCD -> "cdtbcd"
  | Op.CBCDTD -> "cbcdtd"
  | Op.ADDG6S -> "addg6s"
  | Op.MFVSRD -> "mfvsrd"
  | Op.MFVSRLD -> "mfvsrld"
  | Op.MFVSRWZ -> "mfvsrwz"
  | Op.MTVSRD -> "mtvsrd"
  | Op.MTVSRWA -> "mtvsrwa"
  | Op.MTVSRWZ -> "mtvsrwz"
  | Op.MTVSRDD -> "mtvsrdd"
  | Op.MTVSRWS -> "mtvsrws"
  | Op.MTSPR -> "mtspr"
  | Op.MFSPR -> "mfspr"
  | Op.MCRXRX -> "mcrxrx"
  | Op.MTOCRF -> "mtocrf"
  | Op.MTCRF -> "mtcrf"
  | Op.MFOCRF -> "mfocrf"
  | Op.MFCR -> "mfcr"
  | Op.SETB -> "setb"
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
  | OprTO toValue ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt32 (uint32 toValue))
  | OprFXM fxm ->
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt32 (uint32 fxm))

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
  | FiveOperands(opr1, opr2, opr3, opr4, opr5) ->
    builder.Accumulate(AsmWordKind.String, " ")
    buildOperand opr1 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr2 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr3 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr4 builder
    builder.Accumulate(AsmWordKind.String, ", ")
    buildOperand opr5 builder

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder
  buildOperands ins builder

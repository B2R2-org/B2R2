(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>

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

module internal B2R2.FrontEnd.ARM64.Disasm

open B2R2
open System.Text

let addrToString (addr: Addr) wordSize verbose =
  if verbose then
    if wordSize = WordSize.Bit32 then addr.ToString("X8") + ": "
    else addr.ToString("X16") + ": "
  else ""

let condToString = function
  | Some EQ -> "eq"
  | Some NE -> "ne"
  | Some CS -> "cs"
  | Some HS -> "hs"
  | Some CC -> "cc"
  | Some LO -> "lo"
  | Some MI -> "mi"
  | Some PL -> "pl"
  | Some VS -> "vs"
  | Some VC -> "vc"
  | Some HI -> "hi"
  | Some LS -> "ls"
  | Some GE -> "ge"
  | Some LT -> "lt"
  | Some GT -> "gt"
  | Some LE -> "le"
  | Some AL -> ""
  | Some NV -> "nv"
  | None -> ""

let opCodeToString = function
  | Opcode.ABS -> "abs"
  | Opcode.ADC -> "adc"
  | Opcode.ADCS -> "adcs"
  | Opcode.ADD -> "add"
  | Opcode.ADDHN -> "addhn"
  | Opcode.ADDHN2 -> "addhn2"
  | Opcode.ADDP -> "addp"
  | Opcode.ADDS -> "adds"
  | Opcode.ADDV -> "addv"
  | Opcode.ADR -> "adr"
  | Opcode.ADRP -> "adrp"
  | Opcode.AESD -> "aesd"
  | Opcode.AESE -> "aese"
  | Opcode.AESIMC -> "aesimc"
  | Opcode.AESMC -> "aesmc"
  | Opcode.AND -> "and"
  | Opcode.ANDS -> "ands"
  | Opcode.ASR -> "asr"
  | Opcode.ASRV -> "asrv"
  | Opcode.B -> "b"
  | Opcode.BAL -> "b.al"
  | Opcode.BCC -> "b.cc"
  | Opcode.BCS -> "b.cs"
  | Opcode.BEQ -> "b.eq"
  | Opcode.BFI -> "bfi"
  | Opcode.BFM -> "bfm"
  | Opcode.BFXIL -> "bfxil"
  | Opcode.BGE -> "b.ge"
  | Opcode.BGT -> "b.gt"
  | Opcode.BHI -> "b.hi"
  | Opcode.BHS -> "b.hs"
  | Opcode.BIC -> "bic"
  | Opcode.BICS -> "bics"
  | Opcode.BIF -> "bif"
  | Opcode.BIT -> "bit"
  | Opcode.BL -> "bl"
  | Opcode.BLE -> "b.le"
  | Opcode.BLO -> "b.lo"
  | Opcode.BLR -> "blr"
  | Opcode.BLS -> "b.ls"
  | Opcode.BLT -> "b.lt"
  | Opcode.BMI -> "b.mi"
  | Opcode.BNE -> "b.ne"
  | Opcode.BNV -> "b.nv"
  | Opcode.BPL -> "b.pl"
  | Opcode.BR -> "br"
  | Opcode.BRK -> "brk"
  | Opcode.BSL -> "bsl"
  | Opcode.BVC -> "b.vc"
  | Opcode.BVS -> "b.vs"
  | Opcode.CBNZ -> "cbnz"
  | Opcode.CBZ -> "cbz"
  | Opcode.CCMN -> "ccmn"
  | Opcode.CCMP -> "ccmp"
  | Opcode.CINC -> "cinc"
  | Opcode.CINV -> "cinv"
  | Opcode.CLREX -> "clrex"
  | Opcode.CLS -> "cls"
  | Opcode.CLZ -> "clz"
  | Opcode.CMEQ -> "cmeq"
  | Opcode.CMGE -> "cmge"
  | Opcode.CMGT -> "cmgt"
  | Opcode.CMHI -> "cmhi"
  | Opcode.CMHS -> "cmhs"
  | Opcode.CMLE -> "cmle"
  | Opcode.CMLT -> "cmlt"
  | Opcode.CMN -> "cmn"
  | Opcode.CMP -> "cmp"
  | Opcode.CMTST -> "cmtst"
  | Opcode.CNEG -> "cneg"
  | Opcode.CNT -> "cnt"
  | Opcode.CRC32B -> "crc32b"
  | Opcode.CRC32CB -> "crc32cb"
  | Opcode.CRC32CH -> "crc32ch"
  | Opcode.CRC32CW -> "crc32cw"
  | Opcode.CRC32CX -> "crc32cx"
  | Opcode.CRC32H -> "crc32h"
  | Opcode.CRC32W -> "crc32w"
  | Opcode.CRC32X -> "crc32x"
  | Opcode.CSEL -> "csel"
  | Opcode.CSET -> "cset"
  | Opcode.CSETM -> "csetm"
  | Opcode.CSINC -> "csinc"
  | Opcode.CSINV -> "csinv"
  | Opcode.CSNEG -> "csneg"
  | Opcode.DC -> "dc"
  | Opcode.DCPS1 -> "dcps1"
  | Opcode.DCPS2 -> "dcps2"
  | Opcode.DCPS3 -> "dcps3"
  | Opcode.DMB -> "dmb"
  | Opcode.DRPS -> "drps"
  | Opcode.DSB -> "dsb"
  | Opcode.DUP -> "dup"
  | Opcode.EON -> "eon"
  | Opcode.EOR -> "eor"
  | Opcode.ERET -> "eret"
  | Opcode.EXT -> "ext"
  | Opcode.EXTR -> "extr"
  | Opcode.FABD -> "fabd"
  | Opcode.FABS -> "fabs"
  | Opcode.FACGE -> "facge"
  | Opcode.FACGT -> "facgt"
  | Opcode.FADD -> "fadd"
  | Opcode.FADDP -> "faddp"
  | Opcode.FCCMP -> "fccmp"
  | Opcode.FCCMPE -> "fccmpe"
  | Opcode.FCMEQ -> "fcmeq"
  | Opcode.FCMGE -> "fcmge"
  | Opcode.FCMGT -> "fcmgt"
  | Opcode.FCMLE -> "fcmle"
  | Opcode.FCMLT -> "fcmlt"
  | Opcode.FCMP -> "fcmp"
  | Opcode.FCMPE -> "fcmpe"
  | Opcode.FCSEL -> "fcsel"
  | Opcode.FCVT -> "fcvt"
  | Opcode.FCVTAS -> "fcvtas"
  | Opcode.FCVTAU -> "fcvtau"
  | Opcode.FCVTL -> "fcvtl"
  | Opcode.FCVTL2 -> "fcvtl2"
  | Opcode.FCVTMS -> "fcvtms"
  | Opcode.FCVTMU -> "fcvtmu"
  | Opcode.FCVTN -> "fcvtn"
  | Opcode.FCVTN2 -> "fcvtn2"
  | Opcode.FCVTNS -> "fcvtns"
  | Opcode.FCVTNU -> "fcvtnu"
  | Opcode.FCVTPS -> "fcvtps"
  | Opcode.FCVTPU -> "fcvtpu"
  | Opcode.FCVTXN -> "fcvtxn"
  | Opcode.FCVTXN2 -> "fcvtxn2"
  | Opcode.FCVTZS -> "fcvtzs"
  | Opcode.FCVTZU -> "fcvtzu"
  | Opcode.FDIV -> "fdiv"
  | Opcode.FMADD -> "fmadd"
  | Opcode.FMAX -> "fmax"
  | Opcode.FMAXNM -> "fmaxnm"
  | Opcode.FMAXNMP -> "fmaxnmp"
  | Opcode.FMAXNMV -> "fmaxnmv"
  | Opcode.FMAXP -> "fmaxp"
  | Opcode.FMAXV -> "fmaxv"
  | Opcode.FMIN -> "fmin"
  | Opcode.FMINNM -> "fminnm"
  | Opcode.FMINNMP -> "fminnmp"
  | Opcode.FMINNMV -> "fminnmv"
  | Opcode.FMINP -> "fminp"
  | Opcode.FMINV -> "fminv"
  | Opcode.FMLA -> "fmla"
  | Opcode.FMLS -> "fmls"
  | Opcode.FMOV -> "fmov"
  | Opcode.FMSUB -> "fmsub"
  | Opcode.FMUL -> "fmul"
  | Opcode.FMULX -> "fmulx"
  | Opcode.FNEG -> "fneg"
  | Opcode.FNMADD -> "fnmadd"
  | Opcode.FNMSUB -> "fnmsub"
  | Opcode.FNMUL -> "fnmul"
  | Opcode.FRECPE -> "frecpe"
  | Opcode.FRECPS -> "frecps"
  | Opcode.FRECPX -> "frecpx"
  | Opcode.FRINTA -> "frinta"
  | Opcode.FRINTI -> "frinti"
  | Opcode.FRINTM -> "frintm"
  | Opcode.FRINTN -> "frintn"
  | Opcode.FRINTP -> "frintp"
  | Opcode.FRINTX -> "frintx"
  | Opcode.FRINTZ -> "frintz"
  | Opcode.FRSQRTE -> "frsqrte"
  | Opcode.FRSQRTS -> "frsqrts"
  | Opcode.FSQRT -> "fsqrt"
  | Opcode.FSUB -> "fsub"
  | Opcode.HINT -> "hint"
  | Opcode.HLT -> "hlt"
  | Opcode.HVC -> "hvc"
  | Opcode.INS -> "ins"
  | Opcode.ISB -> "isb"
  | Opcode.LD1 -> "ld1"
  | Opcode.LD1R -> "ld1r"
  | Opcode.LD2 -> "ld2"
  | Opcode.LD2R -> "ld2r"
  | Opcode.LD3 -> "ld3"
  | Opcode.LD3R -> "ld3r"
  | Opcode.LD4 -> "ld4"
  | Opcode.LD4R -> "ld4r"
  | Opcode.LDAR -> "ldar"
  | Opcode.LDARB -> "ldarb"
  | Opcode.LDARH -> "ldarh"
  | Opcode.LDAXP -> "ldaxp"
  | Opcode.LDAXR -> "ldaxr"
  | Opcode.LDAXRB -> "ldaxrb"
  | Opcode.LDAXRH -> "ldaxrh"
  | Opcode.LDNP -> "ldnp"
  | Opcode.LDP -> "ldp"
  | Opcode.LDPSW -> "ldpsw"
  | Opcode.LDR -> "ldr"
  | Opcode.LDRB -> "ldrb"
  | Opcode.LDRH -> "ldrh"
  | Opcode.LDRSB -> "ldrsb"
  | Opcode.LDRSH -> "ldrsh"
  | Opcode.LDRSW -> "ldrsw"
  | Opcode.LDTR -> "ldtr"
  | Opcode.LDTRB -> "ldtrb"
  | Opcode.LDTRH -> "ldtrh"
  | Opcode.LDTRSB -> "ldtrsb"
  | Opcode.LDTRSH -> "ldtrsh"
  | Opcode.LDTRSW -> "ldtrsw"
  | Opcode.LDUR -> "ldur"
  | Opcode.LDURB -> "ldurb"
  | Opcode.LDURH -> "ldurh"
  | Opcode.LDURSB -> "ldursb"
  | Opcode.LDURSH -> "ldursh"
  | Opcode.LDURSW -> "ldursw"
  | Opcode.LDXP -> "ldxp"
  | Opcode.LDXR -> "ldxr"
  | Opcode.LDXRB -> "ldxrb"
  | Opcode.LDXRH -> "ldxrh"
  | Opcode.LSL -> "lsl"
  | Opcode.LSLV -> "lslv"
  | Opcode.LSR -> "lsr"
  | Opcode.LSRV -> "lsrv"
  | Opcode.MADD -> "madd"
  | Opcode.MLA -> "mla"
  | Opcode.MLS -> "mls"
  | Opcode.MNEG -> "mneg"
  | Opcode.MOV -> "mov"
  | Opcode.MOVI -> "movi"
  | Opcode.MOVK -> "movk"
  | Opcode.MOVN -> "movn"
  | Opcode.MOVZ -> "movz"
  | Opcode.MRS -> "mrs"
  | Opcode.MSR -> "msr"
  | Opcode.MSUB -> "msub"
  | Opcode.MUL -> "mul"
  | Opcode.MVN -> "mvn"
  | Opcode.MVNI -> "mvni"
  | Opcode.NEG -> "neg"
  | Opcode.NEGS -> "negs"
  | Opcode.NGC -> "ngc"
  | Opcode.NGCS -> "ngcs"
  | Opcode.NOP -> "nop"
  | Opcode.NOT -> "not"
  | Opcode.ORN -> "orn"
  | Opcode.ORR -> "orr"
  | Opcode.PMUL -> "pmul"
  | Opcode.PMULL -> "pmull"
  | Opcode.PMULL2 -> "pmull2"
  | Opcode.PRFM -> "prfm"
  | Opcode.PRFUM -> "prfum"
  | Opcode.RADDHN -> "raddhn"
  | Opcode.RADDHN2 -> "raddhn2"
  | Opcode.RBIT -> "rbit"
  | Opcode.RET -> "ret"
  | Opcode.REV -> "rev"
  | Opcode.REV16 -> "rev16"
  | Opcode.REV32 -> "rev32"
  | Opcode.REV64 -> "rev64"
  | Opcode.ROR -> "ror"
  | Opcode.RORV -> "rorv"
  | Opcode.RSHRN -> "rshrn"
  | Opcode.RSHRN2 -> "rshrn2"
  | Opcode.RSUBHN -> "rsubhn"
  | Opcode.RSUBHN2 -> "rsubhn2"
  | Opcode.SABA -> "saba"
  | Opcode.SABAL -> "sabal"
  | Opcode.SABAL2 -> "sabal2"
  | Opcode.SABD -> "sabd"
  | Opcode.SABDL -> "sabdl"
  | Opcode.SABDL2 -> "sabdl2"
  | Opcode.SADALP -> "sadalp"
  | Opcode.SADDL -> "saddl"
  | Opcode.SADDL2 -> "saddl2"
  | Opcode.SADDLP -> "saddlp"
  | Opcode.SADDLV -> "saddlv"
  | Opcode.SADDW -> "saddw"
  | Opcode.SADDW2 -> "saddw2"
  | Opcode.SBC -> "sbc"
  | Opcode.SBCS -> "sbcs"
  | Opcode.SBFIZ -> "sbfiz"
  | Opcode.SBFM -> "sbfm "
  | Opcode.SBFX -> "sbfx"
  | Opcode.SCVTF -> "scvtf"
  | Opcode.SDIV -> "sdiv"
  | Opcode.SEV -> "sev"
  | Opcode.SEVL -> "sevl"
  | Opcode.SHA1C -> "sha1c"
  | Opcode.SHA1H -> "sha1h"
  | Opcode.SHA1M -> "sha1m"
  | Opcode.SHA1P -> "sha1p"
  | Opcode.SHA1SU0 -> "sha1su0"
  | Opcode.SHA1SU1 -> "sha1su1"
  | Opcode.SHA256H -> "sha256h"
  | Opcode.SHA256H2 -> "sha256h2"
  | Opcode.SHA256SU0 -> "sha256su0"
  | Opcode.SHA256SU1 -> "sha256su1"
  | Opcode.SHADD -> "shadd"
  | Opcode.SHL -> "shl"
  | Opcode.SHLL -> "shll"
  | Opcode.SHLL2 -> "shll2"
  | Opcode.SHRN -> "shrn"
  | Opcode.SHRN2 -> "shrn2"
  | Opcode.SHSUB -> "shsub"
  | Opcode.SLI -> "sli"
  | Opcode.SMADDL -> "smaddl"
  | Opcode.SMAX -> "smax"
  | Opcode.SMAXP -> "smaxp"
  | Opcode.SMAXV -> "smaxv"
  | Opcode.SMC -> "smc"
  | Opcode.SMIN -> "smin"
  | Opcode.SMINP -> "sminp"
  | Opcode.SMINV -> "sminv"
  | Opcode.SMLAL -> "smlal"
  | Opcode.SMLAL2 -> "smlal2"
  | Opcode.SMLSL -> "smlsl"
  | Opcode.SMLSL2 -> "smlsl2"
  | Opcode.SMNEGL -> "smnegl"
  | Opcode.SMOV -> "smov"
  | Opcode.SMSUBL -> "smsubl"
  | Opcode.SMULH -> "smulh"
  | Opcode.SMULL -> "smull"
  | Opcode.SMULL2 -> "smull2"
  | Opcode.SQABS -> "sqabs"
  | Opcode.SQADD -> "sqadd"
  | Opcode.SQDMLAL -> "sqdmlal"
  | Opcode.SQDMLAL2 -> "sqdmlal2"
  | Opcode.SQDMLSL -> "sqdmlsl"
  | Opcode.SQDMLSL2 -> "sqdmlsl2"
  | Opcode.SQDMULH -> "sqdmulh"
  | Opcode.SQDMULL -> "sqdmull"
  | Opcode.SQDMULL2 -> "sqdmull2"
  | Opcode.SQNEG -> "sqneg"
  | Opcode.SQRDMULH -> "sqrdmulh"
  | Opcode.SQRSHL -> "sqrshl"
  | Opcode.SQRSHRN -> "sqrshrn"
  | Opcode.SQRSHRN2 -> "sqrshrn2"
  | Opcode.SQRSHRUN -> "sqrshrun"
  | Opcode.SQRSHRUN2 -> "sqrshrun2"
  | Opcode.SQSHL -> "sqshl"
  | Opcode.SQSHLU -> "sqshlu"
  | Opcode.SQSHRN -> "sqshrn"
  | Opcode.SQSHRN2 -> "sqshrn2"
  | Opcode.SQSHRUN -> "sqshrun"
  | Opcode.SQSHRUN2 -> "sqshrun2"
  | Opcode.SQSUB -> "sqsub"
  | Opcode.SQXTN -> "sqxtn"
  | Opcode.SQXTN2 -> "sqxtn2"
  | Opcode.SQXTUN -> "sqxtun"
  | Opcode.SQXTUN2 -> "sqxtun2"
  | Opcode.SRHADD -> "srhadd"
  | Opcode.SRI -> "sri"
  | Opcode.SRSHL -> "srshl"
  | Opcode.SRSHR -> "srshr"
  | Opcode.SRSRA -> "srsra"
  | Opcode.SSHL -> "sshl"
  | Opcode.SSHLL -> "sshll"
  | Opcode.SSHLL2 -> "sshll2"
  | Opcode.SSHR -> "sshr"
  | Opcode.SSRA -> "ssra"
  | Opcode.SSUBL -> "ssubl"
  | Opcode.SSUBL2 -> "ssubl2"
  | Opcode.SSUBW  -> "ssubw"
  | Opcode.SSUBW2 -> "ssubw2"
  | Opcode.ST1 -> "st1"
  | Opcode.ST2 -> "st2"
  | Opcode.ST3 -> "st3"
  | Opcode.ST4 -> "st4"
  | Opcode.STLR -> "stlr"
  | Opcode.STLRB -> "stlrb"
  | Opcode.STLRH -> "stlrh"
  | Opcode.STLXP -> "stlxp"
  | Opcode.STLXR -> "stlxr"
  | Opcode.STLXRB -> "stlxrb"
  | Opcode.STLXRH -> "stlxrh"
  | Opcode.STNP -> "stnp"
  | Opcode.STP -> "stp"
  | Opcode.STR -> "str"
  | Opcode.STRB -> "strb"
  | Opcode.STRH -> "strh"
  | Opcode.STTR -> "sttr"
  | Opcode.STTRB -> "sttrb"
  | Opcode.STTRH -> "sttrh"
  | Opcode.STUR -> "stur"
  | Opcode.STURB -> "sturb"
  | Opcode.STURH -> "sturh"
  | Opcode.STXP -> "stxp"
  | Opcode.STXR -> "stxr"
  | Opcode.STXRB -> "stxrb"
  | Opcode.STXRH -> "stxrh"
  | Opcode.SUB -> "sub"
  | Opcode.SUBHN -> "subhn"
  | Opcode.SUBHN2 -> "subhn2"
  | Opcode.SUBS -> "subs"
  | Opcode.SUQADD -> "suqadd"
  | Opcode.SVC -> "svc"
  | Opcode.SXTB -> "sxtb"
  | Opcode.SXTH -> "sxth"
  | Opcode.SXTW -> "sxtw"
  | Opcode.SYS -> "sys"
  | Opcode.SYSL -> "sysl"
  | Opcode.TBL -> "tbl"
  | Opcode.TBNZ -> "tbnz"
  | Opcode.TBX -> "tbx"
  | Opcode.TBZ -> "tbz"
  | Opcode.TRN1 -> "trn1"
  | Opcode.TRN2 -> "trn2"
  | Opcode.TST -> "tst"
  | Opcode.UABA -> "uaba"
  | Opcode.UABAL -> "uabal"
  | Opcode.UABAL2 -> "uabal2"
  | Opcode.UABD -> "uabd"
  | Opcode.UABDL -> "uabdl"
  | Opcode.UABDL2 -> "uabdl2"
  | Opcode.UADALP -> "uadalp"
  | Opcode.UADDL -> "uaddl"
  | Opcode.UADDL2 -> "uaddl2"
  | Opcode.UADDLP -> "uaddlp"
  | Opcode.UADDLV -> "uaddlv"
  | Opcode.UADDW -> "uaddw"
  | Opcode.UADDW2 -> "uaddw2"
  | Opcode.UBFIZ -> "ubfiz"
  | Opcode.UBFM -> "ubfm"
  | Opcode.UBFX -> "ubfx"
  | Opcode.UCVTF -> "ucvtf"
  | Opcode.UDIV -> "udiv"
  | Opcode.UHADD -> "uhadd"
  | Opcode.UHSUB -> "uhsub"
  | Opcode.UMADDL -> "umaddl"
  | Opcode.UMAX -> "umax"
  | Opcode.UMAXP -> "umaxp"
  | Opcode.UMAXV -> "umaxv"
  | Opcode.UMIN -> "umin"
  | Opcode.UMINP -> "uminp"
  | Opcode.UMINV -> "uminv"
  | Opcode.UMLAL -> "umlal"
  | Opcode.UMLAL2 -> "umlal2"
  | Opcode.UMLSL -> "umlsl"
  | Opcode.UMLSL2 -> "umlsl2"
  | Opcode.UMNEGL -> "umnegl"
  | Opcode.UMOV -> "umov"
  | Opcode.UMSUBL -> "umsubl"
  | Opcode.UMULH -> "umulh"
  | Opcode.UMULL -> "umull"
  | Opcode.UMULL2 -> "umull2"
  | Opcode.UQADD -> "uqadd"
  | Opcode.UQRSHL -> "uqrshl"
  | Opcode.UQRSHRN -> "uqrshrn"
  | Opcode.UQRSHRN2 -> "uqrshrn2"
  | Opcode.UQSHL -> "uqshl"
  | Opcode.UQSHRN -> "uqshrn"
  | Opcode.UQSHRN2 -> "uqshrn2"
  | Opcode.UQSUB -> "uqsub"
  | Opcode.UQXTN -> "uqxtn"
  | Opcode.UQXTN2 -> "uqxtn2"
  | Opcode.URECPE -> "urecpe"
  | Opcode.URHADD -> "urhadd"
  | Opcode.URSHL -> "urshl"
  | Opcode.URSHR -> "urshr"
  | Opcode.URSQRTE -> "ursqrte"
  | Opcode.URSRA -> "ursra"
  | Opcode.USHL -> "ushl"
  | Opcode.USHLL -> "ushll"
  | Opcode.USHLL2 -> "ushll2"
  | Opcode.USHR -> "ushr"
  | Opcode.USQADD -> "usqadd"
  | Opcode.USRA -> "usra"
  | Opcode.USUBL -> "usubl"
  | Opcode.USUBL2 -> "usubl2"
  | Opcode.USUBW -> "usubw"
  | Opcode.USUBW2 -> "usubw2"
  | Opcode.UXTB -> "uxtb"
  | Opcode.UXTH -> "uxth"
  | Opcode.UZP1 -> "uzp1"
  | Opcode.UZP2 -> "uzp2"
  | Opcode.WFE -> "wfe"
  | Opcode.WFI -> "wfi"
  | Opcode.XTN -> "xtn"
  | Opcode.XTN2 -> "xtn2"
  | Opcode.YIELD -> "yield"
  | Opcode.ZIP1 -> "zip1"
  | Opcode.ZIP2 -> "zip2"
  | _ -> failwith "Unknown opcode encountered."

let srtypeToString = function
  | SRTypeLSL -> "lsl"
  | SRTypeLSR -> "lsr"
  | SRTypeASR -> "asr"
  | SRTypeROR -> "ror"
  | SRTypeRRX -> "rrx"
  | SRTypeMSL -> "msl"

let regToString = function
  | R.X0 -> "x0"
  | R.X1 -> "x1"
  | R.X2 -> "x2"
  | R.X3 -> "x3"
  | R.X4 -> "x4"
  | R.X5 -> "x5"
  | R.X6 -> "x6"
  | R.X7 -> "x7"
  | R.X8 -> "x8"
  | R.X9 -> "x9"
  | R.X10 -> "x10"
  | R.X11 -> "x11"
  | R.X12 -> "x12"
  | R.X13 -> "x13"
  | R.X14 -> "x14"
  | R.X15 -> "x15"
  | R.X16 -> "x16"
  | R.X17 -> "x17"
  | R.X18 -> "x18"
  | R.X19 -> "x19"
  | R.X20 -> "x20"
  | R.X21 -> "x21"
  | R.X22 -> "x22"
  | R.X23 -> "x23"
  | R.X24 -> "x24"
  | R.X25 -> "x25"
  | R.X26 -> "x26"
  | R.X27 -> "x27"
  | R.X28 -> "x28"
  | R.X29 -> "x29"
  | R.X30 -> "x30"
  | R.XZR -> "xzr"
  | R.W0 -> "w0"
  | R.W1 -> "w1"
  | R.W2 -> "w2"
  | R.W3 -> "w3"
  | R.W4 -> "w4"
  | R.W5 -> "w5"
  | R.W6 -> "w6"
  | R.W7 -> "w7"
  | R.W8 -> "w8"
  | R.W9 -> "w9"
  | R.W10 -> "w10"
  | R.W11 -> "w11"
  | R.W12 -> "w12"
  | R.W13 -> "w13"
  | R.W14 -> "w14"
  | R.W15 -> "w15"
  | R.W16 -> "w16"
  | R.W17 -> "w17"
  | R.W18 -> "w18"
  | R.W19 -> "w19"
  | R.W20 -> "w20"
  | R.W21 -> "w21"
  | R.W22 -> "w22"
  | R.W23 -> "w23"
  | R.W24 -> "w24"
  | R.W25 -> "w25"
  | R.W26 -> "w26"
  | R.W27 -> "w27"
  | R.W28 -> "w28"
  | R.W29 -> "w29"
  | R.W30 -> "w30"
  | R.WZR -> "wzr"
  | R.SP -> "sp"
  | R.WSP -> "wsp"
  | R.PC -> "pc"
  | R.V0 -> "v0"
  | R.V1 -> "v1"
  | R.V2 -> "v2"
  | R.V3 -> "v3"
  | R.V4 -> "v4"
  | R.V5 -> "v5"
  | R.V6 -> "v6"
  | R.V7 -> "v7"
  | R.V8 -> "v8"
  | R.V9 -> "v9"
  | R.V10 -> "v10"
  | R.V11 -> "v11"
  | R.V12 -> "v12"
  | R.V13 -> "v13"
  | R.V14 -> "v14"
  | R.V15 -> "v15"
  | R.V16 -> "v16"
  | R.V17 -> "v17"
  | R.V18 -> "v18"
  | R.V19 -> "v19"
  | R.V20 -> "v20"
  | R.V21 -> "v21"
  | R.V22 -> "v22"
  | R.V23 -> "v23"
  | R.V24 -> "v24"
  | R.V25 -> "v25"
  | R.V26 -> "v26"
  | R.V27 -> "v27"
  | R.V28 -> "v28"
  | R.V29 -> "v29"
  | R.V30 -> "v30"
  | R.V31 -> "v31"
  | R.B0 -> "b0"
  | R.B1 -> "b1"
  | R.B2 -> "b2"
  | R.B3 -> "b3"
  | R.B4 -> "b4"
  | R.B5 -> "b5"
  | R.B6 -> "b6"
  | R.B7 -> "b7"
  | R.B8 -> "b8"
  | R.B9 -> "b9"
  | R.B10 -> "b10"
  | R.B11 -> "b11"
  | R.B12 -> "b12"
  | R.B13 -> "b13"
  | R.B14 -> "b14"
  | R.B15 -> "b15"
  | R.B16 -> "b16"
  | R.B17 -> "b17"
  | R.B18 -> "b18"
  | R.B19 -> "b19"
  | R.B20 -> "b20"
  | R.B21 -> "b21"
  | R.B22 -> "b22"
  | R.B23 -> "b23"
  | R.B24 -> "b24"
  | R.B25 -> "b25"
  | R.B26 -> "b26"
  | R.B27 -> "b27"
  | R.B28 -> "b28"
  | R.B29 -> "b29"
  | R.B30 -> "b30"
  | R.B31 -> "b31"
  | R.H0 -> "h0"
  | R.H1 -> "h1"
  | R.H2 -> "h2"
  | R.H3 -> "h3"
  | R.H4 -> "h4"
  | R.H5 -> "h5"
  | R.H6 -> "h6"
  | R.H7 -> "h7"
  | R.H8 -> "h8"
  | R.H9 -> "h9"
  | R.H10 -> "h10"
  | R.H11 -> "h11"
  | R.H12 -> "h12"
  | R.H13 -> "h13"
  | R.H14 -> "h14"
  | R.H15 -> "h15"
  | R.H16 -> "h16"
  | R.H17 -> "h17"
  | R.H18 -> "h18"
  | R.H19 -> "h19"
  | R.H20 -> "h20"
  | R.H21 -> "h21"
  | R.H22 -> "h22"
  | R.H23 -> "h23"
  | R.H24 -> "h24"
  | R.H25 -> "h25"
  | R.H26 -> "h26"
  | R.H27 -> "h27"
  | R.H28 -> "h28"
  | R.H29 -> "h29"
  | R.H30 -> "h30"
  | R.H31 -> "h31"
  | R.S0 -> "s0"
  | R.S1 -> "s1"
  | R.S2 -> "s2"
  | R.S3 -> "s3"
  | R.S4 -> "s4"
  | R.S5 -> "s5"
  | R.S6 -> "s6"
  | R.S7 -> "s7"
  | R.S8 -> "s8"
  | R.S9 -> "s9"
  | R.S10 -> "s10"
  | R.S11 -> "s11"
  | R.S12 -> "s12"
  | R.S13 -> "s13"
  | R.S14 -> "s14"
  | R.S15 -> "s15"
  | R.S16 -> "s16"
  | R.S17 -> "s17"
  | R.S18 -> "s18"
  | R.S19 -> "s19"
  | R.S20 -> "s20"
  | R.S21 -> "s21"
  | R.S22 -> "s22"
  | R.S23 -> "s23"
  | R.S24 -> "s24"
  | R.S25 -> "s25"
  | R.S26 -> "s26"
  | R.S27 -> "s27"
  | R.S28 -> "s28"
  | R.S29 -> "s29"
  | R.S30 -> "s30"
  | R.S31 -> "s31"
  | R.D0 -> "d0"
  | R.D1 -> "d1"
  | R.D2 -> "d2"
  | R.D3 -> "d3"
  | R.D4 -> "d4"
  | R.D5 -> "d5"
  | R.D6 -> "d6"
  | R.D7 -> "d7"
  | R.D8 -> "d8"
  | R.D9 -> "d9"
  | R.D10 -> "d10"
  | R.D11 -> "d11"
  | R.D12 -> "d12"
  | R.D13 -> "d13"
  | R.D14 -> "d14"
  | R.D15 -> "d15"
  | R.D16 -> "d16"
  | R.D17 -> "d17"
  | R.D18 -> "d18"
  | R.D19 -> "d19"
  | R.D20 -> "d20"
  | R.D21 -> "d21"
  | R.D22 -> "d22"
  | R.D23 -> "d23"
  | R.D24 -> "d24"
  | R.D25 -> "d25"
  | R.D26 -> "d26"
  | R.D27 -> "d27"
  | R.D28 -> "d28"
  | R.D29 -> "d29"
  | R.D30 -> "d30"
  | R.D31 -> "d31"
  | R.Q0 -> "q0"
  | R.Q1 -> "q1"
  | R.Q2 -> "q2"
  | R.Q3 -> "q3"
  | R.Q4 -> "q4"
  | R.Q5 -> "q5"
  | R.Q6 -> "q6"
  | R.Q7 -> "q7"
  | R.Q8 -> "q8"
  | R.Q9 -> "q9"
  | R.Q10 -> "q10"
  | R.Q11 -> "q11"
  | R.Q12 -> "q12"
  | R.Q13 -> "q13"
  | R.Q14 -> "q14"
  | R.Q15 -> "q15"
  | R.Q16 -> "q16"
  | R.Q17 -> "q17"
  | R.Q18 -> "q18"
  | R.Q19 -> "q19"
  | R.Q20 -> "q20"
  | R.Q21 -> "q21"
  | R.Q22 -> "q22"
  | R.Q23 -> "q23"
  | R.Q24 -> "q24"
  | R.Q25 -> "q25"
  | R.Q26 -> "q26"
  | R.Q27 -> "q27"
  | R.Q28 -> "q28"
  | R.Q29 -> "q29"
  | R.Q30 -> "q30"
  | R.Q31 -> "q31"
  | R.C0 -> "c0"
  | R.C1 -> "c1"
  | R.C2 -> "c2"
  | R.C3 -> "c3"
  | R.C4 -> "c4"
  | R.C5 -> "c5"
  | R.C6 -> "c6"
  | R.C7 -> "c7"
  | R.C8 -> "c8"
  | R.C9 -> "c9"
  | R.C10 -> "c10"
  | R.C11 -> "c11"
  | R.C12 -> "c12"
  | R.C13 -> "c13"
  | R.C14 -> "c14"
  | R.C15 -> "c15"
  | R.N -> "n"
  | R.Z -> "z"
  | R.C -> "c"
  | R.V -> "v"
  | R.ACTLREL1 -> "actlr_el1"
  | R.ACTLREL2 -> "actlr_el2"
  | R.ACTLREL3 -> "actlr_el3"
  | R.AFSR0EL1 -> "afsr0_el1"
  | R.AFSR0EL2 -> "afsr0_el2"
  | R.AFSR0EL3 -> "afsr0_el3"
  | R.AFSR1EL1 -> "afsr1_el1"
  | R.AFSR1EL2 -> "afsr1_el2"
  | R.AFSR1EL3 -> "afsr1_el3"
  | R.AIDREL1 -> "aidr_el1"
  | R.AMAIREL1 -> "amair_el1"
  | R.AMAIREL2 -> "amair_el2"
  | R.AMAIREL3 -> "amair_el3"
  | R.CCSIDREL1 -> "ccsidr_el1"
  | R.CLIDREL1 -> "clidr_el1"
  | R.CONTEXTIDREL1 -> "contextidr_el1"
  | R.CPACREL1 -> "cpacr_el1"
  | R.CPTREL2 -> "cptr_el2"
  | R.CPTREL3 -> "cptr_el3"
  | R.CSSELREL1 -> "csselr_el1"
  | R.CTREL0 -> "ctr_el0"
  | R.DACR32EL2 -> "dacr32_el2"
  | R.DCZIDEL0 -> "dczid_el0"
  | R.ESREL1 -> "esr_el1"
  | R.ESREL2 -> "esr_el2"
  | R.ESREL3 -> "esr_el3"
  | R.HPFAREL2 -> "hpfar_el2"
  | R.TPIDREL0 -> "tpidr_el0"
  | R.FPCR -> "fpcr"
  | R.FPSR -> "fpsr"
  | _ -> "UnknowReg"

let simdVectorToString = function
  | VecB -> "b"
  | VecH -> "h"
  | VecS -> "s"
  | VecD -> "d"
  | EightB -> "8b"
  | SixteenB -> "16b"
  | FourH -> "4h"
  | EightH -> "8h"
  | TwoS -> "2s"
  | FourS -> "4s"
  | OneD -> "1d"
  | TwoD -> "2d"
  | OneQ -> "1q"

let simdFPRegToString simdOpr (sb: StringBuilder) =
  match simdOpr with
  | SIMDFPScalarReg sReg -> sb.Append (regToString sReg)
  | SIMDVecReg (reg, vec) ->
    let sb = (sb.Append (regToString reg)).Append (".")
    sb.Append (simdVectorToString vec)
  | SIMDVecRegWithIdx (reg, vec, _) ->
    let sb = (sb.Append (regToString reg)).Append (".")
    sb.Append (simdVectorToString vec)

let finalSimdOpr s isList (sb: StringBuilder) =
  let sb = if isList then sb.Append (" }") else sb
  match s with
  | SIMDVecReg _ -> sb
  | SIMDVecRegWithIdx (_, _, idx) ->
    ((sb.Append ("[")).Append (string idx)).Append ("]")
  | SIMDFPScalarReg _ -> sb

let simdToString simdOprs (sb: StringBuilder) =
  match simdOprs with
  (* SIMD&FP register *)
  | SFReg s -> simdFPRegToString s sb |> finalSimdOpr s false
  (* SIMD vector register list or SIMD vector element list *)
  | OneReg s -> simdFPRegToString s (sb.Append ("{ ")) |> finalSimdOpr s true
  | TwoRegs (s1, s2) ->
    let sb = simdFPRegToString s1 (sb.Append ("{ "))
    simdFPRegToString s2 (sb.Append (", ")) |> finalSimdOpr s1 true
  | ThreeRegs (s1, s2, s3) ->
    let sb = simdFPRegToString s1 (sb.Append ("{ "))
    let sb = simdFPRegToString s2 (sb.Append (", "))
    simdFPRegToString s3 (sb.Append (", ")) |> finalSimdOpr s1 true
  | FourRegs (s1, _, _, s4) ->
    let sb = simdFPRegToString s1 (sb.Append ("{ "))
    simdFPRegToString s4 (sb.Append (" - ")) |> finalSimdOpr s1 true

let immToString (imm: int64) (sb: StringBuilder) =
  ((sb.Append ("#")).Append ("0x")).Append (imm.ToString ("X"))

let fpImmToString (fp: float) (sb: StringBuilder) =
  (sb.Append ("#")).Append (fp.ToString ("N8"))

let nzcvToString (imm: uint8) (sb: StringBuilder) =
  ((sb.Append ("#")).Append ("0x")).Append (imm.ToString ("X"))

let amountToString amount (sb: StringBuilder) =
  match amount with
  | Imm i -> immToString i sb
  | Reg r -> sb.Append (regToString r)

let shiftToString shift (sb: StringBuilder) =
  match shift with
  | _, Imm 0L -> sb.Remove (sb.Length - 2, 2)
  | s, amt -> (sb.Append (srtypeToString s)).Append (" ") |> amountToString amt

let extToString = function
  | ExtUXTB -> "uxtb"
  | ExtUXTH -> "uxth"
  | ExtUXTW -> "uxtw"
  | ExtUXTX -> "uxtx"
  | ExtSXTB -> "sxtb"
  | ExtSXTH -> "sxth"
  | ExtSXTW -> "sxtw"
  | ExtSXTX -> "sxtx"

let extRegToString regOff (sb: StringBuilder) =
  match regOff with
  | (ext, None) | (ext, Some 0L) -> sb.Append (extToString ext)
  | (ext, Some i) ->
    ((sb.Append (extToString ext)).Append (" #")).Append (i.ToString ("X"))

let regOffString regOff sb =
  match regOff with
  | ShiftOffset regOff -> shiftToString regOff sb
  | ExtRegOffset regOff -> extRegToString regOff sb

let delimPostIdx = function
  | PostIdxMode _ -> "], "
  | _ -> ", "

let processAddrExn64 ins addr =
  match ins.Opcode with
  | Opcode.ADRP -> addr &&& 0xFFFFFFFFFFFFF000UL
  | _ -> addr

let immOffsetToString i addr mode offset (sb: StringBuilder) =
  match offset with
  | BaseOffset (reg, None) | BaseOffset (reg, Some 0L) ->
    sb.Append (regToString reg)
  | BaseOffset (reg, Some imm) ->
    ((sb.Append (regToString reg)).Append (delimPostIdx mode))
    |> immToString imm
  | Lbl imm -> (* FIXME *)
    let sb = sb.Append ("0x")
    let addr = processAddrExn64 i addr
    sb.Append ((int64 addr + imm).ToString ("x"))
    (* alternative : [PC, imm] *)

let regOffsetToString mode offset (sb: StringBuilder) =
  match offset with
  | r1, r2, Some regOff ->
    let sb = (sb.Append (regToString r1)).Append (", ")
    (sb.Append (regToString r2)).Append (", ") |> regOffString regOff
  | r1, r2, None ->
    ((sb.Append (regToString r1)).Append (delimPostIdx mode))
      .Append (regToString r2)

let postBracket mode (sb: StringBuilder) =
  match mode with
  | BaseMode _ -> sb.Append ("]")
  | PreIdxMode _ -> sb.Append ("]!")
  | PostIdxMode _ -> sb
  | LiteralMode _ -> sb

let offsetToString i addr mode offset (sb: StringBuilder) =
  match offset with
  | ImmOffset offset -> immOffsetToString i addr mode offset sb
  | RegOffset (r1, r2, offset) -> regOffsetToString mode (r1, r2, offset) sb
  |> postBracket mode

let memToString insInfo addr mode (sb: StringBuilder) =
  match mode with
  | LiteralMode offset ->
    offsetToString insInfo addr mode offset sb
  | BaseMode off | PreIdxMode off | PostIdxMode off ->
    offsetToString insInfo addr mode off (sb.Append ("["))

let optToString = function
  | SY -> "sy"
  | ST -> "st"
  | LD -> "ld"
  | ISH -> "ish"
  | ISHST -> "ishst"
  | ISHLD -> "ishld"
  | NSH -> "nsh"
  | NSHST -> "nshst"
  | NSHLD -> "nshld"
  | OSH -> "osh"
  | OSHST -> "oshst"
  | OSHLD -> "oshld"

let pStToString = function
  | SPSEL -> "spsel"
  | DAIFSET -> "daifset"
  | DAIFCLR -> "daifclr"

let prfOpToString = function
  | PLDL1KEEP -> "pldl1keep"
  | PLDL1STRM -> "pldl1strm"
  | PLDL2KEEP -> "pldl2keep"
  | PLDL2STRM -> "pldl2strm"
  | PLDL3KEEP -> "pldl3keep"
  | PLDL3STRM -> "pldl3strm"
  | PSTL1KEEP -> "pstl1keep"
  | PSTL1STRM -> "pstl1strm"
  | PSTL2KEEP -> "pstl2keep"
  | PSTL2STRM -> "pstl2strm"
  | PSTL3KEEP -> "pstl3keep"
  | PSTL3STRM -> "pstl3strm"
  | PLIL1KEEP -> "plil1keep"
  | PLIL1STRM -> "plil1strm"
  | PLIL2KEEP -> "plil2keep"
  | PLIL2STRM -> "plil2strm"
  | PLIL3KEEP -> "plil3keep"
  | PLIL3STRM -> "plil3strm"

let fBitsToString = function
  | f -> "#" + string f

let idxToString = function
  | i -> string i

let lsbToString = function
  | l -> "#" + string l

let isRET ins = ins.Opcode = Opcode.RET

let dcOprToString = function
  | IVAC -> "ivac"
  | ISW -> "isw"
  | CSW -> "csw"
  | CISW -> "cisw"
  | ZVA -> "zva"
  | CVAC -> "cvac"
  | CVAU -> "cvau"
  | CIVAC -> "civac"

let sysOprToString = function
  | DCOpr dc -> dcOprToString dc

let oprToString i addr (sb: StringBuilder) = function
  | Register reg when isRET i && reg = R.X30 -> sb.Remove (sb.Length - 2, 2)
  | Register reg -> sb.Append (regToString reg)
  | SIMDOpr simdOpr -> simdToString simdOpr sb
  | Immediate imm -> immToString imm sb
  | FPImmediate fp -> fpImmToString fp sb
  | NZCV ui8 -> nzcvToString ui8 sb
  | Shift s -> shiftToString s sb
  | ExtReg (Some regOffset) -> regOffString regOffset sb
  | ExtReg None -> sb.Remove (sb.Length - 2, 2)
  | Memory mode -> memToString i addr mode sb
  | Option opt -> sb.Append (optToString opt)
  | Pstate p -> sb.Append (pStToString p)
  | PrfOp e1 -> sb.Append (prfOpToString e1)
  | Cond c -> sb.Append (condToString (Some c))
  | Fbits ui8 -> sb.Append (fBitsToString ui8)
  | LSB ui8 -> sb.Append (lsbToString ui8)
  | SysOpr sys -> sb.Append (sysOprToString sys)

let inline printAddr (addr: Addr) wordSz verbose (sb: StringBuilder) =
  if not verbose then sb
  else
    if wordSz = WordSize.Bit32 then sb.Append(addr.ToString("X8")).Append(": ")
    else sb.Append(addr.ToString("X16")).Append(": ")

let inline printOpcode ins (sb: StringBuilder) =
  sb.Append (opCodeToString ins.Opcode)

let inline printCond ins (sb: StringBuilder) =
  sb.Append (condToString ins.Condition)

let printOprs insInfo pc _wordSize (sb: StringBuilder) =
  let toStrFn = oprToString insInfo pc
  match insInfo.Operands with
  | NoOperand -> sb
  | OneOperand opr ->
    toStrFn (sb.Append ("  ")) opr
  | TwoOperands (opr1, opr2) ->
    let sb = toStrFn (sb.Append ("  ")) opr1
    toStrFn (sb.Append (", ")) opr2
  | ThreeOperands (opr1, opr2, opr3) ->
    let sb = toStrFn (sb.Append ("  ")) opr1
    let sb = toStrFn (sb.Append (", ")) opr2
    toStrFn (sb.Append (", ")) opr3
  | FourOperands (opr1, opr2, opr3, opr4) ->
    let sb = toStrFn (sb.Append ("  ")) opr1
    let sb = toStrFn (sb.Append (", ")) opr2
    let sb = toStrFn (sb.Append (", ")) opr3
    toStrFn (sb.Append (", ")) opr4
  | FiveOperands (opr1, opr2, opr3, opr4, opr5) ->
    let sb = toStrFn (sb.Append ("  ")) opr1
    let sb = toStrFn (sb.Append (", ")) opr2
    let sb = toStrFn (sb.Append (", ")) opr3
    let sb = toStrFn (sb.Append (", ")) opr4
    toStrFn (sb.Append (", ")) opr5

let disasm showAddr wordSize ins =
  let pc = ins.Address
  let sb = StringBuilder ()
  let sb = printAddr pc wordSize showAddr sb
  let sb = printOpcode ins sb
  let sb = printCond ins sb
  let sb = printOprs ins pc wordSize sb
  sb.ToString ()

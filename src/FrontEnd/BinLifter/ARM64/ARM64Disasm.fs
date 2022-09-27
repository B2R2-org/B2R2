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

module internal B2R2.FrontEnd.BinLifter.ARM64.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

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
  | Opcode.DCCGDSW -> "dccgdsw"
  | Opcode.DCCGDVAC -> "dccgdvac"
  | Opcode.DCCGDVADP -> "dccgdvadp"
  | Opcode.DCCGDVAP -> "dccgdvap"
  | Opcode.DCCGSW -> "dccgsw"
  | Opcode.DCCGVAC -> "dccgvac"
  | Opcode.DCCGVADP -> "dccgvadp"
  | Opcode.DCCGVAP -> "dccgvap"
  | Opcode.DCCIGDSW -> "dccigdsw"
  | Opcode.DCCIGDVAC -> "dccigdvac"
  | Opcode.DCCIGSW -> "dccigsw"
  | Opcode.DCCIGVAC -> "dccigvac"
  | Opcode.DCCISW -> "dccisw"
  | Opcode.DCCIVAC -> "dccivac"
  | Opcode.DCCSW -> "dccsw"
  | Opcode.DCCVAC -> "dccvac"
  | Opcode.DCCVADP -> "dccvadp"
  | Opcode.DCCVAP -> "dccvap"
  | Opcode.DCCVAU -> "dccvau"
  | Opcode.DCGVA -> "dcgva"
  | Opcode.DCGZVA -> "dcgzva"
  | Opcode.DCIGDSW -> "dcigdsw"
  | Opcode.DCIGDVAC -> "dcigdvac"
  | Opcode.DCIGSW -> "dcigsw"
  | Opcode.DCIGVAC -> "dcigvac"
  | Opcode.DCISW -> "dcisw"
  | Opcode.DCIVAC -> "dcivac"
  | Opcode.DCPS1 -> "dcps1"
  | Opcode.DCPS2 -> "dcps2"
  | Opcode.DCPS3 -> "dcps3"
  | Opcode.DCZVA -> "dczva"
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

let simdFPRegToString simdOpr (builder: DisasmBuilder<_>) =
  match simdOpr with
  | SIMDFPScalarReg sReg ->
    builder.Accumulate AsmWordKind.Variable (Register.toString sReg)
  | SIMDVecReg (reg, vec) ->
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)
    builder.Accumulate AsmWordKind.String ("." + simdVectorToString vec)
  | SIMDVecRegWithIdx (reg, vec, _) ->
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)
    builder.Accumulate AsmWordKind.String ("." + simdVectorToString vec)

let finalSIMDOpr s (builder: DisasmBuilder<_>) =
  match s with
  | SIMDVecRegWithIdx (_, _, idx) ->
    builder.Accumulate AsmWordKind.String "["
    builder.Accumulate AsmWordKind.String (string idx)
    builder.Accumulate AsmWordKind.String "]"
  | _ -> ()

let simdToString simdOprs builder =
  match simdOprs with
  (* SIMD & FP register *)
  | SFReg s ->
    simdFPRegToString s builder
    finalSIMDOpr s builder
  (* SIMD vector register list or SIMD vector element list *)
  | OneReg s ->
    builder.Accumulate AsmWordKind.String "{ "
    simdFPRegToString s builder
    builder.Accumulate AsmWordKind.String " }"
    finalSIMDOpr s builder
  | TwoRegs (s1, s2) ->
    builder.Accumulate AsmWordKind.String "{ "
    simdFPRegToString s1 builder
    builder.Accumulate AsmWordKind.String ", "
    simdFPRegToString s2 builder
    builder.Accumulate AsmWordKind.String " }"
    finalSIMDOpr s1 builder
  | ThreeRegs (s1, s2, s3) ->
    builder.Accumulate AsmWordKind.String "{ "
    simdFPRegToString s1 builder
    builder.Accumulate AsmWordKind.String ", "
    simdFPRegToString s2 builder
    builder.Accumulate AsmWordKind.String ", "
    simdFPRegToString s3 builder
    builder.Accumulate AsmWordKind.String " }"
    finalSIMDOpr s1 builder
  | FourRegs (s1, _, _, s4) ->
    builder.Accumulate AsmWordKind.String "{ "
    simdFPRegToString s1 builder
    builder.Accumulate AsmWordKind.String " - "
    simdFPRegToString s4 builder
    builder.Accumulate AsmWordKind.String " }"
    finalSIMDOpr s1 builder

let immToString imm (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.String "#"
  builder.Accumulate AsmWordKind.String (String.i64ToHex imm)

let fpImmToString (fp: float) (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.String "#"
  builder.Accumulate AsmWordKind.String (fp.ToString ("N8"))

let nzcvToString (imm: uint8) (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.String "#"
  builder.Accumulate AsmWordKind.String ("0x" + imm.ToString "x")

let amountToString amount builder =
  match amount with
  | Imm i -> immToString i builder
  | Reg r -> builder.Accumulate AsmWordKind.Variable (Register.toString r)

let prependDelimiter delimiter (builder: DisasmBuilder<_>) =
  match delimiter with
  | None -> ()
  | Some delim -> builder.Accumulate AsmWordKind.String delim

let shiftToString shift delim builder =
  match shift with
  | _, Imm 0L -> ()
  | s, amount ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.String (srtypeToString s)
    builder.Accumulate AsmWordKind.String " "
    amountToString amount builder

let extToString = function
  | ExtUXTB -> "uxtb"
  | ExtUXTH -> "uxth"
  | ExtUXTW -> "uxtw"
  | ExtUXTX -> "uxtx"
  | ExtSXTB -> "sxtb"
  | ExtSXTH -> "sxth"
  | ExtSXTW -> "sxtw"
  | ExtSXTX -> "sxtx"

let extRegToString regOff delim builder =
  match regOff with
  | (ext, None)
  | (ext, Some 0L) ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.String (extToString ext)
  | (ext, Some i) ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.String (extToString ext)
    builder.Accumulate AsmWordKind.String " #"
    builder.Accumulate AsmWordKind.Value (i.ToString ("x"))

let regOffString regOff delim builder =
  match regOff with
  | ShiftOffset regOff -> shiftToString regOff delim builder
  | ExtRegOffset regOff -> extRegToString regOff delim builder

let delimPostIdx = function
  | PostIdxMode _ -> "], "
  | _ -> ", "

let processAddrExn64 ins addr =
  match ins.Opcode with
  | Opcode.ADRP -> addr &&& 0xFFFFFFFFFFFFF000UL
  | _ -> addr

let immOffsetToString i addr mode offset (builder: DisasmBuilder<_>) =
  match offset with
  | BaseOffset (reg, None) | BaseOffset (reg, Some 0L) ->
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)
  | BaseOffset (reg, Some imm) ->
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)
    builder.Accumulate AsmWordKind.String (delimPostIdx mode)
    immToString imm builder
  | Lbl imm ->
    let addr = processAddrExn64 i addr
    builder.Accumulate AsmWordKind.Value (String.i64ToHex (int64 addr + imm))

let regOffsetToString mode offset (builder: DisasmBuilder<_>) =
  match offset with
  | r1, r2, Some regOff ->
    builder.Accumulate AsmWordKind.Variable (Register.toString r1)
    builder.Accumulate AsmWordKind.String ", "
    builder.Accumulate AsmWordKind.Variable (Register.toString r2)
    regOffString regOff (Some ", ") builder
  | r1, r2, None ->
    builder.Accumulate AsmWordKind.Variable (Register.toString r1)
    builder.Accumulate AsmWordKind.String (delimPostIdx mode)
    builder.Accumulate AsmWordKind.Variable (Register.toString r2)

let postBracket mode (builder: DisasmBuilder<_>) =
  match mode with
  | BaseMode _ -> builder.Accumulate AsmWordKind.String "]"
  | PreIdxMode _ -> builder.Accumulate AsmWordKind.String "]!"
  | _ -> ()

let offsetToString i addr mode offset builder =
  match offset with
  | ImmOffset offset ->
    immOffsetToString i addr mode offset builder
    postBracket mode builder
  | RegOffset (r1, r2, offset) ->
    regOffsetToString mode (r1, r2, offset) builder
    postBracket mode builder

let memToString insInfo addr mode builder =
  match mode with
  | LiteralMode offset ->
    offsetToString insInfo addr mode offset builder
  | BaseMode off | PreIdxMode off | PostIdxMode off ->
    builder.Accumulate AsmWordKind.String "["
    offsetToString insInfo addr mode off builder

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

let oprToString i addr opr delim builder =
  match opr with
  | OprRegister reg when isRET i && reg = R.X30 -> ()
  | OprRegister reg ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)
  | SIMDOpr simdOpr ->
    prependDelimiter delim builder
    simdToString simdOpr builder
  | Immediate imm ->
    prependDelimiter delim builder
    immToString imm builder
  | FPImmediate fp ->
    prependDelimiter delim builder
    fpImmToString fp builder
  | NZCV ui8 ->
    prependDelimiter delim builder
    nzcvToString ui8 builder
  | Shift s -> shiftToString s delim builder
  | ExtReg None -> ()
  | ExtReg (Some regOffset) -> regOffString regOffset delim builder
  | Memory mode ->
    prependDelimiter delim builder
    memToString i addr mode builder
  | Option opt ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.Variable (optToString opt)
  | Pstate p ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.Variable (pStToString p)
  | PrfOp e1 ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.Variable (prfOpToString e1)
  | Cond c ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.Variable (condToString (Some c))
  | Fbits ui8 ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.Variable (fBitsToString ui8)
  | LSB ui8 ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.Variable (lsbToString ui8)

let inline buildOpcode ins (builder: DisasmBuilder<_>) =
  let opcode = opCodeToString ins.Opcode + condToString ins.Condition
  builder.Accumulate AsmWordKind.Mnemonic opcode

let buildOprs insInfo pc builder =
  match insInfo.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    oprToString insInfo pc opr (Some " ") builder
  | TwoOperands (opr1, opr2) ->
    oprToString insInfo pc opr1 (Some " ") builder
    oprToString insInfo pc opr2 (Some ", ") builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString insInfo pc opr1 (Some " ") builder
    oprToString insInfo pc opr2 (Some ", ") builder
    oprToString insInfo pc opr3 (Some ", ") builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    oprToString insInfo pc opr1 (Some " ") builder
    oprToString insInfo pc opr2 (Some ", ") builder
    oprToString insInfo pc opr3 (Some ", ") builder
    oprToString insInfo pc opr4 (Some ", ") builder
  | FiveOperands (opr1, opr2, opr3, opr4, opr5) ->
    oprToString insInfo pc opr1 (Some " ") builder
    oprToString insInfo pc opr2 (Some ", ") builder
    oprToString insInfo pc opr3 (Some ", ") builder
    oprToString insInfo pc opr4 (Some ", ") builder
    oprToString insInfo pc opr5 (Some ", ") builder

let disasm ins (builder: DisasmBuilder<_>) =
  let pc = ins.Address
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode ins builder
  buildOprs ins pc builder

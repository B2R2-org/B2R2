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

module internal B2R2.FrontEnd.BinLifter.ARM32.Disasm

open System.Text
open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  | Op.ADC -> "adc"
  | Op.ADCS -> "adcs"
  | Op.ADD -> "add"
  | Op.ADDS -> "adds"
  | Op.ADDW -> "addw"
  | Op.ADR -> "adr"
  | Op.AESD -> "aesd"
  | Op.AESE -> "aese"
  | Op.AESIMC -> "aesimc"
  | Op.AESMC -> "aesmc"
  | Op.AND -> "and"
  | Op.ANDS -> "ands"
  | Op.ASR -> "asr"
  | Op.ASRS -> "asrs"
  | Op.B -> "b"
  | Op.BFC -> "bfc"
  | Op.BFI -> "bfi"
  | Op.BIC -> "bic"
  | Op.BICS -> "bics"
  | Op.BKPT -> "bkpt"
  | Op.BL -> "bl"
  | Op.BLX -> "blx"
  | Op.BX -> "bx"
  | Op.BXJ -> "bxj"
  | Op.CBNZ -> "cbnz"
  | Op.CBZ -> "cbz"
  | Op.CDP -> "cdp"
  | Op.CDP2 -> "cdp2"
  | Op.CLREX -> "clrex"
  | Op.CLZ -> "clz"
  | Op.CMN -> "cmn"
  | Op.CMP -> "cmp"
  | Op.CPS -> "cps"
  | Op.CPSID -> "cpsid"
  | Op.CPSIE -> "cpsie"
  | Op.CRC32B -> "crc32b"
  | Op.CRC32CB -> "crc32cb"
  | Op.CRC32CH -> "crc32ch"
  | Op.CRC32CW -> "crc32cw"
  | Op.CRC32H -> "crc32h"
  | Op.CRC32W -> "crc32w"
  | Op.CSDB -> "csdb"
  | Op.DBG -> "dbg"
  | Op.DCPS1 -> "dcps1"
  | Op.DCPS2 -> "dcps2"
  | Op.DCPS3 -> "dcps3"
  | Op.DMB -> "dmb"
  | Op.DSB -> "dsb"
  | Op.ENTERX -> "enterx"
  | Op.EOR -> "eor"
  | Op.EORS -> "eors"
  | Op.ERET -> "eret"
  | Op.ESB -> "esb"
  | Op.FLDMDBX -> "fldmdbx"
  | Op.FLDMIAX -> "fldmiax"
  | Op.FSTMDBX -> "fstmdbx"
  | Op.FSTMIAX -> "fstmiax"
  | Op.HLT -> "hlt"
  | Op.HVC -> "hvc"
  | Op.ISB -> "isb"
  | Op.IT -> "it"
  | Op.ITE -> "ite"
  | Op.ITEE -> "itee"
  | Op.ITEEE -> "iteee"
  | Op.ITEET -> "iteet"
  | Op.ITET -> "itet"
  | Op.ITETE -> "itete"
  | Op.ITETT -> "itett"
  | Op.ITT -> "itt"
  | Op.ITTE -> "itte"
  | Op.ITTEE -> "ittee"
  | Op.ITTET -> "ittet"
  | Op.ITTT -> "ittt"
  | Op.ITTTE -> "ittte"
  | Op.ITTTT -> "itttt"
  | Op.LDA -> "lda"
  | Op.LDAB -> "ldab"
  | Op.LDAEX -> "ldaex"
  | Op.LDAEXB -> "ldaexb"
  | Op.LDAEXD -> "ldaexd"
  | Op.LDAEXH -> "ldaexh"
  | Op.LDAH -> "ldah"
  | Op.LDC -> "ldc"
  | Op.LDC2 -> "ldc2"
  | Op.LDC2L -> "ldc2l"
  | Op.LDCL -> "ldcl"
  | Op.LDM -> "ldm"
  | Op.LDMDA -> "ldmda"
  | Op.LDMDB -> "ldmdb"
  | Op.LDMIA -> "ldmia"
  | Op.LDMIB -> "ldmib"
  | Op.LDR -> "ldr"
  | Op.LDRB -> "ldrb"
  | Op.LDRBT -> "ldrbt"
  | Op.LDRD -> "ldrd"
  | Op.LDREX -> "ldrex"
  | Op.LDREXB -> "ldrexb"
  | Op.LDREXD -> "ldrexd"
  | Op.LDREXH -> "ldrexh"
  | Op.LDRH -> "ldrh"
  | Op.LDRHT -> "ldrht"
  | Op.LDRSB -> "ldrsb"
  | Op.LDRSBT -> "ldrsbt"
  | Op.LDRSH -> "ldrsh"
  | Op.LDRSHT -> "ldrsht"
  | Op.LDRT -> "ldrt"
  | Op.LEAVEX -> "leavex"
  | Op.LSL -> "lsl"
  | Op.LSLS -> "lsls"
  | Op.LSR -> "lsr"
  | Op.LSRS -> "lsrs"
  | Op.MCR -> "mcr"
  | Op.MCR2 -> "mcr2"
  | Op.MCRR -> "mcrr"
  | Op.MCRR2 -> "mcrr2"
  | Op.MLA -> "mla"
  | Op.MLAS -> "mlas"
  | Op.MLS -> "mls"
  | Op.MOV -> "mov"
  | Op.MOVS -> "movs"
  | Op.MOVT -> "movt"
  | Op.MOVW -> "movw"
  | Op.MRC -> "mrc"
  | Op.MRC2 -> "mrc2"
  | Op.MRRC -> "mrrc"
  | Op.MRRC2 -> "mrrc2"
  | Op.MRS -> "mrs"
  | Op.MSR -> "msr"
  | Op.MUL -> "mul"
  | Op.MULS -> "muls"
  | Op.MVN -> "mvn"
  | Op.MVNS -> "mvns"
  | Op.NOP -> "nop"
  | Op.ORN -> "orn"
  | Op.ORNS -> "orns"
  | Op.ORR -> "orr"
  | Op.ORRS -> "orrs"
  | Op.PKHBT -> "pkhbt"
  | Op.PKHTB -> "pkhtb"
  | Op.PLD -> "pld"
  | Op.PLDW -> "pldw"
  | Op.PLI -> "pli"
  | Op.POP -> "pop"
  | Op.PSSBB -> "pssbb"
  | Op.PUSH -> "push"
  | Op.QADD -> "qadd"
  | Op.QADD16 -> "qadd16"
  | Op.QADD8 -> "qadd8"
  | Op.QASX -> "qasx"
  | Op.QDADD -> "qdadd"
  | Op.QDSUB -> "qdsub"
  | Op.QSAX -> "qsax"
  | Op.QSUB -> "qsub"
  | Op.QSUB16 -> "qsub16"
  | Op.QSUB8 -> "qsub8"
  | Op.RBIT -> "rbit"
  | Op.REV -> "rev"
  | Op.REV16 -> "rev16"
  | Op.REVSH -> "revsh"
  | Op.RFE -> "rfe"
  | Op.RFEDA -> "rfeda"
  | Op.RFEDB -> "rfedb"
  | Op.RFEIA -> "rfeia"
  | Op.RFEIB -> "rfeib"
  | Op.ROR -> "ror"
  | Op.RORS -> "rors"
  | Op.RRX -> "rrx"
  | Op.RRXS -> "rrxs"
  | Op.RSB -> "rsb"
  | Op.RSBS -> "rsbs"
  | Op.RSC -> "rsc"
  | Op.RSCS -> "rscs"
  | Op.SADD16 -> "sadd16"
  | Op.SADD8 -> "sadd8"
  | Op.SASX -> "sasx"
  | Op.SB -> "sb"
  | Op.SBC -> "sbc"
  | Op.SBCS -> "sbcs"
  | Op.SBFX -> "sbfx"
  | Op.SDIV -> "sdiv"
  | Op.SEL -> "sel"
  | Op.SETEND -> "setend"
  | Op.SETPAN -> "setpan"
  | Op.SEV -> "sev"
  | Op.SEVL -> "sevl"
  | Op.SHA1C -> "sha1c"
  | Op.SHA1H -> "sha1h"
  | Op.SHA1M -> "sha1m"
  | Op.SHA1P -> "sha1p"
  | Op.SHA1SU0 -> "sha1su0"
  | Op.SHA1SU1 -> "sha1su1"
  | Op.SHA256H -> "sha256h"
  | Op.SHA256H2 -> "sha256h2 "
  | Op.SHA256SU0 -> "sha256su0"
  | Op.SHA256SU1 -> "sha256su1"
  | Op.SHADD16 -> "shadd16"
  | Op.SHADD8 -> "shadd8"
  | Op.SHASX -> "shasx"
  | Op.SHSAX -> "shsax"
  | Op.SHSUB16 -> "shsub16"
  | Op.SHSUB8 -> "shsub8"
  | Op.SMC -> "smc"
  | Op.SMLABB -> "smlabb"
  | Op.SMLABT -> "smlabt"
  | Op.SMLAD -> "smlad"
  | Op.SMLADX -> "smladx"
  | Op.SMLAL -> "smlal"
  | Op.SMLALBB -> "smlalbb"
  | Op.SMLALBT -> "smlalbt"
  | Op.SMLALD -> "smlald"
  | Op.SMLALDX -> "smlaldx"
  | Op.SMLALS -> "smlals"
  | Op.SMLALTB -> "smlaltb"
  | Op.SMLALTT -> "smlaltt"
  | Op.SMLATB -> "smlatb"
  | Op.SMLATT -> "smlatt"
  | Op.SMLAWB -> "smlawb"
  | Op.SMLAWT -> "smlawt"
  | Op.SMLSD -> "smlsd"
  | Op.SMLSDX -> "smlsdx"
  | Op.SMLSLD -> "smlsld"
  | Op.SMLSLDX -> "smlsldx"
  | Op.SMMLA -> "smmla"
  | Op.SMMLAR -> "smmlar"
  | Op.SMMLS -> "smmls"
  | Op.SMMLSR -> "smmlsr"
  | Op.SMMUL -> "smmul"
  | Op.SMMULR -> "smmulr"
  | Op.SMUAD -> "smuad"
  | Op.SMUADX -> "smuadx"
  | Op.SMULBB -> "smulbb"
  | Op.SMULBT -> "smulbt"
  | Op.SMULL -> "smull"
  | Op.SMULLS -> "smulls"
  | Op.SMULTB -> "smultb"
  | Op.SMULTT -> "smultt"
  | Op.SMULWB -> "smulwb"
  | Op.SMULWT -> "smulwt"
  | Op.SMUSD -> "smusd"
  | Op.SMUSDX -> "smusdx"
  | Op.SRS -> "srs"
  | Op.SRSDA -> "srsda"
  | Op.SRSDB -> "srsdb"
  | Op.SRSIA -> "srsia"
  | Op.SRSIB -> "srsib"
  | Op.SSAT -> "ssat"
  | Op.SSAT16 -> "ssat16"
  | Op.SSAX -> "ssax"
  | Op.SSBB -> "ssbb"
  | Op.SSUB16 -> "ssub16"
  | Op.SSUB8 -> "ssub8"
  | Op.STC -> "stc"
  | Op.STC2 -> "stc2"
  | Op.STC2L -> "stc2l"
  | Op.STCL -> "stcl"
  | Op.STL -> "stl"
  | Op.STLB -> "stlb"
  | Op.STLEX -> "stlex"
  | Op.STLEXB -> "stlexb"
  | Op.STLEXD -> "stlexd"
  | Op.STLEXH -> "stlexh"
  | Op.STLH -> "stlh"
  | Op.STM -> "stm"
  | Op.STMDA -> "stmda"
  | Op.STMDB -> "stmdb"
  | Op.STMEA -> "stmea"
  | Op.STMIA -> "stmia"
  | Op.STMIB -> "stmib"
  | Op.STR -> "str"
  | Op.STRB -> "strb"
  | Op.STRBT -> "strbt"
  | Op.STRD -> "strd"
  | Op.STREX -> "strex"
  | Op.STREXB -> "strexb"
  | Op.STREXD -> "strexd"
  | Op.STREXH -> "strexh"
  | Op.STRH -> "strh"
  | Op.STRHT -> "strht"
  | Op.STRT -> "strt"
  | Op.SUB -> "sub"
  | Op.SUBS -> "subs"
  | Op.SUBW -> "subw"
  | Op.SVC -> "svc"
  | Op.SWP -> "swp"
  | Op.SWPB -> "swpb"
  | Op.SXTAB -> "sxtab"
  | Op.SXTAB16 -> "sxtab16"
  | Op.SXTAH -> "sxtah"
  | Op.SXTB -> "sxtb"
  | Op.SXTB16 -> "sxtb16"
  | Op.SXTH -> "sxth"
  | Op.TBB -> "tbb"
  | Op.TBH -> "tbh"
  | Op.TEQ -> "teq"
  | Op.TSB -> "tsb"
  | Op.TST -> "tst"
  | Op.UADD16 -> "uadd16"
  | Op.UADD8 -> "uadd8"
  | Op.UASX -> "uasx"
  | Op.UBFX -> "ubfx"
  | Op.UDF -> "udf"
  | Op.UDIV -> "udiv"
  | Op.UHADD16 -> "uhadd16"
  | Op.UHADD8 -> "uhadd8"
  | Op.UHASX -> "uhasx"
  | Op.UHSAX -> "uhsax"
  | Op.UHSUB16 -> "uhsub16"
  | Op.UHSUB8 -> "uhsub8"
  | Op.UMAAL -> "umaal"
  | Op.UMLAL -> "umlal"
  | Op.UMLALS -> "umlals"
  | Op.UMULL -> "umull"
  | Op.UMULLS -> "umulls"
  | Op.UQADD16 -> "uqadd16"
  | Op.UQADD8 -> "uqadd8"
  | Op.UQASX -> "uqasx"
  | Op.UQSAX -> "uqsax"
  | Op.UQSUB16 -> "uqsub16"
  | Op.UQSUB8 -> "uqsub8"
  | Op.USAD8 -> "usad8"
  | Op.USADA8 -> "usada8"
  | Op.USAT -> "usat"
  | Op.USAT16 -> "usat16"
  | Op.USAX -> "usax"
  | Op.USUB16 -> "usub16"
  | Op.USUB8 -> "usub8"
  | Op.UXTAB -> "uxtab"
  | Op.UXTAB16 -> "uxtab16"
  | Op.UXTAH -> "uxtah"
  | Op.UXTB -> "uxtb"
  | Op.UXTB16 -> "uxtb16"
  | Op.UXTH -> "uxth"
  | Op.VABA -> "vaba"
  | Op.VABAL -> "vabal"
  | Op.VABD -> "vabd"
  | Op.VABDL -> "vabdl"
  | Op.VABS -> "vabs"
  | Op.VACGE -> "vacge"
  | Op.VACGT -> "vacgt"
  | Op.VACLE -> "vacle"
  | Op.VACLT -> "vaclt"
  | Op.VADD -> "vadd"
  | Op.VADDHN -> "vaddhn"
  | Op.VADDL -> "vaddl"
  | Op.VADDW -> "vaddw"
  | Op.VAND -> "vand"
  | Op.VBIC -> "vbic"
  | Op.VBIF -> "vbif"
  | Op.VBIT -> "vbit"
  | Op.VBSL -> "vbsl"
  | Op.VCADD -> "vcadd"
  | Op.VCEQ -> "vceq"
  | Op.VCGE -> "vcge"
  | Op.VCGT -> "vcgt"
  | Op.VCLE -> "vcle"
  | Op.VCLS -> "vcls"
  | Op.VCLT -> "vclt"
  | Op.VCLZ -> "vclz"
  | Op.VCMLA -> "vcmla"
  | Op.VCMP -> "vcmp"
  | Op.VCMPE -> "vcmpe"
  | Op.VCNT -> "vcnt"
  | Op.VCVT -> "vcvt"
  | Op.VCVTA -> "vcvta"
  | Op.VCVTB -> "vcvtb"
  | Op.VCVTM -> "vcvtm"
  | Op.VCVTN -> "vcvtn"
  | Op.VCVTP -> "vcvtp"
  | Op.VCVTR -> "vcvtr"
  | Op.VCVTT -> "vcvtt"
  | Op.VDIV -> "vdiv"
  | Op.VDOT -> "vdot"
  | Op.VDUP -> "vdup"
  | Op.VEOR -> "veor"
  | Op.VEXT -> "vext"
  | Op.VFMA -> "vfma"
  | Op.VFMAB -> "vfmab"
  | Op.VFMAL -> "vfmal"
  | Op.VFMAT -> "vfmat"
  | Op.VFMS -> "vfms"
  | Op.VFMSL -> "vfmsl"
  | Op.VFNMA -> "vfnma"
  | Op.VFNMS -> "vfnms"
  | Op.VHADD -> "vhadd"
  | Op.VHSUB -> "vhsub"
  | Op.VINS -> "vins"
  | Op.VJCVT -> "vjcvt"
  | Op.VLD1 -> "vld1"
  | Op.VLD2 -> "vld2"
  | Op.VLD3 -> "vld3"
  | Op.VLD4 -> "vld4"
  | Op.VLDM -> "vldm"
  | Op.VLDMDB -> "vldmdb"
  | Op.VLDMIA -> "vldmia"
  | Op.VLDR -> "vldr"
  | Op.VMAX -> "vmax"
  | Op.VMAXNM -> "vmaxnm"
  | Op.VMIN -> "vmin"
  | Op.VMINNM -> "vminnm"
  | Op.VMLA -> "vmla"
  | Op.VMLAL -> "vmlal"
  | Op.VMLS -> "vmls"
  | Op.VMLSL -> "vmlsl"
  | Op.VMMLA -> "vmmla"
  | Op.VMOV -> "vmov"
  | Op.VMOVL -> "vmovl"
  | Op.VMOVN -> "vmovn"
  | Op.VMOVX -> "vmovx"
  | Op.VMRS -> "vmrs"
  | Op.VMSR -> "vmsr"
  | Op.VMUL -> "vmul"
  | Op.VMULL -> "vmull"
  | Op.VMVN -> "vmvn"
  | Op.VNEG -> "vneg"
  | Op.VNMLA -> "vnmla"
  | Op.VNMLS -> "vnmls"
  | Op.VNMUL -> "vnmul"
  | Op.VORN -> "vorn"
  | Op.VORR -> "vorr"
  | Op.VPADAL -> "vpadal"
  | Op.VPADD -> "vpadd"
  | Op.VPADDL -> "vpaddl"
  | Op.VPMAX -> "vpmax"
  | Op.VPMIN -> "vpmin"
  | Op.VPOP -> "vpop"
  | Op.VPUSH -> "vpush"
  | Op.VQABS -> "vqabs"
  | Op.VQADD -> "vqadd"
  | Op.VQDMLAL -> "vqdmlal"
  | Op.VQDMLSL -> "vqdmlsl"
  | Op.VQDMULH -> "vqdmulh"
  | Op.VQDMULL -> "vqdmull"
  | Op.VQMOVN -> "vqmovn"
  | Op.VQMOVUN -> "vqmovun"
  | Op.VQNEG -> "vqneg"
  | Op.VQRDMLAH -> "vqrdmlah"
  | Op.VQRDMLSH -> "vqrdmlsh"
  | Op.VQRDMULH -> "vqrdmulh"
  | Op.VQRSHL -> "vqrshl"
  | Op.VQRSHRN -> "vqrshrn"
  | Op.VQRSHRUN -> "vqrshrun"
  | Op.VQSHL -> "vqshl"
  | Op.VQSHLU -> "vqshlu"
  | Op.VQSHRN -> "vqshrn"
  | Op.VQSHRUN -> "vqshrun"
  | Op.VQSUB -> "vqsub"
  | Op.VRADDHN -> "vraddhn"
  | Op.VRECPE -> "vrecpe"
  | Op.VRECPS -> "vrecps"
  | Op.VREV16 -> "vrev16"
  | Op.VREV32 -> "vrev32"
  | Op.VREV64 -> "vrev64"
  | Op.VRHADD -> "vrhadd"
  | Op.VRINTA -> "vrinta"
  | Op.VRINTM -> "vrintm"
  | Op.VRINTN -> "vrintn"
  | Op.VRINTP -> "vrintp"
  | Op.VRINTR -> "vrintr"
  | Op.VRINTX -> "vrintx"
  | Op.VRINTZ -> "vrintz"
  | Op.VRSHL -> "vrshl"
  | Op.VRSHR -> "vrshr"
  | Op.VRSHRN -> "vrshrn"
  | Op.VRSQRTE -> "vrsqrte"
  | Op.VRSQRTS -> "vrsqrts"
  | Op.VRSRA -> "vrsra"
  | Op.VRSUBHN -> "vrsubhn"
  | Op.VSDOT -> "vsdot"
  | Op.VSELEQ -> "vseleq"
  | Op.VSELGE -> "vselge"
  | Op.VSELGT -> "vselgt"
  | Op.VSELVS -> "vselvs"
  | Op.VSHL -> "vshl"
  | Op.VSHLL -> "vshll"
  | Op.VSHR -> "vshr"
  | Op.VSHRN -> "vshrn"
  | Op.VSLI -> "vsli"
  | Op.VSMMLA -> "vsmmla"
  | Op.VSQRT -> "vsqrt"
  | Op.VSRA -> "vsra"
  | Op.VSRI -> "vsri"
  | Op.VST1 -> "vst1"
  | Op.VST2 -> "vst2"
  | Op.VST3 -> "vst3"
  | Op.VST4 -> "vst4"
  | Op.VSTM -> "vstm"
  | Op.VSTMDB -> "vstmdb"
  | Op.VSTMIA -> "vstmia"
  | Op.VSTR -> "vstr"
  | Op.VSUB -> "vsub"
  | Op.VSUBHN -> "vsubhn"
  | Op.VSUBL -> "vsubl"
  | Op.VSUBW -> "vsubw"
  | Op.VSUDOT -> "vsudot"
  | Op.VSWP -> "vswp"
  | Op.VTBL -> "vtbl"
  | Op.VTBX -> "vtbx"
  | Op.VTRN -> "vtrn"
  | Op.VTST -> "vtst"
  | Op.VUDOT -> "vudot"
  | Op.VUMMLA -> "vummla"
  | Op.VUSDOT -> "vusdot"
  | Op.VUSMMLA -> "vusmmla"
  | Op.VUZP -> "vuzp"
  | Op.VZIP -> "vzip"
  | Op.WFE -> "wfe"
  | Op.WFI -> "wfi"
  | Op.YIELD -> "yield"
  | Op.InvalidOP -> "(illegal)"
  | _ -> raise ParsingFailureException

let condToString = function
  | Condition.EQ -> "eq"
  | Condition.NE -> "ne"
  | Condition.CS -> "cs"
  | Condition.HS -> "hs"
  | Condition.CC -> "cc"
  | Condition.LO -> "lo"
  | Condition.MI -> "mi"
  | Condition.PL -> "pl"
  | Condition.VS -> "vs"
  | Condition.VC -> "vc"
  | Condition.HI -> "hi"
  | Condition.LS -> "ls"
  | Condition.GE -> "ge"
  | Condition.LT -> "lt"
  | Condition.GT -> "gt"
  | Condition.LE -> "le"
  | Condition.NV -> "nv"
  | Condition.UN | Condition.AL -> ""
  | _ -> raise ParsingFailureException

let SIMDTypToStr = function
  | SIMDTyp8 -> ".8"
  | SIMDTyp16 -> ".16"
  | SIMDTyp32 -> ".32"
  | SIMDTyp64 -> ".64"
  | SIMDTypS8 -> ".s8"
  | SIMDTypS16 -> ".s16"
  | SIMDTypS32 -> ".s32"
  | SIMDTypS64 -> ".s64"
  | SIMDTypU8 -> ".u8"
  | SIMDTypU16 -> ".u16"
  | SIMDTypU32 -> ".u32"
  | SIMDTypU64 -> ".u64"
  | SIMDTypI8 -> ".i8"
  | SIMDTypI16 -> ".i16"
  | SIMDTypI32 -> ".i32"
  | SIMDTypI64 -> ".i64"
  | SIMDTypF16 -> ".f16"
  | SIMDTypF32 -> ".f32"
  | SIMDTypF64 -> ".f64"
  | SIMDTypP8 -> ".p8"
  | SIMDTypP64 -> ".p64"
  | BF16 -> ".bf16"

let qualifierToStr = function
  | W -> ".w"
  | N -> ""

let inline appendQualifier (ins: InsInfo) (sb: StringBuilder) =
  sb.Append (qualifierToStr ins.Qualifier)

let inline appendSIMDDataTypes (ins: InsInfo) (sb: StringBuilder) =
  match ins.SIMDTyp with
  | None -> sb
  | Some (OneDT dt) -> sb.Append (SIMDTypToStr dt)
  | Some (TwoDT (dt1, dt2)) ->
    (sb.Append (SIMDTypToStr dt1)).Append (SIMDTypToStr dt2)

let inline buildOpcode (ins: InsInfo) (builder: DisasmBuilder<_>) =
  let sb = StringBuilder ()
  let sb = sb.Append (opCodeToString ins.Opcode)
  let sb = sb.Append (condToString ins.Condition)
  let sb = appendQualifier ins sb
  let sb = appendSIMDDataTypes ins sb
  builder.Accumulate AsmWordKind.Mnemonic (sb.ToString ())

let existRegList = function
  | TwoOperands (_, OprRegList _) -> true
  | _ -> false

let isRFEorSRS = function
  | Op.RFE | Op.RFEDA | Op.RFEDB | Op.RFEIA | Op.RFEIB
  | Op.SRS | Op.SRSDA | Op.SRSDB | Op.SRSIA | Op.SRSIB -> true
  | _ -> false

let buildReg (ins: InsInfo) isRegList reg (builder: DisasmBuilder<_>) =
  let reg = Register.toString reg
  match ins.WriteBack with
  | true when existRegList ins.Operands && not isRegList ->
    builder.Accumulate AsmWordKind.Variable reg
    builder.Accumulate AsmWordKind.String "!"
  | true when isRFEorSRS ins.Opcode ->
    builder.Accumulate AsmWordKind.Variable reg
    builder.Accumulate AsmWordKind.String "!"
  | _ (* false *) ->
    builder.Accumulate AsmWordKind.Variable reg

/// See A8-499 the description of <spec_reg>.
let flagToString = function
  | PSRc -> "_c"
  | PSRx -> "_x"
  | PSRxc -> "_xc"
  | PSRs -> "_s"
  | PSRsc -> "_sc"
  | PSRsx -> "_sx"
  | PSRsxc -> "_sxc"
  | PSRf -> "_f"
  | PSRfc -> "_fc"
  | PSRfx -> "_fx"
  | PSRfxc -> "_fxc"
  | PSRfs -> "_fs"
  | PSRfsc -> "_fsc"
  | PSRfsx -> "_fsx"
  | PSRfsxc -> "_fsxc"
  | PSRnzcv -> "_nzcv"
  | PSRnzcvq -> "_nzcvq"
  | PSRg -> "_g"
  | PSRnzcvqg -> "_nzcvqg"

let specRegToString ins reg pFlag builder =
  match pFlag with
  | None -> buildReg ins false reg builder
  | Some f ->
    buildReg ins false reg builder
    builder.Accumulate AsmWordKind.String (flagToString f)

let regListToString ins list (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.String "{"
  let len = List.length list
  list
  |> List.iteri (fun idx r ->
    buildReg ins true r builder
    if idx + 1 = len then ()
    else builder.Accumulate AsmWordKind.String ", ")
  builder.Accumulate AsmWordKind.String "}"

let simdToString ins s builder =
  match s with
  | Vector v -> buildReg ins false v builder
  | Scalar (v, None) ->
    buildReg ins false v builder
    builder.Accumulate AsmWordKind.String "[]"
  | Scalar (v, Some i) ->
    buildReg ins false v builder
    builder.Accumulate AsmWordKind.String "["
    builder.Accumulate AsmWordKind.String (string i)
    builder.Accumulate AsmWordKind.String "]"

let simdOprToString ins simd builder =
  match simd with
  | SFReg s -> simdToString ins s builder
  | OneReg s ->
    builder.Accumulate AsmWordKind.String "{"
    simdToString ins s builder
    builder.Accumulate AsmWordKind.String "}"
  | TwoRegs (s1, s2) ->
    builder.Accumulate AsmWordKind.String "{"
    simdToString ins s1 builder
    builder.Accumulate AsmWordKind.String ", "
    simdToString ins s2 builder
    builder.Accumulate AsmWordKind.String "}"
  | ThreeRegs (s1, s2, s3) ->
    builder.Accumulate AsmWordKind.String "{"
    simdToString ins s1 builder
    builder.Accumulate AsmWordKind.String ", "
    simdToString ins s2 builder
    builder.Accumulate AsmWordKind.String ", "
    simdToString ins s3 builder
    builder.Accumulate AsmWordKind.String "}"
  | FourRegs (s1, s2, s3, s4) ->
    builder.Accumulate AsmWordKind.String "{"
    simdToString ins s1 builder
    builder.Accumulate AsmWordKind.String ", "
    simdToString ins s2 builder
    builder.Accumulate AsmWordKind.String ", "
    simdToString ins s3 builder
    builder.Accumulate AsmWordKind.String ", "
    simdToString ins s4 builder
    builder.Accumulate AsmWordKind.String "}"

let signToString = function
  | None -> ""
  | Some Plus -> ""
  | Some Minus -> "-"

let immToString imm sign (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.String "#"
  builder.Accumulate AsmWordKind.String (signToString sign)
  builder.Accumulate AsmWordKind.Value (String.i64ToHex imm)

let fpImmToString (fp: float) (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.String "#"
  builder.Accumulate AsmWordKind.Value (fp.ToString ("N8"))

let optionToString (opt: int64) (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.Value (String.i64ToHex opt)

let srTypeToString = function
  | SRTypeLSL -> "lsl"
  | SRTypeLSR -> "lsr"
  | SRTypeASR -> "asr"
  | SRTypeROR -> "ror"
  | SRTypeRRX -> "rrx"

let prependDelimiter delimiter (builder: DisasmBuilder<_>) =
  match delimiter with
  | None -> ()
  | Some delim -> builder.Accumulate AsmWordKind.String delim

let shiftToString shift delim builder =
  match shift with
  | _, Imm 0u -> ()
  | s, Imm i ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.String (srTypeToString s)
    builder.Accumulate AsmWordKind.String " "
    immToString (int64 i) None builder

let regShiftToString ins shift reg (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.String (srTypeToString shift)
  builder.Accumulate AsmWordKind.String " "
  buildReg ins false reg builder

let delimPostIdx = function
  | PostIdxMode _ -> "], "
  | _ -> ", "

let immOffsetToString ins addrMode offset builder =
  match offset with
  | reg, _, None | reg, _, Some 0L -> buildReg ins false reg builder
  | reg, s, Some imm ->
    buildReg ins false reg builder
    builder.Accumulate AsmWordKind.String (delimPostIdx addrMode)
    immToString imm s builder

let regOffsetToString ins addrMode offset builder =
  match offset with
  | bReg, s, reg, None ->
    buildReg ins false bReg builder
    builder.Accumulate AsmWordKind.String (delimPostIdx addrMode)
    builder.Accumulate AsmWordKind.String (signToString s)
    buildReg ins false reg builder
  | bReg, s, reg, Some shift ->
    buildReg ins false bReg builder
    builder.Accumulate AsmWordKind.String (delimPostIdx addrMode)
    builder.Accumulate AsmWordKind.String (signToString s)
    buildReg ins false reg builder
    shiftToString shift (Some ", ") builder

let alignOffsetToString ins offset builder =
  match offset with
  | bReg, Some align, None ->
    buildReg ins false bReg builder
    builder.Accumulate AsmWordKind.String ":"
    builder.Accumulate AsmWordKind.String (string align)
  | bReg, Some align, Some reg ->
    buildReg ins false bReg builder
    builder.Accumulate AsmWordKind.String ":"
    builder.Accumulate AsmWordKind.String (string align)
    builder.Accumulate AsmWordKind.String "], "
    buildReg ins false reg builder
  | bReg, None, Some reg ->
    buildReg ins false bReg builder
    builder.Accumulate AsmWordKind.String "], "
    buildReg ins false reg builder
  | bReg, None, None -> buildReg ins false bReg builder

let offsetToString ins addrMode offset builder =
  match offset with
  | ImmOffset (reg, s, imm) ->
    immOffsetToString ins addrMode (reg, s, imm) builder
  | RegOffset (bReg, s, reg, shf) ->
    regOffsetToString ins addrMode (bReg, s, reg, shf) builder
  | AlignOffset (bReg, align, reg) ->
    alignOffsetToString ins (bReg, align, reg) builder

let processAddrExn32 (ins: InsInfo) addr =
  let pc =
    if ins.Mode = ArchOperationMode.ThumbMode then addr + 4UL else addr + 8UL
  match ins.Opcode with
  | Op.CBZ | Op.CBNZ
  | Op.B | Op.BX -> pc
  | Op.BL | Op.BLX -> ParseUtils.align pc 4UL
  | Op.ADR -> ParseUtils.align pc 4UL
  | _ -> addr

let calculateRelativePC lbl addr = int32 addr + int32 lbl |> uint64

let commentWithSymbol helper addr addrStr (builder: DisasmBuilder<_>) =
  if builder.ResolveSymbol then
    match (helper: DisasmHelper).FindFunctionSymbol (addr) with
    | Error _ ->
      builder.Accumulate AsmWordKind.String addrStr
    | Ok "" -> ()
    | Ok name ->
      builder.Accumulate AsmWordKind.String (addrStr + " ; <")
      builder.Accumulate AsmWordKind.Value name
      builder.Accumulate AsmWordKind.String ">"
  else ()

let memHead hlp ins addr addrMode (builder: DisasmBuilder<_>) =
  match addrMode with
  | OffsetMode offset | PreIdxMode offset | PostIdxMode offset ->
    builder.Accumulate AsmWordKind.String "["
    offsetToString ins addrMode offset builder
  | UnIdxMode (reg, opt) ->
    builder.Accumulate AsmWordKind.String "["
    buildReg ins false reg builder
    builder.Accumulate AsmWordKind.String "], {"
    optionToString opt builder
  | LiteralMode lbl ->
    let addr = processAddrExn32 ins addr |> calculateRelativePC lbl
    let addrStr = "0x" + addr.ToString ("x")
    match ins.Opcode with
    | Op.BL | Op.BLX -> commentWithSymbol hlp addr addrStr builder
    | _ -> builder.Accumulate AsmWordKind.String addrStr

let memTail addrMode (builder: DisasmBuilder<_>) =
  match addrMode with
  | OffsetMode _ -> builder.Accumulate AsmWordKind.String "]"
  | PreIdxMode _ -> builder.Accumulate AsmWordKind.String "]!"
  | PostIdxMode _ -> ()
  | UnIdxMode _ -> builder.Accumulate AsmWordKind.String "}"
  | LiteralMode _ -> ()

let memToString hlp ins addr addrMode builder =
  memHead hlp ins addr addrMode builder
  memTail addrMode builder

let optToString = function
  | Option.SY -> "sy"
  | Option.ST -> "st"
  | Option.LD -> "ld"
  | Option.ISH -> "ish"
  | Option.ISHST -> "ishst"
  | Option.ISHLD -> "ishld"
  | Option.NSH -> "nsh"
  | Option.NSHST -> "nshst"
  | Option.NSHLD -> "nshld"
  | Option.OSH -> "osh"
  | Option.OSHST -> "oshst"
  | Option.OSHLD -> "oshld"
  | _ -> raise ParsingFailureException

let iFlagToString = function
  | A -> "a"
  | I -> "i"
  | F -> "f"
  | AI -> "ai"
  | AF -> "af"
  | IF -> "if"
  | AIF -> "aif"

let endToString endian =
  match endian with
  | Endian.Little -> "le"
  | Endian.Big -> "be"
  | _ -> invalidArg (nameof endian) "Invalid endian is given."

let oprToString hlp ins addr operand delim builder =
  match operand with
  | OprReg reg ->
    prependDelimiter delim builder
    buildReg ins false reg builder
  | OprSpecReg (reg, pFlag) ->
    prependDelimiter delim builder
    specRegToString ins reg pFlag builder
  | OprRegList regList ->
    prependDelimiter delim builder
    regListToString ins regList builder
  | OprSIMD simd ->
    prependDelimiter delim builder
    simdOprToString ins simd builder
  | OprImm imm ->
    prependDelimiter delim builder
    immToString imm None builder
  | OprFPImm fp ->
    prependDelimiter delim builder
    fpImmToString fp builder
  | OprShift s ->
    shiftToString s delim builder
  | OprRegShift (s, r) ->
    prependDelimiter delim builder
    regShiftToString ins s r builder
  | OprMemory addrMode ->
    prependDelimiter delim builder
    memToString hlp ins addr addrMode builder
  | OprOption opt ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.String (optToString opt)
  | OprIflag flag ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.String (iFlagToString flag)
  | OprEndian e ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.String (endToString e)
  | OprCond c ->
    prependDelimiter delim builder
    builder.Accumulate AsmWordKind.String (condToString c)
  | GoToLabel _ -> ()

let buildOprs hlp (ins: InsInfo) pc builder =
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    oprToString hlp ins pc opr (Some " ") builder
  | TwoOperands (opr1, opr2) ->
    oprToString hlp ins pc opr1 (Some " ") builder
    oprToString hlp ins pc opr2 (Some ", ") builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString hlp ins pc opr1 (Some " ") builder
    oprToString hlp ins pc opr2 (Some ", ") builder
    oprToString hlp ins pc opr3 (Some ", ") builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    oprToString hlp ins pc opr1 (Some " ") builder
    oprToString hlp ins pc opr2 (Some ", ") builder
    oprToString hlp ins pc opr3 (Some ", ") builder
    oprToString hlp ins pc opr4 (Some ", ") builder
  | FiveOperands (opr1, opr2, opr3, opr4, opr5) ->
    oprToString hlp ins pc opr1 (Some " ") builder
    oprToString hlp ins pc opr2 (Some ", ") builder
    oprToString hlp ins pc opr3 (Some ", ") builder
    oprToString hlp ins pc opr4 (Some ", ") builder
    oprToString hlp ins pc opr5 (Some ", ") builder
  | SixOperands (opr1, opr2, opr3, opr4, opr5, opr6) ->
    oprToString hlp ins pc opr1 (Some " ") builder
    oprToString hlp ins pc opr2 (Some ", ") builder
    oprToString hlp ins pc opr3 (Some ", ") builder
    oprToString hlp ins pc opr4 (Some ", ") builder
    oprToString hlp ins pc opr5 (Some ", ") builder
    oprToString hlp ins pc opr6 (Some ", ") builder

let disasm hlp (ins: InsInfo) (builder: DisasmBuilder<_>) =
  let pc = ins.Address
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode ins builder
  buildOprs hlp ins pc builder

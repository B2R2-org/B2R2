(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module internal B2R2.FrontEnd.ARM32.Disasm

open B2R2
open B2R2.FrontEnd
open System.Text

let opCodeToString = function
  | Op.MOV -> "mov"
  | Op.MOVS -> "movs"
  | Op.MOVW -> "movw"
  | Op.MOVT -> "movt"
  | Op.AND -> "and"
  | Op.ANDS -> "ands"
  | Op.EOR -> "eor"
  | Op.EORS -> "eors"
  | Op.SUB -> "sub"
  | Op.SUBS -> "subs"
  | Op.RSB -> "rsb"
  | Op.RSBS -> "rsbs"
  | Op.ADD -> "add"
  | Op.ADDS -> "adds"
  | Op.ADC -> "adc"
  | Op.ADCS -> "adcs"
  | Op.SBC -> "sbc"
  | Op.SBCS -> "sbcs"
  | Op.RSC -> "rsc"
  | Op.RSCS -> "rscs"
  | Op.TST -> "tst"
  | Op.TEQ -> "teq"
  | Op.CMP -> "cmp"
  | Op.CMN -> "cmn"
  | Op.ORR -> "orr"
  | Op.ORRS -> "orrs"
  | Op.LSL -> "lsl"
  | Op.LSLS -> "lsls"
  | Op.LSR -> "lsr"
  | Op.LSRS -> "lsrs"
  | Op.ASR -> "asr"
  | Op.ASRS -> "asrs"
  | Op.RRX -> "rrx"
  | Op.RRXS -> "rrxs"
  | Op.ROR -> "ror"
  | Op.RORS -> "rors"
  | Op.BIC -> "bic"
  | Op.BICS -> "bics"
  | Op.MVN -> "mvn"
  | Op.MVNS -> "mvns"
  | Op.ADR -> "adr"
  | Op.MRS -> "mrs"
  | Op.MSR -> "msr"
  | Op.BX  -> "bx"
  | Op.CLZ -> "clz"
  | Op.BXJ -> "bxj"
  | Op.BLX -> "blx"
  | Op.ERET -> "eret"
  | Op.BKPT -> "bkpt"
  | Op.HVC -> "hvc"
  | Op.SMC -> "smc"
  | Op.QADD -> "qadd"
  | Op.QSUB -> "qsub"
  | Op.QDADD -> "qdadd"
  | Op.QDSUB -> "qdsub"
  | Op.SMLABB -> "smlabb"
  | Op.SMLABT -> "smlabt"
  | Op.SMLATB -> "smlatb"
  | Op.SMLATT -> "smlatt"
  | Op.SMLAWB -> "smlawb"
  | Op.SMLAWT -> "smlawt"
  | Op.SMULWB -> "smulwb"
  | Op.SMULWT -> "smulwt"
  | Op.SMLALBB -> "smlalbb"
  | Op.SMLALBT -> "smlalbt"
  | Op.SMLALTB -> "smlaltb"
  | Op.SMLALTT -> "smlaltt"
  | Op.SMULBB -> "smulbb"
  | Op.SMULBT -> "smulbt"
  | Op.SMULTB -> "smultb"
  | Op.SMULTT -> "smultt"
  | Op.MUL -> "mul"
  | Op.MULS -> "muls"
  | Op.MLA -> "mla"
  | Op.UMAAL -> "umaal"
  | Op.MLS -> "mls"
  | Op.UMULL -> "umull"
  | Op.UMLAL -> "umlal"
  | Op.SMULL -> "smull"
  | Op.SMLAL -> "smlal"
  | Op.SWP -> "swp"
  | Op.SWPB -> "swpb"
  | Op.STREX -> "strex"
  | Op.LDREX -> "ldrex"
  | Op.STREXD -> "strexd"
  | Op.LDREXD -> "ldrexd"
  | Op.STREXB -> "strexb"
  | Op.LDREXB -> "ldrexb"
  | Op.STREXH -> "strexh"
  | Op.LDREXH -> "ldrexh"
  | Op.STRH -> "strh"
  | Op.LDRH -> "ldrh"
  | Op.LDRD -> "ldrd"
  | Op.LDRSB -> "ldrsb"
  | Op.STRD -> "strd"
  | Op.LDRSH -> "ldrsh"
  | Op.STRHT -> "strht"
  | Op.LDRHT -> "ldrht"
  | Op.LDRSBT -> "ldrsbt"
  | Op.LDRSHT -> "ldrsht"
  | Op.NOP -> "nop"
  | Op.YIELD -> "yield"
  | Op.WFE -> "wfe"
  | Op.WFI -> "wfi"
  | Op.SEV -> "sev"
  | Op.DBG -> "dbg"
  | Op.STR -> "str"
  | Op.STRT -> "strt"
  | Op.LDR -> "ldr"
  | Op.LDRT -> "ldrt"
  | Op.STRB -> "strb"
  | Op.STRBT -> "strbt"
  | Op.LDRB -> "ldrb"
  | Op.LDRBT -> "ldrbt"
  | Op.USAD8 -> "usad8"
  | Op.USADA8 -> "usada8"
  | Op.SBFX -> "sbfx"
  | Op.BFC -> "bfc"
  | Op.BFI -> "bfi"
  | Op.UBFX -> "ubfx"
  | Op.UDF -> "udf"
  | Op.SADD16 -> "sadd16"
  | Op.SASX -> "sasx"
  | Op.SSAX -> "ssax"
  | Op.SSUB16 -> "ssub16"
  | Op.SADD8 -> "sadd8"
  | Op.SSUB8 -> "ssub8"
  | Op.QADD16 -> "qadd16"
  | Op.QASX -> "qasx"
  | Op.QSAX -> "qsax"
  | Op.QSUB16 -> "qsub16"
  | Op.QADD8 -> "qadd8"
  | Op.QSUB8 -> "qsub8"
  | Op.SHADD16 -> "shadd16"
  | Op.SHASX -> "shasx"
  | Op.SHSAX -> "shsax"
  | Op.SHSUB16 -> "shsub16"
  | Op.SHADD8 -> "shadd8"
  | Op.SHSUB8 -> "shsub8"
  | Op.UADD16 -> "uadd16"
  | Op.UASX -> "uasx"
  | Op.USAX -> "usax"
  | Op.USUB16 -> "usub16"
  | Op.UADD8 -> "uadd8"
  | Op.USUB8 -> "usub8"
  | Op.UQADD16 -> "uqadd16"
  | Op.UQASX -> "uqasx"
  | Op.UQSAX -> "uqsax"
  | Op.UQSUB16 -> "uqsub16"
  | Op.UQADD8 -> "uqadd8"
  | Op.UQSUB8 -> "uqsub8"
  | Op.UHADD16 -> "uhadd16"
  | Op.UHASX -> "uhasx"
  | Op.UHSAX -> "uhsax"
  | Op.UHSUB16 -> "uhsub16"
  | Op.UHADD8 -> "uhadd8"
  | Op.UHSUB8 -> "uhsub8"
  | Op.PKHBT -> "pkhbt"
  | Op.PKHTB -> "pkhtb"
  | Op.SXTAB16 -> "sxtab16"
  | Op.SXTB16 -> "sxtb16"
  | Op.SEL -> "sel"
  | Op.SSAT -> "ssat"
  | Op.SSAT16 -> "ssat16"
  | Op.SXTAB -> "sxtab"
  | Op.SXTB -> "sxtb"
  | Op.REV -> "rev"
  | Op.SXTAH -> "sxtah"
  | Op.SXTH -> "sxth"
  | Op.REV16 -> "rev16"
  | Op.UXTAB16 -> "uxtab16"
  | Op.UXTB16 -> "uxtb16"
  | Op.USAT -> "usat"
  | Op.USAT16 -> "usat16"
  | Op.UXTAB -> "uxtab"
  | Op.UXTB -> "uxtb"
  | Op.RBIT -> "rbit"
  | Op.UXTAH -> "uxtah"
  | Op.UXTH -> "uxth"
  | Op.REVSH -> "revsh"
  | Op.SMLAD -> "smlad"
  | Op.SMLADX -> "smladx"
  | Op.SMUAD -> "smuad"
  | Op.SMUADX -> "smuadx"
  | Op.SMLSD -> "smlsd"
  | Op.SMLSDX -> "smlsdx"
  | Op.SMUSD -> "smusd"
  | Op.SMUSDX -> "smusdx"
  | Op.SDIV -> "sdiv"
  | Op.UDIV -> "udiv"
  | Op.SMLALD -> "smlald"
  | Op.SMLALDX -> "smlaldx"
  | Op.SMLSLD -> "smlsld"
  | Op.SMLSLDX -> "smlsldx"
  | Op.SMMLA -> "smmla"
  | Op.SMMLAR -> "smmlar"
  | Op.SMMUL -> "smmul"
  | Op.SMMULR -> "smmulr"
  | Op.SMMLS -> "smmls"
  | Op.SMMLSR -> "smmlsr"
  | Op.STMDA -> "stmda"
  | Op.LDMDA -> "ldmda"
  | Op.STM -> "stm"
  | Op.STMIA -> "stmia"
  | Op.STMEA -> "stmea"
  | Op.LDM -> "ldm"
  | Op.LDMIA -> "ldmia"
  | Op.POP -> "pop"
  | Op.STMDB -> "stmdb"
  | Op.PUSH -> "push"
  | Op.LDMDB -> "ldmdb"
  | Op.STMIB -> "stmib"
  | Op.LDMIB -> "ldmib"
  | Op.B -> "b"
  | Op.BL -> "bl"
  | Op.SVC -> "svc"
  | Op.STC -> "stc"
  | Op.STCL -> "stcl"
  | Op.STC2 -> "stc2"
  | Op.STC2L -> "stc2l"
  | Op.LDC -> "ldc"
  | Op.LDCL -> "ldcl"
  | Op.LDC2 -> "ldc2"
  | Op.LDC2L -> "ldc2l"
  | Op.MCRR -> "mcrr"
  | Op.MCRR2 -> "mcrr2"
  | Op.MRRC -> "mrrc"
  | Op.MRRC2 -> "mrrc2"
  | Op.CDP -> "cdp"
  | Op.CDP2 -> "cdp2"
  | Op.MCR -> "mcr"
  | Op.MCR2 -> "mcr2"
  | Op.MRC -> "mrc"
  | Op.MRC2 -> "mrc2"
  | Op.VSTM -> "vstm"
  | Op.VSTMIA -> "vstmia"
  | Op.VSTMDB -> "vstmdb"
  | Op.VSTR -> "vstr"
  | Op.VPUSH -> "vpush"
  | Op.VLDM -> "vldm"
  | Op.VLDMIA -> "vldmia"
  | Op.VLDMDB -> "vldmdb"
  | Op.VPOP -> "vpop"
  | Op.VLDR -> "vldr"
  | Op.VMOV -> "vmov"
  | Op.VMLA -> "vmla"
  | Op.VMLS -> "vmls"
  | Op.VNMLA -> "vnmla"
  | Op.VNMLS -> "vnmls"
  | Op.VNMUL -> "vnmul"
  | Op.VMUL -> "vmul"
  | Op.VADD -> "vadd"
  | Op.VSUB -> "vsub"
  | Op.VDIV -> "vdiv"
  | Op.VFNMA -> "vfnma"
  | Op.VFNMS -> "vfnms"
  | Op.VFMA -> "vfma"
  | Op.VFMS -> "vfms"
  | Op.VABS -> "vabs"
  | Op.VNEG -> "vneg"
  | Op.VSQRT -> "vsqrt"
  | Op.VCVTB -> "vcvtb"
  | Op.VCVTT -> "vcvtt"
  | Op.VCMP -> "vcmp"
  | Op.VCMPE -> "vcmpe"
  | Op.VCVT -> "vcvt"
  | Op.VCVTR -> "vcvtr"
  | Op.VMSR -> "vmsr"
  | Op.VDUP -> "vdup"
  | Op.VMRS -> "vmrs"
  | Op.SRS -> "srs"
  | Op.SRSDA -> "srsda"
  | Op.SRSDB -> "srsdb"
  | Op.SRSIA -> "srsia"
  | Op.SRSIB -> "srsib"
  | Op.RFE -> "rfe"
  | Op.RFEDA -> "rfeda"
  | Op.RFEDB -> "rfedb"
  | Op.RFEIA -> "rfeia"
  | Op.RFEIB -> "rfeib"
  | Op.CPS -> "cps"
  | Op.SETEND -> "setend"
  | Op.PLI -> "pli"
  | Op.PLD -> "pld"
  | Op.PLDW -> "pldw"
  | Op.CLREX -> "clrex"
  | Op.DSB -> "dsb"
  | Op.DMB -> "dmb"
  | Op.ISB -> "isb"
  | Op.VEXT -> "vext"
  | Op.VTBL -> "vtbl"
  | Op.VTBX -> "vtbx"
  | Op.VHADD -> "vhadd"
  | Op.VHSUB -> "vhsub"
  | Op.VQADD -> "vqadd"
  | Op.VRHADD -> "vrhadd"
  | Op.VAND -> "vand"
  | Op.VBIC -> "vbic"
  | Op.VORR -> "vorr"
  | Op.VORN -> "vorn"
  | Op.VEOR -> "veor"
  | Op.VBIF -> "vbif"
  | Op.VBIT -> "vbit"
  | Op.VBSL -> "vbsl"
  | Op.VQSUB -> "vqsub"
  | Op.VCGT -> "vcgt"
  | Op.VCGE -> "vcge"
  | Op.VSHL -> "vshl"
  | Op.VQSHL -> "vqshl"
  | Op.VRSHL -> "vrshl"
  | Op.VQRSHL -> "vqrshl"
  | Op.VMAX -> "vmax"
  | Op.VMIN -> "vmin"
  | Op.VABD -> "vabd"
  | Op.VABDL -> "vabdl"
  | Op.VABA -> "vaba"
  | Op.VABAL -> "vabal"
  | Op.VTST -> "vtst"
  | Op.VCEQ -> "vceq"
  | Op.VMLAL -> "vmlal"
  | Op.VMLSL -> "vmlsl"
  | Op.VMULL -> "vmull"
  | Op.VPMAX -> "vpmax"
  | Op.VPMIN -> "vpmin"
  | Op.VQDMULH -> "vqdmulh"
  | Op.VQRDMULH -> "vqrdmulh"
  | Op.VPADD -> "vpadd"
  | Op.VACGE -> "vacge"
  | Op.VACGT -> "vacgt"
  | Op.VACLE -> "vacle"
  | Op.VACLT -> "vaclt"
  | Op.VRECPS -> "vrecps"
  | Op.VRSQRTS -> "vrsqrts"
  | Op.VMVN -> "vmvn"
  | Op.VSHR -> "vshr"
  | Op.VSRA -> "vsra"
  | Op.VRSHR -> "vrshr"
  | Op.VRSRA -> "vrsra"
  | Op.VSRI -> "vsri"
  | Op.VSLI -> "vsli"
  | Op.VQSHLU -> "vqshlu"
  | Op.VSHRN -> "vshrn"
  | Op.VRSHRN -> "vrshrn"
  | Op.VQSHRN -> "vqshrn"
  | Op.VQSHRUN -> "vqshrun"
  | Op.VQRSHRN -> "vqrshrn"
  | Op.VQRSHRUN -> "vqrshrun"
  | Op.VSHLL -> "vshll"
  | Op.VMOVL -> "vmovl"
  | Op.VADDL -> "vaddl"
  | Op.VADDW -> "vaddw"
  | Op.VSUBL -> "vsubl"
  | Op.VSUBW -> "vsubw"
  | Op.VADDHN -> "vaddhn"
  | Op.VRADDHN -> "vraddhn"
  | Op.VSUBHN -> "vsubhn"
  | Op.VRSUBHN -> "vrsubhn"
  | Op.VQDMLAL -> "vqdmlal"
  | Op.VQDMLSL -> "vqdmlsl"
  | Op.VQDMULL -> "vqdmull"
  | Op.VREV16 -> "vrev16"
  | Op.VREV32 -> "vrev32"
  | Op.VREV64 -> "vrev64"
  | Op.VPADDL -> "vpaddl"
  | Op.VCLS -> "vcls"
  | Op.VCLZ -> "vclz"
  | Op.VCNT -> "vcnt"
  | Op.VPADAL -> "vpadal"
  | Op.VQABS -> "vqabs"
  | Op.VQNEG -> "vqneg"
  | Op.VCLE -> "vcle"
  | Op.VCLT -> "vclt"
  | Op.VSWP -> "vswp"
  | Op.VTRN -> "vtrn"
  | Op.VUZP -> "vuzp"
  | Op.VZIP -> "vzip"
  | Op.VMOVN -> "vmovn"
  | Op.VQMOVN -> "vqmovn"
  | Op.VQMOVUN -> "vqmovun"
  | Op.VRECPE -> "vrecpe"
  | Op.VRSQRTE -> "vrsqrte"
  | Op.VST1 -> "vst1"
  | Op.VST2 -> "vst2"
  | Op.VST3 -> "vst3"
  | Op.VST4 -> "vst4"
  | Op.VLD1 -> "vld1"
  | Op.VLD2 -> "vld2"
  | Op.VLD3 -> "vld3"
  | Op.VLD4 -> "vld4"
  | Op.CBNZ -> "cbnz"
  | Op.CBZ -> "cbz"
  | Op.CPSIE -> "cpsie"
  | Op.CPSID -> "cpsid"
  | Op.IT -> "it"
  | Op.ITT -> "itt"
  | Op.ITE -> "ite"
  | Op.ITTT -> "ittt"
  | Op.ITET -> "itet"
  | Op.ITTE -> "itte"
  | Op.ITEE -> "itee"
  | Op.ITTTT -> "itttt"
  | Op.ITETT -> "itett"
  | Op.ITTET -> "ittet"
  | Op.ITEET -> "iteet"
  | Op.ITTTE -> "ittte"
  | Op.ITETE -> "itete"
  | Op.ITTEE -> "ittee"
  | Op.ITEEE -> "iteee"
  | Op.TBB -> "tbb"
  | Op.TBH -> "tbh"
  | Op.ORN -> "orn"
  | Op.ORNS -> "orns"
  | Op.ADDW -> "addw"
  | Op.SUBW -> "subw"
  | Op.ENTERX -> "enterx"
  | Op.LEAVEX -> "leavex"
  | Op.MLAS -> "mlas"
  | Op.UMULLS -> "umulls"
  | Op.UMLALS -> "umlals"
  | Op.SMULLS -> "smulls"
  | Op.SMLALS -> "smlals"
  | Op.HLT -> "hlt"
  | Op.CRC32B -> "crc32b"
  | Op.CRC32CB -> "crc32cb"
  | Op.CRC32H -> "crc32h"
  | Op.CRC32CH -> "crc32ch"
  | Op.CRC32W -> "crc32w"
  | Op.CRC32CW -> "crc32cw"
  | Op.SEVL -> "sevl"
  | Op.STL -> "stl"
  | Op.STLEX -> "stlex"
  | Op.LDA -> "lda"
  | Op.LDAEX -> "ldaex"
  | Op.STLEXD -> "stlexd"
  | Op.LDAEXD -> "ldaexd"
  | Op.STLB -> "stlb"
  | Op.STLEXB -> "stlexb"
  | Op.LDAB -> "ldab"
  | Op.LDAEXB -> "ldaexb"
  | Op.STLH -> "stlh"
  | Op.STLEXH -> "stlexh"
  | Op.LDAH -> "ldah"
  | Op.LDAEXH -> "ldaexh"
  | Op.FSTMDBX -> "fstmdbx"
  | Op.FSTMIAX -> "fstmiax"
  | Op.AESE -> "aese"
  | Op.AESD -> "aesd"
  | Op.AESMC -> "aesmc"
  | Op.AESIMC -> "aesimc"
  | Op.SHA1H -> "sha1h"
  | Op.SHA1SU1 -> "sha1su1"
  | Op.SHA256SU0 -> "sha256su0"
  | Op.VRINTN -> "vrintn"
  | Op.VRINTX -> "vrintx"
  | Op.VRINTA -> "vrinta"
  | Op.VRINTZ -> "vrintz"
  | Op.VRINTM -> "vrintm"
  | Op.VRINTP -> "vrintp"
  | Op.VCVTA -> "vcvta"
  | Op.VCVTN -> "vcvtn"
  | Op.VCVTP -> "vcvtp"
  | Op.VCVTM -> "vcvtm"
  | Op.InvalidOP -> "(illegal)"
  | _ -> failwith "Unknown opcode encountered."

let condToString = function
  | Some Condition.EQ -> "eq"
  | Some Condition.NE -> "ne"
  | Some Condition.CS -> "cs"
  | Some Condition.HS -> "hs"
  | Some Condition.CC -> "cc"
  | Some Condition.LO -> "lo"
  | Some Condition.MI -> "mi"
  | Some Condition.PL -> "pl"
  | Some Condition.VS -> "vs"
  | Some Condition.VC -> "vc"
  | Some Condition.HI -> "hi"
  | Some Condition.LS -> "ls"
  | Some Condition.GE -> "ge"
  | Some Condition.LT -> "lt"
  | Some Condition.GT -> "gt"
  | Some Condition.LE -> "le"
  | Some Condition.AL -> ""
  | Some Condition.NV -> "nv"
  | Some Condition.UN | None -> ""
  | _ -> failwith "Unknown condition encountered."

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

let qualifierToStr = function
  | W -> ".w"
  | N -> ".n"

let inline appendQualifier ins (sb: StringBuilder) =
  match ins.Qualifier with
  | None ->  sb
  | Some q -> sb.Append (qualifierToStr q)

let inline appendSIMDDataTypes ins (sb: StringBuilder) =
  match ins.SIMDTyp with
  | None -> sb
  | Some (OneDT dt) -> sb.Append (SIMDTypToStr dt)
  | Some (TwoDT (dt1, dt2)) ->
    (sb.Append (SIMDTypToStr dt1)).Append (SIMDTypToStr dt2)

let inline buildOpcode ins builder acc =
  let sb = StringBuilder ()
  let sb = sb.Append (opCodeToString ins.Opcode)
  let sb = sb.Append (condToString ins.Condition)
  let sb = appendQualifier ins sb
  let sb = appendSIMDDataTypes ins sb
  builder AsmWordKind.Mnemonic (sb.ToString ()) acc

let existRegList = function
  | TwoOperands (_, OprRegList _) -> true
  | _ -> false

let isRFEorSRS = function
  | Op.RFE | Op.RFEDA | Op.RFEDB | Op.RFEIA | Op.RFEIB
  | Op.SRS | Op.SRSDA | Op.SRSDB | Op.SRSIA | Op.SRSIB -> true
  | _ -> false

let regToString = function
  | R.R0 -> "r0"
  | R.R1 -> "r1"
  | R.R2 -> "r2"
  | R.R3 -> "r3"
  | R.R4 -> "r4"
  | R.R5 -> "r5"
  | R.R6 -> "r6"
  | R.R7 -> "r7"
  | R.R8 -> "r8"
  | R.SB -> "sb"
  | R.SL -> "sl"
  | R.FP -> "fp"
  | R.IP -> "ip"
  | R.SP -> "sp"
  | R.LR -> "lr"
  | R.PC -> "pc"
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
  | R.FPINST2 -> "fpinst2"
  | R.MVFR0 -> "mvfr0"
  | R.MVFR1 -> "mvfr1"
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
  | R.P0 -> "p0"
  | R.P1 -> "p1"
  | R.P2 -> "p2"
  | R.P3 -> "p3"
  | R.P4 -> "p4"
  | R.P5 -> "p5"
  | R.P6 -> "p6"
  | R.P7 -> "p7"
  | R.P8 -> "p8"
  | R.P9 -> "p9"
  | R.P10 -> "p10"
  | R.P11 -> "p11"
  | R.P12 -> "p12"
  | R.P13 -> "p13"
  | R.P14 -> "p14"
  | R.P15 -> "p15"
  | R.APSR -> "apsr"
  | R.CPSR -> "cpsr"
  | R.SPSR -> "spsr"
  | R.SCR -> "scr"
  | R.SCTLR -> "sctlr"
  | R.NSACR -> "nsacr"
  | R.FPSCR -> "fpscr"
  | R.R8usr -> "r8_usr"
  | R.R9usr -> "r9_usr"
  | R.R10usr -> "r10_usr"
  | R.R11usr -> "r11_usr"
  | R.R12usr -> "r12_usr"
  | R.SPusr -> "sp_usr"
  | R.LRusr -> "lr_usr"
  | R.SPhyp -> "sp_hyp"
  | R.SPSRhyp -> "spsr_hyp"
  | R.ELRhyp -> "elr_hyp"
  | R.SPsvc -> "sp_svc"
  | R.LRsvc -> "lr_svc"
  | R.SPSRsvc -> "spsr_svc"
  | R.SPabt -> "sp_abt"
  | R.LRabt -> "lr_abt"
  | R.SPSRabt -> "spsr_abt"
  | R.SPund -> "sp_und"
  | R.LRund -> "lr_und"
  | R.SPSRund -> "spsr_und"
  | R.SPmon -> "sp_mon"
  | R.LRmon -> "lr_mon"
  | R.SPSRmon -> "spsr_mon"
  | R.SPirq -> "sp_irq"
  | R.LRirq -> "lr_irq"
  | R.SPSRirq -> "spsr_irq"
  | R.R8fiq -> "r8_fiq"
  | R.R9fiq -> "r9_fiq"
  | R.R10fiq -> "r10_fiq"
  | R.R11fiq -> "r11_fiq"
  | R.R12fiq -> "r12_fiq"
  | R.SPfiq -> "sp_fiq"
  | R.LRfiq -> "lr_fiq"
  | R.SPSRfiq -> "spsr_fiq"
  | _ -> failwith "Invalid Register"

let buildReg ins isRegList reg builder acc =
  let reg = regToString reg
  match ins.WriteBack with
  | Some true when existRegList ins.Operands && not isRegList ->
    builder AsmWordKind.Variable reg acc |> builder AsmWordKind.String "!"
  | Some true when isRFEorSRS ins.Opcode ->
    builder AsmWordKind.Variable reg acc |> builder AsmWordKind.String "!"
  | _ ->
    builder AsmWordKind.Variable reg acc

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

let specRegToString ins reg pFlag builder acc =
  match pFlag with
  | None -> buildReg ins false reg builder acc
  | Some f ->
    buildReg ins false reg builder acc
    |> builder AsmWordKind.String (flagToString f)

let regListToString ins list builder acc =
  let acc = builder AsmWordKind.String "{" acc
  let len = List.length list
  list
  |> List.fold (fun (acc, idx) r ->
    let acc = buildReg ins true r builder acc
    if idx + 1 = len then (acc, idx + 1)
    else builder AsmWordKind.String ", " acc, idx + 1) (acc, 0)
  |> fst
  |> builder AsmWordKind.String "}"

let simdToString ins s builder acc =
  match s with
  | Vector v -> buildReg ins false v builder acc
  | Scalar (v, None) ->
    buildReg ins false v builder acc
    |> builder AsmWordKind.String "[]"
  | Scalar (v, Some i) ->
    buildReg ins false v builder acc
    |> builder AsmWordKind.String "["
    |> builder AsmWordKind.String (string i)
    |> builder AsmWordKind.String "]"

let simdOprToString ins simd builder acc =
  match simd with
  | SFReg s -> simdToString ins s builder acc
  | OneReg s ->
    builder AsmWordKind.String "{" acc
    |> simdToString ins s builder
    |> builder AsmWordKind.String "}"
  | TwoRegs (s1, s2) ->
    builder AsmWordKind.String "{" acc
    |> simdToString ins s1 builder
    |> builder AsmWordKind.String ", "
    |> simdToString ins s2 builder
    |> builder AsmWordKind.String "}"
  | ThreeRegs (s1, s2, s3) ->
    builder AsmWordKind.String "{" acc
    |> simdToString ins s1 builder
    |> builder AsmWordKind.String ", "
    |> simdToString ins s2 builder
    |> builder AsmWordKind.String ", "
    |> simdToString ins s3 builder
    |> builder AsmWordKind.String "}"
  | FourRegs (s1, s2, s3, s4) ->
    builder AsmWordKind.String "{" acc
    |> simdToString ins s1 builder
    |> builder AsmWordKind.String ", "
    |> simdToString ins s2 builder
    |> builder AsmWordKind.String ", "
    |> simdToString ins s3 builder
    |> builder AsmWordKind.String ", "
    |> simdToString ins s4 builder
    |> builder AsmWordKind.String "}"

let signToString = function
  | None -> ""
  | Some Plus -> ""
  | Some Minus -> "-"

let immToString (imm: int64) sign builder acc =
  builder AsmWordKind.String "#" acc
  |> builder AsmWordKind.String (signToString sign)
  |> builder AsmWordKind.Value ("0x" + imm.ToString ("X"))

let fpImmToString (fp: float) builder acc =
  builder AsmWordKind.String "#" acc
  |> builder AsmWordKind.Value (fp.ToString ("N8"))

let optionToString (opt: int64) builder acc =
  builder AsmWordKind.Value ("0x" + opt.ToString ("X")) acc

let srTypeToString = function
  | SRTypeLSL -> "lsl"
  | SRTypeLSR -> "lsr"
  | SRTypeASR -> "asr"
  | SRTypeROR -> "ror"
  | SRTypeRRX -> "rrx"

let prependDelimiter delimiter builder acc =
  match delimiter with
  | None -> acc
  | Some delim ->
    builder AsmWordKind.String delim acc

let shiftToString shift delim builder acc =
  match shift with
  | _, Imm 0u -> acc
  | s, Imm i ->
    prependDelimiter delim builder acc
    |> builder AsmWordKind.String (srTypeToString s)
    |> builder AsmWordKind.String " "
    |> immToString (int64 i) None builder

let regShiftToString ins shift reg builder acc =
  builder AsmWordKind.String (srTypeToString shift) acc
  |> builder AsmWordKind.String " "
  |> buildReg ins false reg builder

let delimPostIdx = function
  | PostIdxMode _ -> "], "
  | _ -> ", "

let immOffsetToString ins addrMode offset builder acc =
  match offset with
  | reg, _, None | reg, _, Some 0L -> buildReg ins false reg builder acc
  | reg, s, Some imm ->
    buildReg ins false reg builder acc
    |> builder AsmWordKind.String (delimPostIdx addrMode)
    |> immToString imm s builder

let regOffsetToString ins addrMode offset builder acc =
  match offset with
  | bReg, s, reg, None ->
    buildReg ins false bReg builder acc
    |> builder AsmWordKind.String (delimPostIdx addrMode)
    |> builder AsmWordKind.String (signToString s)
    |> buildReg ins false reg builder
  | bReg, s, reg, Some shift ->
    buildReg ins false bReg builder acc
    |> builder AsmWordKind.String (delimPostIdx addrMode)
    |> builder AsmWordKind.String (signToString s)
    |> buildReg ins false reg builder
    |> shiftToString shift (Some ", ") builder

let alignOffsetToString ins offset builder acc =
  match offset with
  | bReg, Some align, None ->
    buildReg ins false bReg builder acc
    |> builder AsmWordKind.String ":"
    |> builder AsmWordKind.String (string align)
  | bReg, Some align, Some reg ->
    buildReg ins false bReg builder acc
    |> builder AsmWordKind.String ":"
    |> builder AsmWordKind.String (string align)
    |> builder AsmWordKind.String "], "
    |> buildReg ins false reg builder
  | bReg, None, Some reg ->
    buildReg ins false bReg builder acc
    |> builder AsmWordKind.String "], "
    |> buildReg ins false reg builder
  | bReg, None, None -> buildReg ins false bReg builder acc

let offsetToString ins addrMode offset builder acc =
  match offset with
  | ImmOffset (reg, s, imm) ->
    immOffsetToString ins addrMode (reg, s, imm) builder acc
  | RegOffset (bReg, s, reg, shf) ->
    regOffsetToString ins addrMode (bReg, s, reg, shf) builder acc
  | AlignOffset (bReg, align, reg) ->
    alignOffsetToString ins (bReg, align, reg) builder acc

let processAddrExn32 ins addr =
  let pc =
    if ins.Mode = ArchOperationMode.ThumbMode then addr + 4UL else addr + 8UL
  match ins.Opcode with
  | Op.CBZ | Op.CBNZ
  | Op.B | Op.BX -> pc
  | Op.BL | Op.BLX -> ParseUtils.align pc 4UL
  | Op.ADR -> ParseUtils.align pc 4UL
  | _ -> addr

let memHead ins addr addrMode builder acc =
  match addrMode with
  | OffsetMode offset | PreIdxMode offset | PostIdxMode offset ->
    builder AsmWordKind.String "[" acc
    |> offsetToString ins addrMode offset builder
  | UnIdxMode (reg, opt) ->
    builder AsmWordKind.String "[" acc
    |> buildReg ins false reg builder
    |> builder AsmWordKind.String "], {"
    |> optionToString opt builder
  | LiteralMode lbl ->
    let addr = processAddrExn32 ins addr
    let str = "0x" + ((int32 addr) + (int32 lbl)).ToString ("x")
    builder AsmWordKind.String str acc

let memTail addrMode builder acc =
  match addrMode with
  | OffsetMode _ -> builder AsmWordKind.String "]" acc
  | PreIdxMode _ -> builder AsmWordKind.String "]!" acc
  | PostIdxMode _ -> acc
  | UnIdxMode _ -> builder AsmWordKind.String "}" acc
  | LiteralMode _ -> acc

let memToString ins addr addrMode builder acc =
  memHead ins addr addrMode builder acc
  |> memTail addrMode builder

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

let iFlagToString = function
  | A -> "a"
  | I -> "i"
  | F -> "f"
  | AI -> "ai"
  | AF -> "af"
  | IF -> "if"
  | AIF -> "aif"

let endToString = function
  | Endian.Little -> "le"
  | Endian.Big -> "be"
  | _ -> invalidArg "Endian" "Invalid endian is given."

let oprToString i addr operand delim builder acc =
  match operand with
  | OprReg reg ->
    prependDelimiter delim builder acc |> buildReg i false reg builder
  | OprSpecReg (reg, pFlag) ->
    prependDelimiter delim builder acc |> specRegToString i reg pFlag builder
  | OprRegList regList ->
    prependDelimiter delim builder acc |> regListToString i regList builder
  | OprSIMD simd ->
    prependDelimiter delim builder acc |> simdOprToString i simd builder
  | OprImm imm ->
    prependDelimiter delim builder acc |> immToString imm None builder
  | OprFPImm fp ->
    prependDelimiter delim builder acc |> fpImmToString fp builder
  | OprShift s ->
    shiftToString s delim builder acc
  | OprRegShift (s, r) ->
    prependDelimiter delim builder acc |> regShiftToString i s r builder
  | OprMemory addrMode ->
    prependDelimiter delim builder acc |> memToString i addr addrMode builder
  | OprOption opt ->
    prependDelimiter delim builder acc
    |> builder AsmWordKind.String (optToString opt)
  | OprIflag flag ->
    prependDelimiter delim builder acc
    |> builder AsmWordKind.String (iFlagToString flag)
  | OprEndian e ->
    prependDelimiter delim builder acc
    |> builder AsmWordKind.String (endToString e)
  | OprCond c ->
    prependDelimiter delim builder acc
    |> builder AsmWordKind.String (condToString (Some c))

let buildOprs ins pc builder acc =
  match ins.Operands with
  | NoOperand -> acc
  | OneOperand opr ->
    oprToString ins pc opr (Some " ") builder acc
  | TwoOperands (opr1, opr2) ->
    oprToString ins pc opr1 (Some " ") builder acc
    |> oprToString ins pc opr2 (Some ", ") builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString ins pc opr1 (Some " ") builder acc
    |> oprToString ins pc opr2 (Some ", ") builder
    |> oprToString ins pc opr3 (Some ", ") builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    oprToString ins pc opr1 (Some " ") builder acc
    |> oprToString ins pc opr2 (Some ", ") builder
    |> oprToString ins pc opr3 (Some ", ") builder
    |> oprToString ins pc opr4 (Some ", ") builder
  | FiveOperands (opr1, opr2, opr3, opr4, opr5) ->
    oprToString ins pc opr1 (Some " ") builder acc
    |> oprToString ins pc opr2 (Some ", ") builder
    |> oprToString ins pc opr3 (Some ", ") builder
    |> oprToString ins pc opr4 (Some ", ") builder
    |> oprToString ins pc opr5 (Some ", ") builder
  | SixOperands (opr1, opr2, opr3, opr4, opr5, opr6) ->
    oprToString ins pc opr1 (Some " ") builder acc
    |> oprToString ins pc opr2 (Some ", ") builder
    |> oprToString ins pc opr3 (Some ", ") builder
    |> oprToString ins pc opr4 (Some ", ") builder
    |> oprToString ins pc opr5 (Some ", ") builder
    |> oprToString ins pc opr6 (Some ", ") builder

let disasm showAddr ins builder acc =
  let pc = ins.Address
  DisasmBuilder.addr pc WordSize.Bit32 showAddr builder acc
  |> buildOpcode ins builder
  |> buildOprs ins pc builder

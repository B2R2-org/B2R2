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
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

type Condition =
  /// Less than [LT].
  | LT = 0x0
  /// Less than or equal (equivalent to ng) [GT].
  | LE = 0x1
  /// Equal [EQ].
  | EQ = 0x2
  /// Greater than or equal (equivalent to nl) [LT].
  | GE = 0x3
  /// Greater than [GT].
  | GT = 0x4
  /// Not less than (equivalent to ge) [LT].
  | NL = 0x5
  /// Not equal [EQ].
  | NE = 0x6
  /// Not greater than (equivalent to le) [GT].
  | NG = 0x7
  /// Summary overflow [SO].
  | SO = 0x8
  /// Not summary overflow [SO].
  | NS = 0x9
  /// Unordered (after floating-point comparison) [SO].
  | UN = 0xA
  /// Not unordered (after floating-point comparison) [SO].
  | NU = 0xB

let opCodeToString = function
  | Op.ADD -> "add"
  | Op.ADDdot -> "add."
  | Op.ADDO -> "addo"
  | Op.ADDOdot -> "addo."
  | Op.ADDC -> "addc"
  | Op.ADDCdot -> "addc."
  | Op.ADDCO -> "addco"
  | Op.ADDCOdot -> "addco."
  | Op.ADDE -> "adde"
  | Op.ADDEdot -> "adde."
  | Op.ADDEO -> "addeo"
  | Op.ADDEOdot -> "addeo."
  | Op.ADDME -> "addme"
  | Op.ADDMEdot -> "addme."
  | Op.ADDMEO -> "addmeo"
  | Op.ADDMEOdot -> "addmeo."
  | Op.ADDZE -> "addze"
  | Op.ADDZEdot -> "addze."
  | Op.ADDZEO -> "addzeo"
  | Op.ADDZEOdot -> "addzeo."
  | Op.DIVW -> "divw"
  | Op.DIVWdot -> "divw."
  | Op.DIVWO -> "divwo"
  | Op.DIVWOdot -> "divwo."
  | Op.DIVWU -> "divwu"
  | Op.DIVWUdot -> "divwu."
  | Op.DIVWUO -> "divwuo"
  | Op.DIVWUOdot -> "divwuo."
  | Op.MULLW -> "mullw"
  | Op.MULLWdot -> "mullw."
  | Op.MULLWO -> "mullwo"
  | Op.MULLWOdot -> "mullwo."
  | Op.NEG -> "neg"
  | Op.NEGdot -> "neg."
  | Op.NEGO -> "nego"
  | Op.NEGOdot -> "nego."
  | Op.SUBF -> "subf"
  | Op.SUBFdot -> "subf."
  | Op.SUBFO -> "subfo"
  | Op.SUBFOdot -> "subfo."
  | Op.SUBFC -> "subfc"
  | Op.SUBFCdot -> "subfc."
  | Op.SUBFCO -> "subfco"
  | Op.SUBFCOdot -> "subfco."
  | Op.SUBFE -> "subfe"
  | Op.SUBFEdot -> "subfe."
  | Op.SUBFEO -> "subfeo"
  | Op.SUBFEOdot -> "subfeo."
  | Op.SUBFME -> "subfme"
  | Op.SUBFMEdot -> "subfme."
  | Op.SUBFMEO -> "subfmeo"
  | Op.SUBFMEOdot -> "subfmeo."
  | Op.SUBFZE -> "subfze"
  | Op.SUBFZEdot -> "subfze."
  | Op.SUBFZEO -> "subfzeo"
  | Op.SUBFZEOdot -> "subfzeo."
  | Op.MULHW -> "mulhw"
  | Op.MULHWdot -> "mulhw."
  | Op.MULHWU -> "mulhwu"
  | Op.MULHWUdot -> "mulhwu."
  | Op.AND -> "and"
  | Op.ANDdot -> "and."
  | Op.ANDC -> "andc"
  | Op.ANDCdot -> "andc."
  | Op.CNTLZW -> "cntlzw"
  | Op.CNTLZWdot -> "cntlzw."
  | Op.DCBTST -> "dcbtst"
  | Op.DCBA -> "dcba"
  | Op.DCBF -> "dcbf"
  | Op.DCBI -> "dcbi"
  | Op.ICBI -> "icbi"
  | Op.DCBST -> "dcbst"
  | Op.DCBT -> "dcbt"
  | Op.DCBZ -> "dcbz"
  | Op.ECIWX -> "eciwx"
  | Op.ECOWX -> "ecowx"
  | Op.EIEIO -> "eieio"
  | Op.EQV -> "eqv"
  | Op.EQVdot -> "eqv."
  | Op.EXTSB -> "extsb"
  | Op.EXTSBdot -> "extsb."
  | Op.EXTSH -> "extsh"
  | Op.EXTSHdot -> "extsh."
  | Op.LBZUX -> "lbzux"
  | Op.LBZX -> "lbzx"
  | Op.LFDUX -> "lfdux"
  | Op.LFDX -> "lfdx"
  | Op.LFSUX -> "lfsux"
  | Op.LFSX -> "lfsx"
  | Op.LHAUX -> "lhaux"
  | Op.LHAX -> "lhax"
  | Op.LHBRX -> "lhbrx"
  | Op.LHZUX -> "lhzux"
  | Op.LHZX -> "lhzx"
  | Op.LSWI -> "lswi"
  | Op.LSWX -> "lswx"
  | Op.LWARX -> "lwarx"
  | Op.LWBRX -> "lwbrx"
  | Op.LWZUX -> "lwzux"
  | Op.LWZX -> "lwzx"
  | Op.CMP -> "cmp"
  | Op.CMPL -> "cmpl"
  | Op.MCRXR -> "mcrxr"
  | Op.MFCR -> "mfcr"
  | Op.MFMSR -> "mfmsr"
  | Op.MFSRIN -> "mfsrin"
  | Op.MTMSR -> "mtmsr"
  | Op.MTSRIN -> "mtsrin"
  | Op.NAND -> "nand"
  | Op.NANDdot -> "nand."
  | Op.NOR -> "nor"
  | Op.NORdot -> "nor."
  | Op.OR -> "or"
  | Op.ORdot -> "or."
  | Op.ORC -> "orc"
  | Op.ORCdot -> "orc."
  | Op.SLW -> "slw"
  | Op.SLWdot -> "slw."
  | Op.SRAW -> "sraw"
  | Op.SRAWdot -> "sraw."
  | Op.SRW -> "srw"
  | Op.SRWdot -> "srw."
  | Op.STBUX -> "stbux"
  | Op.STBX -> "stbx"
  | Op.STFDUX -> "stfdux"
  | Op.STFDX -> "stfdx"
  | Op.STFIWX -> "stfiwx"
  | Op.STWUX -> "stwux"
  | Op.STFSUX -> "stfsux"
  | Op.STWX -> "stwx"
  | Op.STFSX -> "stfsx"
  | Op.STHBRX -> "sthbrx"
  | Op.STHUX -> "sthux"
  | Op.STHX -> "sthx"
  | Op.STWBRX -> "stwbrx"
  | Op.STWCXdot -> "stwcx."
  | Op.SYNC -> "sync"
  | Op.TLBIA -> "tlbia"
  | Op.TLBIE -> "tlbie"
  | Op.TLBSYNC -> "tlbsync"
  | Op.XOR -> "xor"
  | Op.XORdot -> "xor."
  | Op.STSWX -> "stswx"
  | Op.CMPW -> "cmpw"
  | Op.CMPLW -> "cmplw"
  | Op.TW -> "tw"
  | Op.TWEQ -> "tweq"
  | Op.TRAP -> "trap"
  | Op.MTCRF -> "mtcrf"
  | Op.MTSR -> "mtsr"
  | Op.MFSPR -> "mfspr"
  | Op.MFXER -> "mfxer"
  | Op.MFLR -> "mflr"
  | Op.MFCTR -> "mfctr"
  | Op.MFTB -> "mftb"
  | Op.MFTBU -> "mftbu"
  | Op.MTSPR -> "mtspr"
  | Op.MTXER -> "mtxer"
  | Op.MTLR -> "mtlr"
  | Op.MTCTR -> "mtctr"
  | Op.MFSR -> "mfsr"
  | Op.STSWI -> "stswi"
  | Op.SRAWI -> "srawi"
  | Op.SRAWIdot -> "srawi."
  | Op.FCMPU -> "fcmpu"
  | Op.FRSP -> "frsp"
  | Op.FRSPdot -> "frsp."
  | Op.FCTIW -> "fctiw"
  | Op.FCTIWdot -> "fctiw."
  | Op.FCTIWZ -> "fctiwz"
  | Op.FCTIWZdot -> "fctiwz."
  | Op.FDIV -> "fdiv"
  | Op.FDIVdot -> "fdiv."
  | Op.FSUB -> "fsub"
  | Op.FSUBdot -> "fsub."
  | Op.FADD -> "fadd"
  | Op.FADDdot -> "fadd."
  | Op.FSQRT -> "fsqrt"
  | Op.FSQRTdot -> "fsqrt."
  | Op.FSEL -> "fsel"
  | Op.FSELdot -> "fsel."
  | Op.FMUL -> "fmul"
  | Op.FMULdot -> "fmul."
  | Op.FRSQRTE -> "frsqrte"
  | Op.FRSQRTEdot -> "frsqrte."
  | Op.FMSUB -> "fmsub"
  | Op.FMSUBdot -> "fmsub."
  | Op.FMADD -> "fmadd"
  | Op.FMADDdot -> "fmadd."
  | Op.FNMSUB -> "fnmsub"
  | Op.FNMSUBdot -> "fnmsub."
  | Op.FNMADD -> "fnmadd"
  | Op.FNMADDdot -> "fnmadd."
  | Op.FCMPO -> "fcmpo"
  | Op.MTFSB1 -> "mtfsb1"
  | Op.MTFSB1dot -> "mtfsb1."
  | Op.FNEG -> "fneg"
  | Op.FNEGdot -> "fneg."
  | Op.MCRFS -> "mcrfs"
  | Op.MTFSB0 -> "mtfsb0"
  | Op.MTFSB0dot -> "mtfsb0."
  | Op.FMR -> "fmr"
  | Op.FMRdot -> "fmr."
  | Op.MTFSFI -> "mtfsfi"
  | Op.MTFSFIdot -> "mtfsfi."
  | Op.FNABS -> "fnabs"
  | Op.FNABSdot -> "fnabs."
  | Op.FABS -> "fabs"
  | Op.FABSdot -> "fabs."
  | Op.MFFS -> "mffs"
  | Op.MFFSdot -> "mffs."
  | Op.MTFSF -> "mtfsf"
  | Op.MTFSFdot -> "mtfsf."
  | Op.FDIVS -> "fdivs"
  | Op.FDIVSdot -> "fdivs."
  | Op.FSUBS -> "fsubs"
  | Op.FSUBSdot -> "fsubs."
  | Op.FADDS -> "fadds"
  | Op.FADDSdot -> "fadds."
  | Op.FSQRTS -> "fsqrts"
  | Op.FSQRTSdot -> "fsqrts."
  | Op.FRES -> "fres"
  | Op.FRESdot -> "fres."
  | Op.FMULS -> "fmuls"
  | Op.FMULSdot -> "fmuls."
  | Op.FMSUBS -> "fmsubs"
  | Op.FMSUBSdot -> "fmsubs."
  | Op.FMADDS -> "fmadds"
  | Op.FMADDSdot -> "fmadds."
  | Op.FNMSUBS -> "fnmsubs"
  | Op.FNMSUBSdot -> "fnmsubs."
  | Op.FNMADDS -> "fnmadds"
  | Op.FNMADDSdot -> "fnmadds."
  | Op.TWLGT -> "twlgt"
  | Op.TWLLE -> "twlle"
  | Op.TWGE -> "twge"
  | Op.TWGT -> "twgt"
  | Op.TWLE -> "twle"
  | Op.TWLT -> "twlt"
  | Op.TWLLT -> "twllt"
  | Op.TWLNL -> "twlnl"
  | Op.TWNE -> "twne"
  | Op.TWI -> "twi"
  | Op.TWLGTI -> "twlgti"
  | Op.TWLLEI -> "twllei"
  | Op.TWLLTI -> "twllti"
  | Op.TWEQI -> "tweqi"
  | Op.TWLNLI -> "twlnli"
  | Op.TWGEI -> "twgei"
  | Op.TWGTI -> "twgti"
  | Op.TWLTI -> "twlti"
  | Op.TWLEI -> "twlei"
  | Op.TWNEI -> "twnei"
  | Op.MULLI -> "mulli"
  | Op.SUBFIC -> "subfic"
  | Op.CMPLI -> "cmpli"
  | Op.CMPLWI -> "cmplwi"
  | Op.CMPI -> "cmpi"
  | Op.CMPWI -> "cmpwi"
  | Op.ADDIC -> "addic"
  | Op.ADDICdot -> "addic."
  | Op.LI -> "li"
  | Op.ADDI -> "addi"
  | Op.LIS -> "lis"
  | Op.ADDIS -> "addis"
  | Op.SC -> "sc"
  | Op.B -> "b"
  | Op.BL -> "bl"
  | Op.BA -> "ba"
  | Op.BLA -> "bla"
  | Op.LWZ -> "lwz"
  | Op.LWZU -> "lwzu"
  | Op.LBZ -> "lbz"
  | Op.LBZU -> "lbzu"
  | Op.STW -> "stw"
  | Op.STWU -> "stwu"
  | Op.STB -> "stb"
  | Op.STBU -> "stbu"
  | Op.LHZ -> "lhz"
  | Op.LHZU -> "lhzu"
  | Op.LHA -> "lha"
  | Op.LHAU -> "lhau"
  | Op.STH -> "sth"
  | Op.STHU -> "sthu"
  | Op.LMW -> "lmw"
  | Op.STMW -> "stmw"
  | Op.LFIWAX -> "lfiwax"
  | Op.LFIWZX -> "lfiwzx"
  | Op.LFS -> "lfs"
  | Op.LFSU -> "lfsu"
  | Op.LFD -> "lfd"
  | Op.LFDU -> "lfdu"
  | Op.STFS -> "stfs"
  | Op.STFSU -> "stfsu"
  | Op.STFD -> "stfd"
  | Op.STFDU -> "stfdu"
  | Op.ORI -> "ori"
  | Op.NOP -> "nop"
  | Op.ORIS -> "oris"
  | Op.XORI -> "xori"
  | Op.XORIS -> "xoris"
  | Op.ANDIdot -> "andi."
  | Op.ANDISdot -> "andis."
  | Op.RLWNM -> "rlwnm"
  | Op.ROTLW -> "rotlw"
  | Op.RLWNMdot -> "rlwnm."
  | Op.RLWIMI -> "rlwimi"
  | Op.RLWIMIdot -> "rlwimi."
  | Op.RLWINM -> "rlwinm"
  | Op.RLWINMdot -> "rlwinm."
  | Op.CLRLWI -> "clrlwi"
  | Op.SLWI -> "slwi"
  | Op.ROTLWI -> "rotlwi"
  | Op.SRWI -> "srwi"
  | Op.MCRF -> "mcrf"
  | Op.CRNOR -> "crnor"
  | Op.CRNOT -> "crnot"
  | Op.RFI -> "rfi"
  | Op.CRANDC -> "crandc"
  | Op.ISYNC -> "isync"
  | Op.CRXOR -> "crxor"
  | Op.CRCLR -> "crclr"
  | Op.CRAND -> "crand"
  | Op.CRNAND -> "crnand"
  | Op.CREQV -> "creqv"
  | Op.CRSET -> "crset"
  | Op.CRORC -> "crorc"
  | Op.CROR -> "cror"
  | Op.CRMOVE -> "crmove"
  | Op.BC -> "bc"
  | Op.BCA -> "bca"
  | Op.BCL -> "bcl"
  | Op.BCLA -> "bcla"
  | Op.BCLR -> "bclr"
  | Op.BCLRL -> "bclrl"
  | Op.BCCTR -> "bcctr"
  | Op.BCCTRL -> "bcctrl"
  | Op.BDNZF -> "bdnzf"
  | Op.BDNZFA -> "bdnzfa"
  | Op.BDNZFL -> "bdnzfl"
  | Op.BDNZFLA -> "bdnzfla"
  | Op.BDZF -> "bdzf"
  | Op.BDZFA -> "bdzfa"
  | Op.BDZFL -> "bdzfl"
  | Op.BDZFLA -> "bdzfla"
  | Op.BGE -> "bge"
  | Op.BLE -> "ble"
  | Op.BNE -> "bne"
  | Op.BNS -> "bns"
  | Op.BGEL -> "bgel"
  | Op.BLEL -> "blel"
  | Op.BNEL -> "bnel"
  | Op.BNSL -> "bnsl"
  | Op.BGEA -> "bgea"
  | Op.BLEA -> "blea"
  | Op.BNEA -> "bnea"
  | Op.BNSA -> "bnsa"
  | Op.BGELA -> "bgela"
  | Op.BLELA -> "blela"
  | Op.BNELA -> "bnela"
  | Op.BNSLA -> "bnsla"
  | Op.BDNZT -> "bdnzt"
  | Op.BDNZTA -> "bdnzta"
  | Op.BDNZTL -> "bdnztl"
  | Op.BDNZTLA -> "bdnztla"
  | Op.BDZT -> "bdzt"
  | Op.BDZTL -> "bdztl"
  | Op.BDZTA -> "bdzta"
  | Op.BDZTLA -> "bdztla"
  | Op.BLT -> "blt"
  | Op.BGT -> "bgt"
  | Op.BEQ -> "beq"
  | Op.BSO -> "bso"
  | Op.BLTL -> "bltl"
  | Op.BGTL -> "bgtl"
  | Op.BEQL -> "beql"
  | Op.BSOL -> "bsol"
  | Op.BLTA -> "blta"
  | Op.BGTA -> "bgta"
  | Op.BEQA -> "beqa"
  | Op.BSOA -> "bsoa"
  | Op.BLTLA -> "bltla"
  | Op.BGTLA -> "bgtla"
  | Op.BEQLA -> "beqla"
  | Op.BSOLA -> "bsola"
  | Op.BDNZ -> "bdnz"
  | Op.BDNZL -> "bdnzl"
  | Op.BDNZA -> "bdnza"
  | Op.BDNZLA -> "bdnzla"
  | Op.BDZ -> "bdz"
  | Op.BDZL -> "bdzl"
  | Op.BDZA -> "bdza"
  | Op.BDZLA -> "bdzla"
  | Op.BDNZFLR -> "bdnzflr"
  | Op.BDNZFLRL -> "bdnzflrl"
  | Op.BDZFLR -> "bdzflr"
  | Op.BDZFLRL -> "bdzflrl"
  | Op.BGELR -> "bgelr"
  | Op.BLELR -> "blelr"
  | Op.BNELR -> "bnelr"
  | Op.BNSLR -> "bnslr"
  | Op.BGELRL -> "bgelrl"
  | Op.BLELRL -> "blelrl"
  | Op.BNELRL -> "bnelrl"
  | Op.BNSLRL -> "bnslrl"
  | Op.BDNZTLR -> "bdnztlr"
  | Op.BDNZTLRL -> "bdnztlrl"
  | Op.BDZTLR -> "bdztlr"
  | Op.BDZTLRL -> "bdztlrl"
  | Op.BLTLR -> "bltlr"
  | Op.BGTLR -> "bgtlr"
  | Op.BEQLR -> "beqlr"
  | Op.BSOLR -> "bsolr"
  | Op.BLTLRL -> "bltlrl"
  | Op.BGTLRL -> "bgtlrl"
  | Op.BEQLRL -> "beqlrl"
  | Op.BSOLRL -> "bsolrl"
  | Op.BDNZLR -> "bdnzlr"
  | Op.BDNZLRL -> "bdnzlrl"
  | Op.BDZLR -> "bdzlr"
  | Op.BDZLRL -> "bdzlrl"
  | Op.BLR -> "blr"
  | Op.BLRL -> "blrl"
  | Op.BGECTR -> "bgectr"
  | Op.BLECTR -> "blectr"
  | Op.BNECTR -> "bnectr"
  | Op.BNSCTR -> "bnsctr"
  | Op.BGECTRL -> "bgectrl"
  | Op.BLECTRL -> "blectrl"
  | Op.BNECTRL -> "bnectrl"
  | Op.BNSCTRL -> "bnsctrl"
  | Op.BLTCTR -> "bltctr"
  | Op.BGTCTR -> "bgtctr"
  | Op.BEQCTR -> "beqctr"
  | Op.BSOCTR -> "bsoctr"
  | Op.BLTCTRL -> "bltctrl"
  | Op.BGTCTRL -> "bgtctrl"
  | Op.BEQCTRL -> "beqctrl"
  | Op.BSOCTRL -> "bsoctrl"
  | Op.BCTR -> "bctr"
  | Op.BCTRL -> "bctrl"
  | Op.MR -> "mr"
  | Op.BTLRL -> "btlrl"
  | Op.BFLRL -> "bflrl"
  | Op.BTCTRL -> "btctrl"
  | Op.CLRRWI -> "clrrwi"
  | Op.LWSYNC -> "lwsync"
  (* 64-bit forms. *)
  | Op.LD -> "ld"
  | Op.LDU -> "ldu"
  | Op.LDX -> "ldx"
  | Op.LDUX -> "ldux"
  | Op.LDARX -> "ldarx"
  | Op.LBARX -> "lbarx"
  | Op.LHARX -> "lharx"
  | Op.STBCXdot -> "stbcx."
  | Op.STHCXdot -> "sthcx."
  | Op.LDBRX -> "ldbrx"
  | Op.LWA -> "lwa"
  | Op.LWAX -> "lwax"
  | Op.LWAUX -> "lwaux"
  | Op.STD -> "std"
  | Op.STDU -> "stdu"
  | Op.STDX -> "stdx"
  | Op.STDUX -> "stdux"
  | Op.STDCXdot -> "stdcx."
  | Op.STDBRX -> "stdbrx"
  | Op.RLDICL -> "rldicl"
  | Op.RLDICLdot -> "rldicl."
  | Op.RLDICR -> "rldicr"
  | Op.RLDICRdot -> "rldicr."
  | Op.RLDIC -> "rldic"
  | Op.RLDICdot -> "rldic."
  | Op.RLDIMI -> "rldimi"
  | Op.RLDIMIdot -> "rldimi."
  | Op.RLDCL -> "rldcl"
  | Op.RLDCLdot -> "rldcl."
  | Op.RLDCR -> "rldcr"
  | Op.RLDCRdot -> "rldcr."
  | Op.SLD -> "sld"
  | Op.SLDdot -> "sld."
  | Op.SRD -> "srd"
  | Op.SRDdot -> "srd."
  | Op.SRAD -> "srad"
  | Op.SRADdot -> "srad."
  | Op.SRADI -> "sradi"
  | Op.SRADIdot -> "sradi."
  | Op.EXTSW -> "extsw"
  | Op.EXTSWdot -> "extsw."
  | Op.CNTLZD -> "cntlzd"
  | Op.CNTLZDdot -> "cntlzd."
  | Op.POPCNTB -> "popcntb"
  | Op.POPCNTW -> "popcntw"
  | Op.POPCNTD -> "popcntd"
  | Op.PRTYW -> "prtyw"
  | Op.PRTYD -> "prtyd"
  | Op.BPERMD -> "bpermd"
  | Op.CMPB -> "cmpb"
  | Op.CMPD -> "cmpd"
  | Op.CMPDI -> "cmpdi"
  | Op.CMPLD -> "cmpld"
  | Op.CMPLDI -> "cmpldi"
  | Op.MULLD -> "mulld"
  | Op.MULLDdot -> "mulld."
  | Op.MULLDO -> "mulldo"
  | Op.MULLDOdot -> "mulldo."
  | Op.MULHD -> "mulhd"
  | Op.MULHDdot -> "mulhd."
  | Op.MULHDU -> "mulhdu"
  | Op.MULHDUdot -> "mulhdu."
  | Op.DIVD -> "divd"
  | Op.DIVDdot -> "divd."
  | Op.DIVDO -> "divdo"
  | Op.DIVDOdot -> "divdo."
  | Op.DIVDU -> "divdu"
  | Op.DIVDUdot -> "divdu."
  | Op.DIVDUO -> "divduo"
  | Op.DIVDUOdot -> "divduo."
  | Op.TD -> "td"
  | Op.TDI -> "tdi"
  | Op.ISEL -> "isel"
  | Op.MTOCRF -> "mtocrf"
  | Op.MFOCRF -> "mfocrf"
  | Op.MFVSRD -> "mfvsrd"
  | Op.MFVSRWZ -> "mfvsrwz"
  | Op.MTVSRD -> "mtvsrd"
  | Op.MTVSRWA -> "mtvsrwa"
  | Op.MTVSRWZ -> "mtvsrwz"
  | Op.FCTID -> "fctid"
  | Op.FCTIDdot -> "fctid."
  | Op.FCTIDZ -> "fctidz"
  | Op.FCTIDZdot -> "fctidz."
  | Op.FCTIDU -> "fctidu"
  | Op.FCTIDUdot -> "fctidu."
  | Op.FCTIDUZ -> "fctiduz"
  | Op.FCTIDUZdot -> "fctiduz."
  | Op.FCTIWU -> "fctiwu"
  | Op.FCTIWUdot -> "fctiwu."
  | Op.FCTIWUZ -> "fctiwuz"
  | Op.FCTIWUZdot -> "fctiwuz."
  | Op.FCFID -> "fcfid"
  | Op.FCFIDdot -> "fcfid."
  | Op.FCFIDU -> "fcfidu"
  | Op.FCFIDUdot -> "fcfidu."
  | Op.FCFIDS -> "fcfids"
  | Op.FCFIDSdot -> "fcfids."
  | Op.FCFIDUS -> "fcfidus"
  | Op.FCFIDUSdot -> "fcfidus."
  | Op.FRIN -> "frin"
  | Op.FRINdot -> "frin."
  | Op.FRIZ -> "friz"
  | Op.FRIZdot -> "friz."
  | Op.FRIP -> "frip"
  | Op.FRIPdot -> "frip."
  | Op.FRIM -> "frim"
  | Op.FRIMdot -> "frim."
  (* Vector forms. *)
  | Op.LVEBX -> "lvebx"
  | Op.LVEHX -> "lvehx"
  | Op.LVEWX -> "lvewx"
  | Op.LVSL -> "lvsl"
  | Op.LVSR -> "lvsr"
  | Op.LVX -> "lvx"
  | Op.LVXL -> "lvxl"
  | Op.STVEBX -> "stvebx"
  | Op.STVEHX -> "stvehx"
  | Op.STVEWX -> "stvewx"
  | Op.STVX -> "stvx"
  | Op.STVXL -> "stvxl"
  | Op.LXSDX -> "lxsdx"
  | Op.LXSD -> "lxsd"
  | Op.LXVD2X -> "lxvd2x"
  | Op.LXVDSX -> "lxvdsx"
  | Op.LXVW4X -> "lxvw4x"
  | Op.STXSDX -> "stxsdx"
  | Op.STXSD -> "stxsd"
  | Op.STXVD2X -> "stxvd2x"
  | Op.STXVW4X -> "stxvw4x"
  | Op.XXLAND -> "xxland"
  | Op.XXLANDC -> "xxlandc"
  | Op.XXLEQV -> "xxleqv"
  | Op.XXLNAND -> "xxlnand"
  | Op.XXLNOR -> "xxlnor"
  | Op.XXLOR -> "xxlor"
  | Op.XXLORC -> "xxlorc"
  | Op.XXLXOR -> "xxlxor"
  | Op.XXPERMDI -> "xxpermdi"
  | Op.XXMRGHW -> "xxmrghw"
  | Op.XXMRGLW -> "xxmrglw"
  | Op.XXSEL -> "xxsel"
  | Op.XXSLDWI -> "xxsldwi"
  | Op.XSADDDP -> "xsadddp"
  | Op.XVADDDP -> "xvadddp"
  | Op.XVSUBDP -> "xvsubdp"
  | Op.XVMULDP -> "xvmuldp"
  | Op.XVDIVDP -> "xvdivdp"
  | Op.XVNEGDP -> "xvnegdp"
  | Op.XVCMPGEDP -> "xvcmpgedp"
  | Op.XVCMPGEDPdot -> "xvcmpgedp."
  | Op.XVCMPGTDP -> "xvcmpgtdp"
  | Op.XVCMPGTDPdot -> "xvcmpgtdp."
  | Op.XVCVSXWDP -> "xvcvsxwdp"
  | Op.XSSUBDP -> "xssubdp"
  | Op.XSSUBSP -> "xssubsp"
  | Op.XSCVSXDDP -> "xscvsxddp"
  | Op.XSCVSXDSP -> "xscvsxdsp"
  | Op.XSCVUXDDP -> "xscvuxddp"
  | Op.XSCVUXDSP -> "xscvuxdsp"
  | Op.XSDIVDP -> "xsdivdp"
  | Op.XSDIVSP -> "xsdivsp"
  | Op.XSADDSP -> "xsaddsp"
  | Op.XSCMPUDP -> "xscmpudp"
  | Op.XSCPSGNDP -> "xscpsgndp"
  | Op.XSABSDP -> "xsabsdp"
  | Op.XSMADDADP -> "xsmaddadp"
  | Op.XSMADDASP -> "xsmaddasp"
  | Op.XSMADDMDP -> "xsmaddmdp"
  | Op.XSMADDMSP -> "xsmaddmsp"
  | Op.XSMULDP -> "xsmuldp"
  | Op.XSMULSP -> "xsmulsp"
  | Op.XSMAXDP -> "xsmaxdp"
  | Op.XSMINDP -> "xsmindp"
  | Op.XSMSUBADP -> "xsmsubadp"
  | Op.XSMSUBASP -> "xsmsubasp"
  | Op.XSMSUBMDP -> "xsmsubmdp"
  | Op.XSMSUBMSP -> "xsmsubmsp"
  | Op.XSNABSDP -> "xsnabsdp"
  | Op.XSNEGDP -> "xsnegdp"
  | Op.XSNMADDADP -> "xsnmaddadp"
  | Op.XSNMADDASP -> "xsnmaddasp"
  | Op.XSNMADDMDP -> "xsnmaddmdp"
  | Op.XSNMADDMSP -> "xsnmaddmsp"
  | Op.XSNMSUBADP -> "xsnmsubadp"
  | Op.XSNMSUBASP -> "xsnmsubasp"
  | Op.XSNMSUBMDP -> "xsnmsubmdp"
  | Op.XSNMSUBMSP -> "xsnmsubmsp"
  | Op.XSRDPI -> "xsrdpi"
  | Op.XSRDPIM -> "xsrdpim"
  | Op.XSRDPIP -> "xsrdpip"
  | Op.XSRDPIZ -> "xsrdpiz"
  | Op.XSSQRTDP -> "xssqrtdp"
  | Op.XSSQRTSP -> "xssqrtsp"
  | Op.XSRSP -> "xsrsp"
  | Op.XSCVDPSP -> "xscvdpsp"
  | Op.XSCVDPSPN -> "xscvdpspn"
  | Op.XSCVDPSXDS -> "xscvdpsxds"
  | Op.XSCVDPSXWS -> "xscvdpsxws"
  | Op.XSCVDPUXDS -> "xscvdpuxds"
  | Op.XSCVDPUXWS -> "xscvdpuxws"
  | Op.XSCVSPDP -> "xscvspdp"
  | Op.XSCVSPDPN -> "xscvspdpn"
  | Op.XXSPLTW -> "xxspltw"
  | Op.MTVSRDD -> "mtvsrdd"
  | Op.MFVSRLD -> "mfvsrld"
  | Op.FCPSGN -> "fcpsgn"
  | Op.MFFSCRN -> "mffscrn"
  | Op.MFFSCRNI -> "mffscrni"
  | Op.MFFSL -> "mffsl"
  | Op.XXSPLTIB -> "xxspltib"
  | Op.VAND -> "vand"
  | Op.VANDC -> "vandc"
  | Op.VEQV -> "veqv"
  | Op.VNAND -> "vnand"
  | Op.VNOR -> "vnor"
  | Op.VOR -> "vor"
  | Op.VORC -> "vorc"
  | Op.VXOR -> "vxor"
  | Op.VSPLTISB -> "vspltisb"
  | Op.VSPLTISH -> "vspltish"
  | Op.VSPLTISW -> "vspltisw"
  | Op.VSPLTB -> "vspltb"
  | Op.VSPLTH -> "vsplth"
  | Op.VSPLTW -> "vspltw"
  | Op.VMRGHB -> "vmrghb"
  | Op.VMRGHH -> "vmrghh"
  | Op.VMRGHW -> "vmrghw"
  | Op.VMRGLB -> "vmrglb"
  | Op.VMRGLH -> "vmrglh"
  | Op.VMRGLW -> "vmrglw"
  | Op.VMRGEW -> "vmrgew"
  | Op.VMRGOW -> "vmrgow"
  | Op.VPERM -> "vperm"
  | Op.VSEL -> "vsel"
  | Op.VSLDOI -> "vsldoi"
  | Op.VCMPEQUB -> "vcmpequb"
  | Op.VCMPEQUBdot -> "vcmpequb."
  | Op.VCMPEQUH -> "vcmpequh"
  | Op.VCMPEQUHdot -> "vcmpequh."
  | Op.VCMPEQUW -> "vcmpequw"
  | Op.VCMPEQUWdot -> "vcmpequw."
  | Op.VCMPEQUD -> "vcmpequd"
  | Op.VCMPEQUDdot -> "vcmpequd."
  | Op.VCMPGTUB -> "vcmpgtub"
  | Op.VCMPGTUBdot -> "vcmpgtub."
  | Op.VCMPGTUH -> "vcmpgtuh"
  | Op.VCMPGTUHdot -> "vcmpgtuh."
  | Op.VCMPGTUW -> "vcmpgtuw"
  | Op.VCMPGTUWdot -> "vcmpgtuw."
  | Op.VCMPGTUD -> "vcmpgtud"
  | Op.VCMPGTUDdot -> "vcmpgtud."
  | Op.VCMPGTSB -> "vcmpgtsb"
  | Op.VCMPGTSBdot -> "vcmpgtsb."
  | Op.VCMPGTSH -> "vcmpgtsh"
  | Op.VCMPGTSHdot -> "vcmpgtsh."
  | Op.VCMPGTSW -> "vcmpgtsw"
  | Op.VCMPGTSWdot -> "vcmpgtsw."
  | Op.VCMPGTSD -> "vcmpgtsd"
  | Op.VCMPGTSDdot -> "vcmpgtsd."
  | Op.VSLB -> "vslb"
  | Op.VSLH -> "vslh"
  | Op.VSLW -> "vslw"
  | Op.VSLD -> "vsld"
  | Op.VSRB -> "vsrb"
  | Op.VSRH -> "vsrh"
  | Op.VSRW -> "vsrw"
  | Op.VSRD -> "vsrd"
  | Op.VSRAB -> "vsrab"
  | Op.VSRAH -> "vsrah"
  | Op.VSRAW -> "vsraw"
  | Op.VSRAD -> "vsrad"
  | Op.VSL -> "vsl"
  | Op.VSR -> "vsr"
  | Op.VSLO -> "vslo"
  | Op.VSRO -> "vsro"
  | Op.VRLB -> "vrlb"
  | Op.VRLH -> "vrlh"
  | Op.VRLW -> "vrlw"
  | Op.VRLD -> "vrld"
  | Op.VADDUBM -> "vaddubm"
  | Op.VADDUBS -> "vaddubs"
  | Op.VADDUHM -> "vadduhm"
  | Op.VADDUWM -> "vadduwm"
  | Op.VMULUWM -> "vmuluwm"
  | Op.VMULESW -> "vmulesw"
  | Op.VMULOSW -> "vmulosw"
  | Op.VADDUDM -> "vaddudm"
  | Op.VSUBUBM -> "vsububm"
  | Op.VSUBUBS -> "vsububs"
  | Op.VSUBUHM -> "vsubuhm"
  | Op.VSUBUWM -> "vsubuwm"
  | Op.VSUBUDM -> "vsubudm"
  | Op.VMINUB -> "vminub"
  | Op.VMINUH -> "vminuh"
  | Op.VMINUW -> "vminuw"
  | Op.VMINUD -> "vminud"
  | Op.VMAXUB -> "vmaxub"
  | Op.VMAXUH -> "vmaxuh"
  | Op.VMAXUW -> "vmaxuw"
  | Op.VMAXUD -> "vmaxud"
  | Op.VMINSB -> "vminsb"
  | Op.VMINSH -> "vminsh"
  | Op.VMINSW -> "vminsw"
  | Op.VMINSD -> "vminsd"
  | Op.VMAXSB -> "vmaxsb"
  | Op.VMAXSH -> "vmaxsh"
  | Op.VMAXSW -> "vmaxsw"
  | Op.VMAXSD -> "vmaxsd"
  | Op.VPKUHUM -> "vpkuhum"
  | Op.VPKUWUM -> "vpkuwum"
  | Op.VUPKHSB -> "vupkhsb"
  | Op.VUPKHSH -> "vupkhsh"
  | Op.VUPKHSW -> "vupkhsw"
  | Op.VUPKLSB -> "vupklsb"
  | Op.VUPKLSH -> "vupklsh"
  | Op.VUPKLSW -> "vupklsw"
  | Op.VCLZB -> "vclzb"
  | Op.VCLZH -> "vclzh"
  | Op.VCLZW -> "vclzw"
  | Op.VCLZD -> "vclzd"
  | Op.VPOPCNTB -> "vpopcntb"
  | Op.VPOPCNTH -> "vpopcnth"
  | Op.VPOPCNTW -> "vpopcntw"
  | Op.VPOPCNTD -> "vpopcntd"
  | Op.VGBBD -> "vgbbd"
  | Op.VBPERMQ -> "vbpermq"
  | Op.MFVSCR -> "mfvscr"
  | Op.MTVSCR -> "mtvscr"
  | Op.DADD -> "dadd"
  | Op.DADDdot -> "dadd."
  | Op.DADDQ -> "daddq"
  | Op.DADDQdot -> "daddq."
  | Op.DCFFIX -> "dcffix"
  | Op.DCFFIXdot -> "dcffix."
  | Op.DCFFIXQ -> "dcffixq"
  | Op.DCFFIXQdot -> "dcffixq."
  | Op.DCFFIXQQ -> "dcffixqq"
  | Op.DCMPO -> "dcmpo"
  | Op.DCMPOQ -> "dcmpoq"
  | Op.DCMPU -> "dcmpu"
  | Op.DCMPUQ -> "dcmpuq"
  | Op.DCTDP -> "dctdp"
  | Op.DCTDPdot -> "dctdp."
  | Op.DCTFIX -> "dctfix"
  | Op.DCTFIXdot -> "dctfix."
  | Op.DCTFIXQ -> "dctfixq"
  | Op.DCTFIXQdot -> "dctfixq."
  | Op.DCTFIXQQ -> "dctfixqq"
  | Op.DCTQPQ -> "dctqpq"
  | Op.DCTQPQdot -> "dctqpq."
  | Op.DDEDPD -> "ddedpd"
  | Op.DDEDPDdot -> "ddedpd."
  | Op.DDEDPDQ -> "ddedpdq"
  | Op.DDEDPDQdot -> "ddedpdq."
  | Op.DDIV -> "ddiv"
  | Op.DDIVdot -> "ddiv."
  | Op.DDIVQ -> "ddivq"
  | Op.DDIVQdot -> "ddivq."
  | Op.DENBCD -> "denbcd"
  | Op.DENBCDdot -> "denbcd."
  | Op.DENBCDQ -> "denbcdq"
  | Op.DENBCDQdot -> "denbcdq."
  | Op.DIEX -> "diex"
  | Op.DIEXdot -> "diex."
  | Op.DIEXQ -> "diexq"
  | Op.DIEXQdot -> "diexq."
  | Op.DMUL -> "dmul"
  | Op.DMULdot -> "dmul."
  | Op.DMULQ -> "dmulq"
  | Op.DMULQdot -> "dmulq."
  | Op.DQUA -> "dqua"
  | Op.DQUAdot -> "dqua."
  | Op.DQUAI -> "dquai"
  | Op.DQUAIdot -> "dquai."
  | Op.DQUAIQ -> "dquaiq"
  | Op.DQUAIQdot -> "dquaiq."
  | Op.DQUAQ -> "dquaq"
  | Op.DQUAQdot -> "dquaq."
  | Op.DRDPQ -> "drdpq"
  | Op.DRDPQdot -> "drdpq."
  | Op.DRINTN -> "drintn"
  | Op.DRINTNdot -> "drintn."
  | Op.DRINTNQ -> "drintnq"
  | Op.DRINTNQdot -> "drintnq."
  | Op.DRINTX -> "drintx"
  | Op.DRINTXdot -> "drintx."
  | Op.DRINTXQ -> "drintxq"
  | Op.DRINTXQdot -> "drintxq."
  | Op.DRRND -> "drrnd"
  | Op.DRRNDdot -> "drrnd."
  | Op.DRRNDQ -> "drrndq"
  | Op.DRRNDQdot -> "drrndq."
  | Op.DRSP -> "drsp"
  | Op.DRSPdot -> "drsp."
  | Op.DSCLI -> "dscli"
  | Op.DSCLIdot -> "dscli."
  | Op.DSCLIQ -> "dscliq"
  | Op.DSCLIQdot -> "dscliq."
  | Op.DSCRI -> "dscri"
  | Op.DSCRIdot -> "dscri."
  | Op.DSCRIQ -> "dscriq"
  | Op.DSCRIQdot -> "dscriq."
  | Op.DSUB -> "dsub"
  | Op.DSUBdot -> "dsub."
  | Op.DSUBQ -> "dsubq"
  | Op.DSUBQdot -> "dsubq."
  | Op.DTSTDC -> "dtstdc"
  | Op.DTSTDCQ -> "dtstdcq"
  | Op.DTSTDG -> "dtstdg"
  | Op.DTSTDGQ -> "dtstdgq"
  | Op.DTSTEX -> "dtstex"
  | Op.DTSTEXQ -> "dtstexq"
  | Op.DTSTSF -> "dtstsf"
  | Op.DTSTSFI -> "dtstsfi"
  | Op.DTSTSFIQ -> "dtstsfiq"
  | Op.DTSTSFQ -> "dtstsfq"
  | Op.DXEX -> "dxex"
  | Op.DXEXdot -> "dxex."
  | Op.DXEXQ -> "dxexq"
  | Op.DXEXQdot -> "dxexq."
  | Op.FCPSGNdot -> "fcpsgn."
  | Op.FMRGEW -> "fmrgew"
  | Op.FMRGOW -> "fmrgow"
  | Op.FRE -> "fre"
  | Op.FREdot -> "fre."
  | Op.FRSQRTES -> "frsqrtes"
  | Op.FRSQRTESdot -> "frsqrtes."
  | Op.FTDIV -> "ftdiv"
  | Op.FTSQRT -> "ftsqrt"
  | Op.LFDP -> "lfdp"
  | Op.LFDPX -> "lfdpx"
  | Op.MFFSCDRN -> "mffscdrn"
  | Op.MFFSCDRNI -> "mffscdrni"
  | Op.MFFSCE -> "mffsce"
  | Op.STFDP -> "stfdp"
  | Op.STFDPX -> "stfdpx"
  (* Lane V: the vector facility, primary opcode 4. *)
  | Op.BCDADDdot -> "bcdadd."
  | Op.BCDCFNdot -> "bcdcfn."
  | Op.BCDCFSQdot -> "bcdcfsq."
  | Op.BCDCFZdot -> "bcdcfz."
  | Op.BCDCPSGNdot -> "bcdcpsgn."
  | Op.BCDCTNdot -> "bcdctn."
  | Op.BCDCTSQdot -> "bcdctsq."
  | Op.BCDCTZdot -> "bcdctz."
  | Op.BCDSETSGNdot -> "bcdsetsgn."
  | Op.BCDSRdot -> "bcdsr."
  | Op.BCDSUBdot -> "bcdsub."
  | Op.BCDSdot -> "bcds."
  | Op.BCDTRUNCdot -> "bcdtrunc."
  | Op.BCDUSdot -> "bcdus."
  | Op.BCDUTRUNCdot -> "bcdutrunc."
  | Op.MADDHD -> "maddhd"
  | Op.MADDHDU -> "maddhdu"
  | Op.MADDLD -> "maddld"
  | Op.MTVSRBM -> "mtvsrbm"
  | Op.MTVSRBMI -> "mtvsrbmi"
  | Op.MTVSRDM -> "mtvsrdm"
  | Op.MTVSRHM -> "mtvsrhm"
  | Op.MTVSRQM -> "mtvsrqm"
  | Op.MTVSRWM -> "mtvsrwm"
  | Op.VABSDUB -> "vabsdub"
  | Op.VABSDUH -> "vabsduh"
  | Op.VABSDUW -> "vabsduw"
  | Op.VADDCUQ -> "vaddcuq"
  | Op.VADDCUW -> "vaddcuw"
  | Op.VADDECUQ -> "vaddecuq"
  | Op.VADDEUQM -> "vaddeuqm"
  | Op.VADDFP -> "vaddfp"
  | Op.VADDSBS -> "vaddsbs"
  | Op.VADDSHS -> "vaddshs"
  | Op.VADDSWS -> "vaddsws"
  | Op.VADDUHS -> "vadduhs"
  | Op.VADDUQM -> "vadduqm"
  | Op.VADDUWS -> "vadduws"
  | Op.VAVGSB -> "vavgsb"
  | Op.VAVGSH -> "vavgsh"
  | Op.VAVGSW -> "vavgsw"
  | Op.VAVGUB -> "vavgub"
  | Op.VAVGUH -> "vavguh"
  | Op.VAVGUW -> "vavguw"
  | Op.VBPERMD -> "vbpermd"
  | Op.VCFSX -> "vcfsx"
  | Op.VCFUGED -> "vcfuged"
  | Op.VCFUX -> "vcfux"
  | Op.VCIPHER -> "vcipher"
  | Op.VCIPHERLAST -> "vcipherlast"
  | Op.VCLRLB -> "vclrlb"
  | Op.VCLRRB -> "vclrrb"
  | Op.VCLZDM -> "vclzdm"
  | Op.VCLZLSBB -> "vclzlsbb"
  | Op.VCMPBFP -> "vcmpbfp"
  | Op.VCMPBFPdot -> "vcmpbfp."
  | Op.VCMPEQFP -> "vcmpeqfp"
  | Op.VCMPEQFPdot -> "vcmpeqfp."
  | Op.VCMPEQUQ -> "vcmpequq"
  | Op.VCMPEQUQdot -> "vcmpequq."
  | Op.VCMPGEFP -> "vcmpgefp"
  | Op.VCMPGEFPdot -> "vcmpgefp."
  | Op.VCMPGTFP -> "vcmpgtfp"
  | Op.VCMPGTFPdot -> "vcmpgtfp."
  | Op.VCMPGTSQ -> "vcmpgtsq"
  | Op.VCMPGTSQdot -> "vcmpgtsq."
  | Op.VCMPGTUQ -> "vcmpgtuq"
  | Op.VCMPGTUQdot -> "vcmpgtuq."
  | Op.VCMPNEB -> "vcmpneb"
  | Op.VCMPNEBdot -> "vcmpneb."
  | Op.VCMPNEH -> "vcmpneh"
  | Op.VCMPNEHdot -> "vcmpneh."
  | Op.VCMPNEW -> "vcmpnew"
  | Op.VCMPNEWdot -> "vcmpnew."
  | Op.VCMPNEZB -> "vcmpnezb"
  | Op.VCMPNEZBdot -> "vcmpnezb."
  | Op.VCMPNEZH -> "vcmpnezh"
  | Op.VCMPNEZHdot -> "vcmpnezh."
  | Op.VCMPNEZW -> "vcmpnezw"
  | Op.VCMPNEZWdot -> "vcmpnezw."
  | Op.VCMPSQ -> "vcmpsq"
  | Op.VCMPUQ -> "vcmpuq"
  | Op.VCNTMBB -> "vcntmbb"
  | Op.VCNTMBD -> "vcntmbd"
  | Op.VCNTMBH -> "vcntmbh"
  | Op.VCNTMBW -> "vcntmbw"
  | Op.VCTSXS -> "vctsxs"
  | Op.VCTUXS -> "vctuxs"
  | Op.VCTZB -> "vctzb"
  | Op.VCTZD -> "vctzd"
  | Op.VCTZDM -> "vctzdm"
  | Op.VCTZH -> "vctzh"
  | Op.VCTZLSBB -> "vctzlsbb"
  | Op.VCTZW -> "vctzw"
  | Op.VDIVESD -> "vdivesd"
  | Op.VDIVESQ -> "vdivesq"
  | Op.VDIVESW -> "vdivesw"
  | Op.VDIVEUD -> "vdiveud"
  | Op.VDIVEUQ -> "vdiveuq"
  | Op.VDIVEUW -> "vdiveuw"
  | Op.VDIVSD -> "vdivsd"
  | Op.VDIVSQ -> "vdivsq"
  | Op.VDIVSW -> "vdivsw"
  | Op.VDIVUD -> "vdivud"
  | Op.VDIVUQ -> "vdivuq"
  | Op.VDIVUW -> "vdivuw"
  | Op.VEXPANDBM -> "vexpandbm"
  | Op.VEXPANDDM -> "vexpanddm"
  | Op.VEXPANDHM -> "vexpandhm"
  | Op.VEXPANDQM -> "vexpandqm"
  | Op.VEXPANDWM -> "vexpandwm"
  | Op.VEXPTEFP -> "vexptefp"
  | Op.VEXTDDVLX -> "vextddvlx"
  | Op.VEXTDDVRX -> "vextddvrx"
  | Op.VEXTDUBVLX -> "vextdubvlx"
  | Op.VEXTDUBVRX -> "vextdubvrx"
  | Op.VEXTDUHVLX -> "vextduhvlx"
  | Op.VEXTDUHVRX -> "vextduhvrx"
  | Op.VEXTDUWVLX -> "vextduwvlx"
  | Op.VEXTDUWVRX -> "vextduwvrx"
  | Op.VEXTRACTBM -> "vextractbm"
  | Op.VEXTRACTD -> "vextractd"
  | Op.VEXTRACTDM -> "vextractdm"
  | Op.VEXTRACTHM -> "vextracthm"
  | Op.VEXTRACTQM -> "vextractqm"
  | Op.VEXTRACTUB -> "vextractub"
  | Op.VEXTRACTUH -> "vextractuh"
  | Op.VEXTRACTUW -> "vextractuw"
  | Op.VEXTRACTWM -> "vextractwm"
  | Op.VEXTSB2D -> "vextsb2d"
  | Op.VEXTSB2W -> "vextsb2w"
  | Op.VEXTSD2Q -> "vextsd2q"
  | Op.VEXTSH2D -> "vextsh2d"
  | Op.VEXTSH2W -> "vextsh2w"
  | Op.VEXTSW2D -> "vextsw2d"
  | Op.VEXTUBLX -> "vextublx"
  | Op.VEXTUBRX -> "vextubrx"
  | Op.VEXTUHLX -> "vextuhlx"
  | Op.VEXTUHRX -> "vextuhrx"
  | Op.VEXTUWLX -> "vextuwlx"
  | Op.VEXTUWRX -> "vextuwrx"
  | Op.VGNB -> "vgnb"
  | Op.VINSBLX -> "vinsblx"
  | Op.VINSBRX -> "vinsbrx"
  | Op.VINSBVLX -> "vinsbvlx"
  | Op.VINSBVRX -> "vinsbvrx"
  | Op.VINSD -> "vinsd"
  | Op.VINSDLX -> "vinsdlx"
  | Op.VINSDRX -> "vinsdrx"
  | Op.VINSERTB -> "vinsertb"
  | Op.VINSERTD -> "vinsertd"
  | Op.VINSERTH -> "vinserth"
  | Op.VINSERTW -> "vinsertw"
  | Op.VINSHLX -> "vinshlx"
  | Op.VINSHRX -> "vinshrx"
  | Op.VINSHVLX -> "vinshvlx"
  | Op.VINSHVRX -> "vinshvrx"
  | Op.VINSW -> "vinsw"
  | Op.VINSWLX -> "vinswlx"
  | Op.VINSWRX -> "vinswrx"
  | Op.VINSWVLX -> "vinswvlx"
  | Op.VINSWVRX -> "vinswvrx"
  | Op.VLOGEFP -> "vlogefp"
  | Op.VMADDFP -> "vmaddfp"
  | Op.VMAXFP -> "vmaxfp"
  | Op.VMHADDSHS -> "vmhaddshs"
  | Op.VMHRADDSHS -> "vmhraddshs"
  | Op.VMINFP -> "vminfp"
  | Op.VMLADDUHM -> "vmladduhm"
  | Op.VMODSD -> "vmodsd"
  | Op.VMODSQ -> "vmodsq"
  | Op.VMODSW -> "vmodsw"
  | Op.VMODUD -> "vmodud"
  | Op.VMODUQ -> "vmoduq"
  | Op.VMODUW -> "vmoduw"
  | Op.VMSUMCUD -> "vmsumcud"
  | Op.VMSUMMBM -> "vmsummbm"
  | Op.VMSUMSHM -> "vmsumshm"
  | Op.VMSUMSHS -> "vmsumshs"
  | Op.VMSUMUBM -> "vmsumubm"
  | Op.VMSUMUDM -> "vmsumudm"
  | Op.VMSUMUHM -> "vmsumuhm"
  | Op.VMSUMUHS -> "vmsumuhs"
  | Op.VMUL10CUQ -> "vmul10cuq"
  | Op.VMUL10ECUQ -> "vmul10ecuq"
  | Op.VMUL10EUQ -> "vmul10euq"
  | Op.VMUL10UQ -> "vmul10uq"
  | Op.VMULESB -> "vmulesb"
  | Op.VMULESD -> "vmulesd"
  | Op.VMULESH -> "vmulesh"
  | Op.VMULEUB -> "vmuleub"
  | Op.VMULEUD -> "vmuleud"
  | Op.VMULEUH -> "vmuleuh"
  | Op.VMULEUW -> "vmuleuw"
  | Op.VMULHSD -> "vmulhsd"
  | Op.VMULHSW -> "vmulhsw"
  | Op.VMULHUD -> "vmulhud"
  | Op.VMULHUW -> "vmulhuw"
  | Op.VMULLD -> "vmulld"
  | Op.VMULOSB -> "vmulosb"
  | Op.VMULOSD -> "vmulosd"
  | Op.VMULOSH -> "vmulosh"
  | Op.VMULOUB -> "vmuloub"
  | Op.VMULOUD -> "vmuloud"
  | Op.VMULOUH -> "vmulouh"
  | Op.VMULOUW -> "vmulouw"
  | Op.VNCIPHER -> "vncipher"
  | Op.VNCIPHERLAST -> "vncipherlast"
  | Op.VNEGD -> "vnegd"
  | Op.VNEGW -> "vnegw"
  | Op.VNMSUBFP -> "vnmsubfp"
  | Op.VPDEPD -> "vpdepd"
  | Op.VPERMR -> "vpermr"
  | Op.VPERMXOR -> "vpermxor"
  | Op.VPEXTD -> "vpextd"
  | Op.VPKPX -> "vpkpx"
  | Op.VPKSDSS -> "vpksdss"
  | Op.VPKSDUS -> "vpksdus"
  | Op.VPKSHSS -> "vpkshss"
  | Op.VPKSHUS -> "vpkshus"
  | Op.VPKSWSS -> "vpkswss"
  | Op.VPKSWUS -> "vpkswus"
  | Op.VPKUDUM -> "vpkudum"
  | Op.VPKUDUS -> "vpkudus"
  | Op.VPKUHUS -> "vpkuhus"
  | Op.VPKUWUS -> "vpkuwus"
  | Op.VPMSUMB -> "vpmsumb"
  | Op.VPMSUMD -> "vpmsumd"
  | Op.VPMSUMH -> "vpmsumh"
  | Op.VPMSUMW -> "vpmsumw"
  | Op.VPRTYBD -> "vprtybd"
  | Op.VPRTYBQ -> "vprtybq"
  | Op.VPRTYBW -> "vprtybw"
  | Op.VREFP -> "vrefp"
  | Op.VRFIM -> "vrfim"
  | Op.VRFIN -> "vrfin"
  | Op.VRFIP -> "vrfip"
  | Op.VRFIZ -> "vrfiz"
  | Op.VRLDMI -> "vrldmi"
  | Op.VRLDNM -> "vrldnm"
  | Op.VRLQ -> "vrlq"
  | Op.VRLQMI -> "vrlqmi"
  | Op.VRLQNM -> "vrlqnm"
  | Op.VRLWMI -> "vrlwmi"
  | Op.VRLWNM -> "vrlwnm"
  | Op.VRSQRTEFP -> "vrsqrtefp"
  | Op.VSBOX -> "vsbox"
  | Op.VSHASIGMAD -> "vshasigmad"
  | Op.VSHASIGMAW -> "vshasigmaw"
  | Op.VSLDBI -> "vsldbi"
  | Op.VSLQ -> "vslq"
  | Op.VSLV -> "vslv"
  | Op.VSRAQ -> "vsraq"
  | Op.VSRDBI -> "vsrdbi"
  | Op.VSRQ -> "vsrq"
  | Op.VSRV -> "vsrv"
  | Op.VSTRIBL -> "vstribl"
  | Op.VSTRIBLdot -> "vstribl."
  | Op.VSTRIBR -> "vstribr"
  | Op.VSTRIBRdot -> "vstribr."
  | Op.VSTRIHL -> "vstrihl"
  | Op.VSTRIHLdot -> "vstrihl."
  | Op.VSTRIHR -> "vstrihr"
  | Op.VSTRIHRdot -> "vstrihr."
  | Op.VSUBCUQ -> "vsubcuq"
  | Op.VSUBCUW -> "vsubcuw"
  | Op.VSUBECUQ -> "vsubecuq"
  | Op.VSUBEUQM -> "vsubeuqm"
  | Op.VSUBFP -> "vsubfp"
  | Op.VSUBSBS -> "vsubsbs"
  | Op.VSUBSHS -> "vsubshs"
  | Op.VSUBSWS -> "vsubsws"
  | Op.VSUBUHS -> "vsubuhs"
  | Op.VSUBUQM -> "vsubuqm"
  | Op.VSUBUWS -> "vsubuws"
  | Op.VSUM2SWS -> "vsum2sws"
  | Op.VSUM4SBS -> "vsum4sbs"
  | Op.VSUM4SHS -> "vsum4shs"
  | Op.VSUM4UBS -> "vsum4ubs"
  | Op.VSUMSWS -> "vsumsws"
  | Op.VUPKHPX -> "vupkhpx"
  | Op.VUPKLPX -> "vupklpx"
  (* Lane X: VSX, MMA and quad precision. *)
  | Op.LXSIBZX -> "lxsibzx"
  | Op.LXSIHZX -> "lxsihzx"
  | Op.LXSIWAX -> "lxsiwax"
  | Op.LXSIWZX -> "lxsiwzx"
  | Op.LXSSP -> "lxssp"
  | Op.LXSSPX -> "lxsspx"
  | Op.LXV -> "lxv"
  | Op.LXVB16X -> "lxvb16x"
  | Op.LXVH8X -> "lxvh8x"
  | Op.LXVKQ -> "lxvkq"
  | Op.LXVL -> "lxvl"
  | Op.LXVLL -> "lxvll"
  | Op.LXVP -> "lxvp"
  | Op.LXVPX -> "lxvpx"
  | Op.LXVRBX -> "lxvrbx"
  | Op.LXVRDX -> "lxvrdx"
  | Op.LXVRHX -> "lxvrhx"
  | Op.LXVRWX -> "lxvrwx"
  | Op.LXVWSX -> "lxvwsx"
  | Op.LXVX -> "lxvx"
  | Op.MTVSRWS -> "mtvsrws"
  | Op.STXSIBX -> "stxsibx"
  | Op.STXSIHX -> "stxsihx"
  | Op.STXSIWX -> "stxsiwx"
  | Op.STXSSP -> "stxssp"
  | Op.STXSSPX -> "stxsspx"
  | Op.STXV -> "stxv"
  | Op.STXVB16X -> "stxvb16x"
  | Op.STXVH8X -> "stxvh8x"
  | Op.STXVL -> "stxvl"
  | Op.STXVLL -> "stxvll"
  | Op.STXVP -> "stxvp"
  | Op.STXVPX -> "stxvpx"
  | Op.STXVRBX -> "stxvrbx"
  | Op.STXVRDX -> "stxvrdx"
  | Op.STXVRHX -> "stxvrhx"
  | Op.STXVRWX -> "stxvrwx"
  | Op.STXVX -> "stxvx"
  | Op.XSABSQP -> "xsabsqp"
  | Op.XSADDQP -> "xsaddqp"
  | Op.XSADDQPO -> "xsaddqpo"
  | Op.XSCMPEQDP -> "xscmpeqdp"
  | Op.XSCMPEQQP -> "xscmpeqqp"
  | Op.XSCMPEXPDP -> "xscmpexpdp"
  | Op.XSCMPEXPQP -> "xscmpexpqp"
  | Op.XSCMPGEDP -> "xscmpgedp"
  | Op.XSCMPGEQP -> "xscmpgeqp"
  | Op.XSCMPGTDP -> "xscmpgtdp"
  | Op.XSCMPGTQP -> "xscmpgtqp"
  | Op.XSCMPODP -> "xscmpodp"
  | Op.XSCMPOQP -> "xscmpoqp"
  | Op.XSCMPUQP -> "xscmpuqp"
  | Op.XSCPSGNQP -> "xscpsgnqp"
  | Op.XSCVDPHP -> "xscvdphp"
  | Op.XSCVDPQP -> "xscvdpqp"
  | Op.XSCVHPDP -> "xscvhpdp"
  | Op.XSCVQPDP -> "xscvqpdp"
  | Op.XSCVQPDPO -> "xscvqpdpo"
  | Op.XSCVQPSDZ -> "xscvqpsdz"
  | Op.XSCVQPSQZ -> "xscvqpsqz"
  | Op.XSCVQPSWZ -> "xscvqpswz"
  | Op.XSCVQPUDZ -> "xscvqpudz"
  | Op.XSCVQPUQZ -> "xscvqpuqz"
  | Op.XSCVQPUWZ -> "xscvqpuwz"
  | Op.XSCVSDQP -> "xscvsdqp"
  | Op.XSCVSQQP -> "xscvsqqp"
  | Op.XSCVUDQP -> "xscvudqp"
  | Op.XSCVUQQP -> "xscvuqqp"
  | Op.XSDIVQP -> "xsdivqp"
  | Op.XSDIVQPO -> "xsdivqpo"
  | Op.XSIEXPDP -> "xsiexpdp"
  | Op.XSIEXPQP -> "xsiexpqp"
  | Op.XSMADDQP -> "xsmaddqp"
  | Op.XSMADDQPO -> "xsmaddqpo"
  | Op.XSMAXCDP -> "xsmaxcdp"
  | Op.XSMAXCQP -> "xsmaxcqp"
  | Op.XSMAXJDP -> "xsmaxjdp"
  | Op.XSMINCDP -> "xsmincdp"
  | Op.XSMINCQP -> "xsmincqp"
  | Op.XSMINJDP -> "xsminjdp"
  | Op.XSMSUBQP -> "xsmsubqp"
  | Op.XSMSUBQPO -> "xsmsubqpo"
  | Op.XSMULQP -> "xsmulqp"
  | Op.XSMULQPO -> "xsmulqpo"
  | Op.XSNABSQP -> "xsnabsqp"
  | Op.XSNEGQP -> "xsnegqp"
  | Op.XSNMADDQP -> "xsnmaddqp"
  | Op.XSNMADDQPO -> "xsnmaddqpo"
  | Op.XSNMSUBQP -> "xsnmsubqp"
  | Op.XSNMSUBQPO -> "xsnmsubqpo"
  | Op.XSRDPIC -> "xsrdpic"
  | Op.XSREDP -> "xsredp"
  | Op.XSRESP -> "xsresp"
  | Op.XSRQPI -> "xsrqpi"
  | Op.XSRQPIX -> "xsrqpix"
  | Op.XSRQPXP -> "xsrqpxp"
  | Op.XSRSQRTEDP -> "xsrsqrtedp"
  | Op.XSRSQRTESP -> "xsrsqrtesp"
  | Op.XSSQRTQP -> "xssqrtqp"
  | Op.XSSQRTQPO -> "xssqrtqpo"
  | Op.XSSUBQP -> "xssubqp"
  | Op.XSSUBQPO -> "xssubqpo"
  | Op.XSTDIVDP -> "xstdivdp"
  | Op.XSTSQRTDP -> "xstsqrtdp"
  | Op.XSTSTDCDP -> "xststdcdp"
  | Op.XSTSTDCQP -> "xststdcqp"
  | Op.XSTSTDCSP -> "xststdcsp"
  | Op.XSXEXPDP -> "xsxexpdp"
  | Op.XSXEXPQP -> "xsxexpqp"
  | Op.XSXSIGDP -> "xsxsigdp"
  | Op.XSXSIGQP -> "xsxsigqp"
  | Op.XVABSDP -> "xvabsdp"
  | Op.XVABSSP -> "xvabssp"
  | Op.XVADDSP -> "xvaddsp"
  | Op.XVBF16GER2 -> "xvbf16ger2"
  | Op.XVBF16GER2NN -> "xvbf16ger2nn"
  | Op.XVBF16GER2NP -> "xvbf16ger2np"
  | Op.XVBF16GER2PN -> "xvbf16ger2pn"
  | Op.XVBF16GER2PP -> "xvbf16ger2pp"
  | Op.XVCMPEQDP -> "xvcmpeqdp"
  | Op.XVCMPEQDPdot -> "xvcmpeqdp."
  | Op.XVCMPEQSP -> "xvcmpeqsp"
  | Op.XVCMPEQSPdot -> "xvcmpeqsp."
  | Op.XVCMPGESP -> "xvcmpgesp"
  | Op.XVCMPGESPdot -> "xvcmpgesp."
  | Op.XVCMPGTSP -> "xvcmpgtsp"
  | Op.XVCMPGTSPdot -> "xvcmpgtsp."
  | Op.XVCPSGNDP -> "xvcpsgndp"
  | Op.XVCPSGNSP -> "xvcpsgnsp"
  | Op.XVCVBF16SPN -> "xvcvbf16spn"
  | Op.XVCVDPSP -> "xvcvdpsp"
  | Op.XVCVDPSXDS -> "xvcvdpsxds"
  | Op.XVCVDPSXWS -> "xvcvdpsxws"
  | Op.XVCVDPUXDS -> "xvcvdpuxds"
  | Op.XVCVDPUXWS -> "xvcvdpuxws"
  | Op.XVCVHPSP -> "xvcvhpsp"
  | Op.XVCVSPBF16 -> "xvcvspbf16"
  | Op.XVCVSPDP -> "xvcvspdp"
  | Op.XVCVSPHP -> "xvcvsphp"
  | Op.XVCVSPSXDS -> "xvcvspsxds"
  | Op.XVCVSPSXWS -> "xvcvspsxws"
  | Op.XVCVSPUXDS -> "xvcvspuxds"
  | Op.XVCVSPUXWS -> "xvcvspuxws"
  | Op.XVCVSXDDP -> "xvcvsxddp"
  | Op.XVCVSXDSP -> "xvcvsxdsp"
  | Op.XVCVSXWSP -> "xvcvsxwsp"
  | Op.XVCVUXDDP -> "xvcvuxddp"
  | Op.XVCVUXDSP -> "xvcvuxdsp"
  | Op.XVCVUXWDP -> "xvcvuxwdp"
  | Op.XVCVUXWSP -> "xvcvuxwsp"
  | Op.XVDIVSP -> "xvdivsp"
  | Op.XVF16GER2 -> "xvf16ger2"
  | Op.XVF16GER2NN -> "xvf16ger2nn"
  | Op.XVF16GER2NP -> "xvf16ger2np"
  | Op.XVF16GER2PN -> "xvf16ger2pn"
  | Op.XVF16GER2PP -> "xvf16ger2pp"
  | Op.XVF32GER -> "xvf32ger"
  | Op.XVF32GERNN -> "xvf32gernn"
  | Op.XVF32GERNP -> "xvf32gernp"
  | Op.XVF32GERPN -> "xvf32gerpn"
  | Op.XVF32GERPP -> "xvf32gerpp"
  | Op.XVF64GER -> "xvf64ger"
  | Op.XVF64GERNN -> "xvf64gernn"
  | Op.XVF64GERNP -> "xvf64gernp"
  | Op.XVF64GERPN -> "xvf64gerpn"
  | Op.XVF64GERPP -> "xvf64gerpp"
  | Op.XVI16GER2 -> "xvi16ger2"
  | Op.XVI16GER2PP -> "xvi16ger2pp"
  | Op.XVI16GER2S -> "xvi16ger2s"
  | Op.XVI16GER2SPP -> "xvi16ger2spp"
  | Op.XVI4GER8 -> "xvi4ger8"
  | Op.XVI4GER8PP -> "xvi4ger8pp"
  | Op.XVI8GER4 -> "xvi8ger4"
  | Op.XVI8GER4PP -> "xvi8ger4pp"
  | Op.XVI8GER4SPP -> "xvi8ger4spp"
  | Op.XVIEXPDP -> "xviexpdp"
  | Op.XVIEXPSP -> "xviexpsp"
  | Op.XVMADDADP -> "xvmaddadp"
  | Op.XVMADDASP -> "xvmaddasp"
  | Op.XVMADDMDP -> "xvmaddmdp"
  | Op.XVMADDMSP -> "xvmaddmsp"
  | Op.XVMAXDP -> "xvmaxdp"
  | Op.XVMAXSP -> "xvmaxsp"
  | Op.XVMINDP -> "xvmindp"
  | Op.XVMINSP -> "xvminsp"
  | Op.XVMSUBADP -> "xvmsubadp"
  | Op.XVMSUBASP -> "xvmsubasp"
  | Op.XVMSUBMDP -> "xvmsubmdp"
  | Op.XVMSUBMSP -> "xvmsubmsp"
  | Op.XVMULSP -> "xvmulsp"
  | Op.XVNABSDP -> "xvnabsdp"
  | Op.XVNABSSP -> "xvnabssp"
  | Op.XVNEGSP -> "xvnegsp"
  | Op.XVNMADDADP -> "xvnmaddadp"
  | Op.XVNMADDASP -> "xvnmaddasp"
  | Op.XVNMADDMDP -> "xvnmaddmdp"
  | Op.XVNMADDMSP -> "xvnmaddmsp"
  | Op.XVNMSUBADP -> "xvnmsubadp"
  | Op.XVNMSUBASP -> "xvnmsubasp"
  | Op.XVNMSUBMDP -> "xvnmsubmdp"
  | Op.XVNMSUBMSP -> "xvnmsubmsp"
  | Op.XVRDPI -> "xvrdpi"
  | Op.XVRDPIC -> "xvrdpic"
  | Op.XVRDPIM -> "xvrdpim"
  | Op.XVRDPIP -> "xvrdpip"
  | Op.XVRDPIZ -> "xvrdpiz"
  | Op.XVREDP -> "xvredp"
  | Op.XVRESP -> "xvresp"
  | Op.XVRSPI -> "xvrspi"
  | Op.XVRSPIC -> "xvrspic"
  | Op.XVRSPIM -> "xvrspim"
  | Op.XVRSPIP -> "xvrspip"
  | Op.XVRSPIZ -> "xvrspiz"
  | Op.XVRSQRTEDP -> "xvrsqrtedp"
  | Op.XVRSQRTESP -> "xvrsqrtesp"
  | Op.XVSQRTDP -> "xvsqrtdp"
  | Op.XVSQRTSP -> "xvsqrtsp"
  | Op.XVSUBSP -> "xvsubsp"
  | Op.XVTDIVDP -> "xvtdivdp"
  | Op.XVTDIVSP -> "xvtdivsp"
  | Op.XVTLSBB -> "xvtlsbb"
  | Op.XVTSQRTDP -> "xvtsqrtdp"
  | Op.XVTSQRTSP -> "xvtsqrtsp"
  | Op.XVTSTDCDP -> "xvtstdcdp"
  | Op.XVTSTDCSP -> "xvtstdcsp"
  | Op.XVXEXPDP -> "xvxexpdp"
  | Op.XVXEXPSP -> "xvxexpsp"
  | Op.XVXSIGDP -> "xvxsigdp"
  | Op.XVXSIGSP -> "xvxsigsp"
  | Op.XXBRD -> "xxbrd"
  | Op.XXBRH -> "xxbrh"
  | Op.XXBRQ -> "xxbrq"
  | Op.XXBRW -> "xxbrw"
  | Op.XXEXTRACTUW -> "xxextractuw"
  | Op.XXGENPCVBM -> "xxgenpcvbm"
  | Op.XXGENPCVDM -> "xxgenpcvdm"
  | Op.XXGENPCVHM -> "xxgenpcvhm"
  | Op.XXGENPCVWM -> "xxgenpcvwm"
  | Op.XXINSERTW -> "xxinsertw"
  | Op.XXMFACC -> "xxmfacc"
  | Op.XXMTACC -> "xxmtacc"
  | Op.XXPERM -> "xxperm"
  | Op.XXPERMR -> "xxpermr"
  | Op.XXSETACCZ -> "xxsetaccz"
  (* Lane A: integer, branch, storage and system instructions. *)
  | Op.ADDEX -> "addex"
  | Op.ADDG6S -> "addg6s"
  | Op.ADDPCIS -> "addpcis"
  | Op.BCTAR -> "bctar"
  | Op.BCTARL -> "bctarl"
  | Op.BRD -> "brd"
  | Op.BRH -> "brh"
  | Op.BRW -> "brw"
  | Op.CBCDTD -> "cbcdtd"
  | Op.CDTBCD -> "cdtbcd"
  | Op.CFUGED -> "cfuged"
  | Op.CLRBHRB -> "clrbhrb"
  | Op.CMPEQB -> "cmpeqb"
  | Op.CMPRB -> "cmprb"
  | Op.CNTLZDM -> "cntlzdm"
  | Op.CNTTZD -> "cnttzd"
  | Op.CNTTZDdot -> "cnttzd."
  | Op.CNTTZDM -> "cnttzdm"
  | Op.CNTTZW -> "cnttzw"
  | Op.CNTTZWdot -> "cnttzw."
  | Op.COPY -> "copy"
  | Op.CPABORT -> "cpabort"
  | Op.DARN -> "darn"
  | Op.DIVDE -> "divde"
  | Op.DIVDEdot -> "divde."
  | Op.DIVDEO -> "divdeo"
  | Op.DIVDEOdot -> "divdeo."
  | Op.DIVDEU -> "divdeu"
  | Op.DIVDEUdot -> "divdeu."
  | Op.DIVDEUO -> "divdeuo"
  | Op.DIVDEUOdot -> "divdeuo."
  | Op.DIVWE -> "divwe"
  | Op.DIVWEdot -> "divwe."
  | Op.DIVWEO -> "divweo"
  | Op.DIVWEOdot -> "divweo."
  | Op.DIVWEU -> "divweu"
  | Op.DIVWEUdot -> "divweu."
  | Op.DIVWEUO -> "divweuo"
  | Op.DIVWEUOdot -> "divweuo."
  | Op.EXTSWSLI -> "extswsli"
  | Op.EXTSWSLIdot -> "extswsli."
  | Op.ICBT -> "icbt"
  | Op.LDAT -> "ldat"
  | Op.LQ -> "lq"
  | Op.LQARX -> "lqarx"
  | Op.LWAT -> "lwat"
  | Op.MCRXRX -> "mcrxrx"
  | Op.MFBHRBE -> "mfbhrbe"
  | Op.MODSD -> "modsd"
  | Op.MODSW -> "modsw"
  | Op.MODUD -> "modud"
  | Op.MODUW -> "moduw"
  | Op.PASTE -> "paste"
  | Op.PASTEdot -> "paste."
  | Op.PDEPD -> "pdepd"
  | Op.PEXTD -> "pextd"
  | Op.PHWSYNC -> "phwsync"
  | Op.PLWSYNC -> "plwsync"
  | Op.PTESYNC -> "ptesync"
  | Op.RFEBB -> "rfebb"
  | Op.SCV -> "scv"
  | Op.SETB -> "setb"
  | Op.SETBC -> "setbc"
  | Op.SETBCR -> "setbcr"
  | Op.SETNBC -> "setnbc"
  | Op.SETNBCR -> "setnbcr"
  | Op.STCISYNC -> "stcisync"
  | Op.STDAT -> "stdat"
  | Op.STNCISYNC -> "stncisync"
  | Op.STQ -> "stq"
  | Op.STQCXdot -> "stqcx."
  | Op.STSYNC -> "stsync"
  | Op.STWAT -> "stwat"
  | Op.WAIT -> "wait"
  (* Lane E: the categories Power ISA 2.07B has and 3.1 dropped. *)
  | Op.MACCHW -> "macchw"
  | Op.MACCHWO -> "macchwo"
  | Op.MACCHWOdot -> "macchwo."
  | Op.MACCHWS -> "macchws"
  | Op.MACCHWSO -> "macchwso"
  | Op.MACCHWSOdot -> "macchwso."
  | Op.MACCHWSU -> "macchwsu"
  | Op.MACCHWSUO -> "macchwsuo"
  | Op.MACCHWSUOdot -> "macchwsuo."
  | Op.MACCHWSUdot -> "macchwsu."
  | Op.MACCHWSdot -> "macchws."
  | Op.MACCHWU -> "macchwu"
  | Op.MACCHWUO -> "macchwuo"
  | Op.MACCHWUOdot -> "macchwuo."
  | Op.MACCHWUdot -> "macchwu."
  | Op.MACCHWdot -> "macchw."
  | Op.MACHHW -> "machhw"
  | Op.MACHHWO -> "machhwo"
  | Op.MACHHWOdot -> "machhwo."
  | Op.MACHHWS -> "machhws"
  | Op.MACHHWSO -> "machhwso"
  | Op.MACHHWSOdot -> "machhwso."
  | Op.MACHHWSU -> "machhwsu"
  | Op.MACHHWSUO -> "machhwsuo"
  | Op.MACHHWSUOdot -> "machhwsuo."
  | Op.MACHHWSUdot -> "machhwsu."
  | Op.MACHHWSdot -> "machhws."
  | Op.MACHHWU -> "machhwu"
  | Op.MACHHWUO -> "machhwuo"
  | Op.MACHHWUOdot -> "machhwuo."
  | Op.MACHHWUdot -> "machhwu."
  | Op.MACHHWdot -> "machhw."
  | Op.MACLHW -> "maclhw"
  | Op.MACLHWO -> "maclhwo"
  | Op.MACLHWOdot -> "maclhwo."
  | Op.MACLHWS -> "maclhws"
  | Op.MACLHWSO -> "maclhwso"
  | Op.MACLHWSOdot -> "maclhwso."
  | Op.MACLHWSU -> "maclhwsu"
  | Op.MACLHWSUO -> "maclhwsuo"
  | Op.MACLHWSUOdot -> "maclhwsuo."
  | Op.MACLHWSUdot -> "maclhwsu."
  | Op.MACLHWSdot -> "maclhws."
  | Op.MACLHWU -> "maclhwu"
  | Op.MACLHWUO -> "maclhwuo"
  | Op.MACLHWUOdot -> "maclhwuo."
  | Op.MACLHWUdot -> "maclhwu."
  | Op.MACLHWdot -> "maclhw."
  | Op.MULCHW -> "mulchw"
  | Op.MULCHWU -> "mulchwu"
  | Op.MULCHWUdot -> "mulchwu."
  | Op.MULCHWdot -> "mulchw."
  | Op.MULHHW -> "mulhhw"
  | Op.MULHHWU -> "mulhhwu"
  | Op.MULHHWUdot -> "mulhhwu."
  | Op.MULHHWdot -> "mulhhw."
  | Op.MULLHW -> "mullhw"
  | Op.MULLHWU -> "mullhwu"
  | Op.MULLHWUdot -> "mullhwu."
  | Op.MULLHWdot -> "mullhw."
  | Op.NMACCHW -> "nmacchw"
  | Op.NMACCHWO -> "nmacchwo"
  | Op.NMACCHWOdot -> "nmacchwo."
  | Op.NMACCHWS -> "nmacchws"
  | Op.NMACCHWSO -> "nmacchwso"
  | Op.NMACCHWSOdot -> "nmacchwso."
  | Op.NMACCHWSdot -> "nmacchws."
  | Op.NMACCHWdot -> "nmacchw."
  | Op.NMACHHW -> "nmachhw"
  | Op.NMACHHWO -> "nmachhwo"
  | Op.NMACHHWOdot -> "nmachhwo."
  | Op.NMACHHWS -> "nmachhws"
  | Op.NMACHHWSO -> "nmachhwso"
  | Op.NMACHHWSOdot -> "nmachhwso."
  | Op.NMACHHWSdot -> "nmachhws."
  | Op.NMACHHWdot -> "nmachhw."
  | Op.NMACLHW -> "nmaclhw"
  | Op.NMACLHWO -> "nmaclhwo"
  | Op.NMACLHWOdot -> "nmaclhwo."
  | Op.NMACLHWS -> "nmaclhws"
  | Op.NMACLHWSO -> "nmaclhwso"
  | Op.NMACLHWSOdot -> "nmaclhwso."
  | Op.NMACLHWSdot -> "nmaclhws."
  | Op.NMACLHWdot -> "nmaclhw."
  | Op.DLMZB -> "dlmzb"
  | Op.DLMZBdot -> "dlmzb."
  | Op.DCBLC -> "dcblc"
  | Op.DCBLQdot -> "dcblq."
  | Op.DCBTLS -> "dcbtls"
  | Op.DCBTSTLS -> "dcbtstls"
  | Op.ICBLC -> "icblc"
  | Op.ICBLQdot -> "icblq."
  | Op.ICBTLS -> "icbtls"
  | Op.DNH -> "dnh"
  | Op.EHPRIV -> "ehpriv"
  | Op.MBAR -> "mbar"
  | Op.MFDCRUX -> "mfdcrux"
  | Op.MFPMR -> "mfpmr"
  | Op.MTDCRUX -> "mtdcrux"
  | Op.MTPMR -> "mtpmr"
  | Op.XNOP -> "xnop"
  | Op.DSN -> "dsn"
  | Op.LBDX -> "lbdx"
  | Op.LDDX -> "lddx"
  | Op.LFDDX -> "lfddx"
  | Op.LHDX -> "lhdx"
  | Op.LWDX -> "lwdx"
  | Op.STBDX -> "stbdx"
  | Op.STDDX -> "stddx"
  | Op.STFDDX -> "stfddx"
  | Op.STHDX -> "sthdx"
  | Op.STWDX -> "stwdx"
  | Op.TABORTDCIdot -> "tabortdci."
  | Op.TABORTDCdot -> "tabortdc."
  | Op.TABORTWCIdot -> "tabortwci."
  | Op.TABORTWCdot -> "tabortwc."
  | Op.TABORTdot -> "tabort."
  | Op.TBEGINdot -> "tbegin."
  | Op.TCHECK -> "tcheck"
  | Op.TENDdot -> "tend."
  | Op.TSRdot -> "tsr."
  | Op.MFTEXASR -> "mftexasr"
  | Op.MFTEXASRU -> "mftexasru"
  | Op.MFTFHAR -> "mftfhar"
  | Op.MFTFIAR -> "mftfiar"
  | Op.MTTEXASR -> "mttexasr"
  | Op.MTTEXASRU -> "mttexasru"
  | Op.MTTFHAR -> "mttfhar"
  | Op.MTTFIAR -> "mttfiar"
  (* Lane S: the Signal Processing Engine. *)
  | Op.EVADDIW -> "evaddiw"
  | Op.EVADDW -> "evaddw"
  | Op.EVAND -> "evand"
  | Op.EVANDC -> "evandc"
  | Op.EVEQV -> "eveqv"
  | Op.EVNAND -> "evnand"
  | Op.EVNOR -> "evnor"
  | Op.EVOR -> "evor"
  | Op.EVORC -> "evorc"
  | Op.EVSUBFW -> "evsubfw"
  | Op.EVSUBIFW -> "evsubifw"
  | Op.EVXOR -> "evxor"
  | Op.BRINC -> "brinc"
  | Op.EVABS -> "evabs"
  | Op.EVCNTLSW -> "evcntlsw"
  | Op.EVCNTLZW -> "evcntlzw"
  | Op.EVEXTSB -> "evextsb"
  | Op.EVEXTSH -> "evextsh"
  | Op.EVMERGEHI -> "evmergehi"
  | Op.EVMERGEHILO -> "evmergehilo"
  | Op.EVMERGELO -> "evmergelo"
  | Op.EVMERGELOHI -> "evmergelohi"
  | Op.EVNEG -> "evneg"
  | Op.EVRLW -> "evrlw"
  | Op.EVRLWI -> "evrlwi"
  | Op.EVRNDW -> "evrndw"
  | Op.EVSLW -> "evslw"
  | Op.EVSLWI -> "evslwi"
  | Op.EVSPLATFI -> "evsplatfi"
  | Op.EVSPLATI -> "evsplati"
  | Op.EVSRWIS -> "evsrwis"
  | Op.EVSRWIU -> "evsrwiu"
  | Op.EVSRWS -> "evsrws"
  | Op.EVSRWU -> "evsrwu"
  | Op.EVCMPEQ -> "evcmpeq"
  | Op.EVCMPGTS -> "evcmpgts"
  | Op.EVCMPGTU -> "evcmpgtu"
  | Op.EVCMPLTS -> "evcmplts"
  | Op.EVCMPLTU -> "evcmpltu"
  | Op.EVSEL -> "evsel"
  | Op.EVLDD -> "evldd"
  | Op.EVLDDX -> "evlddx"
  | Op.EVLDH -> "evldh"
  | Op.EVLDHX -> "evldhx"
  | Op.EVLDW -> "evldw"
  | Op.EVLDWX -> "evldwx"
  | Op.EVLHHESPLAT -> "evlhhesplat"
  | Op.EVLHHESPLATX -> "evlhhesplatx"
  | Op.EVLHHOSSPLAT -> "evlhhossplat"
  | Op.EVLHHOSSPLATX -> "evlhhossplatx"
  | Op.EVLHHOUSPLAT -> "evlhhousplat"
  | Op.EVLHHOUSPLATX -> "evlhhousplatx"
  | Op.EVLWHE -> "evlwhe"
  | Op.EVLWHEX -> "evlwhex"
  | Op.EVLWHOS -> "evlwhos"
  | Op.EVLWHOSX -> "evlwhosx"
  | Op.EVLWHOU -> "evlwhou"
  | Op.EVLWHOUX -> "evlwhoux"
  | Op.EVLWHSPLAT -> "evlwhsplat"
  | Op.EVLWHSPLATX -> "evlwhsplatx"
  | Op.EVLWWSPLAT -> "evlwwsplat"
  | Op.EVLWWSPLATX -> "evlwwsplatx"
  | Op.EVSTDD -> "evstdd"
  | Op.EVSTDDX -> "evstddx"
  | Op.EVSTDH -> "evstdh"
  | Op.EVSTDHX -> "evstdhx"
  | Op.EVSTDW -> "evstdw"
  | Op.EVSTDWX -> "evstdwx"
  | Op.EVSTWHE -> "evstwhe"
  | Op.EVSTWHEX -> "evstwhex"
  | Op.EVSTWHO -> "evstwho"
  | Op.EVSTWHOX -> "evstwhox"
  | Op.EVSTWWE -> "evstwwe"
  | Op.EVSTWWEX -> "evstwwex"
  | Op.EVSTWWO -> "evstwwo"
  | Op.EVSTWWOX -> "evstwwox"
  | Op.EVMHEGSMFAA -> "evmhegsmfaa"
  | Op.EVMHEGSMFAN -> "evmhegsmfan"
  | Op.EVMHEGSMIAA -> "evmhegsmiaa"
  | Op.EVMHEGSMIAN -> "evmhegsmian"
  | Op.EVMHEGUMIAA -> "evmhegumiaa"
  | Op.EVMHEGUMIAN -> "evmhegumian"
  | Op.EVMHESMF -> "evmhesmf"
  | Op.EVMHESMFA -> "evmhesmfa"
  | Op.EVMHESMFAAW -> "evmhesmfaaw"
  | Op.EVMHESMFANW -> "evmhesmfanw"
  | Op.EVMHESMI -> "evmhesmi"
  | Op.EVMHESMIA -> "evmhesmia"
  | Op.EVMHESMIAAW -> "evmhesmiaaw"
  | Op.EVMHESMIANW -> "evmhesmianw"
  | Op.EVMHESSF -> "evmhessf"
  | Op.EVMHESSFA -> "evmhessfa"
  | Op.EVMHESSFAAW -> "evmhessfaaw"
  | Op.EVMHESSFANW -> "evmhessfanw"
  | Op.EVMHESSIAAW -> "evmhessiaaw"
  | Op.EVMHESSIANW -> "evmhessianw"
  | Op.EVMHEUMI -> "evmheumi"
  | Op.EVMHEUMIA -> "evmheumia"
  | Op.EVMHEUMIAAW -> "evmheumiaaw"
  | Op.EVMHEUMIANW -> "evmheumianw"
  | Op.EVMHEUSIAAW -> "evmheusiaaw"
  | Op.EVMHEUSIANW -> "evmheusianw"
  | Op.EVMHOGSMFAA -> "evmhogsmfaa"
  | Op.EVMHOGSMFAN -> "evmhogsmfan"
  | Op.EVMHOGSMIAA -> "evmhogsmiaa"
  | Op.EVMHOGSMIAN -> "evmhogsmian"
  | Op.EVMHOGUMIAA -> "evmhogumiaa"
  | Op.EVMHOGUMIAN -> "evmhogumian"
  | Op.EVMHOSMF -> "evmhosmf"
  | Op.EVMHOSMFA -> "evmhosmfa"
  | Op.EVMHOSMFAAW -> "evmhosmfaaw"
  | Op.EVMHOSMFANW -> "evmhosmfanw"
  | Op.EVMHOSMI -> "evmhosmi"
  | Op.EVMHOSMIA -> "evmhosmia"
  | Op.EVMHOSMIAAW -> "evmhosmiaaw"
  | Op.EVMHOSMIANW -> "evmhosmianw"
  | Op.EVMHOSSF -> "evmhossf"
  | Op.EVMHOSSFA -> "evmhossfa"
  | Op.EVMHOSSFAAW -> "evmhossfaaw"
  | Op.EVMHOSSFANW -> "evmhossfanw"
  | Op.EVMHOSSIAAW -> "evmhossiaaw"
  | Op.EVMHOSSIANW -> "evmhossianw"
  | Op.EVMHOUMI -> "evmhoumi"
  | Op.EVMHOUMIA -> "evmhoumia"
  | Op.EVMHOUMIAAW -> "evmhoumiaaw"
  | Op.EVMHOUMIANW -> "evmhoumianw"
  | Op.EVMHOUSIAAW -> "evmhousiaaw"
  | Op.EVMHOUSIANW -> "evmhousianw"
  | Op.EVMWHSMF -> "evmwhsmf"
  | Op.EVMWHSMFA -> "evmwhsmfa"
  | Op.EVMWHSMI -> "evmwhsmi"
  | Op.EVMWHSMIA -> "evmwhsmia"
  | Op.EVMWHSSF -> "evmwhssf"
  | Op.EVMWHSSFA -> "evmwhssfa"
  | Op.EVMWHUMI -> "evmwhumi"
  | Op.EVMWHUMIA -> "evmwhumia"
  | Op.EVMWLSMIAAW -> "evmwlsmiaaw"
  | Op.EVMWLSMIANW -> "evmwlsmianw"
  | Op.EVMWLSSIAAW -> "evmwlssiaaw"
  | Op.EVMWLSSIANW -> "evmwlssianw"
  | Op.EVMWLUMI -> "evmwlumi"
  | Op.EVMWLUMIA -> "evmwlumia"
  | Op.EVMWLUMIAAW -> "evmwlumiaaw"
  | Op.EVMWLUMIANW -> "evmwlumianw"
  | Op.EVMWLUSIAAW -> "evmwlusiaaw"
  | Op.EVMWLUSIANW -> "evmwlusianw"
  | Op.EVMWSMF -> "evmwsmf"
  | Op.EVMWSMFA -> "evmwsmfa"
  | Op.EVMWSMFAA -> "evmwsmfaa"
  | Op.EVMWSMFAN -> "evmwsmfan"
  | Op.EVMWSMI -> "evmwsmi"
  | Op.EVMWSMIA -> "evmwsmia"
  | Op.EVMWSMIAA -> "evmwsmiaa"
  | Op.EVMWSMIAN -> "evmwsmian"
  | Op.EVMWSSF -> "evmwssf"
  | Op.EVMWSSFA -> "evmwssfa"
  | Op.EVMWSSFAA -> "evmwssfaa"
  | Op.EVMWSSFAN -> "evmwssfan"
  | Op.EVMWUMI -> "evmwumi"
  | Op.EVMWUMIA -> "evmwumia"
  | Op.EVMWUMIAA -> "evmwumiaa"
  | Op.EVMWUMIAN -> "evmwumian"
  | _ -> Terminator.impossible ()

let condToString = function
  | Condition.LT -> "lt"
  | Condition.LE -> "le"
  | Condition.EQ -> "eq"
  | Condition.GE -> "ge"
  | Condition.GT -> "gt"
  | Condition.NL -> "nl"
  | Condition.NE -> "ne"
  | Condition.NG -> "ng"
  | Condition.SO -> "so"
  | Condition.NS -> "ns"
  | Condition.UN -> "un"
  | Condition.NU -> "nu"
  | _ -> raise ParsingFailureException

let inline buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate(AsmWordKind.Mnemonic, str)

/// Whether the place a branch names is written into the branch outright rather
/// than counted from where the branch itself sits.
let private isAbsolute = function
  | Op.BCA | Op.BCLA -> true
  | _ -> false

/// <summary>
/// Where a branch goes.
///
/// A branch that counts the distance to its place reaches it by adding that
/// distance to where the branch sits, and the sum is cut back to the width of a
/// register because reaching past the end of the address space wraps round to
/// the beginning of it rather than beyond. A branch that names its place
/// outright already holds the address, and adding anything to it would name
/// somewhere else.
/// </summary>
let relToString (ins: Instruction) offset (builder: IDisasmBuilder) =
  let target =
    if isAbsolute ins.Opcode then
      uint64 offset
    else
      let mask = System.UInt64.MaxValue >>> (64 - int ins.OperationSize)
      (ins.Address + uint64 offset) &&& mask
  builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 target)

let inline getCond bi =
  match Bits.extract bi 1u 0u with
  | 0b00u -> Condition.LT
  | 0b01u -> Condition.GT
  | 0b10u -> Condition.EQ
  | _ (* 11 *) -> Condition.SO

/// A register's assembly name. A vector register is modeled as two 64-bit
/// halves but written as one register, so an operand naming its high half
/// prints under the whole register's name.
let private regName (reg: Register) =
  if reg >= Register.V0A && reg <= Register.V31B then
    "v" + string ((int reg - int Register.V0A) / 2)
  else
    Register.toString reg

let oprToString (ins: Instruction) opr delim (builder: IDisasmBuilder) =
  match opr with
  | OprReg reg ->
    builder.Accumulate(AsmWordKind.String, delim)
    builder.Accumulate(AsmWordKind.Variable, regName reg)
  | OprMem(imm, reg) ->
    builder.Accumulate(AsmWordKind.String, delim)
    builder.Accumulate(AsmWordKind.Value, HexString.ofInt32 imm)
    builder.Accumulate(AsmWordKind.String, "(")
    builder.Accumulate(AsmWordKind.Variable, Register.toString reg)
    builder.Accumulate(AsmWordKind.String, ")")
  | OprImm imm ->
    builder.Accumulate(AsmWordKind.String, delim)
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 imm)
  | OprAddr addr ->
    builder.Accumulate(AsmWordKind.String, delim)
    relToString ins addr builder
  | OprBI imm ->
    let cr = Bits.extract imm 4u 2u |> getCondRegister
    builder.Accumulate(AsmWordKind.String, delim)
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt32 4u)
    builder.Accumulate(AsmWordKind.String, " * ")
    builder.Accumulate(AsmWordKind.Variable, Register.toString cr)
    builder.Accumulate(AsmWordKind.String, " + ")
    builder.Accumulate(AsmWordKind.String, condToString (getCond imm))

let buildOprs (ins: Instruction) builder =
  match ins.Operands with
  | NoOperand ->
    ()
  | OneOperand opr ->
    oprToString ins opr " " builder
  | TwoOperands(opr1, opr2) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
  | ThreeOperands(opr1, opr2, opr3) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
    oprToString ins opr3 ", " builder
  | FourOperands(opr1, opr2, opr3, opr4) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
    oprToString ins opr3 ", " builder
    oprToString ins opr4 ", " builder
  | FiveOperands(opr1, opr2, opr3, opr4, opr5) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
    oprToString ins opr3 ", " builder
    oprToString ins opr4 ", " builder
    oprToString ins opr5 ", " builder

let buildSimpleMnemonic opcode bi addr ins (builder: IDisasmBuilder) =
  let cr = Bits.extract bi 4u 2u |> getCondRegister
  builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString opcode)
  builder.Accumulate(AsmWordKind.String, " ")
  builder.Accumulate(AsmWordKind.Variable, Register.toString cr)
  builder.Accumulate(AsmWordKind.String, ", ")
  relToString ins addr builder

let buildCrMnemonic opcode bi (builder: IDisasmBuilder) =
  let cr = Bits.extract bi 4u 2u |> getCondRegister
  builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString opcode)
  builder.Accumulate(AsmWordKind.String, " ")
  builder.Accumulate(AsmWordKind.Variable, Register.toString cr)

let buildTargetMnemonic opcode addr ins (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString opcode)
  builder.Accumulate(AsmWordKind.String, " ")
  relToString ins addr builder

let buildRotateMnemonic opcode ra rs n (builder: IDisasmBuilder) =
  builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString opcode)
  builder.Accumulate(AsmWordKind.String, " ")
  builder.Accumulate(AsmWordKind.Variable, Register.toString ra)
  builder.Accumulate(AsmWordKind.String, ", ")
  builder.Accumulate(AsmWordKind.Variable, Register.toString rs)
  builder.Accumulate(AsmWordKind.String, ", ")
  builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 n)

let buildBC (ins: Instruction) builder =
  match ins.Operands with
  | ThreeOperands(OprImm bo, OprBI bi, OprAddr addr) ->
    let bibit = bi % 4u
    match bo, bi, bibit with
    (* bdnz reads no bit of the condition register, so it writes no field of
       it either; every other name below tests one and says which field. *)
    | 16UL, 0u, _ ->
      buildTargetMnemonic Op.BDNZ addr ins builder
    | 12UL, _, 0u ->
      buildSimpleMnemonic Op.BLT bi addr ins builder
    | 12UL, _, 1u ->
      buildSimpleMnemonic Op.BGT bi addr ins builder
    | 12UL, _, 2u ->
      buildSimpleMnemonic Op.BEQ bi addr ins builder
    | 12UL, _, 3u ->
      buildSimpleMnemonic Op.BSO bi addr ins builder
    | 4UL, _, 0u ->
      buildSimpleMnemonic Op.BGE bi addr ins builder
    | 4UL, _, 1u ->
      buildSimpleMnemonic Op.BLE bi addr ins builder
    | 4UL, _, 2u ->
      buildSimpleMnemonic Op.BNE bi addr ins builder
    | 4UL, _, 3u ->
      buildSimpleMnemonic Op.BNS bi addr ins builder
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let buildBCA (ins: Instruction) builder =
  match ins.Operands with
  | ThreeOperands(OprImm bo, OprBI bi, OprAddr addr) ->
    let bibit = bi % 4u
    match bo, bibit with
    | 12UL, 0u ->
      buildSimpleMnemonic Op.BLTA bi addr ins builder
    | 12UL, 1u ->
      buildSimpleMnemonic Op.BGTA bi addr ins builder
    | 12UL, 2u ->
      buildSimpleMnemonic Op.BEQA bi addr ins builder
    | 12UL, 3u ->
      buildSimpleMnemonic Op.BSOA bi addr ins builder
    | 4UL, 0u ->
      buildSimpleMnemonic Op.BGEA bi addr ins builder
    | 4UL, 1u ->
      buildSimpleMnemonic Op.BLEA bi addr ins builder
    | 4UL, 2u ->
      buildSimpleMnemonic Op.BNEA bi addr ins builder
    | 4UL, 3u ->
      buildSimpleMnemonic Op.BNSA bi addr ins builder
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let buildBCL (ins: Instruction) builder =
  match ins.Operands with
  | ThreeOperands(OprImm bo, OprBI bi, OprAddr addr) ->
    let bibit = bi % 4u
    match bo, bibit with
    | 12UL, 0u ->
      buildSimpleMnemonic Op.BLTL bi addr ins builder
    | 12UL, 1u ->
      buildSimpleMnemonic Op.BGTL bi addr ins builder
    | 12UL, 2u ->
      buildSimpleMnemonic Op.BEQL bi addr ins builder
    | 12UL, 3u ->
      buildSimpleMnemonic Op.BSOL bi addr ins builder
    | 4UL, 0u ->
      buildSimpleMnemonic Op.BGEL bi addr ins builder
    | 4UL, 1u ->
      buildSimpleMnemonic Op.BLEL bi addr ins builder
    | 4UL, 2u ->
      buildSimpleMnemonic Op.BNEL bi addr ins builder
    | 4UL, 3u ->
      buildSimpleMnemonic Op.BNSL bi addr ins builder
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let buildBCLA (ins: Instruction) builder =
  match ins.Operands with
  | ThreeOperands(OprImm bo, OprBI bi, OprAddr addr) ->
    let bibit = bi % 4u
    match bo, bibit with
    | 12uL, 0u ->
      buildSimpleMnemonic Op.BLTLA bi addr ins builder
    | 12UL, 1u ->
      buildSimpleMnemonic Op.BGTLA bi addr ins builder
    | 12UL, 2u ->
      buildSimpleMnemonic Op.BEQLA bi addr ins builder
    | 12UL, 3u ->
      buildSimpleMnemonic Op.BSOLA bi addr ins builder
    | 4UL, 0u ->
      buildSimpleMnemonic Op.BGELA bi addr ins builder
    | 4UL, 1u ->
      buildSimpleMnemonic Op.BLELA bi addr ins builder
    | 4UL, 2u ->
      buildSimpleMnemonic Op.BNELA bi addr ins builder
    | 4UL, 3u ->
      buildSimpleMnemonic Op.BNSLA bi addr ins builder
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let buildBCLR (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | TwoOperands(OprImm bo, OprBI bi) ->
    let bibit = bi % 4u
    match bo, bibit with
    | 20uL, 0u ->
      builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString Op.BLR)
    | 12UL, 0u ->
      buildCrMnemonic Op.BLTLR bi builder
    | 12UL, 1u ->
      buildCrMnemonic Op.BGTLR bi builder
    | 12UL, 2u ->
      buildCrMnemonic Op.BEQLR bi builder
    | 12UL, 3u ->
      buildCrMnemonic Op.BSOLR bi builder
    | 4UL, 0u ->
      buildCrMnemonic Op.BGELR bi builder
    | 4UL, 1u ->
      buildCrMnemonic Op.BLELR bi builder
    | 4UL, 2u ->
      buildCrMnemonic Op.BNELR bi builder
    | 4UL, 3u ->
      buildCrMnemonic Op.BNSLR bi builder
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let buildBCLRL (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | TwoOperands(OprImm bo, OprBI bi) ->
    match bo, bi with
    | 12UL, 0u ->
      buildCrMnemonic Op.BLTLRL bi builder
    | 12UL, 1u ->
      buildCrMnemonic Op.BGTLRL bi builder
    | 12UL, 2u ->
      buildCrMnemonic Op.BEQLRL bi builder
    | 12UL, 3u ->
      buildCrMnemonic Op.BSOLRL bi builder
    | 4UL, 0u ->
      buildCrMnemonic Op.BGELRL bi builder
    | 4UL, 1u ->
      buildCrMnemonic Op.BLELRL bi builder
    | 4UL, 2u ->
      buildCrMnemonic Op.BNELRL bi builder
    | 4UL, 3u ->
      buildCrMnemonic Op.BNSLRL bi builder
    | 20UL, 0u ->
      builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString Op.BLRL)
    | 16UL, 0u ->
      builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString Op.BDNZLRL)
    | 18UL, 0u ->
      builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString Op.BDZLRL)
    | 8UL, _ ->
      buildCrMnemonic Op.BDNZTLRL bi builder
    | 0UL, _ ->
      buildCrMnemonic Op.BDNZFLRL bi builder
    | 10UL, _ ->
      buildCrMnemonic Op.BDZTLRL bi builder
    | 2UL, _ ->
      buildCrMnemonic Op.BDZFLRL bi builder
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let buildBCCTR (ins: Instruction) builder =
  match ins.Operands with
  | TwoOperands(OprImm bo, OprBI bi) ->
    let bibit = bi % 4u
    match bo, bibit with
    | 12UL, 0u ->
      buildCrMnemonic Op.BLTCTR bi builder
    | 12UL, 1u ->
      buildCrMnemonic Op.BGTCTR bi builder
    | 12UL, 2u ->
      buildCrMnemonic Op.BEQCTR bi builder
    | 12UL, 3u ->
      buildCrMnemonic Op.BSOCTR bi builder
    | 4UL, 0u ->
      buildCrMnemonic Op.BGECTR bi builder
    | 4UL, 1u ->
      buildCrMnemonic Op.BLECTR bi builder
    | 4UL, 2u ->
      buildCrMnemonic Op.BNECTR bi builder
    | 4UL, 3u ->
      buildCrMnemonic Op.BNSCTR bi builder
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let buildBCCTRL (ins: Instruction) builder =
  match ins.Operands with
  | TwoOperands(OprImm bo, OprBI bi) ->
    let bibit = bi % 4u
    match bo, bibit with
    | 12UL, 0u ->
      buildCrMnemonic Op.BLTCTRL bi builder
    | 12UL, 1u ->
      buildCrMnemonic Op.BGTCTRL bi builder
    | 12UL, 2u ->
      buildCrMnemonic Op.BEQCTRL bi builder
    | 12UL, 3u ->
      buildCrMnemonic Op.BSOCTRL bi builder
    | 4UL, 0u ->
      buildCrMnemonic Op.BGECTRL bi builder
    | 4UL, 1u ->
      buildCrMnemonic Op.BLECTRL bi builder
    | 4UL, 2u ->
      buildCrMnemonic Op.BNECTRL bi builder
    | 4UL, 3u ->
      buildCrMnemonic Op.BNSCTRL bi builder
    | 20UL, 0u ->
      builder.Accumulate(AsmWordKind.Mnemonic, opCodeToString Op.BCTRL)
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let buildRLWINM (ins: Instruction) builder =
  match ins.Operands with
  | FiveOperands(OprReg ra, OprReg rs, OprImm sh, OprImm mb, OprImm me) ->
    match sh, mb, me with
    | _, 0UL, 31UL ->
      buildRotateMnemonic Op.ROTLWI ra rs sh builder
    | n1, 0UL, n2 when n2 = (31UL - n1) ->
      buildRotateMnemonic Op.SLWI ra rs sh builder
    | n1, n2, 31UL when n1 = (32UL - n2) ->
      buildRotateMnemonic Op.SRWI ra rs mb builder
    | 0UL, _, 31UL ->
      buildRotateMnemonic Op.CLRLWI ra rs mb builder
    | 0UL, 0UL, n ->
      buildRotateMnemonic Op.CLRRWI ra rs (31UL - me) builder
    | _ ->
      buildOpcode ins builder
      buildOprs ins builder
  | _ ->
    raise ParsingFailureException

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  match ins.Opcode with
  | Op.BC ->
    buildBC ins builder
  | Op.BCA ->
    buildBCA ins builder
  | Op.BCL ->
    buildBCL ins builder
  | Op.BCLA ->
    buildBCLA ins builder
  | Op.BCLR ->
    buildBCLR ins builder
  | Op.BCLRL ->
    buildBCLRL ins builder
  | Op.BCCTR ->
    buildBCCTR ins builder
  | Op.BCCTRL ->
    buildBCCTRL ins builder
  | Op.RLWINM ->
    buildRLWINM ins builder
  | _ ->
    buildOpcode ins builder
    buildOprs ins builder

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
  | Op.LXVD2X -> "lxvd2x"
  | Op.LXVDSX -> "lxvdsx"
  | Op.LXVW4X -> "lxvw4x"
  | Op.STXSDX -> "stxsdx"
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
  | Op.XXSEL -> "xxsel"
  | Op.XXSLDWI -> "xxsldwi"
  | Op.XSADDDP -> "xsadddp"
  | Op.XSSUBDP -> "xssubdp"
  | Op.XSDIVDP -> "xsdivdp"
  | Op.XSCMPUDP -> "xscmpudp"
  | Op.XSCPSGNDP -> "xscpsgndp"
  | Op.XSABSDP -> "xsabsdp"
  | Op.XSRSP -> "xsrsp"
  | Op.XSCVDPSPN -> "xscvdpspn"
  | Op.XSCVSPDPN -> "xscvspdpn"
  | Op.XXSPLTW -> "xxspltw"
  | Op.MTVSRDD -> "mtvsrdd"
  | Op.MFVSRLD -> "mfvsrld"
  | Op.FCPSGN -> "fcpsgn"
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
  | Op.VADDUHM -> "vadduhm"
  | Op.VADDUWM -> "vadduwm"
  | Op.VADDUDM -> "vaddudm"
  | Op.VSUBUBM -> "vsububm"
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
  | Op.VUPKLSB -> "vupklsb"
  | Op.VUPKLSH -> "vupklsh"
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

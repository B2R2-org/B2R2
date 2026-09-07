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

module internal B2R2.FrontEnd.S390.Lifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390
open B2R2.FrontEnd.S390.LiftingUtils
open B2R2.FrontEnd.S390.GeneralLifter

/// The identity widening, for an operation whose source is already as wide as
/// the operation itself.
let private same (_: RegType) e = e

/// The plain loads, the address computations, and the immediate insertions.
let private liftLoad ins bld opcode =
  match opcode with
  | Opcode.LR -> load ins bld WSize WSize same
  | Opcode.LGR -> load ins bld GRSize GRSize same
  | Opcode.LGFR -> load ins bld GRSize WSize sextTo
  | Opcode.LLGFR -> load ins bld GRSize WSize zextTo
  | Opcode.LBR -> load ins bld WSize 8<rt> sextTo
  | Opcode.LGBR -> load ins bld GRSize 8<rt> sextTo
  | Opcode.LHR -> load ins bld WSize 16<rt> sextTo
  | Opcode.LGHR -> load ins bld GRSize 16<rt> sextTo
  | Opcode.LLCR -> load ins bld WSize 8<rt> zextTo
  | Opcode.LLGCR -> load ins bld GRSize 8<rt> zextTo
  | Opcode.LLHR -> load ins bld WSize 16<rt> zextTo
  | Opcode.LLGHR -> load ins bld GRSize 16<rt> zextTo
  | Opcode.L | Opcode.LY -> load ins bld WSize WSize same
  | Opcode.LG -> load ins bld GRSize GRSize same
  | Opcode.LGF -> load ins bld GRSize WSize sextTo
  | Opcode.LLGF -> load ins bld GRSize WSize zextTo
  | Opcode.LH | Opcode.LHY -> load ins bld WSize 16<rt> sextTo
  | Opcode.LGH -> load ins bld GRSize 16<rt> sextTo
  | Opcode.LLH -> load ins bld WSize 16<rt> zextTo
  | Opcode.LLGH -> load ins bld GRSize 16<rt> zextTo
  | Opcode.LB -> load ins bld WSize 8<rt> sextTo
  | Opcode.LGB -> load ins bld GRSize 8<rt> sextTo
  | Opcode.LLC -> load ins bld WSize 8<rt> zextTo
  | Opcode.LLGC -> load ins bld GRSize 8<rt> zextTo
  | Opcode.LHI -> load ins bld WSize WSize same
  | Opcode.LGHI | Opcode.LGFI -> load ins bld GRSize GRSize same
  | Opcode.LT | Opcode.LTR -> loadTest ins bld WSize WSize same
  | Opcode.LTG | Opcode.LTGR -> loadTest ins bld GRSize GRSize same
  | Opcode.LTGF | Opcode.LTGFR -> loadTest ins bld GRSize WSize sextTo
  | Opcode.LRL -> loadRel ins bld WSize WSize same
  | Opcode.LGRL -> loadRel ins bld GRSize GRSize same
  | Opcode.LGFRL -> loadRel ins bld GRSize WSize sextTo
  | Opcode.LLGFRL -> loadRel ins bld GRSize WSize zextTo
  | Opcode.LHRL -> loadRel ins bld WSize 16<rt> sextTo
  | Opcode.LGHRL -> loadRel ins bld GRSize 16<rt> sextTo
  | Opcode.LLHRL -> loadRel ins bld WSize 16<rt> zextTo
  | Opcode.LLGHRL -> loadRel ins bld GRSize 16<rt> zextTo
  | Opcode.LLGT | Opcode.LLGTR -> loadThirtyOne ins bld
  | Opcode.LA | Opcode.LAY -> la ins bld
  | Opcode.LARL -> larl ins bld
  | Opcode.LM | Opcode.LMY -> loadMultiple ins bld WSize
  | Opcode.LMG -> loadMultiple ins bld GRSize
  | Opcode.LOC | Opcode.LOCR -> loadOnCondition ins bld WSize
  | Opcode.LOCG | Opcode.LOCGR -> loadOnCondition ins bld GRSize
  | Opcode.LOCHI -> loadImmOnCondition ins bld WSize
  | Opcode.LOCGHI -> loadImmOnCondition ins bld GRSize
  | Opcode.IILF -> insertImm ins bld 0 WSize
  | Opcode.IIHF -> insertImm ins bld 32 WSize
  | Opcode.IILL -> insertImm ins bld 0 16<rt>
  | Opcode.IILH -> insertImm ins bld 16 16<rt>
  | Opcode.IIHL -> insertImm ins bld 32 16<rt>
  | Opcode.IIHH -> insertImm ins bld 48 16<rt>
  | Opcode.LLILF | Opcode.LLILL -> loadLogicalImm ins bld 0
  | Opcode.LLILH -> loadLogicalImm ins bld 16
  | Opcode.LLIHF | Opcode.LLIHL -> loadLogicalImm ins bld 32
  | Opcode.LLIHH -> loadLogicalImm ins bld 48
  | Opcode.IC | Opcode.ICY -> ic ins bld
  | Opcode.ICM | Opcode.ICMY -> icm ins bld 0
  | Opcode.ICMH -> icm ins bld 32
  | Opcode.LRVR -> loadReversed ins bld WSize WSize
  | Opcode.LRVGR -> loadReversed ins bld GRSize GRSize
  | Opcode.LRV -> loadReversed ins bld WSize WSize
  | Opcode.LRVG -> loadReversed ins bld GRSize GRSize
  | Opcode.LRVH -> loadReversed ins bld WSize 16<rt>
  | _ -> raise ParsingFailureException

/// The stores, including the ones that move an immediate straight to storage
/// and the storage-to-storage operations.
let private liftStore ins bld opcode =
  match opcode with
  | Opcode.ST | Opcode.STY -> store ins bld WSize
  | Opcode.STG -> store ins bld GRSize
  | Opcode.STH | Opcode.STHY -> store ins bld 16<rt>
  | Opcode.STC | Opcode.STCY -> store ins bld 8<rt>
  | Opcode.STRL -> storeRel ins bld WSize
  | Opcode.STGRL -> storeRel ins bld GRSize
  | Opcode.STHRL -> storeRel ins bld 16<rt>
  | Opcode.STM | Opcode.STMY -> storeMultiple ins bld WSize
  | Opcode.STMG -> storeMultiple ins bld GRSize
  | Opcode.STOC -> storeOnCondition ins bld WSize
  | Opcode.STOCG -> storeOnCondition ins bld GRSize
  | Opcode.STCM | Opcode.STCMY -> stcm ins bld
  | Opcode.STRV -> storeReversed ins bld WSize
  | Opcode.STRVG -> storeReversed ins bld GRSize
  | Opcode.STRVH -> storeReversed ins bld 16<rt>
  | Opcode.MVI | Opcode.MVIY -> moveImm ins bld 8<rt>
  | Opcode.MVHHI -> moveImm ins bld 16<rt>
  | Opcode.MVHI -> moveImm ins bld WSize
  | Opcode.MVGHI -> moveImm ins bld GRSize
  | Opcode.MVC -> ssOp ins bld (fun _ s -> s)
  | Opcode.NC -> ssLogic ins bld (.&)
  | Opcode.OC -> ssLogic ins bld (.|)
  | Opcode.XC -> ssLogic ins bld (<+>)
  | _ -> raise ParsingFailureException

/// The fixed-point arithmetic.
let private liftArith ins bld opcode =
  match opcode with
  | Opcode.AR | Opcode.A | Opcode.AY | Opcode.AHI | Opcode.AFI ->
    alu2 ins bld WSize (.+) ccAdd
  | Opcode.AGR | Opcode.AG | Opcode.AGHI | Opcode.AGFI ->
    alu2 ins bld GRSize (.+) ccAdd
  | Opcode.AH | Opcode.AHY ->
    alu2Ext ins bld WSize 16<rt> sextTo (.+) ccAdd
  | Opcode.AGH ->
    alu2Ext ins bld GRSize 16<rt> sextTo (.+) ccAdd
  | Opcode.AGF | Opcode.AGFR ->
    alu2Ext ins bld GRSize WSize sextTo (.+) ccAdd
  | Opcode.ARK ->
    alu3 ins bld WSize (.+) ccAdd
  | Opcode.AGRK ->
    alu3 ins bld GRSize (.+) ccAdd
  | Opcode.AHIK ->
    alu3Imm ins bld WSize (.+) ccAdd
  | Opcode.AGHIK ->
    alu3Imm ins bld GRSize (.+) ccAdd
  | Opcode.ASI ->
    addToStorage ins bld WSize
  | Opcode.AGSI ->
    addToStorage ins bld GRSize
  | Opcode.ALR | Opcode.AL | Opcode.ALY | Opcode.ALFI ->
    alu2 ins bld WSize (.+) ccAddL
  | Opcode.ALGR | Opcode.ALG | Opcode.ALGFI ->
    alu2 ins bld GRSize (.+) ccAddL
  | Opcode.ALGF | Opcode.ALGFR ->
    alu2Ext ins bld GRSize WSize zextTo (.+) ccAddL
  | Opcode.ALRK ->
    alu3 ins bld WSize (.+) ccAddL
  | Opcode.ALGRK ->
    alu3 ins bld GRSize (.+) ccAddL
  | Opcode.ALHSIK ->
    alu3Imm ins bld WSize (.+) ccAddL
  | Opcode.ALGHSIK ->
    alu3Imm ins bld GRSize (.+) ccAddL
  | Opcode.ALCR ->
    addCarry ins bld WSize
  | Opcode.ALCGR ->
    addCarry ins bld GRSize
  | Opcode.SR | Opcode.S | Opcode.SY ->
    alu2 ins bld WSize (.-) ccSub
  | Opcode.SGR | Opcode.SG ->
    alu2 ins bld GRSize (.-) ccSub
  | Opcode.SH | Opcode.SHY ->
    alu2Ext ins bld WSize 16<rt> sextTo (.-) ccSub
  | Opcode.SGF | Opcode.SGFR ->
    alu2Ext ins bld GRSize WSize sextTo (.-) ccSub
  | Opcode.SRK ->
    alu3 ins bld WSize (.-) ccSub
  | Opcode.SGRK ->
    alu3 ins bld GRSize (.-) ccSub
  | Opcode.SLR | Opcode.SL | Opcode.SLY | Opcode.SLFI ->
    alu2 ins bld WSize (.-) ccSubL
  | Opcode.SLGR | Opcode.SLG | Opcode.SLGFI ->
    alu2 ins bld GRSize (.-) ccSubL
  | Opcode.SLGF | Opcode.SLGFR ->
    alu2Ext ins bld GRSize WSize zextTo (.-) ccSubL
  | Opcode.SLRK ->
    alu3 ins bld WSize (.-) ccSubL
  | Opcode.SLGRK ->
    alu3 ins bld GRSize (.-) ccSubL
  | Opcode.SLBR ->
    subBorrow ins bld WSize
  | Opcode.SLBGR ->
    subBorrow ins bld GRSize
  | Opcode.LCR ->
    unaryArith ins bld WSize WSize AST.neg
  | Opcode.LCGR ->
    unaryArith ins bld GRSize GRSize AST.neg
  | Opcode.LCGFR ->
    unaryArith ins bld GRSize WSize AST.neg
  | Opcode.LPR ->
    unaryArith ins bld WSize WSize absValue
  | Opcode.LPGR ->
    unaryArith ins bld GRSize GRSize absValue
  | Opcode.LPGFR ->
    unaryArith ins bld GRSize WSize absValue
  | Opcode.LNR ->
    unaryArith ins bld WSize WSize negAbsValue
  | Opcode.LNGR ->
    unaryArith ins bld GRSize GRSize negAbsValue
  | Opcode.LNGFR ->
    unaryArith ins bld GRSize WSize negAbsValue
  | Opcode.MSR | Opcode.MS | Opcode.MSY | Opcode.MSFI | Opcode.MHI ->
    mul ins bld WSize WSize same
  | Opcode.MSGR | Opcode.MSG | Opcode.MSGFI | Opcode.MGHI ->
    mul ins bld GRSize GRSize same
  | Opcode.MSGF | Opcode.MSGFR ->
    mul ins bld GRSize WSize sextTo
  | Opcode.MH | Opcode.MHY ->
    mul ins bld WSize 16<rt> sextTo
  | Opcode.MSRKC ->
    mul3 ins bld WSize
  | Opcode.MSGRKC ->
    mul3 ins bld GRSize
  | Opcode.MLR | Opcode.ML ->
    mulLogical ins bld WSize WSize
  | Opcode.MLGR | Opcode.MLG ->
    mulLogical ins bld GRSize GRSize
  | Opcode.DLR | Opcode.DL ->
    divLogical ins bld WSize WSize
  | Opcode.DLGR | Opcode.DLG ->
    divLogical ins bld GRSize GRSize
  | Opcode.DSGR | Opcode.DSG ->
    divSingle ins bld GRSize GRSize
  | Opcode.DSGFR | Opcode.DSGF ->
    divSingle ins bld GRSize WSize
  | Opcode.FLOGR ->
    flogr ins bld
  | Opcode.POPCNT ->
    popcnt ins bld
  | _ ->
    raise ParsingFailureException

/// The bitwise operations, including the ones an immediate names a field of a
/// register or a byte of storage for.
let private liftLogic ins bld opcode =
  match opcode with
  | Opcode.NR | Opcode.N | Opcode.NY -> alu2 ins bld WSize (.&) ccLogic
  | Opcode.NGR | Opcode.NG -> alu2 ins bld GRSize (.&) ccLogic
  | Opcode.NRK -> alu3 ins bld WSize (.&) ccLogic
  | Opcode.NGRK -> alu3 ins bld GRSize (.&) ccLogic
  | Opcode.OR | Opcode.O | Opcode.OY -> alu2 ins bld WSize (.|) ccLogic
  | Opcode.OGR | Opcode.OG -> alu2 ins bld GRSize (.|) ccLogic
  | Opcode.ORK -> alu3 ins bld WSize (.|) ccLogic
  | Opcode.OGRK -> alu3 ins bld GRSize (.|) ccLogic
  | Opcode.XR | Opcode.X | Opcode.XY -> alu2 ins bld WSize (<+>) ccLogic
  | Opcode.XGR | Opcode.XG -> alu2 ins bld GRSize (<+>) ccLogic
  | Opcode.XRK -> alu3 ins bld WSize (<+>) ccLogic
  | Opcode.XGRK -> alu3 ins bld GRSize (<+>) ccLogic
  | Opcode.NILF -> logicImmField ins bld 0 WSize (.&)
  | Opcode.NIHF -> logicImmField ins bld 32 WSize (.&)
  | Opcode.NILL -> logicImmField ins bld 0 16<rt> (.&)
  | Opcode.NILH -> logicImmField ins bld 16 16<rt> (.&)
  | Opcode.NIHL -> logicImmField ins bld 32 16<rt> (.&)
  | Opcode.NIHH -> logicImmField ins bld 48 16<rt> (.&)
  | Opcode.OILF -> logicImmField ins bld 0 WSize (.|)
  | Opcode.OIHF -> logicImmField ins bld 32 WSize (.|)
  | Opcode.OILL -> logicImmField ins bld 0 16<rt> (.|)
  | Opcode.OILH -> logicImmField ins bld 16 16<rt> (.|)
  | Opcode.OIHL -> logicImmField ins bld 32 16<rt> (.|)
  | Opcode.OIHH -> logicImmField ins bld 48 16<rt> (.|)
  | Opcode.XILF -> logicImmField ins bld 0 WSize (<+>)
  | Opcode.XIHF -> logicImmField ins bld 32 WSize (<+>)
  | Opcode.NI | Opcode.NIY -> logicImmStorage ins bld (.&) true
  | Opcode.OI | Opcode.OIY -> logicImmStorage ins bld (.|) true
  | Opcode.XI | Opcode.XIY -> logicImmStorage ins bld (<+>) true
  | _ -> raise ParsingFailureException

/// The shifts and the rotate-then-insert family.
let private liftShift ins bld opcode =
  match opcode with
  | Opcode.SLL ->
    shift2 ins bld (<<) false
  | Opcode.SRL ->
    shift2 ins bld (>>) false
  | Opcode.SLA ->
    shift2 ins bld (<<) true
  | Opcode.SRA ->
    shift2 ins bld (?>>) true
  | Opcode.SLLK ->
    shift3 ins bld WSize (<<) false
  | Opcode.SRLK ->
    shift3 ins bld WSize (>>) false
  | Opcode.SLAK ->
    shift3 ins bld WSize (<<) true
  | Opcode.SRAK ->
    shift3 ins bld WSize (?>>) true
  | Opcode.SLLG ->
    shift3 ins bld GRSize (<<) false
  | Opcode.SRLG ->
    shift3 ins bld GRSize (>>) false
  | Opcode.SLAG ->
    shift3 ins bld GRSize (<<) true
  | Opcode.SRAG ->
    shift3 ins bld GRSize (?>>) true
  | Opcode.RLL ->
    rotate ins bld WSize
  | Opcode.RLLG ->
    rotate ins bld GRSize
  | Opcode.RISBG ->
    rotateInsert ins bld (.|) true
  | Opcode.RISBGN ->
    rotateInsert ins bld (.|) false
  | Opcode.ROSBG ->
    rotateCombine ins bld (fun d r m -> d .| (r .& numG (int64 m)))
  | Opcode.RXSBG ->
    rotateCombine ins bld (fun d r m -> d <+> (r .& numG (int64 m)))
  | Opcode.RNSBG ->
    rotateCombine ins bld (fun d r m -> d .& (r .| numG (int64 ~~~m)))
  | _ ->
    raise ParsingFailureException

/// The comparisons and the tests under a mask.
let private liftCompare ins bld opcode =
  match opcode with
  | Opcode.CR | Opcode.C | Opcode.CY | Opcode.CHI | Opcode.CFI ->
    compare ins bld WSize WSize same true
  | Opcode.CGR | Opcode.CG | Opcode.CGHI | Opcode.CGFI ->
    compare ins bld GRSize GRSize same true
  | Opcode.CH | Opcode.CHY ->
    compare ins bld WSize 16<rt> sextTo true
  | Opcode.CGH ->
    compare ins bld GRSize 16<rt> sextTo true
  | Opcode.CGF | Opcode.CGFR ->
    compare ins bld GRSize WSize sextTo true
  | Opcode.CLR | Opcode.CL | Opcode.CLY | Opcode.CLFI ->
    compare ins bld WSize WSize same false
  | Opcode.CLGR | Opcode.CLG | Opcode.CLGFI ->
    compare ins bld GRSize GRSize same false
  | Opcode.CLGF | Opcode.CLGFR ->
    compare ins bld GRSize WSize zextTo false
  | Opcode.CRL ->
    compareRel ins bld WSize WSize same true
  | Opcode.CGRL ->
    compareRel ins bld GRSize GRSize same true
  | Opcode.CGFRL ->
    compareRel ins bld GRSize WSize sextTo true
  | Opcode.CHRL ->
    compareRel ins bld WSize 16<rt> sextTo true
  | Opcode.CGHRL ->
    compareRel ins bld GRSize 16<rt> sextTo true
  | Opcode.CLRL ->
    compareRel ins bld WSize WSize same false
  | Opcode.CLGRL ->
    compareRel ins bld GRSize GRSize same false
  | Opcode.CLGFRL ->
    compareRel ins bld GRSize WSize zextTo false
  | Opcode.CLHRL ->
    compareRel ins bld WSize 16<rt> zextTo false
  | Opcode.CLGHRL ->
    compareRel ins bld GRSize 16<rt> zextTo false
  | Opcode.CLI | Opcode.CLIY ->
    compareStorageImm ins bld 8<rt> false
  | Opcode.CHHSI ->
    compareStorageImm ins bld 16<rt> true
  | Opcode.CHSI ->
    compareStorageImm ins bld WSize true
  | Opcode.CGHSI ->
    compareStorageImm ins bld GRSize true
  | Opcode.CLHHSI ->
    compareStorageImm ins bld 16<rt> false
  | Opcode.CLFHSI ->
    compareStorageImm ins bld WSize false
  | Opcode.CLGHSI ->
    compareStorageImm ins bld GRSize false
  | Opcode.CLC ->
    compareStorage ins bld
  | Opcode.CLM | Opcode.CLMY ->
    clm ins bld
  | Opcode.TM | Opcode.TMY ->
    testMaskStorage ins bld
  | Opcode.TMLL ->
    testMaskReg ins bld 0
  | Opcode.TMLH ->
    testMaskReg ins bld 16
  | Opcode.TMHL ->
    testMaskReg ins bld 32
  | Opcode.TMHH ->
    testMaskReg ins bld 48
  | Opcode.CS | Opcode.CSY ->
    compareAndSwap ins bld WSize
  | Opcode.CSG ->
    compareAndSwap ins bld GRSize
  | _ ->
    raise ParsingFailureException

/// The transfers of control.
let private liftBranch ins bld opcode =
  match opcode with
  | Opcode.BRC | Opcode.BRCL ->
    branchRelative ins bld
  | Opcode.BC ->
    branchOnCondition ins bld
  | Opcode.BCR ->
    branchOnConditionReg ins bld
  | Opcode.BRAS | Opcode.BRASL ->
    branchAndSaveRel ins bld
  | Opcode.BAS | Opcode.BAL ->
    branchAndSave ins bld
  | Opcode.BASR | Opcode.BALR | Opcode.BASSM ->
    branchAndSaveReg ins bld
  | Opcode.BCT ->
    branchOnCount ins bld WSize
  | Opcode.BCTG ->
    branchOnCount ins bld GRSize
  | Opcode.BCTR ->
    branchOnCountReg ins bld WSize
  | Opcode.BCTGR ->
    branchOnCountReg ins bld GRSize
  | Opcode.BRCT ->
    branchOnCountRel ins bld WSize
  | Opcode.BRCTG ->
    branchOnCountRel ins bld GRSize
  | Opcode.BXH ->
    branchOnIndex ins bld WSize true
  | Opcode.BXHG ->
    branchOnIndex ins bld GRSize true
  | Opcode.BXLE ->
    branchOnIndex ins bld WSize false
  | Opcode.BXLEG ->
    branchOnIndex ins bld GRSize false
  | Opcode.BRXH ->
    branchOnIndexRel ins bld WSize true
  | Opcode.BRXHG ->
    branchOnIndexRel ins bld GRSize true
  | Opcode.BRXLE ->
    branchOnIndexRel ins bld WSize false
  | Opcode.BRXLG ->
    branchOnIndexRel ins bld GRSize false
  | Opcode.CRJ | Opcode.CIJ ->
    compareAndBranchRel ins bld WSize true
  | Opcode.CGRJ | Opcode.CGIJ ->
    compareAndBranchRel ins bld GRSize true
  | Opcode.CLRJ | Opcode.CLIJ ->
    compareAndBranchRel ins bld WSize false
  | Opcode.CLGRJ | Opcode.CLGIJ ->
    compareAndBranchRel ins bld GRSize false
  | Opcode.CRB | Opcode.CIB ->
    compareAndBranch ins bld WSize true
  | Opcode.CGRB | Opcode.CGIB ->
    compareAndBranch ins bld GRSize true
  | Opcode.CLRB | Opcode.CLIB ->
    compareAndBranch ins bld WSize false
  | Opcode.CLGRB | Opcode.CLGIB ->
    compareAndBranch ins bld GRSize false
  | Opcode.CRT | Opcode.CIT ->
    compareAndTrap ins bld WSize true
  | Opcode.CGRT | Opcode.CGIT ->
    compareAndTrap ins bld GRSize true
  | Opcode.CLRT | Opcode.CLFIT ->
    compareAndTrap ins bld WSize false
  | Opcode.CLGRT | Opcode.CLGIT ->
    compareAndTrap ins bld GRSize false
  | _ ->
    raise ParsingFailureException

/// The floating-point operations this lifter models, which are the short and
/// the long binary formats; the extended one is left out.
let private liftFloat ins bld opcode =
  match opcode with
  | Opcode.LDR | Opcode.LD | Opcode.LDY ->
    FloatLifter.move ins bld 64<rt>
  | Opcode.LER | Opcode.LE | Opcode.LEY ->
    FloatLifter.move ins bld 32<rt>
  | Opcode.LZDR ->
    FloatLifter.loadZero ins bld 64<rt>
  | Opcode.LZER ->
    FloatLifter.loadZero ins bld 32<rt>
  | Opcode.LDGR | Opcode.LGDR ->
    regCopy ins bld
  | Opcode.STD | Opcode.STDY ->
    store ins bld 64<rt>
  | Opcode.STE | Opcode.STEY ->
    storeHigh ins bld
  | Opcode.ADBR | Opcode.ADB ->
    FloatLifter.arith ins bld 64<rt> AST.fadd true
  | Opcode.AEBR | Opcode.AEB ->
    FloatLifter.arith ins bld 32<rt> AST.fadd true
  | Opcode.SDBR | Opcode.SDB ->
    FloatLifter.arith ins bld 64<rt> AST.fsub true
  | Opcode.SEBR | Opcode.SEB ->
    FloatLifter.arith ins bld 32<rt> AST.fsub true
  | Opcode.MDBR | Opcode.MDB ->
    FloatLifter.arith ins bld 64<rt> AST.fmul false
  | Opcode.MEEBR | Opcode.MEEB ->
    FloatLifter.arith ins bld 32<rt> AST.fmul false
  | Opcode.DDBR | Opcode.DDB ->
    FloatLifter.arith ins bld 64<rt> AST.fdiv false
  | Opcode.DEBR | Opcode.DEB ->
    FloatLifter.arith ins bld 32<rt> AST.fdiv false
  | Opcode.CDBR | Opcode.CDB | Opcode.KDBR | Opcode.KDB ->
    FloatLifter.compare ins bld 64<rt>
  | Opcode.CEBR | Opcode.CEB | Opcode.KEBR | Opcode.KEB ->
    FloatLifter.compare ins bld 32<rt>
  | Opcode.LTDBR ->
    FloatLifter.loadTest ins bld 64<rt>
  | Opcode.LTEBR ->
    FloatLifter.loadTest ins bld 32<rt>
  | Opcode.LCDBR ->
    FloatLifter.loadSign ins bld 64<rt> (<+>)
  | Opcode.LCEBR ->
    FloatLifter.loadSign ins bld 32<rt> (<+>)
  | Opcode.LPDBR | Opcode.LPDR ->
    FloatLifter.loadSign ins bld 64<rt> (fun v s -> v .& AST.not s)
  | Opcode.LPEBR ->
    FloatLifter.loadSign ins bld 32<rt> (fun v s -> v .& AST.not s)
  | Opcode.LNDBR ->
    FloatLifter.loadSign ins bld 64<rt> (.|)
  | Opcode.LNEBR ->
    FloatLifter.loadSign ins bld 32<rt> (.|)
  | Opcode.SQDBR | Opcode.SQDB ->
    FloatLifter.sqrt ins bld 64<rt>
  | Opcode.SQEBR | Opcode.SQEB ->
    FloatLifter.sqrt ins bld 32<rt>
  | Opcode.CPSDR ->
    FloatLifter.copySign ins bld
  | Opcode.LDEBR | Opcode.LDEB ->
    FloatLifter.convertFormat ins bld 32<rt> 64<rt>
  | Opcode.LEDBR | Opcode.LEDBRA ->
    FloatLifter.convertFormat ins bld 64<rt> 32<rt>
  | Opcode.CEFBR | Opcode.CEFBRA ->
    FloatLifter.fromInt ins bld 32<rt> WSize true
  | Opcode.CDFBR | Opcode.CDFBRA ->
    FloatLifter.fromInt ins bld 64<rt> WSize true
  | Opcode.CEGBR | Opcode.CEGBRA ->
    FloatLifter.fromInt ins bld 32<rt> GRSize true
  | Opcode.CDGBR | Opcode.CDGBRA ->
    FloatLifter.fromInt ins bld 64<rt> GRSize true
  | Opcode.CELFBR ->
    FloatLifter.fromInt ins bld 32<rt> WSize false
  | Opcode.CDLFBR ->
    FloatLifter.fromInt ins bld 64<rt> WSize false
  | Opcode.CELGBR ->
    FloatLifter.fromInt ins bld 32<rt> GRSize false
  | Opcode.CDLGBR ->
    FloatLifter.fromInt ins bld 64<rt> GRSize false
  | Opcode.CFEBR | Opcode.CFEBRA | Opcode.CLFEBR ->
    FloatLifter.toInt ins bld 32<rt> WSize
  | Opcode.CFDBR | Opcode.CFDBRA | Opcode.CLFDBR ->
    FloatLifter.toInt ins bld 64<rt> WSize
  | Opcode.CGEBR | Opcode.CGEBRA | Opcode.CLGEBR ->
    FloatLifter.toInt ins bld 32<rt> GRSize
  | Opcode.CGDBR | Opcode.CGDBRA | Opcode.CLGDBR ->
    FloatLifter.toInt ins bld 64<rt> GRSize
  | Opcode.FIDBR | Opcode.FIDBRA ->
    FloatLifter.roundToInt ins bld 64<rt>
  | Opcode.FIEBR | Opcode.FIEBRA ->
    FloatLifter.roundToInt ins bld 32<rt>
  | Opcode.LCDFR ->
    FloatLifter.loadSignQuiet ins bld (<+>)
  | Opcode.LPDFR ->
    FloatLifter.loadSignQuiet ins bld (fun v s -> v .& AST.not s)
  | Opcode.LNDFR ->
    FloatLifter.loadSignQuiet ins bld (.|)
  | Opcode.TCDB ->
    FloatLifter.testDataClass ins bld 64<rt>
  | Opcode.TCEB ->
    FloatLifter.testDataClass ins bld 32<rt>
  | Opcode.MADB | Opcode.MADBR ->
    FloatLifter.mulAdd ins bld 64<rt> false
  | Opcode.MAEB | Opcode.MAEBR ->
    FloatLifter.mulAdd ins bld 32<rt> false
  | Opcode.MSDB | Opcode.MSDBR ->
    FloatLifter.mulAdd ins bld 64<rt> true
  | Opcode.MSEB | Opcode.MSEBR ->
    FloatLifter.mulAdd ins bld 32<rt> true
  | Opcode.MDEB | Opcode.MDEBR ->
    FloatLifter.mulWiden ins bld
  | Opcode.DIDBR ->
    FloatLifter.divideToInteger ins bld 64<rt>
  | Opcode.DIEBR ->
    FloatLifter.divideToInteger ins bld 32<rt>
  | Opcode.SRNM ->
    FloatLifter.setRoundingMode ins bld 2
  | Opcode.SRNMB ->
    FloatLifter.setRoundingMode ins bld 3
  | Opcode.SRNMT ->
    FloatLifter.setRoundingMode ins bld 3
  | Opcode.LFAS ->
    FloatLifter.loadFpc ins bld
  | Opcode.SFASR ->
    FloatLifter.setFpc ins bld
  | Opcode.SFPC ->
    FloatLifter.setFpc ins bld
  | Opcode.EFPC ->
    FloatLifter.extractFpc ins bld
  | Opcode.LFPC ->
    FloatLifter.loadFpc ins bld
  | Opcode.STFPC ->
    FloatLifter.storeFpc ins bld
  | _ ->
    raise ParsingFailureException

/// The high-word facility, which addresses bits 0 to 31 of a general register
/// as a register of its own.
let private liftHighWord ins bld opcode =
  match opcode with
  | Opcode.LFH ->
    HighWordLifter.load ins bld WSize same
  | Opcode.LBH ->
    HighWordLifter.load ins bld 8<rt> sextTo
  | Opcode.LHH ->
    HighWordLifter.load ins bld 16<rt> sextTo
  | Opcode.LLCH ->
    HighWordLifter.load ins bld 8<rt> zextTo
  | Opcode.LLHH ->
    HighWordLifter.load ins bld 16<rt> zextTo
  | Opcode.LFHAT ->
    HighWordLifter.loadAndTrap ins bld
  | Opcode.STFH ->
    HighWordLifter.store ins bld WSize
  | Opcode.STCH ->
    HighWordLifter.store ins bld 8<rt>
  | Opcode.STHH ->
    HighWordLifter.store ins bld 16<rt>
  | Opcode.AHHHR ->
    HighWordLifter.alu3 ins bld false (.+) ccAdd
  | Opcode.AHHLR ->
    HighWordLifter.alu3 ins bld true (.+) ccAdd
  | Opcode.SHHHR ->
    HighWordLifter.alu3 ins bld false (.-) ccSub
  | Opcode.SHHLR ->
    HighWordLifter.alu3 ins bld true (.-) ccSub
  | Opcode.ALHHHR ->
    HighWordLifter.alu3 ins bld false (.+) ccAddL
  | Opcode.ALHHLR ->
    HighWordLifter.alu3 ins bld true (.+) ccAddL
  | Opcode.SLHHHR ->
    HighWordLifter.alu3 ins bld false (.-) ccSubL
  | Opcode.SLHHLR ->
    HighWordLifter.alu3 ins bld true (.-) ccSubL
  | Opcode.AIH ->
    HighWordLifter.addImm ins bld ccAdd
  | Opcode.ALSIH ->
    HighWordLifter.addImm ins bld ccAddL
  | Opcode.ALSIHN ->
    HighWordLifter.addImm ins bld ccNone
  | Opcode.CIH ->
    HighWordLifter.compare ins bld true HighWordLifter.wordOf
  | Opcode.CLIH ->
    HighWordLifter.compare ins bld false HighWordLifter.wordOf
  | Opcode.CHF ->
    HighWordLifter.compare ins bld true HighWordLifter.wordOf
  | Opcode.CLHF ->
    HighWordLifter.compare ins bld false HighWordLifter.wordOf
  | Opcode.CHHR ->
    HighWordLifter.compare ins bld true HighWordLifter.highOf
  | Opcode.CLHHR ->
    HighWordLifter.compare ins bld false HighWordLifter.highOf
  | Opcode.CHLR ->
    HighWordLifter.compare ins bld true HighWordLifter.lowOf
  | Opcode.CLHLR ->
    HighWordLifter.compare ins bld false HighWordLifter.lowOf
  | Opcode.BRCTH ->
    HighWordLifter.branchOnCount ins bld
  | Opcode.LOCFHR ->
    HighWordLifter.loadOnCondition ins bld HighWordLifter.highOf
  | Opcode.LOCFH ->
    HighWordLifter.loadOnCondition ins bld HighWordLifter.wordOf
  | Opcode.LOCHHI ->
    HighWordLifter.loadOnCondition ins bld HighWordLifter.wordOf
  | Opcode.STOCFH ->
    HighWordLifter.storeOnCondition ins bld
  | Opcode.LMH ->
    HighWordLifter.loadMultiple ins bld
  | Opcode.STMH ->
    HighWordLifter.storeMultiple ins bld
  | Opcode.STCMH ->
    HighWordLifter.storeUnderMask ins bld
  | Opcode.CLMH ->
    HighWordLifter.compareUnderMask ins bld
  | Opcode.RISBHG ->
    HighWordLifter.rotateInsert ins bld true
  | Opcode.RISBLG ->
    HighWordLifter.rotateInsert ins bld false
  | _ ->
    raise ParsingFailureException

/// The register-pair operations, the long moves and comparisons, the
/// translations, and the odds and ends that belong to no other group.
let private liftWide ins bld opcode =
  match opcode with
  | Opcode.M | Opcode.MR | Opcode.MFY -> mulPair ins bld WSize WSize
  | Opcode.MG -> mulPair ins bld GRSize GRSize
  | Opcode.MGRK -> mulPair3 ins bld GRSize
  | Opcode.MGH -> mul ins bld GRSize 16<rt> sextTo
  | Opcode.MSC -> mulCC ins bld WSize WSize same
  | Opcode.MSGC -> mulCC ins bld GRSize GRSize same
  | Opcode.D | Opcode.DR -> divPair ins bld WSize WSize
  | Opcode.SGH -> alu2Ext ins bld GRSize 16<rt> sextTo (.-) ccSub
  | Opcode.ALC -> addCarry ins bld WSize
  | Opcode.ALCG -> addCarry ins bld GRSize
  | Opcode.SLB -> subBorrow ins bld WSize
  | Opcode.SLBG -> subBorrow ins bld GRSize
  | Opcode.ALSI -> addLogicalToStorage ins bld WSize
  | Opcode.ALGSI -> addLogicalToStorage ins bld GRSize
  | Opcode.SLDL -> shiftDouble ins bld (<<) false
  | Opcode.SRDL -> shiftDouble ins bld (>>) false
  | Opcode.SLDA -> shiftDouble ins bld (<<) true
  | Opcode.SRDA -> shiftDouble ins bld (?>>) true
  | Opcode.CDS | Opcode.CDSY -> compareDoubleAndSwap ins bld WSize
  | Opcode.CDSG -> compareDoubleAndSwap ins bld GRSize
  | Opcode.LPD -> loadPairDisjoint ins bld WSize
  | Opcode.LPDG -> loadPairDisjoint ins bld GRSize
  | Opcode.LPQ -> quadPair ins bld true
  | Opcode.STPQ -> quadPair ins bld false
  | Opcode.LAT -> loadAndTrap ins bld WSize WSize same
  | Opcode.LGAT -> loadAndTrap ins bld GRSize GRSize same
  | Opcode.LLGFAT -> loadAndTrap ins bld GRSize WSize zextTo
  | Opcode.LLGTAT -> loadAndTrap ins bld GRSize WSize zextTo
  | Opcode.LZRF -> loadZeroRightmost ins bld WSize WSize same
  | Opcode.LZRG -> loadZeroRightmost ins bld GRSize GRSize same
  | Opcode.LLZRGF -> loadZeroRightmost ins bld GRSize WSize zextTo
  | Opcode.LAE | Opcode.LAEY -> loadAddressExtended ins bld
  | Opcode.LAM | Opcode.LAMY -> accessMultiple ins bld true
  | Opcode.STAM | Opcode.STAMY -> accessMultiple ins bld false
  | Opcode.CPYA -> copyAccess ins bld
  | Opcode.TAR -> testAccess ins bld
  | Opcode.TAM -> testAddressingMode ins bld
  | Opcode.TS -> testAndSet ins bld
  | Opcode.CKSM -> checksum ins bld
  | Opcode.CLT -> compareTrapStorage ins bld WSize
  | Opcode.CLGT -> compareTrapStorage ins bld GRSize
  | Opcode.BIC -> branchIndirect ins bld
  | Opcode.MVPG -> movePage ins bld
  | Opcode.NTSTG -> store ins bld GRSize
  | Opcode.MVN -> ssNibble ins bld true
  | Opcode.MVZ -> ssNibble ins bld false
  | Opcode.MVCIN -> moveInverse ins bld
  | Opcode.MVCRL -> moveRightToLeft ins bld
  | Opcode.MVO -> moveWithOffset ins bld
  | Opcode.MVCL -> moveLong ins bld
  | Opcode.CLCL -> compareLong ins bld
  | Opcode.MVCLE -> moveLongExtended ins bld 1
  | Opcode.MVCLU -> moveLongExtended ins bld 2
  | Opcode.CLCLE -> compareLongExtended ins bld 1
  | Opcode.CLCLU -> compareLongExtended ins bld 2
  | Opcode.TR -> translate ins bld
  | Opcode.TRT -> translateAndTest ins bld false
  | Opcode.TRTR -> translateAndTest ins bld true
  | Opcode.TRE -> translateExtended ins bld
  | Opcode.TROO -> translateUnits ins bld 8<rt> 8<rt>
  | Opcode.TROT -> translateUnits ins bld 8<rt> 16<rt>
  | Opcode.TRTO -> translateUnits ins bld 16<rt> 8<rt>
  | Opcode.TRTT -> translateUnits ins bld 16<rt> 16<rt>
  | Opcode.TRTE -> translateTestExtended ins bld false
  | Opcode.TRTRE -> translateTestExtended ins bld true
  | Opcode.SRSTU -> searchStringUnicode ins bld
  | Opcode.PTFF -> ptff ins bld
  | Opcode.EPSW -> extractPsw ins bld
  | Opcode.LCBB -> loadCountToBoundary ins bld
  | Opcode.STCKE -> storeClockExtended ins bld
  | Opcode.LMD -> loadMultipleDisjoint ins bld
  | Opcode.CUSE -> compareUntilEqual ins bld
  | Opcode.SAM24 -> setAddressMode ins bld 24
  | Opcode.SAM31 -> setAddressMode ins bld 31
  | Opcode.SAM64 -> setAddressMode ins bld 64
  | Opcode.NIAI | Opcode.MC -> nop ins bld
  | Opcode.TABORT -> illegal ins bld
  | _ -> raise ParsingFailureException

/// Everything that belongs to none of the groups above: the entry into the
/// supervisor, the reads of state a program cannot otherwise see, the string
/// operations, the atomic read-modify-writes, and the instructions an emulator
/// of user code has nothing to do for.
let private liftOther ins bld opcode =
  match opcode with
  | Opcode.SVC ->
    svc ins bld
  | Opcode.EX ->
    execute ins bld
  | Opcode.EXRL ->
    executeRel ins bld
  | Opcode.IPM ->
    ipm ins bld
  | Opcode.SPM ->
    spm ins bld
  | Opcode.EAR ->
    ear ins bld
  | Opcode.SAR ->
    sar ins bld
  | Opcode.SRST ->
    srst ins bld
  | Opcode.MVST ->
    mvst ins bld
  | Opcode.CLST ->
    clst ins bld
  | Opcode.LAA | Opcode.LAAL ->
    loadAndOp ins bld WSize (.+)
  | Opcode.LAAG | Opcode.LAALG ->
    loadAndOp ins bld GRSize (.+)
  | Opcode.LAN ->
    loadAndOp ins bld WSize (.&)
  | Opcode.LANG ->
    loadAndOp ins bld GRSize (.&)
  | Opcode.LAO ->
    loadAndOp ins bld WSize (.|)
  | Opcode.LAOG ->
    loadAndOp ins bld GRSize (.|)
  | Opcode.LAX ->
    loadAndOp ins bld WSize (<+>)
  | Opcode.LAXG ->
    loadAndOp ins bld GRSize (<+>)
  | Opcode.ECAG ->
    ecag ins bld
  | Opcode.TBEGIN | Opcode.TBEGINC ->
    tbegin ins bld
  | Opcode.TEND ->
    tend ins bld
  | Opcode.ETND ->
    etnd ins bld
  | Opcode.STCK | Opcode.STCKF ->
    storeClock ins bld
  | Opcode.STFLE ->
    stfle ins bld
  | Opcode.BCR ->
    branchOnConditionReg ins bld
  (* A prefetch, a branch-prediction hint, and a performance-assist hint move
     nothing a program can see, and the serializing instructions only order
     what is around them, which one thread at a time already is. *)
  | Opcode.PFD | Opcode.PFDRL | Opcode.BPP | Opcode.BPRP | Opcode.PPA ->
    nop ins bld
  | _ ->
    raise ParsingFailureException

/// The extended binary floating-point format, whose 128 bits live in a pair of
/// registers. Everything that is a matter of moving or reading the bits is done
/// exactly; the four arithmetic operations and the square root, which would
/// need a 112-bit fraction the IR has no type for, are carried out in double
/// precision instead and so answer to 53 bits rather than 113.
let private liftExtFloat ins bld opcode =
  match opcode with
  | Opcode.LXR ->
    FloatLifter.extLoadSign ins bld (fun v _ -> v) false
  | Opcode.LZXR ->
    FloatLifter.extLoadZero ins bld
  | Opcode.LTXBR ->
    FloatLifter.extLoadSign ins bld (fun v _ -> v) true
  | Opcode.LCXBR ->
    FloatLifter.extLoadSign ins bld (<+>) true
  | Opcode.LPXBR ->
    FloatLifter.extLoadSign ins bld (fun v s -> v .& AST.not s) true
  | Opcode.LNXBR ->
    FloatLifter.extLoadSign ins bld (fun v s -> v .| s) true
  | Opcode.CXBR | Opcode.KXBR ->
    FloatLifter.extCompare ins bld
  | Opcode.TCXB ->
    FloatLifter.extTestDataClass ins bld
  | Opcode.LXDBR | Opcode.LXDB ->
    FloatLifter.extFromNarrow ins bld 64<rt>
  | Opcode.LXEBR | Opcode.LXEB ->
    FloatLifter.extFromNarrow ins bld 32<rt>
  | Opcode.LDXBR | Opcode.LDXBRA ->
    FloatLifter.extToNarrow ins bld 64<rt>
  | Opcode.LEXBR | Opcode.LEXBRA ->
    FloatLifter.extToNarrow ins bld 32<rt>
  | Opcode.CXFBR | Opcode.CXFBRA ->
    FloatLifter.extFromInt ins bld WSize true
  | Opcode.CXGBR | Opcode.CXGBRA ->
    FloatLifter.extFromInt ins bld GRSize true
  | Opcode.CXLFBR ->
    FloatLifter.extFromInt ins bld WSize false
  | Opcode.CXLGBR ->
    FloatLifter.extFromInt ins bld GRSize false
  | Opcode.CFXBR | Opcode.CFXBRA | Opcode.CLFXBR ->
    FloatLifter.extToInt ins bld WSize
  | Opcode.CGXBR | Opcode.CGXBRA | Opcode.CLGXBR ->
    FloatLifter.extToInt ins bld GRSize
  | Opcode.AXBR ->
    FloatLifter.extArith ins bld AST.fadd true
  | Opcode.SXBR ->
    FloatLifter.extArith ins bld AST.fsub true
  | Opcode.MXBR ->
    FloatLifter.extArith ins bld AST.fmul false
  | Opcode.DXBR ->
    FloatLifter.extArith ins bld AST.fdiv false
  | Opcode.SQXBR ->
    FloatLifter.extSqrt ins bld
  | Opcode.MXDBR | Opcode.MXDB ->
    FloatLifter.extMulLong ins bld
  | Opcode.FIXBR | Opcode.FIXBRA ->
    FloatLifter.extRoundToInt ins bld
  | _ ->
    unsupported ins bld

/// The instructions this lifter models, grouped by what they do so that the
/// dispatch stays a few wide matches rather than one enormous one.
let private groupOf opcode =
  match opcode with
  | Opcode.LR | Opcode.LGR | Opcode.LGFR | Opcode.LLGFR | Opcode.LBR
  | Opcode.LGBR | Opcode.LHR | Opcode.LGHR | Opcode.LLCR | Opcode.LLGCR
  | Opcode.LLHR | Opcode.LLGHR | Opcode.L | Opcode.LY | Opcode.LG
  | Opcode.LGF | Opcode.LLGF | Opcode.LH | Opcode.LHY | Opcode.LGH
  | Opcode.LLH | Opcode.LLGH | Opcode.LB | Opcode.LGB | Opcode.LLC
  | Opcode.LLGC | Opcode.LHI | Opcode.LGHI | Opcode.LGFI | Opcode.LT
  | Opcode.LTR | Opcode.LTG | Opcode.LTGR | Opcode.LTGF | Opcode.LTGFR
  | Opcode.LRL | Opcode.LGRL | Opcode.LGFRL | Opcode.LLGFRL | Opcode.LHRL
  | Opcode.LGHRL | Opcode.LLHRL | Opcode.LLGHRL | Opcode.LLGT
  | Opcode.LLGTR | Opcode.LA | Opcode.LAY | Opcode.LARL | Opcode.LM
  | Opcode.LMY | Opcode.LMG | Opcode.LOC | Opcode.LOCR | Opcode.LOCG
  | Opcode.LOCGR | Opcode.LOCHI | Opcode.LOCGHI | Opcode.IILF | Opcode.IIHF
  | Opcode.IILL | Opcode.IILH | Opcode.IIHL | Opcode.IIHH | Opcode.LLILF
  | Opcode.LLIHF | Opcode.LLILL | Opcode.LLILH | Opcode.LLIHL | Opcode.LLIHH
  | Opcode.IC | Opcode.ICY | Opcode.ICM | Opcode.ICMY | Opcode.ICMH
  | Opcode.LRVR | Opcode.LRVGR | Opcode.LRV | Opcode.LRVG
  | Opcode.LRVH -> 0
  | Opcode.ST | Opcode.STY | Opcode.STG | Opcode.STH | Opcode.STHY
  | Opcode.STC | Opcode.STCY | Opcode.STRL | Opcode.STGRL | Opcode.STHRL
  | Opcode.STM | Opcode.STMY | Opcode.STMG | Opcode.STOC | Opcode.STOCG
  | Opcode.STCM | Opcode.STCMY | Opcode.MVI | Opcode.MVIY | Opcode.MVHHI
  | Opcode.MVHI | Opcode.MVGHI | Opcode.MVC | Opcode.NC | Opcode.OC
  | Opcode.XC | Opcode.STRV | Opcode.STRVG | Opcode.STRVH -> 1
  | Opcode.AR | Opcode.A | Opcode.AY | Opcode.AHI | Opcode.AFI | Opcode.AGR
  | Opcode.AG | Opcode.AGHI | Opcode.AGFI | Opcode.AH | Opcode.AHY
  | Opcode.AGH | Opcode.AGF | Opcode.AGFR | Opcode.ARK | Opcode.AGRK
  | Opcode.AHIK | Opcode.AGHIK | Opcode.ASI | Opcode.AGSI | Opcode.ALR
  | Opcode.AL | Opcode.ALY | Opcode.ALFI | Opcode.ALGR | Opcode.ALG
  | Opcode.ALGFI | Opcode.ALGF | Opcode.ALGFR | Opcode.ALRK | Opcode.ALGRK
  | Opcode.ALHSIK | Opcode.ALGHSIK | Opcode.ALCR | Opcode.ALCGR | Opcode.SR
  | Opcode.S | Opcode.SY | Opcode.SGR | Opcode.SG | Opcode.SH | Opcode.SHY
  | Opcode.SGF | Opcode.SGFR | Opcode.SRK | Opcode.SGRK | Opcode.SLR
  | Opcode.SL | Opcode.SLY | Opcode.SLFI | Opcode.SLGR | Opcode.SLG
  | Opcode.SLGFI | Opcode.SLGF | Opcode.SLGFR | Opcode.SLRK | Opcode.SLGRK
  | Opcode.SLBR | Opcode.SLBGR | Opcode.LCR | Opcode.LCGR | Opcode.LCGFR
  | Opcode.LPR | Opcode.LPGR | Opcode.LPGFR | Opcode.LNR | Opcode.LNGR
  | Opcode.LNGFR | Opcode.MSR | Opcode.MS | Opcode.MSY | Opcode.MSFI
  | Opcode.MHI | Opcode.MSGR | Opcode.MSG | Opcode.MSGFI | Opcode.MGHI
  | Opcode.MSGF | Opcode.MSGFR | Opcode.MH | Opcode.MHY | Opcode.MSRKC
  | Opcode.MSGRKC | Opcode.MLR | Opcode.ML | Opcode.MLGR | Opcode.MLG
  | Opcode.DLR | Opcode.DL | Opcode.DLGR | Opcode.DLG | Opcode.DSGR
  | Opcode.DSG | Opcode.DSGFR | Opcode.DSGF | Opcode.FLOGR
  | Opcode.POPCNT -> 2
  | Opcode.NR | Opcode.N | Opcode.NY | Opcode.NGR | Opcode.NG | Opcode.NRK
  | Opcode.NGRK | Opcode.OR | Opcode.O | Opcode.OY | Opcode.OGR | Opcode.OG
  | Opcode.ORK | Opcode.OGRK | Opcode.XR | Opcode.X | Opcode.XY | Opcode.XGR
  | Opcode.XG | Opcode.XRK | Opcode.XGRK | Opcode.NILF | Opcode.NIHF
  | Opcode.NILL | Opcode.NILH | Opcode.NIHL | Opcode.NIHH | Opcode.OILF
  | Opcode.OIHF | Opcode.OILL | Opcode.OILH | Opcode.OIHL | Opcode.OIHH
  | Opcode.XILF | Opcode.XIHF | Opcode.NI | Opcode.NIY | Opcode.OI
  | Opcode.OIY | Opcode.XI | Opcode.XIY -> 3
  | Opcode.SLL | Opcode.SRL | Opcode.SLA | Opcode.SRA | Opcode.SLLK
  | Opcode.SRLK | Opcode.SLAK | Opcode.SRAK | Opcode.SLLG | Opcode.SRLG
  | Opcode.SLAG | Opcode.SRAG | Opcode.RLL | Opcode.RLLG | Opcode.RISBG
  | Opcode.RISBGN | Opcode.ROSBG | Opcode.RXSBG | Opcode.RNSBG -> 4
  | Opcode.CR | Opcode.C | Opcode.CY | Opcode.CHI | Opcode.CFI | Opcode.CGR
  | Opcode.CG | Opcode.CGHI | Opcode.CGFI | Opcode.CH | Opcode.CHY
  | Opcode.CGH | Opcode.CGF | Opcode.CGFR | Opcode.CLR | Opcode.CL
  | Opcode.CLY | Opcode.CLFI | Opcode.CLGR | Opcode.CLG | Opcode.CLGFI
  | Opcode.CLGF | Opcode.CLGFR | Opcode.CRL | Opcode.CGRL | Opcode.CGFRL
  | Opcode.CHRL | Opcode.CGHRL | Opcode.CLRL | Opcode.CLGRL | Opcode.CLGFRL
  | Opcode.CLHRL | Opcode.CLGHRL | Opcode.CLI | Opcode.CLIY | Opcode.CHHSI
  | Opcode.CHSI | Opcode.CGHSI | Opcode.CLHHSI | Opcode.CLFHSI
  | Opcode.CLGHSI | Opcode.CLC | Opcode.CLM | Opcode.CLMY | Opcode.TM
  | Opcode.TMY | Opcode.TMLL | Opcode.TMLH | Opcode.TMHL | Opcode.TMHH
  | Opcode.CS | Opcode.CSY | Opcode.CSG -> 5
  | Opcode.BRC | Opcode.BRCL | Opcode.BC | Opcode.BRAS
  | Opcode.BRASL | Opcode.BAS | Opcode.BAL | Opcode.BASR | Opcode.BALR
  | Opcode.BASSM | Opcode.BCT | Opcode.BCTG | Opcode.BCTR | Opcode.BCTGR
  | Opcode.BRCT | Opcode.BRCTG | Opcode.BXH | Opcode.BXHG | Opcode.BXLE
  | Opcode.BXLEG | Opcode.BRXH | Opcode.BRXHG | Opcode.BRXLE | Opcode.BRXLG
  | Opcode.CRJ | Opcode.CIJ | Opcode.CGRJ | Opcode.CGIJ | Opcode.CLRJ
  | Opcode.CLIJ | Opcode.CLGRJ | Opcode.CLGIJ | Opcode.CRB | Opcode.CIB
  | Opcode.CGRB | Opcode.CGIB | Opcode.CLRB | Opcode.CLIB | Opcode.CLGRB
  | Opcode.CLGIB | Opcode.CRT | Opcode.CIT | Opcode.CGRT | Opcode.CGIT
  | Opcode.CLRT | Opcode.CLFIT | Opcode.CLGRT | Opcode.CLGIT -> 6
  | Opcode.LDR | Opcode.LER | Opcode.LD | Opcode.LDY | Opcode.LE
  | Opcode.LEY | Opcode.LZDR | Opcode.LZER | Opcode.LDGR | Opcode.LGDR
  | Opcode.STD | Opcode.STDY | Opcode.STE | Opcode.STEY | Opcode.ADBR
  | Opcode.ADB | Opcode.AEBR | Opcode.AEB | Opcode.SDBR | Opcode.SDB
  | Opcode.SEBR | Opcode.SEB | Opcode.MDBR | Opcode.MDB | Opcode.MEEBR
  | Opcode.MEEB | Opcode.DDBR | Opcode.DDB | Opcode.DEBR | Opcode.DEB
  | Opcode.CDBR | Opcode.CDB | Opcode.KDBR | Opcode.KDB | Opcode.CEBR
  | Opcode.CEB | Opcode.KEBR | Opcode.KEB | Opcode.LTDBR | Opcode.LTEBR
  | Opcode.LCDBR | Opcode.LCEBR | Opcode.LPDBR | Opcode.LPEBR
  | Opcode.LNDBR | Opcode.LNEBR | Opcode.LPDR | Opcode.SQDBR | Opcode.SQDB
  | Opcode.SQEBR | Opcode.SQEB | Opcode.CPSDR | Opcode.LDEBR | Opcode.LDEB
  | Opcode.LEDBR | Opcode.LEDBRA | Opcode.CEFBR | Opcode.CEFBRA
  | Opcode.CDFBR | Opcode.CDFBRA | Opcode.CEGBR | Opcode.CEGBRA
  | Opcode.CDGBR | Opcode.CDGBRA | Opcode.CELFBR | Opcode.CDLFBR
  | Opcode.CELGBR | Opcode.CDLGBR | Opcode.CFEBR | Opcode.CFEBRA
  | Opcode.CLFEBR | Opcode.CFDBR | Opcode.CFDBRA | Opcode.CLFDBR
  | Opcode.CGEBR | Opcode.CGEBRA | Opcode.CLGEBR | Opcode.CGDBR
  | Opcode.CGDBRA | Opcode.CLGDBR | Opcode.FIDBR | Opcode.FIDBRA
  | Opcode.FIEBR | Opcode.FIEBRA | Opcode.LCDFR | Opcode.LPDFR
  | Opcode.LNDFR | Opcode.TCDB | Opcode.TCEB | Opcode.SFPC | Opcode.EFPC
  | Opcode.LFPC | Opcode.STFPC -> 7
  | Opcode.SVC | Opcode.EX | Opcode.EXRL | Opcode.IPM | Opcode.SPM
  | Opcode.EAR | Opcode.SAR
  | Opcode.SRST | Opcode.MVST | Opcode.CLST | Opcode.LAA | Opcode.LAAL
  | Opcode.LAAG | Opcode.LAALG | Opcode.LAN | Opcode.LANG | Opcode.LAO
  | Opcode.LAOG | Opcode.LAX | Opcode.LAXG | Opcode.ECAG | Opcode.TBEGIN
  | Opcode.TBEGINC | Opcode.TEND | Opcode.ETND | Opcode.STCK | Opcode.STCKF
  | Opcode.STFLE | Opcode.BCR | Opcode.PFD | Opcode.PFDRL | Opcode.BPP
  | Opcode.BPRP | Opcode.PPA -> 8
  | Opcode.LFH | Opcode.LBH | Opcode.LHH | Opcode.LLCH | Opcode.LLHH
  | Opcode.LFHAT | Opcode.STFH | Opcode.STCH | Opcode.STHH | Opcode.AHHHR
  | Opcode.AHHLR | Opcode.SHHHR | Opcode.SHHLR | Opcode.ALHHHR
  | Opcode.ALHHLR | Opcode.SLHHHR | Opcode.SLHHLR | Opcode.AIH
  | Opcode.ALSIH | Opcode.ALSIHN | Opcode.CIH | Opcode.CLIH | Opcode.CHF
  | Opcode.CLHF | Opcode.CHHR | Opcode.CLHHR | Opcode.CHLR | Opcode.CLHLR
  | Opcode.BRCTH | Opcode.LOCFHR | Opcode.LOCFH | Opcode.LOCHHI
  | Opcode.STOCFH | Opcode.LMH | Opcode.STMH | Opcode.STCMH | Opcode.CLMH
  | Opcode.RISBHG | Opcode.RISBLG -> 9
  | Opcode.M | Opcode.MR | Opcode.MFY | Opcode.MG | Opcode.MGRK | Opcode.MGH
  | Opcode.MSC | Opcode.MSGC | Opcode.D | Opcode.DR | Opcode.SGH
  | Opcode.ALC | Opcode.ALCG | Opcode.SLB | Opcode.SLBG | Opcode.ALSI
  | Opcode.ALGSI | Opcode.SLDL | Opcode.SRDL | Opcode.SLDA | Opcode.SRDA
  | Opcode.CDS | Opcode.CDSY | Opcode.CDSG | Opcode.LPD | Opcode.LPDG
  | Opcode.LPQ | Opcode.STPQ | Opcode.LAT | Opcode.LGAT | Opcode.LLGFAT
  | Opcode.LLGTAT | Opcode.LZRF | Opcode.LZRG | Opcode.LLZRGF | Opcode.LAE
  | Opcode.LAEY | Opcode.LAM | Opcode.LAMY | Opcode.STAM | Opcode.STAMY
  | Opcode.CPYA | Opcode.TAR | Opcode.TAM | Opcode.TS | Opcode.CKSM
  | Opcode.CLT | Opcode.CLGT | Opcode.BIC | Opcode.MVPG | Opcode.NTSTG
  | Opcode.MVN | Opcode.MVZ | Opcode.MVCIN | Opcode.MVCRL | Opcode.MVO
  | Opcode.MVCL | Opcode.CLCL | Opcode.MVCLE | Opcode.MVCLU | Opcode.CLCLE
  | Opcode.CLCLU | Opcode.TR | Opcode.TRT | Opcode.TRTR | Opcode.TRE
  | Opcode.TROO | Opcode.TROT | Opcode.TRTO | Opcode.TRTT | Opcode.TRTE
  | Opcode.TRTRE | Opcode.SRSTU | Opcode.PTFF | Opcode.NIAI | Opcode.MC -> 10
  | Opcode.LPSW | Opcode.LPSWE | Opcode.LPSWEY | Opcode.LCTL | Opcode.LCTLG
  | Opcode.STCTL | Opcode.STCTG | Opcode.SIGP | Opcode.IPTE | Opcode.IDTE
  | Opcode.ISKE | Opcode.IVSK | Opcode.SSKE | Opcode.RRBE | Opcode.RRBM
  | Opcode.PALB | Opcode.PTLB | Opcode.PTI | Opcode.PTF | Opcode.SPX
  | Opcode.STPX | Opcode.SPT | Opcode.STPT | Opcode.SCK | Opcode.SCKC
  | Opcode.STCKC | Opcode.SPKA | Opcode.IPK | Opcode.SAC | Opcode.SACF
  | Opcode.SSM | Opcode.STNSM | Opcode.STOSM | Opcode.LASP | Opcode.LURA
  | Opcode.LURAG | Opcode.STURA | Opcode.STURG | Opcode.LRA | Opcode.LRAG
  | Opcode.LRAY | Opcode.LPTEA | Opcode.TPROT | Opcode.TPEI | Opcode.EPAR
  | Opcode.EPAIR | Opcode.ESAR | Opcode.ESAIR | Opcode.SSAR | Opcode.SSAIR
  | Opcode.ESEA | Opcode.IAC | Opcode.EREG | Opcode.EREGG | Opcode.ESTA
  | Opcode.TRACE | Opcode.TRACG | Opcode.HSCH | Opcode.MSCH | Opcode.SSCH
  | Opcode.STSCH | Opcode.TSCH | Opcode.CSCH | Opcode.RSCH | Opcode.RCHP
  | Opcode.SCHM | Opcode.STCRW | Opcode.STCPS | Opcode.TPI | Opcode.XSCH
  | Opcode.STAP | Opcode.STIDP | Opcode.STSI | Opcode.SCKPF | Opcode.CRDTE
  | Opcode.CSP | Opcode.CSPG | Opcode.PCKMO | Opcode.PFMF | Opcode.STFL
  | Opcode.PGIN | Opcode.PGOUT | Opcode.IRBM | Opcode.LBEAR | Opcode.STBEAR
  | Opcode.MVCK | Opcode.MVCP | Opcode.MVCS | Opcode.MVCOS | Opcode.MVCSK
  | Opcode.MVCDK | Opcode.SAL | Opcode.TB | Opcode.QPACI | Opcode.STGSC
  | Opcode.LGSC | Opcode.PC | Opcode.PT | Opcode.PR | Opcode.BAKR
  | Opcode.BSA | Opcode.BSG | Opcode.RP | Opcode.MSTA | Opcode.TRAP2
  | Opcode.TRAP4 | Opcode.CFC | Opcode.UPT | Opcode.PLO -> 11
  | Opcode.VBPERM | Opcode.VGEF | Opcode.VGEG | Opcode.VGBM | Opcode.VGM
  | Opcode.VL | Opcode.VLR | Opcode.VLREP | Opcode.VLEB | Opcode.VLEH
  | Opcode.VLEF | Opcode.VLEG | Opcode.VLEIB | Opcode.VLEIH | Opcode.VLEIF
  | Opcode.VLEIG | Opcode.VLGV | Opcode.VLLEZ | Opcode.VLM | Opcode.VLRLR
  | Opcode.VLRL | Opcode.VLBB | Opcode.VLVG | Opcode.VLVGP | Opcode.VLL
  | Opcode.VMRH | Opcode.VMRL | Opcode.VPK | Opcode.VPKS | Opcode.VPKLS
  | Opcode.VPERM | Opcode.VPDI | Opcode.VREP | Opcode.VREPI | Opcode.VSCEF
  | Opcode.VSCEG | Opcode.VSEL | Opcode.VSEG | Opcode.VST | Opcode.VSTEB
  | Opcode.VSTEH | Opcode.VSTEF | Opcode.VSTEG | Opcode.VSTM | Opcode.VSTRLR
  | Opcode.VSTRL | Opcode.VSTL | Opcode.VUPH | Opcode.VUPLH | Opcode.VUPL
  | Opcode.VUPLL | Opcode.VA | Opcode.VACC | Opcode.VAC | Opcode.VACCC
  | Opcode.VN | Opcode.VNC | Opcode.VAVG | Opcode.VAVGL | Opcode.VCKSM
  | Opcode.VEC | Opcode.VECL | Opcode.VCEQ | Opcode.VCH | Opcode.VCHL
  | Opcode.VCLZ | Opcode.VCTZ | Opcode.VX | Opcode.VGFM | Opcode.VGFMA
  | Opcode.VLC | Opcode.VLP | Opcode.VMX | Opcode.VMXL | Opcode.VMN
  | Opcode.VMNL | Opcode.VMAL | Opcode.VMAH | Opcode.VMALH | Opcode.VMAE
  | Opcode.VMALE | Opcode.VMAO | Opcode.VMALO | Opcode.VMH | Opcode.VMLH
  | Opcode.VML | Opcode.VME | Opcode.VMLE | Opcode.VMO | Opcode.VMLO
  | Opcode.VMSL | Opcode.VNN | Opcode.VNO | Opcode.VNX | Opcode.VO
  | Opcode.VOC | Opcode.VPOPCT | Opcode.VERLLV | Opcode.VERLL | Opcode.VERIM
  | Opcode.VESLV | Opcode.VESL | Opcode.VESRAV | Opcode.VESRA
  | Opcode.VESRLV | Opcode.VESRL | Opcode.VSL | Opcode.VSLB | Opcode.VSLDB
  | Opcode.VSRA | Opcode.VSRAB | Opcode.VSRL | Opcode.VSRLB | Opcode.VS
  | Opcode.VSCBI | Opcode.VSBI | Opcode.VSBCBI | Opcode.VSUMG | Opcode.VSUMQ
  | Opcode.VSUM | Opcode.VTM | Opcode.VFAE | Opcode.VFEE | Opcode.VFENE
  | Opcode.VISTR | Opcode.VSTRC | Opcode.VFA | Opcode.VFCE | Opcode.VFCH
  | Opcode.VFCHE | Opcode.VFD | Opcode.VFI | Opcode.VFLL | Opcode.VFLR
  | Opcode.VFMAX | Opcode.VFMIN | Opcode.VFM | Opcode.VFMA | Opcode.VFMS
  | Opcode.VFNMA | Opcode.VFNMS | Opcode.VFPSO | Opcode.VFSQ | Opcode.VFS
  | Opcode.VFTCI | Opcode.VAP | Opcode.VCP | Opcode.VCVB | Opcode.VCVBG
  | Opcode.VCVD | Opcode.VCVDG | Opcode.VDP | Opcode.VLIP | Opcode.VMP
  | Opcode.VMSP | Opcode.VPKZ | Opcode.VPSOP | Opcode.VRP | Opcode.VSDP
  | Opcode.VSRP | Opcode.VPKZR | Opcode.VSRPR | Opcode.VSP | Opcode.VSLD
  | Opcode.VSRD | Opcode.VCLZDP | Opcode.VUPKZH | Opcode.VCNF
  | Opcode.VCLFNH | Opcode.VUPKZL | Opcode.VCFN | Opcode.VCLFNL | Opcode.VTP
  | Opcode.VSCHP | Opcode.VCRNF | Opcode.VSCSHP | Opcode.VCSPH
  | Opcode.VSTRS | Opcode.VCLFP | Opcode.VCFPL | Opcode.VCSFP | Opcode.VCFPS
  | Opcode.VLEBRH | Opcode.VLEBRG | Opcode.VLEBRF | Opcode.VLLEBRZ
  | Opcode.VLBRREP | Opcode.VLBR | Opcode.VLER | Opcode.VSTEBRH
  | Opcode.VSTEBRF | Opcode.VSTEBRG | Opcode.VSTBR | Opcode.VSTER
  | Opcode.VUPKZ -> 12
  | Opcode.AD | Opcode.ADR | Opcode.AE | Opcode.AER | Opcode.AU | Opcode.AUR
  | Opcode.AW | Opcode.AWR | Opcode.SD | Opcode.SDR | Opcode.SE | Opcode.SER
  | Opcode.SU | Opcode.SUR | Opcode.SW | Opcode.SWR | Opcode.MD | Opcode.MDR
  | Opcode.MDE | Opcode.MDER | Opcode.MEE | Opcode.MEER | Opcode.MXD
  | Opcode.MXDR | Opcode.MXR | Opcode.MY | Opcode.MYR | Opcode.MYH
  | Opcode.MYHR | Opcode.MYL | Opcode.MYLR | Opcode.MAD | Opcode.MADR
  | Opcode.MAE | Opcode.MAER | Opcode.MAY | Opcode.MAYR | Opcode.MAYH
  | Opcode.MAYHR | Opcode.MAYL | Opcode.MAYLR | Opcode.MSD | Opcode.MSDR
  | Opcode.MSE | Opcode.MSER | Opcode.DD | Opcode.DDR | Opcode.DE
  | Opcode.DER | Opcode.DXR | Opcode.CD | Opcode.CDR | Opcode.CE
  | Opcode.CER | Opcode.HDR | Opcode.HER | Opcode.SQD | Opcode.SQDR
  | Opcode.SQE | Opcode.SQER | Opcode.LDE | Opcode.LDER | Opcode.LEDR
  | Opcode.LTDR | Opcode.LTER | Opcode.LCDR | Opcode.LCER | Opcode.LNDR
  | Opcode.LNER | Opcode.LPER | Opcode.LDXR | Opcode.LEXR | Opcode.LXD
  | Opcode.LXDR | Opcode.LXE | Opcode.LXER | Opcode.LTXR | Opcode.LCXR
  | Opcode.LNXR | Opcode.LPXR | Opcode.CXR | Opcode.FIDR | Opcode.FIER
  | Opcode.FIXR | Opcode.SQXR | Opcode.CEFR | Opcode.CDFR | Opcode.CEGR
  | Opcode.CDGR | Opcode.CFER | Opcode.CFDR | Opcode.CFXR | Opcode.CGER
  | Opcode.CGDR | Opcode.CGXR | Opcode.CXFR | Opcode.CXGR | Opcode.THDR
  | Opcode.THDER | Opcode.TBDR | Opcode.TBEDR | Opcode.AXR | Opcode.SXR -> 13
  | Opcode.LXR | Opcode.LZXR | Opcode.LTXBR | Opcode.LCXBR | Opcode.LPXBR
  | Opcode.LNXBR | Opcode.CXBR | Opcode.KXBR | Opcode.TCXB | Opcode.LXDBR
  | Opcode.LXDB | Opcode.LXEBR | Opcode.LXEB | Opcode.LDXBR | Opcode.LDXBRA
  | Opcode.LEXBR | Opcode.LEXBRA | Opcode.CXFBR | Opcode.CXFBRA
  | Opcode.CXGBR | Opcode.CXGBRA | Opcode.CXLFBR | Opcode.CXLGBR
  | Opcode.CFXBR | Opcode.CFXBRA | Opcode.CLFXBR | Opcode.CGXBR
  | Opcode.CGXBRA | Opcode.CLGXBR | Opcode.AXBR | Opcode.SXBR | Opcode.MXBR
  | Opcode.DXBR | Opcode.SQXBR | Opcode.FIXBR | Opcode.FIXBRA | Opcode.MXDB
  | Opcode.MXDBR -> 14
  | Opcode.MADB | Opcode.MADBR | Opcode.MAEB | Opcode.MAEBR | Opcode.MSDB
  | Opcode.MSDBR | Opcode.MSEB | Opcode.MSEBR | Opcode.MDEB | Opcode.MDEBR
  | Opcode.DIDBR | Opcode.DIEBR | Opcode.SRNM | Opcode.SRNMB | Opcode.SRNMT
  | Opcode.LFAS | Opcode.SFASR -> 7
  | Opcode.EPSW | Opcode.LCBB | Opcode.STCKE | Opcode.LMD | Opcode.CUSE
  | Opcode.SAM24 | Opcode.SAM31 | Opcode.SAM64 | Opcode.TABORT -> 10
  | Opcode.BSM | Opcode.CSST | Opcode.WFC | Opcode.WFK | Opcode.LGG
  | Opcode.LLGFSG | Opcode.STRAG -> 15
  | _ -> -1

/// Translates one instruction into LowUIR. What is left over -- and so raises
/// the not-implemented exception, which ends the block being decoded and, if
/// execution really reaches it, gives the guest the illegal-instruction signal
/// -- is three families this lifter does not model at all: decimal floating
/// point, whose densely-packed-decimal encoding and arithmetic no type the IR
/// has can carry; the packed-decimal arithmetic of the System/360 commercial
/// instruction set; and the message-security, compression, sort, and neural
/// assists, which are engines rather than arithmetic. No compiler targeting
/// Linux emits any of them.
let translate (ins: Instruction) bld =
  let opcode = ins.Opcode
  match groupOf opcode with
  | 0 -> liftLoad ins bld opcode
  | 1 -> liftStore ins bld opcode
  | 2 -> liftArith ins bld opcode
  | 3 -> liftLogic ins bld opcode
  | 4 -> liftShift ins bld opcode
  | 5 -> liftCompare ins bld opcode
  | 6 -> liftBranch ins bld opcode
  | 7 -> liftFloat ins bld opcode
  | 8 -> liftOther ins bld opcode
  | 9 -> liftHighWord ins bld opcode
  | 10 -> liftWide ins bld opcode
  | 11 -> illegal ins bld
  | 12 -> VectorLifter.translate ins bld
  | 13 -> HexFloatLifter.translate ins bld
  | 14 -> liftExtFloat ins bld opcode
  | 15 -> unsupported ins bld
  | _ -> raise (NotImplementedIRException(Disasm.opCodeToString opcode))

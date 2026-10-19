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

/// <summary>
/// Encodes the instructions of the floating-point unit.
///
/// The unit is written in two primary opcodes, one for what it does to a
/// single-precision number and one for what it does to a double-precision one,
/// and the two hold the same instructions under the same extended opcodes; so
/// what differs between a pair of them is which opcode they are written in.
/// </summary>
module internal B2R2.Assembly.PPC.AsmFloat

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// An X-form "frD, frA, frB". Its extended opcode fills the field an A-form
/// keeps a fourth register in, so it is ten bits wide rather than five.
let private fpArith po xo rc ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b ] -> xForm po (fpr d) (fpr a) (fpr b) xo rc
  | _ -> wrongOperands ins

/// An X-form "frD, frB", which is every instruction the unit performs on one
/// number: the roundings, the conversions, and the ones that touch only a
/// number's sign.
let private fpUnary po xo rc ins =
  match ins.Operands with
  | [ Rg d; Rg b ] -> xForm po (fpr d) 0u (fpr b) xo rc
  | _ -> wrongOperands ins

/// An A-form "frD, frA, frC", whose third register is the one a multiply
/// scales by rather than the one the arithmetic reads.
let private fpMultiply po xo rc ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg c ] -> aForm po (fpr d) (fpr a) 0u (fpr c) xo rc
  | _ -> wrongOperands ins

/// An A-form "frD, frA, frC, frB", which is what a multiply and an addition
/// performed as one instruction take.
let private fpMultiplyAdd po xo rc ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg c; Rg b ] -> aForm po (fpr d) (fpr a) (fpr b) (fpr c) xo rc
  | _ -> wrongOperands ins

/// An X-form comparison, whose answer goes into one field of the condition
/// register.
let private fpCompare xo ins =
  match ins.Operands with
  | [ Rg f; Rg a; Rg b ] -> xForm 63u ((crf f) <<< 2) (fpr a) (fpr b) xo 0u
  | _ -> wrongOperands ins

/// mcrfs, which moves one field of the unit's status register into one field
/// of the condition register.
let private fpMoveCondField ins =
  match ins.Operands with
  | [ Rg d; Rg s ] -> xForm 63u ((crf d) <<< 2) ((crf s) <<< 2) 0u 64u 0u
  | _ -> wrongOperands ins

/// mtfsb0 and mtfsb1, which write one bit of the unit's status register.
let private fpSetStatusBit xo rc ins =
  match ins.Operands with
  | [ Im b ] -> xForm 63u (unsigned 5 b) 0u 0u xo rc
  | _ -> wrongOperands ins

/// mtfsfi, which writes one field of that register with what is written
/// beside it, of its low word or, where W is 1, of its high word.
let private fpSetStatusField rc ins =
  match ins.Operands with
  | [ Im f; Im v ] ->
    xForm 63u ((unsigned 3 f) <<< 2) 0u ((unsigned 4 v) <<< 1) 134u rc
  | [ Im f; Im v; Im w ] ->
    let field = (unsigned 3 f) <<< 2
    xForm 63u field (unsigned 1 w) ((unsigned 4 v) <<< 1) 134u rc
  | _ ->
    wrongOperands ins

/// mffs, which reads the whole of that register into a floating-point one.
let private fpReadStatus rc ins =
  match ins.Operands with
  | [ Rg d ] -> xForm 63u (fpr d) 0u 0u 583u rc
  | _ -> wrongOperands ins

/// mffsl, which reads only the bits of it that say what the unit is to do and
/// what it has done, and is told from mffs by the field above the register.
let private fpReadStatusLight ins =
  match ins.Operands with
  | [ Rg d ] -> xForm 63u (fpr d) 24u 0u 583u 0u
  | _ -> wrongOperands ins

/// mffscrn, which reads that register and then puts the rounding mode a
/// floating-point register names in force. What tells it from mffs is again
/// the field above the register, which no register of its own fills.
let private fpReadStatusSetRound ins =
  match ins.Operands with
  | [ Rg d; Rg b ] -> xForm 63u (fpr d) 22u (fpr b) 583u 0u
  | _ -> wrongOperands ins

/// mffscrni, which names the rounding mode it puts in force outright, in the
/// two lowest bits of the field a register would have been named in.
let private fpReadStatusSetRoundImm ins =
  match ins.Operands with
  | [ Rg d; Im m ] -> xForm 63u (fpr d) 23u (unsigned 2 m) 583u 0u
  | _ -> wrongOperands ins

/// mtfsf, whose mask says which fields of that register it writes and lies
/// across the two fields the other forms keep registers in, beside L (the
/// whole register) and W (its high word).
let private fpWriteStatus rc ins =
  let encode m b l w =
    let mask = unsigned 8 m
    let d = ((unsigned 1 l) <<< 4) ||| (mask >>> 4)
    let a = ((mask &&& 0xFu) <<< 1) ||| unsigned 1 w
    word 63u d a (fpr b) ((711u <<< 1) ||| rc)
  match ins.Operands with
  | [ Im m; Rg b ] -> encode m b 0UL 0UL
  | [ Im m; Rg b; Im l; Im w ] -> encode m b l w
  | _ -> wrongOperands ins

/// A D-form load or store of a floating-point register.
let private fpMemory po ins =
  match ins.Operands with
  | [ Rg f; Mem(disp, b) ] -> dForm po (fpr f) (gpr b) (displacement disp)
  | _ -> wrongOperands ins

/// An X-form load or store of one at a distance another register holds.
let private fpIndexed xo ins =
  match ins.Operands with
  | [ Rg f; Rg a; Rg b ] -> xForm 31u (fpr f) (gpr a) (gpr b) xo 0u
  | _ -> wrongOperands ins

/// The arithmetic of the floating-point unit, which is written twice: once for
/// what it does to a single-precision number and once for a double-precision
/// one.
let private arithmeticOf po (divide, sub, add) (sqrt, mul) =
  List.concat
    [ recording (fpArith po) 18u (fst divide) (snd divide)
      recording (fpArith po) 20u (fst sub) (snd sub)
      recording (fpArith po) 21u (fst add) (snd add)
      recording (fpUnary po) 22u (fst sqrt) (snd sqrt)
      recording (fpMultiply po) 25u (fst mul) (snd mul) ]

/// The four instructions that multiply and then add, which differ only in
/// which of the two answers they negate.
let private multiplyAddsOf po (msub, madd) (nmsub, nmadd) =
  List.concat
    [ recording (fpMultiplyAdd po) 28u (fst msub) (snd msub)
      recording (fpMultiplyAdd po) 29u (fst madd) (snd madd)
      recording (fpMultiplyAdd po) 30u (fst nmsub) (snd nmsub)
      recording (fpMultiplyAdd po) 31u (fst nmadd) (snd nmadd) ]

/// The instructions the unit performs on one number, which are the roundings
/// and the conversions between how a number is written and what it counts.
let private unaryEncoders () =
  List.concat
    [ recording (fpUnary 63u) 12u Op.FRSP Op.FRSPdot
      recording (fpUnary 63u) 14u Op.FCTIW Op.FCTIWdot
      recording (fpUnary 63u) 15u Op.FCTIWZ Op.FCTIWZdot
      recording (fpUnary 63u) 26u Op.FRSQRTE Op.FRSQRTEdot
      recording (fpUnary 63u) 40u Op.FNEG Op.FNEGdot
      recording (fpUnary 63u) 72u Op.FMR Op.FMRdot
      recording (fpUnary 63u) 136u Op.FNABS Op.FNABSdot
      recording (fpUnary 63u) 142u Op.FCTIWU Op.FCTIWUdot
      recording (fpUnary 63u) 143u Op.FCTIWUZ Op.FCTIWUZdot
      recording (fpUnary 63u) 264u Op.FABS Op.FABSdot
      recording (fpUnary 63u) 392u Op.FRIN Op.FRINdot
      recording (fpUnary 63u) 424u Op.FRIZ Op.FRIZdot
      recording (fpUnary 63u) 456u Op.FRIP Op.FRIPdot
      recording (fpUnary 63u) 488u Op.FRIM Op.FRIMdot
      recording (fpUnary 63u) 814u Op.FCTID Op.FCTIDdot
      recording (fpUnary 63u) 815u Op.FCTIDZ Op.FCTIDZdot
      recording (fpUnary 63u) 846u Op.FCFID Op.FCFIDdot
      recording (fpUnary 63u) 942u Op.FCTIDU Op.FCTIDUdot
      recording (fpUnary 63u) 943u Op.FCTIDUZ Op.FCTIDUZdot
      recording (fpUnary 63u) 974u Op.FCFIDU Op.FCFIDUdot
      recording (fpUnary 59u) 24u Op.FRES Op.FRESdot
      recording (fpUnary 59u) 846u Op.FCFIDS Op.FCFIDSdot
      recording (fpUnary 59u) 974u Op.FCFIDUS Op.FCFIDUSdot ]

/// The loads and the stores of a floating-point register, and the instructions
/// that read or write the unit's own status register.
let private memoryAndStatusEncoders () =
  [ Op.LFS, fpMemory 48u
    Op.LFSU, fpMemory 49u
    Op.LFD, fpMemory 50u
    Op.LFDU, fpMemory 51u
    Op.STFS, fpMemory 52u
    Op.STFSU, fpMemory 53u
    Op.STFD, fpMemory 54u
    Op.STFDU, fpMemory 55u
    Op.LFSX, fpIndexed 535u
    Op.LFSUX, fpIndexed 567u
    Op.LFDX, fpIndexed 599u
    Op.LFDUX, fpIndexed 631u
    Op.STFSX, fpIndexed 663u
    Op.STFSUX, fpIndexed 695u
    Op.STFDX, fpIndexed 727u
    Op.STFDUX, fpIndexed 759u
    Op.LFIWAX, fpIndexed 855u
    Op.LFIWZX, fpIndexed 887u
    Op.STFIWX, fpIndexed 983u
    Op.FCMPU, fpCompare 0u
    Op.FCMPO, fpCompare 32u
    Op.MCRFS, fpMoveCondField
    Op.MTFSFI, fpSetStatusField 0u
    Op.MTFSFIdot, fpSetStatusField 1u
    Op.MFFS, fpReadStatus 0u
    Op.MFFSdot, fpReadStatus 1u
    Op.MFFSL, fpReadStatusLight
    Op.MFFSCRN, fpReadStatusSetRound
    Op.MFFSCRNI, fpReadStatusSetRoundImm
    Op.MTFSF, fpWriteStatus 0u
    Op.MTFSFdot, fpWriteStatus 1u
    Op.FCPSGN, fpArith 63u 8u 0u ]

/// The five bits that name the even register of an even-odd pair of
/// floating-point registers, which an odd register cannot name.
let private fprPair reg =
  let n = fpr reg
  if n &&& 1u = 0u then n else fail $"{reg} does not begin a register pair"

/// ftsqrt, which tests one number into a field of the condition register.
let private fpTestOne xo ins =
  match ins.Operands with
  | [ Rg f; Rg b ] -> xForm 63u ((crf f) <<< 2) 0u (fpr b) xo 0u
  | _ -> wrongOperands ins

/// mffsce, which reads the status register and clears its enables.
let private fpReadStatusClearEnables ins =
  match ins.Operands with
  | [ Rg d ] -> xForm 63u (fpr d) 1u 0u 583u 0u
  | _ -> wrongOperands ins

/// mffscdrn, which reads the control bits and puts the decimal rounding mode
/// a floating-point register names in force.
let private fpReadStatusSetDecimalRound ins =
  match ins.Operands with
  | [ Rg d; Rg b ] -> xForm 63u (fpr d) 20u (fpr b) 583u 0u
  | _ -> wrongOperands ins

/// mffscdrni, which names that rounding mode outright, in three bits.
let private fpReadStatusSetDecimalRoundImm ins =
  match ins.Operands with
  | [ Rg d; Im m ] -> xForm 63u (fpr d) 21u (unsigned 3 m) 583u 0u
  | _ -> wrongOperands ins

/// lfdp and stfdp, the DS-form accesses of a register pair.
let private fpPairMemory po ins =
  match ins.Operands with
  | [ Rg f; Mem(disp, b) ] ->
    dForm po (fprPair f) (gpr b) (wordDisplacement disp)
  | _ ->
    wrongOperands ins

/// lfdpx and stfdpx, the X-form accesses of a register pair.
let private fpPairIndexed xo ins =
  match ins.Operands with
  | [ Rg f; Rg a; Rg b ] -> xForm 31u (fprPair f) (gpr a) (gpr b) xo 0u
  | _ -> wrongOperands ins

/// The instructions the Floating-Point Facility added after the first
/// PowerPC: the estimates, the merges, the software divide and square root
/// tests, and the register pair accesses.
let private laterEncoders () =
  List.concat
    [ recording (fpUnary 63u) 24u Op.FRE Op.FREdot
      recording (fpUnary 59u) 26u Op.FRSQRTES Op.FRSQRTESdot
      [ Op.FCPSGNdot, fpArith 63u 8u 1u
        Op.FMRGEW, fpArith 63u 966u 0u
        Op.FMRGOW, fpArith 63u 838u 0u
        Op.FTDIV, fpCompare 128u
        Op.FTSQRT, fpTestOne 160u
        Op.LFDP, fpPairMemory 57u
        Op.STFDP, fpPairMemory 61u
        Op.LFDPX, fpPairIndexed 791u
        Op.MFFSCE, fpReadStatusClearEnables
        Op.MFFSCDRN, fpReadStatusSetDecimalRound
        Op.MFFSCDRNI, fpReadStatusSetDecimalRoundImm
        Op.STFDPX, fpPairIndexed 919u ] ]

/// Every instruction of the floating-point unit.
let floatEncoders () =
  List.concat
    [ arithmeticOf 59u
        ((Op.FDIVS, Op.FDIVSdot),
         (Op.FSUBS, Op.FSUBSdot),
         (Op.FADDS, Op.FADDSdot))
        ((Op.FSQRTS, Op.FSQRTSdot), (Op.FMULS, Op.FMULSdot))
      arithmeticOf 63u
        ((Op.FDIV, Op.FDIVdot), (Op.FSUB, Op.FSUBdot), (Op.FADD, Op.FADDdot))
        ((Op.FSQRT, Op.FSQRTdot), (Op.FMUL, Op.FMULdot))
      multiplyAddsOf 59u
        ((Op.FMSUBS, Op.FMSUBSdot), (Op.FMADDS, Op.FMADDSdot))
        ((Op.FNMSUBS, Op.FNMSUBSdot), (Op.FNMADDS, Op.FNMADDSdot))
      multiplyAddsOf 63u
        ((Op.FMSUB, Op.FMSUBdot), (Op.FMADD, Op.FMADDdot))
        ((Op.FNMSUB, Op.FNMSUBdot), (Op.FNMADD, Op.FNMADDdot))
      recording (fpMultiplyAdd 63u) 23u Op.FSEL Op.FSELdot
      recording fpSetStatusBit 38u Op.MTFSB1 Op.MTFSB1dot
      recording fpSetStatusBit 70u Op.MTFSB0 Op.MTFSB0dot
      unaryEncoders ()
      memoryAndStatusEncoders ()
      laterEncoders () ]

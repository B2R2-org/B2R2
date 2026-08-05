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
/// beside it.
let private fpSetStatusField rc ins =
  match ins.Operands with
  | [ Im f; Im v ] ->
    xForm 63u ((unsigned 3 f) <<< 2) 0u ((unsigned 4 v) <<< 1) 134u rc
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

/// mtfsf, whose mask says which fields of that register it writes and lies
/// across the two fields the other forms keep registers in.
let private fpWriteStatus rc ins =
  match ins.Operands with
  | [ Im m; Rg b ] ->
    let mask = unsigned 8 m
    word 63u (mask >>> 4) ((mask &&& 0xFu) <<< 1) (fpr b) ((711u <<< 1) ||| rc)
  | _ ->
    wrongOperands ins

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
    Op.STFIWX, fpIndexed 983u
    Op.FCMPU, fpCompare 0u
    Op.FCMPO, fpCompare 32u
    Op.MCRFS, fpMoveCondField
    Op.MTFSFI, fpSetStatusField 0u
    Op.MTFSFIdot, fpSetStatusField 1u
    Op.MFFS, fpReadStatus 0u
    Op.MFFSdot, fpReadStatus 1u
    Op.MFFSL, fpReadStatusLight
    Op.MTFSF, fpWriteStatus 0u
    Op.MTFSFdot, fpWriteStatus 1u
    Op.FCPSGN, fpArith 63u 8u 0u ]

/// Every instruction of the floating-point unit.
let floatEncoders () =
  List.concat
    [ arithmeticOf 59u
        ((Op.FDIVS, Op.FDIVSdot), (Op.FSUBS, Op.FSUBSdot),
         (Op.FADDS, Op.FADDSdot))
        ((Op.FSQRTS, Op.FSQRTSdot), (Op.FMULS, Op.FMULSdot))
      arithmeticOf 63u
        ((Op.FDIV, Op.FDIVdot), (Op.FSUB, Op.FSUBdot),
         (Op.FADD, Op.FADDdot))
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
      memoryAndStatusEncoders () ]

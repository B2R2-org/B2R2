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
/// Which of the ARMv7 extensions an A32 or T32 instruction needs, so that an
/// ISA naming a version refuses what the version does not have. The
/// floating-point instructions need FP and the Advanced SIMD ones SIMD, with
/// VFPv4 for the fused multiply-adds and FP16 for the half-precision
/// conversions on top; SDIV and UDIV need IDIV, PLDW MP, SMC Sec, and HVC,
/// ERET and the banked register moves Virt. What Armv8 added to AArch32 no
/// ARMv7 ISA reads, apart from its hints, which execute as NOPs there.
/// </summary>
module internal B2R2.FrontEnd.ARM32.Features

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32.ParseUtils

/// What an instruction needs of the ISA it is read under.
type Requirement =
  /// Nothing beyond ARMv7-A.
  | Base
  /// An extension.
  | Needs of ARMv7Extension
  /// Either of two extensions: the register moves and the loads and stores of
  /// the extension registers, which the floating-point unit and the SIMD one
  /// share.
  | Either of ARMv7Extension * ARMv7Extension
  /// Both of these.
  | Both of Requirement * Requirement
  /// An instruction Armv8 added, which no ARMv7 ISA has.
  | Later

/// <summary>
/// The extensions an ISA has: the ones it names and the ones those bring.
/// ARMv7VE has the integer divides and the Multiprocessing, Security and
/// Virtualization Extensions; the Virtualization Extensions bring the divides;
/// VFPv4 brings VFPv3 and its half-precision conversions; and Advanced SIMD
/// in an A-profile processor comes with VFPv3.
/// </summary>
let private extensionsOf (isa: ISA) =
  let named = isa.ARMv7Extensions
  let has (ext: ARMv7Extension) = (named &&& ext) = ext
  let bring cond (ext: ARMv7Extension) =
    if cond then ext else ARMv7Extension.None
  named
  ||| bring (isa.ARMArchVersion = ARMArchVersion.V7VE)
        (ARMv7Extension.IDIV ||| ARMv7Extension.MP ||| ARMv7Extension.Sec
         ||| ARMv7Extension.Virt)
  ||| bring (has ARMv7Extension.Virt) ARMv7Extension.IDIV
  ||| bring (has ARMv7Extension.VFPv4)
        (ARMv7Extension.FP ||| ARMv7Extension.FP16)
  ||| bring (has ARMv7Extension.SIMD) ARMv7Extension.FP

let rec private isMet exts req =
  let has (ext: ARMv7Extension) = (exts &&& ext) = ext
  match req with
  | Base -> true
  | Needs ext -> has ext
  | Either(e1, e2) -> has e1 || has e2
  | Both(r1, r2) -> isMet exts r1 && isMet exts r2
  | Later -> false

let private fp = Needs ARMv7Extension.FP

let private simd = Needs ARMv7Extension.SIMD

let private fpOrSIMD = Either(ARMv7Extension.FP, ARMv7Extension.SIMD)

/// <summary>
/// The unit of a move between the core registers and the extension ones: to
/// or from a single-precision register it is FP's and VMRS and VMSR are
/// either unit's; VDUP and the 8- and 16-bit scalar moves are SIMD's, and the
/// 32-bit scalar moves either unit's.
/// </summary>
let private unitOfTransfer bin =
  match pickBit bin 8, pickBit bin 23 with
  | 0u, _ when extract bin 23 21 = 0b111u -> fpOrSIMD
  | 0u, _ -> fp
  | _, 1u -> simd
  | _ when pickBit bin 22 = 0u && extract bin 6 5 = 0u -> fpOrSIMD
  | _ -> simd

/// <summary>
/// The unit a conditional word in the coprocessor space belongs to, in the
/// A32 layout T32 shares below its top nibble: the floating-point data
/// processing is FP's, and the loads, stores and 64-bit moves of the
/// extension registers are either unit's.
/// </summary>
let private unitOfCoprocessor bin =
  let isExtReg = extract bin 11 9 = 0b101u
  match extract bin 27 24 with
  | _ when not isExtReg -> Base
  | 0b1110u when pickBit bin 4 = 0u -> fp
  | 0b1110u -> unitOfTransfer bin
  | 0b1100u | 0b1101u -> fpOrSIMD
  | _ -> Base

/// The unit an A32 word belongs to by the class its bits put it in.
let private unitOfA32 bin =
  let isSIMDData = extract bin 27 25 = 0b001u
  let isSIMDLoadStore = extract bin 27 24 = 0b0100u && pickBit bin 20 = 0u
  match extract bin 31 28 with
  | 0xfu when isSIMDData || isSIMDLoadStore -> simd
  | 0xfu -> Base
  | _ -> unitOfCoprocessor bin

/// The unit a 32-bit T32 instruction belongs to, its first halfword on top.
let private unitOfT32 bin =
  let isSIMDData = extract bin 31 29 = 0b111u && extract bin 27 24 = 0xfu
  let isSIMDLoadStore = extract bin 31 24 = 0b11111001u && pickBit bin 20 = 0u
  if isSIMDData || isSIMDLoadStore then simd
  elif extract bin 31 28 = 0b1110u then unitOfCoprocessor bin
  else Base

let private hasType (t: SIMDDataType) (ins: Instruction) =
  match ins.SIMDTyp with
  | Some(OneDT a) -> a = t
  | Some(TwoDT(a, b)) -> a = t || b = t
  | None -> false

/// VCVTB and VCVTT between single and half precision are the half-precision
/// extension's; between double and half precision they are Armv8's.
let private halfConversion unit (ins: Instruction) =
  if hasType SIMDTypF64 ins then Later
  else Both(unit, Needs ARMv7Extension.FP16)

/// A vector VCVT between halves and singles is the half-precision
/// extension's; one between halves and integers is Armv8's, as is any other
/// instruction on halves.
let private halfOrLater unit (ins: Instruction) =
  match ins.Opcode, ins.SIMDTyp with
  | Opcode.VCVT, Some(TwoDT(SIMDTypF16, SIMDTypF32))
  | Opcode.VCVT, Some(TwoDT(SIMDTypF32, SIMDTypF16)) ->
    Both(unit, Needs ARMv7Extension.FP16)
  | _ ->
    Later

/// The banked registers the Virtualization Extensions' MRS and MSR name.
let private isBanked opr =
  match opr with
  | OprReg r -> r >= Register.R8usr && r <= Register.SPSRfiq
  | _ -> false

let private namesBanked (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> isBanked o1 || isBanked o2
  | _ -> false

/// <summary>
/// What an instruction needs beyond its unit, by its opcode and, where that
/// is not enough, its data type and operands.
/// </summary>
let private requirementOf unit (ins: Instruction) =
  match ins.Opcode with
  | Opcode.AESD | Opcode.AESE | Opcode.AESIMC | Opcode.AESMC
  | Opcode.SHA1C | Opcode.SHA1H | Opcode.SHA1M | Opcode.SHA1P
  | Opcode.SHA1SU0 | Opcode.SHA1SU1 | Opcode.SHA256H | Opcode.SHA256H2
  | Opcode.SHA256SU0 | Opcode.SHA256SU1
  | Opcode.CRC32B | Opcode.CRC32H | Opcode.CRC32W | Opcode.CRC32CB
  | Opcode.CRC32CH | Opcode.CRC32CW
  | Opcode.LDA | Opcode.LDAB | Opcode.LDAH | Opcode.LDAEX | Opcode.LDAEXB
  | Opcode.LDAEXH | Opcode.LDAEXD | Opcode.STL | Opcode.STLB | Opcode.STLH
  | Opcode.STLEX | Opcode.STLEXB | Opcode.STLEXH | Opcode.STLEXD
  | Opcode.HLT | Opcode.DCPS1 | Opcode.DCPS2 | Opcode.DCPS3 | Opcode.SB
  | Opcode.VSELEQ | Opcode.VSELGE | Opcode.VSELGT | Opcode.VSELVS
  | Opcode.VMAXNM | Opcode.VMINNM | Opcode.VCVTA | Opcode.VCVTN
  | Opcode.VCVTP | Opcode.VCVTM | Opcode.VRINTA | Opcode.VRINTN
  | Opcode.VRINTP | Opcode.VRINTM | Opcode.VRINTR | Opcode.VRINTX
  | Opcode.VRINTZ | Opcode.VJCVT | Opcode.VQRDMLAH | Opcode.VQRDMLSH
  | Opcode.VCMLA | Opcode.VCADD | Opcode.VSDOT | Opcode.VUDOT
  | Opcode.VUSDOT | Opcode.VSUDOT | Opcode.VSMMLA | Opcode.VUMMLA
  | Opcode.VUSMMLA | Opcode.VFMAL | Opcode.VFMSL | Opcode.VDOT
  | Opcode.VMMLA | Opcode.VFMAB | Opcode.VFMAT | Opcode.VINS
  | Opcode.VMOVX | Opcode.SEVL | Opcode.ESB | Opcode.TSB | Opcode.CSDB
  | Opcode.SETPAN ->
    Later
  | _ when hasType BF16 ins ->
    Later
  | Opcode.VCVTB | Opcode.VCVTT ->
    halfConversion unit ins
  | _ when hasType SIMDTypF16 ins ->
    halfOrLater unit ins
  | Opcode.VLDR | Opcode.VSTR when hasType SIMDTyp16 ins ->
    Later
  | Opcode.VMULL when hasType SIMDTypP64 ins ->
    Later
  | Opcode.VFMA | Opcode.VFMS | Opcode.VFNMA | Opcode.VFNMS ->
    Both(unit, Needs ARMv7Extension.VFPv4)
  | Opcode.SDIV | Opcode.UDIV ->
    Needs ARMv7Extension.IDIV
  | Opcode.PLDW ->
    Needs ARMv7Extension.MP
  | Opcode.SMC ->
    Needs ARMv7Extension.Sec
  | Opcode.HVC | Opcode.ERET ->
    Needs ARMv7Extension.Virt
  | Opcode.MRS | Opcode.MSR when namesBanked ins ->
    Needs ARMv7Extension.Virt
  | _ ->
    unit

/// The hints Armv8 added, which an ARMv7 processor runs as the NOPs its
/// unallocated hints are.
let private isLaterHint (ins: Instruction) =
  match ins.Opcode with
  | Opcode.SEVL | Opcode.ESB | Opcode.TSB | Opcode.CSDB -> true
  | _ -> false

/// The NOP an Armv8 hint is to an ARMv7 processor, where the hint was and as
/// long as it was.
let private asNOP (ins: Instruction) lifter =
  Instruction(ins.Address,
              ins.Length,
              ins.Condition,
              Opcode.NOP,
              NoOperand,
              ins.ITState,
              false,
              false,
              ins.Qualifier,
              None,
              ins.IsThumb,
              ins.Cflag,
              ins.OprSize,
              ins.IsAdd,
              lifter)

/// <summary>
/// The instruction a word is under the ISA: itself where the ISA has what it
/// needs; a NOP where it is one of Armv8's hints and the ISA is ARMv7's; and
/// otherwise nothing, as the ISA leaves the word UNDEFINED. An ISA naming no
/// version has everything. The word is the instruction's bits, a 32-bit T32
/// one with its first halfword on top.
/// </summary>
let check (isa: ISA) bin (ins: Instruction) lifter =
  let unitOf () =
    if not ins.IsThumb then unitOfA32 bin
    elif ins.Length = 4u then unitOfT32 bin
    else Base
  if isa.ARMArchVersion = ARMArchVersion.Any
     || isMet (extensionsOf isa) (requirementOf (unitOf ()) ins) then
    ins
  elif isLaterHint ins then
    asNOP ins lifter
  else
    raise ParsingFailureException

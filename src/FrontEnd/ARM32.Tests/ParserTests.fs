(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.ARM32.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.OperandHelper
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private Shortcut =
  type O =
    static member Reg(r) = OprReg r

    static member Imm(v) = OprImm v

    static member RegShift(srType, r) = OprRegShift(srType, r)

    static member Shift(srType, v) = OprShift(srType, Imm v)

    static member SpecReg(r, psfFlag) = OprSpecReg(r, Some psfFlag)

    static member Iflag(flag) = OprIflag flag

    static member RegList(lst) = OprRegList lst

    static member Option(barrier) = OprOption barrier

    static member Endian(endian) = OprEndian endian

    static member Cond(cond) = OprCond cond

    static member SimdScalarReg(r, elem) = toSSReg (r, elem)

    static member SimdVectorReg(r) = toSVReg r

    static member MemLabel(v) = memLabel v

    static member MemUnIdx(r, v) = memUnIdxImm (r, v)

    static member MemOffsetImm(offset) = memOffsetImm offset

    static member MemOffsetReg(r1, signOpt, r2, srType, v) =
      memOffsetReg (r1, signOpt, r2, Some(srType, Imm v))

    static member MemOffsetReg(r1, signOpt, r2) =
      memOffsetReg (r1, signOpt, r2, None)

    static member MemOffsetAlign(offset) = memOffsetAlign offset

    static member MemPreIdxImm(offset) = memPreIdxImm offset

    static member MemPreIdxReg(r1, signOpt, r2, srType, v) =
      memPreIdxReg (r1, signOpt, r2, Some(srType, Imm v))

    static member MemPreIdxReg(r1, signOpt, r2) =
      memPreIdxReg (r1, signOpt, r2, None)

    static member MemPreIdxAlign(offset) = memPreIdxAlign offset

    static member MemPostIdxImm(offset) = memPostIdxImm offset

    static member MemPostIdxReg(r1, signOpt, r2, srType, v) =
      memPostIdxReg (r1, signOpt, r2, Some(srType, Imm v))

    static member MemPostIdxReg(r1, signOpt, r2) =
      memPostIdxReg (r1, signOpt, r2, None)

    static member MemPostIdxAlign(offset) = memPostIdxAlign offset

    static member SimdScalarRegs(regList, elem) = getSIMDScalar elem regList

    static member SimdVectorRegs(regList) = getSIMDVector regList

/// - A4.3 Branch instructions
/// - A4.4 Data-processing instructions
/// - A4.5 Status register access instructions
/// - A4.6 Load/store instructions
/// - A4.7 Load/store multiple instructions
/// - A4.8 Miscellaneous instructions
/// - A4.9 Exception-generating and exception-handling instructions
/// - A4.10 Co-processor instructions
/// - A4.11 Advanced SIMD and Floating-point load/store instructions
/// - A4.12 Advanced SIMD and Floating-point register transfer instructions
/// - A4.13 Advanced SIMD data-processing instructions
/// - A4.14 Floating-point data-processing instructions
[<TestClass>]
type ParserTests() =
  let parse (isa: ISA) (bytes: byte[]) =
    let reader = BinReader.Init Endian.Big
    let parser = Parser(isa, false, reader) :> IInstructionParsable
    parser.Parse(bytes, 0UL) :?> Instruction

  let assertIns cond op wback simd oprs (ins: Instruction) =
    Assert.AreEqual<Condition>(cond, ins.Condition)
    Assert.AreEqual<Opcode>(op, ins.Opcode)
    Assert.AreEqual<bool>(wback, ins.WriteBack)
    Assert.AreEqual<SIMDDataTypes option>(simd, ins.SIMDTyp)
    Assert.AreEqual<Operands>(oprs, ins.Operands)

  let test cond op wback simd oprs bytes =
    parse (ISA(Architecture.ARMv7, Endian.Big)) bytes
    |> assertIns cond op wback simd oprs

  /// Parses as AArch32, for the instructions ARMv8 added.
  let testV8 cond op wback simd oprs bytes =
    parse (ISA(Architecture.ARMv8, Endian.Big, WordSize.Bit32)) bytes
    |> assertIns cond op wback simd oprs

  let testNoWbackNoQNoSimd pref (bytes: byte[]) (opcode, operands) =
    test pref opcode false None operands bytes

  let testV8NoWbackNoQNoSimd pref (bytes: byte[]) (opcode, operands) =
    testV8 pref opcode false None operands bytes

  let testNoWbackNoQ pref simd (bytes: byte[]) (opcode, operands) =
    test pref opcode false simd operands bytes

  /// Checks the disassembly, for what no operand carries: the caret that tells
  /// a transfer of another mode's registers from the ordinary one.
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let ins = parse (ISA(Architecture.ARMv7, Endian.Big)) bytes
    Assert.AreEqual<string>(expected, (ins :> IInstruction).Disasm())

  /// Checks that a word the manual calls UNPREDICTABLE is refused rather than
  /// decoded into whatever its fields happen to say.
  let testRefused (byteString: string) =
    let bytes = ByteArray.ofHexString byteString
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parse (ISA(Architecture.ARMv7, Endian.Big)) bytes |> ignore)
    |> ignore

  /// The disassembly of a word under the ISA a name gives, or nothing where
  /// that ISA leaves the word UNDEFINED.
  let under (isaName: string) (byteString: string) =
    let parser = Parser(ISA isaName, false, BinReader.Init Endian.Big)
    let bytes = ByteArray.ofHexString byteString
    try Some(((parser :> IInstructionParsable).Parse(bytes, 0UL)).Disasm())
    with :? ParsingFailureException -> None

  /// Checks that a word reads under each ISA of one list and is refused under
  /// each of the other, which is what a version and its extensions decide.
  let readsOnlyUnder word (reads: string list) (refuses: string list) =
    for name in reads do
      Assert.AreEqual<bool>(true, (under name word).IsSome, $"{word} {name}")
    for name in refuses do
      Assert.AreEqual<string option>(None, under name word, $"{word} {name}")

  let testNoQNoSimd pref wback (bytes: byte[]) (opcode, operands) =
    test pref opcode wback None operands bytes

  let testNoQ pref wback simd (bytes: byte[]) (opcode, operands) =
    test pref opcode wback simd operands bytes

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands(oprs[0], oprs[1])
    | 3 -> ThreeOperands(oprs[0], oprs[1], oprs[2])
    | 4 -> FourOperands(oprs[0], oprs[1], oprs[2], oprs[3])
    | 5 -> FiveOperands(oprs[0], oprs[1], oprs[2], oprs[3], oprs[4])
    | 6 -> SixOperands(oprs[0], oprs[1], oprs[2], oprs[3], oprs[4], oprs[5])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  [<TestMethod>]
  member _.``[ARMv7] Branch Parse Test (1)``() =
    "ea0000ff"
    ++ B ** [ O.MemLabel 1020L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Branch Parse Test (2)``() =
    "fa000010"
    ++ BLX ** [ O.MemLabel 64L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Branch Parse Test (3)``() =
    "e12fff10"
    ++ BX ** [ O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.1 Standard data-processing instructions
  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (1)``() =
    "e080285e"
    ++ ADD
    ** [ O.Reg R2; O.Reg R0; O.Reg LR; O.RegShift(ShiftOp.ASR, R8) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (2)``() =
    "e28f0ff0"
    ++ ADD ** [ O.Reg R0; O.Reg PC; O.Imm 960L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (3)``() =
    "e0000000"
    ++ AND ** [ O.Reg R0; O.Reg R0; O.Reg R0; O.Shift(ShiftOp.LSL, 0u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (4)``() =
    "e15c0262"
    ++ CMP ** [ O.Reg IP; O.Reg R2; O.Shift(ShiftOp.ROR, 4u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (5)``() =
    "e23010fc"
    ++ EORS ** [ O.Reg R1; O.Reg R0; O.Imm 252L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (6)``() =
    "e300a00f"
    ++ MOVW ** [ O.Reg SL; O.Imm 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (7)``() =
    "e1b0800c"
    ++ MOVS ** [ O.Reg R8; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (8)``() =
    "e1e00819"
    ++ MVN ** [ O.Reg R0; O.Reg SB; O.RegShift(ShiftOp.LSL, R8) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (9)``() =
    "e13a0c16"
    ++ TEQ ** [ O.Reg SL; O.Reg R6; O.RegShift(ShiftOp.LSL, IP) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (10)``() =
    "e3130004"
    ++ TST ** [ O.Reg R3; O.Imm 4L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.2 Shift instructions
  [<TestMethod>]
  member _.``[ARMv7] Shift Parse Test (1)``() =
    "e1b00113"
    ++ LSLS ** [ O.Reg R0; O.Reg R3; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Shift Parse Test (2)``() =
    "e1a00e65"
    ++ ROR ** [ O.Reg R0; O.Reg R5; O.Imm 28L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.3 Multiply instructions
  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (1)``() =
    "e0100c99"
    ++ MULS ** [ O.Reg R0; O.Reg SB; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (2)``() =
    "e100cac5"
    ++ SMLABT ** [ O.Reg R0; O.Reg R5; O.Reg SL; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (3)``() =
    "e14012e8"
    ++ SMLALTT ** [ O.Reg R1; O.Reg R0; O.Reg R8; O.Reg R2 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (4)``() =
    "e700f112"
    ++ SMUAD ** [ O.Reg R0; O.Reg R2; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (5)``() =
    "e1600e8c"
    ++ SMULBB ** [ O.Reg R0; O.Reg IP; O.Reg LR ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.4 Saturating instructions
  [<TestMethod>]
  member _.``[ARMv7] Saturating Parse Test (1)``() =
    "e6bc03d2"
    ++ SSAT
    ** [ O.Reg R0; O.Imm 29L; O.Reg R2; O.Shift(ShiftOp.ASR, 7u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// The signed saturation counts the width it saturates to from one, and the
  /// unsigned one holds it as it is.
  [<TestMethod>]
  member _.``[ARMv7] Saturating Parse Test (2)``() =
    "e6a10f31"
    ++ SSAT16 ** [ O.Reg R0; O.Imm 2L; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Saturating Parse Test (3)``() =
    "e6e10f31"
    ++ USAT16 ** [ O.Reg R0; O.Imm 1L; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.5 Saturating addition and subtraction instructions
  [<TestMethod>]
  member _.``[ARMv7] Saturating addition and subtraction Parse Test (1)``() =
    "e1001052"
    ++ QADD ** [ O.Reg R1; O.Reg R2; O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.6 Packing and unpacking instructions
  [<TestMethod>]
  member _.``[ARMv7] Packing and unpacking Parse Test (1)``() =
    "e6801ad8"
    ++ PKHTB
    ** [ O.Reg R1; O.Reg R0; O.Reg R8; O.Shift(ShiftOp.ASR, 21u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Packing and unpacking Parse Test (2)``() =
    "e6a01c70"
    ++ SXTAB
    ** [ O.Reg R1; O.Reg R0; O.Reg R0; O.Shift(ShiftOp.ROR, 24u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Packing and unpacking Parse Test (3)``() =
    "e6bf0073"
    ++ SXTH ** [ O.Reg R0; O.Reg R3; O.Shift(ShiftOp.ROR, 0u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.7 Parallel addition and subtraction instructions
  [<TestMethod>]
  member _.``[ARMv7] Parallel addition and subtraction Parse Test (1)``() =
    "e6101f37"
    ++ SASX ** [ O.Reg R1; O.Reg R0; O.Reg R7 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.9 Miscellaneous data-processing instructions
  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (1)``() =
    "e7df019f"
    ++ BFC ** [ O.Reg R0; O.Imm 3L; O.Imm 29L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (2)``() =
    "e7ca0290"
    ++ BFI ** [ O.Reg R0; O.Reg R0; O.Imm 5L; O.Imm 6L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (3)``() =
    "e16f0f11"
    ++ CLZ ** [ O.Reg R0; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (4)``() =
    "e7a20e52"
    ++ SBFX ** [ O.Reg R0; O.Reg R2; O.Imm 28L; O.Imm 3L ]
    ||> testNoWbackNoQNoSimd Condition.AL

#if !EMULATION
  (* Refusing a word the manual calls UNPREDICTABLE is one of the checks an
     emulation build compiles out of the parser, so what follows is only true of
     a build that compiles them in. *)

  /// The width of a bitfield is how far its top bit sits above its bottom one,
  /// so a top bit below the bottom one names no field at all.
  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (5)``() =
    testRefused "e7c12314" (* bfi, msb = 1, lsb = 6 *)

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (6)``() =
    testRefused "e7c1231f" (* bfc, msb = 1, lsb = 6 *)
#endif

  /// The element and structure loads and stores are 1111 0100 with bit 20
  /// clear; the same word with bit 24 set is no instruction.
  [<TestMethod>]
  member _.``[ARMv7] VLD1 of four registers steps by a register``() =
    testDisasm "f42af2d2" "vld1.64 {d15, d16, d17, d18}, [sl:64], r2"

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD element load/store needs bit 24 clear``() =
    testRefused "f52af2d2"

  /// An A32 VSTR may take the PC as its base: the manual's UNPREDICTABLE is
  /// for every other instruction set.
  [<TestMethod>]
  member _.``[ARMv7] VSTR may take the PC as its base``() =
    testDisasm "adcf7bcc" "vstrge.64 d23, [pc, #0x330]"

  /// VLD2 of one register a structure steps by one, so d30 and d31 are the
  /// last pair it can name.
  [<TestMethod>]
  member _.``[ARMv7] VLD2 of the last two D registers``() =
    testDisasm "f46be812" "vld2.8 {d30, d31}, [fp:64], r2"

  /// <summary>
  /// Which ISAs read each word, and which refuse it. An ARMv7 ISA naming a
  /// version reads the instructions of the extensions it has and no others:
  /// the moves and loads of the extension registers are either unit's, the
  /// fused multiply-adds need VFPv4 and the half-precision conversions FP16
  /// on top, and what Armv8 added no ARMv7 version reads.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VADD.F32 is either unit's``() =
    readsOnlyUnder "ee300a81" [ "armv7-v7+fp"; "armv7-v7+simd" ] [ "armv7-v7" ]

  [<TestMethod>]
  member _.``[ARMv7] VADD.I32 is Advanced SIMD's``() =
    readsOnlyUnder "f2210802" [ "armv7-v7+simd" ] [ "armv7-v7+fp"; "armv7-v7" ]

  [<TestMethod>]
  member _.``[ARMv7] VFMA.F32 is VFPv4's``() =
    readsOnlyUnder "eea00a81" [ "armv7-v7+vfpv4" ]
      [ "armv7-v7+fp"; "armv7-v7+simd" ]

  [<TestMethod>]
  member _.``[ARMv7] VFMA of vectors needs SIMD and VFPv4``() =
    readsOnlyUnder "f2010c12" [ "armv7-v7+simd+vfpv4" ] [ "armv7-v7+simd" ]

  [<TestMethod>]
  member _.``[ARMv7] VCVTB is the half-precision extension's``() =
    readsOnlyUnder "eeb20a60" [ "armv7-v7+fp+fp16"; "armv7-v7+vfpv4" ]
      [ "armv7-v7+fp" ]

  [<TestMethod>]
  member _.``[ARMv7] VCVT of halves needs SIMD and FP16``() =
    readsOnlyUnder "f3b60602" [ "armv7-v7+simd+fp16" ] [ "armv7-v7+simd" ]

  [<TestMethod>]
  member _.``[ARMv7] SDIV is the divide extension's``() =
    readsOnlyUnder "e710f211" [ "armv7-v7+idiv"; "armv7-v7+virt" ]
      [ "armv7-v7+mp" ]

  [<TestMethod>]
  member _.``[ARMv7] SDIV comes with ARMv7VE``() =
    readsOnlyUnder "e710f211" [ "armv7-v7ve" ] [ "armv7-v7" ]

  [<TestMethod>]
  member _.``[ARMv7] PLDW is the multiprocessing extension's``() =
    readsOnlyUnder "f590f000" [ "armv7-v7+mp"; "armv7-v7ve" ] [ "armv7-v7" ]

  [<TestMethod>]
  member _.``[ARMv7] SMC is the security extension's``() =
    readsOnlyUnder "e1600070" [ "armv7-v7+sec"; "armv7-v7ve" ] [ "armv7-v7" ]

  [<TestMethod>]
  member _.``[ARMv7] HVC is the virtualization extension's``() =
    readsOnlyUnder "e1400070" [ "armv7-v7+virt"; "armv7-v7ve" ]
      [ "armv7-v7+idiv" ]

  [<TestMethod>]
  member _.``[ARMv7] MRS (banked) is the virtualization extension's``() =
    readsOnlyUnder "e1000200" [ "armv7-v7+virt" ] [ "armv7-v7" ]

  [<TestMethod>]
  member _.``[ARMv7] VLDM is either unit's``() =
    readsOnlyUnder "ec900b04" [ "armv7-v7+fp"; "armv7-v7+simd" ] [ "armv7-v7" ]

  [<TestMethod>]
  member _.``[ARMv7] VLD1 is Advanced SIMD's``() =
    readsOnlyUnder "f420070f" [ "armv7-v7+simd" ] [ "armv7-v7+fp" ]

  [<TestMethod>]
  member _.``[ARMv7] VMOV of a word to a core register is either unit's``() =
    readsOnlyUnder "ee300b10" [ "armv7-v7+fp"; "armv7-v7+simd" ] [ "armv7-v7" ]

  [<TestMethod>]
  member _.``[ARMv7] VMOV of a byte to a core register is Advanced SIMD's``() =
    readsOnlyUnder "eed00b30" [ "armv7-v7+simd" ] [ "armv7-v7+fp" ]

  [<TestMethod>]
  member _.``[ARMv7] CRC32B is Armv8's``() =
    readsOnlyUnder "e1010042" [ "armv7" ] [ "armv7-v7ve+simd+vfpv4" ]

  [<TestMethod>]
  member _.``[ARMv7] VMAXNM is Armv8's``() =
    readsOnlyUnder "f3010f12" [ "armv7" ] [ "armv7-v7ve+simd+vfpv4" ]

  [<TestMethod>]
  member _.``[ARMv7] LDA is Armv8's``() =
    readsOnlyUnder "e1910c9f" [ "armv7" ] [ "armv7-v7ve" ]

  [<TestMethod>]
  member _.``[ARMv7] ADD is every version's``() =
    readsOnlyUnder "e0810002" [ "armv7-v7" ] []

  /// Armv8's hints are NOPs to an ARMv7 processor, as its unallocated hints
  /// are, so an ARMv7 version reads them as NOP.
  [<TestMethod>]
  member _.``[ARMv7] SEVL reads as NOP under an ARMv7 version``() =
    Assert.AreEqual<string option>(Some "nop", under "armv7-v7" "e320f005")

  /// An ISA that names no version reads every instruction.
  [<TestMethod>]
  member _.``[ARMv7] SEVL reads as SEVL without a version``() =
    Assert.AreEqual<string option>(Some "sevl", under "armv7" "e320f005")

  /// A register list of no registers is UNPREDICTABLE. A build that checks
  /// refuses it, and one that does not reads the empty list it names; either
  /// way the word comes back, rather than being read as every register there
  /// is.
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``[ARMv7] VLDM with no registers``() =
#if EMULATION
    let bytes = ByteArray.ofHexString "7cba0b00" (* vldmiavc r10!, {} *)
    let ins = parse (ISA(Architecture.ARMv7, Endian.Big)) bytes
    let expected = TwoOperands(O.Reg SL, O.RegList [])
    Assert.AreEqual<Operands>(expected, ins.Operands)
#else
    testRefused "7cba0b00" (* vldmiavc r10!, {} *)
#endif

  [<TestMethod>]
  member _.``[ARMv7] Status register access Parse Test (1)``() =
    "e32cf0f0"
    ++ MSR ** [ O.SpecReg(CPSR, PSRfs); O.Imm 240L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Status register access Parse Test (2)``() =
    "e12cf002"
    ++ MSR ** [ O.SpecReg(CPSR, PSRfs); O.Reg R2 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Status register access Parse Test (3)``() =
    "f10a0142"
    ++ CPSIE ** [ O.Iflag AF; O.Imm 2L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Lord) Parse test (1)``() =
    "e59f000f"
    ++ LDR ** [ O.Reg R0; O.MemLabel 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Lord) Parse test (2)``() =
    "e09010bc"
    ++ LDRH ** [ O.Reg R1; O.MemPostIdxReg(R0, Some Plus, IP) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Lord) Parse test (3)``() =
    "e75010c2"
    ++ LDRB
    ** [ O.Reg R1; O.MemOffsetReg(R0, Some Minus, R2, ShiftOp.ASR, 1u) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Lord) Parse test (4)``() =
    "e1701cd3"
    ++ LDRSB ** [ O.Reg R1; O.MemPreIdxImm(R0, Some Minus, Some 195L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store) Parse test (1)``() =
    "e50010f3"
    ++ STR ** [ O.Reg R1; O.MemOffsetImm(R0, Some Minus, Some 243L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store) Parse test (2)``() =
    "e640122c"
    ++ STRB
    ** [ O.Reg R1; O.MemPostIdxReg(R0, Some Minus, IP, ShiftOp.LSR, 4u) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store) Parse test (3)``() =
    "e1a0c0f8"
    ++ STRD ** [ O.Reg IP; O.Reg SP; O.MemPreIdxReg(R0, Some Plus, R8) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Load unprivileged) Parse test (1)``() =
    "e070e0fe"
    ++ LDRSHT ** [ O.Reg LR; O.MemPostIdxImm(R0, Some Minus, Some 14L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store unprivileged) Parse test (1)``() =
    "e4a0100f"
    ++ STRT ** [ O.Reg R1; O.MemPostIdxImm(R0, Some Plus, Some 15L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store unprivileged) Parse test (2)``() =
    "e02010b4"
    ++ STRHT ** [ O.Reg R1; O.MemPostIdxReg(R0, Some Minus, R4) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A post-indexed access keeps a zero offset, which the other addressing
  /// modes leave out: it is what closes the bracket and says that the base is
  /// written back. A zero offset has no sign, but one that is not zero keeps
  /// its own.
  [<TestMethod>]
  member _.``[ARMv7] Load/store Disasm test (1)``() =
    testDisasm "e4910000" "ldr r0, [r1], #0x0"

  [<TestMethod>]
  member _.``[ARMv7] Load/store Disasm test (2)``() =
    testDisasm "e4810000" "str r0, [r1], #0x0"

  [<TestMethod>]
  member _.``[ARMv7] Load/store Disasm test (3)``() =
    testDisasm "e5910000" "ldr r0, [r1]"

  [<TestMethod>]
  member _.``[ARMv7] Load/store Disasm test (4)``() =
    testDisasm "e4110004" "ldr r0, [r1], #-0x4"

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Load-Exclusive) Parse test (1)``() =
    "e190ef9f"
    ++ LDREX ** [ O.Reg LR; O.MemOffsetImm(R0, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// The narrower exclusive loads keep the register they read above the field
  /// the exclusive stores keep it in, and ones below.
  [<TestMethod>]
  member _.``[ARMv7] Load/store (Load-Exclusive) Parse test (2)``() =
    "e1d12f9f"
    ++ LDREXB ** [ O.Reg R2; O.MemOffsetImm(R1, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Load-Exclusive) Parse test (3)``() =
    "e1f12f9f"
    ++ LDREXH ** [ O.Reg R2; O.MemOffsetImm(R1, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Load-Exclusive) Parse test (4)``() =
    "e1b12f9f"
    ++ LDREXD ** [ O.Reg R2; O.Reg R3; O.MemOffsetImm(R1, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store-Exclusive) Parse test (1)``() =
    "e1a01f92"
    ++ STREXD ** [ O.Reg R1
                   O.Reg R2
                   O.Reg R3
                   O.MemOffsetImm(R0, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A store that releases keeps the register it writes below the field a load
  /// keeps it in, and ones above.
  [<TestMethod>]
  member _.``[ARMv8] Load/store (Store-Release) Parse test (1)``() =
    "e181fc90"
    ++ STL ** [ O.Reg R0; O.MemOffsetImm(R1, None, None) ]
    ||> testV8NoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv8] Load/store (Store-Release) Parse test (2)``() =
    "e1c1fc90"
    ++ STLB ** [ O.Reg R0; O.MemOffsetImm(R1, None, None) ]
    ||> testV8NoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv8] Load/store (Store-Release) Parse test (3)``() =
    "e1e1fc90"
    ++ STLH ** [ O.Reg R0; O.MemOffsetImm(R1, None, None) ]
    ||> testV8NoWbackNoQNoSimd Condition.AL

  /// A load that acquires keeps the register it reads where every other load
  /// keeps it, whatever its width.
  [<TestMethod>]
  member _.``[ARMv8] Load/store (Load-Acquire) Parse test (1)``() =
    "e1d12c9f"
    ++ LDAB ** [ O.Reg R2; O.MemOffsetImm(R1, None, None) ]
    ||> testV8NoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv8] Load/store (Load-Acquire) Parse test (2)``() =
    "e1f12c9f"
    ++ LDAH ** [ O.Reg R2; O.MemOffsetImm(R1, None, None) ]
    ||> testV8NoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv8] Load/store (Load-Acquire) Parse test (3)``() =
    "e1d12e9f"
    ++ LDAEXB ** [ O.Reg R2; O.MemOffsetImm(R1, None, None) ]
    ||> testV8NoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv8] Load/store (Load-Acquire) Parse test (4)``() =
    "e1f12e9f"
    ++ LDAEXH ** [ O.Reg R2; O.MemOffsetImm(R1, None, None) ]
    ||> testV8NoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv8] Load/store (Load-Acquire) Parse test (5)``() =
    "e1b12e9f"
    ++ LDAEXD ** [ O.Reg R2; O.Reg R3; O.MemOffsetImm(R1, None, None) ]
    ||> testV8NoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (1)``() =
    "e8100f0c"
    ++ LDMDA ** [ O.Reg R0; O.RegList [ R2; R3; R8; SB; SL; FP ] ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (2)``() =
    "e8300f0c"
    ++ LDMDA ** [ O.Reg R0; O.RegList [ R2; R3; R8; SB; SL; FP ] ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (3)``() =
    "e8bd000f"
    ++ POP ** [ O.RegList [ R0; R1; R2; R3 ] ]
    ||> testNoWbackNoQNoSimd Condition.AL

    (*
    "e52d0004"
    ++ STR ** [ O.Reg R0; O.MemPreIdxImm(SP, Some Minus, Some 4L) ]
    ||> testNoQNoSimd Condition.AL (Some true)
    *)

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (4)``() =
    "e52d0004"
    ++ PUSH ** [ O.RegList [ R0 ] ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (5)``() =
    "e8c9e000"
    ++ STM ** [ O.Reg SB; O.RegList [ SP; LR; PC ] ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A transfer of the registers of another mode ends in a caret, and shares
  /// its mnemonic with the ordinary transfer that it is not.
  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Disasm test (1)``() =
    testDisasm "e8912304" "ldm r1, {r2, r8, sb, sp}"

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Disasm test (2)``() =
    testDisasm "e8d12304" "ldm r1, {r2, r8, sb, sp}^"

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Disasm test (3)``() =
    testDisasm "e8812304" "stm r1, {r2, r8, sb, sp}"

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Disasm test (4)``() =
    testDisasm "e8c12304" "stm r1, {r2, r8, sb, sp}^"

  /// A return from an exception writes its base back when its write-back bit
  /// says so, which the transfer of another mode's registers has no room for.
  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Disasm test (5)``() =
    testDisasm "e8d1a304" "ldm r1, {r2, r8, sb, sp, pc}^"

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Disasm test (6)``() =
    testDisasm "e8f1a304" "ldm r1!, {r2, r8, sb, sp, pc}^"

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (1)``() =
    "f57ff01f"
    ++ CLREX ** []
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (2)``() =
    "f57ff05f"
    ++ DMB ** [ O.Option BarrierOption.SY ]
    ||> testNoWbackNoQNoSimd Condition.UN

  /// SSBB and PSSBB are DSB with options 0000 and 0100, which the manual
  /// names apart (DDI0487F.c F5.1.213 and F5.1.141).
  [<TestMethod>]
  member _.``[ARMv7] SSBB and PSSBB read apart from DSB``() =
    testDisasm "f57ff040" "ssbb"
    testDisasm "f57ff044" "pssbb"
    testDisasm "f57ff04f" "dsb sy"

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (3)``() =
    "e320f000"
    ++ NOP ** []
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (4)``() =
    "f55fff00"
    ++ PLD ** [ O.MemLabel -3840L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (5)``() =
    "f790f1c0"
    ++ PLDW ** [ O.MemOffsetReg(R0, Some Plus, R0, ShiftOp.ASR, 3u) ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (6)``() =
    "f450f0f0"
    ++ PLI ** [ O.MemLabel -240L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (7)``() =
    "f1010200"
    ++ SETEND ** [ O.Endian Endian.Big ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (8)``() =
    "e100c09e"
    ++ SWP ** [ O.Reg IP; O.Reg LR; O.MemOffsetImm(R0, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Exception-gen and exception-handling Parse Test (1)``() =
    "e120f07c"
    ++ BKPT ** [ O.Imm 3852L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Exception-gen and exception-handling Parse Test (2)``() =
    "e160007f"
    ++ SMC ** [ O.Imm 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Exception-gen and exception-handling Parse Test (3)``() =
    "f9bc0a00"
    ++ RFEIB ** [ O.Reg IP ]
    ||> testNoQNoSimd Condition.UN true

  [<TestMethod>]
  member _.``[ARMv7] Exception-gen and exception-handling Parse Test (4)``() =
    "f96d0504"
    ++ SRSDB ** [ O.Reg SP; O.Imm 4L ]
    ||> testNoQNoSimd Condition.UN true

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (1)``() =
    (* Only ARMv7 *)
    "ee0123e8"
    ++ CDP ** [ O.Reg P3; O.Imm 0L; O.Reg C2; O.Reg C1; O.Reg C8; O.Imm 7L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (2)``() =
    "ec401fe3"
    ++ MCRR ** [ O.Reg P15; O.Imm 14L; O.Reg R1; O.Reg R0; O.Reg C3 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (3)``() =
    "ee9e9e32"
    ++ MRC ** [ O.Reg P14; O.Imm 4L; O.Reg SB; O.Reg C14; O.Reg C2; O.Imm 1L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (4)``() =
    "ed9f5e30"
    ++ LDC ** [ O.Reg P14; O.Reg C5; O.MemLabel 192L ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (5)``() =
    "ec905e80"
    ++ LDC ** [ O.Reg P14; O.Reg C5; O.MemUnIdx(R0, 128L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// The coprocessor transfers reach the same post-indexed zero offset.
  [<TestMethod>]
  member _.``[ARMv7] Co-processor Disasm test (1)``() =
    testDisasm "fc200000" "stc2 p0, c0, [r0], #0x0"

  /// A4.11.1 Element and structure load/store instructions
  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Parse Test (1)``() =
    "f4e02f70"
    ++ VLD4 ** [ O.SimdScalarRegs([ D18; D20; D22; D24 ], None)
                 O.MemPostIdxAlign(R0, Some 64L, Some R0) ]
    ||> testNoQ Condition.UN true (Some(OneDT SIMDTyp16))

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Parse test (2)``() =
    "f402c690"
    ++ VST1 ** [ O.SimdVectorRegs([ D12; D13; D14 ])
                 O.MemPostIdxAlign(R2, Some 64L, Some R0) ]
    ||> testNoQ Condition.UN true (Some(OneDT SIMDTyp32))

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Parse test (3)``() =
    "f48eeac3"
    ++ VST3 ** [ O.SimdScalarRegs([ D14; D16; D18 ], Some 1uy)
                 O.MemPostIdxReg(LR, None, R3) ]
    ||> testNoQ Condition.UN true (Some(OneDT SIMDTyp32))

  /// VLD2, VST2, VLD3 and VST3 of multiple structures are the types a pair
  /// or a triple spaced one or two apart, and two pairs; the one-lane VLD1
  /// and VST1 name their register with the D bit, and the one-lane and
  /// all-lane VLD3 and VST3 read their memory operand as the others do.
  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (1)``() =
    testDisasm "f4e110e2" "vld1.8 {d17[7]}, [r1], r2"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (2)``() =
    testDisasm "f4c110e2" "vst1.8 {d17[7]}, [r1], r2"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (3)``() =
    testDisasm "f421080f" "vld2.8 {d0, d1}, [r1]"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (4)``() =
    testDisasm "f4210942" "vld2.16 {d0, d2}, [r1], r2"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (5)``() =
    testDisasm "f421038d" "vld2.32 {d0, d1, d2, d3}, [r1]!"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (6)``() =
    testDisasm "f461080f" "vld2.8 {d16, d17}, [r1]"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (7)``() =
    testDisasm "f4010942" "vst2.16 {d0, d2}, [r1], r2"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (8)``() =
    testDisasm "f401038d" "vst2.32 {d0, d1, d2, d3}, [r1]!"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (9)``() =
    testDisasm "f421040f" "vld3.8 {d0, d1, d2}, [r1]"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (10)``() =
    testDisasm "f4210542" "vld3.16 {d0, d2, d4}, [r1], r2"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (11)``() =
    testDisasm "f4613582" "vld3.32 {d19, d21, d23}, [r1], r2"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (12)``() =
    testDisasm "f401050d" "vst3.8 {d0, d2, d4}, [r1]!"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (13)``() =
    testDisasm "f4a1026f" "vld3.8 {d0[3], d1[3], d2[3]}, [r1]"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (14)``() =
    testDisasm "f4a10e6d" "vld3.16 {d0[], d2[], d4[]}, [r1]!"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (15)``() =
    testDisasm "f48106ad" "vst3.16 {d0[2], d2[2], d4[2]}, [r1]!"

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Disasm test (16)``() =
    testDisasm "f421004d" "vld4.16 {d0, d1, d2, d3}, [r1]!"

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD and FP register transfer Parse test (1)``() =
    "ee82ebb0"
    ++ VDUP ** [ O.SimdVectorReg D18; O.Reg LR ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTyp16))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD and FP register transfer Parse test (2)``() =
    "ee42cbb0"
    ++ VMOV ** [ O.SimdScalarReg(D18, Some 1uy); O.Reg IP ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTyp8))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD and FP register transfer Parse test (3)``() =
    "ee108bb0"
    ++ VMOV ** [ O.Reg R8; O.SimdScalarReg(D16, Some 0uy) ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypS16))

  /// A4.13.1 Advanced SIMD parallel addition and subtraction
  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD parallel add and sub Parse test (1)``() =
    "f2c0c18a"
    ++ VADDW ** [ O.SimdVectorReg Q14; O.SimdVectorReg Q8; O.SimdVectorReg D10 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypS8))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD parallel add and sub Parse test (2)``() =
    "f320122c"
    ++ VHSUB ** [ O.SimdVectorReg D1; O.SimdVectorReg D0; O.SimdVectorReg D28 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypU32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD parallel add and sub Parse test (3)``() =
    "f3b0028e"
    ++ VPADDL ** [ O.SimdVectorReg D0; O.SimdVectorReg D14 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypU8))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD parallel add and sub Parse test (4)``() =
    "f290c682"
    ++ VSUBHN ** [ O.SimdVectorReg D12; O.SimdVectorReg Q8; O.SimdVectorReg Q1 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypI32))

  /// A4.13.2 Bitwise Advanced SIMD data-processing instructions
  [<TestMethod>]
  member _.``[ARMv7] Bitwise Advanced SIMD data-processing Parse test (1)``() =
    "f242c1f8"
    ++ VAND ** [ O.SimdVectorReg Q14; O.SimdVectorReg Q9; O.SimdVectorReg Q12 ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Bitwise Advanced SIMD data-processing Parse test (2)``() =
    "f3c1e57b"
    ++ VBIC ** [ O.SimdVectorReg Q15; O.Imm 0x9B0000L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypI32))

  [<TestMethod>]
  member _.``[ARMv7] Bitwise Advanced SIMD data-processing Parse test (3)``() =
    "ee12ca10"
    ++ VMOV ** [ O.Reg IP; O.SimdVectorReg S4 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.13.3 Advanced SIMD comparison instructions
  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD comparison Parse test (1)``() =
    "f24c8e40"
    ++ VCEQ ** [ O.SimdVectorReg Q12; O.SimdVectorReg Q6; O.SimdVectorReg Q0 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypF32))

  /// A4.13.4 Advanced SIMD shift instructions
  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (1)``() =
    "f3a00950"
    ++ VQRSHRN ** [ O.SimdVectorReg D0; O.SimdVectorReg Q0; O.Imm 32L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypU64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (2)``() =
    "f3b80830"
    ++ VQSHRUN ** [ O.SimdVectorReg D0; O.SimdVectorReg Q8; O.Imm 8L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypS64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (3)``() =
    "f2b825d8"
    ++ VSHL ** [ O.SimdVectorReg Q1; O.SimdVectorReg Q4; O.Imm 56L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypI64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (4)``() =
    "f2a00832"
    ++ VSHRN ** [ O.SimdVectorReg D0; O.SimdVectorReg Q9; O.Imm 32L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypI64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (5)``() =
    "f3e801f0"
    ++ VSRA ** [ O.SimdVectorReg Q8; O.SimdVectorReg Q8; O.Imm 24L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypU64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (6)``() =
    "f3b9943a"
    ++ VSRI ** [ O.SimdVectorReg D9; O.SimdVectorReg D26; O.Imm 7L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTyp32))

  /// A4.13.5 Advanced SIMD multiply instructions
  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (1)``() =
    "f3a02a28"
    ++ VMLSL ** [ O.SimdVectorReg Q1; O.SimdVectorReg D0; O.SimdVectorReg D24 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypU32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (2)``() =
    "ee202aa8"
    ++ VMUL ** [ O.SimdVectorReg S4; O.SimdVectorReg S1; O.SimdVectorReg S17 ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypF32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (3)``() =
    "f2c28ca0"
    ++ VMULL ** [ O.SimdVectorReg Q12
                  O.SimdVectorReg D18
                  O.SimdVectorReg D16 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypS8))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (4)``() =
    "f3e24a4a"
    ++ VMULL ** [ O.SimdVectorReg Q10
                  O.SimdVectorReg D2
                  O.SimdScalarReg(D10, Some 0uy) ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypU32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (5)``() =
    "f3d02ce8"
    ++ VQDMULH ** [ O.SimdVectorReg Q9
                    O.SimdVectorReg Q8
                    O.SimdScalarReg(D0, Some 3uy) ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypS16))

  /// A4.13.6 Miscellaneous Advanced SIMD data-processing instructions
  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (1)``() =
    "f3aa0f30"
    ++ VCVT ** [ O.SimdVectorReg D0; O.SimdVectorReg D16; O.Imm 22L ]
    ||> testNoWbackNoQ Condition.UN (Some(TwoDT(SIMDTypU32, SIMDTypF32)))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (2)``() =
    "eebf0b62"
    ++ VCVT ** [ O.SimdVectorReg D0; O.SimdVectorReg D0; O.Imm 11L ]
    ||> testNoWbackNoQ Condition.AL (Some(TwoDT(SIMDTypU16, SIMDTypF64)))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (3)``() =
    "f3f0a56e"
    ++ VCNT ** [ O.SimdVectorReg Q13; O.SimdVectorReg Q15 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTyp8))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (4)``() =
    "f2b003ce"
    ++ VEXT ** [ O.SimdVectorReg Q0
                 O.SimdVectorReg Q8
                 O.SimdVectorReg Q7
                 O.Imm 3L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTyp8))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (5)``() =
    "eef10b62"
    ++ VNEG ** [ O.SimdVectorReg D16; O.SimdVectorReg D18 ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypF64))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (6)``() =
    "f3409f0f"
    ++ VPMAX ** [ O.SimdVectorReg D25; O.SimdVectorReg D0; O.SimdVectorReg D15 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypF32))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (7)``() =
    "f3b400c2"
    ++ VREV32 ** [ O.SimdVectorReg Q0; O.SimdVectorReg Q1 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTyp16))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (8)``() =
    "f3b35b43"
    ++ VTBX ** [ O.SimdVectorReg D5
                 O.SimdVectorRegs [ D3; D4; D5; D6 ]
                 O.SimdVectorReg D3 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTyp8))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (1)``() =
    "eeb50bc0"
    ++ VCMPE ** [ O.SimdVectorReg D0; O.Imm 0L ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypF64))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (2)``() =
    "eeb82a68"
    ++ VCVT ** [ O.SimdVectorReg S4; O.SimdVectorReg S17 ]
    ||> testNoWbackNoQ Condition.AL (Some(TwoDT(SIMDTypF32, SIMDTypU32)))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (3)``() =
    "eeb30a43"
    ++ VCVTB ** [ O.SimdVectorReg S0; O.SimdVectorReg S6 ]
    ||> testNoWbackNoQ Condition.AL (Some(TwoDT(SIMDTypF16, SIMDTypF32)))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (4)``() =
    "eeb23a02"
    ++ VMOV ** [ O.SimdVectorReg S6; O.Imm 1091567616L ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypF32))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (5)``() =
    "f3d2c460"
    ++ VMLS ** [ O.SimdVectorReg Q14
                 O.SimdVectorReg Q1
                 O.SimdScalarReg(D0, Some 2uy) ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypI16))

  /// The narrowing moves are the I<size> forms of the manual: the size names
  /// the elements READ, which are twice as wide as the ones written, and it
  /// carries no signedness because the move keeps the low half either way.
  [<TestMethod>]
  member _.``[ARMv7] VMOVN names the width it reads``() =
    "f3b20202"
    ++ VMOVN ** [ O.SimdVectorReg D0; O.SimdVectorReg Q1 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypI16))

  [<TestMethod>]
  member _.``[ARMv7] VQSUB names quadwords in its Q form``() =
    "f2020254"
    ++ VQSUB ** [ O.SimdVectorReg Q0; O.SimdVectorReg Q1; O.SimdVectorReg Q2 ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypS8))

  /// VQSHLU reads signed elements and saturates into unsigned ones, so the U
  /// bit its encoding sets says which instruction this is and not how the
  /// elements are read.
  [<TestMethod>]
  member _.``[ARMv7] VQSHLU keeps a signed data type``() =
    "f3890611"
    ++ VQSHLU ** [ O.SimdVectorReg D0; O.SimdVectorReg D1; O.Imm 1L ]
    ||> testNoWbackNoQ Condition.UN (Some(OneDT SIMDTypS8))

  /// TSB CSYNC names its option, which is part of what it is written as.
  [<TestMethod>]
  member _.``[ARMv7] TSB CSYNC names its option``() =
    testDisasm "e320f012" "tsb csync"

  /// RRX rotates by exactly one place and is written with no amount.
  [<TestMethod>]
  member _.``[ARMv7] An RRX operand takes no amount``() =
    testDisasm "e0010064" "and r0, r1, r4, rrx"

  /// VMOV.F32 builds a single-precision number from its eight bits the way
  /// AdvSIMDExpandImm does (J1-7926): sign, an exponent whose top bit is the
  /// inverse of the bit below it, and four bits of fraction.
  [<TestMethod>]
  member _.``[ARMv7] VMOV.F32 (immediate) expands its constant``() =
    testDisasm "f2810f14" "vmov.f32 d0, #0x40a00000"

  /// The sign is the i bit, bit 24 of an A32 word.
  [<TestMethod>]
  member _.``[ARMv7] VMOV.F32 (immediate) takes its sign from i``() =
    testDisasm "f3810f14" "vmov.f32 d0, #0xc0a00000"

  /// With the bit the exponent is built from set, the inverted one is clear.
  [<TestMethod>]
  member _.``[ARMv7] VMOV.F32 (immediate) inverts its exponent bit``() =
    testDisasm "f2850f10" "vmov.f32 d0, #0x3e800000"

  /// The quadword form holds the same constant, all four bytes of it.
  [<TestMethod>]
  member _.``[ARMv7] VMOV.F32 (immediate) to a quadword keeps the constant``() =
    testDisasm "f2810f54" "vmov.f32 q0, #0x40a00000"

  /// cmode 1100 shifts the byte in over eight ones, and 1101 over sixteen.
  [<TestMethod>]
  member _.``[ARMv7] VMOV.I32 (immediate) shifts in eight ones``() =
    testDisasm "f2850c1a" "vmov.i32 d0, #0x5aff"

  [<TestMethod>]
  member _.``[ARMv7] VMOV.I32 (immediate) shifts in sixteen ones``() =
    testDisasm "f2850d1a" "vmov.i32 d0, #0x5affff"

  /// VMVN builds the same two constants: which one cmode names does not
  /// depend on op.
  [<TestMethod>]
  member _.``[ARMv7] VMVN.I32 (immediate) shifts in eight ones``() =
    testDisasm "f2850c3a" "vmvn.i32 d0, #0x5aff"

  [<TestMethod>]
  member _.``[ARMv7] VMVN.I32 (immediate) shifts in sixteen ones``() =
    testDisasm "f2850d3a" "vmvn.i32 d0, #0x5affff"

  /// DBG names the option it passes to the debug system (F5-4385).
  [<TestMethod>]
  member _.``[ARMv7] DBG names its option``() =
    testDisasm "e320f0f4" "dbg #0x4"

  /// SHA256H2 is written as one word with its data type, as every other SHA
  /// instruction is.
  [<TestMethod>]
  member _.``[ARMv7] SHA256H2 is written as one word``() =
    testDisasm "f3100c40" "sha256h2.32 q0, q0, q0"

  /// <summary>
  /// The floating-point instructions are the coprocessor space with 10 in bits
  /// 11:10: coprocessors 10 and 11, and 9 for half precision. The four above
  /// them are not floating-point either, and hold no CDP: ARMv7 reserves 12
  /// and 13 (A2.9) and makes every CDP to 14 and 15 UNDEFINED (B3.15.2).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] CDP to coprocessors 12 to 15 is UNDEFINED``() =
    testRefused "ee000c00"
    testRefused "ee000d00"
    testRefused "ee000e00"
    testRefused "ee000f00"

  /// Coprocessor 9 is where Armv8.2 put the half-precision arithmetic.
  [<TestMethod>]
  member _.``[ARMv7] VMLA.F16 is coprocessor 9's``() =
    testDisasm "ee000900" "vmla.f16 s0, s0, s0"

  /// A register list that runs past the last register names registers that do
  /// not exist. The manual calls it UNPREDICTABLE, but there is nothing for any
  /// build to read, so every build refuses it: here d31 and the one after it.
  [<TestMethod>]
  member _.``[ARMv7] VLDM past D31 is refused in every build``() =
    testRefused "ecd0fb04"

  /// The same for the single-precision list, s31 and the one after it.
  [<TestMethod>]
  member _.``[ARMv7] VLDM past S31 is refused in every build``() =
    testRefused "ecd0fa02"

  /// MSR names SPSR with its R bit, bit 22, as MRS does.
  [<TestMethod>]
  member _.``[ARMv7] MSR (register) can name SPSR``() =
    testDisasm "e16ff001" "msr spsr_fsxc, r1"

  [<TestMethod>]
  member _.``[ARMv7] MSR (immediate) can name SPSR``() =
    testDisasm "e368f0ff" "msr spsr_f, #0xff"

  /// An immediate MSR to SPSR that names no field is UNPREDICTABLE (DDI0406C
  /// B9.3.11); the same encoding for CPSR is a hint.
  [<TestMethod>]
  member _.``[ARMv7] MSR (immediate) to SPSR with no field is refused``() =
    testRefused "e360f004"

  /// VMRS and VMSR name the floating-point system register their reg field
  /// selects (DDI0406C B9.3.21 and B9.3.22; DDI0487F.c F6.1.144 adds MVFR2).
  [<TestMethod>]
  member _.``[ARMv7] VMRS can name FPSID``() =
    testDisasm "eef00a10" "vmrs r0, fpsid"

  [<TestMethod>]
  member _.``[ARMv7] VMRS can name FPSCR``() =
    testDisasm "eef10a10" "vmrs r0, fpscr"

  [<TestMethod>]
  member _.``[ARMv7] VMRS can name MVFR2``() =
    testDisasm "eef50a10" "vmrs r0, mvfr2"

  [<TestMethod>]
  member _.``[ARMv7] VMRS can name MVFR1``() =
    testDisasm "eef60a10" "vmrs r0, mvfr1"

  [<TestMethod>]
  member _.``[ARMv7] VMRS can name MVFR0``() =
    testDisasm "eef70a10" "vmrs r0, mvfr0"

  [<TestMethod>]
  member _.``[ARMv7] VMRS can name FPEXC``() =
    testDisasm "eef80a10" "vmrs r0, fpexc"

  [<TestMethod>]
  member _.``[ARMv7] VMSR can name FPSID``() =
    testDisasm "eee00a10" "vmsr fpsid, r0"

  [<TestMethod>]
  member _.``[ARMv7] VMSR can name FPEXC``() =
    testDisasm "eee80a10" "vmsr fpexc, r0"

  /// A reg field that names no register is UNPREDICTABLE, and there is no
  /// register for any build to read.
  [<TestMethod>]
  member _.``[ARMv7] VMRS of no register is refused in every build``() =
    testRefused "eef20a10"

  /// VMSR names only FPSID, FPSCR and FPEXC; the MVFRs are read-only.
  [<TestMethod>]
  member _.``[ARMv7] VMSR to MVFR0 is refused in every build``() =
    testRefused "eee70a10"

  /// MVFR2 is Armv8's, which no ARMv7 version has.
  [<TestMethod>]
  member _.``[ARMv7] VMRS of MVFR2 is Armv8's``() =
    readsOnlyUnder "eef50a10" [ "armv7" ] [ "armv7-v7ve+simd+vfpv4" ]

  /// <summary>
  /// VCMLA (vector) takes its rotation from op1, so it is every word of the
  /// extension space's xx1x00x0 (DDI0487F.c F6.1.52), not only rotation 0.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCMLA (vector) decodes at every rotation``() =
    testDisasm "fc310802" "vcmla.f32 d0, d1, d2, #0x0"
    testDisasm "fcb10802" "vcmla.f32 d0, d1, d2, #0x5a"
    testDisasm "fd310802" "vcmla.f32 d0, d1, d2, #0xb4"
    testDisasm "fdb20844" "vcmla.f32 q0, q1, q2, #0x10e"
    testDisasm "fca10802" "vcmla.f16 d0, d1, d2, #0x5a"

  /// The half-precision VCADD and VCMLA leave bit 20 clear, which ARMv7's
  /// STC2 decoder used to take: coprocessor 8 is reserved to ARMv7.
  [<TestMethod>]
  member _.``[ARMv7] VCADD.F16 is not STC2``() =
    testDisasm "fc810802" "vcadd.f16 d0, d1, d2, #0x5a"
    readsOnlyUnder "fc810802" [ "armv7" ] [ "armv7-v7ve+simd+vfpv4" ]

  /// A quadword by element names an even destination and first source; an
  /// odd one is UNDEFINED, as it is for the doubleword form's Q check.
  [<TestMethod>]
  member _.``[ARMv7] VCMLA.F16 by element refuses an odd quadword``() =
    testRefused "fe021842"

  /// It is Armv8.3's, which no ARMv7 version has.
  [<TestMethod>]
  member _.``[ARMv7] VCMLA (vector) is Armv8.3's``() =
    readsOnlyUnder "fcb10802" [ "armv7" ] [ "armv7-v7ve+simd+vfpv4" ]

  /// The dot products and the matrix multiplies leave bit 20 clear in
  /// coprocessors 12 and 13, which ARMv7's STC2 decoder used to take: those
  /// are reserved to ARMv7 as 8 and 9 are (A2.9).
  [<TestMethod>]
  member _.``[ARMv7] The dot products are not STC2``() =
    testDisasm "fc210d02" "vsdot.s8 d0, d1, d2"
    testDisasm "fca10d02" "vusdot.s8 d0, d1, d2"
    testDisasm "fc010d02" "vdot.bf16 d0, d1, d2"
    testDisasm "fc220c44" "vsmmla.s8 q0, q1, q2"
    testDisasm "fc020c44" "vmmla.bf16 q0, q1, q2"

  /// VCVTA and the other directed conversions name the integer they write
  /// first, as every conversion names its result first (DDI0487F.c F6.1.66).
  [<TestMethod>]
  member _.``[ARMv7] VCVTA names the integer it writes first``() =
    testDisasm "febc0ac0" "vcvta.s32.f32 s0, s0"
    testDisasm "febf0b41" "vcvtm.u32.f64 s0, d1"

  /// The brain floating-point VCVTB narrows a single (DDI0487F.c F6.1.68).
  [<TestMethod>]
  member _.``[ARMv7] VCVTB.BF16 converts from a single``() =
    testDisasm "eeb30941" "vcvtb.bf16.f32 s0, s2"

  /// VFMAL by one element writes a doubleword from single-precision registers,
  /// so the element is one of a single's halves (DDI0487F.c F6.1.90).
  [<TestMethod>]
  member _.``[ARMv7] VFMAL by an element names a single``() =
    testDisasm "fe000819" "vfmal.f16 d0, s0, s2[1]"

  /// A fixed-point VCVT that counts more fraction bits than its integer holds
  /// is UNPREDICTABLE (DDI0406C A8.8.309), and is refused.
  [<TestMethod>]
  member _.``[ARMv7] VCVT to fixed point refuses negative fraction bits``() =
    testDisasm "eeba0a40" "vcvt.f32.s16 s0, s0, #0x10"
    testRefused "eeba0a4f"

  /// FLDMX and FSTMX are told from VLDM and VSTM by imm8<0>, so a list of
  /// two registers, imm8 = 5, is FLDMIAX (DDI0406C A8.8.51).
  [<TestMethod>]
  member _.``[ARMv7] FLDMIAX of an even count decodes``() =
    testDisasm "ecb00b05" "fldmiax r0!, {d0, d1}"
    testDisasm "eca00b05" "fstmiax r0!, {d0, d1}"

  /// <summary>
  /// The Advanced SIMD VCVT between halves and singles checks the register
  /// it reads a quadword from or writes one to, and only that one (DDI0406C
  /// A8.8.311): an odd Qm is UNDEFINED when it narrows, an odd Qd when it
  /// widens, and the doubleword on the other side may be odd.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] VCVT between halves and singles checks the quadword``() =
    testDisasm "f3b60701" "vcvt.f32.f16 q0, d1"
    testDisasm "f3b61600" "vcvt.f16.f32 d1, q0"
    testRefused "f3b60601"
    testRefused "f3b61700"

  /// The Advanced SIMD VCVT between halves and integers converts to and from
  /// 16-bit integers (DDI0487F.c F6.1.60).
  [<TestMethod>]
  member _.``[ARMv7] VCVT.U16.F16 names 16-bit integers``() =
    testDisasm "f3b7478f" "vcvt.u16.f16 d4, d15"

  /// VLDR of a half names its size, which tells it from VLDR of a single.
  [<TestMethod>]
  member _.``[ARMv7] VLDR.16 names its size``() =
    testDisasm "ed1b7947" "vldr.16 s14, [fp, #-0x8e]"

  /// <summary>
  /// ARMv7 leaves coprocessors 0 to 7 to implementations: CDP, MCR and MRC,
  /// MCRR and MRRC, LDC and STC, and in the unconditional encoding the forms
  /// named 2 (DDI0406C A5.6 and A5.7). Bit 4 tells a transfer to a core
  /// register from a CDP, and D a long transfer.
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] The ordinary coprocessors take every instruction``() =
    testDisasm "ee000010" "mcr p0, #0x0, r0, c0, c0, #0x0"
    testDisasm "ee100010" "mrc p0, #0x0, r0, c0, c0, #0x0"
    testDisasm "ee0b41e5" "cdp p1, #0x0, c4, c11, c5, #0x7"
    testDisasm "ee2b41e5" "cdp p1, #0x2, c4, c11, c5, #0x7"
    testDisasm "ed911100" "ldc p1, c1, [r1]"
    testDisasm "edd11100" "ldcl p1, c1, [r1]"
    testDisasm "ed811100" "stc p1, c1, [r1]"
    testDisasm "edc11100" "stcl p1, c1, [r1]"
    testDisasm "ec410203" "mcrr p2, #0x0, r0, r1, c3"
    testDisasm "ec510203" "mrrc p2, #0x0, r0, r1, c3"

  [<TestMethod>]
  member _.``[ARMv7] The unconditional coprocessor forms are named 2``() =
    testDisasm "fe000300" "cdp2 p3, #0x0, c0, c0, c0, #0x0"
    testDisasm "fe2b41e5" "cdp2 p1, #0x2, c4, c11, c5, #0x7"
    testDisasm "fe000310" "mcr2 p3, #0x0, r0, c0, c0, #0x0"
    testDisasm "fe100310" "mrc2 p3, #0x0, r0, c0, c0, #0x0"
    testDisasm "fd911100" "ldc2 p1, c1, [r1]"
    testDisasm "fc410203" "mcrr2 p2, #0x0, r0, r1, c3"
    testDisasm "fc510203" "mrrc2 p2, #0x0, r0, r1, c3"
    testDisasm "fdd11100" "ldc2l p1, c1, [r1]"
    testDisasm "fc6485df" "stc2l p5, c8, [r4], #-0x37c"

  /// STC2 is UNDEFINED on the floating-point coprocessors and on 14 and 15.
  [<TestMethod>]
  member _.``[ARMv7] STC2 to coprocessors 10 and 14 is UNDEFINED``() =
    testRefused "fc200a00"
    testRefused "fc200e00"

  /// <summary>
  /// What the manual makes UNPREDICTABLE in them is refused: an MCR from the
  /// PC, an MCRR from it, an MRRC to one register twice, and an STC that
  /// writes its address back to the PC (DDI0406C A8.8.99, A8.8.100, A8.8.109
  /// and A8.8.199).
  /// </summary>
  [<TestMethod>]
  member _.``[ARMv7] The ordinary coprocessors refuse UNPREDICTABLE forms``() =
    testRefused "ee00f010"
    testRefused "ec4f0000"
    testRefused "ec511100"
    testRefused "ed2f1100"

  /// Armv8 keeps none of the ordinary coprocessors.
  [<TestMethod>]
  member _.``[ARMv7] The ordinary coprocessors are ARMv7's alone``() =
    readsOnlyUnder "ee000010" [ "armv7-v7" ] [ "aarch32" ]

  /// A Q register is an even pair of D registers, so VDUP from a core register
  /// with Q set and Vd odd is UNDEFINED (DDI0406C A8.8.315). Vd sits where the
  /// other Advanced SIMD instructions keep Vn, in bits 19 to 16.
  [<TestMethod>]
  member _.``[ARMv7] VDUP to a Q register refuses an odd Vd``() =
    testDisasm "eea02b10" "vdup.32 q0, r2"
    testRefused "eea12b14"
    testRefused "eee12b10"
    testRefused "eea12b30"

  /// An MRC whose Rt field is 15 names APSR_nzcv: it writes the flags from the
  /// top four bits of what it reads, never the PC (DDI0406C A8.8.108 and
  /// DDI0487F.c F5.1.115, which Armv8 reads too). An MCR from the PC stays
  /// refused.
  [<TestMethod>]
  member _.``[ARMv7] MRC to Rt 15 names APSR_nzcv``() =
    let text = "mrc p14, #0x0, apsr_nzcv, c1, c4, #0x0"
    testDisasm "ee11fe14" text
    testDisasm "ee10ff10" "mrc p15, #0x0, apsr_nzcv, c0, c0, #0x0"
    testDisasm "fe10f310" "mrc2 p3, #0x0, apsr_nzcv, c0, c0, #0x0"
    testRefused "ee00ff10"
    Assert.AreEqual<string option>(Some text, under "aarch32" "ee11fe14")

  /// TSB CSYNC (DDI0487F.c F5.1.261, Armv8.4): binutils 2.42 has no AArch32
  /// TSB, so this is the manual's encoding, cond 0011 0010 0000 1111 0000
  /// 0000 0001 0010, written out by hand.
  [<TestMethod>]
  member _.``[ARMv8] TSB CSYNC``() =
    testDisasm "e320f012" "tsb csync"

  (* One test for each A32 instruction DDI0406C and DDI0487F.c's AArch32
     chapters describes, in the order of its sections. Each reads words of the
     instruction and checks the text, and each word is one binutils' objdump
     reads as the same instruction with the same operands, so what is asserted
     is a reading two decoders agree on. *)
  /// A8.8.1 ADC (immediate)
  [<TestMethod>]
  member _.``A8.8.1 ADC``() =
    testDisasm "e0a00002" "adc r0, r0, r2"
    testDisasm "e0b10002" "adcs r0, r1, r2"
    testDisasm "e0a10082" "adc r0, r1, r2, lsl #0x1"
    testDisasm "e0a101a2" "adc r0, r1, r2, lsr #0x3"

  /// A8.8.100 MCRR, MCRR2
  [<TestMethod>]
  member _.``A8.8.100 MCRR``() =
    testDisasm "ec412e04" "mcrr p14, #0x0, r2, r1, c4"
    testDisasm "ec41de04" "mcrr p14, #0x0, sp, r1, c4"
    testDisasm "ec492e04" "mcrr p14, #0x0, r2, sb, c4"
    testDisasm "ec49de04" "mcrr p14, #0x0, sp, sb, c4"

  /// A8.8.100 MCRR, MCRR2
  [<TestMethod>]
  member _.``A8.8.100 MCRR2``() =
    testDisasm "fc432314" "mcrr2 p3, #0x1, r2, r3, c4"

  /// A8.8.101 MLA
  [<TestMethod>]
  member _.``A8.8.101 MLA``() =
    testDisasm "e0203291" "mla r0, r1, r2, r3"
    testDisasm "e0303291" "mlas r0, r1, r2, r3"
    testDisasm "e0212994" "mla r1, r4, sb, r2"
    testDisasm "e0212a94" "mla r1, r4, sl, r2"

  /// A8.8.102 MLS
  [<TestMethod>]
  member _.``A8.8.102 MLS``() =
    testDisasm "e0603291" "mls r0, r1, r2, r3"
    testDisasm "e0612994" "mls r1, r4, sb, r2"
    testDisasm "e0612a94" "mls r1, r4, sl, r2"
    testDisasm "e0612b94" "mls r1, r4, fp, r2"

  /// A8.8.103 MOV (immediate)
  [<TestMethod>]
  member _.``A8.8.103 MOV``() =
    testDisasm "e3a00003" "mov r0, #0x3"
    testDisasm "e1a00002" "mov r0, r2"
    testDisasm "e1b00002" "movs r0, r2"
    testDisasm "e1a0200f" "mov r2, pc"

  /// A8.8.107 MOVT
  [<TestMethod>]
  member _.``A8.8.107 MOVT``() =
    testDisasm "e3400007" "movt r0, #0x7"
    testDisasm "e341d004" "movt sp, #0x1004"
    testDisasm "e341f004" "movt pc, #0x1004"
    testDisasm "13412004" "movtne r2, #0x1004"

  /// A8.8.108 MRC, MRC2
  [<TestMethod>]
  member _.``A8.8.108 MRC``() =
    testDisasm "ee112e14" "mrc p14, #0x0, r2, c1, c4, #0x0"
    testDisasm "ee11de14" "mrc p14, #0x0, sp, c1, c4, #0x0"
    testDisasm "ee11fe14" "mrc p14, #0x0, apsr_nzcv, c1, c4, #0x0"
    testDisasm "1e112e14" "mrcne p14, #0x0, r2, c1, c4, #0x0"

  /// A8.8.108 MRC, MRC2
  [<TestMethod>]
  member _.``A8.8.108 MRC2``() =
    testDisasm "fe3323b4" "mrc2 p3, #0x1, r2, c3, c4, #0x5"

  /// A8.8.109 MRRC, MRRC2
  [<TestMethod>]
  member _.``A8.8.109 MRRC``() =
    testDisasm "ec512e04" "mrrc p14, #0x0, r2, r1, c4"
    testDisasm "ec51de04" "mrrc p14, #0x0, sp, r1, c4"
    testDisasm "ec592e04" "mrrc p14, #0x0, r2, sb, c4"
    testDisasm "ec59de04" "mrrc p14, #0x0, sp, sb, c4"

  /// A8.8.109 MRRC, MRRC2
  [<TestMethod>]
  member _.``A8.8.109 MRRC2``() =
    testDisasm "fc532314" "mrrc2 p3, #0x1, r2, r3, c4"

  /// A8.8.110 MRS
  [<TestMethod>]
  member _.``A8.8.110 MRS``() =
    testDisasm "e1012200" "mrs r2, r9_usr"
    testDisasm "e1012300" "mrs r2, sp_irq"
    testDisasm "e101d200" "mrs sp, r9_usr"
    testDisasm "e101d300" "mrs sp, sp_irq"

  /// A8.8.112 MSR (immediate)
  [<TestMethod>]
  member _.``A8.8.112 MSR``() =
    testDisasm "e321f004" "msr cpsr_c, #0x4"
    testDisasm "e329f004" "msr cpsr_fc, #0x4"
    testDisasm "e32df004" "msr cpsr_fsc, #0x4"
    testDisasm "e32ff004" "msr cpsr_fsxc, #0x4"

  /// A8.8.115 MUL
  [<TestMethod>]
  member _.``A8.8.115 MUL``() =
    testDisasm "e0100091" "muls r0, r1, r0"
    testDisasm "e0000291" "mul r0, r1, r2"
    testDisasm "e0012994" "mul r1, r4, sb"
    testDisasm "e0012a94" "mul r1, r4, sl"

  /// A8.8.116 MVN (immediate)
  [<TestMethod>]
  member _.``A8.8.116 MVN``() =
    testDisasm "e1e00002" "mvn r0, r2"
    testDisasm "e1f00002" "mvns r0, r2"
    testDisasm "e1e00082" "mvn r0, r2, lsl #0x1"
    testDisasm "e1e001a2" "mvn r0, r2, lsr #0x3"

  /// A8.8.119 NEG
  [<TestMethod>]
  member _.``A8.8.119 NEG``() =
    testDisasm "e2620000" "rsb r0, r2, #0x0"
    testDisasm "e2712000" "rsbs r2, r1, #0x0"
    testDisasm "12612000" "rsbne r2, r1, #0x0"
    testDisasm "12712000" "rsbsne r2, r1, #0x0"

  /// A8.8.120 NOP
  [<TestMethod>]
  member _.``A8.8.120 NOP``() =
    testDisasm "e320f000" "nop"

  /// A8.8.123 ORR (immediate)
  [<TestMethod>]
  member _.``A8.8.123 ORR``() =
    testDisasm "e1800002" "orr r0, r0, r2"
    testDisasm "e1910002" "orrs r0, r1, r2"
    testDisasm "e1810082" "orr r0, r1, r2, lsl #0x1"
    testDisasm "e18101a2" "orr r0, r1, r2, lsr #0x3"

  /// A8.8.126 PKH
  [<TestMethod>]
  member _.``A8.8.126 PKH``() =
    testDisasm "e6810212" "pkhbt r0, r1, r2, lsl #0x4"
    testDisasm "e6810252" "pkhtb r0, r1, r2, asr #0x4"
    testDisasm "e6810012" "pkhbt r0, r1, r2"
    testDisasm "e681d014" "pkhbt sp, r1, r4"

  /// A8.8.127 PLD, PLDW (immediate)
  [<TestMethod>]
  member _.``A8.8.127 PLD``() =
    testDisasm "f5d1f007" "pld [r1, #0x7]"
    testDisasm "f55ff004" "pld [0x4]"
    testDisasm "f7d1f002" "pld [r1, r2]"
    testDisasm "f5d1f000" "pld [r1]"

  /// A8.8.127 PLD, PLDW (immediate)
  [<TestMethod>]
  member _.``A8.8.127 PLDW``() =
    testDisasm "f591f007" "pldw [r1, #0x7]"
    testDisasm "f791f002" "pldw [r1, r2]"
    testDisasm "f591f000" "pldw [r1]"
    testDisasm "f519f000" "pldw [sb]"

  /// A8.8.13 AND (immediate)
  [<TestMethod>]
  member _.``A8.8.13 AND``() =
    testDisasm "e0000002" "and r0, r0, r2"
    testDisasm "e0110002" "ands r0, r1, r2"
    testDisasm "e0010082" "and r0, r1, r2, lsl #0x1"
    testDisasm "e00101a2" "and r0, r1, r2, lsr #0x3"

  /// A8.8.130 PLI (immediate, literal)
  [<TestMethod>]
  member _.``A8.8.130 PLI``() =
    testDisasm "f45ff004" "pli [0x4]"
    testDisasm "f6d1f002" "pli [r1, r2]"
    testDisasm "f651f004" "pli [r1, -r4]"
    testDisasm "f651f104" "pli [r1, -r4, lsl #0x2]"

  /// A8.8.132 POP (Thumb)
  [<TestMethod>]
  member _.``A8.8.132 POP``() =
    testDisasm "e8bd000c" "pop {r2, r3}"
    testDisasm "e49d2004" "pop {r2}"
    testDisasm "e49df004" "pop {pc}"
    testDisasm "e8bd000f" "pop {r0, r1, r2, r3}"

  /// A8.8.134 PUSH
  [<TestMethod>]
  member _.``A8.8.134 PUSH``() =
    testDisasm "e92d000c" "push {r2, r3}"
    testDisasm "e52d2004" "push {r2}"
    testDisasm "e52df004" "push {pc}"
    testDisasm "e92d2004" "push {r2, sp}"

  /// A8.8.135 QADD
  [<TestMethod>]
  member _.``A8.8.135 QADD``() =
    testDisasm "e1020051" "qadd r0, r1, r2"
    testDisasm "e101d054" "qadd sp, r4, r1"
    testDisasm "e1092054" "qadd r2, r4, sb"
    testDisasm "e109d054" "qadd sp, r4, sb"

  /// A8.8.136 QADD16
  [<TestMethod>]
  member _.``A8.8.136 QADD16``() =
    testDisasm "e6210f12" "qadd16 r0, r1, r2"

  /// A8.8.137 QADD8
  [<TestMethod>]
  member _.``A8.8.137 QADD8``() =
    testDisasm "e6210f92" "qadd8 r0, r1, r2"

  /// A8.8.138 QASX
  [<TestMethod>]
  member _.``A8.8.138 QASX``() =
    testDisasm "e6210f32" "qasx r0, r1, r2"

  /// A8.8.139 QDADD
  [<TestMethod>]
  member _.``A8.8.139 QDADD``() =
    testDisasm "e1420051" "qdadd r0, r1, r2"
    testDisasm "e141205f" "qdadd r2, pc, r1"
    testDisasm "e141d054" "qdadd sp, r4, r1"
    testDisasm "e141d05f" "qdadd sp, pc, r1"

  /// A8.8.140 QDSUB
  [<TestMethod>]
  member _.``A8.8.140 QDSUB``() =
    testDisasm "e1620051" "qdsub r0, r1, r2"
    testDisasm "e161205f" "qdsub r2, pc, r1"
    testDisasm "e161d054" "qdsub sp, r4, r1"
    testDisasm "e161d05f" "qdsub sp, pc, r1"

  /// A8.8.141 QSAX
  [<TestMethod>]
  member _.``A8.8.141 QSAX``() =
    testDisasm "e6210f52" "qsax r0, r1, r2"

  /// A8.8.142 QSUB
  [<TestMethod>]
  member _.``A8.8.142 QSUB``() =
    testDisasm "e1220051" "qsub r0, r1, r2"
    testDisasm "e121205f" "qsub r2, pc, r1"
    testDisasm "e121d054" "qsub sp, r4, r1"
    testDisasm "e121d05f" "qsub sp, pc, r1"

  /// A8.8.143 QSUB16
  [<TestMethod>]
  member _.``A8.8.143 QSUB16``() =
    testDisasm "e6210f72" "qsub16 r0, r1, r2"

  /// A8.8.144 QSUB8
  [<TestMethod>]
  member _.``A8.8.144 QSUB8``() =
    testDisasm "e6210ff2" "qsub8 r0, r1, r2"

  /// A8.8.145 RBIT
  [<TestMethod>]
  member _.``A8.8.145 RBIT``() =
    testDisasm "e6ff0f31" "rbit r0, r1"

  /// A8.8.146 REV
  [<TestMethod>]
  member _.``A8.8.146 REV``() =
    testDisasm "e6bf0f31" "rev r0, r1"

  /// A8.8.147 REV16
  [<TestMethod>]
  member _.``A8.8.147 REV16``() =
    testDisasm "e6bf0fb1" "rev16 r0, r1"

  /// A8.8.148 REVSH
  [<TestMethod>]
  member _.``A8.8.148 REVSH``() =
    testDisasm "e6ff0fb1" "revsh r0, r1"

  /// A8.8.149 RFE
  [<TestMethod>]
  member _.``A8.8.149 RFE``() =
    testDisasm "f8910a00" "rfeia r1"
    testDisasm "f8310a00" "rfeda r1!"
    testDisasm "f9110a00" "rfedb r1"
    testDisasm "f9b10a00" "rfeib r1!"

  /// A8.8.150 ROR (immediate)
  [<TestMethod>]
  member _.``A8.8.150 ROR``() =
    testDisasm "e1a00862" "ror r0, r2, #0x10"
    testDisasm "e1b00862" "rors r0, r2, #0x10"
    testDisasm "e1a00270" "ror r0, r0, r2"
    testDisasm "e1b00271" "rors r0, r1, r2"

  /// A8.8.152 RRX
  [<TestMethod>]
  member _.``A8.8.152 RRX``() =
    testDisasm "e1b00062" "rrxs r0, r2"
    testDisasm "e1a00062" "rrx r0, r2"
    testDisasm "e1a0206f" "rrx r2, pc"
    testDisasm "e1a0d064" "rrx sp, r4"

  /// A8.8.153 RSB (immediate)
  [<TestMethod>]
  member _.``A8.8.153 RSB``() =
    testDisasm "e0610002" "rsb r0, r1, r2"
    testDisasm "e0710002" "rsbs r0, r1, r2"
    testDisasm "e0610082" "rsb r0, r1, r2, lsl #0x1"
    testDisasm "e06101a2" "rsb r0, r1, r2, lsr #0x3"

  /// A8.8.156 RSC (immediate)
  [<TestMethod>]
  member _.``A8.8.156 RSC``() =
    testDisasm "e2e10000" "rsc r0, r1, #0x0"
    testDisasm "e0e10002" "rsc r0, r1, r2"
    testDisasm "e0f10002" "rscs r0, r1, r2"
    testDisasm "e0e10082" "rsc r0, r1, r2, lsl #0x1"

  /// A8.8.159 SADD16
  [<TestMethod>]
  member _.``A8.8.159 SADD16``() =
    testDisasm "e6110f12" "sadd16 r0, r1, r2"

  /// A8.8.16 ASR (immediate)
  [<TestMethod>]
  member _.``A8.8.16 ASR``() =
    testDisasm "e1a00842" "asr r0, r2, #0x10"
    testDisasm "e1b00842" "asrs r0, r2, #0x10"
    testDisasm "e1a00250" "asr r0, r0, r2"
    testDisasm "e1b00251" "asrs r0, r1, r2"

  /// A8.8.160 SADD8
  [<TestMethod>]
  member _.``A8.8.160 SADD8``() =
    testDisasm "e6110f92" "sadd8 r0, r1, r2"

  /// A8.8.161 SASX
  [<TestMethod>]
  member _.``A8.8.161 SASX``() =
    testDisasm "e6110f32" "sasx r0, r1, r2"

  /// A8.8.162 SBC (immediate)
  [<TestMethod>]
  member _.``A8.8.162 SBC``() =
    testDisasm "e0c00002" "sbc r0, r0, r2"
    testDisasm "e0d10002" "sbcs r0, r1, r2"
    testDisasm "e0c10082" "sbc r0, r1, r2, lsl #0x1"
    testDisasm "e0c101a2" "sbc r0, r1, r2, lsr #0x3"

  /// A8.8.165 SBFX
  [<TestMethod>]
  member _.``A8.8.165 SBFX``() =
    testDisasm "e7a401d1" "sbfx r0, r1, #0x3, #0x5"
    testDisasm "e7a1d054" "sbfx sp, r4, #0x0, #0x2"
    testDisasm "17a12054" "sbfxne r2, r4, #0x0, #0x2"
    testDisasm "17a1d054" "sbfxne sp, r4, #0x0, #0x2"

  /// A8.8.166 SDIV
  [<TestMethod>]
  member _.``A8.8.166 SDIV``() =
    testDisasm "e710f211" "sdiv r0, r1, r2"
    testDisasm "e711f914" "sdiv r1, r4, sb"
    testDisasm "e711fa14" "sdiv r1, r4, sl"
    testDisasm "e711fb14" "sdiv r1, r4, fp"

  /// A8.8.167 SEL
  [<TestMethod>]
  member _.``A8.8.167 SEL``() =
    testDisasm "e6810fb2" "sel r0, r1, r2"

  /// A8.8.168 SETEND
  [<TestMethod>]
  member _.``A8.8.168 SETEND``() =
    testDisasm "f1010200" "setend be"
    testDisasm "f1010000" "setend le"

  /// A8.8.169 SEV
  [<TestMethod>]
  member _.``A8.8.169 SEV``() =
    testDisasm "e320f004" "sev"
    testDisasm "1320f004" "sevne"

  /// A8.8.170 SHADD16
  [<TestMethod>]
  member _.``A8.8.170 SHADD16``() =
    testDisasm "e6310f12" "shadd16 r0, r1, r2"

  /// A8.8.171 SHADD8
  [<TestMethod>]
  member _.``A8.8.171 SHADD8``() =
    testDisasm "e6310f92" "shadd8 r0, r1, r2"

  /// A8.8.172 SHASX
  [<TestMethod>]
  member _.``A8.8.172 SHASX``() =
    testDisasm "e6310f32" "shasx r0, r1, r2"

  /// A8.8.173 SHSAX
  [<TestMethod>]
  member _.``A8.8.173 SHSAX``() =
    testDisasm "e6310f52" "shsax r0, r1, r2"

  /// A8.8.174 SHSUB16
  [<TestMethod>]
  member _.``A8.8.174 SHSUB16``() =
    testDisasm "e6310f72" "shsub16 r0, r1, r2"

  /// A8.8.175 SHSUB8
  [<TestMethod>]
  member _.``A8.8.175 SHSUB8``() =
    testDisasm "e6310ff2" "shsub8 r0, r1, r2"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLABB``() =
    testDisasm "e1003281" "smlabb r0, r1, r2, r3"
    testDisasm "e1012984" "smlabb r1, r4, sb, r2"
    testDisasm "e1012a84" "smlabb r1, r4, sl, r2"
    testDisasm "e1012b84" "smlabb r1, r4, fp, r2"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLABT``() =
    testDisasm "e10032c1" "smlabt r0, r1, r2, r3"
    testDisasm "e10129c4" "smlabt r1, r4, sb, r2"
    testDisasm "e1012ac4" "smlabt r1, r4, sl, r2"
    testDisasm "e1012bc4" "smlabt r1, r4, fp, r2"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLATB``() =
    testDisasm "e10032a1" "smlatb r0, r1, r2, r3"
    testDisasm "e10129a4" "smlatb r1, r4, sb, r2"
    testDisasm "e1012aa4" "smlatb r1, r4, sl, r2"
    testDisasm "e1012ba4" "smlatb r1, r4, fp, r2"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLATT``() =
    testDisasm "e10032e1" "smlatt r0, r1, r2, r3"
    testDisasm "e10129e4" "smlatt r1, r4, sb, r2"
    testDisasm "e1012ae4" "smlatt r1, r4, sl, r2"
    testDisasm "e1012be4" "smlatt r1, r4, fp, r2"

  /// A8.8.178 SMLAD
  [<TestMethod>]
  member _.``A8.8.178 SMLAD``() =
    testDisasm "e7003211" "smlad r0, r1, r2, r3"
    testDisasm "e7012914" "smlad r1, r4, sb, r2"
    testDisasm "e7012a14" "smlad r1, r4, sl, r2"
    testDisasm "e7012b14" "smlad r1, r4, fp, r2"

  /// A8.8.179 SMLAL
  [<TestMethod>]
  member _.``A8.8.179 SMLAL``() =
    testDisasm "e0e10392" "smlal r0, r1, r2, r3"
    testDisasm "e0f10291" "smlals r0, r1, r1, r2"
    testDisasm "e0e12994" "smlal r2, r1, r4, sb"
    testDisasm "e0e12a94" "smlal r2, r1, r4, sl"

  /// A8.8.18 B
  [<TestMethod>]
  member _.``A8.8.18 B``() =
    testDisasm "eaffffff" "b 0x4 ; "

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALBB``() =
    testDisasm "e1410382" "smlalbb r0, r1, r2, r3"
    testDisasm "e1412984" "smlalbb r2, r1, r4, sb"
    testDisasm "e1412a84" "smlalbb r2, r1, r4, sl"
    testDisasm "e1412b84" "smlalbb r2, r1, r4, fp"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALBT``() =
    testDisasm "e14103c2" "smlalbt r0, r1, r2, r3"
    testDisasm "e14129c4" "smlalbt r2, r1, r4, sb"
    testDisasm "e1412ac4" "smlalbt r2, r1, r4, sl"
    testDisasm "e1412bc4" "smlalbt r2, r1, r4, fp"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALTB``() =
    testDisasm "e14103a2" "smlaltb r0, r1, r2, r3"
    testDisasm "e14129a4" "smlaltb r2, r1, r4, sb"
    testDisasm "e1412aa4" "smlaltb r2, r1, r4, sl"
    testDisasm "e1412ba4" "smlaltb r2, r1, r4, fp"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALTT``() =
    testDisasm "e14103e2" "smlaltt r0, r1, r2, r3"
    testDisasm "e14129e4" "smlaltt r2, r1, r4, sb"
    testDisasm "e1412ae4" "smlaltt r2, r1, r4, sl"
    testDisasm "e1412be4" "smlaltt r2, r1, r4, fp"

  /// A8.8.181 SMLALD
  [<TestMethod>]
  member _.``A8.8.181 SMLALD``() =
    testDisasm "e7410312" "smlald r0, r1, r2, r3"
    testDisasm "e7412914" "smlald r2, r1, r4, sb"
    testDisasm "e7412a14" "smlald r2, r1, r4, sl"
    testDisasm "e7412b14" "smlald r2, r1, r4, fp"

  /// A8.8.182 SMLAWB, SMLAWT
  [<TestMethod>]
  member _.``A8.8.182 SMLAWB``() =
    testDisasm "e1203281" "smlawb r0, r1, r2, r3"
    testDisasm "e1212984" "smlawb r1, r4, sb, r2"
    testDisasm "e1212a84" "smlawb r1, r4, sl, r2"
    testDisasm "e1212b84" "smlawb r1, r4, fp, r2"

  /// A8.8.182 SMLAWB, SMLAWT
  [<TestMethod>]
  member _.``A8.8.182 SMLAWT``() =
    testDisasm "e12032c1" "smlawt r0, r1, r2, r3"
    testDisasm "e12129c4" "smlawt r1, r4, sb, r2"
    testDisasm "e1212ac4" "smlawt r1, r4, sl, r2"
    testDisasm "e1212bc4" "smlawt r1, r4, fp, r2"

  /// A8.8.183 SMLSD
  [<TestMethod>]
  member _.``A8.8.183 SMLSD``() =
    testDisasm "e7003251" "smlsd r0, r1, r2, r3"
    testDisasm "e7012954" "smlsd r1, r4, sb, r2"
    testDisasm "e7012a54" "smlsd r1, r4, sl, r2"
    testDisasm "e7012b54" "smlsd r1, r4, fp, r2"

  /// A8.8.184 SMLSLD
  [<TestMethod>]
  member _.``A8.8.184 SMLSLD``() =
    testDisasm "e7410352" "smlsld r0, r1, r2, r3"
    testDisasm "e7412954" "smlsld r2, r1, r4, sb"
    testDisasm "e7412a54" "smlsld r2, r1, r4, sl"
    testDisasm "e7412b54" "smlsld r2, r1, r4, fp"

  /// A8.8.185 SMMLA
  [<TestMethod>]
  member _.``A8.8.185 SMMLA``() =
    testDisasm "e7503211" "smmla r0, r1, r2, r3"
    testDisasm "e7512914" "smmla r1, r4, sb, r2"
    testDisasm "e7512a14" "smmla r1, r4, sl, r2"
    testDisasm "e7512b14" "smmla r1, r4, fp, r2"

  /// A8.8.186 SMMLS
  [<TestMethod>]
  member _.``A8.8.186 SMMLS``() =
    testDisasm "e75032d1" "smmls r0, r1, r2, r3"
    testDisasm "e75129d4" "smmls r1, r4, sb, r2"
    testDisasm "e7512ad4" "smmls r1, r4, sl, r2"
    testDisasm "e7512bd4" "smmls r1, r4, fp, r2"

  /// A8.8.187 SMMUL
  [<TestMethod>]
  member _.``A8.8.187 SMMUL``() =
    testDisasm "e750f211" "smmul r0, r1, r2"
    testDisasm "e751f914" "smmul r1, r4, sb"
    testDisasm "e751fa14" "smmul r1, r4, sl"
    testDisasm "e751fb14" "smmul r1, r4, fp"

  /// A8.8.188 SMUAD
  [<TestMethod>]
  member _.``A8.8.188 SMUAD``() =
    testDisasm "e700f211" "smuad r0, r1, r2"
    testDisasm "e701f914" "smuad r1, r4, sb"
    testDisasm "e701fa14" "smuad r1, r4, sl"
    testDisasm "e701fb14" "smuad r1, r4, fp"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULBB``() =
    testDisasm "e1600281" "smulbb r0, r1, r2"
    testDisasm "e1610984" "smulbb r1, r4, sb"
    testDisasm "e1610a84" "smulbb r1, r4, sl"
    testDisasm "e1610b84" "smulbb r1, r4, fp"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULBT``() =
    testDisasm "e16002c1" "smulbt r0, r1, r2"
    testDisasm "e16109c4" "smulbt r1, r4, sb"
    testDisasm "e1610ac4" "smulbt r1, r4, sl"
    testDisasm "e1610bc4" "smulbt r1, r4, fp"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULTB``() =
    testDisasm "e16002a1" "smultb r0, r1, r2"
    testDisasm "e16109a4" "smultb r1, r4, sb"
    testDisasm "e1610aa4" "smultb r1, r4, sl"
    testDisasm "e1610ba4" "smultb r1, r4, fp"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULTT``() =
    testDisasm "e16002e1" "smultt r0, r1, r2"
    testDisasm "e16109e4" "smultt r1, r4, sb"
    testDisasm "e1610ae4" "smultt r1, r4, sl"
    testDisasm "e1610be4" "smultt r1, r4, fp"

  /// A8.8.19 BFC
  [<TestMethod>]
  member _.``A8.8.19 BFC``() =
    testDisasm "e7c7019f" "bfc r0, #0x3, #0x5"
    testDisasm "e7c1d01f" "bfc sp, #0x0, #0x2"
    testDisasm "17c1201f" "bfcne r2, #0x0, #0x2"
    testDisasm "17c1d01f" "bfcne sp, #0x0, #0x2"

  /// A8.8.190 SMULL
  [<TestMethod>]
  member _.``A8.8.190 SMULL``() =
    testDisasm "e0c10392" "smull r0, r1, r2, r3"
    testDisasm "e0d10291" "smulls r0, r1, r1, r2"
    testDisasm "e0c12994" "smull r2, r1, r4, sb"
    testDisasm "e0c12a94" "smull r2, r1, r4, sl"

  /// A8.8.191 SMULWB, SMULWT
  [<TestMethod>]
  member _.``A8.8.191 SMULWB``() =
    testDisasm "e12002a1" "smulwb r0, r1, r2"
    testDisasm "e12109a4" "smulwb r1, r4, sb"
    testDisasm "e1210aa4" "smulwb r1, r4, sl"
    testDisasm "e1210ba4" "smulwb r1, r4, fp"

  /// A8.8.191 SMULWB, SMULWT
  [<TestMethod>]
  member _.``A8.8.191 SMULWT``() =
    testDisasm "e12002e1" "smulwt r0, r1, r2"
    testDisasm "e12109e4" "smulwt r1, r4, sb"
    testDisasm "e1210ae4" "smulwt r1, r4, sl"
    testDisasm "e1210be4" "smulwt r1, r4, fp"

  /// A8.8.192 SMUSD
  [<TestMethod>]
  member _.``A8.8.192 SMUSD``() =
    testDisasm "e700f251" "smusd r0, r1, r2"
    testDisasm "e701f954" "smusd r1, r4, sb"
    testDisasm "e701fa54" "smusd r1, r4, sl"
    testDisasm "e701fb54" "smusd r1, r4, fp"

  /// A8.8.193 SRS
  [<TestMethod>]
  member _.``A8.8.193 SRS``() =
    testDisasm "f8cd0513" "srsia sp, #0x13"
    testDisasm "f8ed0513" "srsia sp!, #0x13"
    testDisasm "f84d0513" "srsda sp, #0x13"
    testDisasm "f96d0513" "srsdb sp!, #0x13"

  /// A8.8.194 SSAT
  [<TestMethod>]
  member _.``A8.8.194 SSAT``() =
    testDisasm "e6a70011" "ssat r0, #0x8, r1"
    testDisasm "e6af0091" "ssat r0, #0x10, r1, lsl #0x1"
    testDisasm "e6af02d1" "ssat r0, #0x10, r1, asr #0x5"
    testDisasm "e6a1d014" "ssat sp, #0x2, r4"

  /// A8.8.195 SSAT16
  [<TestMethod>]
  member _.``A8.8.195 SSAT16``() =
    testDisasm "e6a70f31" "ssat16 r0, #0x8, r1"

  /// A8.8.196 SSAX
  [<TestMethod>]
  member _.``A8.8.196 SSAX``() =
    testDisasm "e6110f52" "ssax r0, r1, r2"

  /// A8.8.197 SSUB16
  [<TestMethod>]
  member _.``A8.8.197 SSUB16``() =
    testDisasm "e6110f72" "ssub16 r0, r1, r2"

  /// A8.8.198 SSUB8
  [<TestMethod>]
  member _.``A8.8.198 SSUB8``() =
    testDisasm "e6110ff2" "ssub8 r0, r1, r2"

  /// A8.8.199 STC, STC2
  [<TestMethod>]
  member _.``A8.8.199 STC2``() =
    testDisasm "fd815302" "stc2 p3, c5, [r1, #0x8]"

  /// A8.8.20 BFI
  [<TestMethod>]
  member _.``A8.8.20 BFI``() =
    testDisasm "e7c70191" "bfi r0, r1, #0x3, #0x5"
    testDisasm "e7c1d014" "bfi sp, r4, #0x0, #0x2"
    testDisasm "17c12014" "bfine r2, r4, #0x0, #0x2"
    testDisasm "17c1d014" "bfine sp, r4, #0x0, #0x2"

  /// A8.8.200 STM (STMIA, STMEA)
  [<TestMethod>]
  member _.``A8.8.200 STM``() =
    testDisasm "e881000c" "stm r1, {r2, r3}"
    testDisasm "e8a1000c" "stm r1!, {r2, r3}"
    testDisasm "e8812004" "stm r1, {r2, sp}"
    testDisasm "e8812000" "stm r1, {sp}"

  /// A8.8.201 STMDA (STMED)
  [<TestMethod>]
  member _.``A8.8.201 STMDA``() =
    testDisasm "e801000c" "stmda r1, {r2, r3}"
    testDisasm "e8012004" "stmda r1, {r2, sp}"
    testDisasm "e8012000" "stmda r1, {sp}"
    testDisasm "e801200f" "stmda r1, {r0, r1, r2, r3, sp}"

  /// A8.8.202 STMDB (STMFD)
  [<TestMethod>]
  member _.``A8.8.202 STMDB``() =
    testDisasm "e901000c" "stmdb r1, {r2, r3}"
    testDisasm "e921000c" "stmdb r1!, {r2, r3}"
    testDisasm "e9012004" "stmdb r1, {r2, sp}"
    testDisasm "e9012000" "stmdb r1, {sp}"

  /// A8.8.203 STMIB (STMFA)
  [<TestMethod>]
  member _.``A8.8.203 STMIB``() =
    testDisasm "e981000c" "stmib r1, {r2, r3}"
    testDisasm "e9812004" "stmib r1, {r2, sp}"
    testDisasm "e9812000" "stmib r1, {sp}"
    testDisasm "e981200f" "stmib r1, {r0, r1, r2, r3, sp}"

  /// A8.8.204 STR (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.204 STR``() =
    testDisasm "e5810010" "str r0, [r1, #0x10]"
    testDisasm "e7810002" "str r0, [r1, r2]"
    testDisasm "e7810082" "str r0, [r1, r2, lsl #0x1]"
    testDisasm "e5810000" "str r0, [r1]"

  /// A8.8.207 STRB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.207 STRB``() =
    testDisasm "e5c10003" "strb r0, [r1, #0x3]"
    testDisasm "e7c10002" "strb r0, [r1, r2]"
    testDisasm "e7c10082" "strb r0, [r1, r2, lsl #0x1]"
    testDisasm "e5c10000" "strb r0, [r1]"

  /// A8.8.21 BIC (immediate)
  [<TestMethod>]
  member _.``A8.8.21 BIC``() =
    testDisasm "e1c00002" "bic r0, r0, r2"
    testDisasm "e1d10002" "bics r0, r1, r2"
    testDisasm "e1c10082" "bic r0, r1, r2, lsl #0x1"
    testDisasm "e1c101a2" "bic r0, r1, r2, lsr #0x3"

  /// A8.8.210 STRBT
  [<TestMethod>]
  member _.``A8.8.210 STRBT``() =
    testDisasm "e4e10000" "strbt r0, [r1], #0x0"
    testDisasm "e461d004" "strbt sp, [r1], #-0x4"
    testDisasm "e4692004" "strbt r2, [sb], #-0x4"
    testDisasm "e469d004" "strbt sp, [sb], #-0x4"

  /// A8.8.211 STRD (immediate)
  [<TestMethod>]
  member _.``A8.8.211 STRD``() =
    testDisasm "e1c100f0" "strd r0, r1, [r1]"
    testDisasm "e00120f4" "strd r2, r3, [r1], -r4"
    testDisasm "e00920f4" "strd r2, r3, [sb], -r4"
    testDisasm "e00d20f4" "strd r2, r3, [sp], -r4"

  /// A8.8.213 STREX
  [<TestMethod>]
  member _.``A8.8.213 STREX``() =
    testDisasm "e1810f92" "strex r0, r2, [r1]"
    testDisasm "e181df94" "strex sp, r4, [r1]"
    testDisasm "e1892f94" "strex r2, r4, [sb]"
    testDisasm "e189df94" "strex sp, r4, [sb]"

  /// A8.8.214 STREXB
  [<TestMethod>]
  member _.``A8.8.214 STREXB``() =
    testDisasm "e1c10f92" "strexb r0, r2, [r1]"
    testDisasm "e1c1df94" "strexb sp, r4, [r1]"
    testDisasm "e1c92f94" "strexb r2, r4, [sb]"
    testDisasm "e1c9df94" "strexb sp, r4, [sb]"

  /// A8.8.215 STREXD
  [<TestMethod>]
  member _.``A8.8.215 STREXD``() =
    testDisasm "e1a10f92" "strexd r0, r2, r3, [r1]"

  /// A8.8.216 STREXH
  [<TestMethod>]
  member _.``A8.8.216 STREXH``() =
    testDisasm "e1e10f92" "strexh r0, r2, [r1]"
    testDisasm "e1e1df94" "strexh sp, r4, [r1]"
    testDisasm "e1e92f94" "strexh r2, r4, [sb]"
    testDisasm "e1e9df94" "strexh sp, r4, [sb]"

  /// A8.8.217 STRH (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.217 STRH``() =
    testDisasm "e1c101b0" "strh r0, [r1, #0x10]"
    testDisasm "e18100b2" "strh r0, [r1, r2]"
    testDisasm "e1c100b0" "strh r0, [r1]"
    testDisasm "e00120b4" "strh r2, [r1], -r4"

  /// A8.8.220 STRHT
  [<TestMethod>]
  member _.``A8.8.220 STRHT``() =
    testDisasm "e0e100b0" "strht r0, [r1], #0x0"
    testDisasm "e02120b4" "strht r2, [r1], -r4"
    testDisasm "e021d0b4" "strht sp, [r1], -r4"
    testDisasm "e02920b4" "strht r2, [sb], -r4"

  /// A8.8.221 STRT
  [<TestMethod>]
  member _.``A8.8.221 STRT``() =
    testDisasm "e4a10000" "strt r0, [r1], #0x0"
    testDisasm "e421d004" "strt sp, [r1], #-0x4"
    testDisasm "e421f004" "strt pc, [r1], #-0x4"
    testDisasm "e4292004" "strt r2, [sb], #-0x4"

  /// A8.8.222 SUB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.222 SUB``() =
    testDisasm "e24dd008" "sub sp, sp, #0x8"
    testDisasm "e2400003" "sub r0, r0, #0x3"
    testDisasm "e0410002" "sub r0, r1, r2"
    testDisasm "e0510002" "subs r0, r1, r2"

  /// A8.8.228 SUBS PC, LR and related instructions
  [<TestMethod>]
  member _.``A8.8.228 SUBS``() =
    testDisasm "e0510002" "subs r0, r1, r2"
    testDisasm "e2510e3f" "subs r0, r1, #0x3f0"
    testDisasm "e0510312" "subs r0, r1, r2, lsl r3"
    testDisasm "e0510332" "subs r0, r1, r2, lsr r3"

  /// A8.8.229 SVC (previously SWI)
  [<TestMethod>]
  member _.``A8.8.229 SVC``() =
    testDisasm "ef012004" "svc #0x12004"
    testDisasm "1f012004" "svcne #0x12004"

  /// A8.8.230 SWP, SWPB
  [<TestMethod>]
  member _.``A8.8.230 SWP``() =
    testDisasm "e1020091" "swp r0, r1, [r2]"

  /// A8.8.230 SWP, SWPB
  [<TestMethod>]
  member _.``A8.8.230 SWPB``() =
    testDisasm "e1420091" "swpb r0, r1, [r2]"

  /// A8.8.231 SXTAB
  [<TestMethod>]
  member _.``A8.8.231 SXTAB``() =
    testDisasm "e6a10072" "sxtab r0, r1, r2"
    testDisasm "e6a12474" "sxtab r2, r1, r4, ror #0x8"
    testDisasm "e6a1d074" "sxtab sp, r1, r4"
    testDisasm "e6a1d474" "sxtab sp, r1, r4, ror #0x8"

  /// A8.8.232 SXTAB16
  [<TestMethod>]
  member _.``A8.8.232 SXTAB16``() =
    testDisasm "e6810072" "sxtab16 r0, r1, r2"
    testDisasm "e6812474" "sxtab16 r2, r1, r4, ror #0x8"
    testDisasm "e681d074" "sxtab16 sp, r1, r4"
    testDisasm "e681d474" "sxtab16 sp, r1, r4, ror #0x8"

  /// A8.8.233 SXTAH
  [<TestMethod>]
  member _.``A8.8.233 SXTAH``() =
    testDisasm "e6b10072" "sxtah r0, r1, r2"
    testDisasm "e6b12474" "sxtah r2, r1, r4, ror #0x8"
    testDisasm "e6b1d074" "sxtah sp, r1, r4"
    testDisasm "e6b1d474" "sxtah sp, r1, r4, ror #0x8"

  /// A8.8.234 SXTB
  [<TestMethod>]
  member _.``A8.8.234 SXTB``() =
    testDisasm "e6af0071" "sxtb r0, r1"
    testDisasm "e6af2474" "sxtb r2, r4, ror #0x8"
    testDisasm "e6afd074" "sxtb sp, r4"
    testDisasm "e6afd474" "sxtb sp, r4, ror #0x8"

  /// A8.8.235 SXTB16
  [<TestMethod>]
  member _.``A8.8.235 SXTB16``() =
    testDisasm "e68f0071" "sxtb16 r0, r1"
    testDisasm "e68f2474" "sxtb16 r2, r4, ror #0x8"
    testDisasm "e68fd074" "sxtb16 sp, r4"
    testDisasm "e68fd474" "sxtb16 sp, r4, ror #0x8"

  /// A8.8.236 SXTH
  [<TestMethod>]
  member _.``A8.8.236 SXTH``() =
    testDisasm "e6bf0071" "sxth r0, r1"
    testDisasm "e6bf2474" "sxth r2, r4, ror #0x8"
    testDisasm "e6bfd074" "sxth sp, r4"
    testDisasm "e6bfd474" "sxth sp, r4, ror #0x8"

  /// A8.8.238 TEQ (immediate)
  [<TestMethod>]
  member _.``A8.8.238 TEQ``() =
    testDisasm "e1310002" "teq r1, r2"
    testDisasm "e1310082" "teq r1, r2, lsl #0x1"
    testDisasm "e13101a2" "teq r1, r2, lsr #0x3"
    testDisasm "e13102c2" "teq r1, r2, asr #0x5"

  /// A8.8.24 BKPT
  [<TestMethod>]
  member _.``A8.8.24 BKPT``() =
    testDisasm "e1200073" "bkpt #0x3"

  /// A8.8.241 TST (immediate)
  [<TestMethod>]
  member _.``A8.8.241 TST``() =
    testDisasm "e1110002" "tst r1, r2"
    testDisasm "e1110082" "tst r1, r2, lsl #0x1"
    testDisasm "e11101a2" "tst r1, r2, lsr #0x3"
    testDisasm "e11102c2" "tst r1, r2, asr #0x5"

  /// A8.8.244 UADD16
  [<TestMethod>]
  member _.``A8.8.244 UADD16``() =
    testDisasm "e6510f12" "uadd16 r0, r1, r2"

  /// A8.8.245 UADD8
  [<TestMethod>]
  member _.``A8.8.245 UADD8``() =
    testDisasm "e6510f92" "uadd8 r0, r1, r2"

  /// A8.8.246 UASX
  [<TestMethod>]
  member _.``A8.8.246 UASX``() =
    testDisasm "e6510f32" "uasx r0, r1, r2"

  /// A8.8.247 UBFX
  [<TestMethod>]
  member _.``A8.8.247 UBFX``() =
    testDisasm "e7e401d1" "ubfx r0, r1, #0x3, #0x5"
    testDisasm "e7e1d054" "ubfx sp, r4, #0x0, #0x2"
    testDisasm "17e12054" "ubfxne r2, r4, #0x0, #0x2"
    testDisasm "17e1d054" "ubfxne sp, r4, #0x0, #0x2"

  /// A8.8.248 UDF
  [<TestMethod>]
  member _.``A8.8.248 UDF``() =
    testDisasm "e7f120f4" "udf #0x1204"

  /// A8.8.249 UDIV
  [<TestMethod>]
  member _.``A8.8.249 UDIV``() =
    testDisasm "e730f211" "udiv r0, r1, r2"
    testDisasm "e731f914" "udiv r1, r4, sb"
    testDisasm "e731fa14" "udiv r1, r4, sl"
    testDisasm "e731fb14" "udiv r1, r4, fp"

  /// A8.8.25 BL, BLX (immediate)
  [<TestMethod>]
  member _.``A8.8.25 BL``() =
    testDisasm "ebffffff" "bl 0x4 ; "
    testDisasm "1b012004" "blne 0x48018 ; "

  /// A8.8.25 BL, BLX (immediate)
  [<TestMethod>]
  member _.``A8.8.25 BLX``() =
    testDisasm "faffffff" "blx 0x4 ; "

  /// A8.8.250 UHADD16
  [<TestMethod>]
  member _.``A8.8.250 UHADD16``() =
    testDisasm "e6710f12" "uhadd16 r0, r1, r2"

  /// A8.8.251 UHADD8
  [<TestMethod>]
  member _.``A8.8.251 UHADD8``() =
    testDisasm "e6710f92" "uhadd8 r0, r1, r2"

  /// A8.8.252 UHASX
  [<TestMethod>]
  member _.``A8.8.252 UHASX``() =
    testDisasm "e6710f32" "uhasx r0, r1, r2"

  /// A8.8.253 UHSAX
  [<TestMethod>]
  member _.``A8.8.253 UHSAX``() =
    testDisasm "e6710f52" "uhsax r0, r1, r2"

  /// A8.8.254 UHSUB16
  [<TestMethod>]
  member _.``A8.8.254 UHSUB16``() =
    testDisasm "e6710f72" "uhsub16 r0, r1, r2"

  /// A8.8.255 UHSUB8
  [<TestMethod>]
  member _.``A8.8.255 UHSUB8``() =
    testDisasm "e6710ff2" "uhsub8 r0, r1, r2"

  /// A8.8.256 UMAAL
  [<TestMethod>]
  member _.``A8.8.256 UMAAL``() =
    testDisasm "e0410392" "umaal r0, r1, r2, r3"
    testDisasm "e0412994" "umaal r2, r1, r4, sb"
    testDisasm "e0412a94" "umaal r2, r1, r4, sl"
    testDisasm "e0412b94" "umaal r2, r1, r4, fp"

  /// A8.8.257 UMLAL
  [<TestMethod>]
  member _.``A8.8.257 UMLAL``() =
    testDisasm "e0a10392" "umlal r0, r1, r2, r3"
    testDisasm "e0b10291" "umlals r0, r1, r1, r2"
    testDisasm "e0a12994" "umlal r2, r1, r4, sb"
    testDisasm "e0a12a94" "umlal r2, r1, r4, sl"

  /// A8.8.258 UMULL
  [<TestMethod>]
  member _.``A8.8.258 UMULL``() =
    testDisasm "e0810392" "umull r0, r1, r2, r3"
    testDisasm "e0910291" "umulls r0, r1, r1, r2"
    testDisasm "e0812994" "umull r2, r1, r4, sb"
    testDisasm "e0812a94" "umull r2, r1, r4, sl"

  /// A8.8.259 UQADD16
  [<TestMethod>]
  member _.``A8.8.259 UQADD16``() =
    testDisasm "e6610f12" "uqadd16 r0, r1, r2"

  /// A8.8.260 UQADD8
  [<TestMethod>]
  member _.``A8.8.260 UQADD8``() =
    testDisasm "e6610f92" "uqadd8 r0, r1, r2"

  /// A8.8.261 UQASX
  [<TestMethod>]
  member _.``A8.8.261 UQASX``() =
    testDisasm "e6610f32" "uqasx r0, r1, r2"

  /// A8.8.262 UQSAX
  [<TestMethod>]
  member _.``A8.8.262 UQSAX``() =
    testDisasm "e6610f52" "uqsax r0, r1, r2"

  /// A8.8.263 UQSUB16
  [<TestMethod>]
  member _.``A8.8.263 UQSUB16``() =
    testDisasm "e6610f72" "uqsub16 r0, r1, r2"

  /// A8.8.264 UQSUB8
  [<TestMethod>]
  member _.``A8.8.264 UQSUB8``() =
    testDisasm "e6610ff2" "uqsub8 r0, r1, r2"

  /// A8.8.265 USAD8
  [<TestMethod>]
  member _.``A8.8.265 USAD8``() =
    testDisasm "e780f211" "usad8 r0, r1, r2"
    testDisasm "e781f914" "usad8 r1, r4, sb"
    testDisasm "e781fa14" "usad8 r1, r4, sl"
    testDisasm "e781fb14" "usad8 r1, r4, fp"

  /// A8.8.266 USADA8
  [<TestMethod>]
  member _.``A8.8.266 USADA8``() =
    testDisasm "e7803211" "usada8 r0, r1, r2, r3"
    testDisasm "e7812914" "usada8 r1, r4, sb, r2"
    testDisasm "e7812a14" "usada8 r1, r4, sl, r2"
    testDisasm "e7812b14" "usada8 r1, r4, fp, r2"

  /// A8.8.267 USAT
  [<TestMethod>]
  member _.``A8.8.267 USAT``() =
    testDisasm "e6e30011" "usat r0, #0x3, r1"
    testDisasm "e6e30091" "usat r0, #0x3, r1, lsl #0x1"
    testDisasm "e6e302d1" "usat r0, #0x3, r1, asr #0x5"
    testDisasm "e6e1d014" "usat sp, #0x1, r4"

  /// A8.8.268 USAT16
  [<TestMethod>]
  member _.``A8.8.268 USAT16``() =
    testDisasm "e6e30f31" "usat16 r0, #0x3, r1"

  /// A8.8.269 USAX
  [<TestMethod>]
  member _.``A8.8.269 USAX``() =
    testDisasm "e6510f52" "usax r0, r1, r2"

  /// A8.8.270 USUB16
  [<TestMethod>]
  member _.``A8.8.270 USUB16``() =
    testDisasm "e6510f72" "usub16 r0, r1, r2"

  /// A8.8.271 USUB8
  [<TestMethod>]
  member _.``A8.8.271 USUB8``() =
    testDisasm "e6510ff2" "usub8 r0, r1, r2"

  /// A8.8.272 UXTAB
  [<TestMethod>]
  member _.``A8.8.272 UXTAB``() =
    testDisasm "e6e10072" "uxtab r0, r1, r2"
    testDisasm "e6e12474" "uxtab r2, r1, r4, ror #0x8"
    testDisasm "e6e1d074" "uxtab sp, r1, r4"
    testDisasm "e6e1d474" "uxtab sp, r1, r4, ror #0x8"

  /// A8.8.273 UXTAB16
  [<TestMethod>]
  member _.``A8.8.273 UXTAB16``() =
    testDisasm "e6c10072" "uxtab16 r0, r1, r2"
    testDisasm "e6c12474" "uxtab16 r2, r1, r4, ror #0x8"
    testDisasm "e6c1d074" "uxtab16 sp, r1, r4"
    testDisasm "e6c1d474" "uxtab16 sp, r1, r4, ror #0x8"

  /// A8.8.274 UXTAH
  [<TestMethod>]
  member _.``A8.8.274 UXTAH``() =
    testDisasm "e6f10072" "uxtah r0, r1, r2"
    testDisasm "e6f12474" "uxtah r2, r1, r4, ror #0x8"
    testDisasm "e6f1d074" "uxtah sp, r1, r4"
    testDisasm "e6f1d474" "uxtah sp, r1, r4, ror #0x8"

  /// A8.8.275 UXTB
  [<TestMethod>]
  member _.``A8.8.275 UXTB``() =
    testDisasm "e6ef0071" "uxtb r0, r1"
    testDisasm "e6ef2474" "uxtb r2, r4, ror #0x8"
    testDisasm "e6efd074" "uxtb sp, r4"
    testDisasm "e6efd474" "uxtb sp, r4, ror #0x8"

  /// A8.8.276 UXTB16
  [<TestMethod>]
  member _.``A8.8.276 UXTB16``() =
    testDisasm "e6cf0071" "uxtb16 r0, r1"
    testDisasm "e6cf2474" "uxtb16 r2, r4, ror #0x8"
    testDisasm "e6cfd074" "uxtb16 sp, r4"
    testDisasm "e6cfd474" "uxtb16 sp, r4, ror #0x8"

  /// A8.8.277 UXTH
  [<TestMethod>]
  member _.``A8.8.277 UXTH``() =
    testDisasm "e6ff0071" "uxth r0, r1"

  /// A8.8.278 VABA, VABAL
  [<TestMethod>]
  member _.``A8.8.278 VABA``() =
    testDisasm "f2120754" "vaba.s16 q0, q1, q2"
    testDisasm "f3020754" "vaba.u8 q0, q1, q2"
    testDisasm "f2010712" "vaba.s8 d0, d1, d2"
    testDisasm "f3010712" "vaba.u8 d0, d1, d2"

  /// A8.8.278 VABA, VABAL
  [<TestMethod>]
  member _.``A8.8.278 VABAL``() =
    testDisasm "f2810502" "vabal.s8 q0, d1, d2"
    testDisasm "f3812504" "vabal.u8 q1, d1, d4"

  /// A8.8.279 VABD, VABDL (integer)
  [<TestMethod>]
  member _.``A8.8.279 VABD``() =
    testDisasm "f3320d44" "vabd.f16 q0, q1, q2"
    testDisasm "f2120744" "vabd.s16 q0, q1, q2"
    testDisasm "f3020744" "vabd.u8 q0, q1, q2"
    testDisasm "f2010702" "vabd.s8 d0, d1, d2"

  /// A8.8.279 VABD, VABDL (integer)
  [<TestMethod>]
  member _.``A8.8.279 VABDL``() =
    testDisasm "f2810702" "vabdl.s8 q0, d1, d2"
    testDisasm "f3812704" "vabdl.u8 q1, d1, d4"

  /// A8.8.28 BXJ
  [<TestMethod>]
  member _.``A8.8.28 BXJ``() =
    testDisasm "e12fff21" "bxj r1"

  /// A8.8.281 VABS
  [<TestMethod>]
  member _.``A8.8.281 VABS``() =
    testDisasm "eeb009e0" "vabs.f16 s0, s1"
    testDisasm "f3b50742" "vabs.f16 q0, q1"
    testDisasm "f3b10344" "vabs.s8 q0, q2"
    testDisasm "f3b10302" "vabs.s8 d0, d2"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACGE``() =
    testDisasm "f3120e54" "vacge.f16 q0, q1, q2"
    testDisasm "f3020e11" "vacge.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACGT``() =
    testDisasm "f3320e54" "vacgt.f16 q0, q1, q2"
    testDisasm "f3220e11" "vacgt.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACLE``() =
    testDisasm "f3120e54" "vacge.f16 q0, q1, q2"
    testDisasm "f3020e11" "vacge.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACLT``() =
    testDisasm "f3320e54" "vacgt.f16 q0, q1, q2"
    testDisasm "f3220e11" "vacgt.f32 d0, d2, d1"

  /// A8.8.283 VADD (integer)
  [<TestMethod>]
  member _.``A8.8.283 VADD``() =
    testDisasm "ee300981" "vadd.f16 s0, s1, s2"
    testDisasm "f2120d44" "vadd.f16 q0, q1, q2"
    testDisasm "f2120844" "vadd.i16 q0, q1, q2"
    testDisasm "f2010802" "vadd.i8 d0, d1, d2"

  /// A8.8.285 VADDHN
  [<TestMethod>]
  member _.``A8.8.285 VADDHN``() =
    testDisasm "f2920404" "vaddhn.i32 d0, q1, q2"

  /// A8.8.286 VADDL, VADDW
  [<TestMethod>]
  member _.``A8.8.286 VADDL``() =
    testDisasm "f2910002" "vaddl.s16 q0, d1, d2"
    testDisasm "f3810002" "vaddl.u8 q0, d1, d2"

  /// A8.8.286 VADDL, VADDW
  [<TestMethod>]
  member _.``A8.8.286 VADDW``() =
    testDisasm "f2800101" "vaddw.s8 q0, q0, d1"
    testDisasm "f3802104" "vaddw.u8 q1, q0, d4"

  /// A8.8.287 VAND (immediate)
  [<TestMethod>]
  member _.``A8.8.287 VAND``() =
    testDisasm "f2020154" "vand q0, q1, q2"
    testDisasm "f2011112" "vand d1, d1, d2"

  /// A8.8.289 VBIC (immediate)
  [<TestMethod>]
  member _.``A8.8.289 VBIC``() =
    testDisasm "f2120154" "vbic q0, q1, q2"
    testDisasm "f2810970" "vbic.i16 q0, #0x10"
    testDisasm "f2810930" "vbic.i16 d0, #0x10"
    testDisasm "f2111112" "vbic d1, d1, d2"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBIF``() =
    testDisasm "f3320154" "vbif q0, q1, q2"
    testDisasm "f3312114" "vbif d2, d1, d4"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBIT``() =
    testDisasm "f3220154" "vbit q0, q1, q2"
    testDisasm "f3212114" "vbit d2, d1, d4"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBSL``() =
    testDisasm "f3120154" "vbsl q0, q1, q2"
    testDisasm "f3112114" "vbsl d2, d1, d4"

  /// A8.8.292 VCEQ (register)
  [<TestMethod>]
  member _.``A8.8.292 VCEQ``() =
    testDisasm "f2120e44" "vceq.f16 q0, q1, q2"
    testDisasm "f3b50542" "vceq.f16 q0, q1, #0x0"
    testDisasm "f3010812" "vceq.i8 d0, d1, d2"
    testDisasm "f2010e02" "vceq.f32 d0, d1, d2"

  /// A8.8.294 VCGE (register)
  [<TestMethod>]
  member _.``A8.8.294 VCGE``() =
    testDisasm "f3120e44" "vcge.f16 q0, q1, q2"
    testDisasm "f3b504c2" "vcge.f16 q0, q1, #0x0"
    testDisasm "f2010312" "vcge.s8 d0, d1, d2"
    testDisasm "f3010312" "vcge.u8 d0, d1, d2"

  /// A8.8.296 VCGT (register)
  [<TestMethod>]
  member _.``A8.8.296 VCGT``() =
    testDisasm "f3320e44" "vcgt.f16 q0, q1, q2"
    testDisasm "f3b50442" "vcgt.f16 q0, q1, #0x0"
    testDisasm "f2010302" "vcgt.s8 d0, d1, d2"
    testDisasm "f3010302" "vcgt.u8 d0, d1, d2"

  /// A8.8.298 VCLE (register)
  [<TestMethod>]
  member _.``A8.8.298 VCLE``() =
    testDisasm "f3b505c2" "vcle.f16 q0, q1, #0x0"
    testDisasm "f3b101c4" "vcle.s8 q0, q2, #0x0"
    testDisasm "f3b10182" "vcle.s8 d0, d2, #0x0"
    testDisasm "f3b90582" "vcle.f32 d0, d2, #0x0"

  /// A8.8.30 CDP, CDP2
  [<TestMethod>]
  member _.``A8.8.30 CDP``() =
    testDisasm "ee1323a4" "cdp p3, #0x1, c2, c3, c4, #0x5"

  /// A8.8.30 CDP, CDP2
  [<TestMethod>]
  member _.``A8.8.30 CDP2``() =
    testDisasm "fe1323a4" "cdp2 p3, #0x1, c2, c3, c4, #0x5"

  /// A8.8.300 VCLS
  [<TestMethod>]
  member _.``A8.8.300 VCLS``() =
    testDisasm "f3b00444" "vcls.s8 q0, q2"
    testDisasm "f3b00402" "vcls.s8 d0, d2"

  /// A8.8.301 VCLT (register)
  [<TestMethod>]
  member _.``A8.8.301 VCLT``() =
    testDisasm "f3b50642" "vclt.f16 q0, q1, #0x0"
    testDisasm "f3b10244" "vclt.s8 q0, q2, #0x0"
    testDisasm "f3b10202" "vclt.s8 d0, d2, #0x0"
    testDisasm "f3b90602" "vclt.f32 d0, d2, #0x0"

  /// A8.8.303 VCLZ
  [<TestMethod>]
  member _.``A8.8.303 VCLZ``() =
    testDisasm "f3b004c4" "vclz.i8 q0, q2"
    testDisasm "f3b00482" "vclz.i8 d0, d2"

  /// A8.8.304 VCMP, VCMPE
  [<TestMethod>]
  member _.``A8.8.304 VCMP``() =
    testDisasm "eeb40960" "vcmp.f16 s0, s1"
    testDisasm "eeb40b42" "vcmp.f64 d0, d2"

  /// A8.8.304 VCMP, VCMPE
  [<TestMethod>]
  member _.``A8.8.304 VCMPE``() =
    testDisasm "eeb409e0" "vcmpe.f16 s0, s1"
    testDisasm "eeb40bc2" "vcmpe.f64 d0, d2"

  /// A8.8.305 VCNT
  [<TestMethod>]
  member _.``A8.8.305 VCNT``() =
    testDisasm "f3b00544" "vcnt.8 q0, q2"
    testDisasm "f3b00502" "vcnt.8 d0, d2"

  /// A8.8.306 VCVT (between floating-point and integer, Advanced SIMD)
  [<TestMethod>]
  member _.``A8.8.306 VCVT``() =
    testDisasm "eebd09e0" "vcvt.s32.f16 s0, s1"
    testDisasm "eebc09e0" "vcvt.u32.f16 s0, s1"
    testDisasm "eeb809e0" "vcvt.f16.s32 s0, s1"
    testDisasm "eeb80960" "vcvt.f16.u32 s0, s1"

  /// A8.8.307 VCVT, VCVTR (between floating-point and integer, Floating-point)
  [<TestMethod>]
  member _.``A8.8.307 VCVTR``() =
    testDisasm "eebd0960" "vcvtr.s32.f16 s0, s1"
    testDisasm "eebd0b42" "vcvtr.s32.f64 s0, d2"
    testDisasm "eebc0b42" "vcvtr.u32.f64 s0, d2"
    testDisasm "eebc0a41" "vcvtr.u32.f32 s0, s2"

  /// A8.8.312 VCVTB, VCVTT
  [<TestMethod>]
  member _.``A8.8.312 VCVTB``() =
    testDisasm "eeb20a60" "vcvtb.f32.f16 s0, s1"

  /// A8.8.312 VCVTB, VCVTT
  [<TestMethod>]
  member _.``A8.8.312 VCVTT``() =
    testDisasm "eeb20ae0" "vcvtt.f32.f16 s0, s1"

  /// A8.8.313 VDIV
  [<TestMethod>]
  member _.``A8.8.313 VDIV``() =
    testDisasm "ee800981" "vdiv.f16 s0, s1, s2"
    testDisasm "ee810b02" "vdiv.f64 d0, d1, d2"
    testDisasm "1e812a04" "vdivne.f32 s4, s2, s8"
    testDisasm "1e812b04" "vdivne.f64 d2, d1, d4"

  /// A8.8.314 VDUP (scalar)
  [<TestMethod>]
  member _.``A8.8.314 VDUP``() =
    testDisasm "eec01b10" "vdup.8 d0, r1"
    testDisasm "ee81db14" "vdup.32 d1, sp"
    testDisasm "eea02b14" "vdup.32 q0, r2"
    testDisasm "eea0db14" "vdup.32 q0, sp"

  /// A8.8.316 VEOR
  [<TestMethod>]
  member _.``A8.8.316 VEOR``() =
    testDisasm "f3020154" "veor q0, q1, q2"
    testDisasm "f3011112" "veor d1, d1, d2"

  /// A8.8.317 VEXT
  [<TestMethod>]
  member _.``A8.8.317 VEXT``() =
    testDisasm "f2b00142" "vext.8 q0, q0, q1, #0x1"
    testDisasm "f2b12004" "vext.8 d2, d1, d4, #0x0"

  /// A8.8.318 VFMA, VFMS
  [<TestMethod>]
  member _.``A8.8.318 VFMA``() =
    testDisasm "eea00981" "vfma.f16 s0, s1, s2"
    testDisasm "f2120c54" "vfma.f16 q0, q1, q2"
    testDisasm "eea12b04" "vfma.f64 d2, d1, d4"
    testDisasm "1ea12a04" "vfmane.f32 s4, s2, s8"

  /// A8.8.318 VFMA, VFMS
  [<TestMethod>]
  member _.``A8.8.318 VFMS``() =
    testDisasm "eea009c1" "vfms.f16 s0, s1, s2"
    testDisasm "f2320c54" "vfms.f16 q0, q1, q2"
    testDisasm "eea12b44" "vfms.f64 d2, d1, d4"
    testDisasm "1ea12a44" "vfmsne.f32 s4, s2, s8"

  /// A8.8.319 VFNMA, VFNMS
  [<TestMethod>]
  member _.``A8.8.319 VFNMA``() =
    testDisasm "ee9009c1" "vfnma.f16 s0, s1, s2"
    testDisasm "ee912b44" "vfnma.f64 d2, d1, d4"
    testDisasm "1e912a44" "vfnmane.f32 s4, s2, s8"
    testDisasm "1e912b44" "vfnmane.f64 d2, d1, d4"

  /// A8.8.319 VFNMA, VFNMS
  [<TestMethod>]
  member _.``A8.8.319 VFNMS``() =
    testDisasm "ee900981" "vfnms.f16 s0, s1, s2"
    testDisasm "ee912b04" "vfnms.f64 d2, d1, d4"
    testDisasm "1e912a04" "vfnmsne.f32 s4, s2, s8"
    testDisasm "1e912b04" "vfnmsne.f64 d2, d1, d4"

  /// A8.8.32 CLREX
  [<TestMethod>]
  member _.``A8.8.32 CLREX``() =
    testDisasm "f57ff01f" "clrex"

  /// A8.8.320 VHADD, VHSUB
  [<TestMethod>]
  member _.``A8.8.320 VHADD``() =
    testDisasm "f2020044" "vhadd.s8 q0, q1, q2"
    testDisasm "f2012004" "vhadd.s8 d2, d1, d4"
    testDisasm "f3012004" "vhadd.u8 d2, d1, d4"
    testDisasm "f3002044" "vhadd.u8 q1, q0, q2"

  /// A8.8.320 VHADD, VHSUB
  [<TestMethod>]
  member _.``A8.8.320 VHSUB``() =
    testDisasm "f2020244" "vhsub.s8 q0, q1, q2"
    testDisasm "f2012204" "vhsub.s8 d2, d1, d4"
    testDisasm "f3012204" "vhsub.u8 d2, d1, d4"
    testDisasm "f3002244" "vhsub.u8 q1, q0, q2"

  /// A8.8.321 VLD1 (multiple single elements)
  [<TestMethod>]
  member _.``A8.8.321 VLD1``() =
    testDisasm "f421070f" "vld1.8 {d0}, [r1]"
    testDisasm "f4212204" "vld1.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f421220f" "vld1.8 {d2, d3, d4, d5}, [r1]"
    testDisasm "f4212604" "vld1.8 {d2, d3, d4}, [r1], r4"

  /// A8.8.324 VLD2 (multiple 2-element structures)
  [<TestMethod>]
  member _.``A8.8.324 VLD2``() =
    testDisasm "f421080f" "vld2.8 {d0, d1}, [r1]"
    testDisasm "f4212304" "vld2.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f421230f" "vld2.8 {d2, d3, d4, d5}, [r1]"
    testDisasm "f4212804" "vld2.8 {d2, d3}, [r1], r4"

  /// A8.8.327 VLD3 (multiple 3-element structures)
  [<TestMethod>]
  member _.``A8.8.327 VLD3``() =
    testDisasm "f421040f" "vld3.8 {d0, d1, d2}, [r1]"
    testDisasm "f4212404" "vld3.8 {d2, d3, d4}, [r1], r4"
    testDisasm "f4292404" "vld3.8 {d2, d3, d4}, [sb], r4"
    testDisasm "f429240f" "vld3.8 {d2, d3, d4}, [sb]"

  /// A8.8.33 CLZ
  [<TestMethod>]
  member _.``A8.8.33 CLZ``() =
    testDisasm "e16f0f11" "clz r0, r1"

  /// A8.8.330 VLD4 (multiple 4-element structures)
  [<TestMethod>]
  member _.``A8.8.330 VLD4``() =
    testDisasm "f421000f" "vld4.8 {d0, d1, d2, d3}, [r1]"
    testDisasm "f4212004" "vld4.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f4292004" "vld4.8 {d2, d3, d4, d5}, [sb], r4"
    testDisasm "f429200f" "vld4.8 {d2, d3, d4, d5}, [sb]"

  /// A8.8.333 VLDM
  [<TestMethod>]
  member _.``A8.8.333 VLDM``() =
    testDisasm "ec910b04" "vldmia r1, {d0, d1}"
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecb10b08" "vldmia r1!, {d0, d1, d2, d3}"
    testDisasm "ec912a04" "vldmia r1, {s4, s5, s6, s7}"

  /// A8.8.334 VLDR
  [<TestMethod>]
  member _.``A8.8.334 VLDR``() =
    testDisasm "ed910900" "vldr.16 s0, [r1]"
    testDisasm "ed1f0b01" "vldr d0, [pc, #-0x4]"
    testDisasm "ed1f0b00" "vldr d0, [pc]"
    testDisasm "ed910a00" "vldr s0, [r1]"

  /// A8.8.335 VMAX, VMIN (integer)
  [<TestMethod>]
  member _.``A8.8.335 VMAX``() =
    testDisasm "f2120f44" "vmax.f16 q0, q1, q2"
    testDisasm "f2020644" "vmax.s8 q0, q1, q2"
    testDisasm "f2012604" "vmax.s8 d2, d1, d4"
    testDisasm "f2012f04" "vmax.f32 d2, d1, d4"

  /// A8.8.335 VMAX, VMIN (integer)
  [<TestMethod>]
  member _.``A8.8.335 VMIN``() =
    testDisasm "f2320f44" "vmin.f16 q0, q1, q2"
    testDisasm "f2020654" "vmin.s8 q0, q1, q2"
    testDisasm "f2012614" "vmin.s8 d2, d1, d4"
    testDisasm "f2212f04" "vmin.f32 d2, d1, d4"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLA``() =
    testDisasm "ee000981" "vmla.f16 s0, s1, s2"
    testDisasm "f2120d54" "vmla.f16 q0, q1, q2"
    testDisasm "f392016c" "vmla.f16 q0, q1, d4[3]"
    testDisasm "f2020944" "vmla.i8 q0, q1, q2"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLAL``() =
    testDisasm "f2810802" "vmlal.s8 q0, d1, d2"
    testDisasm "f2912244" "vmlal.s16 q1, d1, d4[0]"
    testDisasm "f3812804" "vmlal.u8 q1, d1, d4"
    testDisasm "f3912244" "vmlal.u16 q1, d1, d4[0]"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLS``() =
    testDisasm "ee0009c1" "vmls.f16 s0, s1, s2"
    testDisasm "f2320d54" "vmls.f16 q0, q1, q2"
    testDisasm "f392056c" "vmls.f16 q0, q1, d4[3]"
    testDisasm "f3020944" "vmls.i8 q0, q1, q2"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLSL``() =
    testDisasm "f2810a02" "vmlsl.s8 q0, d1, d2"
    testDisasm "f2912644" "vmlsl.s16 q1, d1, d4[0]"
    testDisasm "f3812a04" "vmlsl.u8 q1, d1, d4"
    testDisasm "f3912644" "vmlsl.u16 q1, d1, d4[0]"

  /// A8.8.34 CMN (immediate)
  [<TestMethod>]
  member _.``A8.8.34 CMN``() =
    testDisasm "e1710002" "cmn r1, r2"
    testDisasm "e1710082" "cmn r1, r2, lsl #0x1"
    testDisasm "e17101a2" "cmn r1, r2, lsr #0x3"
    testDisasm "e17102c2" "cmn r1, r2, asr #0x5"

  /// A8.8.340 VMOV (immediate)
  [<TestMethod>]
  member _.``A8.8.340 VMOV``() =
    testDisasm "ee000910" "vmov.f16 s0, r0"
    testDisasm "ee100990" "vmov.f16 r0, s1"
    testDisasm "f2810e50" "vmov.i8 q0, #0x10"
    testDisasm "f2810e10" "vmov.i8 d0, #0x10"

  /// A8.8.347 VMOVL
  [<TestMethod>]
  member _.``A8.8.347 VMOVL``() =
    testDisasm "f2880a12" "vmovl.s8 q0, d2"
    testDisasm "f3880a12" "vmovl.u8 q0, d2"

  /// A8.8.348 VMOVN
  [<TestMethod>]
  member _.``A8.8.348 VMOVN``() =
    testDisasm "f3b20204" "vmovn.i16 d0, q2"

  /// A8.8.349 VMRS
  [<TestMethod>]
  member _.``A8.8.349 VMRS``() =
    testDisasm "eef10a10" "vmrs r0, fpscr"
    testDisasm "eef1da10" "vmrs sp, fpscr"
    testDisasm "eef02a10" "vmrs r2, fpsid"
    testDisasm "eef0da10" "vmrs sp, fpsid"

  /// A8.8.350 VMSR
  [<TestMethod>]
  member _.``A8.8.350 VMSR``() =
    testDisasm "eee10a10" "vmsr fpscr, r0"
    testDisasm "eee1da10" "vmsr fpscr, sp"
    testDisasm "eee02a10" "vmsr fpsid, r2"
    testDisasm "eee0da10" "vmsr fpsid, sp"

  /// A8.8.351 VMUL, VMULL (integer and polynomial)
  [<TestMethod>]
  member _.``A8.8.351 VMUL``() =
    testDisasm "ee200981" "vmul.f16 s0, s1, s2"
    testDisasm "f3120d54" "vmul.f16 q0, q1, q2"
    testDisasm "f392096c" "vmul.f16 q0, q1, d4[3]"
    testDisasm "f2120954" "vmul.i16 q0, q1, q2"

  /// A8.8.351 VMUL, VMULL (integer and polynomial)
  [<TestMethod>]
  member _.``A8.8.351 VMULL``() =
    testDisasm "f2810c02" "vmull.s8 q0, d1, d2"
    testDisasm "f2a20e03" "vmull.p64 q0, d2, d3"
    testDisasm "f2912a44" "vmull.s16 q1, d1, d4[0]"
    testDisasm "f3812c04" "vmull.u8 q1, d1, d4"

  /// A8.8.354 VMVN (immediate)
  [<TestMethod>]
  member _.``A8.8.354 VMVN``() =
    testDisasm "f3b005c2" "vmvn q0, q1"
    testDisasm "f2810870" "vmvn.i16 q0, #0x10"
    testDisasm "f2810830" "vmvn.i16 d0, #0x10"
    testDisasm "f3b00582" "vmvn d0, d2"

  /// A8.8.356 VNEG
  [<TestMethod>]
  member _.``A8.8.356 VNEG``() =
    testDisasm "eeb10960" "vneg.f16 s0, s1"
    testDisasm "f3b507c2" "vneg.f16 q0, q1"
    testDisasm "f3b103c4" "vneg.s8 q0, q2"
    testDisasm "f3b10382" "vneg.s8 d0, d2"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMLA``() =
    testDisasm "ee1009c1" "vnmla.f16 s0, s1, s2"
    testDisasm "ee110b42" "vnmla.f64 d0, d1, d2"
    testDisasm "1e112a44" "vnmlane.f32 s4, s2, s8"
    testDisasm "1e112b44" "vnmlane.f64 d2, d1, d4"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMLS``() =
    testDisasm "ee100981" "vnmls.f16 s0, s1, s2"
    testDisasm "ee112b04" "vnmls.f64 d2, d1, d4"
    testDisasm "1e112a04" "vnmlsne.f32 s4, s2, s8"
    testDisasm "1e112b04" "vnmlsne.f64 d2, d1, d4"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMUL``() =
    testDisasm "ee2009c1" "vnmul.f16 s0, s1, s2"
    testDisasm "ee212b44" "vnmul.f64 d2, d1, d4"
    testDisasm "1e212a44" "vnmulne.f32 s4, s2, s8"
    testDisasm "1e212b44" "vnmulne.f64 d2, d1, d4"

  /// A8.8.358 VORN (immediate)
  [<TestMethod>]
  member _.``A8.8.358 VORN``() =
    testDisasm "f2320154" "vorn q0, q1, q2"
    testDisasm "f2311112" "vorn d1, d1, d2"

  /// A8.8.360 VORR (immediate)
  [<TestMethod>]
  member _.``A8.8.360 VORR``() =
    testDisasm "f2220154" "vorr q0, q1, q2"
    testDisasm "f2810950" "vorr.i16 q0, #0x10"
    testDisasm "f2810910" "vorr.i16 d0, #0x10"
    testDisasm "f2211112" "vorr d1, d1, d2"

  /// A8.8.362 VPADAL
  [<TestMethod>]
  member _.``A8.8.362 VPADAL``() =
    testDisasm "f3b00644" "vpadal.s8 q0, q2"
    testDisasm "f3b006c4" "vpadal.u8 q0, q2"
    testDisasm "f3b00602" "vpadal.s8 d0, d2"
    testDisasm "f3b00682" "vpadal.u8 d0, d2"

  /// A8.8.363 VPADD (integer)
  [<TestMethod>]
  member _.``A8.8.363 VPADD``() =
    testDisasm "f3110d02" "vpadd.f16 d0, d1, d2"
    testDisasm "f2110b12" "vpadd.i16 d0, d1, d2"

  /// A8.8.365 VPADDL
  [<TestMethod>]
  member _.``A8.8.365 VPADDL``() =
    testDisasm "f3b00244" "vpaddl.s8 q0, q2"
    testDisasm "f3b002c4" "vpaddl.u8 q0, q2"
    testDisasm "f3b00202" "vpaddl.s8 d0, d2"
    testDisasm "f3b00282" "vpaddl.u8 d0, d2"

  /// A8.8.366 VPMAX, VPMIN (integer)
  [<TestMethod>]
  member _.``A8.8.366 VPMAX``() =
    testDisasm "f3110f02" "vpmax.f16 d0, d1, d2"
    testDisasm "f2010a02" "vpmax.s8 d0, d1, d2"
    testDisasm "f3012a04" "vpmax.u8 d2, d1, d4"

  /// A8.8.366 VPMAX, VPMIN (integer)
  [<TestMethod>]
  member _.``A8.8.366 VPMIN``() =
    testDisasm "f3310f02" "vpmin.f16 d0, d1, d2"
    testDisasm "f2010a12" "vpmin.s8 d0, d1, d2"
    testDisasm "f3012a14" "vpmin.u8 d2, d1, d4"

  /// A8.8.368 VPOP
  [<TestMethod>]
  member _.``A8.8.368 VPOP``() =
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecbd2a04" "vldmia sp!, {s4, s5, s6, s7}"
    testDisasm "ecbd2a01" "vldmia sp!, {s4}"
    ("vldmia sp!, {s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, "
     + "s16, s17, s18}")
    |> testDisasm "ecbd2a0f"

  /// A8.8.369 VPUSH
  [<TestMethod>]
  member _.``A8.8.369 VPUSH``() =
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"
    testDisasm "ed2d2a01" "vstmdb sp!, {s4}"
    ("vstmdb sp!, {s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, "
     + "s16, s17, s18}")
    |> testDisasm "ed2d2a0f"

  /// A8.8.37 CMP (immediate)
  [<TestMethod>]
  member _.``A8.8.37 CMP``() =
    testDisasm "e3510003" "cmp r1, #0x3"
    testDisasm "e1510002" "cmp r1, r2"
    testDisasm "e1510082" "cmp r1, r2, lsl #0x1"
    testDisasm "e15101a2" "cmp r1, r2, lsr #0x3"

  /// A8.8.370 VQABS
  [<TestMethod>]
  member _.``A8.8.370 VQABS``() =
    testDisasm "f3b00744" "vqabs.s8 q0, q2"
    testDisasm "f3b00702" "vqabs.s8 d0, d2"

  /// A8.8.371 VQADD
  [<TestMethod>]
  member _.``A8.8.371 VQADD``() =
    testDisasm "f2120054" "vqadd.s16 q0, q1, q2"
    testDisasm "f3020054" "vqadd.u8 q0, q1, q2"
    testDisasm "f2010012" "vqadd.s8 d0, d1, d2"
    testDisasm "f3010012" "vqadd.u8 d0, d1, d2"

  /// A8.8.372 VQDMLAL, VQDMLSL
  [<TestMethod>]
  member _.``A8.8.372 VQDMLAL``() =
    testDisasm "f2910902" "vqdmlal.s16 q0, d1, d2"
    testDisasm "f2912344" "vqdmlal.s16 q1, d1, d4[0]"

  /// A8.8.372 VQDMLAL, VQDMLSL
  [<TestMethod>]
  member _.``A8.8.372 VQDMLSL``() =
    testDisasm "f2910b02" "vqdmlsl.s16 q0, d1, d2"
    testDisasm "f2912744" "vqdmlsl.s16 q1, d1, d4[0]"

  /// A8.8.373 VQDMULH
  [<TestMethod>]
  member _.``A8.8.373 VQDMULH``() =
    testDisasm "f2220b44" "vqdmulh.s32 q0, q1, q2"
    testDisasm "f2110b02" "vqdmulh.s16 d0, d1, d2"
    testDisasm "f3920c42" "vqdmulh.s16 q0, q1, d2[0]"
    testDisasm "f2910c42" "vqdmulh.s16 d0, d1, d2[0]"

  /// A8.8.374 VQDMULL
  [<TestMethod>]
  member _.``A8.8.374 VQDMULL``() =
    testDisasm "f2a10d02" "vqdmull.s32 q0, d1, d2"
    testDisasm "f2910b42" "vqdmull.s16 q0, d1, d2[0]"

  /// A8.8.375 VQMOVN, VQMOVUN
  [<TestMethod>]
  member _.``A8.8.375 VQMOVN``() =
    testDisasm "f3b20282" "vqmovn.s16 d0, q1"

  /// A8.8.375 VQMOVN, VQMOVUN
  [<TestMethod>]
  member _.``A8.8.375 VQMOVUN``() =
    testDisasm "f3b20242" "vqmovun.s16 d0, q1"

  /// A8.8.376 VQNEG
  [<TestMethod>]
  member _.``A8.8.376 VQNEG``() =
    testDisasm "f3b007c4" "vqneg.s8 q0, q2"
    testDisasm "f3b00782" "vqneg.s8 d0, d2"

  /// A8.8.377 VQRDMULH
  [<TestMethod>]
  member _.``A8.8.377 VQRDMULH``() =
    testDisasm "f3220b44" "vqrdmulh.s32 q0, q1, q2"
    testDisasm "f3110b02" "vqrdmulh.s16 d0, d1, d2"
    testDisasm "f3920d42" "vqrdmulh.s16 q0, q1, d2[0]"
    testDisasm "f2910d42" "vqrdmulh.s16 d0, d1, d2[0]"

  /// A8.8.378 VQRSHL
  [<TestMethod>]
  member _.``A8.8.378 VQRSHL``() =
    testDisasm "f2040552" "vqrshl.s8 q0, q1, q2"
    testDisasm "f2012514" "vqrshl.s8 d2, d4, d1"
    testDisasm "f3012514" "vqrshl.u8 d2, d4, d1"
    testDisasm "f3002554" "vqrshl.u8 q1, q2, q0"

  /// A8.8.379 VQRSHRN, VQRSHRUN
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRN``() =
    testDisasm "f28f0952" "vqrshrn.s16 d0, q1, #0x1"
    testDisasm "f3892954" "vqrshrn.u16 d2, q2, #0x7"

  /// A8.8.379 VQRSHRN, VQRSHRUN
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRUN``() =
    testDisasm "f38f0852" "vqrshrun.s16 d0, q1, #0x1"

  /// A8.8.380 VQSHL (register)
  [<TestMethod>]
  member _.``A8.8.380 VQSHL``() =
    testDisasm "f2040452" "vqshl.s8 q0, q1, q2"
    testDisasm "f2012414" "vqshl.s8 d2, d4, d1"
    testDisasm "f2892714" "vqshl.s8 d2, d4, #0x1"
    testDisasm "f2892754" "vqshl.s8 q1, q2, #0x1"

  /// A8.8.381 VQSHL, VQSHLU (immediate)
  [<TestMethod>]
  member _.``A8.8.381 VQSHLU``() =
    testDisasm "f3890652" "vqshlu.s8 q0, q1, #0x1"
    testDisasm "f3892614" "vqshlu.s8 d2, d4, #0x1"

  /// A8.8.382 VQSHRN, VQSHRUN
  [<TestMethod>]
  member _.``A8.8.382 VQSHRN``() =
    testDisasm "f28f0912" "vqshrn.s16 d0, q1, #0x1"
    testDisasm "f3892914" "vqshrn.u16 d2, q2, #0x7"

  /// A8.8.382 VQSHRN, VQSHRUN
  [<TestMethod>]
  member _.``A8.8.382 VQSHRUN``() =
    testDisasm "f38f0812" "vqshrun.s16 d0, q1, #0x1"

  /// A8.8.383 VQSUB
  [<TestMethod>]
  member _.``A8.8.383 VQSUB``() =
    testDisasm "f2020254" "vqsub.s8 q0, q1, q2"
    testDisasm "f2012214" "vqsub.s8 d2, d1, d4"
    testDisasm "f3012214" "vqsub.u8 d2, d1, d4"
    testDisasm "f3002254" "vqsub.u8 q1, q0, q2"

  /// A8.8.384 VRADDHN
  [<TestMethod>]
  member _.``A8.8.384 VRADDHN``() =
    testDisasm "f3920404" "vraddhn.i32 d0, q1, q2"

  /// A8.8.385 VRECPE
  [<TestMethod>]
  member _.``A8.8.385 VRECPE``() =
    testDisasm "f3b70542" "vrecpe.f16 q0, q1"
    testDisasm "f3bb0444" "vrecpe.u32 q0, q2"
    testDisasm "f3bb0402" "vrecpe.u32 d0, d2"
    testDisasm "f3bb0502" "vrecpe.f32 d0, d2"

  /// A8.8.386 VRECPS
  [<TestMethod>]
  member _.``A8.8.386 VRECPS``() =
    testDisasm "f2120f54" "vrecps.f16 q0, q1, q2"
    testDisasm "f2010f12" "vrecps.f32 d0, d1, d2"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV16``() =
    testDisasm "f3b00142" "vrev16.8 q0, q1"
    testDisasm "f3b02104" "vrev16.8 d2, d4"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV32``() =
    testDisasm "f3b000c2" "vrev32.8 q0, q1"
    testDisasm "f3b02084" "vrev32.8 d2, d4"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV64``() =
    testDisasm "f3b00042" "vrev64.8 q0, q1"
    testDisasm "f3b02004" "vrev64.8 d2, d4"

  /// A8.8.388 VRHADD
  [<TestMethod>]
  member _.``A8.8.388 VRHADD``() =
    testDisasm "f3020144" "vrhadd.u8 q0, q1, q2"
    testDisasm "f2022144" "vrhadd.s8 q1, q1, q2"
    testDisasm "f2011102" "vrhadd.s8 d1, d1, d2"
    testDisasm "f3011102" "vrhadd.u8 d1, d1, d2"

  /// A8.8.389 VRSHL
  [<TestMethod>]
  member _.``A8.8.389 VRSHL``() =
    testDisasm "f2040542" "vrshl.s8 q0, q1, q2"
    testDisasm "f2012504" "vrshl.s8 d2, d4, d1"
    testDisasm "f3012504" "vrshl.u8 d2, d4, d1"
    testDisasm "f3002544" "vrshl.u8 q1, q2, q0"

  /// A8.8.390 VRSHR
  [<TestMethod>]
  member _.``A8.8.390 VRSHR``() =
    testDisasm "f2892214" "vrshr.s8 d2, d4, #0x7"
    testDisasm "f2892254" "vrshr.s8 q1, q2, #0x7"
    testDisasm "f3892214" "vrshr.u8 d2, d4, #0x7"
    testDisasm "f3892254" "vrshr.u8 q1, q2, #0x7"

  /// A8.8.391 VRSHRN
  [<TestMethod>]
  member _.``A8.8.391 VRSHRN``() =
    testDisasm "f28f0852" "vrshrn.i16 d0, q1, #0x1"

  /// A8.8.392 VRSQRTE
  [<TestMethod>]
  member _.``A8.8.392 VRSQRTE``() =
    testDisasm "f3b705c2" "vrsqrte.f16 q0, q1"
    testDisasm "f3bb04c4" "vrsqrte.u32 q0, q2"
    testDisasm "f3bb0482" "vrsqrte.u32 d0, d2"
    testDisasm "f3bb0582" "vrsqrte.f32 d0, d2"

  /// A8.8.393 VRSQRTS
  [<TestMethod>]
  member _.``A8.8.393 VRSQRTS``() =
    testDisasm "f2320f54" "vrsqrts.f16 q0, q1, q2"
    testDisasm "f2210f12" "vrsqrts.f32 d0, d1, d2"

  /// A8.8.394 VRSRA
  [<TestMethod>]
  member _.``A8.8.394 VRSRA``() =
    testDisasm "f28f0352" "vrsra.s8 q0, q1, #0x1"
    testDisasm "f2892314" "vrsra.s8 d2, d4, #0x7"
    testDisasm "f3892314" "vrsra.u8 d2, d4, #0x7"
    testDisasm "f3892354" "vrsra.u8 q1, q2, #0x7"

  /// A8.8.395 VRSUBHN
  [<TestMethod>]
  member _.``A8.8.395 VRSUBHN``() =
    testDisasm "f3920604" "vrsubhn.i32 d0, q1, q2"

  /// A8.8.396 VSHL (immediate)
  [<TestMethod>]
  member _.``A8.8.396 VSHL``() =
    testDisasm "f2890552" "vshl.i8 q0, q1, #0x1"
    testDisasm "f2012404" "vshl.s8 d2, d4, d1"
    testDisasm "f2002444" "vshl.s8 q1, q2, q0"
    testDisasm "f2892514" "vshl.i8 d2, d4, #0x1"

  /// A8.8.398 VSHLL
  [<TestMethod>]
  member _.``A8.8.398 VSHLL``() =
    testDisasm "f2890a11" "vshll.s8 q0, d1, #0x1"
    testDisasm "f3892a14" "vshll.u8 q1, d4, #0x1"

  /// A8.8.399 VSHR
  [<TestMethod>]
  member _.``A8.8.399 VSHR``() =
    testDisasm "f2892014" "vshr.s8 d2, d4, #0x7"
    testDisasm "f2892054" "vshr.s8 q1, q2, #0x7"
    testDisasm "f3892014" "vshr.u8 d2, d4, #0x7"
    testDisasm "f3892054" "vshr.u8 q1, q2, #0x7"

  /// A8.8.4 ADD (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.4 ADD``() =
    testDisasm "e28dd008" "add sp, sp, #0x8"
    testDisasm "e2800003" "add r0, r0, #0x3"
    testDisasm "e0810002" "add r0, r1, r2"
    testDisasm "e0911002" "adds r1, r1, r2"

  /// A8.8.40 CPS
  [<TestMethod>]
  member _.``A8.8.40 CPS``() =
    testDisasm "f1020013" "cps #0x13"

  /// A8.8.400 VSHRN
  [<TestMethod>]
  member _.``A8.8.400 VSHRN``() =
    testDisasm "f28f0812" "vshrn.i16 d0, q1, #0x1"

  /// A8.8.401 VSLI
  [<TestMethod>]
  member _.``A8.8.401 VSLI``() =
    testDisasm "f3890552" "vsli.8 q0, q1, #0x1"
    testDisasm "f3892514" "vsli.8 d2, d4, #0x1"

  /// A8.8.402 VSQRT
  [<TestMethod>]
  member _.``A8.8.402 VSQRT``() =
    testDisasm "eeb109e0" "vsqrt.f16 s0, s1"
    testDisasm "eeb10bc2" "vsqrt.f64 d0, d2"
    testDisasm "1eb12ac4" "vsqrtne.f32 s4, s8"
    testDisasm "1eb12bc4" "vsqrtne.f64 d2, d4"

  /// A8.8.403 VSRA
  [<TestMethod>]
  member _.``A8.8.403 VSRA``() =
    testDisasm "f28f0152" "vsra.s8 q0, q1, #0x1"
    testDisasm "f2892114" "vsra.s8 d2, d4, #0x7"
    testDisasm "f3892114" "vsra.u8 d2, d4, #0x7"
    testDisasm "f3892154" "vsra.u8 q1, q2, #0x7"

  /// A8.8.404 VSRI
  [<TestMethod>]
  member _.``A8.8.404 VSRI``() =
    testDisasm "f38f0452" "vsri.8 q0, q1, #0x1"
    testDisasm "f3892414" "vsri.8 d2, d4, #0x7"

  /// A8.8.405 VST1 (multiple single elements)
  [<TestMethod>]
  member _.``A8.8.405 VST1``() =
    testDisasm "f401070f" "vst1.8 {d0}, [r1]"
    testDisasm "f4012204" "vst1.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f401220f" "vst1.8 {d2, d3, d4, d5}, [r1]"
    testDisasm "f4012604" "vst1.8 {d2, d3, d4}, [r1], r4"

  /// A8.8.407 VST2 (multiple 2-element structures)
  [<TestMethod>]
  member _.``A8.8.407 VST2``() =
    testDisasm "f401080f" "vst2.8 {d0, d1}, [r1]"
    testDisasm "f4012304" "vst2.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f401230f" "vst2.8 {d2, d3, d4, d5}, [r1]"
    testDisasm "f4012804" "vst2.8 {d2, d3}, [r1], r4"

  /// A8.8.409 VST3 (multiple 3-element structures)
  [<TestMethod>]
  member _.``A8.8.409 VST3``() =
    testDisasm "f401040f" "vst3.8 {d0, d1, d2}, [r1]"
    testDisasm "f4012404" "vst3.8 {d2, d3, d4}, [r1], r4"
    testDisasm "f4092404" "vst3.8 {d2, d3, d4}, [sb], r4"
    testDisasm "f409240f" "vst3.8 {d2, d3, d4}, [sb]"

  /// A8.8.41 CPY
  [<TestMethod>]
  member _.``A8.8.41 CPY``() =
    testDisasm "e1a00002" "mov r0, r2"
    testDisasm "e1b00002" "movs r0, r2"
    testDisasm "11a02004" "movne r2, r4"
    testDisasm "11b02004" "movsne r2, r4"

  /// A8.8.411 VST4 (multiple 4-element structures)
  [<TestMethod>]
  member _.``A8.8.411 VST4``() =
    testDisasm "f401000f" "vst4.8 {d0, d1, d2, d3}, [r1]"
    testDisasm "f4012004" "vst4.8 {d2, d3, d4, d5}, [r1], r4"
    testDisasm "f4092004" "vst4.8 {d2, d3, d4, d5}, [sb], r4"
    testDisasm "f409200f" "vst4.8 {d2, d3, d4, d5}, [sb]"

  /// A8.8.413 VSTM
  [<TestMethod>]
  member _.``A8.8.413 VSTM``() =
    testDisasm "ec810b04" "vstmia r1, {d0, d1}"
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ec810a04" "vstmia r1, {s0, s1, s2, s3}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"

  /// A8.8.414 VSTR
  [<TestMethod>]
  member _.``A8.8.414 VSTR``() =
    testDisasm "ed810900" "vstr.16 s0, [r1]"
    testDisasm "ed810b00" "vstr.64 d0, [r1]"
    testDisasm "ed012904" "vstr.16 s4, [r1, #-0x8]"
    testDisasm "ed012b04" "vstr.64 d2, [r1, #-0x10]"

  /// A8.8.415 VSUB (integer)
  [<TestMethod>]
  member _.``A8.8.415 VSUB``() =
    testDisasm "ee3009c1" "vsub.f16 s0, s1, s2"
    testDisasm "f2320d44" "vsub.f16 q0, q1, q2"
    testDisasm "f3120844" "vsub.i16 q0, q1, q2"
    testDisasm "f3010802" "vsub.i8 d0, d1, d2"

  /// A8.8.417 VSUBHN
  [<TestMethod>]
  member _.``A8.8.417 VSUBHN``() =
    testDisasm "f2920604" "vsubhn.i32 d0, q1, q2"

  /// A8.8.418 VSUBL, VSUBW
  [<TestMethod>]
  member _.``A8.8.418 VSUBL``() =
    testDisasm "f2910202" "vsubl.s16 q0, d1, d2"
    testDisasm "f3810202" "vsubl.u8 q0, d1, d2"

  /// A8.8.418 VSUBL, VSUBW
  [<TestMethod>]
  member _.``A8.8.418 VSUBW``() =
    testDisasm "f2800301" "vsubw.s8 q0, q0, d1"
    testDisasm "f3802304" "vsubw.u8 q1, q0, d4"

  /// A8.8.419 VSWP
  [<TestMethod>]
  member _.``A8.8.419 VSWP``() =
    testDisasm "f3b20042" "vswp q0, q1"
    testDisasm "f3b20002" "vswp d0, d2"

  /// A8.8.42 CSDB
  [<TestMethod>]
  member _.``A8.8.42 CSDB``() =
    testDisasm "e320f014" "csdb"

  /// A8.8.420 VTBL, VTBX
  [<TestMethod>]
  member _.``A8.8.420 VTBL``() =
    testDisasm "f3b10802" "vtbl.8 d0, {d1}, d2"
    testDisasm "f3b12904" "vtbl.8 d2, {d1, d2}, d4"
    testDisasm "f3b12a04" "vtbl.8 d2, {d1, d2, d3}, d4"
    testDisasm "f3b12b04" "vtbl.8 d2, {d1, d2, d3, d4}, d4"

  /// A8.8.420 VTBL, VTBX
  [<TestMethod>]
  member _.``A8.8.420 VTBX``() =
    testDisasm "f3b10842" "vtbx.8 d0, {d1}, d2"
    testDisasm "f3b12944" "vtbx.8 d2, {d1, d2}, d4"
    testDisasm "f3b12a44" "vtbx.8 d2, {d1, d2, d3}, d4"
    testDisasm "f3b12b44" "vtbx.8 d2, {d1, d2, d3, d4}, d4"

  /// A8.8.421 VTRN
  [<TestMethod>]
  member _.``A8.8.421 VTRN``() =
    testDisasm "f3b200c2" "vtrn.8 q0, q1"
    testDisasm "f3b20081" "vtrn.8 d0, d1"

  /// A8.8.422 VTST
  [<TestMethod>]
  member _.``A8.8.422 VTST``() =
    testDisasm "f2020854" "vtst.8 q0, q1, q2"
    testDisasm "f2012814" "vtst.8 d2, d1, d4"

  /// A8.8.423 VUZP
  [<TestMethod>]
  member _.``A8.8.423 VUZP``() =
    testDisasm "f3b20142" "vuzp.8 q0, q1"
    testDisasm "f3b20101" "vuzp.8 d0, d1"

  /// A8.8.424 VZIP
  [<TestMethod>]
  member _.``A8.8.424 VZIP``() =
    testDisasm "f3b201c2" "vzip.8 q0, q1"
    testDisasm "f3b20181" "vzip.8 d0, d1"

  /// A8.8.425 WFE
  [<TestMethod>]
  member _.``A8.8.425 WFE``() =
    testDisasm "e320f002" "wfe"

  /// A8.8.426 WFI
  [<TestMethod>]
  member _.``A8.8.426 WFI``() =
    testDisasm "e320f003" "wfi"

  /// A8.8.427 YIELD
  [<TestMethod>]
  member _.``A8.8.427 YIELD``() =
    testDisasm "e320f001" "yield"
    testDisasm "1320f001" "yieldne"

  /// A8.8.43 DBG
  [<TestMethod>]
  member _.``A8.8.43 DBG``() =
    testDisasm "e320f0f4" "dbg #0x4"
    testDisasm "1320f0f4" "dbgne #0x4"

  /// A8.8.44 DMB
  [<TestMethod>]
  member _.``A8.8.44 DMB``() =
    testDisasm "f57ff05f" "dmb sy"
    testDisasm "f57ff05b" "dmb ish"

  /// A8.8.45 DSB
  [<TestMethod>]
  member _.``A8.8.45 DSB``() =
    testDisasm "f57ff04f" "dsb sy"

  /// A8.8.47 EOR (immediate)
  [<TestMethod>]
  member _.``A8.8.47 EOR``() =
    testDisasm "e0200002" "eor r0, r0, r2"
    testDisasm "e0310002" "eors r0, r1, r2"
    testDisasm "e0210082" "eor r0, r1, r2, lsl #0x1"
    testDisasm "e02101a2" "eor r0, r1, r2, lsr #0x3"

  /// A8.8.50 ERET
  [<TestMethod>]
  member _.``A8.8.50 ERET``() =
    testDisasm "e160006e" "eret"

  /// A8.8.53 HVC
  [<TestMethod>]
  member _.``A8.8.53 HVC``() =
    testDisasm "e1412074" "hvc #0x1204"

  /// A8.8.54 ISB
  [<TestMethod>]
  member _.``A8.8.54 ISB``() =
    testDisasm "f57ff06f" "isb sy"

  /// A8.8.56 LDC, LDC2 (immediate)
  [<TestMethod>]
  member _.``A8.8.56 LDC2``() =
    testDisasm "fd915302" "ldc2 p3, c5, [r1, #0x8]"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDM``() =
    testDisasm "e891000c" "ldm r1, {r2, r3}"
    testDisasm "e8b1000c" "ldm r1!, {r2, r3}"
    testDisasm "e8912004" "ldm r1, {r2, sp}"
    testDisasm "e8912000" "ldm r1, {sp}"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDMFD``() =
    testDisasm "e891000c" "ldm r1, {r2, r3}"
    testDisasm "e8bd000c" "pop {r2, r3}"
    testDisasm "e8b1000c" "ldm r1!, {r2, r3}"
    testDisasm "e49d2004" "pop {r2}"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDMIA``() =
    testDisasm "e891000c" "ldm r1, {r2, r3}"
    testDisasm "e8bd000c" "pop {r2, r3}"
    testDisasm "e8b1000c" "ldm r1!, {r2, r3}"
    testDisasm "e49d2004" "pop {r2}"

  /// A8.8.60 LDMDA/LDMFA
  [<TestMethod>]
  member _.``A8.8.60 LDMDA``() =
    testDisasm "e811000c" "ldmda r1, {r2, r3}"
    testDisasm "e8112004" "ldmda r1, {r2, sp}"
    testDisasm "e8112000" "ldmda r1, {sp}"
    testDisasm "e811200f" "ldmda r1, {r0, r1, r2, r3, sp}"

  /// A8.8.60 LDMDA/LDMFA
  [<TestMethod>]
  member _.``A8.8.60 LDMFA``() =
    testDisasm "e811000c" "ldmda r1, {r2, r3}"
    testDisasm "e8112004" "ldmda r1, {r2, sp}"
    testDisasm "e8112000" "ldmda r1, {sp}"
    testDisasm "e811200f" "ldmda r1, {r0, r1, r2, r3, sp}"

  /// A8.8.61 LDMDB/LDMEA
  [<TestMethod>]
  member _.``A8.8.61 LDMDB``() =
    testDisasm "e911000c" "ldmdb r1, {r2, r3}"
    testDisasm "e931000c" "ldmdb r1!, {r2, r3}"
    testDisasm "e9112004" "ldmdb r1, {r2, sp}"
    testDisasm "e9112000" "ldmdb r1, {sp}"

  /// A8.8.61 LDMDB/LDMEA
  [<TestMethod>]
  member _.``A8.8.61 LDMEA``() =
    testDisasm "e911000c" "ldmdb r1, {r2, r3}"
    testDisasm "e931000c" "ldmdb r1!, {r2, r3}"
    testDisasm "e9112004" "ldmdb r1, {r2, sp}"
    testDisasm "e9112000" "ldmdb r1, {sp}"

  /// A8.8.62 LDMIB/LDMED
  [<TestMethod>]
  member _.``A8.8.62 LDMED``() =
    testDisasm "e991000c" "ldmib r1, {r2, r3}"
    testDisasm "e9912004" "ldmib r1, {r2, sp}"
    testDisasm "e9912000" "ldmib r1, {sp}"
    testDisasm "e991200f" "ldmib r1, {r0, r1, r2, r3, sp}"

  /// A8.8.62 LDMIB/LDMED
  [<TestMethod>]
  member _.``A8.8.62 LDMIB``() =
    testDisasm "e991000c" "ldmib r1, {r2, r3}"
    testDisasm "e9912004" "ldmib r1, {r2, sp}"
    testDisasm "e9912000" "ldmib r1, {sp}"
    testDisasm "e991200f" "ldmib r1, {r0, r1, r2, r3, sp}"

  /// A8.8.63 LDR (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.63 LDR``() =
    testDisasm "e5910010" "ldr r0, [r1, #0x10]"
    testDisasm "e51f0004" "ldr r0, [0x4]"
    testDisasm "e7910002" "ldr r0, [r1, r2]"
    testDisasm "e7910082" "ldr r0, [r1, r2, lsl #0x1]"

  /// A8.8.68 LDRB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.68 LDRB``() =
    testDisasm "e5d10003" "ldrb r0, [r1, #0x3]"
    testDisasm "e55f0004" "ldrb r0, [0x4]"
    testDisasm "e7d10002" "ldrb r0, [r1, r2]"
    testDisasm "e5d10000" "ldrb r0, [r1]"

  /// A8.8.72 LDRBT
  [<TestMethod>]
  member _.``A8.8.72 LDRBT``() =
    testDisasm "e4f10000" "ldrbt r0, [r1], #0x0"
    testDisasm "e471d004" "ldrbt sp, [r1], #-0x4"
    testDisasm "e4792004" "ldrbt r2, [sb], #-0x4"
    testDisasm "e479d004" "ldrbt sp, [sb], #-0x4"

  /// A8.8.73 LDRD (immediate)
  [<TestMethod>]
  member _.``A8.8.73 LDRD``() =
    testDisasm "e14f00d4" "ldrd r0, r1, [0x4]"
    testDisasm "e1c100d0" "ldrd r0, r1, [r1]"
    testDisasm "e00120d4" "ldrd r2, r3, [r1], -r4"
    testDisasm "e00920d4" "ldrd r2, r3, [sb], -r4"

  /// A8.8.76 LDREX
  [<TestMethod>]
  member _.``A8.8.76 LDREX``() =
    testDisasm "e1910f9f" "ldrex r0, [r1]"

  /// A8.8.77 LDREXB
  [<TestMethod>]
  member _.``A8.8.77 LDREXB``() =
    testDisasm "e1d10f9f" "ldrexb r0, [r1]"

  /// A8.8.78 LDREXD
  [<TestMethod>]
  member _.``A8.8.78 LDREXD``() =
    testDisasm "e1b10f9f" "ldrexd r0, r1, [r1]"

  /// A8.8.79 LDREXH
  [<TestMethod>]
  member _.``A8.8.79 LDREXH``() =
    testDisasm "e1f10f9f" "ldrexh r0, [r1]"

  /// A8.8.80 LDRH (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.80 LDRH``() =
    testDisasm "e1d101b0" "ldrh r0, [r1, #0x10]"
    testDisasm "e15f00b4" "ldrh r0, [0x4]"
    testDisasm "e19100b2" "ldrh r0, [r1, r2]"
    testDisasm "e1d100b0" "ldrh r0, [r1]"

  /// A8.8.84 LDRHT
  [<TestMethod>]
  member _.``A8.8.84 LDRHT``() =
    testDisasm "e0f100b0" "ldrht r0, [r1], #0x0"
    testDisasm "e03120b4" "ldrht r2, [r1], -r4"
    testDisasm "e031d0b4" "ldrht sp, [r1], -r4"
    testDisasm "e03920b4" "ldrht r2, [sb], -r4"

  /// A8.8.85 LDRSB (immediate)
  [<TestMethod>]
  member _.``A8.8.85 LDRSB``() =
    testDisasm "e1d100d7" "ldrsb r0, [r1, #0x7]"
    testDisasm "e15f00d4" "ldrsb r0, [0x4]"
    testDisasm "e19100d2" "ldrsb r0, [r1, r2]"
    testDisasm "e1d100d0" "ldrsb r0, [r1]"

  /// A8.8.88 LDRSBT
  [<TestMethod>]
  member _.``A8.8.88 LDRSBT``() =
    testDisasm "e0f100d0" "ldrsbt r0, [r1], #0x0"
    testDisasm "e03120d4" "ldrsbt r2, [r1], -r4"
    testDisasm "e031d0d4" "ldrsbt sp, [r1], -r4"
    testDisasm "e03920d4" "ldrsbt r2, [sb], -r4"

  /// A8.8.89 LDRSH (immediate)
  [<TestMethod>]
  member _.``A8.8.89 LDRSH``() =
    testDisasm "e1d100f7" "ldrsh r0, [r1, #0x7]"
    testDisasm "e15f00f4" "ldrsh r0, [0x4]"
    testDisasm "e19100f2" "ldrsh r0, [r1, r2]"
    testDisasm "e1d100f0" "ldrsh r0, [r1]"

  /// A8.8.92 LDRSHT
  [<TestMethod>]
  member _.``A8.8.92 LDRSHT``() =
    testDisasm "e0f100f0" "ldrsht r0, [r1], #0x0"
    testDisasm "e03120f4" "ldrsht r2, [r1], -r4"
    testDisasm "e031d0f4" "ldrsht sp, [r1], -r4"
    testDisasm "e03920f4" "ldrsht r2, [sb], -r4"

  /// A8.8.93 LDRT
  [<TestMethod>]
  member _.``A8.8.93 LDRT``() =
    testDisasm "e4b10000" "ldrt r0, [r1], #0x0"
    testDisasm "e431d004" "ldrt sp, [r1], #-0x4"
    testDisasm "e4392004" "ldrt r2, [sb], #-0x4"
    testDisasm "e439d004" "ldrt sp, [sb], #-0x4"

  /// A8.8.95 LSL (immediate)
  [<TestMethod>]
  member _.``A8.8.95 LSL``() =
    testDisasm "e1a00210" "lsl r0, r0, r2"
    testDisasm "e1b00211" "lsls r0, r1, r2"
    testDisasm "e1a02914" "lsl r2, r4, sb"
    testDisasm "e1a02a14" "lsl r2, r4, sl"

  /// A8.8.97 LSR (immediate)
  [<TestMethod>]
  member _.``A8.8.97 LSR``() =
    testDisasm "e1a00822" "lsr r0, r2, #0x10"
    testDisasm "e1b00822" "lsrs r0, r2, #0x10"
    testDisasm "e1a00230" "lsr r0, r0, r2"
    testDisasm "e1b00231" "lsrs r0, r1, r2"

  /// A8.8.99 MCR, MCR2
  [<TestMethod>]
  member _.``A8.8.99 MCR``() =
    testDisasm "ee012e14" "mcr p14, #0x0, r2, c1, c4, #0x0"
    testDisasm "ee01de14" "mcr p14, #0x0, sp, c1, c4, #0x0"
    testDisasm "1e012e14" "mcrne p14, #0x0, r2, c1, c4, #0x0"
    testDisasm "1e01de14" "mcrne p14, #0x0, sp, c1, c4, #0x0"

  /// A8.8.99 MCR, MCR2
  [<TestMethod>]
  member _.``A8.8.99 MCR2``() =
    testDisasm "fe2323b4" "mcr2 p3, #0x1, r2, c3, c4, #0x5"

  /// F5.1.1 ADC, ADCS (immediate)
  [<TestMethod>]
  member _.``F5.1.1 ADCS``() =
    testDisasm "e0b10002" "adcs r0, r1, r2"
    testDisasm "e0b10312" "adcs r0, r1, r2, lsl r3"
    testDisasm "e0b10332" "adcs r0, r1, r2, lsr r3"
    testDisasm "e0b10352" "adcs r0, r1, r2, asr r3"

  /// F5.1.101 LSLS (immediate)
  [<TestMethod>]
  member _.``F5.1.101 LSLS``() =
    testDisasm "e1b00211" "lsls r0, r1, r2"
    testDisasm "e1b02914" "lsls r2, r4, sb"
    testDisasm "e1b02a14" "lsls r2, r4, sl"
    testDisasm "e1b02b14" "lsls r2, r4, fp"

  /// F5.1.105 LSRS (immediate)
  [<TestMethod>]
  member _.``F5.1.105 LSRS``() =
    testDisasm "e1b00822" "lsrs r0, r2, #0x10"
    testDisasm "e1b00231" "lsrs r0, r1, r2"
    testDisasm "e1b02934" "lsrs r2, r4, sb"
    testDisasm "e1b02a34" "lsrs r2, r4, sl"

  /// F5.1.109 MLA, MLAS
  [<TestMethod>]
  member _.``F5.1.109 MLAS``() =
    testDisasm "e0303291" "mlas r0, r1, r2, r3"
    testDisasm "e0312994" "mlas r1, r4, sb, r2"
    testDisasm "e0312a94" "mlas r1, r4, sl, r2"
    testDisasm "e0312b94" "mlas r1, r4, fp, r2"

  /// F5.1.11 AND, ANDS (immediate)
  [<TestMethod>]
  member _.``F5.1.11 ANDS``() =
    testDisasm "e0110002" "ands r0, r1, r2"
    testDisasm "e0110312" "ands r0, r1, r2, lsl r3"
    testDisasm "e0110332" "ands r0, r1, r2, lsr r3"
    testDisasm "e0110352" "ands r0, r1, r2, asr r3"

  /// F5.1.111 MOV, MOVS (immediate)
  [<TestMethod>]
  member _.``F5.1.111 MOVS``() =
    testDisasm "e1b00002" "movs r0, r2"
    testDisasm "e1b0200f" "movs r2, pc"
    testDisasm "e1b0d004" "movs sp, r4"
    testDisasm "e1b0d00f" "movs sp, pc"

  /// F5.1.122 MUL, MULS
  [<TestMethod>]
  member _.``F5.1.122 MULS``() =
    testDisasm "e0100091" "muls r0, r1, r0"
    testDisasm "e0112994" "muls r1, r4, sb"
    testDisasm "e0112a94" "muls r1, r4, sl"
    testDisasm "e0112b94" "muls r1, r4, fp"

  /// F5.1.123 MVN, MVNS (immediate)
  [<TestMethod>]
  member _.``F5.1.123 MVNS``() =
    testDisasm "e1f00002" "mvns r0, r2"
    testDisasm "e1f00312" "mvns r0, r2, lsl r3"
    testDisasm "e1f00332" "mvns r0, r2, lsr r3"
    testDisasm "e1f00352" "mvns r0, r2, asr r3"

  /// F5.1.129 ORR, ORRS (immediate)
  [<TestMethod>]
  member _.``F5.1.129 ORRS``() =
    testDisasm "e1910002" "orrs r0, r1, r2"
    testDisasm "e1910312" "orrs r0, r1, r2, lsl r3"
    testDisasm "e1910332" "orrs r0, r1, r2, lsr r3"
    testDisasm "e1910352" "orrs r0, r1, r2, asr r3"

  /// F5.1.132 PKHBT, PKHTB
  [<TestMethod>]
  member _.``F5.1.132 PKHBT``() =
    testDisasm "e6810212" "pkhbt r0, r1, r2, lsl #0x4"
    testDisasm "e6810012" "pkhbt r0, r1, r2"
    testDisasm "e681d014" "pkhbt sp, r1, r4"
    testDisasm "e681d114" "pkhbt sp, r1, r4, lsl #0x2"

  /// F5.1.132 PKHBT, PKHTB
  [<TestMethod>]
  member _.``F5.1.132 PKHTB``() =
    testDisasm "e6810252" "pkhtb r0, r1, r2, asr #0x4"
    testDisasm "e681d054" "pkhtb sp, r1, r4, asr #0x20"
    testDisasm "e6892054" "pkhtb r2, sb, r4, asr #0x20"
    testDisasm "e689d054" "pkhtb sp, sb, r4, asr #0x20"

  /// F5.1.141 PSSBB
  [<TestMethod>]
  member _.``F5.1.141 PSSBB``() =
    testDisasm "f57ff044" "pssbb"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEDA``() =
    testDisasm "f8310a00" "rfeda r1!"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEDB``() =
    testDisasm "f9110a00" "rfedb r1"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEIA``() =
    testDisasm "f8910a00" "rfeia r1"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEIB``() =
    testDisasm "f9b10a00" "rfeib r1!"

  /// F5.1.16 ASRS (immediate)
  [<TestMethod>]
  member _.``F5.1.16 ASRS``() =
    testDisasm "e1b00842" "asrs r0, r2, #0x10"
    testDisasm "e1b00251" "asrs r0, r1, r2"
    testDisasm "e1b02954" "asrs r2, r4, sb"
    testDisasm "e1b02a54" "asrs r2, r4, sl"

  /// F5.1.162 RORS (immediate)
  [<TestMethod>]
  member _.``F5.1.162 RORS``() =
    testDisasm "e1b00862" "rors r0, r2, #0x10"
    testDisasm "e1b00271" "rors r0, r1, r2"
    testDisasm "e1b02974" "rors r2, r4, sb"
    testDisasm "e1b02a74" "rors r2, r4, sl"

  /// F5.1.165 RRXS
  [<TestMethod>]
  member _.``F5.1.165 RRXS``() =
    testDisasm "e1b00062" "rrxs r0, r2"
    testDisasm "e1b0206f" "rrxs r2, pc"
    testDisasm "e1b0d064" "rrxs sp, r4"
    testDisasm "e1b0d06f" "rrxs sp, pc"

  /// F5.1.166 RSB, RSBS (immediate)
  [<TestMethod>]
  member _.``F5.1.166 RSBS``() =
    testDisasm "e0710002" "rsbs r0, r1, r2"
    testDisasm "e0710312" "rsbs r0, r1, r2, lsl r3"
    testDisasm "e0710332" "rsbs r0, r1, r2, lsr r3"
    testDisasm "e0710352" "rsbs r0, r1, r2, asr r3"

  /// F5.1.169 RSC, RSCS (immediate)
  [<TestMethod>]
  member _.``F5.1.169 RSCS``() =
    testDisasm "e0f10002" "rscs r0, r1, r2"
    testDisasm "e0f10312" "rscs r0, r1, r2, lsl r3"
    testDisasm "e0f10332" "rscs r0, r1, r2, lsr r3"
    testDisasm "e0f10352" "rscs r0, r1, r2, asr r3"

  /// F5.1.175 SB
  [<TestMethod>]
  member _.``F5.1.175 SB``() =
    testDisasm "e0d10002" "sbcs r0, r1, r2"
    testDisasm "e0d10312" "sbcs r0, r1, r2, lsl r3"
    testDisasm "e0d10332" "sbcs r0, r1, r2, lsr r3"
    testDisasm "e0d10352" "sbcs r0, r1, r2, asr r3"

  /// F5.1.176 SBC, SBCS (immediate)
  [<TestMethod>]
  member _.``F5.1.176 SBCS``() =
    testDisasm "e0d10002" "sbcs r0, r1, r2"
    testDisasm "e0d10312" "sbcs r0, r1, r2, lsl r3"
    testDisasm "e0d10332" "sbcs r0, r1, r2, lsr r3"
    testDisasm "e0d10352" "sbcs r0, r1, r2, asr r3"

  /// F5.1.183 SETPAN
  [<TestMethod>]
  member _.``F5.1.183 SETPAN``() =
    testDisasm "f1100000" "setpan #0x0"

  /// F5.1.185 SEVL
  [<TestMethod>]
  member _.``F5.1.185 SEVL``() =
    testDisasm "e320f005" "sevl"

  /// F5.1.194 SMLAD, SMLADX
  [<TestMethod>]
  member _.``F5.1.194 SMLADX``() =
    testDisasm "e7003231" "smladx r0, r1, r2, r3"
    testDisasm "e7012934" "smladx r1, r4, sb, r2"
    testDisasm "e7012a34" "smladx r1, r4, sl, r2"
    testDisasm "e7012b34" "smladx r1, r4, fp, r2"

  /// F5.1.195 SMLAL, SMLALS
  [<TestMethod>]
  member _.``F5.1.195 SMLALS``() =
    testDisasm "e0f10291" "smlals r0, r1, r1, r2"
    testDisasm "e0f12994" "smlals r2, r1, r4, sb"
    testDisasm "e0f12a94" "smlals r2, r1, r4, sl"
    testDisasm "e0f12b94" "smlals r2, r1, r4, fp"

  /// F5.1.197 SMLALD, SMLALDX
  [<TestMethod>]
  member _.``F5.1.197 SMLALDX``() =
    testDisasm "e7410231" "smlaldx r0, r1, r1, r2"
    testDisasm "e7412934" "smlaldx r2, r1, r4, sb"
    testDisasm "e7412a34" "smlaldx r2, r1, r4, sl"
    testDisasm "e7412b34" "smlaldx r2, r1, r4, fp"

  /// F5.1.199 SMLSD, SMLSDX
  [<TestMethod>]
  member _.``F5.1.199 SMLSDX``() =
    testDisasm "e7003271" "smlsdx r0, r1, r2, r3"
    testDisasm "e7012974" "smlsdx r1, r4, sb, r2"
    testDisasm "e7012a74" "smlsdx r1, r4, sl, r2"
    testDisasm "e7012b74" "smlsdx r1, r4, fp, r2"

  /// F5.1.200 SMLSLD, SMLSLDX
  [<TestMethod>]
  member _.``F5.1.200 SMLSLDX``() =
    testDisasm "e7410271" "smlsldx r0, r1, r1, r2"
    testDisasm "e7412974" "smlsldx r2, r1, r4, sb"
    testDisasm "e7412a74" "smlsldx r2, r1, r4, sl"
    testDisasm "e7412b74" "smlsldx r2, r1, r4, fp"

  /// F5.1.201 SMMLA, SMMLAR
  [<TestMethod>]
  member _.``F5.1.201 SMMLAR``() =
    testDisasm "e7503231" "smmlar r0, r1, r2, r3"
    testDisasm "e7512934" "smmlar r1, r4, sb, r2"
    testDisasm "e7512a34" "smmlar r1, r4, sl, r2"
    testDisasm "e7512b34" "smmlar r1, r4, fp, r2"

  /// F5.1.202 SMMLS, SMMLSR
  [<TestMethod>]
  member _.``F5.1.202 SMMLSR``() =
    testDisasm "e75032f1" "smmlsr r0, r1, r2, r3"
    testDisasm "e75129f4" "smmlsr r1, r4, sb, r2"
    testDisasm "e7512af4" "smmlsr r1, r4, sl, r2"
    testDisasm "e7512bf4" "smmlsr r1, r4, fp, r2"

  /// F5.1.203 SMMUL, SMMULR
  [<TestMethod>]
  member _.``F5.1.203 SMMULR``() =
    testDisasm "e750f231" "smmulr r0, r1, r2"
    testDisasm "e751f934" "smmulr r1, r4, sb"
    testDisasm "e751fa34" "smmulr r1, r4, sl"
    testDisasm "e751fb34" "smmulr r1, r4, fp"

  /// F5.1.204 SMUAD, SMUADX
  [<TestMethod>]
  member _.``F5.1.204 SMUADX``() =
    testDisasm "e700f231" "smuadx r0, r1, r2"
    testDisasm "e701f934" "smuadx r1, r4, sb"
    testDisasm "e701fa34" "smuadx r1, r4, sl"
    testDisasm "e701fb34" "smuadx r1, r4, fp"

  /// F5.1.206 SMULL, SMULLS
  [<TestMethod>]
  member _.``F5.1.206 SMULLS``() =
    testDisasm "e0d10291" "smulls r0, r1, r1, r2"
    testDisasm "e0d12994" "smulls r2, r1, r4, sb"
    testDisasm "e0d12a94" "smulls r2, r1, r4, sl"
    testDisasm "e0d12b94" "smulls r2, r1, r4, fp"

  /// F5.1.208 SMUSD, SMUSDX
  [<TestMethod>]
  member _.``F5.1.208 SMUSDX``() =
    testDisasm "e700f271" "smusdx r0, r1, r2"
    testDisasm "e701f974" "smusdx r1, r4, sb"
    testDisasm "e701fa74" "smusdx r1, r4, sl"
    testDisasm "e701fb74" "smusdx r1, r4, fp"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSDA``() =
    testDisasm "f84d0513" "srsda sp, #0x13"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSDB``() =
    testDisasm "f96d0513" "srsdb sp!, #0x13"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSIA``() =
    testDisasm "f8cd0513" "srsia sp, #0x13"
    testDisasm "f8ed0513" "srsia sp!, #0x13"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSIB``() =
    testDisasm "f9cd0513" "srsib sp, #0x13"

  /// F5.1.21 BIC, BICS (immediate)
  [<TestMethod>]
  member _.``F5.1.21 BICS``() =
    testDisasm "e1d10002" "bics r0, r1, r2"
    testDisasm "e1d10312" "bics r0, r1, r2, lsl r3"
    testDisasm "e1d10332" "bics r0, r1, r2, lsr r3"
    testDisasm "e1d10352" "bics r0, r1, r2, asr r3"

  /// F5.1.213 SSBB
  [<TestMethod>]
  member _.``F5.1.213 SSBB``() =
    testDisasm "f57ff040" "ssbb"

  /// F5.1.217 STL
  [<TestMethod>]
  member _.``F5.1.217 STL``() =
    testDisasm "e181fc90" "stl r0, [r1]"

  /// F5.1.218 STLB
  [<TestMethod>]
  member _.``F5.1.218 STLB``() =
    testDisasm "e1c1fc90" "stlb r0, [r1]"

  /// F5.1.219 STLEX
  [<TestMethod>]
  member _.``F5.1.219 STLEX``() =
    testDisasm "e1810e92" "stlex r0, r2, [r1]"
    testDisasm "e181de94" "stlex sp, r4, [r1]"
    testDisasm "e1892e94" "stlex r2, r4, [sb]"
    testDisasm "e189de94" "stlex sp, r4, [sb]"

  /// F5.1.220 STLEXB
  [<TestMethod>]
  member _.``F5.1.220 STLEXB``() =
    testDisasm "e1c10e92" "stlexb r0, r2, [r1]"
    testDisasm "e1c1de94" "stlexb sp, r4, [r1]"
    testDisasm "e1c92e94" "stlexb r2, r4, [sb]"
    testDisasm "e1c9de94" "stlexb sp, r4, [sb]"

  /// F5.1.221 STLEXD
  [<TestMethod>]
  member _.``F5.1.221 STLEXD``() =
    testDisasm "e1a10e92" "stlexd r0, r2, r3, [r1]"
    testDisasm "e1a1de94" "stlexd sp, r4, r5, [r1]"
    testDisasm "e1a92e94" "stlexd r2, r4, r5, [sb]"
    testDisasm "e1a9de94" "stlexd sp, r4, r5, [sb]"

  /// F5.1.222 STLEXH
  [<TestMethod>]
  member _.``F5.1.222 STLEXH``() =
    testDisasm "e1e10e92" "stlexh r0, r2, [r1]"
    testDisasm "e1e1de94" "stlexh sp, r4, [r1]"
    testDisasm "e1e92e94" "stlexh r2, r4, [sb]"
    testDisasm "e1e9de94" "stlexh sp, r4, [sb]"

  /// F5.1.223 STLH
  [<TestMethod>]
  member _.``F5.1.223 STLH``() =
    testDisasm "e1e1fc90" "stlh r0, [r1]"

  /// F5.1.224 STM, STMIA, STMEA
  [<TestMethod>]
  member _.``F5.1.224 STMEA``() =
    testDisasm "e881000c" "stm r1, {r2, r3}"
    testDisasm "e8a1000c" "stm r1!, {r2, r3}"
    testDisasm "e8812004" "stm r1, {r2, sp}"
    testDisasm "e8812000" "stm r1, {sp}"

  /// F5.1.224 STM, STMIA, STMEA
  [<TestMethod>]
  member _.``F5.1.224 STMIA``() =
    testDisasm "e881000c" "stm r1, {r2, r3}"
    testDisasm "e8a1000c" "stm r1!, {r2, r3}"
    testDisasm "e8812004" "stm r1, {r2, sp}"
    testDisasm "e8812000" "stm r1, {sp}"

  /// F5.1.226 STMDA, STMED
  [<TestMethod>]
  member _.``F5.1.226 STMED``() =
    testDisasm "e801000c" "stmda r1, {r2, r3}"
    testDisasm "e8012004" "stmda r1, {r2, sp}"
    testDisasm "e8012000" "stmda r1, {sp}"
    testDisasm "e801200f" "stmda r1, {r0, r1, r2, r3, sp}"

  /// F5.1.227 STMDB, STMFD
  [<TestMethod>]
  member _.``F5.1.227 STMFD``() =
    testDisasm "e901000c" "stmdb r1, {r2, r3}"
    testDisasm "e92d000c" "push {r2, r3}"
    testDisasm "e921000c" "stmdb r1!, {r2, r3}"
    testDisasm "e52d2004" "push {r2}"

  /// F5.1.228 STMIB, STMFA
  [<TestMethod>]
  member _.``F5.1.228 STMFA``() =
    testDisasm "e981000c" "stmib r1, {r2, r3}"
    testDisasm "e9812004" "stmib r1, {r2, sp}"
    testDisasm "e9812000" "stmib r1, {sp}"
    testDisasm "e981200f" "stmib r1, {r0, r1, r2, r3, sp}"

  /// F5.1.278 UMLAL, UMLALS
  [<TestMethod>]
  member _.``F5.1.278 UMLALS``() =
    testDisasm "e0b10291" "umlals r0, r1, r1, r2"
    testDisasm "e0b12994" "umlals r2, r1, r4, sb"
    testDisasm "e0b12a94" "umlals r2, r1, r4, sl"
    testDisasm "e0b12b94" "umlals r2, r1, r4, fp"

  /// F5.1.279 UMULL, UMULLS
  [<TestMethod>]
  member _.``F5.1.279 UMULLS``() =
    testDisasm "e0910291" "umulls r0, r1, r1, r2"
    testDisasm "e0912994" "umulls r2, r1, r4, sb"
    testDisasm "e0912a94" "umulls r2, r1, r4, sl"
    testDisasm "e0912b94" "umulls r2, r1, r4, fp"

  /// F5.1.38 CPS, CPSID, CPSIE
  [<TestMethod>]
  member _.``F5.1.38 CPSID``() =
    testDisasm "f10e00d3" "cpsid if, #0x13"

  /// F5.1.38 CPS, CPSID, CPSIE
  [<TestMethod>]
  member _.``F5.1.38 CPSIE``() =
    testDisasm "f1080080" "cpsie i"

  /// F5.1.39 CRC32
  [<TestMethod>]
  member _.``F5.1.39 CRC32``() =
    testDisasm "e1020043" "crc32b r0, r2, r3"
    testDisasm "e1210042" "crc32h r0, r1, r2"
    testDisasm "e1410042" "crc32w r0, r1, r2"
    testDisasm "e101d044" "crc32b sp, r1, r4"

  /// F5.1.4 ADD, ADDS (immediate)
  [<TestMethod>]
  member _.``F5.1.4 ADDS``() =
    testDisasm "e0911002" "adds r1, r1, r2"
    testDisasm "e0910312" "adds r0, r1, r2, lsl r3"
    testDisasm "e0910332" "adds r0, r1, r2, lsr r3"
    testDisasm "e0910352" "adds r0, r1, r2, asr r3"

  /// F5.1.40 CRC32C
  [<TestMethod>]
  member _.``F5.1.40 CRC32C``() =
    testDisasm "e1420243" "crc32cw r0, r2, r3"
    testDisasm "e1010242" "crc32cb r0, r1, r2"
    testDisasm "e1210242" "crc32ch r0, r1, r2"
    testDisasm "e101d244" "crc32cb sp, r1, r4"

  /// F5.1.48 EOR, EORS (immediate)
  [<TestMethod>]
  member _.``F5.1.48 EORS``() =
    testDisasm "e0310002" "eors r0, r1, r2"
    testDisasm "e0310312" "eors r0, r1, r2, lsl r3"
    testDisasm "e0310332" "eors r0, r1, r2, lsr r3"
    testDisasm "e0310352" "eors r0, r1, r2, asr r3"

  /// F5.1.52 ESB
  [<TestMethod>]
  member _.``F5.1.52 ESB``() =
    testDisasm "e320f010" "esb"

  /// F5.1.53 HLT
  [<TestMethod>]
  member _.``F5.1.53 HLT``() =
    testDisasm "e1000070" "hlt #0x0"

  /// F5.1.57 LDA
  [<TestMethod>]
  member _.``F5.1.57 LDA``() =
    testDisasm "e1910c9f" "lda r0, [r1]"

  /// F5.1.58 LDAB
  [<TestMethod>]
  member _.``F5.1.58 LDAB``() =
    testDisasm "e1d10c9f" "ldab r0, [r1]"

  /// F5.1.59 LDAEX
  [<TestMethod>]
  member _.``F5.1.59 LDAEX``() =
    testDisasm "e1910e9f" "ldaex r0, [r1]"

  /// F5.1.60 LDAEXB
  [<TestMethod>]
  member _.``F5.1.60 LDAEXB``() =
    testDisasm "e1d10e9f" "ldaexb r0, [r1]"

  /// F5.1.61 LDAEXD
  [<TestMethod>]
  member _.``F5.1.61 LDAEXD``() =
    testDisasm "e1b12e9f" "ldaexd r2, r3, [r1]"

  /// F5.1.62 LDAEXH
  [<TestMethod>]
  member _.``F5.1.62 LDAEXH``() =
    testDisasm "e1f10e9f" "ldaexh r0, [r1]"

  /// F5.1.63 LDAH
  [<TestMethod>]
  member _.``F5.1.63 LDAH``() =
    testDisasm "e1f10c9f" "ldah r0, [r1]"

  /// F6.1.1 AESD
  [<TestMethod>]
  member _.``F6.1.1 AESD``() =
    testDisasm "f3b00342" "aesd.8 q0, q1"

  /// F6.1.10 SHA1P
  [<TestMethod>]
  member _.``F6.1.10 SHA1P``() =
    testDisasm "f2120c44" "sha1p.32 q0, q1, q2"

  /// F6.1.11 SHA1SU0
  [<TestMethod>]
  member _.``F6.1.11 SHA1SU0``() =
    testDisasm "f2320c44" "sha1su0.32 q0, q1, q2"

  /// F6.1.112 VLDM, VLDMDB, VLDMIA
  [<TestMethod>]
  member _.``F6.1.112 VLDMDB``() =
    testDisasm "ed312a04" "vldmdb r1!, {s4, s5, s6, s7}"
    testDisasm "ed312a01" "vldmdb r1!, {s4}"
    ("vldmdb r1!, {s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, "
     + "s16, s17, s18}")
    |> testDisasm "ed312a0f"
    testDisasm "ed312b04" "vldmdb r1!, {d2, d3}"

  /// F6.1.112 VLDM, VLDMDB, VLDMIA
  [<TestMethod>]
  member _.``F6.1.112 VLDMIA``() =
    testDisasm "ec910b04" "vldmia r1, {d0, d1}"
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecb10b08" "vldmia r1!, {d0, d1, d2, d3}"
    testDisasm "ec912a04" "vldmia r1, {s4, s5, s6, s7}"

  /// F6.1.117 VMAXNM
  [<TestMethod>]
  member _.``F6.1.117 VMAXNM``() =
    testDisasm "fe800981" "vmaxnm.f16 s0, s1, s2"
    testDisasm "f3120f54" "vmaxnm.f16 q0, q1, q2"
    testDisasm "f3012f14" "vmaxnm.f32 d2, d1, d4"

  /// F6.1.12 SHA1SU1
  [<TestMethod>]
  member _.``F6.1.12 SHA1SU1``() =
    testDisasm "f3ba0382" "sha1su1.32 q0, q1"

  /// F6.1.120 VMINNM
  [<TestMethod>]
  member _.``F6.1.120 VMINNM``() =
    testDisasm "fe8009c1" "vminnm.f16 s0, s1, s2"
    testDisasm "f3320f54" "vminnm.f16 q0, q1, q2"
    testDisasm "f3212f14" "vminnm.f32 d2, d1, d4"

  /// F6.1.13 SHA256H
  [<TestMethod>]
  member _.``F6.1.13 SHA256H``() =
    testDisasm "f3020c44" "sha256h.32 q0, q1, q2"

  /// F6.1.131 VMMLA
  [<TestMethod>]
  member _.``F6.1.131 VMMLA``() =
    testDisasm "fc002c44" "vmmla.bf16 q1, q0, q2"

  /// F6.1.14 SHA256H2
  [<TestMethod>]
  member _.``F6.1.14 SHA256H2``() =
    testDisasm "f3120c44" "sha256h2.32 q0, q1, q2"

  /// F6.1.143 VMOVX
  [<TestMethod>]
  member _.``F6.1.143 VMOVX``() =
    testDisasm "feb00a60" "vmovx.f16 s0, s1"

  /// F6.1.15 SHA256SU0
  [<TestMethod>]
  member _.``F6.1.15 SHA256SU0``() =
    testDisasm "f3ba03c2" "sha256su0.32 q0, q1"

  /// F6.1.16 SHA256SU1
  [<TestMethod>]
  member _.``F6.1.16 SHA256SU1``() =
    testDisasm "f3220c44" "sha256su1.32 q0, q1, q2"

  /// F6.1.179 VQRDMLAH
  [<TestMethod>]
  member _.``F6.1.179 VQRDMLAH``() =
    testDisasm "f3110b12" "vqrdmlah.s16 d0, d1, d2"
    testDisasm "f2912e44" "vqrdmlah.s16 d2, d1, d4[0]"
    testDisasm "f3102b54" "vqrdmlah.s16 q1, q0, q2"
    testDisasm "f3902e44" "vqrdmlah.s16 q1, q0, d4[0]"

  /// F6.1.180 VQRDMLSH
  [<TestMethod>]
  member _.``F6.1.180 VQRDMLSH``() =
    testDisasm "f3220c54" "vqrdmlsh.s32 q0, q1, q2"
    testDisasm "f2912f44" "vqrdmlsh.s16 d2, d1, d4[0]"
    testDisasm "f3112c14" "vqrdmlsh.s16 d2, d1, d4"
    testDisasm "f3902f44" "vqrdmlsh.s16 q1, q0, d4[0]"

  /// F6.1.199 VRINTA (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.199 VRINTA``() =
    testDisasm "feb80960" "vrinta.f16 s0, s1"
    testDisasm "f3b60542" "vrinta.f16 q0, q1"

  /// F6.1.2 AESE
  [<TestMethod>]
  member _.``F6.1.2 AESE``() =
    testDisasm "f3b00302" "aese.8 q0, q1"

  /// F6.1.201 VRINTM (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.201 VRINTM``() =
    testDisasm "febb0960" "vrintm.f16 s0, s1"
    testDisasm "f3b606c2" "vrintm.f16 q0, q1"
    testDisasm "febb0b41" "vrintm.f64 d0, d1"

  /// F6.1.203 VRINTN (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.203 VRINTN``() =
    testDisasm "feb90960" "vrintn.f16 s0, s1"
    testDisasm "f3b60442" "vrintn.f16 q0, q1"
    testDisasm "feb92b44" "vrintn.f64 d2, d4"

  /// F6.1.205 VRINTP (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.205 VRINTP``() =
    testDisasm "feba0960" "vrintp.f16 s0, s1"
    testDisasm "f3b607c2" "vrintp.f16 q0, q1"
    testDisasm "f3ba0781" "vrintp.f32 d0, d1"

  /// F6.1.207 VRINTR
  [<TestMethod>]
  member _.``F6.1.207 VRINTR``() =
    testDisasm "eeb60960" "vrintr.f16 s0, s1"

  /// F6.1.208 VRINTX (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.208 VRINTX``() =
    testDisasm "eeb70960" "vrintx.f16 s0, s1"
    testDisasm "f3b604c2" "vrintx.f16 q0, q1"
    testDisasm "eeb70b41" "vrintx.f64 d0, d1"

  /// F6.1.210 VRINTZ (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.210 VRINTZ``() =
    testDisasm "eeb609e0" "vrintz.f16 s0, s1"
    testDisasm "f3b605c2" "vrintz.f16 q0, q1"

  /// F6.1.221 VSDOT (by element)
  [<TestMethod>]
  member _.``F6.1.221 VSDOT``() =
    testDisasm "fc210d02" "vsdot.s8 d0, d1, d2"
    testDisasm "fc202d44" "vsdot.s8 q1, q0, q2"
    testDisasm "fe212d04" "vsdot.s8 d2, d1, d4[0]"
    testDisasm "fe202d44" "vsdot.s8 q1, q0, d4[0]"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELEQ``() =
    testDisasm "fe000981" "vseleq.f16 s0, s1, s2"
    testDisasm "fe012b04" "vseleq.f64 d2, d1, d4"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELGE``() =
    testDisasm "fe200981" "vselge.f16 s0, s1, s2"
    testDisasm "fe210b02" "vselge.f64 d0, d1, d2"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELGT``() =
    testDisasm "fe300981" "vselgt.f16 s0, s1, s2"
    testDisasm "fe312b04" "vselgt.f64 d2, d1, d4"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELVS``() =
    testDisasm "fe100981" "vselvs.f16 s0, s1, s2"
    testDisasm "fe110b02" "vselvs.f64 d0, d1, d2"

  /// F6.1.232 VSMMLA
  [<TestMethod>]
  member _.``F6.1.232 VSMMLA``() =
    testDisasm "fc202c44" "vsmmla.s8 q1, q0, q2"

  /// F6.1.244 VSTM, VSTMDB, VSTMIA
  [<TestMethod>]
  member _.``F6.1.244 VSTMDB``() =
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"
    testDisasm "ed212a04" "vstmdb r1!, {s4, s5, s6, s7}"
    testDisasm "ed212a01" "vstmdb r1!, {s4}"

  /// F6.1.244 VSTM, VSTMDB, VSTMIA
  [<TestMethod>]
  member _.``F6.1.244 VSTMIA``() =
    testDisasm "ec810b04" "vstmia r1, {d0, d1}"
    testDisasm "ec810a04" "vstmia r1, {s0, s1, s2, s3}"
    testDisasm "ec812a01" "vstmia r1, {s4}"
    ("vstmia r1, {s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, "
     + "s16, s17, s18}")
    |> testDisasm "ec812a0f"

  /// F6.1.251 VSUDOT (by element)
  [<TestMethod>]
  member _.``F6.1.251 VSUDOT``() =
    testDisasm "fe812d14" "vsudot.u8 d2, d1, d4[0]"
    testDisasm "fe802d54" "vsudot.u8 q1, q0, d4[0]"

  /// F6.1.256 VUDOT (by element)
  [<TestMethod>]
  member _.``F6.1.256 VUDOT``() =
    testDisasm "fe220d74" "vudot.u8 q0, q1, d4[1]"
    testDisasm "fc212d14" "vudot.u8 d2, d1, d4"
    testDisasm "fc202d54" "vudot.u8 q1, q0, q2"
    testDisasm "fe212d14" "vudot.u8 d2, d1, d4[0]"

  /// F6.1.258 VUMMLA
  [<TestMethod>]
  member _.``F6.1.258 VUMMLA``() =
    testDisasm "fc202c54" "vummla.u8 q1, q0, q2"

  /// F6.1.259 VUSDOT (by element)
  [<TestMethod>]
  member _.``F6.1.259 VUSDOT``() =
    testDisasm "fca12d04" "vusdot.s8 d2, d1, d4"
    testDisasm "fca02d44" "vusdot.s8 q1, q0, q2"
    testDisasm "fe812d04" "vusdot.s8 d2, d1, d4[0]"
    testDisasm "fe802d44" "vusdot.s8 q1, q0, d4[0]"

  /// F6.1.261 VUSMMLA
  [<TestMethod>]
  member _.``F6.1.261 VUSMMLA``() =
    testDisasm "fca02c44" "vusmmla.s8 q1, q0, q2"

  /// F6.1.3 AESIMC
  [<TestMethod>]
  member _.``F6.1.3 AESIMC``() =
    testDisasm "f3b003c2" "aesimc.8 q0, q1"

  /// F6.1.39 VCADD
  [<TestMethod>]
  member _.``F6.1.39 VCADD``() =
    testDisasm "fc910802" "vcadd.f32 d0, d1, d2, #0x5a"
    testDisasm "fc802844" "vcadd.f16 q1, q0, q2, #0x5a"

  /// F6.1.4 AESMC
  [<TestMethod>]
  member _.``F6.1.4 AESMC``() =
    testDisasm "f3b00382" "aesmc.8 q0, q1"

  /// F6.1.52 VCMLA
  [<TestMethod>]
  member _.``F6.1.52 VCMLA``() =
    testDisasm "fc310802" "vcmla.f32 d0, d1, d2, #0x0"
    testDisasm "fc202844" "vcmla.f16 q1, q0, q2, #0x0"
    testDisasm "fe012804" "vcmla.f16 d2, d1, d4[0], #0x0"
    testDisasm "fe002844" "vcmla.f16 q1, q0, d4[0], #0x0"

  /// F6.1.6 FSTMDBX, FSTMIAX
  [<TestMethod>]
  member _.``F6.1.6 FSTMDBX``() =
    testDisasm "ed212b0f" "fstmdbx r1!, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ed292b0f" "fstmdbx sb!, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ed2d2b0f" "fstmdbx sp!, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ed212b11" "fstmdbx r1!, {d2, d3, d4, d5, d6, d7, d8, d9}"

  /// F6.1.6 FSTMDBX, FSTMIAX
  [<TestMethod>]
  member _.``F6.1.6 FSTMIAX``() =
    testDisasm "ec812b0f" "fstmiax r1, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ec892b0f" "fstmiax sb, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ec8d2b0f" "fstmiax sp, {d2, d3, d4, d5, d6, d7, d8}"
    testDisasm "ec8f2b0f" "fstmiax pc, {d2, d3, d4, d5, d6, d7, d8}"

  /// F6.1.65 VCVTA (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.65 VCVTA``() =
    testDisasm "febc09e0" "vcvta.s32.f16 s0, s1"
    testDisasm "f3b70042" "vcvta.s16.f16 q0, q1"

  /// F6.1.69 VCVTM (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.69 VCVTM``() =
    testDisasm "febf09e0" "vcvtm.s32.f16 s0, s1"
    testDisasm "f3b70342" "vcvtm.s16.f16 q0, q1"
    testDisasm "febf0b41" "vcvtm.u32.f64 s0, d1"
    testDisasm "febf2944" "vcvtm.u32.f16 s4, s8"

  /// F6.1.7 SHA1C
  [<TestMethod>]
  member _.``F6.1.7 SHA1C``() =
    testDisasm "f2020c44" "sha1c.32 q0, q1, q2"

  /// F6.1.71 VCVTN (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.71 VCVTN``() =
    testDisasm "febd09e0" "vcvtn.s32.f16 s0, s1"
    testDisasm "f3b70142" "vcvtn.s16.f16 q0, q1"
    testDisasm "f3bb0101" "vcvtn.s32.f32 d0, d1"
    testDisasm "febd2944" "vcvtn.u32.f16 s4, s8"

  /// F6.1.73 VCVTP (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.73 VCVTP``() =
    testDisasm "febe09e0" "vcvtp.s32.f16 s0, s1"
    testDisasm "f3b70242" "vcvtp.s16.f16 q0, q1"
    testDisasm "f3bb02c2" "vcvtp.u32.f32 q0, q1"

  /// F6.1.79 VDOT (vector)
  [<TestMethod>]
  member _.``F6.1.79 VDOT``() =
    testDisasm "fc012d04" "vdot.bf16 d2, d1, d4"
    testDisasm "fc002d44" "vdot.bf16 q1, q0, q2"
    testDisasm "fe012d04" "vdot.bf16 d2, d1, d4[0]"
    testDisasm "fe002d44" "vdot.bf16 q1, q0, d4[0]"

  /// F6.1.8 SHA1H
  [<TestMethod>]
  member _.``F6.1.8 SHA1H``() =
    testDisasm "f3b902c2" "sha1h.32 q0, q1"

  /// F6.1.87 VFMAB, VFMAT (BFloat16, vector)
  [<TestMethod>]
  member _.``F6.1.87 VFMAB``() =
    testDisasm "fc302814" "vfmab.bf16 q1, q0, q2"
    testDisasm "fe302814" "vfmab.bf16 q1, q0, d4[0]"

  /// F6.1.87 VFMAB, VFMAT (BFloat16, vector)
  [<TestMethod>]
  member _.``F6.1.87 VFMAT``() =
    testDisasm "fc302854" "vfmat.bf16 q1, q0, q2"
    testDisasm "fe302854" "vfmat.bf16 q1, q0, d4[0]"

  /// F6.1.89 VFMAL (vector)
  [<TestMethod>]
  member _.``F6.1.89 VFMAL``() =
    testDisasm "fc210831" "vfmal.f16 d0, s2, s3"
    testDisasm "fc212854" "vfmal.f16 q1, d1, d4"
    testDisasm "fe012814" "vfmal.f16 d2, s2, s8[0]"
    testDisasm "fe012854" "vfmal.f16 q1, d1, d4[0]"

  /// F6.1.9 SHA1M
  [<TestMethod>]
  member _.``F6.1.9 SHA1M``() =
    testDisasm "f2220c44" "sha1m.32 q0, q1, q2"

  /// F6.1.92 VFMSL (vector)
  [<TestMethod>]
  member _.``F6.1.92 VFMSL``() =
    testDisasm "fe12085b" "vfmsl.f16 q0, d2, d3[1]"
    testDisasm "fca12814" "vfmsl.f16 d2, s2, s8"
    testDisasm "fca12854" "vfmsl.f16 q1, d1, d4"
    testDisasm "fe112814" "vfmsl.f16 d2, s2, s8[0]"

  /// F6.1.98 VINS
  [<TestMethod>]
  member _.``F6.1.98 VINS``() =
    testDisasm "feb00ae0" "vins.f16 s0, s1"

  /// F6.1.99 VJCVT
  [<TestMethod>]
  member _.``F6.1.99 VJCVT``() =
    testDisasm "eeb90bc1" "vjcvt.s32.f64 s0, d1"

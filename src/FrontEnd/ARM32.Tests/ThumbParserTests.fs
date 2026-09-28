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
open type Opcode
open type Register

/// - A4.3 Branch instructions
/// - A4.4 Data-processing instructions
/// - A4.5 Status register access instructions
/// - A4.6 Load/store instructions
/// - A4.7 Load/store multiple instructions
/// - A4.8 Miscellaneous instructions
/// - A4.9 Exception-generating and exception-handling instructions
/// - A5.4 Media instructions
/// - A6.3.4 Branches and miscellaneous control
[<TestClass>]
type ThumbParserTests() =
  let test c op (wback: bool) q (s: SIMDDataTypes option) (oprs: Operands) bs =
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let reader = BinReader.Init Endian.Big
    let parser = ARM32Parser(isa, true, reader) :> IInstructionParsable
    let ins = parser.Parse(bs = bs, addr = 0UL) :?> Instruction
    let cond' = ins.Condition
    let opcode' = ins.Opcode
    let wback' = ins.WriteBack
    let q' = ins.Qualifier
    let q = if Option.isSome q then W else N
    let simd' = ins.SIMDTyp
    let oprs' = ins.Operands
    Assert.AreEqual<Condition>(c, cond')
    Assert.AreEqual<Opcode>(op, opcode')
    Assert.AreEqual<bool>(wback, wback')
    Assert.AreEqual<Qualifier>(q, q')
    Assert.AreEqual<SIMDDataTypes option>(s, simd')
    Assert.AreEqual<Operands>(oprs, oprs')

  let testNoWbackNoQNoSimd pref (bytes: byte[]) (opcode, operands) =
    test pref opcode false None None operands bytes

  let testNoWbackNoSimd pref q (bytes: byte[]) (opcode, operands) =
    test pref opcode false q None operands bytes

  let testNoWbackNoQ pref simd (bytes: byte[]) (opcode, operands) =
    test pref opcode false None simd operands bytes

  let testNoQNoSimd pref wback (bytes: byte[]) (opcode, operands) =
    test pref opcode wback None None operands bytes

  let testNoSimd pref wback q (bytes: byte[]) (opcode, operands) =
    test pref opcode wback q None operands bytes

  /// Checks the disassembly of a word the parser must read.
  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let parser = ARM32Parser(isa, true, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// Checks that a word the manual calls UNPREDICTABLE is refused rather than
  /// decoded into whatever its fields happen to say.
  let testRefused (byteString: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let reader = BinReader.Init Endian.Big
    let parser = ARM32Parser(isa, true, reader) :> IInstructionParsable
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parser.Parse(bs = bytes, addr = 0UL) |> ignore)
    |> ignore

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands(oprs[0], oprs[1])
    | 3 -> ThreeOperands(oprs[0], oprs[1], oprs[2])
    | 4 -> FourOperands(oprs[0], oprs[1], oprs[2], oprs[3])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (1)``() =
    "d826"
    ++ B ** [ O.MemLabel 76L ]
    ||> testNoWbackNoQNoSimd Condition.HI

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (2)``() =
    "e184"
    ++ B ** [ O.MemLabel 776L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (3)``() =
    "f6738866"
    ++ B ** [ O.MemLabel 4294652108L ]
    ||> testNoWbackNoSimd Condition.LS (Some W)

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (4)``() =
    "f0309194"
    ++ B ** [ O.MemLabel 12780328L ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (5)``() =
    "b91a"
    ++ CBNZ ** [ O.Reg R2; O.MemLabel 6L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (6)``() =
    "47c8"
    ++ BLX ** [ O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (7)``() =
    "f436e184"
    ++ BLX ** [ O.MemLabel 4286800648L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (8)``() =
    "4718"
    ++ BX ** [ O.Reg R3 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (9)``() =
    "f3c58f00"
    ++ BXJ ** [ O.Reg R5 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Branch Parse test (10)``() =
    "e8def017"
    ++ TBH ** [ O.MemOffsetReg(LR, None, R7, ShiftOp.LSL, 1u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.1 Standard data-processing instructions
  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (1)``() =
    "f1526318"
    ++ ADCS ** [ O.Reg R3; O.Reg R2; O.Imm 159383552L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (2)``() =
    "44ec"
    ++ ADD ** [ O.Reg IP; O.Reg SP; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (3)``() =
    "44d5"
    ++ ADD ** [ O.Reg SP; O.Reg SP; O.Reg SL ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (4)``() =
    "448b"
    ++ ADD ** [ O.Reg FP; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (5)``() =
    "b066"
    ++ ADD ** [ O.Reg SP; O.Reg SP; O.Imm 408L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (6)``() =
    "ac28"
    ++ ADD ** [ O.Reg R4; O.Reg SP; O.Imm 160L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (7)``() =
    "f1040e01"
    ++ ADD ** [ O.Reg LR; O.Reg R4; O.Imm 1L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (8)``() =
    "180c"
    ++ ADDS ** [ O.Reg R4; O.Reg R1; O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (9)``() =
    "1c77"
    ++ ADDS ** [ O.Reg R7; O.Reg R6; O.Imm 1L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (10)``() =
    "f20b0001"
    ++ ADDW ** [ O.Reg R0; O.Reg FP; O.Imm 1L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (11)``() =
    "f20f0001"
    ++ ADR ** [ O.Reg R0; O.MemLabel 1L ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (12)``() =
    "a20f"
    ++ ADR ** [ O.Reg R2; O.MemLabel 60L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (13)``() =
    "403e"
    ++ ANDS ** [ O.Reg R6; O.Reg R6; O.Reg R7 ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (14)``() =
    "ea3c7605"
    ++ BICS
    ** [ O.Reg R6; O.Reg IP; O.Reg R5; O.Shift(ShiftOp.LSL, 28u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (15)``() =
    "2df3"
    ++ CMP ** [ O.Reg R5; O.Imm 243L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (16)``() =
    "45c8"
    ++ CMP ** [ O.Reg R8; O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (17)``() =
    "4544"
    ++ CMP ** [ O.Reg R4; O.Reg R8 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (18)``() =
    "f04f1708"
    ++ MOV ** [ O.Reg R7; O.Imm 524296L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (19)``() =
    "000e"
    ++ MOVS ** [ O.Reg R6; O.Reg R1; O.Shift(ShiftOp.LSL, 0u) ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (20)``() =
    "f6420b02"
    ++ MOVW ** [ O.Reg FP; O.Imm 10242L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (21)``() =
    "ea6ff49e"
    ++ MVN ** [ O.Reg R4; O.Reg LR; O.Shift(ShiftOp.LSR, 30u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (22)``() =
    "f5d90308"
    ++ RSBS ** [ O.Reg R3; O.Reg SB; O.Imm 8912896L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (23)``() =
    "424b"
    ++ RSBS ** [ O.Reg R3; O.Reg R1; O.Imm 0L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (24)``() =
    "f4914f88"
    ++ TEQ ** [ O.Reg R1; O.Imm 17408L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Standard data-processing Parse test (25)``() =
    "ea125f6b"
    ++ TST ** [ O.Reg R2; O.Reg FP; O.Shift(ShiftOp.ASR, 21u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.2 Shift instructions
  [<TestMethod>]
  member _.``[Thumb] Shift Parse test (1)``() =
    "fa5afb07"
    ++ ASRS ** [ O.Reg FP; O.Reg SL; O.Reg R7 ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Shift Parse test (2)``() =
    "0431"
    ++ LSLS ** [ O.Reg R1; O.Reg R6; O.Imm 16L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Shift Parse test (3)``() =
    "080a"
    ++ LSRS ** [ O.Reg R2; O.Reg R1; O.Imm 32L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Shift Parse test (4)``() =
    "ea5f0cda"
    ++ LSRS ** [ O.Reg IP; O.Reg SL; O.Imm 3L ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Shift Parse test (5)``() =
    "ea5f0039"
    ++ RRXS ** [ O.Reg R0; O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.3 Multiply instructions
  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (1)``() =
    "fb00c901"
    ++ MLA ** [ O.Reg SB; O.Reg R0; O.Reg R1; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (2)``() =
    "fb03fc0b"
    ++ MUL ** [ O.Reg IP; O.Reg R3; O.Reg FP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (3)``() =
    "4366"
    ++ MULS ** [ O.Reg R6; O.Reg R4; O.Reg R6 ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (4)``() =
    "fb2a5c14"
    ++ SMLADX ** [ O.Reg IP; O.Reg SL; O.Reg R4; O.Reg R5 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (5)``() =
    "fb1e5c21"
    ++ SMLATB ** [ O.Reg IP; O.Reg LR; O.Reg R1; O.Reg R5 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (6)``() =
    "fbc18aa3"
    ++ SMLALTB ** [ O.Reg R8; O.Reg SL; O.Reg R1; O.Reg R3 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (7)``() =
    "fbd0ced5"
    ++ SMLSLDX ** [ O.Reg IP; O.Reg LR; O.Reg R0; O.Reg R5 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (8)``() =
    "fb58f019"
    ++ SMMULR ** [ O.Reg R0; O.Reg R8; O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (9)``() =
    "fb1bf837"
    ++ SMULTT ** [ O.Reg R8; O.Reg FP; O.Reg R7 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Multiply Parse test (10)``() =
    "fb83a904"
    ++ SMULL ** [ O.Reg SL; O.Reg SB; O.Reg R3; O.Reg R4 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.4 Saturating instructions
  [<TestMethod>]
  member _.``[Thumb] Saturating Parse test (1)``() =
    "f3280c05"
    ++ SSAT16 ** [ O.Reg IP; O.Imm 6L; O.Reg R8 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Saturating Parse test (2)``() =
    "f3a31791"
    ++ USAT
    ** [ O.Reg R7; O.Imm 17L; O.Reg R3; O.Shift(ShiftOp.ASR, 6u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.5 Saturating addition and subtraction instructions
  [<TestMethod>]
  member _.``[Thumb] Saturating addition and subtraction Parse test (1)``() =
    "fa86fc9e"
    ++ QDADD ** [ O.Reg IP; O.Reg LR; O.Reg R6 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.6 Packing and unpacking instructions
  [<TestMethod>]
  member _.``[Thumb] Packing and unpacking Parse test (1)``() =
    "eacc404a"
    ++ PKHBT
    ** [ O.Reg R0; O.Reg IP; O.Reg SL; O.Shift(ShiftOp.LSL, 17u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Packing and unpacking Parse test (2)``() =
    "fa00f4b6"
    ++ SXTAH
    ** [ O.Reg R4; O.Reg R0; O.Reg R6; O.Shift(ShiftOp.ROR, 24u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Packing and unpacking Parse test (3)``() =
    "fa2ff996"
    ++ SXTB16 ** [ O.Reg SB; O.Reg R6; O.Shift(ShiftOp.ROR, 8u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Packing and unpacking Parse test (4)``() =
    "b287"
    ++ UXTH ** [ O.Reg R7; O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Packing and unpacking Parse test (5)``() =
    "fa1ff28c"
    ++ UXTH ** [ O.Reg R2; O.Reg IP ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  /// A4.4.7 Parallel addition and subtraction instructions
  [<TestMethod>]
  member _.``[Thumb] Parallel addition and subtraction Parse test (1)``() =
    // Signed
    "fa9cfb00"
    ++ SADD16 ** [ O.Reg FP; O.Reg IP; O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Parallel addition and subtraction Parse test (2)``() =
    // Saturating
    "fae8fe19"
    ++ QSAX ** [ O.Reg LR; O.Reg R8; O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Parallel addition and subtraction Parse test (3)``() =
    // Signed halving
    "fac0fc27"
    ++ SHSUB8 ** [ O.Reg IP; O.Reg R0; O.Reg R7 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Parallel addition and subtraction Parse test (4)``() =
    // Unsigned
    "faa0f146"
    ++ UASX ** [ O.Reg R1; O.Reg R0; O.Reg R6 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Parallel addition and subtraction Parse test (5)``() =
    // Unsigned saturating
    "fa8ef953"
    ++ UQADD8 ** [ O.Reg SB; O.Reg LR; O.Reg R3 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Parallel addition and subtraction Parse test (6)``() =
    // Unsigned halving
    "faa0f86a"
    ++ UHASX ** [ O.Reg R8; O.Reg R0; O.Reg SL ]
    ||> testNoWbackNoQNoSimd Condition.AL

  //// A4.4.8 Divide instructions
  [<TestMethod>]
  member _.``[Thumb] Divide Parse test (1)``() =
    "fbb0fcfe"
    ++ UDIV ** [ O.Reg IP; O.Reg R0; O.Reg LR ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.9 Miscellaneous data-processing instructions
  [<TestMethod>]
  member _.``[Thumb] Miscellaneous data-processing Parse test (1)``() =
    "f36f1c12"
    ++ BFC ** [ O.Reg IP; O.Imm 4L; O.Imm 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous data-processing Parse test (2)``() =
    "f3612ad1"
    ++ BFI ** [ O.Reg SL; O.Reg R1; O.Imm 11L; O.Imm 7L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous data-processing Parse test (3)``() =
    "fa94fca4"
    ++ RBIT ** [ O.Reg IP; O.Reg R4 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous data-processing Parse test (4)``() =
    "f34e0918"
    ++ SBFX ** [ O.Reg SB; O.Reg LR; O.Imm 0L; O.Imm 25L ]
    ||> testNoWbackNoQNoSimd Condition.AL

#if !EMULATION
  (* Refusing a word the manual calls UNPREDICTABLE is one of the checks an
     emulation build compiles out of the parser, so what follows is only true of
     a build that compiles them in. *)

  /// The width of a bitfield is how far its top bit sits above its bottom one,
  /// so a top bit below the bottom one names no field at all.
  [<TestMethod>]
  member _.``[Thumb] Miscellaneous data-processing Parse test (5)``() =
    testRefused "f3611081" (* bfi, msb = 1, lsb = 6 *)

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous data-processing Parse test (6)``() =
    testRefused "f36f1081" (* bfc, msb = 1, lsb = 6 *)
#endif

  [<TestMethod>]
  member _.``[Thumb] Status register access Parse test (1)``() =
    "f3ef8500"
    ++ MRS ** [ O.Reg R5; O.Reg APSR ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Status register access Parse test (2)``() =
    "f3ff8c00"
    ++ MRS ** [ O.Reg IP; O.Reg SPSR ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Status register access Parse test (3)``() =
    "f38b8400"
    ++ MSR ** [ O.SpecReg(CPSR, PSRs); O.Reg FP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Status register access Parse test (4)``() =
    "f38c8500"
    ++ MSR ** [ O.SpecReg(CPSR, PSRsc); O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Status register access Parse test (5)``() =
    "f3af8764"
    ++ CPSID ** [ O.Iflag IF; O.Imm 4L ]
    ||> testNoWbackNoQNoSimd Condition.UN (* W *)

  [<TestMethod>]
  member _.``[Thumb] Status register access Parse test (6)``() =
    "b665"
    ++ CPSIE ** [ O.Iflag AF ]
    ||> testNoWbackNoQNoSimd Condition.UN

  /// A4.5.1 Banked register access instructions
  [<TestMethod>]
  member _.``[Thumb] Banked register access Parse test (1)``() =
    "f3e68020"
    ++ MRS ** [ O.Reg R0; O.Reg LRusr ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Banked register access Parse test (2)``() =
    "f3918430"
    ++ MSR ** [ O.Reg SPSRabt; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (1)``() =
    "990f"
    ++ LDR ** [ O.Reg R1; O.MemOffsetImm(SP, Some Plus, Some 60L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (2)``() =
    "4c37"
    ++ LDR ** [ O.Reg R4; O.MemLabel 220L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (3)``() =
    "f8df0087"
    ++ LDR ** [ O.Reg R0; O.MemLabel 135L ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (4)``() =
    "f859c038"
    ++ LDR
    ** [ O.Reg IP; O.MemOffsetReg(SB, Some Plus, R8, ShiftOp.LSL, 3u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (5)``() =
    "f8512f33"
    ++ LDR ** [ O.Reg R2; O.MemPreIdxImm(R1, Some Plus, Some 51L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (6)``() =
    "f8dec080"
    ++ LDR ** [ O.Reg IP; O.MemOffsetImm(LR, Some Plus, Some 128L) ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (7)``() =
    "f839bc82"
    ++ LDRH ** [ O.Reg FP; O.MemOffsetImm(SB, Some Minus, Some 130L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (8)``() =
    "f93f624b"
    ++ LDRSH ** [ O.Reg R6; O.MemLabel -587L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (9)``() =
    "f9b3b00b"
    ++ LDRSH ** [ O.Reg FP; O.MemOffsetImm(R3, Some Plus, Some 11L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (10)``() =
    "79a6"
    ++ LDRB ** [ O.Reg R6; O.MemOffsetImm(R4, Some Plus, Some 6L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (11)``() =
    "f812a036"
    ++ LDRB
    ** [ O.Reg SL; O.MemOffsetReg(R2, Some Plus, R6, ShiftOp.LSL, 3u) ]
    ||> testNoQNoSimd Condition.AL false (* W *)

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (12)``() =
    "f814890c"
    ++ LDRB ** [ O.Reg R8; O.MemPostIdxImm(R4, Some Minus, Some 12L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (13)``() =
    "f89f30f0"
    ++ LDRB ** [ O.Reg R3; O.MemLabel 240L ]
    ||> testNoWbackNoQNoSimd Condition.AL (* W *)

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (14)``() =
    "f9981c32"
    ++ LDRSB ** [ O.Reg R1; O.MemOffsetImm(R8, Some Plus, Some 3122L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (15)``() =
    "f91e9020"
    ++ LDRSB
    ** [ O.Reg SB; O.MemOffsetReg(LR, Some Plus, R0, ShiftOp.LSL, 2u) ]
    ||> testNoQNoSimd Condition.AL false (* W *)

  [<TestMethod>]
  member _.``[Thumb] Load/store (Lord) Parse test (16)``() =
    "e95fc642"
    ++ LDRD ** [ O.Reg IP; O.Reg R6; O.MemLabel -264L ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store) Parse test (1)``() =
    "6637"
    ++ STR ** [ O.Reg R7; O.MemOffsetImm(R6, Some Plus, Some 96L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store) Parse test (2)``() =
    "8457"
    ++ STRH ** [ O.Reg R7; O.MemOffsetImm(R2, Some Plus, Some 34L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store) Parse test (3)``() =
    "549c"
    ++ STRB ** [ O.Reg R4; O.MemOffsetReg(R3, Some Plus, R2) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store) Parse test (4)``() =
    "f809e982"
    ++ STRB ** [ O.Reg LR; O.MemPostIdxImm(SB, Some Minus, Some 130L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store) Parse test (5)``() =
    "f886c80c"
    ++ STRB ** [ O.Reg IP; O.MemOffsetImm(R6, Some Plus, Some 2060L) ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store) Parse test (6)``() =
    "f80a002c"
    ++ STRB
    ** [ O.Reg R0; O.MemOffsetReg(SL, Some Plus, IP, ShiftOp.LSL, 2u) ]
    ||> testNoQNoSimd Condition.AL false (* W *)

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store) Parse test (7)``() =
    "e96a393c"
    ++ STRD ** [ O.Reg R3
                 O.Reg SB
                 O.MemPreIdxImm(SL, Some Minus, Some 240L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[Thumb] Load/store (Load unprivileged) Parse test (1)``() =
    "f8501e04"
    ++ LDRT ** [ O.Reg R1; O.MemOffsetImm(R0, None, Some 4L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Load unprivileged) Parse test (2)``() =
    "f834ce01"
    ++ LDRHT ** [ O.Reg IP; O.MemOffsetImm(R4, None, Some 1L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Load unprivileged) Parse test (3)``() =
    "f91c9e09"
    ++ LDRSBT ** [ O.Reg SB; O.MemOffsetImm(IP, None, Some 9L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store unprivileged) Parse test (1)``() =
    "f827be53"
    ++ STRHT ** [ O.Reg FP; O.MemOffsetImm(R7, None, Some 83L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Load-Exclusive) Parse test (1)``() =
    "e859bf0e"
    ++ LDREX ** [ O.Reg FP; O.MemOffsetImm(SB, None, Some 56L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Load-Exclusive) Parse test (2)``() =
    "e8d90f4f"
    ++ LDREXB ** [ O.Reg R0; O.MemOffsetImm(SB, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Load-Exclusive) Parse test (3)``() =
    "e8deac7f"
    ++ LDREXD ** [ O.Reg SL; O.Reg IP; O.MemOffsetImm(LR, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store-Exclusive) Parse test (1)``() =
    "e841ea0c"
    ++ STREX ** [ O.Reg SL; O.Reg LR; O.MemOffsetImm(R1, None, Some 48L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store-Exclusive) Parse test (2)``() =
    "e8c8af56"
    ++ STREXH ** [ O.Reg R6; O.Reg SL; O.MemOffsetImm(R8, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store (Store-Exclusive) Parse test (3)``() =
    "e8c0cb74"
    ++ STREXD ** [ O.Reg R4
                   O.Reg IP
                   O.Reg FP
                   O.MemOffsetImm(R0, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (1)``() =
    "cbc1"
    ++ LDM ** [ O.Reg R3; O.RegList [ R0; R6; R7 ] ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (2)``() =
    "e8985184"
    ++ LDM ** [ O.Reg R8; O.RegList [ R2; R7; R8; IP; LR ] ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (3)``() =
    "e8bd8611"
    ++ POP ** [ O.RegList [ R0; R4; SB; SL; PC ] ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (4)``() =
    "f85d3b04"
    ++ POP ** [ O.RegList [ R3 ] ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (5)``() =
    "b533"
    ++ PUSH ** [ O.RegList [ R0; R1; R4; R5; LR ] ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (6)``() =
    "e92d0184"
    ++ PUSH ** [ O.RegList [ R2; R7; R8 ] ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (7)``() =
    "f84d1d04"
    ++ PUSH ** [ O.RegList [ R1 ] ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (8)``() =
    "c5a3"
    ++ STM ** [ O.Reg R5; O.RegList [ R0; R1; R5; R7 ] ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[Thumb] Load/store multiple Parse test (9)``() =
    "e8825990"
    ++ STM ** [ O.Reg R2; O.RegList [ R4; R7; R8; FP; IP; LR ] ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (1)``() =
    "f3af80fb"
    ++ DBG ** [ O.Imm 11L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (2)``() =
    "f3bf8f57"
    ++ DMB ** [ O.Option BarrierOption.NSH ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (3)``() =
    "bf6c"
    ++ ITE ** [ O.Cond Condition.VS ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (4)``() =
    "f3af8000"
    ++ NOP ** []
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (5)``() =
    "f81cf01b"
    ++ PLD ** [ O.MemOffsetReg(IP, None, FP, ShiftOp.LSL, 1u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (6)``() =
    "f810fc20"
    ++ PLD ** [ O.MemOffsetImm(R0, Some Minus, Some 32L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (7)``() =
    "f81ff08e"
    ++ PLD ** [ O.MemLabel -142L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (8)``() =
    "f89ff00f"
    ++ PLD ** [ O.MemLabel 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (9)``() =
    "f837f01b"
    ++ PLDW ** [ O.MemOffsetReg(R7, None, FP, ShiftOp.LSL, 1u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (10)``() =
    "f832fc31"
    ++ PLDW ** [ O.MemOffsetImm(R2, Some Minus, Some 49L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (11)``() =
    "f8bcf0c3"
    ++ PLDW ** [ O.MemOffsetImm(IP, Some Plus, Some 195L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (12)``() =
    "f99af003"
    ++ PLI ** [ O.MemOffsetImm(SL, Some Plus, Some 3L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous Parse test (13)``() =
    "b658"
    ++ SETEND ** [ O.Endian Endian.Big ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Exception-gen and exception-handling Parse test (1)``() =
    "be30"
    ++ BKPT ** [ O.Imm 48L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Exception-gen and exception-handling Parse test (2)``() =
    "f7f88000"
    ++ SMC ** [ O.Imm 8L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Exception-gen and exception-handling Parse test (3)``() =
    "e9bac000"
    ++ RFEIA ** [ O.Reg SL ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[Thumb] Exception-gen and exception-handling Parse test (4)``() =
    "f3de8f08"
    ++ SUBS ** [ O.Reg PC; O.Reg LR; O.Imm 8L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Exception-gen and exception-handling Parse test (5)``() =
    "f7e1800c"
    ++ HVC ** [ O.Imm 4108L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[Thumb] Exception-gen and exception-handling Parse test (6)``() =
    "f3de8f00"
    ++ ERET ** []
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Exception-gen and exception-handling Parse test (7)``() =
    "f3de8f00"
    ++ ERET ** []
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Exception-gen and exception-handling Parse test (8)``() =
    "e82dc013"
    ++ SRSDB ** [ O.Reg SP; O.Imm 19L ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[Thumb] Media Parse test (1)``() =
    "de0f"
    ++ UDF ** [ O.Imm 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[Thumb] Miscellaneous control Parse test (1)``() =
    "f3bf8f2f"
    ++ CLREX ** []
    ||> testNoWbackNoQNoSimd Condition.AL

  /// The destination of these is the bit above the field holding it followed by
  /// that field, as it is for every other SIMD instruction: a D of one means
  /// sixteen registers further up rather than two.
  [<TestMethod>]
  member _.``[Thumb] Advanced SIMD multiply accumulate Parse test (1)``() =
    "fc61e834"
    ++ VFMAL ** [ O.SimdVectorReg D30
                  O.SimdVectorReg S2
                  O.SimdVectorReg S9 ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypF16))

  [<TestMethod>]
  member _.``[Thumb] Advanced SIMD multiply accumulate Parse test (2)``() =
    "fca15834"
    ++ VFMSL ** [ O.SimdVectorReg D5
                  O.SimdVectorReg S2
                  O.SimdVectorReg S9 ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypF16))

  /// <summary>
  /// The Thumb encoding of an Advanced SIMD instruction differs from the A32
  /// one only in the four bits above it, so the two tables below that point
  /// say the same thing twice -- and where the Thumb copy disagreed with the
  /// A32 one, it was the Thumb copy that was wrong. Each of the seven below
  /// was measured against the A32 reading of the same instruction.
  /// </summary>
  [<TestMethod>]
  member _.``[Thumb] VABS names a quadword destination in its Q form``() =
    "ffb10342"
    ++ VABS ** [ O.SimdVectorReg Q0; O.SimdVectorReg Q1 ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypS8))

  /// VSHL by an immediate shifts LEFT, and its field counts up from the
  /// element width rather than down from twice it.
  [<TestMethod>]
  member _.``[Thumb] VSHL counts its immediate up from the width``() =
    "ef890511"
    ++ VSHL ** [ O.SimdVectorReg D0; O.SimdVectorReg D1; O.Imm 1L ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypI8))

  /// The smallest size a shift by an immediate names is a byte; the Thumb
  /// table answered U16 to the field that means an unsigned byte.
  [<TestMethod>]
  member _.``[Thumb] VSHR reads a byte as a byte``() =
    "ff8f0011"
    ++ VSHR ** [ O.SimdVectorReg D0; O.SimdVectorReg D1; O.Imm 1L ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypU8))

  /// VQSHRUN reads signed elements and writes unsigned ones, so the U bit of
  /// its encoding selects the instruction rather than the sign of its type.
  [<TestMethod>]
  member _.``[Thumb] VQSHRUN keeps a signed data type``() =
    "ff8f0812"
    ++ VQSHRUN ** [ O.SimdVectorReg D0; O.SimdVectorReg Q1; O.Imm 1L ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypS16))

  /// VMOVL is the shift-by-immediate encoding whose amount is zero, which is
  /// the low three bits of imm6 and not a wider field.
  [<TestMethod>]
  member _.``[Thumb] VMOVL is told from VSHLL by imm6's low bits``() =
    "ef880a11"
    ++ VMOVL ** [ O.SimdVectorReg Q0; O.SimdVectorReg D1 ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypS8))

  [<TestMethod>]
  member _.``[Thumb] VMIN names quadwords in its Q form``() =
    "ef220f44"
    ++ VMIN ** [ O.SimdVectorReg Q0; O.SimdVectorReg Q1; O.SimdVectorReg Q2 ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypF32))

  [<TestMethod>]
  member _.``[Thumb] VRSQRTS names quadwords in its Q form``() =
    "ef220f54"
    ++ VRSQRTS ** [ O.SimdVectorReg Q0
                    O.SimdVectorReg Q1
                    O.SimdVectorReg Q2 ]
    ||> testNoWbackNoQ Condition.AL (Some(OneDT SIMDTypF32))

  /// The by-scalar class keeps Q at bit 28 of a T32 word, where an A32 word
  /// keeps it at bit 24, so a D-register form names odd registers freely.
  [<TestMethod>]
  member _.``[T32] VMLA by an element names an odd D``() =
    testDisasm "efab51c0" "vmla.f32 d5, d27, d0[0]"

  [<TestMethod>]
  member _.``[T32] VQRDMULH by an element names an odd D``() =
    testDisasm "efee7dc5" "vqrdmulh.s32 d23, d30, d5[0]"

  /// VMULL's destination is the quadword that must be even, not a source.
  [<TestMethod>]
  member _.``[T32] VMULL with an odd first source``() =
    testDisasm "ff8bcc0e" "vmull.u8 q6, d11, d14"

  /// VLD2 of one register a structure steps by one, so d30 and d31 are the
  /// last pair it can name.
  [<TestMethod>]
  member _.``[T32] VLD2 of the last two D registers``() =
    testDisasm "f962e818" "vld2.8 {d30, d31}, [r2:64], r8"

  /// VMOV.F32 builds a single-precision number from its eight bits the way
  /// AdvSIMDExpandImm does (J1-7926).
  [<TestMethod>]
  member _.``[T32] VMOV.F32 (immediate) expands its constant``() =
    testDisasm "ef810f14" "vmov.f32 d0, #0x40a00000"

  /// The sign is the i bit, which T32 keeps at bit 28.
  [<TestMethod>]
  member _.``[T32] VMOV.F32 (immediate) takes its sign from i``() =
    testDisasm "ff810f14" "vmov.f32 d0, #0xc0a00000"

  [<TestMethod>]
  member _.``[T32] VMOV.F32 (immediate) to a quadword keeps the constant``() =
    testDisasm "ef810f54" "vmov.f32 q0, #0x40a00000"

  /// cmode 1100 shifts the byte in over eight ones, and 1101 over sixteen.
  [<TestMethod>]
  member _.``[T32] VMOV.I32 (immediate) shifts in eight ones``() =
    testDisasm "ef850c1a" "vmov.i32 d0, #0x5aff"

  [<TestMethod>]
  member _.``[T32] VMVN.I32 (immediate) shifts in sixteen ones``() =
    testDisasm "ef850d3a" "vmvn.i32 d0, #0x5affff"

  /// The floating-point instructions are the coprocessor space with 10 in bits
  /// 11:10, and T32 reads no other coprocessor's data-processing words.
  [<TestMethod>]
  member _.``[T32] Coprocessor 13 is not floating-point``() =
    testRefused "ee000d00"

  [<TestMethod>]
  member _.``[T32] Coprocessor 14 is not floating-point``() =
    testRefused "ee000e00"

  [<TestMethod>]
  member _.``[T32] Coprocessor 15 is not floating-point``() =
    testRefused "ee000f00"

  /// A register list that runs past the last register names registers that do
  /// not exist, so every build refuses it.
  [<TestMethod>]
  member _.``[T32] VLDM past D31 is refused in every build``() =
    testRefused "ecd0fb04"

  [<TestMethod>]
  member _.``[T32] VLDM past S31 is refused in every build``() =
    testRefused "ecd0fa02"

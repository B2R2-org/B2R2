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
    let parser = Parser(isa, true, reader) :> IInstructionParsable
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
    let parser = Parser(isa, true, BinReader.Init Endian.Big)
    let ins = (parser :> IInstructionParsable).Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// Checks that a word the manual calls UNPREDICTABLE is refused rather than
  /// decoded into whatever its fields happen to say.
  let testRefused (byteString: string) =
    let bytes = ByteArray.ofHexString byteString
    let isa = ISA(Architecture.ARMv7, Endian.Big)
    let reader = BinReader.Init Endian.Big
    let parser = Parser(isa, true, reader) :> IInstructionParsable
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parser.Parse(bs = bytes, addr = 0UL) |> ignore)
    |> ignore

  /// The disassembly of a word under the ISA a name gives, or nothing where
  /// that ISA leaves the word UNDEFINED.
  let under (isaName: string) (byteString: string) =
    let parser = Parser(ISA isaName, true, BinReader.Init Endian.Big)
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

  /// MRRC keeps its second register at 19:16, and 11:8 is the coprocessor.
  [<TestMethod>]
  member _.``[T32] MRRC from coprocessor 15``() =
    testDisasm "ec510f34" "mrrc p15, #0x3, r0, r1, c4"

  /// PLDW's eight-bit offset is an immediate; its low four bits name no
  /// register.
  [<TestMethod>]
  member _.``[T32] PLDW with a negative offset ending in F``() =
    testDisasm "f83efcaf" "pldw [lr, #-0xaf]"

  /// A T32 word is gated the way its A32 counterpart is: its class says which
  /// unit it belongs to, and an ARMv7 version reads no Armv8 instruction.
  [<TestMethod>]
  member _.``[T32] SDIV is the divide extension's``() =
    readsOnlyUnder "fb91f0f2" [ "thumb-v7+idiv"; "thumb-v7ve" ] [ "thumb-v7" ]

  [<TestMethod>]
  member _.``[T32] VADD.I32 is Advanced SIMD's``() =
    readsOnlyUnder "ef210802" [ "thumb-v7+simd" ] [ "thumb-v7+fp" ]

  [<TestMethod>]
  member _.``[T32] VADD.F32 is the floating-point unit's``() =
    readsOnlyUnder "ee300a81" [ "thumb-v7+fp" ] [ "thumb-v7" ]

  [<TestMethod>]
  member _.``[T32] VLD1 is Advanced SIMD's``() =
    readsOnlyUnder "f920070f" [ "thumb-v7+simd" ] [ "thumb-v7+fp" ]

  [<TestMethod>]
  member _.``[T32] PLDW is the multiprocessing extension's``() =
    readsOnlyUnder "f8b0f000" [ "thumb-v7+mp" ] [ "thumb-v7" ]

  [<TestMethod>]
  member _.``[T32] CRC32B is Armv8's``() =
    readsOnlyUnder "fac1f082" [ "thumb" ] [ "thumb-v7ve+simd+vfpv4" ]

  /// An Armv8 hint is a NOP to an ARMv7 processor, as its unallocated hints
  /// are.
  [<TestMethod>]
  member _.``[T32] SEVL reads as NOP under an ARMv7 version``() =
    Assert.AreEqual<string option>(Some "nop", under "thumb-v7" "bf50bf00")

  /// TSB CSYNC names its option, which is part of what it is written as.
  [<TestMethod>]
  member _.``[T32] TSB CSYNC names its option``() =
    testDisasm "f3af8012" "tsb csync"

  /// RRX rotates by exactly one place and is written with no amount.
  [<TestMethod>]
  member _.``[T32] An RRX operand takes no amount``() =
    testDisasm "ea010034" "and r0, r1, r4, rrx"

  /// A MOV whose operand is shifted reads as the shift it names, which the
  /// manual gives as its preferred disassembly (F5-4557).
  [<TestMethod>]
  member _.``[T32] MOV with RRX reads as RRX``() =
    testDisasm "ea4f0031" "rrx r0, r1"

  [<TestMethod>]
  member _.``[T32] MOV with LSL reads as LSL``() =
    testDisasm "ea4f00c1" "lsl r0, r1, #0x3"

  [<TestMethod>]
  member _.``[T32] MOV with LSR reads as LSR``() =
    testDisasm "ea4f00d1" "lsr r0, r1, #0x3"

  [<TestMethod>]
  member _.``[T32] MOV with LSR #32 reads as LSR #32``() =
    testDisasm "ea4f0011" "lsr r0, r1, #0x20"

  [<TestMethod>]
  member _.``[T32] MOV with ASR reads as ASR``() =
    testDisasm "ea4f00e1" "asr r0, r1, #0x3"

  [<TestMethod>]
  member _.``[T32] MOV with ROR reads as ROR``() =
    testDisasm "ea4f00f1" "ror r0, r1, #0x3"

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

  /// SHA256H2 is written as one word with its data type.
  [<TestMethod>]
  member _.``[T32] SHA256H2 is written as one word``() =
    testDisasm "ff100c40" "sha256h2.32 q0, q0, q0"

  /// The wide moves of a register keep their destination in bits 11:8 of the
  /// second halfword, as every wide data-processing instruction does; bits
  /// 15:12 hold the top of the shift amount.
  [<TestMethod>]
  member _.``[T32] MOV (register, wide) names its destination``() =
    testDisasm "ea4f0801" "mov r8, r1"

  [<TestMethod>]
  member _.``[T32] MOVS.W (register) names its destination``() =
    testDisasm "ea5f0801" "movs.w r8, r1"

  [<TestMethod>]
  member _.``[T32] RRX names its destination``() =
    testDisasm "ea4f0831" "rrx r8, r1"

  [<TestMethod>]
  member _.``[T32] RRXS names its destination``() =
    testDisasm "ea5f0831" "rrxs r8, r1"

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

  /// ESB and CSDB have no narrow encoding, so they take no .w (DDI0487F.c
  /// F5.1.52 and F5.1.41); the hints that do have one keep it.
  [<TestMethod>]
  member _.``[T32] ESB and CSDB read without a width``() =
    testDisasm "f3af8010" "esb"
    testDisasm "f3af8014" "csdb"
    testDisasm "f3af8004" "sev.w"

  /// MSR names SPSR with its R bit, bit 20 of the first halfword.
  [<TestMethod>]
  member _.``[T32] MSR can name SPSR``() =
    testDisasm "f3918f00" "msr spsr_fsxc, r1"

  /// The narrow MOVS with a register-shifted register reads as the shift it
  /// names, its preferred disassembly (DDI0487F.c F5.1.113).
  [<TestMethod>]
  member _.``[T32] Narrow MOVS by register reads as the shift``() =
    testDisasm "4088" "lsls r0, r1"
    testDisasm "40c8" "lsrs r0, r1"
    testDisasm "4108" "asrs r0, r1"
    testDisasm "41c8" "rors r0, r1"

  /// T1 VMRS and VMSR have A1's reg field (DDI0406C B9.3.21 and B9.3.22).
  [<TestMethod>]
  member _.``[T32] VMRS can name FPEXC``() =
    testDisasm "eef80a10" "vmrs r0, fpexc"

  [<TestMethod>]
  member _.``[T32] VMSR can name FPEXC``() =
    testDisasm "eee80a10" "vmsr fpexc, r0"

  /// Rt = 15 moves FPSCR's flags to APSR, in T32 as in A32: what the manual
  /// refuses is Rt = 15 with any other register (DDI0406C B9.3.21).
  [<TestMethod>]
  member _.``[T32] VMRS can move FPSCR's flags to APSR``() =
    testDisasm "eef1fa10" "vmrs apsr, fpscr"

  /// ERET's T32 encoding is SUBS PC, LR, #0's, which every ARMv7 processor
  /// has; only the Virtualization Extensions call it ERET (DDI0406C B9.3.19).
  [<TestMethod>]
  member _.``[T32] ERET is SUBS PC, LR, #0 without Virt``() =
    let subs = Some "subs pc, lr, #0x0"
    Assert.AreEqual<string option>(subs, under "armv7-v7" "f3de8f00")
    Assert.AreEqual<string option>(Some "eret", under "armv7-v7ve" "f3de8f00")

  /// VCMLA (vector) takes its rotation from op1 in T32 as in A32.
  [<TestMethod>]
  member _.``[T32] VCMLA (vector) decodes at every rotation``() =
    testDisasm "fc310802" "vcmla.f32 d0, d1, d2, #0x0"
    testDisasm "fcb10802" "vcmla.f32 d0, d1, d2, #0x5a"
    testDisasm "fd310802" "vcmla.f32 d0, d1, d2, #0xb4"
    testDisasm "fdb20844" "vcmla.f32 q0, q1, q2, #0x10e"
    testDisasm "fca10802" "vcmla.f16 d0, d1, d2, #0x5a"

  /// The directed conversions name the integer they write first in T32 too.
  [<TestMethod>]
  member _.``[T32] VCVTA names the integer it writes first``() =
    testDisasm "febc0ac0" "vcvta.s32.f32 s0, s0"
    testDisasm "febf0b41" "vcvtm.u32.f64 s0, d1"

  [<TestMethod>]
  member _.``[T32] VCVTB.BF16 converts from a single``() =
    testDisasm "eeb30941" "vcvtb.bf16.f32 s0, s2"

  [<TestMethod>]
  member _.``[T32] VFMAL by an element names a single``() =
    testDisasm "fe000819" "vfmal.f16 d0, s0, s2[1]"

  /// VMINNM names single-precision registers for halves and singles in T32 as
  /// in A32, and its Advanced SIMD form on halves says so.
  [<TestMethod>]
  member _.``[T32] VMINNM names the registers and type it reads``() =
    testDisasm "fe800a4f" "vminnm.f32 s0, s0, s30"
    testDisasm "fe80094f" "vminnm.f16 s0, s0, s30"
    testDisasm "ff300f10" "vminnm.f16 d0, d0, d0"

  /// A fixed-point VCVT that counts more fraction bits than its integer holds
  /// is UNPREDICTABLE (DDI0406C A8.8.309), and is refused.
  [<TestMethod>]
  member _.``[T32] VCVT to fixed point refuses negative fraction bits``() =
    testDisasm "eeba0a40" "vcvt.f32.s16 s0, s0, #0x10"
#if !EMULATION
    testRefused "eeba0a4f"
#endif

  /// VDUP of one element fills a quadword where Q says so.
  [<TestMethod>]
  member _.``[T32] VDUP of an element names a quadword``() =
    testDisasm "ffbe0c41" "vdup.16 q0, d1[3]"

  /// VSHLL by the width of an element widens into a quadword, which is the
  /// register that must be even; the doubleword it reads need not be.
  [<TestMethod>]
  member _.``[T32] VSHLL by the element width reads an odd doubleword``() =
    testDisasm "ffb60301" "vshll.i16 q0, d1, #0x10"
#if !EMULATION
    testRefused "ffb61300"
#endif

  /// VCEQ #0 compares integers of a size, which it names I8, I16 and I32.
  [<TestMethod>]
  member _.``[T32] VCEQ #0 names integers``() =
    testDisasm "ffb5c109" "vceq.i16 d12, d9, #0x0"

  /// <summary>
  /// The multiplies by one element read Q from bit 28 in T32, so a
  /// doubleword form may name odd registers and a quadword form refuses them;
  /// VEXT of quadwords refuses odd ones; and VMOV.F16 refuses the PC, as their
  /// A32 forms do.
  /// </summary>
  [<TestMethod>]
  member _.``[T32] VMUL by an element reads Q from bit 28``() =
    testDisasm "ef99694d" "vmul.f16 d6, d9, d5[1]"
    testDisasm "ff98694d" "vmul.f16 q3, q4, d5[1]"
#if !EMULATION
    testRefused "ff99694d"
    testRefused "ff98794d"
#endif

  [<TestMethod>]
  member _.``[T32] VEXT of quadwords refuses an odd register``() =
    testDisasm "efb2a7ce" "vext.8 q5, q9, q7, #0x7"
#if !EMULATION
    testRefused "efb2a7cf"
#endif

  /// ENTERX and LEAVEX, ThumbEE's two instructions in Thumb state, are the
  /// miscellaneous system encodings with opc 0001 and 0000 (DDI0406C A9.3.1).
  [<TestMethod>]
  member _.``[T32] ENTERX and LEAVEX read``() =
    testDisasm "f3bf8f1f" "enterx"
    testDisasm "f3bf8f0f" "leavex"

  [<TestMethod>]
  member _.``[T32] SSBB and PSSBB read apart from DSB``() =
    testDisasm "f3bf8f40" "ssbb"
    testDisasm "f3bf8f44" "pssbb"
    testDisasm "f3bf8f4f" "dsb sy"

#if !EMULATION
  [<TestMethod>]
  member _.``[T32] VMOV.F16 refuses the PC``() =
    testRefused "ee04f9b2"
#endif

  /// The ordinary coprocessors read in T32 as in A32, bit 28 naming the forms
  /// called 2, and refuse what A32 refuses.
  [<TestMethod>]
  member _.``[T32] The ordinary coprocessors take every instruction``() =
    testDisasm "ee000010" "mcr p0, #0x0, r0, c0, c0, #0x0"
    testDisasm "ee0b41e5" "cdp p1, #0x0, c4, c11, c5, #0x7"
    testDisasm "ee2b41e5" "cdp p1, #0x2, c4, c11, c5, #0x7"
    testDisasm "ed911100" "ldc p1, c1, [r1]"
    testDisasm "ec410203" "mcrr p2, #0x0, r0, r1, c3"
    testDisasm "fe000300" "cdp2 p3, #0x0, c0, c0, c0, #0x0"
    testDisasm "fe2b41e5" "cdp2 p1, #0x2, c4, c11, c5, #0x7"
    testDisasm "fc510203" "mrrc2 p2, #0x0, r0, r1, c3"
    testDisasm "fdd11100" "ldc2l p1, c1, [r1]"
    testDisasm "fc6485df" "stc2l p5, c8, [r4], #-0x37c"
    testRefused "ee000e00"
#if !EMULATION
    testRefused "ee00f010"
    testRefused "ec4f0000"
    testRefused "ec511100"
    testRefused "ed2f1100"
#endif
    readsOnlyUnder "ee000010" [ "armv7-v7" ] [ "aarch32" ]

  /// VDUP from a core register to a Q register refuses an odd Vd in T32 as in
  /// A32 (DDI0406C A8.8.315).
  [<TestMethod>]
  member _.``[T32] VDUP to a Q register refuses an odd Vd``() =
    testDisasm "eea02b10" "vdup.32 q0, r2"
#if !EMULATION
    testRefused "eea12b14"
    testRefused "eee12b10"
    testRefused "eea12b30"
#endif

  /// L, bit 20, tells STRD from LDRD whatever the base: with L clear and Rn 15
  /// the word is STRD with the PC as its base, which is UNPREDICTABLE, and only
  /// with L set is it the literal LDRD (DDI0406C A6.3.6 and A8.8.211).
  [<TestMethod>]
  member _.``[T32] STRD with the PC as its base is refused``() =
    testDisasm "e95f0134" "ldrd r0, r1, [0xffffff34]"
    testDisasm "e94e0134" "strd r0, r1, [lr, #-0xd0]"
#if !EMULATION
    testRefused "e94f0134"
    testRefused "e9cf0134"
#endif

  /// An MRC whose Rt field is 15 names APSR_nzcv in T32 as in A32 (DDI0406C
  /// A8.8.108).
  [<TestMethod>]
  member _.``[T32] MRC to Rt 15 names APSR_nzcv``() =
    testDisasm "ee11fe14" "mrc p14, #0x0, apsr_nzcv, c1, c4, #0x0"
    testDisasm "ee10ff10" "mrc p15, #0x0, apsr_nzcv, c0, c0, #0x0"
#if !EMULATION
    testRefused "ee00ff10"
#endif

  /// <summary>
  /// The ThumbEE instructions of DDI0406C (A8.8.31 CHKA, A8.8.52 HB, HBL,
  /// HBLP, HBP; encodings in A9.5: CHKA is 1100 1010 N Rm Rn, HB and HBL
  /// 1100 001L, HBLP 1100 01, HBP 1100 0000) exist only in ThumbEE state,
  /// which no processor modelled here has, as ENTERX and LEAVEX say by
  /// being UNDEFINED. In Thumb state the same halfwords are the T1 STM and
  /// LDM, and that is what they read as.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.31 CHKA, A8.8.52 HB, HBL, HBLP, HBP read as Thumb``() =
    testDisasm "ca12" "ldm r2!, {r1, r4}"
    testDisasm "c212" "stm r2!, {r1, r4}"
    testDisasm "c312" "stm r3!, {r1, r4}"
    testDisasm "c512" "stm r5!, {r1, r4}"
    testDisasm "c012" "stm r0!, {r1, r4}"

  /// ENTERX and LEAVEX (DDI0406C A8.8.46, A9.3.1) and TSB CSYNC (DDI0487F.c
  /// F5.1.261, Armv8.4). binutils 2.42 reads none of the three in Thumb state
  /// at its default level, so these are the manuals' encodings written out:
  /// 1111 0011 1011 1111 1000 1111 000J 1111 with J set for ENTERX, and
  /// 1111 0011 1010 1111 1000 0000 0001 0010 for TSB.
  [<TestMethod>]
  member _.``A8.8.46 ENTERX, LEAVEX and TSB``() =
    testDisasm "f3bf8f1f" "enterx"
    testDisasm "f3bf8f0f" "leavex"
    testDisasm "f3af8012" "tsb csync"

  (* One test for each T32 instruction DDI0406C and DDI0487F.c's AArch32
     chapters describes, in the order of its sections. Each reads words of the
     instruction and checks the text, and each word is one binutils' objdump
     reads as the same instruction with the same operands, so what is asserted
     is a reading two decoders agree on. *)
  /// A8.8.1 ADC (immediate)
  [<TestMethod>]
  member _.``A8.8.1 ADC``() =
    testDisasm "eb400002" "adc r0, r0, r2"
    testDisasm "eb510002" "adcs.w r0, r1, r2"
    testDisasm "eb410042" "adc r0, r1, r2, lsl #0x1"
    testDisasm "eb4100d2" "adc r0, r1, r2, lsr #0x3"

  /// A8.8.100 MCRR, MCRR2
  [<TestMethod>]
  member _.``A8.8.100 MCRR``() =
    testDisasm "ec410e34" "mcrr p14, #0x3, r0, r1, c4"
    testDisasm "ec419e34" "mcrr p14, #0x3, sb, r1, c4"
    testDisasm "ec41ae34" "mcrr p14, #0x3, sl, r1, c4"
    testDisasm "ec41be34" "mcrr p14, #0x3, fp, r1, c4"

  /// A8.8.101 MLA
  [<TestMethod>]
  member _.``A8.8.101 MLA``() =
    testDisasm "fb013002" "mla r0, r1, r2, r3"
    testDisasm "fb010900" "mla sb, r1, r0, r0"
    testDisasm "fb010a00" "mla sl, r1, r0, r0"
    testDisasm "fb010b00" "mla fp, r1, r0, r0"

  /// A8.8.102 MLS
  [<TestMethod>]
  member _.``A8.8.102 MLS``() =
    testDisasm "fb013012" "mls r0, r1, r2, r3"
    testDisasm "fb010910" "mls sb, r1, r0, r0"
    testDisasm "fb010a10" "mls sl, r1, r0, r0"
    testDisasm "fb010b10" "mls fp, r1, r0, r0"

  /// A8.8.103 MOV (immediate)
  [<TestMethod>]
  member _.``A8.8.103 MOV``() =
    testDisasm "f04f0003" "mov r0, #0x3"
    testDisasm "f05f407f" "movs r0, #0xff000000"
    testDisasm "4610bf00" "mov r0, r2"
    testDisasm "0010bf00" "movs r0, r2"

  /// A8.8.107 MOVT
  [<TestMethod>]
  member _.``A8.8.107 MOVT``() =
    testDisasm "f2c00007" "movt r0, #0x7"
    testDisasm "f2c10934" "movt sb, #0x1034"
    testDisasm "f2c10a34" "movt sl, #0x1034"
    testDisasm "f2c10b34" "movt fp, #0x1034"

  /// A8.8.108 MRC, MRC2
  [<TestMethod>]
  member _.``A8.8.108 MRC``() =
    testDisasm "ee110e34" "mrc p14, #0x0, r0, c1, c4, #0x1"
    testDisasm "ee119e34" "mrc p14, #0x0, sb, c1, c4, #0x1"
    testDisasm "ee11ae34" "mrc p14, #0x0, sl, c1, c4, #0x1"
    testDisasm "ee11be34" "mrc p14, #0x0, fp, c1, c4, #0x1"

  /// A8.8.109 MRRC, MRRC2
  [<TestMethod>]
  member _.``A8.8.109 MRRC``() =
    testDisasm "ec510e34" "mrrc p14, #0x3, r0, r1, c4"
    testDisasm "ec519e34" "mrrc p14, #0x3, sb, r1, c4"
    testDisasm "ec51ae34" "mrrc p14, #0x3, sl, r1, c4"
    testDisasm "ec51be34" "mrrc p14, #0x3, fp, r1, c4"

  /// A8.8.110 MRS
  [<TestMethod>]
  member _.``A8.8.110 MRS``() =
    testDisasm "f3e18034" "mrs r0, sp_irq"
    testDisasm "f3e1806f" "mrs r0, r9_usr"
    testDisasm "f3e18934" "mrs sb, sp_irq"
    testDisasm "f3e1896f" "mrs sb, r9_usr"

  /// A8.8.112 MSR (immediate)
  [<TestMethod>]
  member _.``A8.8.112 MSR``() =
    testDisasm "f3818034" "msr lr_irq, r1"
    testDisasm "f381806f" "msr r8_usr, r1"
    testDisasm "f3818134" "msr sp_irq, r1"
    testDisasm "f3818100" "msr cpsr_c, r1"

  /// A8.8.115 MUL
  [<TestMethod>]
  member _.``A8.8.115 MUL``() =
    testDisasm "fb01f002" "mul r0, r1, r2"
    testDisasm "4340bf00" "muls r0, r0, r0"
    testDisasm "fb01f900" "mul sb, r1, r0"
    testDisasm "fb01fa00" "mul sl, r1, r0"

  /// A8.8.116 MVN (immediate)
  [<TestMethod>]
  member _.``A8.8.116 MVN``() =
    testDisasm "f06f407f" "mvn r0, #0xff000000"
    testDisasm "f07f407f" "mvns r0, #0xff000000"
    testDisasm "ea6f0002" "mvn r0, r2"
    testDisasm "43d0bf00" "mvns r0, r2"

  /// A8.8.119 NEG
  [<TestMethod>]
  member _.``A8.8.119 NEG``() =
    testDisasm "f1c20000" "rsb r0, r2, #0x0"
    testDisasm "f1d10000" "rsbs r0, r1, #0x0"

  /// A8.8.12 ADR
  [<TestMethod>]
  member _.``A8.8.12 ADR``() =
    testDisasm "f20f0002" "adr.w r0, [0x6]"
    testDisasm "a000bf00" "adr r0, [0x4]"
    testDisasm "f20f0934" "adr.w sb, [0x38]"
    testDisasm "f2af0934" "adr sb, [0xffffffd0]"

  /// A8.8.120 NOP
  [<TestMethod>]
  member _.``A8.8.120 NOP``() =
    testDisasm "bf00bf00" "nop"
    testDisasm "f3af8000" "nop.w"

  /// A8.8.121 ORN (immediate)
  [<TestMethod>]
  member _.``A8.8.121 ORN``() =
    testDisasm "f0610001" "orn r0, r1, #0x1"
    testDisasm "f071407f" "orns r0, r1, #0xff000000"
    testDisasm "ea610002" "orn r0, r1, r2"
    testDisasm "ea710002" "orns r0, r1, r2"

  /// A8.8.123 ORR (immediate)
  [<TestMethod>]
  member _.``A8.8.123 ORR``() =
    testDisasm "f041407f" "orr r0, r1, #0xff000000"
    testDisasm "f051407f" "orrs r0, r1, #0xff000000"
    testDisasm "ea400002" "orr r0, r0, r2"
    testDisasm "ea510002" "orrs.w r0, r1, r2"

  /// A8.8.126 PKH
  [<TestMethod>]
  member _.``A8.8.126 PKH``() =
    testDisasm "eac11002" "pkhbt r0, r1, r2, lsl #0x4"
    testDisasm "eac11022" "pkhtb r0, r1, r2, asr #0x4"
    testDisasm "eac10000" "pkhbt r0, r1, r0"
    testDisasm "eac10900" "pkhbt sb, r1, r0"

  /// A8.8.127 PLD, PLDW (immediate)
  [<TestMethod>]
  member _.``A8.8.127 PLD``() =
    testDisasm "f891f007" "pld [r1, #0x7]"
    testDisasm "f89ff002" "pld [0x6]"
    testDisasm "f811f002" "pld [r1, r2]"
    testDisasm "f891f000" "pld [r1]"

  /// A8.8.127 PLD, PLDW (immediate)
  [<TestMethod>]
  member _.``A8.8.127 PLDW``() =
    testDisasm "f8b1f007" "pldw [r1, #0x7]"
    testDisasm "f831f002" "pldw [r1, r2]"
    testDisasm "f8b1f000" "pldw [r1]"
    testDisasm "f831f034" "pldw [r1, r4, lsl #0x3]"

  /// A8.8.13 AND (immediate)
  [<TestMethod>]
  member _.``A8.8.13 AND``() =
    testDisasm "f011407f" "ands r0, r1, #0xff000000"
    testDisasm "f001417f" "and r1, r1, #0xff000000"
    testDisasm "ea000002" "and r0, r0, r2"
    testDisasm "ea110002" "ands.w r0, r1, r2"

  /// A8.8.130 PLI (immediate, literal)
  [<TestMethod>]
  member _.``A8.8.130 PLI``() =
    testDisasm "f991f007" "pli [r1, #0x7]"
    testDisasm "f99ff002" "pli [pc, #0x2]"
    testDisasm "f99ff000" "pli [pc]"
    testDisasm "f911f002" "pli [r1, r2]"

  /// A8.8.132 POP (Thumb)
  [<TestMethod>]
  member _.``A8.8.132 POP``() =
    testDisasm "bc0cbf00" "pop {r2, r3}"
    testDisasm "bc01bf00" "pop {r0}"
    testDisasm "bc07bf00" "pop {r0, r1, r2}"
    testDisasm "bc0fbf00" "pop {r0, r1, r2, r3}"

  /// A8.8.134 PUSH
  [<TestMethod>]
  member _.``A8.8.134 PUSH``() =
    testDisasm "b40cbf00" "push {r2, r3}"
    testDisasm "b401bf00" "push {r0}"
    testDisasm "b407bf00" "push {r0, r1, r2}"
    testDisasm "b40fbf00" "push {r0, r1, r2, r3}"

  /// A8.8.135 QADD
  [<TestMethod>]
  member _.``A8.8.135 QADD``() =
    testDisasm "fa82f081" "qadd r0, r1, r2"

  /// A8.8.136 QADD16
  [<TestMethod>]
  member _.``A8.8.136 QADD16``() =
    testDisasm "fa91f012" "qadd16 r0, r1, r2"
    testDisasm "fa91f910" "qadd16 sb, r1, r0"
    testDisasm "fa91fa10" "qadd16 sl, r1, r0"
    testDisasm "fa91fb10" "qadd16 fp, r1, r0"

  /// A8.8.137 QADD8
  [<TestMethod>]
  member _.``A8.8.137 QADD8``() =
    testDisasm "fa81f012" "qadd8 r0, r1, r2"
    testDisasm "fa81f910" "qadd8 sb, r1, r0"
    testDisasm "fa81fa10" "qadd8 sl, r1, r0"
    testDisasm "fa81fb10" "qadd8 fp, r1, r0"

  /// A8.8.138 QASX
  [<TestMethod>]
  member _.``A8.8.138 QASX``() =
    testDisasm "faa1f012" "qasx r0, r1, r2"
    testDisasm "faa1f910" "qasx sb, r1, r0"
    testDisasm "faa1fa10" "qasx sl, r1, r0"
    testDisasm "faa1fb10" "qasx fp, r1, r0"

  /// A8.8.139 QDADD
  [<TestMethod>]
  member _.``A8.8.139 QDADD``() =
    testDisasm "fa82f091" "qdadd r0, r1, r2"

  /// A8.8.140 QDSUB
  [<TestMethod>]
  member _.``A8.8.140 QDSUB``() =
    testDisasm "fa82f0b1" "qdsub r0, r1, r2"

  /// A8.8.141 QSAX
  [<TestMethod>]
  member _.``A8.8.141 QSAX``() =
    testDisasm "fae1f012" "qsax r0, r1, r2"
    testDisasm "fae1f910" "qsax sb, r1, r0"
    testDisasm "fae1fa10" "qsax sl, r1, r0"
    testDisasm "fae1fb10" "qsax fp, r1, r0"

  /// A8.8.142 QSUB
  [<TestMethod>]
  member _.``A8.8.142 QSUB``() =
    testDisasm "fa82f0a1" "qsub r0, r1, r2"

  /// A8.8.143 QSUB16
  [<TestMethod>]
  member _.``A8.8.143 QSUB16``() =
    testDisasm "fad1f012" "qsub16 r0, r1, r2"
    testDisasm "fad1f910" "qsub16 sb, r1, r0"
    testDisasm "fad1fa10" "qsub16 sl, r1, r0"
    testDisasm "fad1fb10" "qsub16 fp, r1, r0"

  /// A8.8.144 QSUB8
  [<TestMethod>]
  member _.``A8.8.144 QSUB8``() =
    testDisasm "fac1f012" "qsub8 r0, r1, r2"
    testDisasm "fac1f910" "qsub8 sb, r1, r0"
    testDisasm "fac1fa10" "qsub8 sl, r1, r0"
    testDisasm "fac1fb10" "qsub8 fp, r1, r0"

  /// A8.8.145 RBIT
  [<TestMethod>]
  member _.``A8.8.145 RBIT``() =
    testDisasm "fa91f0a1" "rbit r0, r1"

  /// A8.8.146 REV
  [<TestMethod>]
  member _.``A8.8.146 REV``() =
    testDisasm "ba08bf00" "rev r0, r1"
    testDisasm "fa92f082" "rev.w r0, r2"

  /// A8.8.147 REV16
  [<TestMethod>]
  member _.``A8.8.147 REV16``() =
    testDisasm "ba48bf00" "rev16 r0, r1"
    testDisasm "fa92f092" "rev16.w r0, r2"

  /// A8.8.148 REVSH
  [<TestMethod>]
  member _.``A8.8.148 REVSH``() =
    testDisasm "bac8bf00" "revsh r0, r1"
    testDisasm "fa92f0b2" "revsh.w r0, r2"

  /// A8.8.149 RFE
  [<TestMethod>]
  member _.``A8.8.149 RFE``() =
    testDisasm "e991c000" "rfeia r1"
    testDisasm "e831c000" "rfedb r1!"

  /// A8.8.150 ROR (immediate)
  [<TestMethod>]
  member _.``A8.8.150 ROR``() =
    testDisasm "fa60f002" "ror r0, r0, r2"
    testDisasm "fa71f002" "rors.w r0, r1, r2"
    testDisasm "41d1bf00" "rors r1, r2"
    testDisasm "fa61f900" "ror sb, r1, r0"

  /// A8.8.152 RRX
  [<TestMethod>]
  member _.``A8.8.152 RRX``() =
    testDisasm "ea5f0032" "rrxs r0, r2"
    testDisasm "ea4f0032" "rrx r0, r2"
    testDisasm "ea4f0034" "rrx r0, r4"
    testDisasm "ea4f0031" "rrx r0, r1"

  /// A8.8.153 RSB (immediate)
  [<TestMethod>]
  member _.``A8.8.153 RSB``() =
    testDisasm "f1c1407f" "rsb r0, r1, #0xff000000"
    testDisasm "f1d1407f" "rsbs r0, r1, #0xff000000"
    testDisasm "ebc10002" "rsb r0, r1, r2"
    testDisasm "ebd10002" "rsbs r0, r1, r2"

  /// A8.8.159 SADD16
  [<TestMethod>]
  member _.``A8.8.159 SADD16``() =
    testDisasm "fa91f002" "sadd16 r0, r1, r2"
    testDisasm "fa91f900" "sadd16 sb, r1, r0"
    testDisasm "fa91fa00" "sadd16 sl, r1, r0"
    testDisasm "fa91fb00" "sadd16 fp, r1, r0"

  /// A8.8.16 ASR (immediate)
  [<TestMethod>]
  member _.``A8.8.16 ASR``() =
    testDisasm "1410bf00" "asrs r0, r2, #0x10"
    testDisasm "fa40f002" "asr r0, r0, r2"
    testDisasm "fa51f002" "asrs.w r0, r1, r2"
    testDisasm "4111bf00" "asrs r1, r2"

  /// A8.8.160 SADD8
  [<TestMethod>]
  member _.``A8.8.160 SADD8``() =
    testDisasm "fa81f002" "sadd8 r0, r1, r2"
    testDisasm "fa81f900" "sadd8 sb, r1, r0"
    testDisasm "fa81fa00" "sadd8 sl, r1, r0"
    testDisasm "fa81fb00" "sadd8 fp, r1, r0"

  /// A8.8.161 SASX
  [<TestMethod>]
  member _.``A8.8.161 SASX``() =
    testDisasm "faa1f002" "sasx r0, r1, r2"
    testDisasm "faa1f900" "sasx sb, r1, r0"
    testDisasm "faa1fa00" "sasx sl, r1, r0"
    testDisasm "faa1fb00" "sasx fp, r1, r0"

  /// A8.8.162 SBC (immediate)
  [<TestMethod>]
  member _.``A8.8.162 SBC``() =
    testDisasm "f161407f" "sbc r0, r1, #0xff000000"
    testDisasm "f171407f" "sbcs r0, r1, #0xff000000"
    testDisasm "eb600002" "sbc r0, r0, r2"
    testDisasm "eb710002" "sbcs.w r0, r1, r2"

  /// A8.8.165 SBFX
  [<TestMethod>]
  member _.``A8.8.165 SBFX``() =
    testDisasm "f34100c4" "sbfx r0, r1, #0x3, #0x5"
    testDisasm "f3410900" "sbfx sb, r1, #0x0, #0x1"
    testDisasm "f3410a00" "sbfx sl, r1, #0x0, #0x1"
    testDisasm "f3410b00" "sbfx fp, r1, #0x0, #0x1"

  /// A8.8.166 SDIV
  [<TestMethod>]
  member _.``A8.8.166 SDIV``() =
    testDisasm "fb91f0f2" "sdiv r0, r1, r2"
    testDisasm "fb91f9f1" "sdiv sb, r1, r1"
    testDisasm "fb91faf1" "sdiv sl, r1, r1"
    testDisasm "fb91fbf1" "sdiv fp, r1, r1"

  /// A8.8.167 SEL
  [<TestMethod>]
  member _.``A8.8.167 SEL``() =
    testDisasm "faa1f082" "sel r0, r1, r2"

  /// A8.8.168 SETEND
  [<TestMethod>]
  member _.``A8.8.168 SETEND``() =
    testDisasm "b658bf00" "setend be"

  /// A8.8.169 SEV
  [<TestMethod>]
  member _.``A8.8.169 SEV``() =
    testDisasm "bf40bf00" "sev"
    testDisasm "f3af8004" "sev.w"

  /// A8.8.170 SHADD16
  [<TestMethod>]
  member _.``A8.8.170 SHADD16``() =
    testDisasm "fa91f022" "shadd16 r0, r1, r2"

  /// A8.8.171 SHADD8
  [<TestMethod>]
  member _.``A8.8.171 SHADD8``() =
    testDisasm "fa81f022" "shadd8 r0, r1, r2"

  /// A8.8.172 SHASX
  [<TestMethod>]
  member _.``A8.8.172 SHASX``() =
    testDisasm "faa1f022" "shasx r0, r1, r2"

  /// A8.8.173 SHSAX
  [<TestMethod>]
  member _.``A8.8.173 SHSAX``() =
    testDisasm "fae1f022" "shsax r0, r1, r2"

  /// A8.8.174 SHSUB16
  [<TestMethod>]
  member _.``A8.8.174 SHSUB16``() =
    testDisasm "fad1f022" "shsub16 r0, r1, r2"

  /// A8.8.175 SHSUB8
  [<TestMethod>]
  member _.``A8.8.175 SHSUB8``() =
    testDisasm "fac1f022" "shsub8 r0, r1, r2"

  /// A8.8.176 SMC (previously SMI)
  [<TestMethod>]
  member _.``A8.8.176 SMC``() =
    testDisasm "f7f18000" "smc #0x1"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLABB``() =
    testDisasm "fb113002" "smlabb r0, r1, r2, r3"
    testDisasm "fb110900" "smlabb sb, r1, r0, r0"
    testDisasm "fb110a00" "smlabb sl, r1, r0, r0"
    testDisasm "fb110b00" "smlabb fp, r1, r0, r0"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLABT``() =
    testDisasm "fb113012" "smlabt r0, r1, r2, r3"
    testDisasm "fb110910" "smlabt sb, r1, r0, r0"
    testDisasm "fb110a10" "smlabt sl, r1, r0, r0"
    testDisasm "fb110b10" "smlabt fp, r1, r0, r0"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLATB``() =
    testDisasm "fb113022" "smlatb r0, r1, r2, r3"

  /// A8.8.177 SMLABB, SMLABT, SMLATB, SMLATT
  [<TestMethod>]
  member _.``A8.8.177 SMLATT``() =
    testDisasm "fb113032" "smlatt r0, r1, r2, r3"
    testDisasm "fb110934" "smlatt sb, r1, r4, r0"
    testDisasm "fb110a34" "smlatt sl, r1, r4, r0"
    testDisasm "fb110b34" "smlatt fp, r1, r4, r0"

  /// A8.8.178 SMLAD
  [<TestMethod>]
  member _.``A8.8.178 SMLAD``() =
    testDisasm "fb213002" "smlad r0, r1, r2, r3"
    testDisasm "fb210900" "smlad sb, r1, r0, r0"
    testDisasm "fb210a00" "smlad sl, r1, r0, r0"
    testDisasm "fb210b00" "smlad fp, r1, r0, r0"

  /// A8.8.179 SMLAL
  [<TestMethod>]
  member _.``A8.8.179 SMLAL``() =
    testDisasm "fbc20103" "smlal r0, r1, r2, r3"
    testDisasm "fbc10900" "smlal r0, sb, r1, r0"
    testDisasm "fbc10a00" "smlal r0, sl, r1, r0"
    testDisasm "fbc10b00" "smlal r0, fp, r1, r0"

  /// A8.8.18 B
  [<TestMethod>]
  member _.``A8.8.18 B``() =
    testDisasm "e000bf00" "b 0x4 ; "
    testDisasm "f000b800" "b.w 0x4 ; "

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALBB``() =
    testDisasm "fbc20183" "smlalbb r0, r1, r2, r3"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALBT``() =
    testDisasm "fbc20193" "smlalbt r0, r1, r2, r3"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALTB``() =
    testDisasm "fbc201a3" "smlaltb r0, r1, r2, r3"

  /// A8.8.180 SMLALBB, SMLALBT, SMLALTB, SMLALTT
  [<TestMethod>]
  member _.``A8.8.180 SMLALTT``() =
    testDisasm "fbc201b3" "smlaltt r0, r1, r2, r3"

  /// A8.8.181 SMLALD
  [<TestMethod>]
  member _.``A8.8.181 SMLALD``() =
    testDisasm "fbc201c3" "smlald r0, r1, r2, r3"
    testDisasm "fbc109c1" "smlald r0, sb, r1, r1"
    testDisasm "fbc10ac1" "smlald r0, sl, r1, r1"
    testDisasm "fbc10bc1" "smlald r0, fp, r1, r1"

  /// A8.8.182 SMLAWB, SMLAWT
  [<TestMethod>]
  member _.``A8.8.182 SMLAWB``() =
    testDisasm "fb313002" "smlawb r0, r1, r2, r3"
    testDisasm "fb310900" "smlawb sb, r1, r0, r0"
    testDisasm "fb310a00" "smlawb sl, r1, r0, r0"
    testDisasm "fb310b00" "smlawb fp, r1, r0, r0"

  /// A8.8.182 SMLAWB, SMLAWT
  [<TestMethod>]
  member _.``A8.8.182 SMLAWT``() =
    testDisasm "fb313012" "smlawt r0, r1, r2, r3"
    testDisasm "fb310910" "smlawt sb, r1, r0, r0"
    testDisasm "fb310a10" "smlawt sl, r1, r0, r0"
    testDisasm "fb310b10" "smlawt fp, r1, r0, r0"

  /// A8.8.183 SMLSD
  [<TestMethod>]
  member _.``A8.8.183 SMLSD``() =
    testDisasm "fb413002" "smlsd r0, r1, r2, r3"
    testDisasm "fb410900" "smlsd sb, r1, r0, r0"
    testDisasm "fb410a00" "smlsd sl, r1, r0, r0"
    testDisasm "fb410b00" "smlsd fp, r1, r0, r0"

  /// A8.8.184 SMLSLD
  [<TestMethod>]
  member _.``A8.8.184 SMLSLD``() =
    testDisasm "fbd201c3" "smlsld r0, r1, r2, r3"
    testDisasm "fbd109c1" "smlsld r0, sb, r1, r1"
    testDisasm "fbd10ac1" "smlsld r0, sl, r1, r1"
    testDisasm "fbd10bc1" "smlsld r0, fp, r1, r1"

  /// A8.8.185 SMMLA
  [<TestMethod>]
  member _.``A8.8.185 SMMLA``() =
    testDisasm "fb513002" "smmla r0, r1, r2, r3"
    testDisasm "fb510900" "smmla sb, r1, r0, r0"
    testDisasm "fb510a00" "smmla sl, r1, r0, r0"
    testDisasm "fb510b00" "smmla fp, r1, r0, r0"

  /// A8.8.186 SMMLS
  [<TestMethod>]
  member _.``A8.8.186 SMMLS``() =
    testDisasm "fb613002" "smmls r0, r1, r2, r3"
    testDisasm "fb610900" "smmls sb, r1, r0, r0"
    testDisasm "fb610a00" "smmls sl, r1, r0, r0"
    testDisasm "fb610b00" "smmls fp, r1, r0, r0"

  /// A8.8.187 SMMUL
  [<TestMethod>]
  member _.``A8.8.187 SMMUL``() =
    testDisasm "fb51f002" "smmul r0, r1, r2"
    testDisasm "fb51f900" "smmul sb, r1, r0"
    testDisasm "fb51fa00" "smmul sl, r1, r0"
    testDisasm "fb51fb00" "smmul fp, r1, r0"

  /// A8.8.188 SMUAD
  [<TestMethod>]
  member _.``A8.8.188 SMUAD``() =
    testDisasm "fb21f002" "smuad r0, r1, r2"
    testDisasm "fb21f900" "smuad sb, r1, r0"
    testDisasm "fb21fa00" "smuad sl, r1, r0"
    testDisasm "fb21fb00" "smuad fp, r1, r0"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULBB``() =
    testDisasm "fb11f002" "smulbb r0, r1, r2"
    testDisasm "fb11f900" "smulbb sb, r1, r0"
    testDisasm "fb11fa00" "smulbb sl, r1, r0"
    testDisasm "fb11fb00" "smulbb fp, r1, r0"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULBT``() =
    testDisasm "fb11f012" "smulbt r0, r1, r2"
    testDisasm "fb11f910" "smulbt sb, r1, r0"
    testDisasm "fb11fa10" "smulbt sl, r1, r0"
    testDisasm "fb11fb10" "smulbt fp, r1, r0"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULTB``() =
    testDisasm "fb11f022" "smultb r0, r1, r2"

  /// A8.8.189 SMULBB, SMULBT, SMULTB, SMULTT
  [<TestMethod>]
  member _.``A8.8.189 SMULTT``() =
    testDisasm "fb11f032" "smultt r0, r1, r2"
    testDisasm "fb11f934" "smultt sb, r1, r4"
    testDisasm "fb11fa34" "smultt sl, r1, r4"
    testDisasm "fb11fb34" "smultt fp, r1, r4"

  /// A8.8.19 BFC
  [<TestMethod>]
  member _.``A8.8.19 BFC``() =
    testDisasm "f36f00c7" "bfc r0, #0x3, #0x5"
    testDisasm "f36f0900" "bfc sb, #0x0, #0x1"
    testDisasm "f36f0a00" "bfc sl, #0x0, #0x1"
    testDisasm "f36f0b00" "bfc fp, #0x0, #0x1"

  /// A8.8.190 SMULL
  [<TestMethod>]
  member _.``A8.8.190 SMULL``() =
    testDisasm "fb820103" "smull r0, r1, r2, r3"
    testDisasm "fb810900" "smull r0, sb, r1, r0"
    testDisasm "fb810a00" "smull r0, sl, r1, r0"
    testDisasm "fb810b00" "smull r0, fp, r1, r0"

  /// A8.8.191 SMULWB, SMULWT
  [<TestMethod>]
  member _.``A8.8.191 SMULWB``() =
    testDisasm "fb31f002" "smulwb r0, r1, r2"
    testDisasm "fb31f900" "smulwb sb, r1, r0"
    testDisasm "fb31fa00" "smulwb sl, r1, r0"
    testDisasm "fb31fb00" "smulwb fp, r1, r0"

  /// A8.8.191 SMULWB, SMULWT
  [<TestMethod>]
  member _.``A8.8.191 SMULWT``() =
    testDisasm "fb31f012" "smulwt r0, r1, r2"
    testDisasm "fb31f910" "smulwt sb, r1, r0"
    testDisasm "fb31fa10" "smulwt sl, r1, r0"
    testDisasm "fb31fb10" "smulwt fp, r1, r0"

  /// A8.8.192 SMUSD
  [<TestMethod>]
  member _.``A8.8.192 SMUSD``() =
    testDisasm "fb41f002" "smusd r0, r1, r2"
    testDisasm "fb41f900" "smusd sb, r1, r0"
    testDisasm "fb41fa00" "smusd sl, r1, r0"
    testDisasm "fb41fb00" "smusd fp, r1, r0"

  /// A8.8.193 SRS
  [<TestMethod>]
  member _.``A8.8.193 SRS``() =
    testDisasm "e9adc013" "srsia sp!, #0x13"
    testDisasm "e80dc013" "srsdb sp, #0x13"

  /// A8.8.194 SSAT
  [<TestMethod>]
  member _.``A8.8.194 SSAT``() =
    testDisasm "f3010007" "ssat r0, #0x8, r1"
    testDisasm "f301004f" "ssat r0, #0x10, r1, lsl #0x1"
    testDisasm "f321104f" "ssat r0, #0x10, r1, asr #0x5"
    testDisasm "f3010900" "ssat sb, #0x1, r1"

  /// A8.8.195 SSAT16
  [<TestMethod>]
  member _.``A8.8.195 SSAT16``() =
    testDisasm "f3210007" "ssat16 r0, #0x8, r1"
    testDisasm "f3210900" "ssat16 sb, #0x1, r1"
    testDisasm "f3210a00" "ssat16 sl, #0x1, r1"
    testDisasm "f3210b00" "ssat16 fp, #0x1, r1"

  /// A8.8.196 SSAX
  [<TestMethod>]
  member _.``A8.8.196 SSAX``() =
    testDisasm "fae1f002" "ssax r0, r1, r2"
    testDisasm "fae1f900" "ssax sb, r1, r0"
    testDisasm "fae1fa00" "ssax sl, r1, r0"
    testDisasm "fae1fb00" "ssax fp, r1, r0"

  /// A8.8.197 SSUB16
  [<TestMethod>]
  member _.``A8.8.197 SSUB16``() =
    testDisasm "fad1f002" "ssub16 r0, r1, r2"
    testDisasm "fad1f900" "ssub16 sb, r1, r0"
    testDisasm "fad1fa00" "ssub16 sl, r1, r0"
    testDisasm "fad1fb00" "ssub16 fp, r1, r0"

  /// A8.8.198 SSUB8
  [<TestMethod>]
  member _.``A8.8.198 SSUB8``() =
    testDisasm "fac1f002" "ssub8 r0, r1, r2"
    testDisasm "fac1f900" "ssub8 sb, r1, r0"
    testDisasm "fac1fa00" "ssub8 sl, r1, r0"
    testDisasm "fac1fb00" "ssub8 fp, r1, r0"

  /// A8.8.199 STC, STC2
  [<TestMethod>]
  member _.``A8.8.199 STC``() =
    testDisasm "ec215e34" "stc p14, c5, [r1], #-0xd0"
    testDisasm "ec295e34" "stc p14, c5, [sb], #-0xd0"
    testDisasm "ec2d5e34" "stc p14, c5, [sp], #-0xd0"
    testDisasm "ed015e34" "stc p14, c5, [r1, #-0xd0]"

  /// A8.8.20 BFI
  [<TestMethod>]
  member _.``A8.8.20 BFI``() =
    testDisasm "f36100c7" "bfi r0, r1, #0x3, #0x5"
    testDisasm "f3610900" "bfi sb, r1, #0x0, #0x1"
    testDisasm "f3610a00" "bfi sl, r1, #0x0, #0x1"
    testDisasm "f3610b00" "bfi fp, r1, #0x0, #0x1"

  /// A8.8.200 STM (STMIA, STMEA)
  [<TestMethod>]
  member _.``A8.8.200 STM``() =
    testDisasm "e881000c" "stm.w r1, {r2, r3}"
    testDisasm "c10cbf00" "stm r1!, {r2, r3}"
    testDisasm "c001bf00" "stm r0!, {r0}"
    testDisasm "c007bf00" "stm r0!, {r0, r1, r2}"

  /// A8.8.202 STMDB (STMFD)
  [<TestMethod>]
  member _.``A8.8.202 STMDB``() =
    testDisasm "e901000c" "stmdb r1, {r2, r3}"
    testDisasm "e921000c" "stmdb r1!, {r2, r3}"
    testDisasm "e9010034" "stmdb r1, {r2, r4, r5}"
    testDisasm "e901004f" "stmdb r1, {r0, r1, r2, r3, r6}"

  /// A8.8.204 STR (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.204 STR``() =
    testDisasm "6108bf00" "str r0, [r1, #0x10]"
    testDisasm "5088bf00" "str r0, [r1, r2]"
    testDisasm "f8410012" "str r0, [r1, r2, lsl #0x1]"
    testDisasm "6008bf00" "str r0, [r1]"

  /// A8.8.207 STRB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.207 STRB``() =
    testDisasm "70c8bf00" "strb r0, [r1, #0x3]"
    testDisasm "5488bf00" "strb r0, [r1, r2]"
    testDisasm "f8010012" "strb r0, [r1, r2, lsl #0x1]"
    testDisasm "7008bf00" "strb r0, [r1]"

  /// A8.8.21 BIC (immediate)
  [<TestMethod>]
  member _.``A8.8.21 BIC``() =
    testDisasm "f021407f" "bic r0, r1, #0xff000000"
    testDisasm "f031407f" "bics r0, r1, #0xff000000"
    testDisasm "ea200002" "bic r0, r0, r2"
    testDisasm "ea310002" "bics r0, r1, r2"

  /// A8.8.210 STRBT
  [<TestMethod>]
  member _.``A8.8.210 STRBT``() =
    testDisasm "f8010e00" "strbt r0, [r1]"
    testDisasm "f8010e03" "strbt r0, [r1, #0x3]"
    testDisasm "f8019e34" "strbt sb, [r1, #0x34]"
    testDisasm "f8019e00" "strbt sb, [r1]"

  /// A8.8.211 STRD (immediate)
  [<TestMethod>]
  member _.``A8.8.211 STRD``() =
    testDisasm "e9c10100" "strd r0, r1, [r1]"
    testDisasm "e8610034" "strd r0, r0, [r1], #-0xd0"
    testDisasm "e8610934" "strd r0, sb, [r1], #-0xd0"
    testDisasm "e8610a34" "strd r0, sl, [r1], #-0xd0"

  /// A8.8.213 STREX
  [<TestMethod>]
  member _.``A8.8.213 STREX``() =
    testDisasm "e8412000" "strex r0, r2, [r1]"
    testDisasm "e8410234" "strex r2, r0, [r1, #0xd0]"
    testDisasm "e8410934" "strex sb, r0, [r1, #0xd0]"
    testDisasm "e8410900" "strex sb, r0, [r1]"

  /// A8.8.214 STREXB
  [<TestMethod>]
  member _.``A8.8.214 STREXB``() =
    testDisasm "e8c12f40" "strexb r0, r2, [r1]"

  /// A8.8.215 STREXD
  [<TestMethod>]
  member _.``A8.8.215 STREXD``() =
    testDisasm "e8c12370" "strexd r0, r2, r3, [r1]"
    testDisasm "e8c11970" "strexd r0, r1, sb, [r1]"
    testDisasm "e8c11a70" "strexd r0, r1, sl, [r1]"
    testDisasm "e8c11b70" "strexd r0, r1, fp, [r1]"

  /// A8.8.216 STREXH
  [<TestMethod>]
  member _.``A8.8.216 STREXH``() =
    testDisasm "e8c12f50" "strexh r0, r2, [r1]"

  /// A8.8.217 STRH (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.217 STRH``() =
    testDisasm "8208bf00" "strh r0, [r1, #0x10]"
    testDisasm "5288bf00" "strh r0, [r1, r2]"
    testDisasm "8008bf00" "strh r0, [r1]"
    testDisasm "f8a10000" "strh.w r0, [r1]"

  /// A8.8.220 STRHT
  [<TestMethod>]
  member _.``A8.8.220 STRHT``() =
    testDisasm "f8210e00" "strht r0, [r1]"
    testDisasm "f8210e03" "strht r0, [r1, #0x3]"
    testDisasm "f8219e34" "strht sb, [r1, #0x34]"
    testDisasm "f8219e00" "strht sb, [r1]"

  /// A8.8.221 STRT
  [<TestMethod>]
  member _.``A8.8.221 STRT``() =
    testDisasm "f8410e00" "strt r0, [r1]"
    testDisasm "f8410e03" "strt r0, [r1, #0x3]"
    testDisasm "f8419e34" "strt sb, [r1, #0x34]"
    testDisasm "f8419e00" "strt sb, [r1]"

  /// A8.8.222 SUB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.222 SUB``() =
    testDisasm "b082bf00" "sub sp, sp, #0x8"
    testDisasm "f1a00003" "sub r0, r0, #0x3"
    testDisasm "f1b1417f" "subs.w r1, r1, #0xff000000"
    testDisasm "eba10002" "sub r0, r1, r2"

  /// A8.8.228 SUBS PC, LR and related instructions
  [<TestMethod>]
  member _.``A8.8.228 SUBS``() =
    testDisasm "f1b1417f" "subs.w r1, r1, #0xff000000"
    testDisasm "1a88bf00" "subs r0, r1, r2"
    testDisasm "ebb10002" "subs.w r0, r1, r2"
    testDisasm "1e00bf00" "subs r0, r0, #0x0"

  /// A8.8.229 SVC (previously SWI)
  [<TestMethod>]
  member _.``A8.8.229 SVC``() =
    testDisasm "df00bf00" "svc #0x0"

  /// A8.8.231 SXTAB
  [<TestMethod>]
  member _.``A8.8.231 SXTAB``() =
    testDisasm "fa41f082" "sxtab r0, r1, r2"

  /// A8.8.232 SXTAB16
  [<TestMethod>]
  member _.``A8.8.232 SXTAB16``() =
    testDisasm "fa21f082" "sxtab16 r0, r1, r2"

  /// A8.8.233 SXTAH
  [<TestMethod>]
  member _.``A8.8.233 SXTAH``() =
    testDisasm "fa01f082" "sxtah r0, r1, r2"

  /// A8.8.234 SXTB
  [<TestMethod>]
  member _.``A8.8.234 SXTB``() =
    testDisasm "b248bf00" "sxtb r0, r1"
    testDisasm "fa4ff082" "sxtb.w r0, r2"

  /// A8.8.235 SXTB16
  [<TestMethod>]
  member _.``A8.8.235 SXTB16``() =
    testDisasm "fa2ff081" "sxtb16 r0, r1"

  /// A8.8.236 SXTH
  [<TestMethod>]
  member _.``A8.8.236 SXTH``() =
    testDisasm "b208bf00" "sxth r0, r1"
    testDisasm "fa0ff082" "sxth.w r0, r2"

  /// A8.8.237 TBB, TBH
  [<TestMethod>]
  member _.``A8.8.237 TBB``() =
    testDisasm "e8d1f002" "tbb [r1, r2]"
    testDisasm "e8dff002" "tbb [pc, r2]"

  /// A8.8.237 TBB, TBH
  [<TestMethod>]
  member _.``A8.8.237 TBH``() =
    testDisasm "e8dff012" "tbh [pc, r2, lsl #0x1]"

  /// A8.8.238 TEQ (immediate)
  [<TestMethod>]
  member _.``A8.8.238 TEQ``() =
    testDisasm "f0914f7f" "teq r1, #0xff000000"
    testDisasm "ea910f02" "teq r1, r2"
    testDisasm "ea910f42" "teq r1, r2, lsl #0x1"
    testDisasm "ea910fd2" "teq r1, r2, lsr #0x3"

  /// A8.8.24 BKPT
  [<TestMethod>]
  member _.``A8.8.24 BKPT``() =
    testDisasm "be03bf00" "bkpt #0x3"

  /// A8.8.241 TST (immediate)
  [<TestMethod>]
  member _.``A8.8.241 TST``() =
    testDisasm "4211bf00" "tst r1, r2"
    testDisasm "ea110f42" "tst r1, r2, lsl #0x1"
    testDisasm "ea110fd2" "tst r1, r2, lsr #0x3"
    testDisasm "ea111f62" "tst r1, r2, asr #0x5"

  /// A8.8.244 UADD16
  [<TestMethod>]
  member _.``A8.8.244 UADD16``() =
    testDisasm "fa91f042" "uadd16 r0, r1, r2"

  /// A8.8.245 UADD8
  [<TestMethod>]
  member _.``A8.8.245 UADD8``() =
    testDisasm "fa81f042" "uadd8 r0, r1, r2"

  /// A8.8.246 UASX
  [<TestMethod>]
  member _.``A8.8.246 UASX``() =
    testDisasm "faa1f042" "uasx r0, r1, r2"

  /// A8.8.247 UBFX
  [<TestMethod>]
  member _.``A8.8.247 UBFX``() =
    testDisasm "f3c100c4" "ubfx r0, r1, #0x3, #0x5"
    testDisasm "f3c10900" "ubfx sb, r1, #0x0, #0x1"
    testDisasm "f3c10a00" "ubfx sl, r1, #0x0, #0x1"
    testDisasm "f3c10b00" "ubfx fp, r1, #0x0, #0x1"

  /// A8.8.248 UDF
  [<TestMethod>]
  member _.``A8.8.248 UDF``() =
    testDisasm "de00bf00" "udf #0x0"
    testDisasm "f7f1a034" "udf.w #0x1034"

  /// A8.8.249 UDIV
  [<TestMethod>]
  member _.``A8.8.249 UDIV``() =
    testDisasm "fbb1f0f2" "udiv r0, r1, r2"
    testDisasm "fbb1f9f1" "udiv sb, r1, r1"
    testDisasm "fbb1faf1" "udiv sl, r1, r1"
    testDisasm "fbb1fbf1" "udiv fp, r1, r1"

  /// A8.8.25 BL, BLX (immediate)
  [<TestMethod>]
  member _.``A8.8.25 BL``() =
    testDisasm "f000f800" "bl 0x4 ; "
    testDisasm "d900bf00" "bls 0x4 ; "
    testDisasm "f2418034" "bls.w 0x106c ; "

  /// A8.8.25 BL, BLX (immediate)
  [<TestMethod>]
  member _.``A8.8.25 BLX``() =
    testDisasm "f000e802" "blx 0x8 ; "
    testDisasm "4780bf00" "blx r0"
    testDisasm "47c8bf00" "blx sb"
    testDisasm "47d0bf00" "blx sl"

  /// A8.8.250 UHADD16
  [<TestMethod>]
  member _.``A8.8.250 UHADD16``() =
    testDisasm "fa91f062" "uhadd16 r0, r1, r2"

  /// A8.8.251 UHADD8
  [<TestMethod>]
  member _.``A8.8.251 UHADD8``() =
    testDisasm "fa81f062" "uhadd8 r0, r1, r2"

  /// A8.8.252 UHASX
  [<TestMethod>]
  member _.``A8.8.252 UHASX``() =
    testDisasm "faa1f062" "uhasx r0, r1, r2"

  /// A8.8.253 UHSAX
  [<TestMethod>]
  member _.``A8.8.253 UHSAX``() =
    testDisasm "fae1f062" "uhsax r0, r1, r2"

  /// A8.8.254 UHSUB16
  [<TestMethod>]
  member _.``A8.8.254 UHSUB16``() =
    testDisasm "fad1f062" "uhsub16 r0, r1, r2"

  /// A8.8.255 UHSUB8
  [<TestMethod>]
  member _.``A8.8.255 UHSUB8``() =
    testDisasm "fac1f062" "uhsub8 r0, r1, r2"

  /// A8.8.256 UMAAL
  [<TestMethod>]
  member _.``A8.8.256 UMAAL``() =
    testDisasm "fbe20163" "umaal r0, r1, r2, r3"

  /// A8.8.257 UMLAL
  [<TestMethod>]
  member _.``A8.8.257 UMLAL``() =
    testDisasm "fbe20103" "umlal r0, r1, r2, r3"
    testDisasm "fbe10900" "umlal r0, sb, r1, r0"
    testDisasm "fbe10a00" "umlal r0, sl, r1, r0"
    testDisasm "fbe10b00" "umlal r0, fp, r1, r0"

  /// A8.8.258 UMULL
  [<TestMethod>]
  member _.``A8.8.258 UMULL``() =
    testDisasm "fba20103" "umull r0, r1, r2, r3"
    testDisasm "fba10900" "umull r0, sb, r1, r0"
    testDisasm "fba10a00" "umull r0, sl, r1, r0"
    testDisasm "fba10b00" "umull r0, fp, r1, r0"

  /// A8.8.259 UQADD16
  [<TestMethod>]
  member _.``A8.8.259 UQADD16``() =
    testDisasm "fa91f052" "uqadd16 r0, r1, r2"

  /// A8.8.260 UQADD8
  [<TestMethod>]
  member _.``A8.8.260 UQADD8``() =
    testDisasm "fa81f052" "uqadd8 r0, r1, r2"

  /// A8.8.261 UQASX
  [<TestMethod>]
  member _.``A8.8.261 UQASX``() =
    testDisasm "faa1f052" "uqasx r0, r1, r2"

  /// A8.8.262 UQSAX
  [<TestMethod>]
  member _.``A8.8.262 UQSAX``() =
    testDisasm "fae1f052" "uqsax r0, r1, r2"

  /// A8.8.263 UQSUB16
  [<TestMethod>]
  member _.``A8.8.263 UQSUB16``() =
    testDisasm "fad1f052" "uqsub16 r0, r1, r2"

  /// A8.8.264 UQSUB8
  [<TestMethod>]
  member _.``A8.8.264 UQSUB8``() =
    testDisasm "fac1f052" "uqsub8 r0, r1, r2"

  /// A8.8.265 USAD8
  [<TestMethod>]
  member _.``A8.8.265 USAD8``() =
    testDisasm "fb71f002" "usad8 r0, r1, r2"
    testDisasm "fb71f900" "usad8 sb, r1, r0"
    testDisasm "fb71fa00" "usad8 sl, r1, r0"
    testDisasm "fb71fb00" "usad8 fp, r1, r0"

  /// A8.8.266 USADA8
  [<TestMethod>]
  member _.``A8.8.266 USADA8``() =
    testDisasm "fb713002" "usada8 r0, r1, r2, r3"
    testDisasm "fb710900" "usada8 sb, r1, r0, r0"
    testDisasm "fb710a00" "usada8 sl, r1, r0, r0"
    testDisasm "fb710b00" "usada8 fp, r1, r0, r0"

  /// A8.8.267 USAT
  [<TestMethod>]
  member _.``A8.8.267 USAT``() =
    testDisasm "f3810003" "usat r0, #0x3, r1"
    testDisasm "f3810043" "usat r0, #0x3, r1, lsl #0x1"
    testDisasm "f3a11043" "usat r0, #0x3, r1, asr #0x5"
    testDisasm "f3810900" "usat sb, #0x0, r1"

  /// A8.8.268 USAT16
  [<TestMethod>]
  member _.``A8.8.268 USAT16``() =
    testDisasm "f3a10003" "usat16 r0, #0x3, r1"
    testDisasm "f3a10900" "usat16 sb, #0x0, r1"
    testDisasm "f3a10a00" "usat16 sl, #0x0, r1"
    testDisasm "f3a10b00" "usat16 fp, #0x0, r1"

  /// A8.8.269 USAX
  [<TestMethod>]
  member _.``A8.8.269 USAX``() =
    testDisasm "fae1f042" "usax r0, r1, r2"

  /// A8.8.27 BX
  [<TestMethod>]
  member _.``A8.8.27 BX``() =
    testDisasm "4700bf00" "bx r0"
    testDisasm "4748bf00" "bx sb"
    testDisasm "4750bf00" "bx sl"
    testDisasm "4758bf00" "bx fp"

  /// A8.8.270 USUB16
  [<TestMethod>]
  member _.``A8.8.270 USUB16``() =
    testDisasm "fad1f042" "usub16 r0, r1, r2"

  /// A8.8.271 USUB8
  [<TestMethod>]
  member _.``A8.8.271 USUB8``() =
    testDisasm "fac1f042" "usub8 r0, r1, r2"

  /// A8.8.272 UXTAB
  [<TestMethod>]
  member _.``A8.8.272 UXTAB``() =
    testDisasm "fa51f082" "uxtab r0, r1, r2"

  /// A8.8.273 UXTAB16
  [<TestMethod>]
  member _.``A8.8.273 UXTAB16``() =
    testDisasm "fa31f082" "uxtab16 r0, r1, r2"

  /// A8.8.274 UXTAH
  [<TestMethod>]
  member _.``A8.8.274 UXTAH``() =
    testDisasm "fa11f082" "uxtah r0, r1, r2"

  /// A8.8.275 UXTB
  [<TestMethod>]
  member _.``A8.8.275 UXTB``() =
    testDisasm "b2c8bf00" "uxtb r0, r1"
    testDisasm "fa5ff082" "uxtb.w r0, r2"

  /// A8.8.276 UXTB16
  [<TestMethod>]
  member _.``A8.8.276 UXTB16``() =
    testDisasm "fa3ff081" "uxtb16 r0, r1"

  /// A8.8.277 UXTH
  [<TestMethod>]
  member _.``A8.8.277 UXTH``() =
    testDisasm "b288bf00" "uxth r0, r1"
    testDisasm "fa1ff082" "uxth.w r0, r2"

  /// A8.8.278 VABA, VABAL
  [<TestMethod>]
  member _.``A8.8.278 VABA``() =
    testDisasm "ef120754" "vaba.s16 q0, q1, q2"
    testDisasm "ff020754" "vaba.u8 q0, q1, q2"
    testDisasm "ef010712" "vaba.s8 d0, d1, d2"
    testDisasm "ff010712" "vaba.u8 d0, d1, d2"

  /// A8.8.278 VABA, VABAL
  [<TestMethod>]
  member _.``A8.8.278 VABAL``() =
    testDisasm "ef810502" "vabal.s8 q0, d1, d2"
    testDisasm "ff810500" "vabal.u8 q0, d1, d0"

  /// A8.8.279 VABD, VABDL (integer)
  [<TestMethod>]
  member _.``A8.8.279 VABD``() =
    testDisasm "ff320d44" "vabd.f16 q0, q1, q2"
    testDisasm "ef120744" "vabd.s16 q0, q1, q2"
    testDisasm "ff020744" "vabd.u8 q0, q1, q2"
    testDisasm "ef010702" "vabd.s8 d0, d1, d2"

  /// A8.8.279 VABD, VABDL (integer)
  [<TestMethod>]
  member _.``A8.8.279 VABDL``() =
    testDisasm "ef810702" "vabdl.s8 q0, d1, d2"
    testDisasm "ff810700" "vabdl.u8 q0, d1, d0"

  /// A8.8.28 BXJ
  [<TestMethod>]
  member _.``A8.8.28 BXJ``() =
    testDisasm "f3c18f00" "bxj r1"

  /// A8.8.281 VABS
  [<TestMethod>]
  member _.``A8.8.281 VABS``() =
    testDisasm "eeb009e0" "vabs.f16 s0, s1"
    testDisasm "ffb50742" "vabs.f16 q0, q1"
    testDisasm "ffb10344" "vabs.s8 q0, q2"
    testDisasm "ffb10302" "vabs.s8 d0, d2"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACGE``() =
    testDisasm "ff120e54" "vacge.f16 q0, q1, q2"
    testDisasm "ff020e11" "vacge.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACGT``() =
    testDisasm "ff320e54" "vacgt.f16 q0, q1, q2"
    testDisasm "ff210e34" "vacgt.f32 d0, d1, d20"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACLE``() =
    testDisasm "ff120e54" "vacge.f16 q0, q1, q2"
    testDisasm "ff020e11" "vacge.f32 d0, d2, d1"

  /// A8.8.282 VACGE, VACGT, VACLE, VACLT
  [<TestMethod>]
  member _.``A8.8.282 VACLT``() =
    testDisasm "ff320e54" "vacgt.f16 q0, q1, q2"
    testDisasm "ff210e34" "vacgt.f32 d0, d1, d20"

  /// A8.8.283 VADD (integer)
  [<TestMethod>]
  member _.``A8.8.283 VADD``() =
    testDisasm "ee300981" "vadd.f16 s0, s1, s2"
    testDisasm "ef120d44" "vadd.f16 q0, q1, q2"
    testDisasm "ef120844" "vadd.i16 q0, q1, q2"
    testDisasm "ef010802" "vadd.i8 d0, d1, d2"

  /// A8.8.285 VADDHN
  [<TestMethod>]
  member _.``A8.8.285 VADDHN``() =
    testDisasm "ef920404" "vaddhn.i32 d0, q1, q2"

  /// A8.8.286 VADDL, VADDW
  [<TestMethod>]
  member _.``A8.8.286 VADDL``() =
    testDisasm "ef910002" "vaddl.s16 q0, d1, d2"
    testDisasm "ff810002" "vaddl.u8 q0, d1, d2"

  /// A8.8.286 VADDL, VADDW
  [<TestMethod>]
  member _.``A8.8.286 VADDW``() =
    testDisasm "ef800101" "vaddw.s8 q0, q0, d1"
    testDisasm "ff800100" "vaddw.u8 q0, q0, d0"

  /// A8.8.287 VAND (immediate)
  [<TestMethod>]
  member _.``A8.8.287 VAND``() =
    testDisasm "ef020154" "vand q0, q1, q2"
    testDisasm "ef011112" "vand d1, d1, d2"

  /// A8.8.289 VBIC (immediate)
  [<TestMethod>]
  member _.``A8.8.289 VBIC``() =
    testDisasm "ef120154" "vbic q0, q1, q2"
    testDisasm "ef810970" "vbic.i16 q0, #0x10"
    testDisasm "ef810930" "vbic.i16 d0, #0x10"
    testDisasm "ef111112" "vbic d1, d1, d2"

  /// A8.8.29 CBNZ, CBZ
  [<TestMethod>]
  member _.``A8.8.29 CBNZ``() =
    testDisasm "b900bf00" "cbnz r0, 0x4 ; "

  /// A8.8.29 CBNZ, CBZ
  [<TestMethod>]
  member _.``A8.8.29 CBZ``() =
    testDisasm "b100bf00" "cbz r0, 0x4 ; "

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBIF``() =
    testDisasm "ff320154" "vbif q0, q1, q2"
    testDisasm "ff310134" "vbif d0, d1, d20"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBIT``() =
    testDisasm "ff220154" "vbit q0, q1, q2"
    testDisasm "ff210134" "vbit d0, d1, d20"

  /// A8.8.291 VBIF, VBIT, VBSL
  [<TestMethod>]
  member _.``A8.8.291 VBSL``() =
    testDisasm "ff120154" "vbsl q0, q1, q2"
    testDisasm "ff110134" "vbsl d0, d1, d20"

  /// A8.8.292 VCEQ (register)
  [<TestMethod>]
  member _.``A8.8.292 VCEQ``() =
    testDisasm "ef120e44" "vceq.f16 q0, q1, q2"
    testDisasm "ffb50542" "vceq.f16 q0, q1, #0x0"
    testDisasm "ff010812" "vceq.i8 d0, d1, d2"
    testDisasm "ef010e02" "vceq.f32 d0, d1, d2"

  /// A8.8.294 VCGE (register)
  [<TestMethod>]
  member _.``A8.8.294 VCGE``() =
    testDisasm "ff120e44" "vcge.f16 q0, q1, q2"
    testDisasm "ffb504c2" "vcge.f16 q0, q1, #0x0"
    testDisasm "ef010312" "vcge.s8 d0, d1, d2"
    testDisasm "ff010312" "vcge.u8 d0, d1, d2"

  /// A8.8.296 VCGT (register)
  [<TestMethod>]
  member _.``A8.8.296 VCGT``() =
    testDisasm "ff320e44" "vcgt.f16 q0, q1, q2"
    testDisasm "ffb50442" "vcgt.f16 q0, q1, #0x0"
    testDisasm "ef010302" "vcgt.s8 d0, d1, d2"
    testDisasm "ff010302" "vcgt.u8 d0, d1, d2"

  /// A8.8.298 VCLE (register)
  [<TestMethod>]
  member _.``A8.8.298 VCLE``() =
    testDisasm "ffb505c2" "vcle.f16 q0, q1, #0x0"
    testDisasm "ffb101c4" "vcle.s8 q0, q2, #0x0"
    testDisasm "ffb10182" "vcle.s8 d0, d2, #0x0"
    testDisasm "ffb90582" "vcle.f32 d0, d2, #0x0"

  /// A8.8.300 VCLS
  [<TestMethod>]
  member _.``A8.8.300 VCLS``() =
    testDisasm "ffb00444" "vcls.s8 q0, q2"
    testDisasm "ffb00402" "vcls.s8 d0, d2"

  /// A8.8.301 VCLT (register)
  [<TestMethod>]
  member _.``A8.8.301 VCLT``() =
    testDisasm "ffb50642" "vclt.f16 q0, q1, #0x0"
    testDisasm "ffb10244" "vclt.s8 q0, q2, #0x0"
    testDisasm "ffb10202" "vclt.s8 d0, d2, #0x0"
    testDisasm "ffb90602" "vclt.f32 d0, d2, #0x0"

  /// A8.8.303 VCLZ
  [<TestMethod>]
  member _.``A8.8.303 VCLZ``() =
    testDisasm "ffb004c4" "vclz.i8 q0, q2"
    testDisasm "ffb00482" "vclz.i8 d0, d2"

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
    testDisasm "ffb00544" "vcnt.8 q0, q2"
    testDisasm "ffb00502" "vcnt.8 d0, d2"

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

  /// A8.8.314 VDUP (scalar)
  [<TestMethod>]
  member _.``A8.8.314 VDUP``() =
    testDisasm "eec01b10" "vdup.8 d0, r1"
    testDisasm "ee819b10" "vdup.32 d1, sb"
    testDisasm "ee81ab10" "vdup.32 d1, sl"
    testDisasm "ee81bb10" "vdup.32 d1, fp"

  /// A8.8.316 VEOR
  [<TestMethod>]
  member _.``A8.8.316 VEOR``() =
    testDisasm "ff020154" "veor q0, q1, q2"
    testDisasm "ff011112" "veor d1, d1, d2"

  /// A8.8.317 VEXT
  [<TestMethod>]
  member _.``A8.8.317 VEXT``() =
    testDisasm "efb00142" "vext.8 q0, q0, q1, #0x1"
    testDisasm "efb10000" "vext.8 d0, d1, d0, #0x0"

  /// A8.8.318 VFMA, VFMS
  [<TestMethod>]
  member _.``A8.8.318 VFMA``() =
    testDisasm "eea00981" "vfma.f16 s0, s1, s2"
    testDisasm "ef120c54" "vfma.f16 q0, q1, q2"
    testDisasm "eea10b00" "vfma.f64 d0, d1, d0"

  /// A8.8.318 VFMA, VFMS
  [<TestMethod>]
  member _.``A8.8.318 VFMS``() =
    testDisasm "eea009c1" "vfms.f16 s0, s1, s2"
    testDisasm "ef320c54" "vfms.f16 q0, q1, q2"
    testDisasm "eea10b4f" "vfms.f64 d0, d1, d15"

  /// A8.8.319 VFNMA, VFNMS
  [<TestMethod>]
  member _.``A8.8.319 VFNMA``() =
    testDisasm "ee9009c1" "vfnma.f16 s0, s1, s2"
    testDisasm "ee910b4f" "vfnma.f64 d0, d1, d15"

  /// A8.8.319 VFNMA, VFNMS
  [<TestMethod>]
  member _.``A8.8.319 VFNMS``() =
    testDisasm "ee900981" "vfnms.f16 s0, s1, s2"
    testDisasm "ee910b00" "vfnms.f64 d0, d1, d0"

  /// A8.8.32 CLREX
  [<TestMethod>]
  member _.``A8.8.32 CLREX``() =
    testDisasm "f3bf8f2f" "clrex"

  /// A8.8.320 VHADD, VHSUB
  [<TestMethod>]
  member _.``A8.8.320 VHADD``() =
    testDisasm "ef020044" "vhadd.s8 q0, q1, q2"
    testDisasm "ef010000" "vhadd.s8 d0, d1, d0"
    testDisasm "ff010000" "vhadd.u8 d0, d1, d0"

  /// A8.8.320 VHADD, VHSUB
  [<TestMethod>]
  member _.``A8.8.320 VHSUB``() =
    testDisasm "ef020244" "vhsub.s8 q0, q1, q2"
    testDisasm "ef010200" "vhsub.s8 d0, d1, d0"
    testDisasm "ff010200" "vhsub.u8 d0, d1, d0"

  /// A8.8.321 VLD1 (multiple single elements)
  [<TestMethod>]
  member _.``A8.8.321 VLD1``() =
    testDisasm "f921070f" "vld1.8 {d0}, [r1]"
    testDisasm "f9210234" "vld1.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9210200" "vld1.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f921024f" "vld1.16 {d0, d1, d2, d3}, [r1]"

  /// A8.8.324 VLD2 (multiple 2-element structures)
  [<TestMethod>]
  member _.``A8.8.324 VLD2``() =
    testDisasm "f921080f" "vld2.8 {d0, d1}, [r1]"
    testDisasm "f9210334" "vld2.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9210300" "vld2.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f921034f" "vld2.16 {d0, d1, d2, d3}, [r1]"

  /// A8.8.327 VLD3 (multiple 3-element structures)
  [<TestMethod>]
  member _.``A8.8.327 VLD3``() =
    testDisasm "f921040f" "vld3.8 {d0, d1, d2}, [r1]"
    testDisasm "f9210400" "vld3.8 {d0, d1, d2}, [r1], r0"
    testDisasm "f9210410" "vld3.8 {d0, d1, d2}, [r1:64], r0"
    testDisasm "f921045f" "vld3.16 {d0, d1, d2}, [r1:64]"

  /// A8.8.33 CLZ
  [<TestMethod>]
  member _.``A8.8.33 CLZ``() =
    testDisasm "fab1f081" "clz r0, r1"

  /// A8.8.330 VLD4 (multiple 4-element structures)
  [<TestMethod>]
  member _.``A8.8.330 VLD4``() =
    testDisasm "f921000f" "vld4.8 {d0, d1, d2, d3}, [r1]"
    testDisasm "f9210034" "vld4.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9210000" "vld4.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f921005f" "vld4.16 {d0, d1, d2, d3}, [r1:64]"

  /// A8.8.333 VLDM
  [<TestMethod>]
  member _.``A8.8.333 VLDM``() =
    testDisasm "ec910b04" "vldmia r1, {d0, d1}"
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecb10b08" "vldmia r1!, {d0, d1, d2, d3}"
    testDisasm "ec910a01" "vldmia r1, {s0}"

  /// A8.8.334 VLDR
  [<TestMethod>]
  member _.``A8.8.334 VLDR``() =
    testDisasm "ed910900" "vldr.16 s0, [r1]"
    testDisasm "ed9f0b00" "vldr.64 d0, [pc]"
    testDisasm "ed910a00" "vldr s0, [r1]"
    testDisasm "ed9f0a00" "vldr.32 s0, [pc]"

  /// A8.8.335 VMAX, VMIN (integer)
  [<TestMethod>]
  member _.``A8.8.335 VMAX``() =
    testDisasm "ef120f44" "vmax.f16 q0, q1, q2"
    testDisasm "ef020644" "vmax.s8 q0, q1, q2"
    testDisasm "ef010600" "vmax.s8 d0, d1, d0"
    testDisasm "ef010f00" "vmax.f32 d0, d1, d0"

  /// A8.8.335 VMAX, VMIN (integer)
  [<TestMethod>]
  member _.``A8.8.335 VMIN``() =
    testDisasm "ef320f44" "vmin.f16 q0, q1, q2"
    testDisasm "ef020654" "vmin.s8 q0, q1, q2"
    testDisasm "ef010634" "vmin.s8 d0, d1, d20"
    testDisasm "ef210f00" "vmin.f32 d0, d1, d0"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLA``() =
    testDisasm "ee000981" "vmla.f16 s0, s1, s2"
    testDisasm "ef120d54" "vmla.f16 q0, q1, q2"
    testDisasm "ff92016c" "vmla.f16 q0, q1, d4[3]"
    testDisasm "ef020944" "vmla.i8 q0, q1, q2"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLAL``() =
    testDisasm "ef810802" "vmlal.s8 q0, d1, d2"
    testDisasm "ef91024f" "vmlal.s16 q0, d1, d7[1]"
    testDisasm "ff810800" "vmlal.u8 q0, d1, d0"
    testDisasm "ff91024f" "vmlal.u16 q0, d1, d7[1]"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLS``() =
    testDisasm "ee0009c1" "vmls.f16 s0, s1, s2"
    testDisasm "ef320d54" "vmls.f16 q0, q1, q2"
    testDisasm "ff92056c" "vmls.f16 q0, q1, d4[3]"
    testDisasm "ff020944" "vmls.i8 q0, q1, q2"

  /// A8.8.337 VMLA, VMLAL, VMLS, VMLSL (integer)
  [<TestMethod>]
  member _.``A8.8.337 VMLSL``() =
    testDisasm "ef810a02" "vmlsl.s8 q0, d1, d2"
    testDisasm "ef91064f" "vmlsl.s16 q0, d1, d7[1]"
    testDisasm "ff810a00" "vmlsl.u8 q0, d1, d0"
    testDisasm "ff91064f" "vmlsl.u16 q0, d1, d7[1]"

  /// A8.8.34 CMN (immediate)
  [<TestMethod>]
  member _.``A8.8.34 CMN``() =
    testDisasm "f1114f7f" "cmn r1, #0xff000000"
    testDisasm "42d1bf00" "cmn r1, r2"
    testDisasm "eb110f42" "cmn r1, r2, lsl #0x1"
    testDisasm "eb110fd2" "cmn r1, r2, lsr #0x3"

  /// A8.8.340 VMOV (immediate)
  [<TestMethod>]
  member _.``A8.8.340 VMOV``() =
    testDisasm "ee000910" "vmov.f16 s0, r0"
    testDisasm "ee100990" "vmov.f16 r0, s1"
    testDisasm "ef810e50" "vmov.i8 q0, #0x10"
    testDisasm "ef810e10" "vmov.i8 d0, #0x10"

  /// A8.8.347 VMOVL
  [<TestMethod>]
  member _.``A8.8.347 VMOVL``() =
    testDisasm "ef880a12" "vmovl.s8 q0, d2"
    testDisasm "ff880a12" "vmovl.u8 q0, d2"

  /// A8.8.348 VMOVN
  [<TestMethod>]
  member _.``A8.8.348 VMOVN``() =
    testDisasm "ffb20204" "vmovn.i16 d0, q2"

  /// A8.8.349 VMRS
  [<TestMethod>]
  member _.``A8.8.349 VMRS``() =
    testDisasm "eef10a10" "vmrs r0, fpscr"
    testDisasm "eef19a10" "vmrs sb, fpscr"
    testDisasm "eef1aa10" "vmrs sl, fpscr"
    testDisasm "eef1ba10" "vmrs fp, fpscr"

  /// A8.8.350 VMSR
  [<TestMethod>]
  member _.``A8.8.350 VMSR``() =
    testDisasm "eee10a10" "vmsr fpscr, r0"
    testDisasm "eee19a10" "vmsr fpscr, sb"
    testDisasm "eee1aa10" "vmsr fpscr, sl"
    testDisasm "eee1ba10" "vmsr fpscr, fp"

  /// A8.8.351 VMUL, VMULL (integer and polynomial)
  [<TestMethod>]
  member _.``A8.8.351 VMUL``() =
    testDisasm "ee200981" "vmul.f16 s0, s1, s2"
    testDisasm "ff120d54" "vmul.f16 q0, q1, q2"
    testDisasm "ff92096c" "vmul.f16 q0, q1, d4[3]"
    testDisasm "ef120954" "vmul.i16 q0, q1, q2"

  /// A8.8.351 VMUL, VMULL (integer and polynomial)
  [<TestMethod>]
  member _.``A8.8.351 VMULL``() =
    testDisasm "ef810c02" "vmull.s8 q0, d1, d2"
    testDisasm "efa20e03" "vmull.p64 q0, d2, d3"
    testDisasm "ef910a4f" "vmull.s16 q0, d1, d7[1]"
    testDisasm "ff810c00" "vmull.u8 q0, d1, d0"

  /// A8.8.354 VMVN (immediate)
  [<TestMethod>]
  member _.``A8.8.354 VMVN``() =
    testDisasm "ffb005c2" "vmvn q0, q1"
    testDisasm "ef810870" "vmvn.i16 q0, #0x10"
    testDisasm "ef810830" "vmvn.i16 d0, #0x10"
    testDisasm "ffb00582" "vmvn d0, d2"

  /// A8.8.356 VNEG
  [<TestMethod>]
  member _.``A8.8.356 VNEG``() =
    testDisasm "eeb10960" "vneg.f16 s0, s1"
    testDisasm "ffb507c2" "vneg.f16 q0, q1"
    testDisasm "ffb103c4" "vneg.s8 q0, q2"
    testDisasm "ffb10382" "vneg.s8 d0, d2"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMLA``() =
    testDisasm "ee1009c1" "vnmla.f16 s0, s1, s2"
    testDisasm "ee110b42" "vnmla.f64 d0, d1, d2"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMLS``() =
    testDisasm "ee100981" "vnmls.f16 s0, s1, s2"
    testDisasm "ee110b00" "vnmls.f64 d0, d1, d0"

  /// A8.8.357 VNMLA, VNMLS, VNMUL
  [<TestMethod>]
  member _.``A8.8.357 VNMUL``() =
    testDisasm "ee2009c1" "vnmul.f16 s0, s1, s2"
    testDisasm "ee210b4f" "vnmul.f64 d0, d1, d15"

  /// A8.8.358 VORN (immediate)
  [<TestMethod>]
  member _.``A8.8.358 VORN``() =
    testDisasm "ef320154" "vorn q0, q1, q2"
    testDisasm "ef311112" "vorn d1, d1, d2"

  /// A8.8.360 VORR (immediate)
  [<TestMethod>]
  member _.``A8.8.360 VORR``() =
    testDisasm "ef220154" "vorr q0, q1, q2"
    testDisasm "ef810950" "vorr.i16 q0, #0x10"
    testDisasm "ef810910" "vorr.i16 d0, #0x10"
    testDisasm "ef211112" "vorr d1, d1, d2"

  /// A8.8.362 VPADAL
  [<TestMethod>]
  member _.``A8.8.362 VPADAL``() =
    testDisasm "ffb00644" "vpadal.s8 q0, q2"
    testDisasm "ffb006c4" "vpadal.u8 q0, q2"
    testDisasm "ffb00602" "vpadal.s8 d0, d2"
    testDisasm "ffb00682" "vpadal.u8 d0, d2"

  /// A8.8.363 VPADD (integer)
  [<TestMethod>]
  member _.``A8.8.363 VPADD``() =
    testDisasm "ff110d02" "vpadd.f16 d0, d1, d2"
    testDisasm "ef110b12" "vpadd.i16 d0, d1, d2"

  /// A8.8.365 VPADDL
  [<TestMethod>]
  member _.``A8.8.365 VPADDL``() =
    testDisasm "ffb00244" "vpaddl.s8 q0, q2"
    testDisasm "ffb002c4" "vpaddl.u8 q0, q2"
    testDisasm "ffb00202" "vpaddl.s8 d0, d2"
    testDisasm "ffb00282" "vpaddl.u8 d0, d2"

  /// A8.8.366 VPMAX, VPMIN (integer)
  [<TestMethod>]
  member _.``A8.8.366 VPMAX``() =
    testDisasm "ff110f02" "vpmax.f16 d0, d1, d2"
    testDisasm "ef010a02" "vpmax.s8 d0, d1, d2"
    testDisasm "ff010a00" "vpmax.u8 d0, d1, d0"

  /// A8.8.366 VPMAX, VPMIN (integer)
  [<TestMethod>]
  member _.``A8.8.366 VPMIN``() =
    testDisasm "ff310f02" "vpmin.f16 d0, d1, d2"
    testDisasm "ef010a12" "vpmin.s8 d0, d1, d2"
    testDisasm "ff010a34" "vpmin.u8 d0, d1, d20"

  /// A8.8.368 VPOP
  [<TestMethod>]
  member _.``A8.8.368 VPOP``() =
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecbd0a01" "vldmia sp!, {s0}"
    ("vldmia sp!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ecbd0a10"
    ("vldmia sp!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15, s16, s17}")
    |> testDisasm "ecbd0a12"

  /// A8.8.369 VPUSH
  [<TestMethod>]
  member _.``A8.8.369 VPUSH``() =
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"
    testDisasm "ed2d0a01" "vstmdb sp!, {s0}"
    ("vstmdb sp!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ed2d0a10"

  /// A8.8.37 CMP (immediate)
  [<TestMethod>]
  member _.``A8.8.37 CMP``() =
    testDisasm "2903bf00" "cmp r1, #0x3"
    testDisasm "4291bf00" "cmp r1, r2"
    testDisasm "ebb10f42" "cmp r1, r2, lsl #0x1"
    testDisasm "ebb10fd2" "cmp r1, r2, lsr #0x3"

  /// A8.8.370 VQABS
  [<TestMethod>]
  member _.``A8.8.370 VQABS``() =
    testDisasm "ffb00744" "vqabs.s8 q0, q2"
    testDisasm "ffb00702" "vqabs.s8 d0, d2"

  /// A8.8.371 VQADD
  [<TestMethod>]
  member _.``A8.8.371 VQADD``() =
    testDisasm "ef120054" "vqadd.s16 q0, q1, q2"
    testDisasm "ff020054" "vqadd.u8 q0, q1, q2"
    testDisasm "ef010012" "vqadd.s8 d0, d1, d2"
    testDisasm "ff010012" "vqadd.u8 d0, d1, d2"

  /// A8.8.372 VQDMLAL, VQDMLSL
  [<TestMethod>]
  member _.``A8.8.372 VQDMLAL``() =
    testDisasm "ef910902" "vqdmlal.s16 q0, d1, d2"
    testDisasm "ef91034f" "vqdmlal.s16 q0, d1, d7[1]"

  /// A8.8.372 VQDMLAL, VQDMLSL
  [<TestMethod>]
  member _.``A8.8.372 VQDMLSL``() =
    testDisasm "ef910b02" "vqdmlsl.s16 q0, d1, d2"
    testDisasm "ef91074f" "vqdmlsl.s16 q0, d1, d7[1]"

  /// A8.8.373 VQDMULH
  [<TestMethod>]
  member _.``A8.8.373 VQDMULH``() =
    testDisasm "ef220b44" "vqdmulh.s32 q0, q1, q2"
    testDisasm "ef110b02" "vqdmulh.s16 d0, d1, d2"
    testDisasm "ff920c42" "vqdmulh.s16 q0, q1, d2[0]"
    testDisasm "ef910c42" "vqdmulh.s16 d0, d1, d2[0]"

  /// A8.8.374 VQDMULL
  [<TestMethod>]
  member _.``A8.8.374 VQDMULL``() =
    testDisasm "efa10d02" "vqdmull.s32 q0, d1, d2"
    testDisasm "ef910b42" "vqdmull.s16 q0, d1, d2[0]"

  /// A8.8.375 VQMOVN, VQMOVUN
  [<TestMethod>]
  member _.``A8.8.375 VQMOVN``() =
    testDisasm "ffb20282" "vqmovn.s16 d0, q1"

  /// A8.8.375 VQMOVN, VQMOVUN
  [<TestMethod>]
  member _.``A8.8.375 VQMOVUN``() =
    testDisasm "ffb20242" "vqmovun.s16 d0, q1"

  /// A8.8.376 VQNEG
  [<TestMethod>]
  member _.``A8.8.376 VQNEG``() =
    testDisasm "ffb007c4" "vqneg.s8 q0, q2"
    testDisasm "ffb00782" "vqneg.s8 d0, d2"

  /// A8.8.377 VQRDMULH
  [<TestMethod>]
  member _.``A8.8.377 VQRDMULH``() =
    testDisasm "ff220b44" "vqrdmulh.s32 q0, q1, q2"
    testDisasm "ff110b02" "vqrdmulh.s16 d0, d1, d2"
    testDisasm "ff920d42" "vqrdmulh.s16 q0, q1, d2[0]"
    testDisasm "ef910d42" "vqrdmulh.s16 d0, d1, d2[0]"

  /// A8.8.378 VQRSHL
  [<TestMethod>]
  member _.``A8.8.378 VQRSHL``() =
    testDisasm "ef040552" "vqrshl.s8 q0, q1, q2"
    testDisasm "ef010534" "vqrshl.s8 d0, d20, d1"
    testDisasm "ff010534" "vqrshl.u8 d0, d20, d1"
    testDisasm "ff000570" "vqrshl.u8 q0, q8, q0"

  /// A8.8.379 VQRSHRN, VQRSHRUN
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRN``() =
    testDisasm "ef8f0952" "vqrshrn.s16 d0, q1, #0x1"
    testDisasm "ff890970" "vqrshrn.u16 d0, q8, #0x7"

  /// A8.8.379 VQRSHRN, VQRSHRUN
  [<TestMethod>]
  member _.``A8.8.379 VQRSHRUN``() =
    testDisasm "ff8f0852" "vqrshrun.s16 d0, q1, #0x1"

  /// A8.8.380 VQSHL (register)
  [<TestMethod>]
  member _.``A8.8.380 VQSHL``() =
    testDisasm "ef040452" "vqshl.s8 q0, q1, q2"
    testDisasm "ef010434" "vqshl.s8 d0, d20, d1"
    testDisasm "ef890734" "vqshl.s8 d0, d20, #0x1"
    testDisasm "ef890770" "vqshl.s8 q0, q8, #0x1"

  /// A8.8.381 VQSHL, VQSHLU (immediate)
  [<TestMethod>]
  member _.``A8.8.381 VQSHLU``() =
    testDisasm "ff890652" "vqshlu.s8 q0, q1, #0x1"
    testDisasm "ff890634" "vqshlu.s8 d0, d20, #0x1"

  /// A8.8.382 VQSHRN, VQSHRUN
  [<TestMethod>]
  member _.``A8.8.382 VQSHRN``() =
    testDisasm "ef8f0912" "vqshrn.s16 d0, q1, #0x1"
    testDisasm "ff890934" "vqshrn.u16 d0, q10, #0x7"

  /// A8.8.382 VQSHRN, VQSHRUN
  [<TestMethod>]
  member _.``A8.8.382 VQSHRUN``() =
    testDisasm "ff8f0812" "vqshrun.s16 d0, q1, #0x1"

  /// A8.8.383 VQSUB
  [<TestMethod>]
  member _.``A8.8.383 VQSUB``() =
    testDisasm "ef020254" "vqsub.s8 q0, q1, q2"
    testDisasm "ef010234" "vqsub.s8 d0, d1, d20"
    testDisasm "ff010234" "vqsub.u8 d0, d1, d20"
    testDisasm "ff000270" "vqsub.u8 q0, q0, q8"

  /// A8.8.384 VRADDHN
  [<TestMethod>]
  member _.``A8.8.384 VRADDHN``() =
    testDisasm "ff920404" "vraddhn.i32 d0, q1, q2"

  /// A8.8.385 VRECPE
  [<TestMethod>]
  member _.``A8.8.385 VRECPE``() =
    testDisasm "ffb70542" "vrecpe.f16 q0, q1"
    testDisasm "ffbb0444" "vrecpe.u32 q0, q2"
    testDisasm "ffbb0402" "vrecpe.u32 d0, d2"
    testDisasm "ffbb0502" "vrecpe.f32 d0, d2"

  /// A8.8.386 VRECPS
  [<TestMethod>]
  member _.``A8.8.386 VRECPS``() =
    testDisasm "ef120f54" "vrecps.f16 q0, q1, q2"
    testDisasm "ef010f12" "vrecps.f32 d0, d1, d2"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV16``() =
    testDisasm "ffb00142" "vrev16.8 q0, q1"
    testDisasm "ffb00100" "vrev16.8 d0, d0"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV32``() =
    testDisasm "ffb000c2" "vrev32.8 q0, q1"

  /// A8.8.387 VREV16, VREV32, VREV64
  [<TestMethod>]
  member _.``A8.8.387 VREV64``() =
    testDisasm "ffb00042" "vrev64.8 q0, q1"
    testDisasm "ffb00000" "vrev64.8 d0, d0"

  /// A8.8.388 VRHADD
  [<TestMethod>]
  member _.``A8.8.388 VRHADD``() =
    testDisasm "ff020144" "vrhadd.u8 q0, q1, q2"
    testDisasm "ef022144" "vrhadd.s8 q1, q1, q2"
    testDisasm "ef011102" "vrhadd.s8 d1, d1, d2"
    testDisasm "ff011102" "vrhadd.u8 d1, d1, d2"

  /// A8.8.389 VRSHL
  [<TestMethod>]
  member _.``A8.8.389 VRSHL``() =
    testDisasm "ef040542" "vrshl.s8 q0, q1, q2"
    testDisasm "ef010500" "vrshl.s8 d0, d0, d1"
    testDisasm "ff010500" "vrshl.u8 d0, d0, d1"

  /// A8.8.390 VRSHR
  [<TestMethod>]
  member _.``A8.8.390 VRSHR``() =
    testDisasm "ef890234" "vrshr.s8 d0, d20, #0x7"
    testDisasm "ef890270" "vrshr.s8 q0, q8, #0x7"
    testDisasm "ff890234" "vrshr.u8 d0, d20, #0x7"
    testDisasm "ff890270" "vrshr.u8 q0, q8, #0x7"

  /// A8.8.391 VRSHRN
  [<TestMethod>]
  member _.``A8.8.391 VRSHRN``() =
    testDisasm "ef8f0852" "vrshrn.i16 d0, q1, #0x1"

  /// A8.8.392 VRSQRTE
  [<TestMethod>]
  member _.``A8.8.392 VRSQRTE``() =
    testDisasm "ffb705c2" "vrsqrte.f16 q0, q1"
    testDisasm "ffbb04c4" "vrsqrte.u32 q0, q2"
    testDisasm "ffbb0482" "vrsqrte.u32 d0, d2"
    testDisasm "ffbb0582" "vrsqrte.f32 d0, d2"

  /// A8.8.393 VRSQRTS
  [<TestMethod>]
  member _.``A8.8.393 VRSQRTS``() =
    testDisasm "ef320f54" "vrsqrts.f16 q0, q1, q2"
    testDisasm "ef210f12" "vrsqrts.f32 d0, d1, d2"

  /// A8.8.394 VRSRA
  [<TestMethod>]
  member _.``A8.8.394 VRSRA``() =
    testDisasm "ef8f0352" "vrsra.s8 q0, q1, #0x1"
    testDisasm "ef890334" "vrsra.s8 d0, d20, #0x7"
    testDisasm "ff890334" "vrsra.u8 d0, d20, #0x7"
    testDisasm "ff890370" "vrsra.u8 q0, q8, #0x7"

  /// A8.8.395 VRSUBHN
  [<TestMethod>]
  member _.``A8.8.395 VRSUBHN``() =
    testDisasm "ff920604" "vrsubhn.i32 d0, q1, q2"

  /// A8.8.396 VSHL (immediate)
  [<TestMethod>]
  member _.``A8.8.396 VSHL``() =
    testDisasm "ef890552" "vshl.i8 q0, q1, #0x1"
    testDisasm "ef010400" "vshl.s8 d0, d0, d1"
    testDisasm "ef890534" "vshl.i8 d0, d20, #0x1"
    testDisasm "ff010400" "vshl.u8 d0, d0, d1"

  /// A8.8.398 VSHLL
  [<TestMethod>]
  member _.``A8.8.398 VSHLL``() =
    testDisasm "ef890a11" "vshll.s8 q0, d1, #0x1"
    testDisasm "ff890a34" "vshll.u8 q0, d20, #0x1"

  /// A8.8.399 VSHR
  [<TestMethod>]
  member _.``A8.8.399 VSHR``() =
    testDisasm "ef890034" "vshr.s8 d0, d20, #0x7"
    testDisasm "ef890070" "vshr.s8 q0, q8, #0x7"
    testDisasm "ff890034" "vshr.u8 d0, d20, #0x7"
    testDisasm "ff890070" "vshr.u8 q0, q8, #0x7"

  /// A8.8.4 ADD (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.4 ADD``() =
    testDisasm "b002bf00" "add sp, sp, #0x8"
    testDisasm "f1000003" "add r0, r0, #0x3"
    testDisasm "f111417f" "adds.w r1, r1, #0xff000000"
    testDisasm "eb010002" "add r0, r1, r2"

  /// A8.8.40 CPS
  [<TestMethod>]
  member _.``A8.8.40 CPS``() =
    testDisasm "f3af8113" "cps #0x13"

  /// A8.8.400 VSHRN
  [<TestMethod>]
  member _.``A8.8.400 VSHRN``() =
    testDisasm "ef8f0812" "vshrn.i16 d0, q1, #0x1"

  /// A8.8.401 VSLI
  [<TestMethod>]
  member _.``A8.8.401 VSLI``() =
    testDisasm "ff890552" "vsli.8 q0, q1, #0x1"
    testDisasm "ff890534" "vsli.8 d0, d20, #0x1"

  /// A8.8.402 VSQRT
  [<TestMethod>]
  member _.``A8.8.402 VSQRT``() =
    testDisasm "eeb109e0" "vsqrt.f16 s0, s1"
    testDisasm "eeb10bc2" "vsqrt.f64 d0, d2"

  /// A8.8.403 VSRA
  [<TestMethod>]
  member _.``A8.8.403 VSRA``() =
    testDisasm "ef8f0152" "vsra.s8 q0, q1, #0x1"
    testDisasm "ef890134" "vsra.s8 d0, d20, #0x7"
    testDisasm "ff890134" "vsra.u8 d0, d20, #0x7"
    testDisasm "ff890170" "vsra.u8 q0, q8, #0x7"

  /// A8.8.404 VSRI
  [<TestMethod>]
  member _.``A8.8.404 VSRI``() =
    testDisasm "ff8f0452" "vsri.8 q0, q1, #0x1"
    testDisasm "ff890434" "vsri.8 d0, d20, #0x7"

  /// A8.8.405 VST1 (multiple single elements)
  [<TestMethod>]
  member _.``A8.8.405 VST1``() =
    testDisasm "f901070f" "vst1.8 {d0}, [r1]"
    testDisasm "f9010234" "vst1.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9010200" "vst1.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f901024f" "vst1.16 {d0, d1, d2, d3}, [r1]"

  /// A8.8.407 VST2 (multiple 2-element structures)
  [<TestMethod>]
  member _.``A8.8.407 VST2``() =
    testDisasm "f901080f" "vst2.8 {d0, d1}, [r1]"
    testDisasm "f9010334" "vst2.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9010300" "vst2.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f901034f" "vst2.16 {d0, d1, d2, d3}, [r1]"

  /// A8.8.409 VST3 (multiple 3-element structures)
  [<TestMethod>]
  member _.``A8.8.409 VST3``() =
    testDisasm "f901040f" "vst3.8 {d0, d1, d2}, [r1]"
    testDisasm "f9010400" "vst3.8 {d0, d1, d2}, [r1], r0"
    testDisasm "f9010410" "vst3.8 {d0, d1, d2}, [r1:64], r0"
    testDisasm "f901045f" "vst3.16 {d0, d1, d2}, [r1:64]"

  /// A8.8.41 CPY
  [<TestMethod>]
  member _.``A8.8.41 CPY``() =
    testDisasm "4610bf00" "mov r0, r2"
    testDisasm "0010bf00" "movs r0, r2"

  /// A8.8.411 VST4 (multiple 4-element structures)
  [<TestMethod>]
  member _.``A8.8.411 VST4``() =
    testDisasm "f901000f" "vst4.8 {d0, d1, d2, d3}, [r1]"
    testDisasm "f9010034" "vst4.8 {d0, d1, d2, d3}, [r1:256], r4"
    testDisasm "f9010000" "vst4.8 {d0, d1, d2, d3}, [r1], r0"
    testDisasm "f901005f" "vst4.16 {d0, d1, d2, d3}, [r1:64]"

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
    testDisasm "ed810a00" "vstr s0, [r1]"
    testDisasm "ed810b00" "vstr d0, [r1]"
    testDisasm "ed010934" "vstr.16 s0, [r1, #-0x68]"

  /// A8.8.415 VSUB (integer)
  [<TestMethod>]
  member _.``A8.8.415 VSUB``() =
    testDisasm "ee3009c1" "vsub.f16 s0, s1, s2"
    testDisasm "ef320d44" "vsub.f16 q0, q1, q2"
    testDisasm "ff120844" "vsub.i16 q0, q1, q2"
    testDisasm "ff010802" "vsub.i8 d0, d1, d2"

  /// A8.8.417 VSUBHN
  [<TestMethod>]
  member _.``A8.8.417 VSUBHN``() =
    testDisasm "ef920604" "vsubhn.i32 d0, q1, q2"

  /// A8.8.418 VSUBL, VSUBW
  [<TestMethod>]
  member _.``A8.8.418 VSUBL``() =
    testDisasm "ef910202" "vsubl.s16 q0, d1, d2"
    testDisasm "ff810202" "vsubl.u8 q0, d1, d2"

  /// A8.8.418 VSUBL, VSUBW
  [<TestMethod>]
  member _.``A8.8.418 VSUBW``() =
    testDisasm "ef800301" "vsubw.s8 q0, q0, d1"
    testDisasm "ff800300" "vsubw.u8 q0, q0, d0"

  /// A8.8.419 VSWP
  [<TestMethod>]
  member _.``A8.8.419 VSWP``() =
    testDisasm "ffb20042" "vswp q0, q1"
    testDisasm "ffb20002" "vswp d0, d2"

  /// A8.8.42 CSDB
  [<TestMethod>]
  member _.``A8.8.42 CSDB``() =
    testDisasm "f3af8014" "csdb"

  /// A8.8.420 VTBL, VTBX
  [<TestMethod>]
  member _.``A8.8.420 VTBL``() =
    testDisasm "ffb10802" "vtbl.8 d0, {d1}, d2"
    testDisasm "ffb10900" "vtbl.8 d0, {d1, d2}, d0"
    testDisasm "ffb10a00" "vtbl.8 d0, {d1, d2, d3}, d0"
    testDisasm "ffb10b00" "vtbl.8 d0, {d1, d2, d3, d4}, d0"

  /// A8.8.420 VTBL, VTBX
  [<TestMethod>]
  member _.``A8.8.420 VTBX``() =
    testDisasm "ffb10842" "vtbx.8 d0, {d1}, d2"
    testDisasm "ffb1094f" "vtbx.8 d0, {d1, d2}, d15"
    testDisasm "ffb10a4f" "vtbx.8 d0, {d1, d2, d3}, d15"
    testDisasm "ffb10b4f" "vtbx.8 d0, {d1, d2, d3, d4}, d15"

  /// A8.8.421 VTRN
  [<TestMethod>]
  member _.``A8.8.421 VTRN``() =
    testDisasm "ffb200c2" "vtrn.8 q0, q1"

  /// A8.8.422 VTST
  [<TestMethod>]
  member _.``A8.8.422 VTST``() =
    testDisasm "ef020854" "vtst.8 q0, q1, q2"
    testDisasm "ef010834" "vtst.8 d0, d1, d20"

  /// A8.8.423 VUZP
  [<TestMethod>]
  member _.``A8.8.423 VUZP``() =
    testDisasm "ffb20142" "vuzp.8 q0, q1"

  /// A8.8.424 VZIP
  [<TestMethod>]
  member _.``A8.8.424 VZIP``() =
    testDisasm "ffb201c2" "vzip.8 q0, q1"

  /// A8.8.425 WFE
  [<TestMethod>]
  member _.``A8.8.425 WFE``() =
    testDisasm "bf20bf00" "wfe"
    testDisasm "f3af8002" "wfe.w"

  /// A8.8.426 WFI
  [<TestMethod>]
  member _.``A8.8.426 WFI``() =
    testDisasm "bf30bf00" "wfi"

  /// A8.8.427 YIELD
  [<TestMethod>]
  member _.``A8.8.427 YIELD``() =
    testDisasm "bf10bf00" "yield"

  /// A8.8.44 DMB
  [<TestMethod>]
  member _.``A8.8.44 DMB``() =
    testDisasm "f3bf8f5f" "dmb sy"

  /// A8.8.45 DSB
  [<TestMethod>]
  member _.``A8.8.45 DSB``() =
    testDisasm "f3bf8f4f" "dsb sy"

  /// A8.8.47 EOR (immediate)
  [<TestMethod>]
  member _.``A8.8.47 EOR``() =
    testDisasm "ea800002" "eor r0, r0, r2"
    testDisasm "ea910002" "eors.w r0, r1, r2"
    testDisasm "ea810042" "eor r0, r1, r2, lsl #0x1"
    testDisasm "ea8100d2" "eor r0, r1, r2, lsr #0x3"

  /// A8.8.50 ERET
  [<TestMethod>]
  member _.``A8.8.50 ERET``() =
    testDisasm "f3de8f00" "eret"

  /// A8.8.53 HVC
  [<TestMethod>]
  member _.``A8.8.53 HVC``() =
    testDisasm "f7e18034" "hvc #0x1034"

  /// A8.8.54 ISB
  [<TestMethod>]
  member _.``A8.8.54 ISB``() =
    testDisasm "f3bf8f6f" "isb sy"

  /// A8.8.55 IT
  [<TestMethod>]
  member _.``A8.8.55 IT``() =
    testDisasm "bf08bf00" "it eq"
    testDisasm "bf18bf00" "it ne"
    testDisasm "bf28bf00" "it cs"
    testDisasm "bf38bf00" "it cc"

  /// A8.8.56 LDC, LDC2 (immediate)
  [<TestMethod>]
  member _.``A8.8.56 LDC``() =
    testDisasm "ec315e34" "ldc p14, c5, [r1], #-0xd0"
    testDisasm "ec395e34" "ldc p14, c5, [sb], #-0xd0"
    testDisasm "ec3d5e34" "ldc p14, c5, [sp], #-0xd0"
    testDisasm "ed115e34" "ldc p14, c5, [r1, #-0xd0]"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDM``() =
    testDisasm "e891000c" "ldm.w r1, {r2, r3}"
    testDisasm "c90cbf00" "ldm r1!, {r2, r3}"
    testDisasm "c801bf00" "ldm r0, {r0}"
    testDisasm "c802bf00" "ldm r0!, {r1}"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDMFD``() =
    testDisasm "e891000c" "ldm.w r1, {r2, r3}"
    testDisasm "bc0cbf00" "pop {r2, r3}"
    testDisasm "c90cbf00" "ldm r1!, {r2, r3}"
    testDisasm "bc01bf00" "pop {r0}"

  /// A8.8.58 LDM/LDMIA/LDMFD (Thumb)
  [<TestMethod>]
  member _.``A8.8.58 LDMIA``() =
    testDisasm "e891000c" "ldm.w r1, {r2, r3}"
    testDisasm "bc0cbf00" "pop {r2, r3}"
    testDisasm "c90cbf00" "ldm r1!, {r2, r3}"
    testDisasm "bc01bf00" "pop {r0}"

  /// A8.8.61 LDMDB/LDMEA
  [<TestMethod>]
  member _.``A8.8.61 LDMDB``() =
    testDisasm "e911000c" "ldmdb r1, {r2, r3}"
    testDisasm "e9110034" "ldmdb r1, {r2, r4, r5}"
    testDisasm "e911004f" "ldmdb r1, {r0, r1, r2, r3, r6}"
    testDisasm "e911005f" "ldmdb r1, {r0, r1, r2, r3, r4, r6}"

  /// A8.8.61 LDMDB/LDMEA
  [<TestMethod>]
  member _.``A8.8.61 LDMEA``() =
    testDisasm "e911000c" "ldmdb r1, {r2, r3}"
    testDisasm "e9110034" "ldmdb r1, {r2, r4, r5}"
    testDisasm "e911004f" "ldmdb r1, {r0, r1, r2, r3, r6}"
    testDisasm "e911005f" "ldmdb r1, {r0, r1, r2, r3, r4, r6}"

  /// A8.8.63 LDR (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.63 LDR``() =
    testDisasm "6908bf00" "ldr r0, [r1, #0x10]"
    testDisasm "4800bf00" "ldr r0, [0x4]"
    testDisasm "f8df0000" "ldr.w r0, [0x4]"
    testDisasm "5888bf00" "ldr r0, [r1, r2]"

  /// A8.8.68 LDRB (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.68 LDRB``() =
    testDisasm "78c8bf00" "ldrb r0, [r1, #0x3]"
    testDisasm "f89f0002" "ldrb r0, [0x6]"
    testDisasm "5c88bf00" "ldrb r0, [r1, r2]"
    testDisasm "7808bf00" "ldrb r0, [r1]"

  /// A8.8.72 LDRBT
  [<TestMethod>]
  member _.``A8.8.72 LDRBT``() =
    testDisasm "f8110e00" "ldrbt r0, [r1]"
    testDisasm "f8110e03" "ldrbt r0, [r1, #0x3]"
    testDisasm "f8119e34" "ldrbt sb, [r1, #0x34]"
    testDisasm "f8119e00" "ldrbt sb, [r1]"

  /// A8.8.73 LDRD (immediate)
  [<TestMethod>]
  member _.``A8.8.73 LDRD``() =
    testDisasm "e9df0100" "ldrd r0, r1, [0x4]"
    testDisasm "e9d10100" "ldrd r0, r1, [r1]"
    testDisasm "e8710234" "ldrd r0, r2, [r1], #-0xd0"
    testDisasm "e8710934" "ldrd r0, sb, [r1], #-0xd0"

  /// A8.8.76 LDREX
  [<TestMethod>]
  member _.``A8.8.76 LDREX``() =
    testDisasm "e8510f00" "ldrex r0, [r1]"
    testDisasm "e8510f04" "ldrex r0, [r1, #0x10]"

  /// A8.8.77 LDREXB
  [<TestMethod>]
  member _.``A8.8.77 LDREXB``() =
    testDisasm "e8d10f4f" "ldrexb r0, [r1]"

  /// A8.8.78 LDREXD
  [<TestMethod>]
  member _.``A8.8.78 LDREXD``() =
    testDisasm "e8d1017f" "ldrexd r0, r1, [r1]"

  /// A8.8.79 LDREXH
  [<TestMethod>]
  member _.``A8.8.79 LDREXH``() =
    testDisasm "e8d10f5f" "ldrexh r0, [r1]"

  /// A8.8.80 LDRH (immediate, Thumb)
  [<TestMethod>]
  member _.``A8.8.80 LDRH``() =
    testDisasm "8a08bf00" "ldrh r0, [r1, #0x10]"
    testDisasm "f8bf0002" "ldrh r0, [0x6]"
    testDisasm "5a88bf00" "ldrh r0, [r1, r2]"
    testDisasm "8808bf00" "ldrh r0, [r1]"

  /// A8.8.84 LDRHT
  [<TestMethod>]
  member _.``A8.8.84 LDRHT``() =
    testDisasm "f8310e00" "ldrht r0, [r1]"
    testDisasm "f8310e03" "ldrht r0, [r1, #0x3]"
    testDisasm "f8319e34" "ldrht sb, [r1, #0x34]"
    testDisasm "f8319e00" "ldrht sb, [r1]"

  /// A8.8.85 LDRSB (immediate)
  [<TestMethod>]
  member _.``A8.8.85 LDRSB``() =
    testDisasm "f9910007" "ldrsb r0, [r1, #0x7]"
    testDisasm "f99f0000" "ldrsb r0, [0x4]"
    testDisasm "5688bf00" "ldrsb r0, [r1, r2]"
    testDisasm "f9910000" "ldrsb r0, [r1]"

  /// A8.8.88 LDRSBT
  [<TestMethod>]
  member _.``A8.8.88 LDRSBT``() =
    testDisasm "f9110e00" "ldrsbt r0, [r1]"
    testDisasm "f9110e03" "ldrsbt r0, [r1, #0x3]"
    testDisasm "f9119e34" "ldrsbt sb, [r1, #0x34]"
    testDisasm "f9119e00" "ldrsbt sb, [r1]"

  /// A8.8.89 LDRSH (immediate)
  [<TestMethod>]
  member _.``A8.8.89 LDRSH``() =
    testDisasm "f9b10007" "ldrsh r0, [r1, #0x7]"
    testDisasm "f9bf0002" "ldrsh r0, [0x6]"
    testDisasm "5e88bf00" "ldrsh r0, [r1, r2]"
    testDisasm "f9b10000" "ldrsh r0, [r1]"

  /// A8.8.92 LDRSHT
  [<TestMethod>]
  member _.``A8.8.92 LDRSHT``() =
    testDisasm "f9310e00" "ldrsht r0, [r1]"
    testDisasm "f9310e03" "ldrsht r0, [r1, #0x3]"
    testDisasm "f9319e34" "ldrsht sb, [r1, #0x34]"
    testDisasm "f9319e00" "ldrsht sb, [r1]"

  /// A8.8.93 LDRT
  [<TestMethod>]
  member _.``A8.8.93 LDRT``() =
    testDisasm "f8510e00" "ldrt r0, [r1]"
    testDisasm "f8510e03" "ldrt r0, [r1, #0x3]"
    testDisasm "f8519e34" "ldrt sb, [r1, #0x34]"
    testDisasm "f8519e00" "ldrt sb, [r1]"

  /// A8.8.95 LSL (immediate)
  [<TestMethod>]
  member _.``A8.8.95 LSL``() =
    testDisasm "fa00f002" "lsl r0, r0, r2"
    testDisasm "fa11f002" "lsls.w r0, r1, r2"
    testDisasm "4091bf00" "lsls r1, r2"
    testDisasm "01bf00" "lsls r7, r7, #0x6"

  /// A8.8.97 LSR (immediate)
  [<TestMethod>]
  member _.``A8.8.97 LSR``() =
    testDisasm "0c10bf00" "lsrs r0, r2, #0x10"
    testDisasm "fa20f002" "lsr r0, r0, r2"
    testDisasm "fa31f002" "lsrs.w r0, r1, r2"
    testDisasm "40d1bf00" "lsrs r1, r2"

  /// A8.8.99 MCR, MCR2
  [<TestMethod>]
  member _.``A8.8.99 MCR``() =
    testDisasm "ee010e34" "mcr p14, #0x0, r0, c1, c4, #0x1"
    testDisasm "ee019e34" "mcr p14, #0x0, sb, c1, c4, #0x1"
    testDisasm "ee01ae34" "mcr p14, #0x0, sl, c1, c4, #0x1"
    testDisasm "ee01be34" "mcr p14, #0x0, fp, c1, c4, #0x1"

  /// F5.1.1 ADC, ADCS (immediate)
  [<TestMethod>]
  member _.``F5.1.1 ADCS``() =
    testDisasm "eb510002" "adcs.w r0, r1, r2"
    testDisasm "4151bf00" "adcs r1, r1, r2"
    testDisasm "eb510034" "adcs r0, r1, r4, rrx"
    testDisasm "eb510010" "adcs.w r0, r1, r0, lsr #0x20"

  /// F5.1.101 LSLS (immediate)
  [<TestMethod>]
  member _.``F5.1.101 LSLS``() =
    testDisasm "fa11f002" "lsls.w r0, r1, r2"
    testDisasm "4091bf00" "lsls r1, r2"
    testDisasm "01bf00" "lsls r7, r7, #0x6"
    testDisasm "fa11f900" "lsls.w sb, r1, r0"

  /// F5.1.105 LSRS (immediate)
  [<TestMethod>]
  member _.``F5.1.105 LSRS``() =
    testDisasm "0c10bf00" "lsrs r0, r2, #0x10"
    testDisasm "fa31f002" "lsrs.w r0, r1, r2"
    testDisasm "40d1bf00" "lsrs r1, r2"
    testDisasm "fa31f900" "lsrs.w sb, r1, r0"

  /// F5.1.11 AND, ANDS (immediate)
  [<TestMethod>]
  member _.``F5.1.11 ANDS``() =
    testDisasm "f011407f" "ands r0, r1, #0xff000000"
    testDisasm "ea110002" "ands.w r0, r1, r2"
    testDisasm "4011bf00" "ands r1, r1, r2"
    testDisasm "ea110034" "ands r0, r1, r4, rrx"

  /// F5.1.111 MOV, MOVS (immediate)
  [<TestMethod>]
  member _.``F5.1.111 MOVS``() =
    testDisasm "f05f407f" "movs r0, #0xff000000"
    testDisasm "0010bf00" "movs r0, r2"
    testDisasm "ea5f0002" "movs.w r0, r2"
    testDisasm "ea5f0900" "movs.w sb, r0"

  /// F5.1.122 MUL, MULS
  [<TestMethod>]
  member _.``F5.1.122 MULS``() =
    testDisasm "4340bf00" "muls r0, r0, r0"

  /// F5.1.123 MVN, MVNS (immediate)
  [<TestMethod>]
  member _.``F5.1.123 MVNS``() =
    testDisasm "f07f407f" "mvns r0, #0xff000000"
    testDisasm "43d0bf00" "mvns r0, r2"
    testDisasm "ea7f0002" "mvns.w r0, r2"
    testDisasm "ea7f0034" "mvns r0, r4, rrx"

  /// F5.1.127 ORN, ORNS (immediate)
  [<TestMethod>]
  member _.``F5.1.127 ORNS``() =
    testDisasm "f071407f" "orns r0, r1, #0xff000000"
    testDisasm "ea710002" "orns r0, r1, r2"
    testDisasm "ea710034" "orns r0, r1, r4, rrx"
    testDisasm "ea710010" "orns r0, r1, r0, lsr #0x20"

  /// F5.1.129 ORR, ORRS (immediate)
  [<TestMethod>]
  member _.``F5.1.129 ORRS``() =
    testDisasm "f051407f" "orrs r0, r1, #0xff000000"
    testDisasm "ea510002" "orrs.w r0, r1, r2"
    testDisasm "4311bf00" "orrs r1, r1, r2"
    testDisasm "ea510034" "orrs r0, r1, r4, rrx"

  /// F5.1.132 PKHBT, PKHTB
  [<TestMethod>]
  member _.``F5.1.132 PKHBT``() =
    testDisasm "eac11002" "pkhbt r0, r1, r2, lsl #0x4"
    testDisasm "eac10000" "pkhbt r0, r1, r0"
    testDisasm "eac10900" "pkhbt sb, r1, r0"
    testDisasm "eac109c1" "pkhbt sb, r1, r1, lsl #0x3"

  /// F5.1.132 PKHBT, PKHTB
  [<TestMethod>]
  member _.``F5.1.132 PKHTB``() =
    testDisasm "eac11022" "pkhtb r0, r1, r2, asr #0x4"
    testDisasm "eac109e1" "pkhtb sb, r1, r1, asr #0x3"
    testDisasm "eac10ae1" "pkhtb sl, r1, r1, asr #0x3"
    testDisasm "eac10be1" "pkhtb fp, r1, r1, asr #0x3"

  /// F5.1.141 PSSBB
  [<TestMethod>]
  member _.``F5.1.141 PSSBB``() =
    testDisasm "f3bf8f44" "pssbb"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEDB``() =
    testDisasm "e831c000" "rfedb r1!"

  /// F5.1.159 RFE, RFEDA, RFEDB, RFEIA, RFEIB
  [<TestMethod>]
  member _.``F5.1.159 RFEIA``() =
    testDisasm "e991c000" "rfeia r1"

  /// F5.1.16 ASRS (immediate)
  [<TestMethod>]
  member _.``F5.1.16 ASRS``() =
    testDisasm "1410bf00" "asrs r0, r2, #0x10"
    testDisasm "fa51f002" "asrs.w r0, r1, r2"
    testDisasm "4111bf00" "asrs r1, r2"
    testDisasm "fa51f900" "asrs.w sb, r1, r0"

  /// F5.1.162 RORS (immediate)
  [<TestMethod>]
  member _.``F5.1.162 RORS``() =
    testDisasm "fa71f002" "rors.w r0, r1, r2"
    testDisasm "41d1bf00" "rors r1, r2"
    testDisasm "fa71f900" "rors.w sb, r1, r0"
    testDisasm "fa71fa00" "rors.w sl, r1, r0"

  /// F5.1.165 RRXS
  [<TestMethod>]
  member _.``F5.1.165 RRXS``() =
    testDisasm "ea5f0032" "rrxs r0, r2"
    testDisasm "ea5f0034" "rrxs r0, r4"
    testDisasm "ea5f0031" "rrxs r0, r1"
    testDisasm "ea5f0134" "rrxs r1, r4"

  /// F5.1.166 RSB, RSBS (immediate)
  [<TestMethod>]
  member _.``F5.1.166 RSBS``() =
    testDisasm "f1d1407f" "rsbs r0, r1, #0xff000000"
    testDisasm "ebd10002" "rsbs r0, r1, r2"
    testDisasm "ebd10034" "rsbs r0, r1, r4, rrx"
    testDisasm "ebd10010" "rsbs r0, r1, r0, lsr #0x20"

  /// F5.1.175 SB
  [<TestMethod>]
  member _.``F5.1.175 SB``() =
    testDisasm "f171407f" "sbcs r0, r1, #0xff000000"
    testDisasm "eb710002" "sbcs.w r0, r1, r2"
    testDisasm "4191bf00" "sbcs r1, r1, r2"
    testDisasm "eb710034" "sbcs r0, r1, r4, rrx"

  /// F5.1.176 SBC, SBCS (immediate)
  [<TestMethod>]
  member _.``F5.1.176 SBCS``() =
    testDisasm "f171407f" "sbcs r0, r1, #0xff000000"
    testDisasm "eb710002" "sbcs.w r0, r1, r2"
    testDisasm "4191bf00" "sbcs r1, r1, r2"
    testDisasm "eb710034" "sbcs r0, r1, r4, rrx"

  /// F5.1.183 SETPAN
  [<TestMethod>]
  member _.``F5.1.183 SETPAN``() =
    testDisasm "b610bf00" "setpan #0x0"

  /// F5.1.185 SEVL
  [<TestMethod>]
  member _.``F5.1.185 SEVL``() =
    testDisasm "bf50bf00" "sevl"

  /// F5.1.194 SMLAD, SMLADX
  [<TestMethod>]
  member _.``F5.1.194 SMLADX``() =
    testDisasm "fb213012" "smladx r0, r1, r2, r3"
    testDisasm "fb210910" "smladx sb, r1, r0, r0"
    testDisasm "fb210a10" "smladx sl, r1, r0, r0"
    testDisasm "fb210b10" "smladx fp, r1, r0, r0"

  /// F5.1.197 SMLALD, SMLALDX
  [<TestMethod>]
  member _.``F5.1.197 SMLALDX``() =
    testDisasm "fbc101d2" "smlaldx r0, r1, r1, r2"
    testDisasm "fbc109d1" "smlaldx r0, sb, r1, r1"
    testDisasm "fbc10ad1" "smlaldx r0, sl, r1, r1"
    testDisasm "fbc10bd1" "smlaldx r0, fp, r1, r1"

  /// F5.1.199 SMLSD, SMLSDX
  [<TestMethod>]
  member _.``F5.1.199 SMLSDX``() =
    testDisasm "fb413012" "smlsdx r0, r1, r2, r3"
    testDisasm "fb410910" "smlsdx sb, r1, r0, r0"
    testDisasm "fb410a10" "smlsdx sl, r1, r0, r0"
    testDisasm "fb410b10" "smlsdx fp, r1, r0, r0"

  /// F5.1.200 SMLSLD, SMLSLDX
  [<TestMethod>]
  member _.``F5.1.200 SMLSLDX``() =
    testDisasm "fbd101d2" "smlsldx r0, r1, r1, r2"
    testDisasm "fbd109d1" "smlsldx r0, sb, r1, r1"
    testDisasm "fbd10ad1" "smlsldx r0, sl, r1, r1"
    testDisasm "fbd10bd1" "smlsldx r0, fp, r1, r1"

  /// F5.1.201 SMMLA, SMMLAR
  [<TestMethod>]
  member _.``F5.1.201 SMMLAR``() =
    testDisasm "fb513012" "smmlar r0, r1, r2, r3"
    testDisasm "fb510910" "smmlar sb, r1, r0, r0"
    testDisasm "fb510a10" "smmlar sl, r1, r0, r0"
    testDisasm "fb510b10" "smmlar fp, r1, r0, r0"

  /// F5.1.202 SMMLS, SMMLSR
  [<TestMethod>]
  member _.``F5.1.202 SMMLSR``() =
    testDisasm "fb613012" "smmlsr r0, r1, r2, r3"
    testDisasm "fb610910" "smmlsr sb, r1, r0, r0"
    testDisasm "fb610a10" "smmlsr sl, r1, r0, r0"
    testDisasm "fb610b10" "smmlsr fp, r1, r0, r0"

  /// F5.1.203 SMMUL, SMMULR
  [<TestMethod>]
  member _.``F5.1.203 SMMULR``() =
    testDisasm "fb51f012" "smmulr r0, r1, r2"
    testDisasm "fb51f910" "smmulr sb, r1, r0"
    testDisasm "fb51fa10" "smmulr sl, r1, r0"
    testDisasm "fb51fb10" "smmulr fp, r1, r0"

  /// F5.1.204 SMUAD, SMUADX
  [<TestMethod>]
  member _.``F5.1.204 SMUADX``() =
    testDisasm "fb21f012" "smuadx r0, r1, r2"
    testDisasm "fb21f910" "smuadx sb, r1, r0"
    testDisasm "fb21fa10" "smuadx sl, r1, r0"
    testDisasm "fb21fb10" "smuadx fp, r1, r0"

  /// F5.1.208 SMUSD, SMUSDX
  [<TestMethod>]
  member _.``F5.1.208 SMUSDX``() =
    testDisasm "fb41f012" "smusdx r0, r1, r2"
    testDisasm "fb41f910" "smusdx sb, r1, r0"
    testDisasm "fb41fa10" "smusdx sl, r1, r0"
    testDisasm "fb41fb10" "smusdx fp, r1, r0"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSDB``() =
    testDisasm "e80dc013" "srsdb sp, #0x13"

  /// F5.1.209 SRS, SRSDA, SRSDB, SRSIA, SRSIB
  [<TestMethod>]
  member _.``F5.1.209 SRSIA``() =
    testDisasm "e9adc013" "srsia sp!, #0x13"

  /// F5.1.21 BIC, BICS (immediate)
  [<TestMethod>]
  member _.``F5.1.21 BICS``() =
    testDisasm "f031407f" "bics r0, r1, #0xff000000"
    testDisasm "ea310002" "bics r0, r1, r2"
    testDisasm "ea310034" "bics r0, r1, r4, rrx"
    testDisasm "ea310010" "bics r0, r1, r0, lsr #0x20"

  /// F5.1.213 SSBB
  [<TestMethod>]
  member _.``F5.1.213 SSBB``() =
    testDisasm "f3bf8f40" "ssbb"

  /// F5.1.217 STL
  [<TestMethod>]
  member _.``F5.1.217 STL``() =
    testDisasm "e8c10faf" "stl r0, [r1]"

  /// F5.1.218 STLB
  [<TestMethod>]
  member _.``F5.1.218 STLB``() =
    testDisasm "e8c10f8f" "stlb r0, [r1]"

  /// F5.1.219 STLEX
  [<TestMethod>]
  member _.``F5.1.219 STLEX``() =
    testDisasm "e8c12fe0" "stlex r0, r2, [r1]"

  /// F5.1.220 STLEXB
  [<TestMethod>]
  member _.``F5.1.220 STLEXB``() =
    testDisasm "e8c12fc0" "stlexb r0, r2, [r1]"

  /// F5.1.221 STLEXD
  [<TestMethod>]
  member _.``F5.1.221 STLEXD``() =
    testDisasm "e8c123f0" "stlexd r0, r2, r3, [r1]"
    testDisasm "e8c109f3" "stlexd r3, r0, sb, [r1]"
    testDisasm "e8c10af3" "stlexd r3, r0, sl, [r1]"
    testDisasm "e8c10bf3" "stlexd r3, r0, fp, [r1]"

  /// F5.1.222 STLEXH
  [<TestMethod>]
  member _.``F5.1.222 STLEXH``() =
    testDisasm "e8c12fd0" "stlexh r0, r2, [r1]"

  /// F5.1.223 STLH
  [<TestMethod>]
  member _.``F5.1.223 STLH``() =
    testDisasm "e8c10f9f" "stlh r0, [r1]"

  /// F5.1.224 STM, STMIA, STMEA
  [<TestMethod>]
  member _.``F5.1.224 STMEA``() =
    testDisasm "e881000c" "stm.w r1, {r2, r3}"
    testDisasm "c10cbf00" "stm r1!, {r2, r3}"
    testDisasm "c001bf00" "stm r0!, {r0}"
    testDisasm "c007bf00" "stm r0!, {r0, r1, r2}"

  /// F5.1.224 STM, STMIA, STMEA
  [<TestMethod>]
  member _.``F5.1.224 STMIA``() =
    testDisasm "e881000c" "stm.w r1, {r2, r3}"
    testDisasm "c10cbf00" "stm r1!, {r2, r3}"
    testDisasm "c001bf00" "stm r0!, {r0}"
    testDisasm "c007bf00" "stm r0!, {r0, r1, r2}"

  /// F5.1.227 STMDB, STMFD
  [<TestMethod>]
  member _.``F5.1.227 STMFD``() =
    testDisasm "e901000c" "stmdb r1, {r2, r3}"
    testDisasm "b40cbf00" "push {r2, r3}"
    testDisasm "e921000c" "stmdb r1!, {r2, r3}"
    testDisasm "b401bf00" "push {r0}"

  /// F5.1.38 CPS, CPSID, CPSIE
  [<TestMethod>]
  member _.``F5.1.38 CPSID``() =
    testDisasm "b673bf00" "cpsid if"
    testDisasm "b671bf00" "cpsid f"
    testDisasm "b672bf00" "cpsid i"
    testDisasm "b674bf00" "cpsid a"

  /// F5.1.38 CPS, CPSID, CPSIE
  [<TestMethod>]
  member _.``F5.1.38 CPSIE``() =
    testDisasm "b662bf00" "cpsie i"
    testDisasm "b661bf00" "cpsie f"
    testDisasm "b663bf00" "cpsie if"
    testDisasm "b664bf00" "cpsie a"

  /// F5.1.39 CRC32
  [<TestMethod>]
  member _.``F5.1.39 CRC32``() =
    testDisasm "fac2f083" "crc32b r0, r2, r3"
    testDisasm "fac1f092" "crc32h r0, r1, r2"

  /// F5.1.4 ADD, ADDS (immediate)
  [<TestMethod>]
  member _.``F5.1.4 ADDS``() =
    testDisasm "f111417f" "adds.w r1, r1, #0xff000000"
    testDisasm "1889bf00" "adds r1, r1, r2"
    testDisasm "eb110002" "adds.w r0, r1, r2"
    testDisasm "1c00bf00" "adds r0, r0, #0x0"

  /// F5.1.40 CRC32C
  [<TestMethod>]
  member _.``F5.1.40 CRC32C``() =
    testDisasm "fad2f0a3" "crc32cw r0, r2, r3"

  /// F5.1.43 DCPS1
  [<TestMethod>]
  member _.``F5.1.43 DCPS1``() =
    testDisasm "f78f8001" "dcps1"

  /// F5.1.44 DCPS2
  [<TestMethod>]
  member _.``F5.1.44 DCPS2``() =
    testDisasm "f78f8002" "dcps2"

  /// F5.1.45 DCPS3
  [<TestMethod>]
  member _.``F5.1.45 DCPS3``() =
    testDisasm "f78f8003" "dcps3"

  /// F5.1.48 EOR, EORS (immediate)
  [<TestMethod>]
  member _.``F5.1.48 EORS``() =
    testDisasm "ea910002" "eors.w r0, r1, r2"
    testDisasm "4051bf00" "eors r1, r1, r2"
    testDisasm "ea910034" "eors r0, r1, r4, rrx"
    testDisasm "ea910010" "eors.w r0, r1, r0, lsr #0x20"

  /// F5.1.52 ESB
  [<TestMethod>]
  member _.``F5.1.52 ESB``() =
    testDisasm "f3af8010" "esb"

  /// F5.1.53 HLT
  [<TestMethod>]
  member _.``F5.1.53 HLT``() =
    testDisasm "ba80bf00" "hlt #0x0"

  /// F5.1.57 LDA
  [<TestMethod>]
  member _.``F5.1.57 LDA``() =
    testDisasm "e8d10faf" "lda r0, [r1]"

  /// F5.1.58 LDAB
  [<TestMethod>]
  member _.``F5.1.58 LDAB``() =
    testDisasm "e8d10f8f" "ldab r0, [r1]"

  /// F5.1.59 LDAEX
  [<TestMethod>]
  member _.``F5.1.59 LDAEX``() =
    testDisasm "e8d10fef" "ldaex r0, [r1]"

  /// F5.1.60 LDAEXB
  [<TestMethod>]
  member _.``F5.1.60 LDAEXB``() =
    testDisasm "e8d10fcf" "ldaexb r0, [r1]"

  /// F5.1.61 LDAEXD
  [<TestMethod>]
  member _.``F5.1.61 LDAEXD``() =
    testDisasm "e8d123ff" "ldaexd r2, r3, [r1]"
    testDisasm "e8d109ff" "ldaexd r0, sb, [r1]"
    testDisasm "e8d10aff" "ldaexd r0, sl, [r1]"
    testDisasm "e8d10bff" "ldaexd r0, fp, [r1]"

  /// F5.1.62 LDAEXH
  [<TestMethod>]
  member _.``F5.1.62 LDAEXH``() =
    testDisasm "e8d10fdf" "ldaexh r0, [r1]"

  /// F5.1.63 LDAH
  [<TestMethod>]
  member _.``F5.1.63 LDAH``() =
    testDisasm "e8d10f9f" "ldah r0, [r1]"

  /// F6.1.1 AESD
  [<TestMethod>]
  member _.``F6.1.1 AESD``() =
    testDisasm "ffb00342" "aesd.8 q0, q1"

  /// F6.1.10 SHA1P
  [<TestMethod>]
  member _.``F6.1.10 SHA1P``() =
    testDisasm "ef120c44" "sha1p.32 q0, q1, q2"

  /// F6.1.11 SHA1SU0
  [<TestMethod>]
  member _.``F6.1.11 SHA1SU0``() =
    testDisasm "ef320c44" "sha1su0.32 q0, q1, q2"

  /// F6.1.112 VLDM, VLDMDB, VLDMIA
  [<TestMethod>]
  member _.``F6.1.112 VLDMDB``() =
    testDisasm "ed310a01" "vldmdb r1!, {s0}"
    ("vldmdb r1!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ed310a10"
    ("vldmdb r1!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15, s16, s17}")
    |> testDisasm "ed310a12"
    ("vldmdb r1!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15, s16, s17, s18, s19}")
    |> testDisasm "ed310a14"

  /// F6.1.112 VLDM, VLDMDB, VLDMIA
  [<TestMethod>]
  member _.``F6.1.112 VLDMIA``() =
    testDisasm "ec910b04" "vldmia r1, {d0, d1}"
    testDisasm "ecbd0b04" "vldmia sp!, {d0, d1}"
    testDisasm "ecb10b08" "vldmia r1!, {d0, d1, d2, d3}"
    testDisasm "ec910a01" "vldmia r1, {s0}"

  /// F6.1.117 VMAXNM
  [<TestMethod>]
  member _.``F6.1.117 VMAXNM``() =
    testDisasm "fe800981" "vmaxnm.f16 s0, s1, s2"
    testDisasm "ff120f54" "vmaxnm.f16 q0, q1, q2"
    testDisasm "fe810b00" "vmaxnm.f64 d0, d1, d0"

  /// F6.1.12 SHA1SU1
  [<TestMethod>]
  member _.``F6.1.12 SHA1SU1``() =
    testDisasm "ffba0382" "sha1su1.32 q0, q1"

  /// F6.1.120 VMINNM
  [<TestMethod>]
  member _.``F6.1.120 VMINNM``() =
    testDisasm "fe8009c1" "vminnm.f16 s0, s1, s2"
    testDisasm "ff320f54" "vminnm.f16 q0, q1, q2"
    testDisasm "fe810b4f" "vminnm.f64 d0, d1, d15"

  /// F6.1.13 SHA256H
  [<TestMethod>]
  member _.``F6.1.13 SHA256H``() =
    testDisasm "ff020c44" "sha256h.32 q0, q1, q2"

  /// F6.1.14 SHA256H2
  [<TestMethod>]
  member _.``F6.1.14 SHA256H2``() =
    testDisasm "ff120c44" "sha256h2.32 q0, q1, q2"

  /// F6.1.143 VMOVX
  [<TestMethod>]
  member _.``F6.1.143 VMOVX``() =
    testDisasm "feb00a60" "vmovx.f16 s0, s1"

  /// F6.1.15 SHA256SU0
  [<TestMethod>]
  member _.``F6.1.15 SHA256SU0``() =
    testDisasm "ffba03c2" "sha256su0.32 q0, q1"

  /// F6.1.16 SHA256SU1
  [<TestMethod>]
  member _.``F6.1.16 SHA256SU1``() =
    testDisasm "ff220c44" "sha256su1.32 q0, q1, q2"

  /// F6.1.179 VQRDMLAH
  [<TestMethod>]
  member _.``F6.1.179 VQRDMLAH``() =
    testDisasm "ff110b12" "vqrdmlah.s16 d0, d1, d2"
    testDisasm "ef910e4f" "vqrdmlah.s16 d0, d1, d7[1]"
    testDisasm "ff100b70" "vqrdmlah.s16 q0, q0, q8"
    testDisasm "ff900e4f" "vqrdmlah.s16 q0, q0, d7[1]"

  /// F6.1.180 VQRDMLSH
  [<TestMethod>]
  member _.``F6.1.180 VQRDMLSH``() =
    testDisasm "ff220c54" "vqrdmlsh.s32 q0, q1, q2"
    testDisasm "ef910f4f" "vqrdmlsh.s16 d0, d1, d7[1]"
    testDisasm "ff110c34" "vqrdmlsh.s16 d0, d1, d20"
    testDisasm "ff900f4f" "vqrdmlsh.s16 q0, q0, d7[1]"

  /// F6.1.199 VRINTA (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.199 VRINTA``() =
    testDisasm "feb80960" "vrinta.f16 s0, s1"
    testDisasm "ffb60542" "vrinta.f16 q0, q1"

  /// F6.1.2 AESE
  [<TestMethod>]
  member _.``F6.1.2 AESE``() =
    testDisasm "ffb00302" "aese.8 q0, q1"

  /// F6.1.201 VRINTM (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.201 VRINTM``() =
    testDisasm "febb0960" "vrintm.f16 s0, s1"
    testDisasm "ffb606c2" "vrintm.f16 q0, q1"
    testDisasm "febb0b41" "vrintm.f64 d0, d1"

  /// F6.1.203 VRINTN (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.203 VRINTN``() =
    testDisasm "feb90960" "vrintn.f16 s0, s1"
    testDisasm "ffb60442" "vrintn.f16 q0, q1"
    testDisasm "feb90b4f" "vrintn.f64 d0, d15"

  /// F6.1.205 VRINTP (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.205 VRINTP``() =
    testDisasm "feba0960" "vrintp.f16 s0, s1"
    testDisasm "ffb607c2" "vrintp.f16 q0, q1"
    testDisasm "ffba0781" "vrintp.f32 d0, d1"

  /// F6.1.207 VRINTR
  [<TestMethod>]
  member _.``F6.1.207 VRINTR``() =
    testDisasm "eeb60960" "vrintr.f16 s0, s1"

  /// F6.1.208 VRINTX (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.208 VRINTX``() =
    testDisasm "eeb70960" "vrintx.f16 s0, s1"
    testDisasm "ffb604c2" "vrintx.f16 q0, q1"
    testDisasm "eeb70b41" "vrintx.f64 d0, d1"

  /// F6.1.210 VRINTZ (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.210 VRINTZ``() =
    testDisasm "eeb609e0" "vrintz.f16 s0, s1"
    testDisasm "ffb605c2" "vrintz.f16 q0, q1"

  /// F6.1.221 VSDOT (by element)
  [<TestMethod>]
  member _.``F6.1.221 VSDOT``() =
    testDisasm "fc210d02" "vsdot.s8 d0, d1, d2"
    testDisasm "fe210d00" "vsdot.s8 d0, d1, d0[0]"
    testDisasm "fe200d4f" "vsdot.s8 q0, q0, d15[0]"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELEQ``() =
    testDisasm "fe000981" "vseleq.f16 s0, s1, s2"
    testDisasm "fe010b00" "vseleq.f64 d0, d1, d0"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELGE``() =
    testDisasm "fe200981" "vselge.f16 s0, s1, s2"
    testDisasm "fe210b02" "vselge.f64 d0, d1, d2"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELGT``() =
    testDisasm "fe300981" "vselgt.f16 s0, s1, s2"
    testDisasm "fe310b00" "vselgt.f64 d0, d1, d0"

  /// F6.1.223 VSELEQ, VSELGE, VSELGT, VSELVS
  [<TestMethod>]
  member _.``F6.1.223 VSELVS``() =
    testDisasm "fe100981" "vselvs.f16 s0, s1, s2"
    testDisasm "fe110b02" "vselvs.f64 d0, d1, d2"

  /// F6.1.244 VSTM, VSTMDB, VSTMIA
  [<TestMethod>]
  member _.``F6.1.244 VSTMDB``() =
    testDisasm "ed2d0b04" "vstmdb sp!, {d0, d1}"
    testDisasm "ed2d0a04" "vstmdb sp!, {s0, s1, s2, s3}"
    testDisasm "ed210a01" "vstmdb r1!, {s0}"
    ("vstmdb r1!, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ed210a10"

  /// F6.1.244 VSTM, VSTMDB, VSTMIA
  [<TestMethod>]
  member _.``F6.1.244 VSTMIA``() =
    testDisasm "ec810b04" "vstmia r1, {d0, d1}"
    testDisasm "ec810a04" "vstmia r1, {s0, s1, s2, s3}"
    testDisasm "ec810a01" "vstmia r1, {s0}"
    ("vstmia r1, {s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, "
     + "s13, s14, s15}")
    |> testDisasm "ec810a10"

  /// F6.1.251 VSUDOT (by element)
  [<TestMethod>]
  member _.``F6.1.251 VSUDOT``() =
    testDisasm "fe810d34" "vsudot.u8 d0, d1, d4[1]"
    testDisasm "fe800d5f" "vsudot.u8 q0, q0, d15[0]"

  /// F6.1.256 VUDOT (by element)
  [<TestMethod>]
  member _.``F6.1.256 VUDOT``() =
    testDisasm "fe220d74" "vudot.u8 q0, q1, d4[1]"
    testDisasm "fc210d34" "vudot.u8 d0, d1, d20"
    testDisasm "fc200d70" "vudot.u8 q0, q0, q8"
    testDisasm "fe210d34" "vudot.u8 d0, d1, d4[1]"

  /// F6.1.258 VUMMLA
  [<TestMethod>]
  member _.``F6.1.258 VUMMLA``() =
    testDisasm "fc200c70" "vummla.u8 q0, q0, q8"

  /// F6.1.259 VUSDOT (by element)
  [<TestMethod>]
  member _.``F6.1.259 VUSDOT``() =
    testDisasm "fca10d00" "vusdot.s8 d0, d1, d0"
    testDisasm "fe810d00" "vusdot.s8 d0, d1, d0[0]"
    testDisasm "fe800d4f" "vusdot.s8 q0, q0, d15[0]"

  /// F6.1.3 AESIMC
  [<TestMethod>]
  member _.``F6.1.3 AESIMC``() =
    testDisasm "ffb003c2" "aesimc.8 q0, q1"

  /// F6.1.39 VCADD
  [<TestMethod>]
  member _.``F6.1.39 VCADD``() =
    testDisasm "fc910802" "vcadd.f32 d0, d1, d2, #0x5a"

  /// F6.1.4 AESMC
  [<TestMethod>]
  member _.``F6.1.4 AESMC``() =
    testDisasm "ffb00382" "aesmc.8 q0, q1"

  /// F6.1.52 VCMLA
  [<TestMethod>]
  member _.``F6.1.52 VCMLA``() =
    testDisasm "fc310802" "vcmla.f32 d0, d1, d2, #0x0"
    testDisasm "fe010800" "vcmla.f16 d0, d1, d0[0], #0x0"
    testDisasm "fe00084f" "vcmla.f16 q0, q0, d15[0], #0x0"

  /// F6.1.6 FSTMDBX, FSTMIAX
  [<TestMethod>]
  member _.``F6.1.6 FSTMDBX``() =
    testDisasm "ed210b11" "fstmdbx r1!, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ed290b11" "fstmdbx sb!, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ed2d0b11" "fstmdbx sp!, {d0, d1, d2, d3, d4, d5, d6, d7}"

  /// F6.1.6 FSTMDBX, FSTMIAX
  [<TestMethod>]
  member _.``F6.1.6 FSTMIAX``() =
    testDisasm "ec810b11" "fstmiax r1, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ec890b11" "fstmiax sb, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ec8d0b11" "fstmiax sp, {d0, d1, d2, d3, d4, d5, d6, d7}"
    testDisasm "ec8f0b11" "fstmiax pc, {d0, d1, d2, d3, d4, d5, d6, d7}"

  /// F6.1.65 VCVTA (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.65 VCVTA``() =
    testDisasm "febc09e0" "vcvta.s32.f16 s0, s1"
    testDisasm "ffb70042" "vcvta.s16.f16 q0, q1"

  /// F6.1.69 VCVTM (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.69 VCVTM``() =
    testDisasm "febf09e0" "vcvtm.s32.f16 s0, s1"
    testDisasm "ffb70342" "vcvtm.s16.f16 q0, q1"
    testDisasm "febf0b41" "vcvtm.u32.f64 s0, d1"
    testDisasm "febf094f" "vcvtm.u32.f16 s0, s30"

  /// F6.1.7 SHA1C
  [<TestMethod>]
  member _.``F6.1.7 SHA1C``() =
    testDisasm "ef020c44" "sha1c.32 q0, q1, q2"

  /// F6.1.71 VCVTN (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.71 VCVTN``() =
    testDisasm "febd09e0" "vcvtn.s32.f16 s0, s1"
    testDisasm "ffb70142" "vcvtn.s16.f16 q0, q1"
    testDisasm "ffbb0101" "vcvtn.s32.f32 d0, d1"
    testDisasm "febd094f" "vcvtn.u32.f16 s0, s30"

  /// F6.1.73 VCVTP (Advanced SIMD)
  [<TestMethod>]
  member _.``F6.1.73 VCVTP``() =
    testDisasm "febe09e0" "vcvtp.s32.f16 s0, s1"
    testDisasm "ffb70242" "vcvtp.s16.f16 q0, q1"
    testDisasm "ffbb02c2" "vcvtp.u32.f32 q0, q1"

  /// F6.1.79 VDOT (vector)
  [<TestMethod>]
  member _.``F6.1.79 VDOT``() =
    testDisasm "fc010d00" "vdot.bf16 d0, d1, d0"
    testDisasm "fe010d00" "vdot.bf16 d0, d1, d0[0]"
    testDisasm "fe000d4f" "vdot.bf16 q0, q0, d15[0]"

  /// F6.1.8 SHA1H
  [<TestMethod>]
  member _.``F6.1.8 SHA1H``() =
    testDisasm "ffb902c2" "sha1h.32 q0, q1"

  /// F6.1.87 VFMAB, VFMAT (BFloat16, vector)
  [<TestMethod>]
  member _.``F6.1.87 VFMAB``() =
    testDisasm "fc300834" "vfmab.bf16 q0, q0, q10"
    testDisasm "fe300834" "vfmab.bf16 q0, q0, d4[2]"

  /// F6.1.87 VFMAB, VFMAT (BFloat16, vector)
  [<TestMethod>]
  member _.``F6.1.87 VFMAT``() =
    testDisasm "fc300870" "vfmat.bf16 q0, q0, q8"
    testDisasm "fe30085f" "vfmat.bf16 q0, q0, d7[1]"

  /// F6.1.89 VFMAL (vector)
  [<TestMethod>]
  member _.``F6.1.89 VFMAL``() =
    testDisasm "fc210831" "vfmal.f16 d0, s2, s3"
    testDisasm "fc21085f" "vfmal.f16 q0, d1, d15"
    testDisasm "fe010834" "vfmal.f16 d0, s2, s9[0]"
    testDisasm "fe01085f" "vfmal.f16 q0, d1, d7[1]"

  /// F6.1.9 SHA1M
  [<TestMethod>]
  member _.``F6.1.9 SHA1M``() =
    testDisasm "ef220c44" "sha1m.32 q0, q1, q2"

  /// F6.1.92 VFMSL (vector)
  [<TestMethod>]
  member _.``F6.1.92 VFMSL``() =
    testDisasm "fe12085b" "vfmsl.f16 q0, d2, d3[1]"
    testDisasm "fca10834" "vfmsl.f16 d0, s2, s9"
    testDisasm "fca1085f" "vfmsl.f16 q0, d1, d15"
    testDisasm "fe110834" "vfmsl.f16 d0, s2, s9[0]"

  /// F6.1.98 VINS
  [<TestMethod>]
  member _.``F6.1.98 VINS``() =
    testDisasm "feb00ae0" "vins.f16 s0, s1"

  /// F6.1.99 VJCVT
  [<TestMethod>]
  member _.``F6.1.99 VJCVT``() =
    testDisasm "eeb90bc1" "vjcvt.s32.f64 s0, d1"

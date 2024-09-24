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

module B2R2.FrontEnd.Tests.ARMThumb

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM32
open B2R2.FrontEnd.Tests.ARM32
open type Opcode
open type Register

let private test c op w q (s: SIMDDataTypes option) oprs (b: byte[]) =
  let mode = ArchOperationMode.ThumbMode
  let isa = ISA.Init Architecture.ARMv7 Endian.Big
  let parser = ARM32Parser (isa, mode) :> IInstructionParsable
  let ins = parser.Parse (b, 0UL) :?> ARM32Instruction
  let cond' = ins.Condition
  let opcode' = ins.Opcode
  let wback' = ins.WriteBack
  let q' = ins.Qualifier
  let q = if Option.isSome q then W else N
  let simd' = ins.SIMDTyp
  let oprs' = ins.Operands
  Assert.AreEqual (cond', c)
  Assert.AreEqual (opcode', op)
  Assert.AreEqual (wback', w)
  Assert.AreEqual (q', q)
  Assert.AreEqual (simd', s)
  Assert.AreEqual (oprs', oprs)

let private testNoWbackNoQNoSimd pref (bytes: byte[]) (opcode, operands) =
  test pref opcode false None None operands bytes

let private testNoWbackNoSimd pref q (bytes: byte[]) (opcode, operands) =
  test pref opcode false q None operands bytes

let private testNoQNoSimd pref wback (bytes: byte[]) (opcode, operands) =
  test pref opcode wback None None operands bytes

let private testNoSimd pref wback q (bytes: byte[]) (opcode, operands) =
  test pref opcode wback q None operands bytes

let private operandsFromArray oprList =
  let oprs = Array.ofList oprList
  match oprs.Length with
  | 0 -> NoOperand
  | 1 -> OneOperand oprs[0]
  | 2 -> TwoOperands (oprs[0], oprs[1])
  | 3 -> ThreeOperands (oprs[0], oprs[1], oprs[2])
  | 4 -> FourOperands (oprs[0], oprs[1], oprs[2], oprs[3])
  | _ -> Utils.impossible ()

let private ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

let private ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

/// A4.3 Branch instructions
[<TestClass>]
type BranchClass () =
  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (1)`` () =
    "d826"
    ++ B ** [ O.MemLabel 76L ]
    ||> testNoWbackNoQNoSimd Condition.HI

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (2)`` () =
    "e184"
    ++ B ** [ O.MemLabel 776L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (3)`` () =
    "f6738866"
    ++ B ** [ O.MemLabel 4294652108L ]
    ||> testNoWbackNoSimd Condition.LS (Some W)

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (4)`` () =
    "f0309194"
    ++ B ** [ O.MemLabel 12780328L ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (5)`` () =
    "b91a"
    ++ CBNZ ** [ O.Reg R2; O.MemLabel 6L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (6)`` () =
    "47c8"
    ++ BLX ** [ O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (7)`` () =
    "f436e184"
    ++ BLX ** [ O.MemLabel 4286800648L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (8)`` () =
    "4718"
    ++ BX ** [ O.Reg R3 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (9)`` () =
    "f3c58f00"
    ++ BXJ ** [ O.Reg R5 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Branch Parse test (10)`` () =
    "e8def017"
    ++ TBH ** [ O.MemOffsetReg (LR, None, R7, SRTypeLSL, 1u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

/// A4.4 Data-processing instructions
[<TestClass>]
type DataProcessingClass () =
  /// A4.4.1 Standard data-processing instructions
  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (1)`` () =
    "f1526318"
    ++ ADCS ** [ O.Reg R3; O.Reg R2; O.Imm 159383552L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (2)`` () =
    "44ec"
    ++ ADD ** [ O.Reg IP; O.Reg SP; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (3)`` () =
    "44d5"
    ++ ADD ** [ O.Reg SP; O.Reg SP; O.Reg SL ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (4)`` () =
    "448b"
    ++ ADD ** [ O.Reg FP; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (5)`` () =
    "b066"
    ++ ADD ** [ O.Reg SP; O.Reg SP; O.Imm 408L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (6)`` () =
    "ac28"
    ++ ADD ** [ O.Reg R4; O.Reg SP; O.Imm 160L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (7)`` () =
    "f1040e01"
    ++ ADD ** [ O.Reg LR; O.Reg R4; O.Imm 1L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (8)`` () =
    "180c"
    ++ ADDS ** [ O.Reg R4; O.Reg R1; O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (9)`` () =
    "1c77"
    ++ ADDS ** [ O.Reg R7; O.Reg R6; O.Imm 1L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (10)`` () =
    "f20b0001"
    ++ ADDW ** [ O.Reg R0; O.Reg FP; O.Imm 1L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (11)`` () =
    "f20f0001"
    ++ ADR ** [ O.Reg R0; O.MemLabel 1L ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (12)`` () =
    "a20f"
    ++ ADR ** [ O.Reg R2; O.MemLabel 60L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (13)`` () =
    "403e"
    ++ ANDS ** [ O.Reg R6; O.Reg R6; O.Reg R7 ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (14)`` () =
    "ea3c7605"
    ++ BICS ** [ O.Reg R6; O.Reg IP; O.Reg R5; O.Shift (SRTypeLSL, 28u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (15)`` () =
    "2df3"
    ++ CMP ** [ O.Reg R5; O.Imm 243L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (16)`` () =
    "45c8"
    ++ CMP ** [ O.Reg R8; O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (17)`` () =
    "4544"
    ++ CMP ** [ O.Reg R4; O.Reg R8 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (18)`` () =
    "f04f1708"
    ++ MOV ** [ O.Reg R7; O.Imm 524296L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (19)`` () =
    "000e"
    ++ MOVS ** [ O.Reg R6; O.Reg R1; O.Shift (SRTypeLSL, 0u) ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (20)`` () =
    "f6420b02"
    ++ MOVW ** [ O.Reg FP; O.Imm 10242L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (21)`` () =
    "ea6ff49e"
    ++ MVN ** [ O.Reg R4; O.Reg LR; O.Shift (SRTypeLSR, 30u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (22)`` () =
    "f5d90308"
    ++ RSBS ** [ O.Reg R3; O.Reg SB; O.Imm 8912896L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (23)`` () =
    "424b"
    ++ RSBS ** [ O.Reg R3; O.Reg R1; O.Imm 0L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (24)`` () =
    "f4914f88"
    ++ TEQ ** [ O.Reg R1; O.Imm 17408L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse test (25)`` () =
    "ea125f6b"
    ++ TST ** [ O.Reg R2; O.Reg FP; O.Shift (SRTypeASR, 21u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.2 Shift instructions
  [<TestMethod>]
  member __.``[Thumb] Shift Parse test (1)`` () =
    "fa5afb07"
    ++ ASRS ** [ O.Reg FP; O.Reg SL; O.Reg R7 ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Shift Parse test (2)`` () =
    "0431"
    ++ LSLS ** [ O.Reg R1; O.Reg R6; O.Imm 16L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Shift Parse test (3)`` () =
    "080a"
    ++ LSRS ** [ O.Reg R2; O.Reg R1; O.Imm 32L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Shift Parse test (4)`` () =
    "ea5f0cda"
    ++ LSRS ** [ O.Reg IP; O.Reg SL; O.Imm 3L ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Shift Parse test (5)`` () =
    "ea5f0039"
    ++ RRXS ** [ O.Reg R0; O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.3 Multiply instructions
  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (1)`` () =
    "fb00c901"
    ++ MLA ** [ O.Reg SB; O.Reg R0; O.Reg R1; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (2)`` () =
    "fb03fc0b"
    ++ MUL ** [ O.Reg IP; O.Reg R3; O.Reg FP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (3)`` () =
    "4366"
    ++ MULS ** [ O.Reg R6; O.Reg R4; O.Reg R6 ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (4)`` () =
    "fb2a5c14"
    ++ SMLADX ** [ O.Reg IP; O.Reg SL; O.Reg R4; O.Reg R5 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (5)`` () =
    "fb1e5c21"
    ++ SMLATB ** [ O.Reg IP; O.Reg LR; O.Reg R1; O.Reg R5 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (6)`` () =
    "fbc18aa3"
    ++ SMLALTB ** [ O.Reg R8; O.Reg SL; O.Reg R1; O.Reg R3 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (7)`` () =
    "fbd0ced5"
    ++ SMLSLDX ** [ O.Reg IP; O.Reg LR; O.Reg R0; O.Reg R5 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (8)`` () =
    "fb58f019"
    ++ SMMULR ** [ O.Reg R0; O.Reg R8; O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (9)`` () =
    "fb1bf837"
    ++ SMULTT ** [ O.Reg R8; O.Reg FP; O.Reg R7 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Multiply Parse test (10)`` () =
    "fb83a904"
    ++ SMULL ** [ O.Reg SL; O.Reg SB; O.Reg R3; O.Reg R4 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.4 Saturating instructions
  [<TestMethod>]
  member __.``[Thumb] Saturating Parse test (1)`` () =
    "f3280c05"
    ++ SSAT16 ** [ O.Reg IP; O.Imm 6L; O.Reg R8 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Saturating Parse test (2)`` () =
    "f3a31791"
    ++ USAT ** [ O.Reg R7; O.Imm 17L; O.Reg R3; O.Shift (SRTypeASR, 6u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.5 Saturating addition and subtraction instructions
  [<TestMethod>]
  member __.``[Thumb] Saturating addition and subtraction Parse test (1)`` () =
    "fa86fc9e"
    ++ QDADD ** [ O.Reg IP; O.Reg LR; O.Reg R6 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.6 Packing and unpacking instructions
  [<TestMethod>]
  member __.``[Thumb] Packing and unpacking Parse test (1)`` () =
    "eacc404a"
    ++ PKHBT ** [ O.Reg R0; O.Reg IP; O.Reg SL; O.Shift (SRTypeLSL, 17u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Packing and unpacking Parse test (2)`` () =
    "fa00f4b6"
    ++ SXTAH ** [ O.Reg R4; O.Reg R0; O.Reg R6; O.Shift (SRTypeROR, 24u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Packing and unpacking Parse test (3)`` () =
    "fa2ff996"
    ++ SXTB16 ** [ O.Reg SB; O.Reg R6; O.Shift (SRTypeROR, 8u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Packing and unpacking Parse test (4)`` () =
    "b287"
    ++ UXTH ** [ O.Reg R7; O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Packing and unpacking Parse test (5)`` () =
    "fa1ff28c"
    ++ UXTH ** [ O.Reg R2; O.Reg IP ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  /// A4.4.7 Parallel addition and subtraction instructions
  [<TestMethod>]
  member __.``[Thumb] Parallel addition and subtraction Parse test (1)`` () =
    // Signed
    "fa9cfb00"
    ++ SADD16 ** [ O.Reg FP; O.Reg IP; O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Parallel addition and subtraction Parse test (2)`` () =
    // Saturating
    "fae8fe19"
    ++ QSAX ** [ O.Reg LR; O.Reg R8; O.Reg SB ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Parallel addition and subtraction Parse test (3)`` () =
    // Signed halving
    "fac0fc27"
    ++ SHSUB8 ** [ O.Reg IP; O.Reg R0; O.Reg R7 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Parallel addition and subtraction Parse test (4)`` () =
    // Unsigned
    "faa0f146"
    ++ UASX ** [ O.Reg R1; O.Reg R0; O.Reg R6 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Parallel addition and subtraction Parse test (5)`` () =
    // Unsigned saturating
    "fa8ef953"
    ++ UQADD8 ** [ O.Reg SB; O.Reg LR; O.Reg R3 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Parallel addition and subtraction Parse test (6)`` () =
    // Unsigned halving
    "faa0f86a"
    ++ UHASX ** [ O.Reg R8; O.Reg R0; O.Reg SL ]
    ||> testNoWbackNoQNoSimd Condition.AL

  //// A4.4.8 Divide instructions
  [<TestMethod>]
  member __.``[Thumb] Divide Parse test (1)`` () =
    "fbb0fcfe"
    ++ UDIV ** [ O.Reg IP; O.Reg R0; O.Reg LR ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.9 Miscellaneous data-processing instructions
  [<TestMethod>]
  member __.``[Thumb] Miscellaneous data-processing Parse test (1)`` () =
    "f36f1c12"
    ++ BFC ** [ O.Reg IP; O.Imm 4L; O.Imm 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous data-processing Parse test (2)`` () =
    "f3612ad1"
    ++ BFI ** [ O.Reg SL; O.Reg R1; O.Imm 11L; O.Imm 7L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous data-processing Parse test (3)`` () =
    "fa94fca4"
    ++ RBIT ** [ O.Reg IP; O.Reg R4 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous data-processing Parse test (4)`` () =
    "f34e0918"
    ++ SBFX ** [ O.Reg SB; O.Reg LR; O.Imm 0L; O.Imm 25L ]
    ||> testNoWbackNoQNoSimd Condition.AL

/// A4.5 Status register access instructions
[<TestClass>]
type StatusOprRegAccessClass () =
  [<TestMethod>]
  member __.``[Thumb] Status register access Parse test (1)`` () =
    "f3ef8500"
    ++ MRS ** [ O.Reg R5; O.Reg APSR ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Status register access Parse test (2)`` () =
    "f3ff8c00"
    ++ MRS ** [ O.Reg IP; O.Reg SPSR ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Status register access Parse test (3)`` () =
    "f38b8400"
    ++ MSR ** [ O.SpecReg (CPSR, PSRs); O.Reg FP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Status register access Parse test (4)`` () =
    "f38c8500"
    ++ MSR ** [ O.SpecReg (CPSR, PSRsc); O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Status register access Parse test (5)`` () =
    "f3af8764"
    ++ CPSID ** [ O.Iflag IF; O.Imm 4L ]
    ||> testNoWbackNoQNoSimd Condition.UN (* W *)

  [<TestMethod>]
  member __.``[Thumb] Status register access Parse test (6)`` () =
    "b665"
    ++ CPSIE ** [ O.Iflag AF ]
    ||> testNoWbackNoQNoSimd Condition.UN

  /// A4.5.1 Banked register access instructions
  [<TestMethod>]
  member __.``[Thumb] Banked register access Parse test (1)`` () =
    "f3e68020"
    ++ MRS ** [ O.Reg R0; O.Reg LRusr ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Banked register access Parse test (2)`` () =
    "f3918430"
    ++ MSR ** [ O.Reg SPSRabt; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

/// A4.6 Load/store instructions
[<TestClass>]
type LoadStoreClass () =
  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (1)`` () =
    "990f"
    ++ LDR ** [ O.Reg R1; O.MemOffsetImm (SP, Some Plus, Some 60L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (2)`` () =
    "4c37"
    ++ LDR ** [ O.Reg R4; O.MemLabel 220L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (3)`` () =
    "f8df0087"
    ++ LDR ** [ O.Reg R0; O.MemLabel 135L ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (4)`` () =
    "f859c038"
    ++ LDR ** [ O.Reg IP; O.MemOffsetReg (SB, Some Plus, R8, SRTypeLSL, 3u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (5)`` () =
    "f8512f33"
    ++ LDR ** [ O.Reg R2; O.MemPreIdxImm (R1, Some Plus, Some 51L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (6)`` () =
    "f8dec080"
    ++ LDR ** [ O.Reg IP; O.MemOffsetImm (LR, Some Plus, Some 128L) ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (7)`` () =
    "f839bc82"
    ++ LDRH ** [ O.Reg FP; O.MemOffsetImm (SB, Some Minus, Some 130L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (8)`` () =
    "f93f624b"
    ++ LDRSH ** [ O.Reg R6; O.MemLabel -587L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (9)`` () =
    "f9b3b00b"
    ++ LDRSH ** [ O.Reg FP; O.MemOffsetImm (R3, Some Plus, Some 11L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (10)`` () =
    "79a6"
    ++ LDRB ** [ O.Reg R6; O.MemOffsetImm (R4, Some Plus, Some 6L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (11)`` () =
    "f812a036"
    ++ LDRB ** [ O.Reg SL; O.MemOffsetReg (R2, Some Plus, R6, SRTypeLSL, 3u) ]
    ||> testNoQNoSimd Condition.AL false (* W *)

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (12)`` () =
    "f814890c"
    ++ LDRB ** [ O.Reg R8; O.MemPostIdxImm (R4, Some Minus, Some 12L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (13)`` () =
    "f89f30f0"
    ++ LDRB ** [ O.Reg R3; O.MemLabel 240L ]
    ||> testNoWbackNoQNoSimd Condition.AL (* W *)

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (14)`` () =
    "f9981c32"
    ++ LDRSB ** [ O.Reg R1; O.MemOffsetImm (R8, Some Plus, Some 3122L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (15)`` () =
    "f91e9020"
    ++ LDRSB ** [ O.Reg SB; O.MemOffsetReg (LR, Some Plus, R0, SRTypeLSL, 2u) ]
    ||> testNoQNoSimd Condition.AL false (* W *)

  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse test (16)`` () =
    "e95fc642"
    ++ LDRD ** [ O.Reg IP; O.Reg R6; O.MemLabel -264L ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store) Parse test (1)`` () =
    "6637"
    ++ STR ** [ O.Reg R7; O.MemOffsetImm (R6, Some Plus, Some 96L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store) Parse test (2)`` () =
    "8457"
    ++ STRH ** [ O.Reg R7; O.MemOffsetImm (R2, Some Plus, Some 34L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store) Parse test (3)`` () =
    "549c"
    ++ STRB ** [ O.Reg R4; O.MemOffsetReg (R3, Some Plus, R2) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store) Parse test (4)`` () =
    "f809e982"
    ++ STRB ** [ O.Reg LR; O.MemPostIdxImm (SB, Some Minus, Some 130L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store) Parse test (5)`` () =
    "f886c80c"
    ++ STRB ** [ O.Reg IP; O.MemOffsetImm (R6, Some Plus, Some 2060L) ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store) Parse test (6)`` () =
    "f80a002c"
    ++ STRB ** [ O.Reg R0; O.MemOffsetReg (SL, Some Plus, IP, SRTypeLSL, 2u) ]
    ||> testNoQNoSimd Condition.AL false (* W *)

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store) Parse test (7)`` () =
    "e96a393c"
    ++ STRD ** [ O.Reg R3; O.Reg SB;
                 O.MemPreIdxImm (SL, Some Minus, Some 240L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member __.``[Thumb] Load/store (Load unprivileged) Parse test (1)`` () =
    "f8501e04"
    ++ LDRT ** [ O.Reg R1; O.MemOffsetImm (R0, None, Some 4L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Load unprivileged) Parse test (2)`` () =
    "f834ce01"
    ++ LDRHT ** [ O.Reg IP; O.MemOffsetImm (R4, None, Some 1L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Load unprivileged) Parse test (3)`` () =
    "f91c9e09"
    ++ LDRSBT ** [ O.Reg SB; O.MemOffsetImm (IP, None, Some 9L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store unprivileged) Parse test (1)`` () =
    "f827be53"
    ++ STRHT ** [ O.Reg FP; O.MemOffsetImm (R7, None, Some 83L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Load-Exclusive) Parse test (1)`` () =
    "e859bf0e"
    ++ LDREX ** [ O.Reg FP; O.MemOffsetImm (SB, None, Some 56L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Load-Exclusive) Parse test (2)`` () =
    "e8d90f4f"
    ++ LDREXB ** [ O.Reg R0; O.MemOffsetImm (SB, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Load-Exclusive) Parse test (3)`` () =
    "e8deac7f"
    ++ LDREXD ** [ O.Reg SL; O.Reg IP; O.MemOffsetImm (LR, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store-Exclusive) Parse test (1)`` () =
    "e841ea0c"
    ++ STREX ** [ O.Reg SL; O.Reg LR; O.MemOffsetImm (R1, None, Some 48L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store-Exclusive) Parse test (2)`` () =
    "e8c8af56"
    ++ STREXH ** [ O.Reg R6; O.Reg SL; O.MemOffsetImm (R8, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store-Exclusive) Parse test (3)`` () =
    "e8c0cb74"
    ++ STREXD ** [ O.Reg R4; O.Reg IP; O.Reg FP;
                   O.MemOffsetImm (R0, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

/// A4.7 Load/store multiple instructions
[<TestClass>]
type LoadStoreMultipleClass () =
  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (1)`` () =
    "cbc1"
    ++ LDM ** [ O.Reg R3; O.RegList [ R0; R6; R7 ] ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (2)`` () =
    "e8985184"
    ++ LDM ** [ O.Reg R8; O.RegList [ R2; R7; R8; IP; LR ] ]
    ||> testNoSimd Condition.AL false (Some W)

  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (3)`` () =
    "e8bd8611"
    ++ POP ** [ O.RegList [ R0; R4; SB; SL; PC ] ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (4)`` () =
    "f85d3b04"
    ++ POP ** [ O.RegList [ R3 ] ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (5)`` () =
    "b533"
    ++ PUSH ** [ O.RegList [ R0; R1; R4; R5; LR ] ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (6)`` () =
    "e92d0184"
    ++ PUSH ** [ O.RegList [ R2; R7; R8 ] ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (7)`` () =
    "f84d1d04"
    ++ PUSH ** [ O.RegList [ R1 ] ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (8)`` () =
    "c5a3"
    ++ STM ** [ O.Reg R5; O.RegList [ R0; R1; R5; R7 ] ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse test (9)`` () =
    "e8825990"
    ++ STM ** [ O.Reg R2; O.RegList [ R4; R7; R8; FP; IP; LR ] ]
    ||> testNoSimd Condition.AL false (Some W)

/// A4.8 Miscellaneous instructions
[<TestClass>]
type MiscellaneousClass () =
  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (1)`` () =
    "f3af80fb"
    ++ DBG ** [ O.Imm 11L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (2)`` () =
    "f3bf8f57"
    ++ DMB ** [ O.Option BarrierOption.NSH ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (3)`` () =
    "bf6c"
    ++ ITE ** [ O.Cond Condition.VS ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (4)`` () =
    "f3af8000"
    ++ NOP ** [ ]
    ||> testNoWbackNoSimd Condition.AL (Some W)

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (5)`` () =
    "f81cf01b"
    ++ PLD ** [ O.MemOffsetReg (IP, None, FP, SRTypeLSL, 1u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (6)`` () =
    "f810fc20"
    ++ PLD ** [ O.MemOffsetImm (R0, Some Minus, Some 32L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (7)`` () =
    "f81ff08e"
    ++ PLD ** [ O.MemLabel -142L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (8)`` () =
    "f89ff00f"
    ++ PLD ** [ O.MemLabel 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (9)`` () =
    "f837f01b"
    ++ PLDW ** [ O.MemOffsetReg (R7, None, FP, SRTypeLSL, 1u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (10)`` () =
    "f832fc31"
    ++ PLDW ** [ O.MemOffsetImm (R2, Some Minus, Some 49L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (11)`` () =
    "f8bcf0c3"
    ++ PLDW ** [ O.MemOffsetImm (IP, Some Plus, Some 195L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (12)`` () =
    "f99af003"
    ++ PLI ** [ O.MemOffsetImm (SL, Some Plus, Some 3L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse test (13)`` () =
    "b658"
    ++ SETEND ** [ O.Endian Endian.Big ]
    ||> testNoWbackNoQNoSimd Condition.UN

/// A4.9 Exception-generating and exception-handling instructions
[<TestClass>]
type ExcepGenAndExcepHandClass () =
  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse test (1)`` () =
    "be30"
    ++ BKPT ** [ O.Imm 48L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse test (2)`` () =
    "f7f88000"
    ++ SMC ** [ O.Imm 8L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse test (3)`` () =
    "e9bac000"
    ++ RFEIA ** [ O.Reg SL ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse test (4)`` () =
    "f3de8f08"
    ++ SUBS ** [ O.Reg PC; O.Reg LR; O.Imm 8L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse test (5)`` () =
    "f7e1800c"
    ++ HVC ** [ O.Imm 4108L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse test (6)`` () =
    "f3de8f00"
    ++ ERET ** [ ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse test (7)`` () =
    "f3de8f00"
    ++ ERET ** [ ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse test (8)`` () =
    "e82dc013"
    ++ SRSDB ** [ O.Reg SP; O.Imm 19L ]
    ||> testNoQNoSimd Condition.AL true

/// A5.4 Media instructions
[<TestClass>]
type MediaClass () =
  [<TestMethod>]
  member __.``[Thumb] Media Parse test (1)`` () =
    "de0f"
    ++ UDF ** [ O.Imm 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

/// A6.3.4 Branches and miscellaneous control
[<TestClass>]
type MiscellaneousControlClass () =
  [<TestMethod>]
  member __.``[Thumb] Miscellaneous control Parse test (1)`` () =
    "f3bf8f2f"
    ++ CLREX ** [ ]
    ||> testNoWbackNoQNoSimd Condition.AL

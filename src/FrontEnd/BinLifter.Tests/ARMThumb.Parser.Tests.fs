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

let private test arch e c op w q (s: SIMDDataTypes option) oprs (b: byte[]) =
  let mode = ArchOperationMode.ThumbMode
  let parser =
    ARM32Parser (ISA.Init arch e, mode, None) :> IInstructionParsable
  let ins = parser.Parse (b, 0UL) :?> ARM32Instruction
  let cond' = ins.Condition
  let opcode' = ins.Opcode
  let wback' = ins.WriteBack
  let q' = ins.Qualifier
  let simd' = ins.SIMDTyp
  let oprs' = ins.Operands

  let w =
    match w with
    | Some true -> true
    | _ -> false // XXX

  Assert.AreEqual (cond', c)
  Assert.AreEqual (opcode', op)
  Assert.AreEqual (wback', w)
  Assert.AreEqual (q', q)
  Assert.AreEqual (simd', s)
  Assert.AreEqual (oprs', oprs)

let private testThumb = test Architecture.ARMv7 Endian.Big

/// A4.3 Branch instructions
[<TestClass>]
type BranchClass () =
  [<TestMethod>]
  member __.``[Thumb] Branch Parse Test`` () =
    testThumb
      (Condition.HI)
      Op.B
      None
      N
      None
      (OneOperand (OprMemory (LiteralMode 76L)))
      [| 0xd8uy; 0x26uy |]

    testThumb
      (Condition.AL)
      Op.B
      None
      N
      None
      (OneOperand (OprMemory (LiteralMode 776L)))
      [| 0xe1uy; 0x84uy |]

    testThumb
      (Condition.LS)
      Op.B
      None
      W
      None
      (OneOperand (OprMemory (LiteralMode 4294652108L)))
      [| 0xf6uy; 0x73uy; 0x88uy; 0x66uy |]

    testThumb
      (Condition.AL)
      Op.B
      None
      W
      None
      (OneOperand (OprMemory (LiteralMode 12780328L)))
      [| 0xf0uy; 0x30uy; 0x91uy; 0x94uy |]

    testThumb
      Condition.UN
      Op.CBNZ
      None
      N
      None
      (TwoOperands (OprReg R.R2, OprMemory (LiteralMode 6L)))
      [| 0xb9uy; 0x1auy |]

    testThumb
      (Condition.AL)
      Op.BLX
      None
      N
      None
      (OneOperand (OprReg R.SB))
      [| 0x47uy; 0xc8uy |]

    testThumb
      (Condition.AL)
      Op.BLX
      None
      N
      None
      (OneOperand (OprMemory (LiteralMode 4286800648L)))
      [| 0xf4uy; 0x36uy; 0xe1uy; 0x84uy |]

    testThumb
      (Condition.AL)
      Op.BX
      None
      N
      None
      (OneOperand (OprReg R.R3))
      [| 0x47uy; 0x18uy |]

    testThumb
      (Condition.AL)
      Op.BXJ
      None
      N
      None
      (OneOperand (OprReg R.R5))
      [| 0xf3uy; 0xc5uy; 0x8fuy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.TBH
      None
      N
      None
      (OneOperand (
        OprMemory (
          OffsetMode (RegOffset (R.LR, None, R.R7, Some (SRTypeLSL, Imm 1u)))
        )
      ))
      [| 0xe8uy; 0xdeuy; 0xf0uy; 0x17uy |]

/// A4.4 Data-processing instructions
[<TestClass>]
type DataProcessingClass () =
  /// A4.4.1 Standard data-processing instructions
  [<TestMethod>]
  member __.``[Thumb] Standard data-processing Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.ADCS
      None
      N
      None
      (ThreeOperands (OprReg R.R3, OprReg R.R2, OprImm 159383552L))
      [| 0xf1uy; 0x52uy; 0x63uy; 0x18uy |]

    testThumb
      (Condition.AL)
      Op.ADD
      None
      N
      None
      (ThreeOperands (OprReg R.IP, OprReg R.SP, OprReg R.IP))
      [| 0x44uy; 0xecuy |]

    testThumb
      (Condition.AL)
      Op.ADD
      None
      N
      None
      (ThreeOperands (OprReg R.SP, OprReg R.SP, OprReg R.SL))
      [| 0x44uy; 0xd5uy |]

    testThumb
      (Condition.AL)
      Op.ADD
      None
      N
      None
      (TwoOperands (OprReg R.FP, OprReg R.R1))
      [| 0x44uy; 0x8buy |]

    testThumb
      (Condition.AL)
      Op.ADD
      None
      N
      None
      (ThreeOperands (OprReg R.SP, OprReg R.SP, OprImm 408L))
      [| 0xb0uy; 0x66uy |]

    testThumb
      (Condition.AL)
      Op.ADD
      None
      N
      None
      (ThreeOperands (OprReg R.R4, OprReg R.SP, OprImm 160L))
      [| 0xacuy; 0x28uy |]

    testThumb
      (Condition.AL)
      Op.ADD
      None
      N
      None
      (ThreeOperands (OprReg R.LR, OprReg R.R4, OprImm 1L))
      [| 0xf1uy; 0x04uy; 0x0euy; 0x01uy |]

    testThumb
      Condition.UN
      Op.ADDS
      None
      N
      None
      (ThreeOperands (OprReg R.R4, OprReg R.R1, OprReg R.R0))
      [| 0x18uy; 0x0cuy |]

    testThumb
      Condition.UN
      Op.ADDS
      None
      N
      None
      (ThreeOperands (OprReg R.R7, OprReg R.R6, OprImm 1L))
      [| 0x1cuy; 0x77uy |]

    testThumb
      (Condition.AL)
      Op.ADDW
      None
      N
      None
      (ThreeOperands (OprReg R.R0, OprReg R.FP, OprImm 1L))
      [| 0xf2uy; 0x0buy; 0x00uy; 0x01uy |]

    testThumb
      (Condition.AL)
      Op.ADR
      None
      W
      None
      (TwoOperands (OprReg R.R0, OprMemory (LiteralMode 1L)))
      [| 0xf2uy; 0x0fuy; 0x00uy; 0x01uy |]

    testThumb
      (Condition.AL)
      Op.ADR
      None
      N
      None
      (TwoOperands (OprReg R.R2, OprMemory (LiteralMode 60L)))
      [| 0xa2uy; 0x0fuy |]

    testThumb
      Condition.UN
      Op.ANDS
      None
      N
      None
      (ThreeOperands (OprReg R.R6, OprReg R.R6, OprReg R.R7))
      [| 0x40uy; 0x3euy |]

    testThumb
      (Condition.AL)
      Op.BICS
      None
      N
      None
      (FourOperands (
        OprReg R.R6,
        OprReg R.IP,
        OprReg R.R5,
        OprShift (SRTypeLSL, Imm 28u)
      ))
      [| 0xeauy; 0x3cuy; 0x76uy; 0x05uy |]

    testThumb
      (Condition.AL)
      Op.CMP
      None
      N
      None
      (TwoOperands (OprReg R.R5, OprImm 243L))
      [| 0x2duy; 0xf3uy |]

    testThumb
      (Condition.AL)
      Op.CMP
      None
      N
      None
      (TwoOperands (OprReg R.R8, OprReg R.SB))
      [| 0x45uy; 0xc8uy |]

    testThumb
      (Condition.AL)
      Op.CMP
      None
      N
      None
      (TwoOperands (OprReg R.R4, OprReg R.R8))
      [| 0x45uy; 0x44uy |]

    testThumb
      (Condition.AL)
      Op.MOV
      None
      N
      None
      (TwoOperands (OprReg R.R7, OprImm 524296L))
      [| 0xf0uy; 0x4fuy; 0x17uy; 0x08uy |]

    testThumb
      Condition.UN
      Op.MOVS
      None
      N
      None
      (ThreeOperands (OprReg R.R6, OprReg R.R1, OprShift (SRTypeLSL, Imm 0u)))
      [| 0x00uy; 0x0euy |]

    testThumb
      (Condition.AL)
      Op.MOVW
      None
      N
      None
      (TwoOperands (OprReg R.FP, OprImm 10242L))
      [| 0xf6uy; 0x42uy; 0x0buy; 0x02uy |]

    testThumb
      (Condition.AL)
      Op.MVN
      None
      N
      None
      (ThreeOperands (
        OprReg R.R4,
        OprReg R.LR,
        OprShift (SRTypeLSR, Imm 30u)
      ))
      [| 0xeauy; 0x6fuy; 0xf4uy; 0x9euy |]

    testThumb
      (Condition.AL)
      Op.RSBS
      None
      N
      None
      (ThreeOperands (OprReg R.R3, OprReg R.SB, OprImm 8912896L))
      [| 0xf5uy; 0xd9uy; 0x03uy; 0x08uy |]

    testThumb
      Condition.UN
      Op.RSBS
      None
      N
      None
      (ThreeOperands (OprReg R.R3, OprReg R.R1, OprImm 0L))
      [| 0x42uy; 0x4buy |]

    testThumb
      (Condition.AL)
      Op.TEQ
      None
      N
      None
      (TwoOperands (OprReg R.R1, OprImm 17408L))
      [| 0xf4uy; 0x91uy; 0x4fuy; 0x88uy |]

    testThumb
      (Condition.AL)
      Op.TST
      None
      N
      None
      (ThreeOperands (
        OprReg R.R2,
        OprReg R.FP,
        OprShift (SRTypeASR, Imm 21u)
      ))
      [| 0xeauy; 0x12uy; 0x5fuy; 0x6buy |]

  /// A4.4.2 Shift instructions
  [<TestMethod>]
  member __.``[Thumb] Shift Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.ASRS
      None
      W
      None
      (ThreeOperands (OprReg R.FP, OprReg R.SL, OprReg R.R7))
      [| 0xfauy; 0x5auy; 0xfbuy; 0x07uy |]

    testThumb
      (Condition.AL)
      Op.LSLS
      None
      N
      None
      (ThreeOperands (OprReg R.R1, OprReg R.R6, OprImm 16L))
      [| 0x04uy; 0x31uy |]

    testThumb
      (Condition.AL)
      Op.LSRS
      None
      N
      None
      (ThreeOperands (OprReg R.R2, OprReg R.R1, OprImm 32L))
      [| 0x08uy; 0x0auy |]

    testThumb
      (Condition.AL)
      Op.LSRS
      None
      W
      None
      (ThreeOperands (OprReg R.IP, OprReg R.SL, OprImm 3L))
      [| 0xeauy; 0x5fuy; 0x0cuy; 0xdauy |]

    testThumb
      (Condition.AL)
      Op.RRXS
      None
      N
      None
      (TwoOperands (OprReg R.R0, OprReg R.SB))
      [| 0xeauy; 0x5fuy; 0x00uy; 0x39uy |]

  /// A4.4.3 Multiply instructions
  member __.``[Thumb] Multiply Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.MLA
      None
      N
      None
      (FourOperands (OprReg R.SB, OprReg R.R0, OprReg R.R1, OprReg R.IP))
      [| 0xfbuy; 0x00uy; 0xc9uy; 0x01uy |]

    testThumb
      (Condition.AL)
      Op.MUL
      None
      N
      None
      (ThreeOperands (OprReg R.IP, OprReg R.R3, OprReg R.FP))
      [| 0xfbuy; 0x03uy; 0xfcuy; 0x0buy |]

    testThumb
      Condition.UN
      Op.MULS
      None
      N
      None
      (ThreeOperands (OprReg R.R6, OprReg R.R4, OprReg R.R6))
      [| 0x43uy; 0x66uy |]

    testThumb
      (Condition.AL)
      Op.SMLADX
      None
      N
      None
      (FourOperands (OprReg R.IP, OprReg R.SL, OprReg R.R4, OprReg R.R5))
      [| 0xfbuy; 0x2auy; 0x5cuy; 0x14uy |]

    testThumb
      (Condition.AL)
      Op.SMLATB
      None
      N
      None
      (FourOperands (OprReg R.IP, OprReg R.LR, OprReg R.R1, OprReg R.R5))
      [| 0xfbuy; 0x1euy; 0x5cuy; 0x21uy |]

    testThumb
      (Condition.AL)
      Op.SMLALTB
      None
      N
      None
      (FourOperands (OprReg R.R8, OprReg R.SL, OprReg R.R1, OprReg R.R3))
      [| 0xfbuy; 0xc1uy; 0x8auy; 0xa3uy |]

    testThumb
      (Condition.AL)
      Op.SMLSLDX
      None
      N
      None
      (FourOperands (OprReg R.IP, OprReg R.LR, OprReg R.R0, OprReg R.R5))
      [| 0xfbuy; 0xd0uy; 0xceuy; 0xd5uy |]

    testThumb
      (Condition.AL)
      Op.SMMULR
      None
      N
      None
      (ThreeOperands (OprReg R.R0, OprReg R.R8, OprReg R.SB))
      [| 0xfbuy; 0x58uy; 0xf0uy; 0x19uy |]

    testThumb
      (Condition.AL)
      Op.SMULTT
      None
      N
      None
      (ThreeOperands (OprReg R.R8, OprReg R.FP, OprReg R.R7))
      [| 0xfbuy; 0x1buy; 0xf8uy; 0x37uy |]

    testThumb
      (Condition.AL)
      Op.SMULL
      None
      N
      None
      (FourOperands (OprReg R.SL, OprReg R.SB, OprReg R.R3, OprReg R.R4))
      [| 0xfbuy; 0x83uy; 0xa9uy; 0x04uy |]

  /// A4.4.4 Saturating instructions
  [<TestMethod>]
  member __.``[Thumb] Saturating Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.SSAT16
      None
      N
      None
      (ThreeOperands (OprReg R.IP, OprImm 6L, OprReg R.R8))
      [| 0xf3uy; 0x28uy; 0x0cuy; 0x05uy |]

    testThumb
      (Condition.AL)
      Op.USAT
      None
      N
      None
      (FourOperands (
        OprReg R.R7,
        OprImm 17L,
        OprReg R.R3,
        OprShift (SRTypeASR, Imm 6u)
      ))
      [| 0xf3uy; 0xa3uy; 0x17uy; 0x91uy |]

  /// A4.4.5 Saturating addition and subtraction instructions
  [<TestMethod>]
  member __.``[Thumb] Saturating addition and subtraction Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.QDADD
      None
      N
      None
      (ThreeOperands (OprReg R.IP, OprReg R.LR, OprReg R.R6))
      [| 0xfauy; 0x86uy; 0xfcuy; 0x9euy |]

  /// A4.4.6 Packing and unpacking instructions
  [<TestMethod>]
  member __.``[Thumb] Packing and unpacking Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.PKHBT
      None
      N
      None
      (FourOperands (
        OprReg R.R0,
        OprReg R.IP,
        OprReg R.SL,
        OprShift (SRTypeLSL, Imm 17u)
      ))
      [| 0xeauy; 0xccuy; 0x40uy; 0x4auy |]

    testThumb
      (Condition.AL)
      Op.SXTAH
      None
      N
      None
      (FourOperands (
        OprReg R.R4,
        OprReg R.R0,
        OprReg R.R6,
        OprShift (SRTypeROR, Imm 24u)
      ))
      [| 0xfauy; 0x00uy; 0xf4uy; 0xb6uy |]

    testThumb
      (Condition.AL)
      Op.SXTB16
      None
      N
      None
      (ThreeOperands (OprReg R.SB, OprReg R.R6, OprShift (SRTypeROR, Imm 8u)))
      [| 0xfauy; 0x2fuy; 0xf9uy; 0x96uy |]

    testThumb
      (Condition.AL)
      Op.UXTH
      None
      N
      None
      (TwoOperands (OprReg R.R7, OprReg R.R0))
      [| 0xb2uy; 0x87uy |]

    testThumb
      (Condition.AL)
      Op.UXTH
      None
      W
      None
      (TwoOperands (OprReg R.R2, OprReg R.IP))
      [| 0xfauy; 0x1fuy; 0xf2uy; 0x8cuy |]

  /// A4.4.7 Parallel addition and subtraction instructions
  [<TestMethod>]
  member __.``[Thumb] Parallel addition and subtraction Parse Test`` () =
    // Signed
    testThumb
      (Condition.AL)
      Op.SADD16
      None
      N
      None
      (ThreeOperands (OprReg R.FP, OprReg R.IP, OprReg R.R0))
      [| 0xfauy; 0x9cuy; 0xfbuy; 0x00uy |]

    // Saturating
    testThumb
      (Condition.AL)
      Op.QSAX
      None
      N
      None
      (ThreeOperands (OprReg R.LR, OprReg R.R8, OprReg R.SB))
      [| 0xfauy; 0xe8uy; 0xfeuy; 0x19uy |]

    // Signed halving
    testThumb
      (Condition.AL)
      Op.SHSUB8
      None
      N
      None
      (ThreeOperands (OprReg R.IP, OprReg R.R0, OprReg R.R7))
      [| 0xfauy; 0xc0uy; 0xfcuy; 0x27uy |]

    // Unsigned
    testThumb
      (Condition.AL)
      Op.UASX
      None
      N
      None
      (ThreeOperands (OprReg R.R1, OprReg R.R0, OprReg R.R6))
      [| 0xfauy; 0xa0uy; 0xf1uy; 0x46uy |]

    // Unsigned saturating
    testThumb
      (Condition.AL)
      Op.UQADD8
      None
      N
      None
      (ThreeOperands (OprReg R.SB, OprReg R.LR, OprReg R.R3))
      [| 0xfauy; 0x8euy; 0xf9uy; 0x53uy |]

    // Unsigned halving
    testThumb
      (Condition.AL)
      Op.UHASX
      None
      N
      None
      (ThreeOperands (OprReg R.R8, OprReg R.R0, OprReg R.SL))
      [| 0xfauy; 0xa0uy; 0xf8uy; 0x6auy |]

  //// A4.4.8 Divide instructions
  [<TestMethod>]
  member __.``[Thumb] Divide Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.UDIV
      None
      N
      None
      (ThreeOperands (OprReg R.IP, OprReg R.R0, OprReg R.LR))
      [| 0xfbuy; 0xb0uy; 0xfcuy; 0xfeuy |]

  /// A4.4.9 Miscellaneous data-processing instructions
  [<TestMethod>]
  member __.``[Thumb] Miscellaneous data-processing Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.BFC
      None
      N
      None
      (ThreeOperands (OprReg R.IP, OprImm 4L, OprImm 15L))
      [| 0xf3uy; 0x6fuy; 0x1cuy; 0x12uy |]

    testThumb
      (Condition.AL)
      Op.BFI
      None
      N
      None
      (FourOperands (OprReg R.SL, OprReg R.R1, OprImm 11L, OprImm 7L))
      [| 0xf3uy; 0x61uy; 0x2auy; 0xd1uy |]

    testThumb
      (Condition.AL)
      Op.RBIT
      None
      N
      None
      (TwoOperands (OprReg R.IP, OprReg R.R4))
      [| 0xfauy; 0x94uy; 0xfcuy; 0xa4uy |]

    testThumb
      (Condition.AL)
      Op.SBFX
      None
      N
      None
      (FourOperands (OprReg R.SB, OprReg R.LR, OprImm 0L, OprImm 25L))
      [| 0xf3uy; 0x4euy; 0x09uy; 0x18uy |]

/// A4.5 Status register access instructions
[<TestClass>]
type StatusOprRegAccessClass () =
  [<TestMethod>]
  member __.``[Thumb] Status register access Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.MRS
      None
      N
      None
      (TwoOperands (OprReg R.R5, OprReg R.APSR))
      [| 0xf3uy; 0xefuy; 0x85uy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.MRS
      None
      N
      None
      (TwoOperands (OprReg R.IP, OprReg R.SPSR))
      [| 0xf3uy; 0xffuy; 0x8cuy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.MSR
      None
      N
      None
      (TwoOperands (OprSpecReg (R.CPSR, Some PSRs), OprReg R.FP))
      [| 0xf3uy; 0x8buy; 0x84uy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.MSR
      None
      N
      None
      (TwoOperands (OprSpecReg (R.CPSR, Some PSRsc), OprReg R.IP))
      [| 0xf3uy; 0x8cuy; 0x85uy; 0x00uy |]

    testThumb
      Condition.UN
      Op.CPSID
      None
      N (* W *)
      None
      (TwoOperands (OprIflag IF, OprImm 4L))
      [| 0xf3uy; 0xafuy; 0x87uy; 0x64uy |]

    testThumb
      Condition.UN
      Op.CPSIE
      None
      N
      None
      (OneOperand (OprIflag AF))
      [| 0xb6uy; 0x65uy |]

  /// A4.5.1 Banked register access instructions
  [<TestMethod>]
  member __.``[Thumb] Banked register access Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.MRS
      None
      N
      None
      (TwoOperands (OprReg R.R0, OprReg R.LRusr))
      [| 0xf3uy; 0xe6uy; 0x80uy; 0x20uy |]

    testThumb
      (Condition.AL)
      Op.MSR
      None
      N
      None
      (TwoOperands (OprReg R.SPSRabt, OprReg R.R1))
      [| 0xf3uy; 0x91uy; 0x84uy; 0x30uy |]

/// A4.6 Load/store instructions
[<TestClass>]
type LoadStoreClass () =
  [<TestMethod>]
  member __.``[Thumb] Load/store (Lord) Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.LDR
      (Some false)
      N
      None
      (TwoOperands (
        OprReg R.R1,
        OprMemory (OffsetMode (ImmOffset (R.SP, Some Plus, Some 60L)))
      ))
      [| 0x99uy; 0x0fuy |]

    testThumb
      (Condition.AL)
      Op.LDR
      None
      N
      None
      (TwoOperands (OprReg R.R4, OprMemory (LiteralMode 220L)))
      [| 0x4cuy; 0x37uy |]

    testThumb
      (Condition.AL)
      Op.LDR
      (Some false)
      W
      None
      (TwoOperands (OprReg R.R0, OprMemory (LiteralMode 135L)))
      [| 0xf8uy; 0xdfuy; 0x00uy; 0x87uy |]

    testThumb
      (Condition.AL)
      Op.LDR
      None
      N
      None
      (TwoOperands (
        OprReg R.IP,
        OprMemory (
          OffsetMode (
            RegOffset (R.SB, Some Plus, R.R8, Some (SRTypeLSL, Imm 3u))
          )
        )
      ))
      [| 0xf8uy; 0x59uy; 0xc0uy; 0x38uy |]

    testThumb
      (Condition.AL)
      Op.LDR
      (Some true)
      N
      None
      (TwoOperands (
        OprReg R.R2,
        OprMemory (PreIdxMode (ImmOffset (R.R1, Some Plus, Some 51L)))
      ))
      [| 0xf8uy; 0x51uy; 0x2fuy; 0x33uy |]

    testThumb
      (Condition.AL)
      Op.LDR
      (Some false)
      W
      None
      (TwoOperands (
        OprReg R.IP,
        OprMemory (OffsetMode (ImmOffset (R.LR, Some Plus, Some 128L)))
      ))
      [| 0xf8uy; 0xdeuy; 0xc0uy; 0x80uy |]

    testThumb
      (Condition.AL)
      Op.LDRH
      (Some false)
      N
      None
      (TwoOperands (
        OprReg R.FP,
        OprMemory (OffsetMode (ImmOffset (R.SB, Some Minus, Some 130L)))
      ))
      [| 0xf8uy; 0x39uy; 0xbcuy; 0x82uy |]

    testThumb
      (Condition.AL)
      Op.LDRSH
      None
      N
      None
      (TwoOperands (OprReg R.R6, OprMemory (LiteralMode -587L)))
      [| 0xf9uy; 0x3fuy; 0x62uy; 0x4buy |]

    testThumb
      (Condition.AL)
      Op.LDRSH
      (Some false)
      N
      None
      (TwoOperands (
        OprReg R.FP,
        OprMemory (OffsetMode (ImmOffset (R.R3, Some Plus, Some 11L)))
      ))
      [| 0xf9uy; 0xb3uy; 0xb0uy; 0x0buy |]

    testThumb
      (Condition.AL)
      Op.LDRB
      (Some false)
      N
      None
      (TwoOperands (
        OprReg R.R6,
        OprMemory (OffsetMode (ImmOffset (R.R4, Some Plus, Some 6L)))
      ))
      [| 0x79uy; 0xa6uy |]

    testThumb
      (Condition.AL)
      Op.LDRB
      (Some false)
      N (* W *)
      None
      (TwoOperands (
        OprReg R.SL,
        OprMemory (
          OffsetMode (
            RegOffset (R.R2, Some Plus, R.R6, Some (SRTypeLSL, Imm 3u))
          )
        )
      ))
      [| 0xf8uy; 0x12uy; 0xa0uy; 0x36uy |]

    testThumb
      (Condition.AL)
      Op.LDRB
      (Some true)
      N
      None
      (TwoOperands (
        OprReg R.R8,
        OprMemory (PostIdxMode (ImmOffset (R.R4, Some Minus, Some 12L)))
      ))
      [| 0xf8uy; 0x14uy; 0x89uy; 0x0cuy |]

    testThumb
      (Condition.AL)
      Op.LDRB
      None
      N (* W *)
      None
      (TwoOperands (OprReg R.R3, OprMemory (LiteralMode 240L)))
      [| 0xf8uy; 0x9fuy; 0x30uy; 0xf0uy |]

    testThumb
      (Condition.AL)
      Op.LDRSB
      (Some false)
      N
      None
      (TwoOperands (
        OprReg R.R1,
        OprMemory (OffsetMode (ImmOffset (R.R8, Some Plus, Some 3122L)))
      ))
      [| 0xf9uy; 0x98uy; 0x1cuy; 0x32uy |]

    testThumb
      (Condition.AL)
      Op.LDRSB
      (Some false)
      N (* W *)
      None
      (TwoOperands (
        OprReg R.SB,
        OprMemory (
          OffsetMode (
            RegOffset (R.LR, Some Plus, R.R0, Some (SRTypeLSL, Imm 2u))
          )
        )
      ))
      [| 0xf9uy; 0x1euy; 0x90uy; 0x20uy |]

    testThumb
      (Condition.AL)
      Op.LDRD
      (Some false)
      N
      None
      (ThreeOperands (
        OprReg R.IP,
        OprReg R.R6,
        OprMemory (LiteralMode -264L)
      ))
      [| 0xe9uy; 0x5fuy; 0xc6uy; 0x42uy |]

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store) Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.STR
      (Some false)
      N
      None
      (TwoOperands (
        OprReg R.R7,
        OprMemory (OffsetMode (ImmOffset (R.R6, Some Plus, Some 96L)))
      ))
      [| 0x66uy; 0x37uy |]

    testThumb
      (Condition.AL)
      Op.STRH
      (Some false)
      N
      None
      (TwoOperands (
        OprReg R.R7,
        OprMemory (OffsetMode (ImmOffset (R.R2, Some Plus, Some 34L)))
      ))
      [| 0x84uy; 0x57uy |]

    testThumb
      (Condition.AL)
      Op.STRB
      (Some false)
      N
      None
      (TwoOperands (
        OprReg R.R4,
        OprMemory (OffsetMode (RegOffset (R.R3, Some Plus, R.R2, None)))
      ))
      [| 0x54uy; 0x9cuy |]

    testThumb
      (Condition.AL)
      Op.STRB
      (Some true)
      N
      None
      (TwoOperands (
        OprReg R.LR,
        OprMemory (PostIdxMode (ImmOffset (R.SB, Some Minus, Some 130L)))
      ))
      [| 0xf8uy; 0x09uy; 0xe9uy; 0x82uy |]

    testThumb
      (Condition.AL)
      Op.STRB
      (Some false)
      W
      None
      (TwoOperands (
        OprReg R.IP,
        OprMemory (OffsetMode (ImmOffset (R.R6, Some Plus, Some 2060L)))
      ))
      [| 0xf8uy; 0x86uy; 0xc8uy; 0x0cuy |]

    testThumb
      (Condition.AL)
      Op.STRB
      (Some false)
      N (* W *)
      None
      (TwoOperands (
        OprReg R.R0,
        OprMemory (
          OffsetMode (
            RegOffset (R.SL, Some Plus, R.IP, Some (SRTypeLSL, Imm 2u))
          )
        )
      ))
      [| 0xf8uy; 0x0auy; 0x00uy; 0x2cuy |]

    testThumb
      (Condition.AL)
      Op.STRD
      (Some true)
      N
      None
      (ThreeOperands (
        OprReg R.R3,
        OprReg R.SB,
        OprMemory (PreIdxMode (ImmOffset (R.SL, Some Minus, Some 240L)))
      ))
      [| 0xe9uy; 0x6auy; 0x39uy; 0x3cuy |]

  [<TestMethod>]
  member __.``[Thumb] Load/store (Load unprivileged) Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.LDRT
      None
      N
      None
      (TwoOperands (
        OprReg R.R1,
        OprMemory (OffsetMode (ImmOffset (R.R0, None, Some 4L)))
      ))
      [| 0xf8uy; 0x50uy; 0x1euy; 0x04uy |]

    testThumb
      (Condition.AL)
      Op.LDRHT
      None
      N
      None
      (TwoOperands (
        OprReg R.IP,
        OprMemory (OffsetMode (ImmOffset (R.R4, None, Some 1L)))
      ))
      [| 0xf8uy; 0x34uy; 0xceuy; 0x01uy |]

    testThumb
      (Condition.AL)
      Op.LDRSBT
      None
      N
      None
      (TwoOperands (
        OprReg R.SB,
        OprMemory (OffsetMode (ImmOffset (R.IP, None, Some 9L)))
      ))
      [| 0xf9uy; 0x1cuy; 0x9euy; 0x09uy |]

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store unprivileged) Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.STRHT
      None
      N
      None
      (TwoOperands (
        OprReg R.FP,
        OprMemory (OffsetMode (ImmOffset (R.R7, None, Some 83L)))
      ))
      [| 0xf8uy; 0x27uy; 0xbeuy; 0x53uy |]

  [<TestMethod>]
  member __.``[Thumb] Load/store (Load-Exclusive) Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.LDREX
      None
      N
      None
      (TwoOperands (
        OprReg R.FP,
        OprMemory (OffsetMode (ImmOffset (R.SB, None, Some 56L)))
      ))
      [| 0xe8uy; 0x59uy; 0xbfuy; 0x0euy |]

    testThumb
      (Condition.AL)
      Op.LDREXB
      None
      N
      None
      (TwoOperands (
        OprReg R.R0,
        OprMemory (OffsetMode (ImmOffset (R.SB, None, None)))
      ))
      [| 0xe8uy; 0xd9uy; 0x0fuy; 0x4fuy |]

    testThumb
      (Condition.AL)
      Op.LDREXD
      None
      N
      None
      (ThreeOperands (
        OprReg R.SL,
        OprReg R.IP,
        OprMemory (OffsetMode (ImmOffset (R.LR, None, None)))
      ))
      [| 0xe8uy; 0xdeuy; 0xacuy; 0x7fuy |]

  [<TestMethod>]
  member __.``[Thumb] Load/store (Store-Exclusive) Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.STREX
      None
      N
      None
      (ThreeOperands (
        OprReg R.SL,
        OprReg R.LR,
        OprMemory (OffsetMode (ImmOffset (R.R1, None, Some 48L)))
      ))
      [| 0xe8uy; 0x41uy; 0xeauy; 0x0cuy |]

    testThumb
      (Condition.AL)
      Op.STREXH
      None
      N
      None
      (ThreeOperands (
        OprReg R.R6,
        OprReg R.SL,
        OprMemory (OffsetMode (ImmOffset (R.R8, None, None)))
      ))
      [| 0xe8uy; 0xc8uy; 0xafuy; 0x56uy |]

    testThumb
      (Condition.AL)
      Op.STREXD
      None
      N
      None
      (FourOperands (
        OprReg R.R4,
        OprReg R.IP,
        OprReg R.FP,
        OprMemory (OffsetMode (ImmOffset (R.R0, None, None)))
      ))
      [| 0xe8uy; 0xc0uy; 0xcbuy; 0x74uy |]

/// A4.7 Load/store multiple instructions
[<TestClass>]
type LoadStoreMultipleClass () =
  [<TestMethod>]
  member __.``[Thumb] Load/store multiple Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.LDM
      (Some true)
      N
      None
      (TwoOperands (OprReg R.R3, OprRegList [ R.R0; R.R6; R.R7 ]))
      [| 0xcbuy; 0xc1uy |]

    testThumb
      (Condition.AL)
      Op.LDM
      (Some false)
      W
      None
      (TwoOperands (OprReg R.R8, OprRegList [ R.R2; R.R7; R.R8; R.IP; R.LR ]))
      [| 0xe8uy; 0x98uy; 0x51uy; 0x84uy |]

    testThumb
      (Condition.AL)
      Op.POP
      None
      W
      None
      (OneOperand (OprRegList [ R.R0; R.R4; R.SB; R.SL; R.PC ]))
      [| 0xe8uy; 0xbduy; 0x86uy; 0x11uy |]

    testThumb
      (Condition.AL)
      Op.POP
      None
      W
      None
      (OneOperand (OprRegList [ R.R3 ]))
      [| 0xf8uy; 0x5duy; 0x3buy; 0x04uy |]

    testThumb
      (Condition.AL)
      Op.PUSH
      None
      N
      None
      (OneOperand (OprRegList [ R.R0; R.R1; R.R4; R.R5; R.LR ]))
      [| 0xb5uy; 0x33uy |]

    testThumb
      (Condition.AL)
      Op.PUSH
      None
      W
      None
      (OneOperand (OprRegList [ R.R2; R.R7; R.R8 ]))
      [| 0xe9uy; 0x2duy; 0x01uy; 0x84uy |]

    testThumb
      (Condition.AL)
      Op.PUSH
      None
      W
      None
      (OneOperand (OprRegList [ R.R1 ]))
      [| 0xf8uy; 0x4duy; 0x1duy; 0x04uy |]

    testThumb
      (Condition.AL)
      Op.STM
      (Some true)
      N
      None
      (TwoOperands (OprReg R.R5, OprRegList [ R.R0; R.R1; R.R5; R.R7 ]))
      [| 0xc5uy; 0xa3uy |]

    testThumb
      (Condition.AL)
      Op.STM
      (Some false)
      W
      None
      (TwoOperands (
        OprReg R.R2,
        OprRegList [ R.R4; R.R7; R.R8; R.FP; R.IP; R.LR ]
      ))
      [| 0xe8uy; 0x82uy; 0x59uy; 0x90uy |]

/// A4.8 Miscellaneous instructions
[<TestClass>]
type MiscellaneousClass () =
  [<TestMethod>]
  member __.``[Thumb] Miscellaneous Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.DBG
      None
      N
      None
      (OneOperand (OprImm 11L))
      [| 0xf3uy; 0xafuy; 0x80uy; 0xfbuy |]

    testThumb
      (Condition.AL)
      Op.DMB
      None
      N
      None
      (OneOperand (OprOption BarrierOption.NSH))
      [| 0xf3uy; 0xbfuy; 0x8fuy; 0x57uy |]

    testThumb
      Condition.UN
      Op.ITE
      None
      N
      None
      (OneOperand (OprCond Condition.VS))
      [| 0xbfuy; 0x6cuy |]

    testThumb
      (Condition.AL)
      Op.NOP
      None
      W
      None
      NoOperand
      [| 0xf3uy; 0xafuy; 0x80uy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.PLD
      None
      N
      None
      (OneOperand (
        OprMemory (
          OffsetMode (RegOffset (R.IP, None, R.FP, Some (SRTypeLSL, Imm 1u)))
        )
      ))
      [| 0xf8uy; 0x1cuy; 0xf0uy; 0x1buy |]

    testThumb
      (Condition.AL)
      Op.PLD
      None
      N
      None
      (OneOperand (
        OprMemory (OffsetMode (ImmOffset (R.R0, Some Minus, Some 32L)))
      ))
      [| 0xf8uy; 0x10uy; 0xfcuy; 0x20uy |]

    testThumb
      (Condition.AL)
      Op.PLD
      None
      N
      None
      (OneOperand (OprMemory (LiteralMode -142L)))
      [| 0xf8uy; 0x1fuy; 0xf0uy; 0x8euy |]

    testThumb
      (Condition.AL)
      Op.PLD
      None
      N
      None
      (OneOperand (OprMemory (LiteralMode 15L)))
      [| 0xf8uy; 0x9fuy; 0xf0uy; 0x0fuy |]

    testThumb
      (Condition.AL)
      Op.PLDW
      None
      N
      None
      (OneOperand (
        OprMemory (
          OffsetMode (RegOffset (R.R7, None, R.FP, Some (SRTypeLSL, Imm 1u)))
        )
      ))
      [| 0xf8uy; 0x37uy; 0xf0uy; 0x1buy |]

    testThumb
      (Condition.AL)
      Op.PLDW
      None
      N
      None
      (OneOperand (
        OprMemory (OffsetMode (ImmOffset (R.R2, Some Minus, Some 49L)))
      ))
      [| 0xf8uy; 0x32uy; 0xfcuy; 0x31uy |]

    testThumb
      (Condition.AL)
      Op.PLDW
      None
      N
      None
      (OneOperand (
        OprMemory (OffsetMode (ImmOffset (R.IP, Some Plus, Some 195L)))
      ))
      [| 0xf8uy; 0xbcuy; 0xf0uy; 0xc3uy |]

    testThumb
      (Condition.AL)
      Op.PLI
      None
      N
      None
      (OneOperand (
        OprMemory (OffsetMode (ImmOffset (R.SL, Some Plus, Some 3L)))
      ))
      [| 0xf9uy; 0x9auy; 0xf0uy; 0x03uy |]

    testThumb
      Condition.UN
      Op.SETEND
      None
      N
      None
      (OneOperand (OprEndian Endian.Big))
      [| 0xb6uy; 0x58uy |]

/// A4.9 Exception-generating and exception-handling instructions
[<TestClass>]
type ExcepGenAndExcepHandClass () =
  [<TestMethod>]
  member __.``[Thumb] Exception-gen and exception-handling Parse Test`` () =
    testThumb
      Condition.UN
      Op.BKPT
      None
      N
      None
      (OneOperand (OprImm 48L))
      [| 0xbeuy; 0x30uy |]

    testThumb
      (Condition.AL)
      Op.SMC
      None
      N
      None
      (OneOperand (OprImm 8L))
      [| 0xf7uy; 0xf8uy; 0x80uy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.RFEIA
      (Some true)
      N
      None
      (OneOperand (OprReg R.SL))
      [| 0xe9uy; 0xbauy; 0xc0uy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.SUBS
      None
      N
      None
      (ThreeOperands (OprReg R.PC, OprReg R.LR, OprImm 8L))
      [| 0xf3uy; 0xdeuy; 0x8fuy; 0x08uy |]

    testThumb
      Condition.UN
      Op.HVC
      None
      N
      None
      (OneOperand (OprImm 4108L))
      [| 0xf7uy; 0xe1uy; 0x80uy; 0x0cuy |]

    testThumb
      (Condition.AL)
      Op.ERET
      None
      N
      None
      NoOperand
      [| 0xf3uy; 0xdeuy; 0x8fuy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.ERET
      None
      N
      None
      NoOperand
      [| 0xf3uy; 0xdeuy; 0x8fuy; 0x00uy |]

    testThumb
      (Condition.AL)
      Op.SRSDB
      (Some true)
      N
      None
      (TwoOperands ((OprReg R.SP), OprImm 19L))
      [| 0xe8uy; 0x2duy; 0xc0uy; 0x13uy |]

/// A5.4 Media instructions
[<TestClass>]
type MediaClass () =
  [<TestMethod>]
  member __.``[Thumb] Media Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.UDF
      None
      N
      None
      (OneOperand (OprImm 15L))
      [| 0xdeuy; 0x0fuy |]

/// A6.3.4 Branches and miscellaneous control
[<TestClass>]
type MiscellaneousControlClass () =
  [<TestMethod>]
  member __.``[Thumb] Miscellaneous control Parse Test`` () =
    testThumb
      (Condition.AL)
      Op.CLREX
      None
      N
      None
      NoOperand
      [| 0xf3uy; 0xbfuy; 0x8fuy; 0x2fuy |]

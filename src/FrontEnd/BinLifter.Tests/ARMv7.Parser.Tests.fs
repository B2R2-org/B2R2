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

namespace B2R2.FrontEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter

module ARMv7 =
  open B2R2.FrontEnd.BinLifter.ARM32

  let private test arch endian cond op w q simd oprs (bytes: byte[]) =
    let mode = ArchOperationMode.ARMMode
    let parser =
      ARM32Parser (ISA.Init arch endian, mode, None) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL) :?> ARM32Instruction
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

    let q =
      match q with
      | Some W -> W
      | _ -> N // XXX

    Assert.AreEqual (cond', cond)
    Assert.AreEqual (opcode', op)
    Assert.AreEqual (wback', w)
    Assert.AreEqual (q', q)
    Assert.AreEqual (simd', simd)
    Assert.AreEqual (oprs', oprs)

  let private test32 = test Arch.ARMv7 Endian.Big

  /// A4.3 Branch instructions
  [<TestClass>]
  type BranchClass () =
    [<TestMethod>]
    member __.``[ARMv7] Branch Parse Test`` () =
      test32
        (Condition.AL)
        Op.B
        None
        None
        None
        (OneOperand (OprMemory (LiteralMode 1020L)))
        [| 0xeauy; 0x00uy; 0x00uy; 0xffuy |]

      test32
        (Condition.UN)
        Op.BLX
        None
        None
        None
        (OneOperand (OprMemory (LiteralMode 64L)))
        [| 0xfauy; 0x00uy; 0x00uy; 0x10uy |]

      test32
        (Condition.AL)
        Op.BX
        None
        None
        None
        (OneOperand (OprReg R.R0))
        [| 0xe1uy; 0x2fuy; 0xffuy; 0x10uy |]

  /// A4.4 Data-processing instructions
  [<TestClass>]
  type DataProcessingClass () =
    /// A4.4.1 Standard data-processing instructions
    [<TestMethod>]
    member __.``[ARMv7] Standard data-processing Parse Test`` () =
      test32
        (Condition.AL)
        Op.ADD
        None
        None
        None
        (FourOperands (
          OprReg R.R2,
          OprReg R.R0,
          OprReg R.LR,
          OprRegShift (SRTypeASR, R.R8)
        ))
        [| 0xe0uy; 0x80uy; 0x28uy; 0x5euy |]

      test32
        (Condition.AL)
        Op.ADD
        None
        None
        None (* It used to be ADR *)
        (ThreeOperands (OprReg R.R0, OprReg R.PC, OprImm 960L))
        [| 0xe2uy; 0x8fuy; 0x0fuy; 0xf0uy |]

      test32
        (Condition.AL)
        Op.AND
        None
        None
        None
        (FourOperands (
          OprReg R.R0,
          OprReg R.R0,
          OprReg R.R0,
          OprShift (SRTypeLSL, Imm 0u)
        ))
        [| 0xe0uy; 0x00uy; 0x00uy; 0x00uy |]

      test32
        (Condition.AL)
        Op.CMP
        None
        None
        None
        (ThreeOperands (OprReg R.IP, OprReg R.R2, OprShift (SRTypeROR, Imm 4u)))
        [| 0xe1uy; 0x5cuy; 0x02uy; 0x62uy |]

      test32
        (Condition.AL)
        Op.EORS
        None
        None
        None
        (ThreeOperands (OprReg R.R1, OprReg R.R0, OprImm 252L))
        [| 0xe2uy; 0x30uy; 0x10uy; 0xfcuy |]

      test32
        (Condition.AL)
        Op.MOVW
        None
        None
        None
        (TwoOperands (OprReg R.SL, OprImm 15L))
        [| 0xe3uy; 0x00uy; 0xa0uy; 0x0fuy |]

      test32
        (Condition.AL)
        Op.MOVS
        None
        None
        None
        (TwoOperands (OprReg R.R8, OprReg R.IP))
        [| 0xe1uy; 0xb0uy; 0x80uy; 0x0cuy |]

      test32
        (Condition.AL)
        Op.MVN
        None
        None
        None
        (ThreeOperands (
          OprReg R.R0,
          OprReg R.SB,
          OprRegShift (SRTypeLSL, R.R8)
        ))
        [| 0xe1uy; 0xe0uy; 0x08uy; 0x19uy |]

      test32
        (Condition.AL)
        Op.TEQ
        None
        None
        None
        (ThreeOperands (
          OprReg R.SL,
          OprReg R.R6,
          OprRegShift (SRTypeLSL, R.IP)
        ))
        [| 0xe1uy; 0x3auy; 0x0cuy; 0x16uy |]

      test32
        (Condition.AL)
        Op.TST
        None
        None
        None
        (TwoOperands (OprReg R.R3, OprImm 4L))
        [| 0xe3uy; 0x13uy; 0x00uy; 0x04uy |]

    /// A4.4.2 Shift instructions
    [<TestMethod>]
    member __.``[ARMv7] Shift Parse Test`` () =
      test32
        (Condition.AL)
        Op.LSLS
        None
        None
        None
        (ThreeOperands (OprReg R.R0, OprReg R.R3, OprReg R.R1))
        [| 0xe1uy; 0xb0uy; 0x01uy; 0x13uy |]

      test32
        (Condition.AL)
        Op.ROR
        None
        None
        None
        (ThreeOperands (OprReg R.R0, OprReg R.R5, OprImm 28L))
        [| 0xe1uy; 0xa0uy; 0x0euy; 0x65uy |]

    /// A4.4.3 Multiply instructions
    [<TestMethod>]
    member __.``[ARMv7] Multiply Parse Test`` () =
      test32
        (Condition.AL)
        Op.MULS
        None
        None
        None
        (ThreeOperands (OprReg R.R0, OprReg R.SB, OprReg R.IP))
        [| 0xe0uy; 0x10uy; 0x0cuy; 0x99uy |]

      test32
        (Condition.AL)
        Op.SMLABT
        None
        None
        None
        (FourOperands (OprReg R.R0, OprReg R.R5, OprReg R.SL, OprReg R.IP))
        [| 0xe1uy; 0x00uy; 0xcauy; 0xc5uy |]

      test32
        (Condition.AL)
        Op.SMLALTT
        None
        None
        None
        (FourOperands (OprReg R.R1, OprReg R.R0, OprReg R.R8, OprReg R.R2))
        [| 0xe1uy; 0x40uy; 0x12uy; 0xe8uy |]

      test32
        (Condition.AL)
        Op.SMUAD
        None
        None
        None
        (ThreeOperands (OprReg R.R0, OprReg R.R2, OprReg R.R1))
        [| 0xe7uy; 0x00uy; 0xf1uy; 0x12uy |]

      test32
        (Condition.AL)
        Op.SMULBB
        None
        None
        None
        (ThreeOperands (OprReg R.R0, OprReg R.IP, OprReg R.LR))
        [| 0xe1uy; 0x60uy; 0x0euy; 0x8cuy |]

    /// A4.4.4 Saturating instructions
    [<TestMethod>]
    member __.``[ARMv7] Saturating Parse Test`` () =
      test32
        (Condition.AL)
        Op.SSAT
        None
        None
        None
        (FourOperands (
          OprReg R.R0,
          OprImm 29L,
          OprReg R.R2,
          OprShift (SRTypeASR, Imm 7u)
        ))
        [| 0xe6uy; 0xbcuy; 0x03uy; 0xd2uy |]

    /// A4.4.5 Saturating addition and subtraction instructions
    [<TestMethod>]
    member __.``[ARMv7] Saturating addition and subtraction Parse Test`` () =
      test32
        (Condition.AL)
        Op.QADD
        None
        None
        None
        (ThreeOperands (OprReg R.R1, OprReg R.R2, OprReg R.R0))
        [| 0xe1uy; 0x00uy; 0x10uy; 0x52uy |]

    /// A4.4.6 Packing and unpacking instructions
    [<TestMethod>]
    member __.``[ARMv7] Packing and unpacking Parse Test`` () =
      test32
        (Condition.AL)
        Op.PKHTB
        None
        None
        None
        (FourOperands (
          OprReg R.R1,
          OprReg R.R0,
          OprReg R.R8,
          OprShift (SRTypeASR, Imm 21u)
        ))
        [| 0xe6uy; 0x80uy; 0x1auy; 0xd8uy |]

      test32
        (Condition.AL)
        Op.SXTAB
        None
        None
        None
        (FourOperands (
          OprReg R.R1,
          OprReg R.R0,
          OprReg R.R0,
          OprShift (SRTypeROR, Imm 24u)
        ))
        [| 0xe6uy; 0xa0uy; 0x1cuy; 0x70uy |]

      test32
        (Condition.AL)
        Op.SXTH
        None
        None
        None
        (ThreeOperands (OprReg R.R0, OprReg R.R3, OprShift (SRTypeROR, Imm 0u)))
        [| 0xe6uy; 0xbfuy; 0x00uy; 0x73uy |]

    /// A4.4.7 Parallel addition and subtraction instructions
    [<TestMethod>]
    member __.``[ARMv7] Parallel addition and subtraction Parse Test`` () =
      test32
        (Condition.AL)
        Op.SASX
        None
        None
        None
        (ThreeOperands (OprReg R.R1, OprReg R.R0, OprReg R.R7))
        [| 0xe6uy; 0x10uy; 0x1fuy; 0x37uy |]


    /// A4.4.9 Miscellaneous data-processing instructions
    [<TestMethod>]
    member __.``[ARMv7] Miscellaneous data-processing Parse Test`` () =
      test32
        (Condition.AL)
        Op.BFC
        None
        None
        None
        (ThreeOperands (OprReg R.R0, OprImm 3L, OprImm 29L))
        [| 0xe7uy; 0xdfuy; 0x01uy; 0x9fuy |]

      test32
        (Condition.AL)
        Op.BFI
        None
        None
        None
        (FourOperands (OprReg R.R0, OprReg R.R0, OprImm 5L, OprImm 6L))
        [| 0xe7uy; 0xcauy; 0x02uy; 0x90uy |]

      test32
        (Condition.AL)
        Op.CLZ
        None
        None
        None
        (TwoOperands (OprReg R.R0, OprReg R.R1))
        [| 0xe1uy; 0x6fuy; 0x0fuy; 0x11uy |]

      test32
        (Condition.AL)
        Op.SBFX
        None
        None
        None
        (FourOperands (OprReg R.R0, OprReg R.R2, OprImm 28L, OprImm 3L))
        [| 0xe7uy; 0xa2uy; 0x0euy; 0x52uy |]

  /// A4.5 Status register access instructions
  [<TestClass>]
  type StatusOprRegAccessClass () =
    [<TestMethod>]
    member __.``[ARMv7] Status register access Parse Test`` () =
      test32
        (Condition.AL)
        Op.MSR
        None
        None
        None
        (TwoOperands (OprSpecReg (R.CPSR, Some PSRfs), OprImm 240L))
        [| 0xe3uy; 0x2cuy; 0xf0uy; 0xf0uy |]

      test32
        (Condition.AL)
        Op.MSR
        None
        None
        None
        (TwoOperands (OprSpecReg (R.CPSR, Some PSRfs), OprReg R.R2))
        [| 0xe1uy; 0x2cuy; 0xf0uy; 0x02uy |]

      test32
        (Condition.UN)
        Op.CPSIE
        None
        None
        None
        (TwoOperands (OprIflag AF, OprImm 2L))
        [| 0xf1uy; 0x0auy; 0x01uy; 0x42uy |]

  /// A4.6 Load/store instructions
  [<TestClass>]
  type LoadStoreClass () =
    [<TestMethod>]
    member __.``[ARMv7] Load/store (Lord) Parse Test`` () =
      test32
        (Condition.AL)
        Op.LDR
        None
        None
        None
        (TwoOperands (OprReg R.R0, OprMemory (LiteralMode 15L)))
        [| 0xe5uy; 0x9fuy; 0x00uy; 0x0fuy |]

      test32
        (Condition.AL)
        Op.LDRH
        (Some true)
        None
        None
        (TwoOperands (
          OprReg R.R1,
          OprMemory (PostIdxMode (RegOffset (R.R0, Some Plus, R.IP, None)))
        ))
        [| 0xe0uy; 0x90uy; 0x10uy; 0xbcuy |]

      test32
        (Condition.AL)
        Op.LDRB
        (Some false)
        None
        None
        (TwoOperands (
          OprReg R.R1,
          OprMemory (
            OffsetMode (
              RegOffset (R.R0, Some Minus, R.R2, Some (SRTypeASR, Imm 1u))
            )
          )
        ))
        [| 0xe7uy; 0x50uy; 0x10uy; 0xc2uy |]

      test32
        (Condition.AL)
        Op.LDRSB
        (Some true)
        None
        None
        (TwoOperands (
          OprReg R.R1,
          OprMemory (PreIdxMode (ImmOffset (R.R0, Some Minus, Some 195L)))
        ))
        [| 0xe1uy; 0x70uy; 0x1cuy; 0xd3uy |]

    [<TestMethod>]
    member __.``[ARMv7] Load/store (Store) Parse Test`` () =
      test32
        (Condition.AL)
        Op.STR
        (Some false)
        None
        None
        (TwoOperands (
          OprReg R.R1,
          OprMemory (OffsetMode (ImmOffset (R.R0, Some Minus, Some 243L)))
        ))
        [| 0xe5uy; 0x00uy; 0x10uy; 0xf3uy |]

      test32
        (Condition.AL)
        Op.STRB
        (Some true)
        None
        None
        (TwoOperands (
          OprReg R.R1,
          OprMemory (
            PostIdxMode (
              RegOffset (R.R0, Some Minus, R.IP, Some (SRTypeLSR, Imm 4u))
            )
          )
        ))
        [| 0xe6uy; 0x40uy; 0x12uy; 0x2cuy |]

      test32
        (Condition.AL)
        Op.STRD
        (Some true)
        None
        None
        (ThreeOperands (
          OprReg R.IP,
          OprReg R.SP,
          OprMemory (PreIdxMode (RegOffset (R.R0, Some Plus, R.R8, None)))
        ))
        [| 0xe1uy; 0xa0uy; 0xc0uy; 0xf8uy |]

    [<TestMethod>]
    member __.``[ARMv7] Load/store (Load unprivileged) Parse Test`` () =
      test32
        (Condition.AL)
        Op.LDRSHT
        None
        None
        None
        (TwoOperands (
          OprReg R.LR,
          OprMemory (PostIdxMode (ImmOffset (R.R0, Some Minus, Some 14L)))
        ))
        [| 0xe0uy; 0x70uy; 0xe0uy; 0xfeuy |]

    [<TestMethod>]
    member __.``[ARMv7] Load/store (Store unprivileged) Parse Test`` () =
      test32
        (Condition.AL)
        Op.STRT
        None
        None
        None
        (TwoOperands (
          OprReg R.R1,
          OprMemory (PostIdxMode (ImmOffset (R.R0, Some Plus, Some 15L)))
        ))
        [| 0xe4uy; 0xa0uy; 0x10uy; 0x0fuy |]

      test32
        (Condition.AL)
        Op.STRHT
        None
        None
        None
        (TwoOperands (
          OprReg R.R1,
          OprMemory (PostIdxMode (RegOffset (R.R0, Some Minus, R.R4, None)))
        ))
        [| 0xe0uy; 0x20uy; 0x10uy; 0xb4uy |]

    [<TestMethod>]
    member __.``[ARMv7] Load/store (Load-Exclusive) Parse Test`` () =
      test32
        (Condition.AL)
        Op.LDREX
        None
        None
        None
        (TwoOperands (
          OprReg R.LR,
          OprMemory (OffsetMode (ImmOffset (R.R0, None, None)))
        ))
        [| 0xe1uy; 0x90uy; 0xefuy; 0x9fuy |]

    [<TestMethod>]
    member __.``[ARMv7] Load/store (Store-Exclusive) Parse Test`` () =
      test32
        (Condition.AL)
        Op.STREXD
        None
        None
        None
        (FourOperands (
          OprReg R.R1,
          OprReg R.R2,
          OprReg R.R3,
          OprMemory (OffsetMode (ImmOffset (R.R0, None, None)))
        ))
        [| 0xe1uy; 0xa0uy; 0x1fuy; 0x92uy |]

  /// A4.7 Load/store multiple instructions
  [<TestClass>]
  type LoadStoreMultipleClass () =
    [<TestMethod>]
    member __.``[ARMv7] Load/store multiple Parse Test`` () =
      test32
        (Condition.AL)
        Op.LDMDA
        (Some false)
        None
        None
        (TwoOperands (
          OprReg R.R0,
          OprRegList [ R.R2; R.R3; R.R8; R.SB; R.SL; R.FP ]
        ))
        [| 0xe8uy; 0x10uy; 0x0fuy; 0x0cuy |]

      test32
        (Condition.AL)
        Op.LDMDA
        (Some true)
        None
        None
        (TwoOperands (
          OprReg R.R0,
          OprRegList [ R.R2; R.R3; R.R8; R.SB; R.SL; R.FP ]
        ))
        [| 0xe8uy; 0x30uy; 0x0fuy; 0x0cuy |]

      test32
        (Condition.AL)
        Op.POP
        None
        None
        None
        (OneOperand (OprRegList [ R.R0; R.R1; R.R2; R.R3 ]))
        [| 0xe8uy; 0xbduy; 0x00uy; 0x0fuy |]

      (* test32 (Condition.AL) Op.STR (Some true) None None
             (TwoOperands (OprReg R.R0,
               OprMemory (PreIdxMode (ImmOffset (R.SP, Some Minus, Some 4L)))))
             [| 0xe5uy; 0x2duy; 0x00uy; 0x04uy |] *)

      test32
        (Condition.AL)
        Op.PUSH
        (Some true)
        None
        None
        (OneOperand (OprRegList [ R.R0 ]))
        [| 0xe5uy; 0x2duy; 0x00uy; 0x04uy |]

      test32
        (Condition.AL)
        Op.STMIA
        None
        None
        None
        (TwoOperands (OprReg R.SB, OprRegList [ R.SP; R.LR; R.PC ]))
        [| 0xe8uy; 0xc9uy; 0xe0uy; 0x00uy |]

  /// A4.8 Miscellaneous instructions
  [<TestClass>]
  type MiscellaneousClass () =
    [<TestMethod>]
    member __.``[ARMv7] Miscellaneous Parse Test`` () =
      test32
        (Condition.UN)
        Op.CLREX
        None
        None
        None
        (NoOperand)
        [| 0xf5uy; 0x7fuy; 0xf0uy; 0x1fuy |]

      test32
        (Condition.UN)
        Op.DMB
        None
        None
        None
        (OneOperand (OprOption BarrierOption.SY))
        [| 0xf5uy; 0x7fuy; 0xf0uy; 0x5fuy |]

      test32
        (Condition.AL)
        Op.NOP
        None
        None
        None
        NoOperand
        [| 0xe3uy; 0x20uy; 0xf0uy; 0x00uy |]

      test32
        (Condition.UN)
        Op.PLD
        None
        None
        None
        (OneOperand (OprMemory (LiteralMode -3840L)))
        [| 0xf5uy; 0x5fuy; 0xffuy; 0x00uy |]

      test32
        (Condition.UN)
        Op.PLDW
        None
        None
        None
        (OneOperand (
          OprMemory (
            OffsetMode (
              RegOffset (R.R0, Some Plus, R.R0, Some (SRTypeASR, Imm 3u))
            )
          )
        ))
        [| 0xf7uy; 0x90uy; 0xf1uy; 0xc0uy |]

      test32
        (Condition.UN)
        Op.PLI
        None
        None
        None
        (OneOperand (OprMemory (LiteralMode -240L)))
        [| 0xf4uy; 0x50uy; 0xf0uy; 0xf0uy |]

      test32
        (Condition.UN)
        Op.SETEND
        None
        None
        None
        (OneOperand (OprEndian Endian.Big))
        [| 0xf1uy; 0x01uy; 0x02uy; 0x00uy |]

      (* Only ARMv7 *)
      test32
        (Condition.AL)
        Op.SWP
        None
        None
        None
        (ThreeOperands (
          OprReg R.IP,
          OprReg R.LR,
          OprMemory (OffsetMode (ImmOffset (R.R0, None, None)))
        ))
        [| 0xe1uy; 0x00uy; 0xc0uy; 0x9euy |]

  /// A4.9 Exception-generating and exception-handling instructions
  [<TestClass>]
  type ExcepGenAndExcepHandlClass () =
    [<TestMethod>]
    member __.``[ARMv7] Exception-gen and exception-handling Parse Test`` () =
      test32
        Condition.UN
        Op.BKPT
        None
        None
        None
        (OneOperand (OprImm 3852L))
        [| 0xe1uy; 0x20uy; 0xf0uy; 0x7cuy |]

      test32
        (Condition.AL)
        Op.SMC
        None
        None
        None
        (OneOperand (OprImm 15L))
        [| 0xe1uy; 0x60uy; 0x00uy; 0x7fuy |]

      test32
        (Condition.UN)
        Op.RFEIB
        (Some true)
        None
        None
        (OneOperand (OprReg R.IP))
        [| 0xf9uy; 0xbcuy; 0x0auy; 0x00uy |]

      test32
        (Condition.UN)
        Op.SRSDB
        (Some true)
        None
        None
        (TwoOperands (OprReg R.SP, OprImm 4L))
        [| 0xf9uy; 0x6duy; 0x05uy; 0x04uy |]

  /// A4.10 Co-processor instructions
  [<TestClass>]
  type CoprocessorClass () =
    [<TestMethod>]
    member __.``[ARMv7] Co-processor Parse Test`` () =
      (* Only ARMv7 *)
      test32
        (Condition.AL)
        Op.CDP
        None
        None
        None
        (SixOperands (
          OprReg R.P3,
          OprImm 0L,
          OprReg R.C2,
          OprReg R.C1,
          OprReg R.C8,
          OprImm 7L
        ))
        [| 0xeeuy; 0x01uy; 0x23uy; 0xe8uy |]

      test32
        (Condition.AL)
        Op.MCRR
        None
        None
        None
        (FiveOperands (
          OprReg R.P15,
          OprImm 14L,
          OprReg R.R1,
          OprReg R.R0,
          OprReg R.C3
        ))
        [| 0xecuy; 0x40uy; 0x1fuy; 0xe3uy |]

      test32
        (Condition.AL)
        Op.MRC
        None
        None
        None
        (SixOperands (
          OprReg R.P14,
          OprImm 4L,
          OprReg R.SB,
          OprReg R.C14,
          OprReg R.C2,
          OprImm 1L
        ))
        [| 0xeeuy; 0x9euy; 0x9euy; 0x32uy |]

      test32
        (Condition.AL)
        Op.LDC
        (Some false)
        None
        None
        (ThreeOperands (
          OprReg R.P14,
          OprReg R.C5,
          OprMemory (LiteralMode 192L)
        ))
        [| 0xeduy; 0x9fuy; 0x5euy; 0x30uy |]

      test32
        (Condition.AL)
        Op.LDC
        None
        None
        None
        (ThreeOperands (
          OprReg R.P14,
          OprReg R.C5,
          OprMemory (UnIdxMode (R.R0, 128L))
        ))
        [| 0xecuy; 0x90uy; 0x5euy; 0x80uy |]

  /// A4.11 Advanced SIMD and Floating-point load/store instructions
  [<TestClass>]
  type AdvSIMDAndFPLoadStoreClass () =
    /// A4.11.1 Element and structure load/store instructions
    [<TestMethod>]
    member __.``[ARMv7] Element and structure load/store Parse Test`` () =
      test32
        (Condition.UN)
        Op.VLD4
        (Some true)
        None
        (Some (OneDT SIMDTyp16))
        (TwoOperands (
          OprSIMD (
            FourRegs (
              Scalar (R.D18, None),
              Scalar (R.D20, None),
              Scalar (R.D22, None),
              Scalar (R.D24, None)
            )
          ),
          OprMemory (PostIdxMode (AlignOffset (R.R0, Some 64L, Some R.R0)))
        ))
        [| 0xf4uy; 0xe0uy; 0x2fuy; 0x70uy |]

      test32
        (Condition.UN)
        Op.VST1
        (Some true)
        None
        (Some (OneDT SIMDTyp32))
        (TwoOperands (
          OprSIMD (ThreeRegs (Vector R.D12, Vector R.D13, Vector R.D14)),
          OprMemory (PostIdxMode (AlignOffset (R.R2, Some 64L, Some R.R0)))
        ))
        [| 0xf4uy; 0x02uy; 0xc6uy; 0x90uy |]

      test32
        (Condition.UN)
        Op.VST3
        (Some true)
        None
        (Some (OneDT SIMDTyp32))
        (TwoOperands (
          OprSIMD (
            ThreeRegs (
              Scalar (R.D14, Some 1uy),
              Scalar (R.D16, Some 1uy),
              Scalar (R.D18, Some 1uy)
            )
          ),
          OprMemory (PostIdxMode (RegOffset (R.LR, None, R.R3, None)))
        ))
        [| 0xf4uy; 0x8euy; 0xeauy; 0xc3uy |]

  /// A4.12 Advanced SIMD and Floating-point register transfer instructions
  [<TestClass>]
  type AdvSIMDAndFPRegTransClass () =
    [<TestMethod>]
    member __.``[ARMv7] Advanced SIMD and FP register transfer Parse Test``
      ()
      =
      test32
        (Condition.AL)
        Op.VDUP
        None
        None
        (Some (OneDT SIMDTyp16))
        (TwoOperands (OprSIMD (SFReg (Vector R.D18)), OprReg R.LR))
        [| 0xeeuy; 0x82uy; 0xebuy; 0xb0uy |]

      test32
        (Condition.AL)
        Op.VMOV
        None
        None
        (Some (OneDT SIMDTyp8))
        (TwoOperands (OprSIMD (SFReg (Scalar (R.D18, Some 1uy))), OprReg R.IP))
        [| 0xeeuy; 0x42uy; 0xcbuy; 0xb0uy |]

      test32
        (Condition.AL)
        Op.VMOV
        None
        None
        (Some (OneDT SIMDTypS16))
        (TwoOperands (OprReg R.R8, OprSIMD (SFReg (Scalar (R.D16, Some 0uy)))))
        [| 0xeeuy; 0x10uy; 0x8buy; 0xb0uy |]

  /// A4.13 Advanced SIMD data-processing instructions
  [<TestClass>]
  type AdvSIMDDataProcessingClass () =
    /// A4.13.1 Advanced SIMD parallel addition and subtraction
    [<TestMethod>]
    member __.``[ARMv7] Advanced SIMD parallel add and sub Parse Test`` () =
      test32
        (Condition.UN)
        Op.VADDW
        None
        None
        (Some (OneDT SIMDTypS8))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q14)),
          OprSIMD (SFReg (Vector R.Q8)),
          OprSIMD (SFReg (Vector R.D10))
        ))
        [| 0xf2uy; 0xc0uy; 0xc1uy; 0x8auy |]

      test32
        (Condition.UN)
        Op.VHSUB
        None
        None
        (Some (OneDT SIMDTypU32))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D1)),
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.D28))
        ))
        [| 0xf3uy; 0x20uy; 0x12uy; 0x2cuy |]

      test32
        (Condition.UN)
        Op.VPADDL
        None
        None
        (Some (OneDT SIMDTypU8))
        (TwoOperands (
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.D14))
        ))
        [| 0xf3uy; 0xb0uy; 0x02uy; 0x8euy |]

      test32
        (Condition.UN)
        Op.VSUBHN
        None
        None
        (Some (OneDT SIMDTypI32))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D12)),
          OprSIMD (SFReg (Vector R.Q8)),
          OprSIMD (SFReg (Vector R.Q1))
        ))
        [| 0xf2uy; 0x90uy; 0xc6uy; 0x82uy |]

    /// A4.13.2 Bitwise Advanced SIMD data-processing instructions
    [<TestMethod>]
    member __.``[ARMv7] Bitwise Advanced SIMD data-processing Parse Test`` () =
      test32
        (Condition.UN)
        Op.VAND
        None
        None
        None
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q14)),
          OprSIMD (SFReg (Vector R.Q9)),
          OprSIMD (SFReg (Vector R.Q12))
        ))
        [| 0xf2uy; 0x42uy; 0xc1uy; 0xf8uy |]

      test32
        (Condition.UN)
        Op.VBIC
        None
        None
        (Some (OneDT SIMDTypI32))
        (TwoOperands (OprSIMD (SFReg (Vector R.Q15)), OprImm 0x9B0000L))
        [| 0xf3uy; 0xc1uy; 0xe5uy; 0x7buy |]

      test32
        (Condition.AL)
        Op.VMOV
        None
        None
        None
        (TwoOperands (OprReg R.IP, OprSIMD (SFReg (Vector R.S4))))
        [| 0xeeuy; 0x12uy; 0xcauy; 0x10uy |]

    /// A4.13.3 Advanced SIMD comparison instructions
    [<TestMethod>]
    member __.``[ARMv7] Advanced SIMD comparison Parse Test`` () =
      test32
        (Condition.UN)
        Op.VCEQ
        None
        None
        (Some (OneDT SIMDTypF32))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q12)),
          OprSIMD (SFReg (Vector R.Q6)),
          OprSIMD (SFReg (Vector R.Q0))
        ))
        [| 0xf2uy; 0x4cuy; 0x8euy; 0x40uy |]

    /// A4.13.4 Advanced SIMD shift instructions
    [<TestMethod>]
    member __.``[ARMv7] Advanced SIMD shift Parse Test`` () =
      test32
        (Condition.UN)
        Op.VQRSHRN
        None
        None
        (Some (OneDT SIMDTypU64))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.Q0)),
          OprImm 32L
        ))
        [| 0xf3uy; 0xa0uy; 0x09uy; 0x50uy |]

      test32
        (Condition.UN)
        Op.VQSHRUN
        None
        None
        (Some (OneDT SIMDTypS64))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.Q8)),
          OprImm 8L
        ))
        [| 0xf3uy; 0xb8uy; 0x08uy; 0x30uy |]

      test32
        (Condition.UN)
        Op.VSHL
        None
        None
        (Some (OneDT SIMDTypI64))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q1)),
          OprSIMD (SFReg (Vector R.Q4)),
          OprImm 56L
        ))
        [| 0xf2uy; 0xb8uy; 0x25uy; 0xd8uy |]

      test32
        (Condition.UN)
        Op.VSHRN
        None
        None
        (Some (OneDT SIMDTypI64))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.Q9)),
          OprImm 32L
        ))
        [| 0xf2uy; 0xa0uy; 0x08uy; 0x32uy |]

      test32
        (Condition.UN)
        Op.VSRA
        None
        None
        (Some (OneDT SIMDTypU64))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q8)),
          OprSIMD (SFReg (Vector R.Q8)),
          OprImm 24L
        ))
        [| 0xf3uy; 0xe8uy; 0x01uy; 0xf0uy |]

      test32
        (Condition.UN)
        Op.VSRI
        None
        None
        (Some (OneDT SIMDTyp32))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D9)),
          OprSIMD (SFReg (Vector R.D26)),
          OprImm 7L
        ))
        [| 0xf3uy; 0xb9uy; 0x94uy; 0x3auy |]

    /// A4.13.5 Advanced SIMD multiply instructions
    [<TestMethod>]
    member __.``[ARMv7] Advanced SIMD multiply Parse Test`` () =
      test32
        (Condition.UN)
        Op.VMLSL
        None
        None
        (Some (OneDT SIMDTypU32))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q1)),
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.D24))
        ))
        [| 0xf3uy; 0xa0uy; 0x2auy; 0x28uy |]

      test32
        (Condition.AL)
        Op.VMUL
        None
        None
        (Some (OneDT SIMDTypF32))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.S4)),
          OprSIMD (SFReg (Vector R.S1)),
          OprSIMD (SFReg (Vector R.S17))
        ))
        [| 0xeeuy; 0x20uy; 0x2auy; 0xa8uy |]

      test32
        (Condition.UN)
        Op.VMULL
        None
        None
        (Some (OneDT SIMDTypS8))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q12)),
          OprSIMD (SFReg (Vector R.D18)),
          OprSIMD (SFReg (Vector R.D16))
        ))
        [| 0xf2uy; 0xc2uy; 0x8cuy; 0xa0uy |]

      test32
        (Condition.UN)
        Op.VMULL
        None
        None
        (Some (OneDT SIMDTypU32))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q10)),
          OprSIMD (SFReg (Vector R.D2)),
          OprSIMD (SFReg (Scalar (R.D10, Some 0uy)))
        ))
        [| 0xf3uy; 0xe2uy; 0x4auy; 0x4auy |]

      test32
        (Condition.UN)
        Op.VQDMULH
        None
        None
        (Some (OneDT SIMDTypS16))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q9)),
          OprSIMD (SFReg (Vector R.Q8)),
          OprSIMD (SFReg (Scalar (R.D0, Some 3uy)))
        ))
        [| 0xf3uy; 0xd0uy; 0x2cuy; 0xe8uy |]

    /// A4.13.6 Miscellaneous Advanced SIMD data-processing instructions
    [<TestMethod>]
    member __.``[ARMv7] Misc Advanced SIMD data-processing Parse Test`` () =
      test32
        (Condition.UN)
        Op.VCVT
        None
        None
        (Some (TwoDT (SIMDTypU32, SIMDTypF32)))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.D16)),
          OprImm 22L
        ))
        [| 0xf3uy; 0xaauy; 0x0fuy; 0x30uy |]

      test32
        (Condition.AL)
        Op.VCVT
        None
        None
        (Some (TwoDT (SIMDTypU16, SIMDTypF64)))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.D0)),
          OprImm 11L
        ))
        [| 0xeeuy; 0xbfuy; 0x0buy; 0x62uy |]

      test32
        (Condition.UN)
        Op.VCNT
        None
        None
        (Some (OneDT SIMDTyp8))
        (TwoOperands (
          OprSIMD (SFReg (Vector R.Q13)),
          OprSIMD (SFReg (Vector R.Q15))
        ))
        [| 0xf3uy; 0xf0uy; 0xa5uy; 0x6euy |]

      test32
        (Condition.UN)
        Op.VEXT
        None
        None
        (Some (OneDT SIMDTyp8))
        (FourOperands (
          OprSIMD (SFReg (Vector R.Q0)),
          OprSIMD (SFReg (Vector R.Q8)),
          OprSIMD (SFReg (Vector R.Q7)),
          OprImm 3L
        ))
        [| 0xf2uy; 0xb0uy; 0x03uy; 0xceuy |]

      test32
        (Condition.AL)
        Op.VNEG
        None
        None
        (Some (OneDT SIMDTypF64))
        (TwoOperands (
          OprSIMD (SFReg (Vector R.D16)),
          OprSIMD (SFReg (Vector R.D18))
        ))
        [| 0xeeuy; 0xf1uy; 0x0buy; 0x62uy |]

      test32
        (Condition.UN)
        Op.VPMAX
        None
        None
        (Some (OneDT SIMDTypF32))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D25)),
          OprSIMD (SFReg (Vector R.D0)),
          OprSIMD (SFReg (Vector R.D15))
        ))
        [| 0xf3uy; 0x40uy; 0x9fuy; 0x0fuy |]

      test32
        (Condition.UN)
        Op.VREV32
        None
        None
        (Some (OneDT SIMDTyp16))
        (TwoOperands (
          OprSIMD (SFReg (Vector R.Q0)),
          OprSIMD (SFReg (Vector R.Q1))
        ))
        [| 0xf3uy; 0xb4uy; 0x00uy; 0xc2uy |]

      test32
        (Condition.UN)
        Op.VTBX
        None
        None
        (Some (OneDT SIMDTyp8))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.D5)),
          OprSIMD (
            FourRegs (Vector R.D3, Vector R.D4, Vector R.D5, Vector R.D6)
          ),
          OprSIMD (SFReg (Vector R.D3))
        ))
        [| 0xf3uy; 0xb3uy; 0x5buy; 0x43uy |]

  /// A4.14 Floating-point data-processing instructions
  [<TestClass>]
  type FPDataProcessingClass () =
    [<TestMethod>]
    member __.``[ARMv7] Floating-point data-processing Parse Test`` () =
      test32
        (Condition.AL)
        Op.VCMPE
        None
        None
        (Some (OneDT SIMDTypF64))
        (TwoOperands (OprSIMD (SFReg (Vector R.D0)), OprImm 0L))
        [| 0xeeuy; 0xb5uy; 0x0buy; 0xc0uy |]

      test32
        (Condition.AL)
        Op.VCVT
        None
        None
        (Some (TwoDT (SIMDTypF32, SIMDTypU32)))
        (TwoOperands (
          OprSIMD (SFReg (Vector R.S4)),
          OprSIMD (SFReg (Vector R.S17))
        ))
        [| 0xeeuy; 0xb8uy; 0x2auy; 0x68uy |]

      test32
        (Condition.AL)
        Op.VCVTB
        None
        None
        (Some (TwoDT (SIMDTypF16, SIMDTypF32)))
        (TwoOperands (
          OprSIMD (SFReg (Vector R.S0)),
          OprSIMD (SFReg (Vector R.S6))
        ))
        [| 0xeeuy; 0xb3uy; 0x0auy; 0x43uy |]

      test32
        (Condition.AL)
        Op.VMOV
        None
        None
        (Some (OneDT SIMDTypF32))
        (TwoOperands (OprSIMD (SFReg (Vector R.S6)), OprImm 1091567616L))
        [| 0xeeuy; 0xb2uy; 0x3auy; 0x02uy |]

      test32
        (Condition.UN)
        Op.VMLS
        None
        None
        (Some (OneDT SIMDTypI16))
        (ThreeOperands (
          OprSIMD (SFReg (Vector R.Q14)),
          OprSIMD (SFReg (Vector R.Q1)),
          OprSIMD (SFReg (Scalar (R.D0, Some 2uy)))
        ))
        [| 0xf3uy; 0xd2uy; 0xc4uy; 0x60uy |]
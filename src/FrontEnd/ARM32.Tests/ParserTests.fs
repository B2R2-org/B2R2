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
    static member Reg (r) =
      OprReg r

    static member Imm (v) =
      OprImm v

    static member RegShift (srType, r) =
      OprRegShift (srType, r)

    static member Shift (srType, v) =
      OprShift (srType, Imm v)

    static member SpecReg (r, psfFlag) =
      OprSpecReg (r, Some psfFlag)

    static member Iflag (flag) =
      OprIflag flag

    static member RegList (lst) =
      OprRegList lst

    static member Option (barrier) =
      OprOption barrier

    static member Endian (endian) =
      OprEndian endian

    static member Cond (cond) =
      OprCond cond

    static member SimdScalarReg (r, elem) =
      toSSReg (r, elem)

    static member SimdVectorReg (r) =
      toSVReg r

    static member MemLabel (v) =
      memLabel v

    static member MemUnIdx (r, v) =
      memUnIdxImm (r, v)

    static member MemOffsetImm (offset) =
      memOffsetImm offset

    static member MemOffsetReg (r1, signOpt, r2, srType, v) =
      memOffsetReg (r1, signOpt, r2, Some (srType, Imm v))

    static member MemOffsetReg (r1, signOpt, r2) =
      memOffsetReg (r1, signOpt, r2, None)

    static member MemOffsetAlign (offset) =
      memOffsetAlign offset

    static member MemPreIdxImm (offset) =
      memPreIdxImm offset

    static member MemPreIdxReg (r1, signOpt, r2, srType, v) =
      memPreIdxReg (r1, signOpt, r2, Some (srType, Imm v))

    static member MemPreIdxReg (r1, signOpt, r2) =
      memPreIdxReg (r1, signOpt, r2, None)

    static member MemPreIdxAlign (offset) =
      memPreIdxAlign offset

    static member MemPostIdxImm (offset) =
      memPostIdxImm offset

    static member MemPostIdxReg (r1, signOpt, r2, srType, v) =
      memPostIdxReg (r1, signOpt, r2, Some (srType, Imm v))

    static member MemPostIdxReg (r1, signOpt, r2) =
      memPostIdxReg (r1, signOpt, r2, None)

    static member MemPostIdxAlign (offset) =
      memPostIdxAlign offset

    static member SimdScalarRegs (regList, elem) =
      getSIMDScalar elem regList

    static member SimdVectorRegs (regList) =
      getSIMDVector regList

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
type ParserTests () =
  let test cond op (wback: bool) simd (oprs: Operands) (bytes: byte[]) =
    let isa = ISA (Architecture.ARMv7, Endian.Big)
    let reader = BinReader.Init Endian.Big
    let parser = ARM32Parser (isa, false, reader) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL) :?> Instruction
    let cond' = ins.Condition
    let op' = ins.Opcode
    let wback' = ins.WriteBack
    let simd' = ins.SIMDTyp
    let oprs' = ins.Operands
    Assert.AreEqual<Condition> (cond, cond')
    Assert.AreEqual<Opcode> (op, op')
    Assert.AreEqual<bool> (wback, wback')
    Assert.AreEqual<SIMDDataTypes option> (simd, simd')
    Assert.AreEqual<Operands> (oprs, oprs')

  let testNoWbackNoQNoSimd pref (bytes: byte[]) (opcode, operands) =
    test pref opcode false None operands bytes

  let testNoWbackNoQ pref simd (bytes: byte[]) (opcode, operands) =
    test pref opcode false simd operands bytes

  let testNoQNoSimd pref wback (bytes: byte[]) (opcode, operands) =
    test pref opcode wback None operands bytes

  let testNoQ pref wback simd (bytes: byte[]) (opcode, operands) =
    test pref opcode wback simd operands bytes

  let operandsFromArray oprList =
    let oprs = Array.ofList oprList
    match oprs.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprs[0]
    | 2 -> TwoOperands (oprs[0], oprs[1])
    | 3 -> ThreeOperands (oprs[0], oprs[1], oprs[2])
    | 4 -> FourOperands (oprs[0], oprs[1], oprs[2], oprs[3])
    | 5 -> FiveOperands (oprs[0], oprs[1], oprs[2], oprs[3], oprs[4])
    | 6 -> SixOperands (oprs[0], oprs[1], oprs[2], oprs[3], oprs[4], oprs[5])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  [<TestMethod>]
  member _.``[ARMv7] Branch Parse Test (1)`` () =
    "ea0000ff"
    ++ B ** [ O.MemLabel 1020L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Branch Parse Test (2)`` () =
    "fa000010"
    ++ BLX ** [ O.MemLabel 64L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Branch Parse Test (3)`` () =
    "e12fff10"
    ++ BX ** [ O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.1 Standard data-processing instructions
  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (1)`` () =
    "e080285e"
    ++ ADD ** [ O.Reg R2; O.Reg R0; O.Reg LR; O.RegShift (SRTypeASR, R8) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (2)`` () =
    "e28f0ff0"
    ++ ADD ** [ O.Reg R0; O.Reg PC; O.Imm 960L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (3)`` () =
    "e0000000"
    ++ AND ** [ O.Reg R0; O.Reg R0; O.Reg R0; O.Shift (SRTypeLSL, 0u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (4)`` () =
    "e15c0262"
    ++ CMP ** [ O.Reg IP; O.Reg R2; O.Shift (SRTypeROR, 4u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (5)`` () =
    "e23010fc"
    ++ EORS ** [ O.Reg R1; O.Reg R0; O.Imm 252L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (6)`` () =
    "e300a00f"
    ++ MOVW ** [ O.Reg SL; O.Imm 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (7)`` () =
    "e1b0800c"
    ++ MOVS ** [ O.Reg R8; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (8)`` () =
    "e1e00819"
    ++ MVN ** [ O.Reg R0; O.Reg SB; O.RegShift (SRTypeLSL, R8) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (9)`` () =
    "e13a0c16"
    ++ TEQ ** [ O.Reg SL; O.Reg R6; O.RegShift (SRTypeLSL, IP) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Standard data-processing Parse Test (10)`` () =
    "e3130004"
    ++ TST ** [ O.Reg R3; O.Imm 4L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.2 Shift instructions
  [<TestMethod>]
  member _.``[ARMv7] Shift Parse Test (1)`` () =
    "e1b00113"
    ++ LSLS ** [ O.Reg R0; O.Reg R3; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Shift Parse Test (2)`` () =
    "e1a00e65"
    ++ ROR ** [ O.Reg R0; O.Reg R5; O.Imm 28L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.3 Multiply instructions
  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (1)`` () =
    "e0100c99"
    ++ MULS ** [ O.Reg R0; O.Reg SB; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (2)`` () =
    "e100cac5"
    ++ SMLABT ** [ O.Reg R0; O.Reg R5; O.Reg SL; O.Reg IP ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (3)`` () =
    "e14012e8"
    ++ SMLALTT ** [ O.Reg R1; O.Reg R0; O.Reg R8; O.Reg R2 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (4)`` () =
    "e700f112"
    ++ SMUAD ** [ O.Reg R0; O.Reg R2; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Multiply Parse Test (5)`` () =
    "e1600e8c"
    ++ SMULBB ** [ O.Reg R0; O.Reg IP; O.Reg LR ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.4 Saturating instructions
  [<TestMethod>]
  member _.``[ARMv7] Saturating Parse Test (1)`` () =
    "e6bc03d2"
    ++ SSAT ** [ O.Reg R0; O.Imm 29L; O.Reg R2; O.Shift (SRTypeASR, 7u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.5 Saturating addition and subtraction instructions
  [<TestMethod>]
  member _.``[ARMv7] Saturating addition and subtraction Parse Test (1)`` () =
    "e1001052"
    ++ QADD ** [ O.Reg R1; O.Reg R2; O.Reg R0 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.6 Packing and unpacking instructions
  [<TestMethod>]
  member _.``[ARMv7] Packing and unpacking Parse Test (1)`` () =
    "e6801ad8"
    ++ PKHTB ** [ O.Reg R1; O.Reg R0; O.Reg R8; O.Shift (SRTypeASR, 21u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Packing and unpacking Parse Test (2)`` () =
    "e6a01c70"
    ++ SXTAB ** [ O.Reg R1; O.Reg R0; O.Reg R0; O.Shift (SRTypeROR, 24u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Packing and unpacking Parse Test (3)`` () =
    "e6bf0073"
    ++ SXTH ** [ O.Reg R0; O.Reg R3; O.Shift (SRTypeROR, 0u) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.7 Parallel addition and subtraction instructions
  [<TestMethod>]
  member _.``[ARMv7] Parallel addition and subtraction Parse Test (1)`` () =
    "e6101f37"
    ++ SASX ** [ O.Reg R1; O.Reg R0; O.Reg R7 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.4.9 Miscellaneous data-processing instructions
  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (1)`` () =
    "e7df019f"
    ++ BFC ** [ O.Reg R0; O.Imm 3L; O.Imm 29L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (2)`` () =
    "e7ca0290"
    ++ BFI ** [ O.Reg R0; O.Reg R0; O.Imm 5L; O.Imm 6L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (3)`` () =
    "e16f0f11"
    ++ CLZ ** [ O.Reg R0; O.Reg R1 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous data-processing Parse Test (4)`` () =
    "e7a20e52"
    ++ SBFX ** [ O.Reg R0; O.Reg R2; O.Imm 28L; O.Imm 3L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Status register access Parse Test (1)`` () =
    "e32cf0f0"
    ++ MSR ** [ O.SpecReg (CPSR, PSRfs); O.Imm 240L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Status register access Parse Test (2)`` () =
    "e12cf002"
    ++ MSR ** [ O.SpecReg (CPSR, PSRfs); O.Reg R2 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Status register access Parse Test (3)`` () =
    "f10a0142"
    ++ CPSIE ** [ O.Iflag AF; O.Imm 2L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Lord) Parse test (1)`` () =
    "e59f000f"
    ++ LDR ** [ O.Reg R0; O.MemLabel 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Lord) Parse test (2)`` () =
    "e09010bc"
    ++ LDRH ** [ O.Reg R1; O.MemPostIdxReg (R0, Some Plus, IP) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Lord) Parse test (3)`` () =
    "e75010c2"
    ++ LDRB ** [ O.Reg R1; O.MemOffsetReg (R0, Some Minus, R2, SRTypeASR, 1u) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Lord) Parse test (4)`` () =
    "e1701cd3"
    ++ LDRSB ** [ O.Reg R1; O.MemPreIdxImm (R0, Some Minus, Some 195L) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store) Parse test (1)`` () =
    "e50010f3"
    ++ STR ** [ O.Reg R1; O.MemOffsetImm (R0, Some Minus, Some 243L) ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store) Parse test (2)`` () =
    "e640122c"
    ++ STRB ** [ O.Reg R1; O.MemPostIdxReg (R0, Some Minus, IP, SRTypeLSR, 4u) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store) Parse test (3)`` () =
    "e1a0c0f8"
    ++ STRD ** [ O.Reg IP; O.Reg SP; O.MemPreIdxReg (R0, Some Plus, R8) ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Load unprivileged) Parse test (1)`` () =
    "e070e0fe"
    ++ LDRSHT ** [ O.Reg LR; O.MemPostIdxImm (R0, Some Minus, Some 14L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store unprivileged) Parse test (1)`` () =
    "e4a0100f"
    ++ STRT ** [ O.Reg R1; O.MemPostIdxImm (R0, Some Plus, Some 15L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store unprivileged) Parse test (2)`` () =
    "e02010b4"
    ++ STRHT ** [ O.Reg R1; O.MemPostIdxReg (R0, Some Minus, R4) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Load-Exclusive) Parse test (1)`` () =
    "e190ef9f"
    ++ LDREX ** [ O.Reg LR; O.MemOffsetImm (R0, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store (Store-Exclusive) Parse test (1)`` () =
    "e1a01f92"
    ++ STREXD ** [ O.Reg R1
                   O.Reg R2
                   O.Reg R3
                   O.MemOffsetImm (R0, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (1)`` () =
    "e8100f0c"
    ++ LDMDA ** [ O.Reg R0; O.RegList [ R2; R3; R8; SB; SL; FP ] ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (2)`` () =
    "e8300f0c"
    ++ LDMDA ** [ O.Reg R0; O.RegList [ R2; R3; R8; SB; SL; FP ] ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (3)`` () =
    "e8bd000f"
    ++ POP ** [ O.RegList [ R0; R1; R2; R3 ] ]
    ||> testNoWbackNoQNoSimd Condition.AL

    (*
    "e52d0004"
    ++ STR ** [ O.Reg R0; O.MemPreIdxImm (SP, Some Minus, Some 4L) ]
    ||> testNoQNoSimd Condition.AL (Some true)
    *)

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (4)`` () =
    "e52d0004"
    ++ PUSH ** [ O.RegList [ R0 ] ]
    ||> testNoQNoSimd Condition.AL true

  [<TestMethod>]
  member _.``[ARMv7] Load/store multiple Parse Test (5)`` () =
    "e8c9e000"
    ++ STMIA ** [ O.Reg SB; O.RegList [ SP; LR; PC ] ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (1)`` () =
    "f57ff01f"
    ++ CLREX ** []
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (2)`` () =
    "f57ff05f"
    ++ DMB ** [ O.Option BarrierOption.SY ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (3)`` () =
    "e320f000"
    ++ NOP ** []
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (4)`` () =
    "f55fff00"
    ++ PLD ** [ O.MemLabel -3840L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (5)`` () =
    "f790f1c0"
    ++ PLDW ** [ O.MemOffsetReg (R0, Some Plus, R0, SRTypeASR, 3u) ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (6)`` () =
    "f450f0f0"
    ++ PLI ** [ O.MemLabel -240L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (7)`` () =
    "f1010200"
    ++ SETEND ** [ O.Endian Endian.Big ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Miscellaneous Parse test (8)`` () =
    "e100c09e"
    ++ SWP ** [ O.Reg IP; O.Reg LR; O.MemOffsetImm (R0, None, None) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Exception-gen and exception-handling Parse Test (1)`` () =
    "e120f07c"
    ++ BKPT ** [ O.Imm 3852L ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Exception-gen and exception-handling Parse Test (2)`` () =
    "e160007f"
    ++ SMC ** [ O.Imm 15L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Exception-gen and exception-handling Parse Test (3)`` () =
    "f9bc0a00"
    ++ RFEIB ** [ O.Reg IP ]
    ||> testNoQNoSimd Condition.UN true

  [<TestMethod>]
  member _.``[ARMv7] Exception-gen and exception-handling Parse Test (4)`` () =
    "f96d0504"
    ++ SRSDB ** [ O.Reg SP; O.Imm 4L ]
    ||> testNoQNoSimd Condition.UN true

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (1)`` () =
    (* Only ARMv7 *)
    "ee0123e8"
    ++ CDP ** [ O.Reg P3; O.Imm 0L; O.Reg C2; O.Reg C1; O.Reg C8; O.Imm 7L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (2)`` () =
    "ec401fe3"
    ++ MCRR ** [ O.Reg P15; O.Imm 14L; O.Reg R1; O.Reg R0; O.Reg C3 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (3)`` () =
    "ee9e9e32"
    ++ MRC ** [ O.Reg P14; O.Imm 4L; O.Reg SB; O.Reg C14; O.Reg C2; O.Imm 1L ]
    ||> testNoWbackNoQNoSimd Condition.AL

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (4)`` () =
    "ed9f5e30"
    ++ LDC ** [ O.Reg P14; O.Reg C5; O.MemLabel 192L ]
    ||> testNoQNoSimd Condition.AL false

  [<TestMethod>]
  member _.``[ARMv7] Co-processor Parse test (5)`` () =
    "ec905e80"
    ++ LDC ** [ O.Reg P14; O.Reg C5; O.MemUnIdx (R0, 128L) ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.11.1 Element and structure load/store instructions
  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Parse Test (1)`` () =
    "f4e02f70"
    ++ VLD4 ** [ O.SimdScalarRegs ([ D18; D20; D22; D24 ], None)
                 O.MemPostIdxAlign (R0, Some 64L, Some R0) ]
    ||> testNoQ Condition.UN true (Some (OneDT SIMDTyp16))

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Parse test (2)`` () =
    "f402c690"
    ++ VST1 ** [ O.SimdVectorRegs ([ D12; D13; D14 ])
                 O.MemPostIdxAlign (R2, Some 64L, Some R0) ]
    ||> testNoQ Condition.UN true (Some (OneDT SIMDTyp32))

  [<TestMethod>]
  member _.``[ARMv7] Element and structure load/store Parse test (3)`` () =
    "f48eeac3"
    ++ VST3 ** [ O.SimdScalarRegs ([ D14; D16; D18 ], Some 1uy)
                 O.MemPostIdxReg (LR, None, R3) ]
    ||> testNoQ Condition.UN true (Some (OneDT SIMDTyp32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD and FP register transfer Parse test (1)`` ()
    =
    "ee82ebb0"
    ++ VDUP ** [ O.SimdVectorReg D18; O.Reg LR ]
    ||> testNoWbackNoQ Condition.AL (Some (OneDT SIMDTyp16))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD and FP register transfer Parse test (2)`` ()
    =
    "ee42cbb0"
    ++ VMOV ** [ O.SimdScalarReg (D18, Some 1uy); O.Reg IP ]
    ||> testNoWbackNoQ Condition.AL (Some (OneDT SIMDTyp8))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD and FP register transfer Parse test (3)`` ()
    =
    "ee108bb0"
    ++ VMOV ** [ O.Reg R8; O.SimdScalarReg (D16, Some 0uy) ]
    ||> testNoWbackNoQ Condition.AL (Some (OneDT SIMDTypS16))

  /// A4.13.1 Advanced SIMD parallel addition and subtraction
  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD parallel add and sub Parse test (1)`` () =
    "f2c0c18a"
    ++ VADDW ** [ O.SimdVectorReg Q14; O.SimdVectorReg Q8; O.SimdVectorReg D10 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypS8))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD parallel add and sub Parse test (2)`` () =
    "f320122c"
    ++ VHSUB ** [ O.SimdVectorReg D1; O.SimdVectorReg D0; O.SimdVectorReg D28 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypU32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD parallel add and sub Parse test (3)`` () =
    "f3b0028e"
    ++ VPADDL ** [ O.SimdVectorReg D0; O.SimdVectorReg D14 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypU8))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD parallel add and sub Parse test (4)`` () =
    "f290c682"
    ++ VSUBHN ** [ O.SimdVectorReg D12; O.SimdVectorReg Q8; O.SimdVectorReg Q1 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypI32))

  /// A4.13.2 Bitwise Advanced SIMD data-processing instructions
  [<TestMethod>]
  member _.``[ARMv7] Bitwise Advanced SIMD data-processing Parse test (1)`` ()
    =
    "f242c1f8"
    ++ VAND ** [ O.SimdVectorReg Q14; O.SimdVectorReg Q9; O.SimdVectorReg Q12 ]
    ||> testNoWbackNoQNoSimd Condition.UN

  [<TestMethod>]
  member _.``[ARMv7] Bitwise Advanced SIMD data-processing Parse test (2)`` ()
    =
    "f3c1e57b"
    ++ VBIC ** [ O.SimdVectorReg Q15; O.Imm 0x9B0000L ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypI32))

  [<TestMethod>]
  member _.``[ARMv7] Bitwise Advanced SIMD data-processing Parse test (3)`` ()
    =
    "ee12ca10"
    ++ VMOV ** [ O.Reg IP; O.SimdVectorReg S4 ]
    ||> testNoWbackNoQNoSimd Condition.AL

  /// A4.13.3 Advanced SIMD comparison instructions
  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD comparison Parse test (1)`` () =
    "f24c8e40"
    ++ VCEQ ** [ O.SimdVectorReg Q12; O.SimdVectorReg Q6; O.SimdVectorReg Q0 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypF32))

  /// A4.13.4 Advanced SIMD shift instructions
  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (1)`` () =
    "f3a00950"
    ++ VQRSHRN ** [ O.SimdVectorReg D0; O.SimdVectorReg Q0; O.Imm 32L ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypU64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (2)`` () =
    "f3b80830"
    ++ VQSHRUN ** [ O.SimdVectorReg D0; O.SimdVectorReg Q8; O.Imm 8L ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypS64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (3)`` () =
    "f2b825d8"
    ++ VSHL ** [ O.SimdVectorReg Q1; O.SimdVectorReg Q4; O.Imm 56L ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypI64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (4)`` () =
    "f2a00832"
    ++ VSHRN ** [ O.SimdVectorReg D0; O.SimdVectorReg Q9; O.Imm 32L ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypI64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (5)`` () =
    "f3e801f0"
    ++ VSRA ** [ O.SimdVectorReg Q8; O.SimdVectorReg Q8; O.Imm 24L ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypU64))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD shift Parse test (6)`` () =
    "f3b9943a"
    ++ VSRI ** [ O.SimdVectorReg D9; O.SimdVectorReg D26; O.Imm 7L ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTyp32))

  /// A4.13.5 Advanced SIMD multiply instructions
  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (1)`` () =
    "f3a02a28"
    ++ VMLSL ** [ O.SimdVectorReg Q1; O.SimdVectorReg D0; O.SimdVectorReg D24 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypU32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (2)`` () =
    "ee202aa8"
    ++ VMUL ** [ O.SimdVectorReg S4; O.SimdVectorReg S1; O.SimdVectorReg S17 ]
    ||> testNoWbackNoQ Condition.AL (Some (OneDT SIMDTypF32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (3)`` () =
    "f2c28ca0"
    ++ VMULL ** [ O.SimdVectorReg Q12
                  O.SimdVectorReg D18
                  O.SimdVectorReg D16 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypS8))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (4)`` () =
    "f3e24a4a"
    ++ VMULL ** [ O.SimdVectorReg Q10
                  O.SimdVectorReg D2
                  O.SimdScalarReg (D10, Some 0uy) ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypU32))

  [<TestMethod>]
  member _.``[ARMv7] Advanced SIMD multiply Parse test (5)`` () =
    "f3d02ce8"
    ++ VQDMULH ** [ O.SimdVectorReg Q9
                    O.SimdVectorReg Q8
                    O.SimdScalarReg (D0, Some 3uy) ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypS16))

  /// A4.13.6 Miscellaneous Advanced SIMD data-processing instructions
  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (1)`` () =
    "f3aa0f30"
    ++ VCVT ** [ O.SimdVectorReg D0; O.SimdVectorReg D16; O.Imm 22L ]
    ||> testNoWbackNoQ Condition.UN (Some (TwoDT (SIMDTypU32, SIMDTypF32)))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (2)`` () =
    "eebf0b62"
    ++ VCVT ** [ O.SimdVectorReg D0; O.SimdVectorReg D0; O.Imm 11L ]
    ||> testNoWbackNoQ Condition.AL (Some (TwoDT (SIMDTypU16, SIMDTypF64)))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (3)`` () =
    "f3f0a56e"
    ++ VCNT ** [ O.SimdVectorReg Q13; O.SimdVectorReg Q15 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTyp8))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (4)`` () =
    "f2b003ce"
    ++ VEXT ** [ O.SimdVectorReg Q0
                 O.SimdVectorReg Q8
                 O.SimdVectorReg Q7
                 O.Imm 3L ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTyp8))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (5)`` () =
    "eef10b62"
    ++ VNEG ** [ O.SimdVectorReg D16; O.SimdVectorReg D18 ]
    ||> testNoWbackNoQ Condition.AL (Some (OneDT SIMDTypF64))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (6)`` () =
    "f3409f0f"
    ++ VPMAX ** [ O.SimdVectorReg D25; O.SimdVectorReg D0; O.SimdVectorReg D15 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypF32))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (7)`` () =
    "f3b400c2"
    ++ VREV32 ** [ O.SimdVectorReg Q0; O.SimdVectorReg Q1 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTyp16))

  [<TestMethod>]
  member _.``[ARMv7] Misc Advanced SIMD data-processing Parse test (8)`` () =
    "f3b35b43"
    ++ VTBX ** [ O.SimdVectorReg D5
                 O.SimdVectorRegs [ D3; D4; D5; D6 ]
                 O.SimdVectorReg D3 ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTyp8))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (1)`` () =
    "eeb50bc0"
    ++ VCMPE ** [ O.SimdVectorReg D0; O.Imm 0L ]
    ||> testNoWbackNoQ Condition.AL (Some (OneDT SIMDTypF64))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (2)`` () =
    "eeb82a68"
    ++ VCVT ** [ O.SimdVectorReg S4; O.SimdVectorReg S17 ]
    ||> testNoWbackNoQ Condition.AL (Some (TwoDT (SIMDTypF32, SIMDTypU32)))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (3)`` () =
    "eeb30a43"
    ++ VCVTB ** [ O.SimdVectorReg S0; O.SimdVectorReg S6 ]
    ||> testNoWbackNoQ Condition.AL (Some (TwoDT (SIMDTypF16, SIMDTypF32)))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (4)`` () =
    "eeb23a02"
    ++ VMOV ** [ O.SimdVectorReg S6; O.Imm 1091567616L ]
    ||> testNoWbackNoQ Condition.AL (Some (OneDT SIMDTypF32))

  [<TestMethod>]
  member _.``[ARMv7] Floating-point data-processing Parse test (5)`` () =
    "f3d2c460"
    ++ VMLS ** [ O.SimdVectorReg Q14
                 O.SimdVectorReg Q1
                 O.SimdScalarReg (D0, Some 2uy) ]
    ||> testNoWbackNoQ Condition.UN (Some (OneDT SIMDTypI16))

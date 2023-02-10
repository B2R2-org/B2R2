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
open B2R2.FrontEnd.BinInterface

module ARM64 =
  open B2R2.FrontEnd.BinLifter.ARM64
  open B2R2.FrontEnd.BinLifter.ARM64.OperandHelper

  let private test endian opcode oprs (bytes: byte[]) =
    let reader =
      if endian = Endian.Little then
        BinReader.binReaderLE
      else
        BinReader.binReaderBE
    let span = System.ReadOnlySpan bytes
    let ins = Parser.parse span reader 0UL
    let opcode' = ins.Info.Opcode
    let oprs' = ins.Info.Operands
    Assert.AreEqual (opcode', opcode)
    Assert.AreEqual (oprs', oprs)

  let private test64 = test Endian.Big

  /// C4.2 Data processing - immediate
  [<TestClass>]
  type DataProcessingImmClass () =
    /// C4.2.1 Add/subtract (immediate)
    [<TestMethod>]
    member __.``[AArch64] Add/subtract (immedate) Parse Test`` () =
      test64
        Opcode.ADD
        (FourOperands (
          OprRegister R.W26,
          OprRegister R.W5,
          OprImm 0x371L,
          OprShift (SRTypeLSL, Imm 12L)
        ))
        [| 0x11uy; 0x4duy; 0xc4uy; 0xbauy |]

    /// C4.2.2 Bit Field
    [<TestMethod>]
    member __.``[AArch64] Bitfield Parse Test`` () =
      test64
        Opcode.SBFX
        (FourOperands (
          OprRegister R.W1,
          OprRegister R.W0,
          OprImm 0x1L,
          OprImm 0x1L
        ))
        [| 0x13uy; 0x01uy; 0x04uy; 0x01uy |]

    /// C4.2.3 Extract
    [<TestMethod>]
    member __.``[AArch64] Extract Parse Test`` () =
      test64
        Opcode.EXTR
        (FourOperands (
          OprRegister R.X2,
          OprRegister R.X1,
          OprRegister R.X0,
          OprLSB 0x1uy
        ))
        [| 0x93uy; 0xc0uy; 0x04uy; 0x22uy |]

    /// C4.2.4 Logical (immediate)
    [<TestMethod>]
    member __.``[AArch64] Logical (immedate) Parse Test`` () =
      test64
        Opcode.AND
        (ThreeOperands (
          OprRegister R.W1,
          OprRegister R.W0,
          OprImm 0x80000001L
        ))
        [| 0x12uy; 0x01uy; 0x04uy; 0x01uy |]

      test64
        Opcode.AND
        (ThreeOperands (
          OprRegister R.W1,
          OprRegister R.W0,
          OprImm 0xE0000001L
        ))
        [| 0x12uy; 0x03uy; 0x0cuy; 0x01uy |]

      test64
        Opcode.AND
        (ThreeOperands (OprRegister R.W1, OprRegister R.W0, OprImm 0x3L))
        [| 0x12uy; 0x20uy; 0x04uy; 0x01uy |]

      test64
        Opcode.AND
        (ThreeOperands (
          OprRegister R.W1,
          OprRegister R.W1,
          OprImm 0xffffffdfL
        ))
        [| 0x12uy; 0x1auy; 0x78uy; 0x21uy |]

      test64
        Opcode.AND
        (ThreeOperands (
          OprRegister R.X1,
          OprRegister R.X0,
          OprImm 0x300000003L
        ))
        [| 0x92uy; 0x20uy; 0x04uy; 0x01uy |]

    /// C4.2.5 Move wide (immediate)
    [<TestMethod>]
    member __.``[AArch64] Move wide (immediate) Parse Test`` () =
      test64
        Opcode.MOVN
        (ThreeOperands (
          OprRegister R.X21,
          OprImm 0x0L,
          OprShift (SRTypeLSL, Imm 0x10L)
        ))
        [| 0x92uy; 0xa0uy; 0x00uy; 0x15uy |]

      test64
        Opcode.MOV
        (TwoOperands (OprRegister R.XZR, OprImm 0XE002FFFFFFFFFFFFL))
        [| 0x92uy; 0xe3uy; 0xffuy; 0xbfuy |] (* Alias of MOVN *)

      test64
        Opcode.MOV
        (TwoOperands (OprRegister R.W26, OprImm 0x7FFFFFFFL))
        [| 0x12uy; 0xb0uy; 0x00uy; 0x1auy |] (* Alias of MOVN *)

    /// C4.2.6 PC-rel. addressing
    [<TestMethod>]
    member __.``[AArch64] PC-rel. addressing Parse Test`` () =
      test64
        Opcode.ADR
        (TwoOperands (OprRegister R.X7, memLabel 0xffe0fL))
        [| 0x70uy; 0x7fuy; 0xf0uy; 0x67uy |]

  /// C4.3 Branches, exception generating and system instructions
  [<TestClass>]
  type BranchesAndExcepGenAndSystemClass () =
    /// C4.3.1 Compare & branch (immediate)
    [<TestMethod>]
    member __.``[AArch64] Compare & branch Parse Test`` () =
      test64
        Opcode.CBZ
        (TwoOperands (OprRegister R.X3, memLabel 0x8204L))
        [| 0xb4uy; 0x04uy; 0x10uy; 0x23uy |]

    /// C4.3.2 Conditional branch (immediate)
    [<TestMethod>]
    member __.``[AArch64] Conditional branch (immediate) Parse Test`` () =
      test64
        Opcode.BNE
        (OneOperand (memLabel 0x4L))
        [| 0x54uy; 0x00uy; 0x00uy; 0x21uy |]

    /// C4.3.3 Exception generation
    [<TestMethod>]
    member __.``[AArch64] Exception generation Parse Test`` () =
      test64
        Opcode.SVC
        (OneOperand (OprImm 0x3L))
        [| 0xd4uy; 0x00uy; 0x00uy; 0x61uy |]

    /// C4.3.4 System
    [<TestMethod>]
    member __.``[AArch64] System Parse Test`` () =
      test64
        Opcode.MSR
        (TwoOperands (OprPstate SPSEL, OprImm 0x2L))
        [| 0xd5uy; 0x00uy; 0x42uy; 0xbfuy |]

      test64
        Opcode.MSR
        (TwoOperands (OprPstate DAIFSET, OprImm 0x2L))
        [| 0xd5uy; 0x03uy; 0x42uy; 0xdfuy |]

      test64
        Opcode.HINT
        (OneOperand (OprImm 0x6L))
        [| 0xd5uy; 0x03uy; 0x20uy; 0xdfuy |]

      test64 Opcode.SEVL NoOperand [| 0xd5uy; 0x03uy; 0x20uy; 0xbfuy |]

      test64
        Opcode.DCZVA
        (OneOperand (OprRegister R.X3))
        [| 0xd5uy; 0x0buy; 0x74uy; 0x23uy |]

      test64
        Opcode.SYSL
        (FiveOperands (
          OprRegister R.X24,
          OprImm 0L,
          OprRegister R.C15,
          OprRegister R.C4,
          OprImm 6L
        ))
        [| 0xd5uy; 0x28uy; 0xf4uy; 0xd8uy |]

      test64
        Opcode.MSR
        (TwoOperands (OprRegister (R.HPFAREL2), OprRegister R.X0))
        [| 0xd5uy; 0x1cuy; 0x60uy; 0x80uy |]

      test64
        Opcode.MSR
        (TwoOperands (OprRegister (R.ACTLREL1), OprRegister R.X0))
        [| 0xd5uy; 0x18uy; 0x10uy; 0x20uy |]

      test64
        Opcode.MRS
        (TwoOperands (OprRegister R.X0, OprRegister (R.ACTLREL1)))
        [| 0xd5uy; 0x38uy; 0x10uy; 0x20uy |]

    /// C4.3.5 Test & branch (immediate)
    [<TestMethod>]
    member __.``[AArch64] Test & branch (immediate) Parse Test`` () =
      test64
        Opcode.TBZ
        (ThreeOperands (OprRegister R.X3, OprImm 0x21L, memLabel 0x8L))
        [| 0xb6uy; 0x08uy; 0x00uy; 0x43uy |]

    /// C4.3.6 Unconditional branch (immediate)
    [<TestMethod>]
    member __.``[AArch64] Unconditional branch (immediate) Parse Test`` () =
      test64
        Opcode.B
        (OneOperand (memLabel 0x20a824L))
        [| 0x14uy; 0x08uy; 0x2auy; 0x09uy |]

    /// C4.3.7 Unconditional branch (register)
    [<TestMethod>]
    member __.``[AArch64] Unconditional branch (register) Parse Test`` () =
      test64
        Opcode.BR
        (OneOperand (OprRegister R.XZR))
        [| 0xd6uy; 0x1fuy; 0x03uy; 0xe0uy |]

  /// C4.4 Loads and stores
  [<TestClass>]
  type LoadAndStoreClass () =
    /// C4.4.1 Advanced SIMD load/store multiple structures
    [<TestMethod>]
    member __.``[AArch64] Adv SIMD ld/st multiple structures Parse Test`` () =
      test64
        Opcode.ST4
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V5, EightB);
            SIMDVecReg (R.V6, EightB);
            SIMDVecReg (R.V7, EightB);
            SIMDVecReg (R.V8, EightB) ],
          memBaseImm (R.X14, None)
        ))
        [| 0x0cuy; 0x00uy; 0x01uy; 0xc5uy |]

      test64
        Opcode.ST2
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V24, EightB); SIMDVecReg (R.V25, EightB) ],
          memBaseImm (R.X15, None)
        ))
        [| 0x0cuy; 0x00uy; 0x81uy; 0xf8uy |]

      test64
        Opcode.LD1
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V29, OneD);
            SIMDVecReg (R.V30, OneD);
            SIMDVecReg (R.V31, OneD);
            SIMDVecReg (R.V0, OneD) ],
          memBaseImm (R.X25, None)
        ))
        [| 0x0cuy; 0x40uy; 0x2fuy; 0x3duy |]

    /// C4.4.2 Advanced SIMD load/store multiple structures (post-indexed)
    [<TestMethod>]
    member __.``[AArch64] Adv SIMD ld/st mul struct (post-idx) Parse Test``
      ()
      =
      test64
        Opcode.ST4
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V1, FourH);
            SIMDVecReg (R.V2, FourH);
            SIMDVecReg (R.V3, FourH);
            SIMDVecReg (R.V4, FourH) ],
          memPostIdxReg (R.X1, R.X0, None)
        ))
        [| 0x0cuy; 0x80uy; 0x04uy; 0x21uy |]

      test64
        Opcode.ST4
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V25, FourH);
            SIMDVecReg (R.V26, FourH);
            SIMDVecReg (R.V27, FourH);
            SIMDVecReg (R.V28, FourH) ],
          memPostIdxReg (R.X9, R.X21, None)
        ))
        [| 0x0cuy; 0x95uy; 0x05uy; 0x39uy |]

      test64
        Opcode.ST4
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V4, EightH);
            SIMDVecReg (R.V5, EightH);
            SIMDVecReg (R.V6, EightH);
            SIMDVecReg (R.V7, EightH) ],
          memPostIdxImm (R.X20, Some 0x40L)
        ))
        [| 0x4cuy; 0x9fuy; 0x06uy; 0x84uy |]

      test64
        Opcode.LD3
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V30, EightH);
            SIMDVecReg (R.V31, EightH);
            SIMDVecReg (R.V0, EightH) ],
          memPostIdxReg (R.X21, R.X10, None)
        ))
        [| 0x4cuy; 0xcauy; 0x46uy; 0xbeuy |]

      test64
        Opcode.LD4
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V4, EightH);
            SIMDVecReg (R.V5, EightH);
            SIMDVecReg (R.V6, EightH);
            SIMDVecReg (R.V7, EightH) ],
          memPostIdxImm (R.X20, Some 0x40L)
        ))
        [| 0x4cuy; 0xdfuy; 0x06uy; 0x84uy |]

    /// C4.4.3 Advanced SIMD load/store single structure
    [<TestMethod>]
    member __.``[AArch64] Adv SIMD load/store single structure Parse Test``
      ()
      =
      test64
        Opcode.ST1
        (TwoOperands (
          OprSIMDList [ sVRegIdx R.V30 VecB 5uy ],
          memBaseImm (R.X3, None)
        ))
        [| 0x0duy; 0x00uy; 0x14uy; 0x7euy |]

      test64
        Opcode.ST3
        (TwoOperands (
          OprSIMDList [
            sVRegIdx R.V3 VecB 1uy;
            sVRegIdx R.V4 VecB 1uy;
            sVRegIdx R.V5 VecB 1uy ],
          memBaseImm (R.X14, None)
        ))
        [| 0x0duy; 0x00uy; 0x25uy; 0xc3uy |]

      test64
        Opcode.ST4
        (TwoOperands (
          OprSIMDList [
            sVRegIdx R.V29 VecS 3uy;
            sVRegIdx R.V30 VecS 3uy;
            sVRegIdx R.V31 VecS 3uy;
            sVRegIdx R.V0 VecS 3uy ],
          memBaseImm (R.X21, None)
        ))
        [| 0x4duy; 0x20uy; 0xb2uy; 0xbduy |]

      test64
        Opcode.LD2
        (TwoOperands (
          OprSIMDList [ sVRegIdx R.V10 VecB 0xfuy; sVRegIdx R.V11 VecB 0xfuy ],
          memBaseImm (R.X10, None)
        ))
        [| 0x4duy; 0x60uy; 0x1duy; 0x4auy |]

      test64
        Opcode.LD3R
        (TwoOperands (
          OprSIMDList [
            SIMDVecReg (R.V21, EightH);
            SIMDVecReg (R.V22, EightH);
            SIMDVecReg (R.V23, EightH) ],
          memBaseImm (R.X21, None)
        ))
        [| 0x4duy; 0x40uy; 0xe6uy; 0xb5uy |]

    /// C4.4.4 Advanced SIMD load/store single structure (post-indexed)
    [<TestMethod>]
    member __.``[AArch64] Adv SIMD ld/st sgl struct (post-idx) Parse Test``
      ()
      =
      test64
        Opcode.ST1
        (TwoOperands (
          OprSIMDList [ sVRegIdx R.V30 VecB 1uy ],
          memPostIdxReg (R.X21, R.X10, None)
        ))
        [| 0x0duy; 0x8auy; 0x06uy; 0xbeuy |]

      test64
        Opcode.ST1
        (TwoOperands (
          OprSIMDList [ sVRegIdx R.V30 VecH 7uy ],
          memPostIdxImm (R.X11, Some 0x2L)
        ))
        [| 0x4duy; 0x9fuy; 0x59uy; 0x7euy |]

      test64
        Opcode.ST2
        (TwoOperands (
          OprSIMDList [ sVRegIdx R.V29 VecS 2uy; sVRegIdx R.V30 VecS 2uy ],
          memPostIdxReg (R.X13, R.X21, None)
        ))
        [| 0x4duy; 0xb5uy; 0x81uy; 0xbduy |]

      test64
        Opcode.LD1
        (TwoOperands (
          OprSIMDList [ sVRegIdx R.V30 VecB 1uy ],
          memPostIdxReg (R.X21, R.X10, None)
        ))
        [| 0x0duy; 0xcauy; 0x06uy; 0xbeuy |]

      test64
        Opcode.LD4
        (TwoOperands (
          OprSIMDList [
            sVRegIdx R.V29 VecB 0xeuy;
            sVRegIdx R.V30 VecB 0xeuy;
            sVRegIdx R.V31 VecB 0xeuy;
            sVRegIdx R.V0 VecB 0xeuy ],
          memPostIdxImm (R.X15, Some 0x4L)
        ))
        [| 0x4duy; 0xffuy; 0x39uy; 0xfduy |]

    /// C4.4.5 Load register (literal)
    [<TestMethod>]
    member __.``[AArch64] Load register (literal) Parse Test`` () =
      test64
        Opcode.LDR
        (TwoOperands (OprRegister R.X9, memLabel 0xa6388L))
        [| 0x58uy; 0x53uy; 0x1cuy; 0x49uy |]

      test64
        Opcode.LDRSW
        (TwoOperands (OprRegister R.X30, memLabel 0xfffffffffff00000L))
        [| 0x98uy; 0x80uy; 0x00uy; 0x1euy |]

      test64
        Opcode.PRFM
        (TwoOperands (OprPrfOp PLIL2STRM, memLabel 0x1004L))
        [| 0xd8uy; 0x00uy; 0x80uy; 0x2buy |]

    /// C4.4.6 Load/store exclusive
    [<TestMethod>]
    member __.``[AArch64] Load/store exclusive Parse Test`` () =
      test64
        Opcode.STXRB
        (ThreeOperands (
          OprRegister R.W20,
          OprRegister R.W21,
          memBaseImm (R.X5, None)
        ))
        [| 0x08uy; 0x14uy; 0x7cuy; 0xb5uy |]

      test64
        Opcode.STXP
        (FourOperands (
          OprRegister R.W11,
          OprRegister R.W2,
          OprRegister R.W1,
          memBaseImm (R.X6, None)
        ))
        [| 0x88uy; 0x2buy; 0x04uy; 0xc2uy |]

      test64
        Opcode.LDXRB
        (TwoOperands (OprRegister R.W26, memBaseImm (R.X11, None)))
        [| 0x08uy; 0x5fuy; 0x7duy; 0x7auy |]

    /// C4.4.7 Load/store no-allocate pair (offset)
    [<TestMethod>]
    member __.``[AArch64] Load/store no-allocate pair (offset) Parse Test``
      ()
      =
      test64
        Opcode.STNP
        (ThreeOperands (
          OprRegister R.W3,
          OprRegister R.W10,
          memBaseImm (R.X21, Some 0x60L)
        ))
        [| 0x28uy; 0x0cuy; 0x2auy; 0xa3uy |]

      test64
        Opcode.STNP
        (ThreeOperands (
          scalReg R.Q21,
          scalReg R.Q1,
          memBaseImm (R.X13, Some 0x2a0L)
        ))
        [| 0xacuy; 0x15uy; 0x05uy; 0xb5uy |]

    /// C4.4.8 Load/store register (immediate post-indexed)
    [<TestMethod>]
    member __.``[AArch64] Load/store register (imm post-idx) Parse Test`` () =
      test64
        Opcode.STRB
        (TwoOperands (
          OprRegister R.W3,
          memPostIdxImm (R.X1, Some 0xffffffffffffff0aL)
        ))
        [| 0x38uy; 0x10uy; 0xa4uy; 0x23uy |]

      test64
        Opcode.LDRSB
        (TwoOperands (OprRegister R.W18, memPostIdxImm (R.X5, Some 0xeaL)))
        [| 0x38uy; 0xceuy; 0xa4uy; 0xb2uy |]

      test64
        Opcode.STR
        (TwoOperands (scalReg R.H2, memPostIdxImm (R.X1, Some 0xcaL)))
        [| 0x7cuy; 0x0cuy; 0xa4uy; 0x22uy |]

      test64
        Opcode.STRH
        (TwoOperands (
          OprRegister R.W21,
          memPostIdxImm (R.X7, Some 0xffffffffffffff00L)
        ))
        [| 0x78uy; 0x10uy; 0x04uy; 0xf5uy |]

      test64
        Opcode.LDRSW
        (TwoOperands (OprRegister R.X21, memPostIdxImm (R.X10, Some 0x3L)))
        [| 0xb8uy; 0x80uy; 0x35uy; 0x55uy |]

    /// C4.4.9 Load/store register (immediate pre-indexed)
    [<TestMethod>]
    member __.``[AArch64] Load/store register (imm pre-idx) Parse Test`` () =
      test64
        Opcode.STRB
        (TwoOperands (OprRegister R.W17, memPreIdxImm (R.X5, Some 0xfL)))
        [| 0x38uy; 0x00uy; 0xfcuy; 0xb1uy |]

      test64
        Opcode.STR
        (TwoOperands (scalReg R.H10, memPreIdxImm (R.X3, Some 0xfL)))
        [| 0x7cuy; 0x00uy; 0xfcuy; 0x6auy |]

    /// C4.4.10 Load/store register (register offset)
    [<TestMethod>]
    member __.``[AArch64] Load/store register (reg offset) Parse Test`` () =
      test64
        Opcode.STRB
        (TwoOperands (
          OprRegister R.W7,
          memBaseReg (R.X3, R.W1, Some (ExtRegOffset (ExtUXTW, None)))
        ))
        [| 0x38uy; 0x21uy; 0x48uy; 0x67uy |]

      test64
        Opcode.STRB
        (TwoOperands (
          OprRegister R.W7,
          memBaseReg (R.X3, R.W3, Some (ExtRegOffset (ExtUXTW, Some 0x0L)))
        ))
        [| 0x38uy; 0x23uy; 0x58uy; 0x67uy |]

      test64
        Opcode.STRB
        (TwoOperands (
          OprRegister R.W12,
          memBaseReg (R.X1, R.X0, Some (ShiftOffset (SRTypeLSL, Imm 0x0L)))
        ))
        [| 0x38uy; 0x20uy; 0x78uy; 0x2cuy |]

      test64
        Opcode.LDRH
        (TwoOperands (
          OprRegister R.WZR,
          memBaseReg (R.X21, R.W7, Some (ExtRegOffset (ExtSXTW, None)))
        ))
        [| 0x78uy; 0x67uy; 0xcauy; 0xbfuy |]

      test64
        Opcode.LDRSH
        (TwoOperands (
          OprRegister R.W17,
          memBaseReg (R.X3, R.X3, Some (ShiftOffset (SRTypeLSL, Imm 0x1L)))
        ))
        [| 0x78uy; 0xe3uy; 0x78uy; 0x71uy |]

      test64
        Opcode.PRFM
        (TwoOperands (
          OprImm 0x7L,
          memBaseReg (R.X3, R.W3, Some (ExtRegOffset (ExtUXTW, Some 0x3L)))
        ))
        [| 0xf8uy; 0xa3uy; 0x58uy; 0x67uy |]

      test64
        Opcode.PRFM
        (TwoOperands (
          OprPrfOp PLIL3KEEP,
          memBaseReg (R.X3, R.W3, Some (ExtRegOffset (ExtUXTW, Some 0x3L)))
        ))
        [| 0xf8uy; 0xa3uy; 0x58uy; 0x6cuy |]

    /// C4.4.11 Load/store register (unprivileged)
    [<TestMethod>]
    member __.``[AArch64] Load/store register (unprivileged) Parse Test`` () =
      test64
        Opcode.STTRB
        (TwoOperands (OprRegister R.W14, memBaseImm (R.X7, Some 0x19L)))
        [| 0x38uy; 0x01uy; 0x98uy; 0xeeuy |]

      test64
        Opcode.STTRH
        (TwoOperands (
          OprRegister R.W26,
          memBaseImm (R.X5, Some 0xffffffffffffff18L)
        ))
        [| 0x78uy; 0x11uy; 0x88uy; 0xbauy |]

      test64
        Opcode.LDTRSW
        (TwoOperands (OprRegister R.X10, memBaseImm (R.X3, Some 0x1fL)))
        [| 0xb8uy; 0x81uy; 0xf8uy; 0x6auy |]

    /// C4.4.12 Load/store register (unscaled immediate)
    [<TestMethod>]
    member __.``[AArch64] Load/store register (unscaled imm) Parse Test`` () =
      test64
        Opcode.STURB
        (TwoOperands (OprRegister R.W24, memBaseImm (R.X7, Some 0x6aL)))
        [| 0x38uy; 0x06uy; 0xa0uy; 0xf8uy |]

      test64
        Opcode.LDUR
        (TwoOperands (scalReg R.Q3, memBaseImm (R.X20, Some 0xe0L)))
        [| 0x3cuy; 0xceuy; 0x02uy; 0x83uy |]

      test64
        Opcode.PRFUM
        (TwoOperands (OprImm 0x1cL, memBaseImm (R.X3, Some 0x1fL)))
        [| 0xf8uy; 0x81uy; 0xf0uy; 0x7cuy |]

    /// C4.4.13 Load/store register (unsigned immediate)
    [<TestMethod>]
    member __.``[AArch64] Load/store register (unsigned imm) Parse Test`` () =
      test64
        Opcode.STRB
        (TwoOperands (OprRegister R.WZR, memBaseImm (R.SP, Some 0x555L)))
        [| 0x39uy; 0x15uy; 0x57uy; 0xffuy |]

      test64
        Opcode.STR
        (TwoOperands (scalReg R.S31, memBaseImm (R.SP, Some 0x1ffcL)))
        [| 0xbduy; 0x1fuy; 0xffuy; 0xffuy |]

      test64
        Opcode.PRFM
        (TwoOperands (OprPrfOp PSTL2KEEP, memBaseImm (R.X15, Some 0x7c00L)))
        [| 0xf9uy; 0xbeuy; 0x01uy; 0xf2uy |]

    /// C4.4.14 Load/store register pair (offset)
    [<TestMethod>]
    member __.``[AArch64] Load/store register pair (offset) Parse Test`` () =
      test64
        Opcode.LDP
        (ThreeOperands (
          OprRegister R.W25,
          OprRegister R.W18,
          memBaseImm (R.X29, Some 0xffffffffffffff0cL)
        ))
        [| 0x29uy; 0x61uy; 0xcbuy; 0xb9uy |]

    /// C4.4.15 Load/store register pair (post-indexed)
    [<TestMethod>]
    member __.``[AArch64] Load/store register pair (post-idx) Parse Test`` () =
      test64
        Opcode.STP
        (ThreeOperands (
          OprRegister R.X11,
          OprRegister R.X21,
          memPostIdxImm (R.SP, Some 0x1f8L)
        ))
        [| 0xa8uy; 0x9fuy; 0xd7uy; 0xebuy |]

      test64
        Opcode.LDPSW
        (ThreeOperands (
          OprRegister R.XZR,
          OprRegister R.X23,
          memPostIdxImm (R.X30, Some 0x7cL)
        ))
        [| 0x68uy; 0xcfuy; 0xdfuy; 0xdfuy |]

    /// C4.4.16 Load/store register pair (pre-indexed)
    [<TestMethod>]
    member __.``[AArch64] Load/store register pair (pre-idx) Parse Test`` () =
      test64
        Opcode.STP
        (ThreeOperands (
          OprRegister R.XZR,
          OprRegister R.XZR,
          memPreIdxImm (R.SP, Some 0x1f8L)
        ))
        [| 0xa9uy; 0x9fuy; 0xffuy; 0xffuy |]

  /// C4.5 Data processing - register
  [<TestClass>]
  type DataPorcessingRegClass () =
    /// C4.5.1 Add/subtract (extended register)
    [<TestMethod>]
    member __.``[AArch64] Add/subtract (extended register) Parse Test`` () =
      test64
        Opcode.ADD
        (FourOperands (
          OprRegister R.WSP,
          OprRegister R.WSP,
          OprRegister R.WZR,
          OprExtReg None
        ))
        [| 0x0buy; 0x3fuy; 0x43uy; 0xffuy |]

      test64
        Opcode.ADD
        (FourOperands (
          OprRegister R.WSP,
          OprRegister R.WSP,
          OprRegister R.WZR,
          OprExtReg (Some (ShiftOffset (SRTypeLSL, Imm 2L)))
        ))
        [| 0x0buy; 0x3fuy; 0x4buy; 0xffuy |]

      test64
        Opcode.ADD
        (FourOperands (
          OprRegister R.SP,
          OprRegister R.X10,
          OprRegister R.W10,
          OprExtReg (Some (ExtRegOffset (ExtUXTW, Some 2L)))
        ))
        [| 0x8buy; 0x2auy; 0x49uy; 0x5fuy |]

      test64
        Opcode.CMN
        (ThreeOperands (
          OprRegister R.SP,
          OprRegister R.X14,
          OprExtReg (Some (ShiftOffset (SRTypeLSL, Imm 1L)))
        ))
        [| 0xabuy; 0x2euy; 0x67uy; 0xffuy |]

    /// C4.5.2 Add/subtract (shifted register)
    [<TestMethod>]
    member __.``[AArch64] Add/subtract (shifted register) Parse Test`` () =
      test64
        Opcode.ADD
        (FourOperands (
          OprRegister R.W27,
          OprRegister R.W28,
          OprRegister R.W14,
          OprShift (SRTypeASR, Imm 23L)
        ))
        [| 0x0buy; 0x8euy; 0x5fuy; 0x9buy |]

      test64
        Opcode.SUBS
        (FourOperands (
          OprRegister R.W11,
          OprRegister R.W29,
          OprRegister R.W14,
          OprShift (SRTypeLSR, Imm 7L)
        ))
        [| 0x6buy; 0x4euy; 0x1fuy; 0xabuy |]

      test64
        Opcode.ADDS
        (FourOperands (
          OprRegister R.X18,
          OprRegister R.X29,
          OprRegister R.X14,
          OprShift (SRTypeASR, Imm 7L)
        ))
        [| 0xabuy; 0x8euy; 0x1fuy; 0xb2uy |]

    /// C4.5.3 Add/subtract (with carry)
    [<TestMethod>]
    member __.``[AArch64] Add/subtract (with carry) Parse Test`` () =
      test64
        Opcode.ADCS
        (ThreeOperands (
          OprRegister R.XZR,
          OprRegister R.X21,
          OprRegister R.X10
        ))
        [| 0xbauy; 0x0auy; 0x02uy; 0xbfuy |]

      test64
        Opcode.NGC
        (TwoOperands (OprRegister R.W30, OprRegister R.W11))
        [| 0x5auy; 0x0buy; 0x03uy; 0xfeuy |]

    /// C4.5.4 Conditional compare (immediate)
    [<TestMethod>]
    member __.``[AArch64] Conditional compare (immediate) Parse Test`` () =
      test64
        Opcode.CCMN
        (FourOperands (OprRegister R.X3, OprImm 0x15L, OprNZCV 8uy, OprCond GT))
        [| 0xbauy; 0x55uy; 0xc8uy; 0x68uy |]

    /// C4.5.5 Conditional compare (register)
    [<TestMethod>]
    member __.``[AArch64] Conditional compare (register) Parse Test`` () =
      test64
        Opcode.CCMN
        (FourOperands (
          OprRegister R.X15,
          OprRegister R.X28,
          OprNZCV 0xfuy,
          OprCond PL
        ))
        [| 0xbauy; 0x5cuy; 0x51uy; 0xefuy |]

    /// C4.5.6 Conditional select
    [<TestMethod>]
    member __.``[AArch64] Conditional select Parse Test`` () =
      test64
        Opcode.CSEL
        (FourOperands (
          OprRegister R.X28,
          OprRegister R.X23,
          OprRegister R.X6,
          OprCond LS
        ))
        [| 0x9auy; 0x86uy; 0x92uy; 0xfcuy |]

      test64
        Opcode.CSINC
        (FourOperands (
          OprRegister R.W21,
          OprRegister R.W0,
          OprRegister R.W16,
          OprCond CS
        )) // HS
        [| 0x1auy; 0x90uy; 0x24uy; 0x15uy |]

      test64
        Opcode.CINC
        (ThreeOperands (OprRegister R.W21, OprRegister R.W16, OprCond CC)) // LO
        [| 0x1auy; 0x90uy; 0x26uy; 0x15uy |]

      test64
        Opcode.CSET
        (TwoOperands (OprRegister R.W7, OprCond LE))
        [| 0x1auy; 0x9fuy; 0xc7uy; 0xe7uy |]

      test64
        Opcode.CINV
        (ThreeOperands (OprRegister R.X10, OprRegister R.X7, OprCond LE))
        [| 0xdauy; 0x87uy; 0xc0uy; 0xeauy |]

      test64
        Opcode.CSETM
        (TwoOperands (OprRegister R.X10, OprCond LE))
        [| 0xdauy; 0x9fuy; 0xc3uy; 0xeauy |]

      test64
        Opcode.CSINV
        (FourOperands (
          OprRegister R.X10,
          OprRegister R.X27,
          OprRegister R.XZR,
          OprCond GT
        ))
        [| 0xdauy; 0x9fuy; 0xc3uy; 0x6auy |]

      test64
        Opcode.CSNEG
        (FourOperands (
          OprRegister R.W30,
          OprRegister R.W21,
          OprRegister R.W10,
          OprCond AL
        ))
        [| 0x5auy; 0x8auy; 0xe6uy; 0xbeuy |]

      test64
        Opcode.CNEG
        (ThreeOperands (OprRegister R.W30, OprRegister R.W21, OprCond LE))
        [| 0x5auy; 0x95uy; 0xc6uy; 0xbeuy |]

    /// C4.5.7 Data-processing (1 source)
    [<TestMethod>]
    member __.``[AArch64] Data-processing (1 source) Parse Test`` () =
      test64
        Opcode.RBIT
        (TwoOperands (OprRegister R.W28, OprRegister R.W11))
        [| 0x5auy; 0xc0uy; 0x01uy; 0x7cuy |]

      test64
        Opcode.CLS
        (TwoOperands (OprRegister R.XZR, OprRegister R.X11))
        [| 0xdauy; 0xc0uy; 0x15uy; 0x7fuy |]

      test64
        Opcode.REV32
        (TwoOperands (OprRegister R.X30, OprRegister R.X15))
        [| 0xdauy; 0xc0uy; 0x09uy; 0xfeuy |]

    /// C4.5.8 Data-processing (2 source)
    [<TestMethod>]
    member __.``[AArch64] Data-processing (2 source) Parse Test`` () =
      test64
        Opcode.UDIV
        (ThreeOperands (OprRegister R.W30, OprRegister R.W23, OprRegister R.W9))
        [| 0x1auy; 0xc9uy; 0x0auy; 0xfeuy |]

      test64
        Opcode.CRC32CX
        (ThreeOperands (OprRegister R.W29, OprRegister R.W3, OprRegister R.X26))
        [| 0x9auy; 0xdauy; 0x5cuy; 0x7duy |]

    /// C4.5.9 Data-processing (3 source)
    [<TestMethod>]
    member __.``[AArch64] Data-processing (3 source) Parse Test`` () =
      test64
        Opcode.MADD
        (FourOperands (
          OprRegister R.X7,
          OprRegister R.X28,
          OprRegister R.X10,
          OprRegister R.X11
        ))
        [| 0x9buy; 0x0auy; 0x2fuy; 0x87uy |]

      test64
        Opcode.MUL
        (ThreeOperands (OprRegister R.X7, OprRegister R.X28, OprRegister R.X10))
        [| 0x9buy; 0x0auy; 0x7fuy; 0x87uy |] (* Alias of MADD *)

      test64
        Opcode.MSUB
        (FourOperands (
          OprRegister R.X7,
          OprRegister R.X28,
          OprRegister R.X10,
          OprRegister R.X11
        ))
        [| 0x9buy; 0x0auy; 0xafuy; 0x87uy |]

      test64
        Opcode.SMADDL
        (FourOperands (
          OprRegister R.X7,
          OprRegister R.W28,
          OprRegister R.W10,
          OprRegister R.X11
        ))
        [| 0x9buy; 0x2auy; 0x2fuy; 0x87uy |]

      test64
        Opcode.SMSUBL
        (FourOperands (
          OprRegister R.X7,
          OprRegister R.W28,
          OprRegister R.W10,
          OprRegister R.X11
        ))
        [| 0x9buy; 0x2auy; 0xafuy; 0x87uy |]

      test64
        Opcode.SMULH
        (ThreeOperands (OprRegister R.X7, OprRegister R.X28, OprRegister R.X10))
        [| 0x9buy; 0x4auy; 0x2fuy; 0x87uy |]

      test64
        Opcode.UMADDL
        (FourOperands (
          OprRegister R.X7,
          OprRegister R.W28,
          OprRegister R.W10,
          OprRegister R.X11
        ))
        [| 0x9buy; 0xaauy; 0x2fuy; 0x87uy |]

      test64
        Opcode.UMSUBL
        (FourOperands (
          OprRegister R.X7,
          OprRegister R.W28,
          OprRegister R.W10,
          OprRegister R.X11
        ))
        [| 0x9buy; 0xaauy; 0xafuy; 0x87uy |]

      test64
        Opcode.UMULH
        (ThreeOperands (OprRegister R.X7, OprRegister R.X28, OprRegister R.X10))
        [| 0x9buy; 0xcauy; 0x2fuy; 0x87uy |]

      test64
        Opcode.MNEG
        (ThreeOperands (OprRegister R.X7, OprRegister R.X28, OprRegister R.X10))
        [| 0x9buy; 0x0auy; 0xffuy; 0x87uy |] (* Alias of MSUB *)

      test64
        Opcode.SMULL
        (ThreeOperands (OprRegister R.X7, OprRegister R.W28, OprRegister R.W10))
        [| 0x9buy; 0x2auy; 0x7fuy; 0x87uy |] (* Alias of SMADDL *)

      test64
        Opcode.SMNEGL
        (ThreeOperands (OprRegister R.X7, OprRegister R.W28, OprRegister R.W10))
        [| 0x9buy; 0x2auy; 0xffuy; 0x87uy |] (* Alias of SMSUBL *)

      test64
        Opcode.UMULL
        (ThreeOperands (OprRegister R.X7, OprRegister R.W28, OprRegister R.W10))
        [| 0x9buy; 0xaauy; 0x7fuy; 0x87uy |] (* Alias of UMADDL *)

      test64
        Opcode.UMNEGL
        (ThreeOperands (OprRegister R.X7, OprRegister R.W28, OprRegister R.W10))
        [| 0x9buy; 0xaauy; 0xffuy; 0x87uy |] (* Alias of UMSUBL *)

    /// C4.5.10 Logical (shifted register)
    [<TestMethod>]
    member __.``[AArch64] Logical (shifted register) Parse Test`` () =
      test64
        Opcode.AND
        (FourOperands (
          OprRegister R.X5,
          OprRegister R.X10,
          OprRegister R.X24,
          OprShift (SRTypeLSR, Imm 14L)
        ))
        [| 0x8auy; 0x58uy; 0x39uy; 0x45uy |]

      test64
        Opcode.ORN
        (FourOperands (
          OprRegister R.W26,
          OprRegister R.W29,
          OprRegister R.W22,
          OprShift (SRTypeROR, Imm 7L)
        ))
        [| 0x2auy; 0xf6uy; 0x1fuy; 0xbauy |]

      test64
        Opcode.MVN
        (ThreeOperands (
          OprRegister R.W26,
          OprRegister R.W22,
          OprShift (SRTypeROR, Imm 0x7L)
        ))
        [| 0x2auy; 0xf6uy; 0x1fuy; 0xfauy |]

  /// C4.6 Data processing - SIMD and floating point
  [<TestClass>]
  type DataProcessingSIMDAndFPClass () =
    /// C4.6.1 Advanced SIMD across lanes
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD across lanes Parse Test`` () =
      test64
        Opcode.SADDLV
        (TwoOperands (
          scalReg R.D2,
          OprSIMD (SIMDVecReg (R.V22, FourS))
        ))
        [| 0x4euy; 0xb0uy; 0x3auy; 0xc2uy |]

      test64
        Opcode.SMAXV
        (TwoOperands (
          scalReg R.B18,
          OprSIMD (SIMDVecReg (R.V6, EightB))
        ))
        [| 0x0euy; 0x30uy; 0xa8uy; 0xd2uy |]

      test64
        Opcode.SMINV
        (TwoOperands (
          scalReg R.H10,
          OprSIMD (SIMDVecReg (R.V16, FourH))
        ))
        [| 0x0euy; 0x71uy; 0xaauy; 0x0auy |]

      test64
        Opcode.ADDV
        (TwoOperands (
          scalReg R.H26,
          OprSIMD (SIMDVecReg (R.V4, EightH))
        ))
        [| 0x4euy; 0x71uy; 0xb8uy; 0x9auy |]

      test64
        Opcode.UADDLV
        (TwoOperands (
          scalReg R.D17,
          OprSIMD (SIMDVecReg (R.V9, FourS))
        ))
        [| 0x6euy; 0xb0uy; 0x39uy; 0x31uy |]

      test64
        Opcode.UMAXV
        (TwoOperands (
          scalReg R.H8,
          OprSIMD (SIMDVecReg (R.V28, FourH))
        ))
        [| 0x2euy; 0x70uy; 0xabuy; 0x88uy |]

      test64
        Opcode.UMINV
        (TwoOperands (
          scalReg R.S10,
          OprSIMD (SIMDVecReg (R.V23, FourS))
        ))
        [| 0x6euy; 0xb1uy; 0xaauy; 0xeauy |]

      test64
        Opcode.FMAXNMV
        (TwoOperands (
          scalReg R.S11,
          OprSIMD (SIMDVecReg (R.V18, FourS))
        ))
        [| 0x6euy; 0x30uy; 0xcauy; 0x4buy |]

      test64
        Opcode.FMAXV
        (TwoOperands (
          scalReg R.S8,
          OprSIMD (SIMDVecReg (R.V10, FourS))
        ))
        [| 0x6euy; 0x30uy; 0xf9uy; 0x48uy |]

      test64
        Opcode.FMINNMV
        (TwoOperands (
          scalReg R.S12,
          OprSIMD (SIMDVecReg (R.V22, FourS))
        ))
        [| 0x6euy; 0xb0uy; 0xcauy; 0xccuy |]

      test64
        Opcode.FMINV
        (TwoOperands (
          scalReg R.S2,
          OprSIMD (SIMDVecReg (R.V22, FourS))
        ))
        [| 0x6euy; 0xb0uy; 0xfauy; 0xc2uy |]

    /// C4.6.2 Advanced SIMD copy
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD copy Parse Test`` () =
      test64
        Opcode.DUP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V6, TwoD)),
          OprSIMD (sVRegIdx R.V4 VecD 1uy)
        ))
        [| 0x4euy; 0x18uy; 0x04uy; 0x86uy |]

      test64
        Opcode.DUP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V1, TwoD)),
          OprRegister R.X3
        ))
        [| 0x4euy; 0x08uy; 0x0cuy; 0x61uy |]

      test64
        Opcode.DUP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V28, FourH)),
          OprRegister R.WZR
        )) // Online HEX To ARM Conv error
        [| 0x0euy; 0x1euy; 0x0fuy; 0xfcuy |]

      test64
        Opcode.DUP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V28, FourH)),
          OprRegister R.WZR
        ))
        [| 0x0euy; 0x02uy; 0x0fuy; 0xfcuy |]

      test64
        Opcode.SMOV
        (TwoOperands (
          OprRegister R.W26,
          OprSIMD (sVRegIdx R.V7 VecH 0uy)
        ))
        [| 0x0euy; 0x02uy; 0x2cuy; 0xfauy |]

      test64
        Opcode.UMOV
        (TwoOperands (
          OprRegister R.W3,
          OprSIMD (sVRegIdx R.V14 VecB 0uy)
        ))
        [| 0x0euy; 0x01uy; 0x3duy; 0xc3uy |]

      test64
        Opcode.MOV
        (TwoOperands (
          OprRegister R.W3,
          OprSIMD (sVRegIdx R.V14 VecS 0uy)
        ))
        [| 0x0euy; 0x04uy; 0x3duy; 0xc3uy |]

      test64
        Opcode.MOV
        (TwoOperands (
          OprRegister R.X3,
          OprSIMD (sVRegIdx R.V14 VecD 0uy)
        ))
        [| 0x4euy; 0x08uy; 0x3duy; 0xc3uy |]

      test64
        Opcode.INS
        (TwoOperands (
          OprSIMD (sVRegIdx R.V9 VecS 0uy),
          OprRegister R.W1
        ))
        [| 0x4euy; 0x04uy; 0x1cuy; 0x29uy |]

      test64
        Opcode.INS
        (TwoOperands (
          OprSIMD (sVRegIdx R.V5 VecH 0uy),
          OprSIMD (sVRegIdx R.V6 VecH 7uy)
        ))
        [| 0x6euy; 0x02uy; 0x74uy; 0xc5uy |]

    /// C4.6.3 Advanced SIMD extract
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD extract Parse Test`` () =
      test64
        Opcode.EXT
        (FourOperands (
          OprSIMD (SIMDVecReg (R.V3, SixteenB)),
          OprSIMD (SIMDVecReg (R.V12, SixteenB)),
          OprSIMD (SIMDVecReg (R.V6, SixteenB)),
          OprImm 9L
        ))
        [| 0x6euy; 0x06uy; 0x49uy; 0x83uy |]

      test64
        Opcode.EXT
        (FourOperands (
          OprSIMD (SIMDVecReg (R.V28, EightB)),
          OprSIMD (SIMDVecReg (R.V7, EightB)),
          OprSIMD (SIMDVecReg (R.V7, EightB)),
          OprImm 7L
        ))
        [| 0x2euy; 0x07uy; 0x38uy; 0xfcuy |]

    /// C4.6.4 Advanced SIMD modified immediate
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD modified immediate Parse Test`` () =
      test64
        Opcode.MOVI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, FourS)),
          OprImm 0xAAL,
          OprShift (SRTypeLSL, Imm 24L)
        ))
        [| 0x4fuy; 0x05uy; 0x65uy; 0x59uy |]

      test64
        Opcode.MOVI
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V25, FourS)),
          OprImm 0xAAL
        ))
        [| 0x4fuy; 0x05uy; 0x05uy; 0x59uy |]

      test64
        Opcode.ORR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprImm 0x46L,
          OprShift (SRTypeLSL, Imm 8L)
        ))
        [| 0x4fuy; 0x02uy; 0x34uy; 0xc5uy |]

      test64
        Opcode.MOVI
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V25, SixteenB)),
          OprImm 0x2EL
        ))
        [| 0x4fuy; 0x01uy; 0xe5uy; 0xd9uy |]

      test64
        Opcode.ORR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourH)),
          OprImm 0xC7L,
          OprShift (SRTypeLSL, Imm 8L)
        ))
        [| 0x0fuy; 0x06uy; 0xb4uy; 0xe5uy |]

      test64
        Opcode.MOVI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, EightH)),
          OprImm 0x9AL,
          OprShift (SRTypeLSL, Imm 8L)
        ))
        [| 0x4fuy; 0x04uy; 0xa7uy; 0x59uy |]

      test64
        Opcode.MOVI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprImm 0xB2L,
          OprShift (SRTypeMSL, Imm 8L)
        ))
        [| 0x4fuy; 0x05uy; 0xc6uy; 0x55uy |]

      test64
        Opcode.FMOV
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprFPImm -11.5
        ))
        [| 0x4fuy; 0x05uy; 0xf4uy; 0xe5uy |]

      test64
        Opcode.MVNI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprImm 0xE6L,
          OprShift (SRTypeLSL, Imm 8L)
        ))
        [| 0x6fuy; 0x07uy; 0x24uy; 0xd5uy |]

      test64
        Opcode.BIC
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V7, TwoS)),
          OprImm 0xB5L,
          OprShift (SRTypeLSL, Imm 8L)
        ))
        [| 0x2fuy; 0x05uy; 0x36uy; 0xa7uy |]

      test64
        Opcode.MVNI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprImm 0xE6L,
          OprShift (SRTypeLSL, Imm 8L)
        ))
        [| 0x6fuy; 0x07uy; 0xa4uy; 0xd5uy |]

      test64
        Opcode.BIC
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V7, FourH)),
          OprImm 0xB5L
        ))
        [| 0x2fuy; 0x05uy; 0x96uy; 0xa7uy |]

      test64
        Opcode.MVNI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprImm 0xE6L,
          OprShift (SRTypeMSL, Imm 8L)
        ))
        [| 0x6fuy; 0x07uy; 0xc4uy; 0xd5uy |]

      test64
        Opcode.MOVI
        (TwoOperands (scalReg R.D27, OprImm 0xFF00FFFFFF00FF00L))
        [| 0x2fuy; 0x05uy; 0xe7uy; 0x5buy |]

      test64
        Opcode.MOVI
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V23, TwoD)),
          OprImm 0xFF00FFFFFF00FF00L
        ))
        [| 0x6fuy; 0x05uy; 0xe7uy; 0x57uy |]

      test64
        Opcode.FMOV
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprFPImm -11.5
        ))
        [| 0x6fuy; 0x05uy; 0xf4uy; 0xe5uy |]

    /// C4.6.5 Advanced SIMD permute
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD permute Parse Test`` () =
      test64
        Opcode.UZP1
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V3, EightH)),
          OprSIMD (SIMDVecReg (R.V12, EightH)),
          OprSIMD (SIMDVecReg (R.V14, EightH))
        ))
        [| 0x4euy; 0x4euy; 0x19uy; 0x83uy |]

      test64
        Opcode.TRN1
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V30, TwoS)),
          OprSIMD (SIMDVecReg (R.V7, TwoS)),
          OprSIMD (SIMDVecReg (R.V7, TwoS))
        ))
        [| 0x0euy; 0x87uy; 0x28uy; 0xfeuy |]

      test64
        Opcode.ZIP1
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V28, SixteenB)),
          OprSIMD (SIMDVecReg (R.V1, SixteenB)),
          OprSIMD (SIMDVecReg (R.V3, SixteenB))
        ))
        [| 0x4euy; 0x03uy; 0x38uy; 0x3cuy |]

      test64
        Opcode.ZIP1
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V1, EightB)),
          OprSIMD (SIMDVecReg (R.V6, EightB)),
          OprSIMD (SIMDVecReg (R.V7, EightB))
        ))
        [| 0x0euy; 0x07uy; 0x38uy; 0xc1uy |]

      test64
        Opcode.UZP2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V6, TwoD)),
          OprSIMD (SIMDVecReg (R.V6, TwoD)),
          OprSIMD (SIMDVecReg (R.V1, TwoD))
        ))
        [| 0x4euy; 0xc1uy; 0x58uy; 0xc6uy |]

      test64
        Opcode.TRN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V3, TwoS)),
          OprSIMD (SIMDVecReg (R.V6, TwoS)),
          OprSIMD (SIMDVecReg (R.V7, TwoS))
        ))
        [| 0x0euy; 0x87uy; 0x68uy; 0xc3uy |]

      test64
        Opcode.ZIP2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V4, SixteenB)),
          OprSIMD (SIMDVecReg (R.V1, SixteenB))
        ))
        [| 0x4euy; 0x01uy; 0x78uy; 0x85uy |]

    /// C4.6.6 Advanced SIMD scalar copy
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar copy Parse Test`` () =
      test64
        Opcode.MOV
        (TwoOperands (scalReg R.D10, OprSIMD (sVRegIdx R.V10 VecD 0uy)))
        [| 0x5euy; 0x08uy; 0x05uy; 0x4auy |]

      test64
        Opcode.MOV
        (TwoOperands (scalReg R.B1, OprSIMD (sVRegIdx R.V10 VecB 3uy)))
        [| 0x5euy; 0x07uy; 0x05uy; 0x41uy |]

    /// C4.6.7 Advanced SIMD scalar pairwise
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar pairwise Parse Test`` () =
      test64
        Opcode.ADDP
        (TwoOperands (scalReg R.D7, OprSIMD (SIMDVecReg (R.V3, TwoD))))
        [| 0x5euy; 0xf1uy; 0xb8uy; 0x67uy |]

      test64
        Opcode.FMAXNMP
        (TwoOperands (
          scalReg R.D15,
          OprSIMD (SIMDVecReg (R.V14, TwoD))
        ))
        [| 0x7euy; 0x70uy; 0xc9uy; 0xcfuy |]

      test64
        Opcode.FADDP
        (TwoOperands (
          scalReg R.S31,
          OprSIMD (SIMDVecReg (R.V15, TwoS))
        ))
        [| 0x7euy; 0x30uy; 0xd9uy; 0xffuy |]

      test64
        Opcode.FMAXP
        (TwoOperands (
          scalReg R.D18,
          OprSIMD (SIMDVecReg (R.V17, TwoD))
        ))
        [| 0x7euy; 0x70uy; 0xfauy; 0x32uy |]

      test64
        Opcode.FMINNMP
        (TwoOperands (scalReg R.S1, OprSIMD (SIMDVecReg (R.V14, TwoS))))
        [| 0x7euy; 0xb0uy; 0xc9uy; 0xc1uy |]

      test64
        Opcode.FMINP
        (TwoOperands (scalReg R.D7, OprSIMD (SIMDVecReg (R.V1, TwoD))))
        [| 0x7euy; 0xf0uy; 0xf8uy; 0x27uy |]

    /// C4.6.8 Advanced SIMD scalar shift by immediate
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar shift by imm Parse Test`` () =
      test64
        Opcode.SSHR
        (ThreeOperands (scalReg R.D1, scalReg R.D10, OprImm 0x3eL))
        [| 0x5fuy; 0x42uy; 0x05uy; 0x41uy |]

      test64
        Opcode.SSRA
        (ThreeOperands (scalReg R.D28, scalReg R.D3, OprImm 0x1cL))
        [| 0x5fuy; 0x64uy; 0x14uy; 0x7cuy |]

      test64
        Opcode.SRSHR
        (ThreeOperands (scalReg R.D1, scalReg R.D7, OprImm 0x27L))
        [| 0x5fuy; 0x59uy; 0x24uy; 0xe1uy |]

      test64
        Opcode.SRSRA
        (ThreeOperands (scalReg R.D3, scalReg R.D6, OprImm 1L))
        [| 0x5fuy; 0x7fuy; 0x34uy; 0xc3uy |]

      test64
        Opcode.SHL
        (ThreeOperands (scalReg R.D13, scalReg R.D7, OprImm 2L))
        [| 0x5fuy; 0x42uy; 0x54uy; 0xeduy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (scalReg R.S25, scalReg R.S16, OprImm 4L))
        [| 0x5fuy; 0x24uy; 0x76uy; 0x19uy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (scalReg R.D25, scalReg R.D16, OprImm 0x24L))
        [| 0x5fuy; 0x64uy; 0x76uy; 0x19uy |]

      test64
        Opcode.SQSHRN
        (ThreeOperands (scalReg R.S7, scalReg R.D12, OprImm 0x17L))
        [| 0x5fuy; 0x29uy; 0x95uy; 0x87uy |]

      test64
        Opcode.SQRSHRN
        (ThreeOperands (scalReg R.H25, scalReg R.S7, OprImm 1L))
        [| 0x5fuy; 0x1fuy; 0x9cuy; 0xf9uy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.D1, scalReg R.D6, OprFbits 0x1fuy))
        [| 0x5fuy; 0x61uy; 0xe4uy; 0xc1uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (scalReg R.D11, scalReg R.D8, OprFbits 0x25uy))
        [| 0x5fuy; 0x5buy; 0xfduy; 0x0buy |]

      test64
        Opcode.USHR
        (ThreeOperands (scalReg R.D7, scalReg R.D14, OprImm 0x17L))
        [| 0x7fuy; 0x69uy; 0x05uy; 0xc7uy |]

      test64
        Opcode.USRA
        (ThreeOperands (scalReg R.D17, scalReg R.D1, OprImm 0x36L))
        [| 0x7fuy; 0x4auy; 0x14uy; 0x31uy |]

      test64
        Opcode.URSHR
        (ThreeOperands (scalReg R.D9, scalReg R.D2, OprImm 0x20L))
        [| 0x7fuy; 0x60uy; 0x24uy; 0x49uy |]

      test64
        Opcode.URSRA
        (ThreeOperands (scalReg R.D9, scalReg R.D6, OprImm 0x3cL))
        [| 0x7fuy; 0x44uy; 0x34uy; 0xc9uy |]

      test64
        Opcode.SRI
        (ThreeOperands (scalReg R.D3, scalReg R.D14, OprImm 0x1fL))
        [| 0x7fuy; 0x61uy; 0x45uy; 0xc3uy |]

      test64
        Opcode.SLI
        (ThreeOperands (scalReg R.D3, scalReg R.D6, OprImm 0xeL))
        [| 0x7fuy; 0x4euy; 0x54uy; 0xc3uy |]

      test64
        Opcode.SQSHLU
        (ThreeOperands (scalReg R.S7, scalReg R.S20, OprImm 0xbL))
        [| 0x7fuy; 0x2buy; 0x66uy; 0x87uy |]

      test64
        Opcode.UQSHL
        (ThreeOperands (scalReg R.B24, scalReg R.B7, OprImm 3L))
        [| 0x7fuy; 0x0buy; 0x74uy; 0xf8uy |]

      test64
        Opcode.SQSHRUN
        (ThreeOperands (scalReg R.S13, scalReg R.D12, OprImm 0x11L))
        [| 0x7fuy; 0x2fuy; 0x85uy; 0x8duy |]

      test64
        Opcode.SQRSHRUN
        (ThreeOperands (scalReg R.S16, scalReg R.D1, OprImm 6L))
        [| 0x7fuy; 0x3auy; 0x8cuy; 0x30uy |]

      test64
        Opcode.UQSHRN
        (ThreeOperands (scalReg R.H13, scalReg R.S6, OprImm 0xbL))
        [| 0x7fuy; 0x15uy; 0x94uy; 0xcduy |]

      test64
        Opcode.UQRSHRN
        (ThreeOperands (scalReg R.B6, scalReg R.H2, OprImm 4L))
        [| 0x7fuy; 0x0cuy; 0x9cuy; 0x46uy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.S1, scalReg R.S6, OprFbits 0x1cuy))
        [| 0x7fuy; 0x24uy; 0xe4uy; 0xc1uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (scalReg R.D3, scalReg R.D4, OprFbits 0x2fuy))
        [| 0x7fuy; 0x51uy; 0xfcuy; 0x83uy |]

    /// C4.6.9 Advanced SIMD scalar three different
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar three different Parse Test``
      ()
      =
      test64
        Opcode.SQDMLAL
        (ThreeOperands (scalReg R.D2, scalReg R.S30, scalReg R.S6))
        [| 0x5euy; 0xa6uy; 0x93uy; 0xc2uy |]

      test64
        Opcode.SQDMLSL
        (ThreeOperands (scalReg R.S6, scalReg R.H0, scalReg R.H1))
        [| 0x5euy; 0x61uy; 0xb0uy; 0x06uy |]

      test64
        Opcode.SQDMULL
        (ThreeOperands (scalReg R.D2, scalReg R.S18, scalReg R.S2))
        [| 0x5euy; 0xa2uy; 0xd2uy; 0x42uy |]

    /// C4.6.10 Advanced SIMD scalar three same
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar three same Parse Test`` () =
      test64
        Opcode.SQADD
        (ThreeOperands (scalReg R.B28, scalReg R.B15, scalReg R.B1))
        [| 0x5euy; 0x21uy; 0x0duy; 0xfcuy |]

      test64
        Opcode.SQSUB
        (ThreeOperands (scalReg R.H5, scalReg R.H30, scalReg R.H3))
        [| 0x5euy; 0x63uy; 0x2fuy; 0xc5uy |]

      test64
        Opcode.CMGT
        (ThreeOperands (scalReg R.D5, scalReg R.D6, scalReg R.D1))
        [| 0x5euy; 0xe1uy; 0x34uy; 0xc5uy |]

      test64
        Opcode.CMGE
        (ThreeOperands (scalReg R.D10, scalReg R.D6, scalReg R.D7))
        [| 0x5euy; 0xe7uy; 0x3cuy; 0xcauy |]

      test64
        Opcode.SSHL
        (ThreeOperands (scalReg R.D30, scalReg R.D0, scalReg R.D31))
        [| 0x5euy; 0xffuy; 0x44uy; 0x1euy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (scalReg R.B14, scalReg R.B24, scalReg R.B9))
        [| 0x5euy; 0x29uy; 0x4fuy; 0x0euy |]

      test64
        Opcode.SRSHL
        (ThreeOperands (scalReg R.D17, scalReg R.D28, scalReg R.D30))
        [| 0x5euy; 0xfeuy; 0x57uy; 0x91uy |]

      test64
        Opcode.SQRSHL
        (ThreeOperands (scalReg R.H14, scalReg R.H17, scalReg R.H14))
        [| 0x5euy; 0x6euy; 0x5euy; 0x2euy |]

      test64
        Opcode.ADD
        (ThreeOperands (scalReg R.D24, scalReg R.D3, scalReg R.D24))
        [| 0x5euy; 0xf8uy; 0x84uy; 0x78uy |]

      test64
        Opcode.CMTST
        (ThreeOperands (scalReg R.D10, scalReg R.D12, scalReg R.D28))
        [| 0x5euy; 0xfcuy; 0x8duy; 0x8auy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (scalReg R.S16, scalReg R.S7, scalReg R.S1))
        [| 0x5euy; 0xa1uy; 0xb4uy; 0xf0uy |]

      test64
        Opcode.FMULX
        (ThreeOperands (scalReg R.D12, scalReg R.D24, scalReg R.D1))
        [| 0x5euy; 0x61uy; 0xdfuy; 0x0cuy |]

      test64
        Opcode.FCMEQ
        (ThreeOperands (scalReg R.S1, scalReg R.S6, scalReg R.S24))
        [| 0x5euy; 0x38uy; 0xe4uy; 0xc1uy |]

      test64
        Opcode.FRECPS
        (ThreeOperands (scalReg R.D4, scalReg R.D2, scalReg R.D1))
        [| 0x5euy; 0x61uy; 0xfcuy; 0x44uy |]

      test64
        Opcode.FRSQRTS
        (ThreeOperands (scalReg R.D24, scalReg R.D16, scalReg R.D1))
        [| 0x5euy; 0xe1uy; 0xfeuy; 0x18uy |]

      test64
        Opcode.UQADD
        (ThreeOperands (scalReg R.H18, scalReg R.H8, scalReg R.H1))
        [| 0x7euy; 0x61uy; 0x0duy; 0x12uy |]

      test64
        Opcode.UQSUB
        (ThreeOperands (scalReg R.B1, scalReg R.B12, scalReg R.B12))
        [| 0x7euy; 0x2cuy; 0x2duy; 0x81uy |]

      test64
        Opcode.CMHI
        (ThreeOperands (scalReg R.D30, scalReg R.D5, scalReg R.D1))
        [| 0x7euy; 0xe1uy; 0x34uy; 0xbeuy |]

      test64
        Opcode.CMHS
        (ThreeOperands (scalReg R.D18, scalReg R.D24, scalReg R.D3))
        [| 0x7euy; 0xe3uy; 0x3fuy; 0x12uy |]

      test64
        Opcode.USHL
        (ThreeOperands (scalReg R.D1, scalReg R.D10, scalReg R.D3))
        [| 0x7euy; 0xe3uy; 0x45uy; 0x41uy |]

      test64
        Opcode.UQSHL
        (ThreeOperands (scalReg R.B17, scalReg R.B16, scalReg R.B7))
        [| 0x7euy; 0x27uy; 0x4euy; 0x11uy |]

      test64
        Opcode.URSHL
        (ThreeOperands (scalReg R.D3, scalReg R.D24, scalReg R.D1))
        [| 0x7euy; 0xe1uy; 0x57uy; 0x03uy |]

      test64
        Opcode.UQRSHL
        (ThreeOperands (scalReg R.H24, scalReg R.H17, scalReg R.H7))
        [| 0x7euy; 0x67uy; 0x5euy; 0x38uy |]

      test64
        Opcode.SUB
        (ThreeOperands (scalReg R.D31, scalReg R.D6, scalReg R.D10))
        [| 0x7euy; 0xeauy; 0x84uy; 0xdfuy |]

      test64
        Opcode.CMEQ
        (ThreeOperands (scalReg R.D4, scalReg R.D17, scalReg R.D0))
        [| 0x7euy; 0xe0uy; 0x8euy; 0x24uy |]

      test64
        Opcode.SQRDMULH
        (ThreeOperands (scalReg R.H10, scalReg R.H6, scalReg R.H1))
        [| 0x7euy; 0x61uy; 0xb4uy; 0xcauy |]

      test64
        Opcode.SQRDMULH
        (ThreeOperands (scalReg R.S1, scalReg R.S8, scalReg R.S7))
        [| 0x7euy; 0xa7uy; 0xb5uy; 0x01uy |]

      test64
        Opcode.FCMGE
        (ThreeOperands (scalReg R.D6, scalReg R.D16, scalReg R.D1))
        [| 0x7euy; 0x61uy; 0xe6uy; 0x06uy |]

      test64
        Opcode.FACGE
        (ThreeOperands (scalReg R.S1, scalReg R.S2, scalReg R.S1))
        [| 0x7euy; 0x21uy; 0xecuy; 0x41uy |]

      test64
        Opcode.FABD
        (ThreeOperands (scalReg R.S6, scalReg R.S17, scalReg R.S1))
        [| 0x7euy; 0xa1uy; 0xd6uy; 0x26uy |]

      test64
        Opcode.FCMGT
        (ThreeOperands (scalReg R.D7, scalReg R.D20, scalReg R.D4))
        [| 0x7euy; 0xe4uy; 0xe6uy; 0x87uy |]

      test64
        Opcode.FACGT
        (ThreeOperands (scalReg R.S19, scalReg R.S3, scalReg R.S5))
        [| 0x7euy; 0xa5uy; 0xecuy; 0x73uy |]

    /// C4.6.11 Advanced SIMD scalar two-scalReg miscellaneous
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar two-reg misc Parse Test`` () =
      test64
        Opcode.SUQADD
        (TwoOperands (scalReg R.S21, scalReg R.S29))
        [| 0x5euy; 0xa0uy; 0x3buy; 0xb5uy |]

      test64
        Opcode.SQABS
        (TwoOperands (scalReg R.H1, scalReg R.H30))
        [| 0x5euy; 0x60uy; 0x7buy; 0xc1uy |]

      test64
        Opcode.CMGT
        (ThreeOperands (scalReg R.D30, scalReg R.D15, OprImm 0L))
        [| 0x5euy; 0xe0uy; 0x89uy; 0xfeuy |]

      test64
        Opcode.CMEQ
        (ThreeOperands (scalReg R.D20, scalReg R.D23, OprImm 0L))
        [| 0x5euy; 0xe0uy; 0x9auy; 0xf4uy |]

      test64
        Opcode.CMLT
        (ThreeOperands (scalReg R.D28, scalReg R.D30, OprImm 0L))
        [| 0x5euy; 0xe0uy; 0xabuy; 0xdcuy |]

      test64
        Opcode.ABS
        (TwoOperands (scalReg R.D17, scalReg R.D24))
        [| 0x5euy; 0xe0uy; 0xbbuy; 0x11uy |]

      test64
        Opcode.SQXTN
        (TwoOperands (scalReg R.H7, scalReg R.S28))
        [| 0x5euy; 0x61uy; 0x4buy; 0x87uy |]

      test64
        Opcode.FCVTNS
        (TwoOperands (scalReg R.D1, scalReg R.D24))
        [| 0x5euy; 0x61uy; 0xabuy; 0x01uy |]

      test64
        Opcode.FCVTMS
        (TwoOperands (scalReg R.S22, scalReg R.S25))
        [| 0x5euy; 0x21uy; 0xbbuy; 0x36uy |]

      test64
        Opcode.FCVTAS
        (TwoOperands (scalReg R.D31, scalReg R.D23))
        [| 0x5euy; 0x61uy; 0xcauy; 0xffuy |]

      test64
        Opcode.SCVTF
        (TwoOperands (scalReg R.S10, scalReg R.S21))
        [| 0x5euy; 0x21uy; 0xdauy; 0xaauy |]

      test64
        Opcode.FCMGT
        (ThreeOperands (scalReg R.S28, scalReg R.S21, OprFPImm 0.0))
        [| 0x5euy; 0xa0uy; 0xcauy; 0xbcuy |]

      test64
        Opcode.FCMEQ
        (ThreeOperands (scalReg R.D25, scalReg R.D17, OprFPImm 0.0))
        [| 0x5euy; 0xe0uy; 0xdauy; 0x39uy |]

      test64
        Opcode.FCMGT
        (ThreeOperands (scalReg R.D30, scalReg R.D15, OprFPImm 0.0))
        [| 0x5euy; 0xe0uy; 0xc9uy; 0xfeuy |]

      test64
        Opcode.FCVTPS
        (TwoOperands (scalReg R.S28, scalReg R.S31))
        [| 0x5euy; 0xa1uy; 0xabuy; 0xfcuy |]

      test64
        Opcode.FCVTZS
        (TwoOperands (scalReg R.D30, scalReg R.D15))
        [| 0x5euy; 0xe1uy; 0xb9uy; 0xfeuy |]

      test64
        Opcode.FRECPE
        (TwoOperands (scalReg R.S22, scalReg R.S23))
        [| 0x5euy; 0xa1uy; 0xdauy; 0xf6uy |]

      test64
        Opcode.FRECPX
        (TwoOperands (scalReg R.D31, scalReg R.D15))
        [| 0x5euy; 0xe1uy; 0xf9uy; 0xffuy |]

      test64
        Opcode.USQADD
        (TwoOperands (scalReg R.S28, scalReg R.S19))
        [| 0x7euy; 0xa0uy; 0x3auy; 0x7cuy |]

      test64
        Opcode.SQNEG
        (TwoOperands (scalReg R.H27, scalReg R.H10))
        [| 0x7euy; 0x60uy; 0x79uy; 0x5buy |]

      test64
        Opcode.CMGE
        (ThreeOperands (scalReg R.D1, scalReg R.D20, OprImm 0L))
        [| 0x7euy; 0xe0uy; 0x8auy; 0x81uy |]

      test64
        Opcode.CMLE
        (ThreeOperands (scalReg R.D24, scalReg R.D17, OprImm 0L))
        [| 0x7euy; 0xe0uy; 0x9auy; 0x38uy |]

      test64
        Opcode.NEG
        (TwoOperands (scalReg R.D31, scalReg R.D11))
        [| 0x7euy; 0xe0uy; 0xb9uy; 0x7fuy |]

      test64
        Opcode.SQXTUN
        (TwoOperands (scalReg R.S17, scalReg R.D16))
        [| 0x7euy; 0xa1uy; 0x2auy; 0x11uy |]

      test64
        Opcode.UQXTN
        (TwoOperands (scalReg R.B1, scalReg R.H20))
        [| 0x7euy; 0x21uy; 0x4auy; 0x81uy |]

      test64
        Opcode.FCVTXN
        (TwoOperands (scalReg R.S24, scalReg R.D23))
        [| 0x7euy; 0x61uy; 0x6auy; 0xf8uy |]

      test64
        Opcode.FCVTNU
        (TwoOperands (scalReg R.S24, scalReg R.S23))
        [| 0x7euy; 0x21uy; 0xaauy; 0xf8uy |]

      test64
        Opcode.FCVTMU
        (TwoOperands (scalReg R.D7, scalReg R.D0))
        [| 0x7euy; 0x61uy; 0xb8uy; 0x07uy |]

      test64
        Opcode.FCVTAU
        (TwoOperands (scalReg R.S17, scalReg R.S16))
        [| 0x7euy; 0x21uy; 0xcauy; 0x11uy |]

      test64
        Opcode.UCVTF
        (TwoOperands (scalReg R.D4, scalReg R.D2))
        [| 0x7euy; 0x61uy; 0xd8uy; 0x44uy |]

      test64
        Opcode.FCMGE
        (ThreeOperands (scalReg R.S30, scalReg R.S23, OprFPImm 0.0))
        [| 0x7euy; 0xa0uy; 0xcauy; 0xfeuy |]

      test64
        Opcode.FCMLE
        (ThreeOperands (scalReg R.D8, scalReg R.D6, OprFPImm 0.0))
        [| 0x7euy; 0xe0uy; 0xd8uy; 0xc8uy |]

      test64
        Opcode.FCVTPU
        (TwoOperands (scalReg R.S1, scalReg R.S17))
        [| 0x7euy; 0xa1uy; 0xaauy; 0x21uy |]

      test64
        Opcode.FCVTZU
        (TwoOperands (scalReg R.D3, scalReg R.D1))
        [| 0x7euy; 0xe1uy; 0xb8uy; 0x23uy |]

      test64
        Opcode.FRSQRTE
        (TwoOperands (scalReg R.S21, scalReg R.S17))
        [| 0x7euy; 0xa1uy; 0xdauy; 0x35uy |]

      test64
        Opcode.FRSQRTE
        (TwoOperands (scalReg R.D29, scalReg R.D21))
        [| 0x7euy; 0xe1uy; 0xdauy; 0xbduy |]

    /// C4.6.12 Advanced SIMD scalar x indexed element
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar x indexed elem Parse Test`` () =
      test64
        Opcode.SQDMLAL
        (ThreeOperands (
          scalReg R.D1,
          scalReg R.S17,
          OprSIMD (sVRegIdx R.V8 VecS 2uy)
        ))
        [| 0x5fuy; 0x88uy; 0x3auy; 0x21uy |]

      test64
        Opcode.SQDMLSL
        (ThreeOperands (
          scalReg R.S26,
          scalReg R.H24,
          OprSIMD (sVRegIdx R.V6 VecH 7uy)
        ))
        [| 0x5fuy; 0x76uy; 0x7buy; 0x1auy |]

      test64
        Opcode.SQDMULL
        (ThreeOperands (
          scalReg R.D7,
          scalReg R.S19,
          OprSIMD (sVRegIdx R.V12 VecS 3uy)
        ))
        [| 0x5fuy; 0xacuy; 0xbauy; 0x67uy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (
          scalReg R.H3,
          scalReg R.H16,
          OprSIMD (sVRegIdx R.V14 VecH 3uy)
        ))
        [| 0x5fuy; 0x7euy; 0xc2uy; 0x03uy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (
          scalReg R.S27,
          scalReg R.S27,
          OprSIMD (sVRegIdx R.V31 VecS 3uy)
        ))
        [| 0x5fuy; 0xbfuy; 0xcbuy; 0x7buy |]

      test64
        Opcode.SQRDMULH
        (ThreeOperands (
          scalReg R.H28,
          scalReg R.H19,
          OprSIMD (sVRegIdx R.V15 VecH 7uy)
        ))
        [| 0x5fuy; 0x7fuy; 0xdauy; 0x7cuy |]

      test64
        Opcode.FMLA
        (ThreeOperands (
          scalReg R.D3,
          scalReg R.D6,
          OprSIMD (sVRegIdx R.V19 VecD 1uy)
        ))
        [| 0x5fuy; 0xd3uy; 0x18uy; 0xc3uy |]

      test64
        Opcode.FMLS
        (ThreeOperands (
          scalReg R.S2,
          scalReg R.S1,
          OprSIMD (sVRegIdx R.V16 VecS 3uy)
        ))
        [| 0x5fuy; 0xb0uy; 0x58uy; 0x22uy |]

      test64
        Opcode.FMUL
        (ThreeOperands (
          scalReg R.D30,
          scalReg R.D3,
          OprSIMD (sVRegIdx R.V17 VecD 1uy)
        ))
        [| 0x5fuy; 0xd1uy; 0x98uy; 0x7euy |]

      test64
        Opcode.FMULX
        (ThreeOperands (
          scalReg R.S25,
          scalReg R.S6,
          OprSIMD (sVRegIdx R.V30 VecS 1uy)
        ))
        [| 0x7fuy; 0xbeuy; 0x90uy; 0xd9uy |]

    /// C4.6.13 Advanced SIMD shift by immediate
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD shift by immediate Parse Test`` () =
      test64
        Opcode.SSHR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 3L
        ))
        [| 0x4fuy; 0x0duy; 0x05uy; 0xc5uy |]

      test64
        Opcode.SSHR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V14, EightH)),
          OprImm 0xBL
        ))
        [| 0x4fuy; 0x15uy; 0x05uy; 0xc5uy |]

      test64
        Opcode.SSHR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V14, FourS)),
          OprImm 0xBL
        ))
        [| 0x4fuy; 0x35uy; 0x05uy; 0xc5uy |]

      test64
        Opcode.SSHR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V14, TwoD)),
          OprImm 0x2EL
        ))
        [| 0x4fuy; 0x52uy; 0x05uy; 0xc5uy |]

      test64
        Opcode.SSRA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 3L
        ))
        [| 0x4fuy; 0x0duy; 0x15uy; 0xc5uy |]

      test64
        Opcode.SRSHR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V14, EightH)),
          OprImm 0xBL
        ))
        [| 0x4fuy; 0x15uy; 0x25uy; 0xc5uy |]

      test64
        Opcode.SRSRA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V14, FourS)),
          OprImm 0xBL
        ))
        [| 0x4fuy; 0x35uy; 0x35uy; 0xc5uy |]

      test64
        Opcode.SHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 5L
        ))
        [| 0x4fuy; 0x0duy; 0x55uy; 0xc5uy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 5L
        ))
        [| 0x4fuy; 0x0duy; 0x75uy; 0xc5uy |]

      test64
        Opcode.SHRN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V14, TwoD)),
          OprImm 0x12L
        ))
        [| 0x4fuy; 0x2euy; 0x85uy; 0xc5uy |]

      test64
        Opcode.RSHRN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, EightH)),
          OprImm 3L
        ))
        [| 0x4fuy; 0x0duy; 0x8duy; 0xc5uy |]

      test64
        Opcode.SQSHRN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, EightH)),
          OprImm 3L
        ))
        [| 0x4fuy; 0x0duy; 0x95uy; 0xc5uy |]

      test64
        Opcode.SQRSHRN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, EightH)),
          OprImm 3L
        ))
        [| 0x4fuy; 0x0duy; 0x9duy; 0xc5uy |]

      test64
        Opcode.SSHLL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 5L
        ))
        [| 0x4fuy; 0x0duy; 0xa5uy; 0xc5uy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V13, TwoD)),
          OprSIMD (SIMDVecReg (R.V10, TwoD)),
          OprFbits 0x31uy
        ))
        [| 0x4fuy; 0x4fuy; 0xe5uy; 0x4duy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V13, TwoD)),
          OprSIMD (SIMDVecReg (R.V10, TwoD)),
          OprFbits 0x31uy
        ))
        [| 0x4fuy; 0x4fuy; 0xfduy; 0x4duy |]

      test64
        Opcode.USHR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 3L
        ))
        [| 0x6fuy; 0x0duy; 0x05uy; 0xc5uy |]

      test64
        Opcode.USRA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 3L
        ))
        [| 0x6fuy; 0x0duy; 0x15uy; 0xc5uy |]

      test64
        Opcode.URSHR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 3L
        ))
        [| 0x6fuy; 0x0duy; 0x25uy; 0xc5uy |]

      test64
        Opcode.URSRA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 3L
        ))
        [| 0x6fuy; 0x0duy; 0x35uy; 0xc5uy |]

      test64
        Opcode.SRI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 3L
        ))
        [| 0x6fuy; 0x0duy; 0x45uy; 0xc5uy |]

      test64
        Opcode.SLI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 5L
        ))
        [| 0x6fuy; 0x0duy; 0x55uy; 0xc5uy |]

      test64
        Opcode.SQSHLU
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 5L
        ))
        [| 0x6fuy; 0x0duy; 0x65uy; 0xc5uy |]

      test64
        Opcode.UQSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V14, SixteenB)),
          OprImm 5L
        ))
        [| 0x6fuy; 0x0duy; 0x75uy; 0xc5uy |]

      test64
        Opcode.SQSHRUN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V14, TwoD)),
          OprImm 0x17L
        ))
        [| 0x6fuy; 0x29uy; 0x85uy; 0xc5uy |]

      test64
        Opcode.SQRSHRUN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V14, FourS)),
          OprImm 5L
        ))
        [| 0x6fuy; 0x1buy; 0x8duy; 0xc5uy |]

      test64
        Opcode.UQSHRN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V14, TwoD)),
          OprImm 0x1AL
        ))
        [| 0x6fuy; 0x26uy; 0x95uy; 0xc5uy |]

      test64
        Opcode.UQRSHRN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V14, FourS)),
          OprImm 1L
        ))
        [| 0x6fuy; 0x1fuy; 0x9duy; 0xc5uy |]

      test64
        Opcode.USHLL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoS)),
          OprImm 0xDL
        ))
        [| 0x2fuy; 0x2duy; 0xa4uy; 0xbbuy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V14, FourS)),
          OprFbits 7uy
        ))
        [| 0x6fuy; 0x39uy; 0xe5uy; 0xc5uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V14, FourS)),
          OprFbits 0x1Auy
        ))
        [| 0x6fuy; 0x26uy; 0xfduy; 0xc5uy |]

    /// C4.6.14 Advanced SIMD table lookup
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD table lookup Parse Test`` () =
      test64
        Opcode.TBL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V1, SixteenB)),
          OprSIMDList [
            SIMDVecReg (R.V6, SixteenB); SIMDVecReg (R.V7, SixteenB) ],
          OprSIMD (SIMDVecReg (R.V3, SixteenB))
        ))
        [| 0x4euy; 0x03uy; 0x20uy; 0xc1uy |]

      test64
        Opcode.TBL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V9, EightB)),
          OprSIMDList [
            SIMDVecReg (R.V22, SixteenB);
            SIMDVecReg (R.V23, SixteenB);
            SIMDVecReg (R.V24, SixteenB) ],
          OprSIMD (SIMDVecReg (R.V3, EightB))
        ))
        [| 0x0euy; 0x03uy; 0x42uy; 0xc9uy |]

      test64
        Opcode.TBL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMDList [
            SIMDVecReg (R.V31, SixteenB);
            SIMDVecReg (R.V0, SixteenB);
            SIMDVecReg (R.V1, SixteenB);
            SIMDVecReg (R.V2, SixteenB) ],
          OprSIMD (SIMDVecReg (R.V3, SixteenB))
        ))
        [| 0x4euy; 0x03uy; 0x63uy; 0xe5uy |]

      test64
        Opcode.TBL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V17, EightB)),
          OprSIMDList [ SIMDVecReg (R.V27, SixteenB) ],
          OprSIMD (SIMDVecReg (R.V3, EightB))
        ))
        [| 0x0euy; 0x03uy; 0x03uy; 0x71uy |]

      test64
        Opcode.TBX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V28, EightB)),
          OprSIMDList [
            SIMDVecReg (R.V7, SixteenB); SIMDVecReg (R.V8, SixteenB) ],
          OprSIMD (SIMDVecReg (R.V25, EightB))
        ))
        [| 0x0euy; 0x19uy; 0x30uy; 0xfcuy |]

      test64
        Opcode.TBX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V28, SixteenB)),
          OprSIMDList [
            SIMDVecReg (R.V7, SixteenB);
            SIMDVecReg (R.V8, SixteenB);
            SIMDVecReg (R.V9, SixteenB) ],
          OprSIMD (SIMDVecReg (R.V25, SixteenB))
        ))
        [| 0x4euy; 0x19uy; 0x50uy; 0xfcuy |]

      test64
        Opcode.TBX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V28, EightB)),
          OprSIMDList [
            SIMDVecReg (R.V7, SixteenB);
            SIMDVecReg (R.V8, SixteenB);
            SIMDVecReg (R.V9, SixteenB);
            SIMDVecReg (R.V10, SixteenB) ],
          OprSIMD (SIMDVecReg (R.V25, EightB))
        ))
        [| 0x0euy; 0x19uy; 0x70uy; 0xfcuy |]

      test64
        Opcode.TBX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V28, SixteenB)),
          OprSIMDList [ SIMDVecReg (R.V7, SixteenB) ],
          OprSIMD (SIMDVecReg (R.V25, SixteenB))
        ))
        [| 0x4euy; 0x19uy; 0x10uy; 0xfcuy |]

    /// C4.6.15 Advanced SIMD three different
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD three different Parse Test`` () =
      test64
        Opcode.SADDL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V26, FourS)),
          OprSIMD (SIMDVecReg (R.V28, FourH)),
          OprSIMD (SIMDVecReg (R.V11, FourH))
        ))
        [| 0x0euy; 0x6buy; 0x03uy; 0x9auy |]

      test64
        Opcode.SADDL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V25, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0x03uy; 0x25uy |]

      test64
        Opcode.SADDW
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V26, EightH)),
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V7, EightB))
        ))
        [| 0x0euy; 0x27uy; 0x12uy; 0xbauy |]

      test64
        Opcode.SADDW2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, FourS)),
          OprSIMD (SIMDVecReg (R.V3, FourS)),
          OprSIMD (SIMDVecReg (R.V3, EightH))
        ))
        [| 0x4euy; 0x63uy; 0x10uy; 0x79uy |]

      test64
        Opcode.SSUBL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, FourS)),
          OprSIMD (SIMDVecReg (R.V3, EightH)),
          OprSIMD (SIMDVecReg (R.V3, EightH))
        ))
        [| 0x4euy; 0x63uy; 0x20uy; 0x79uy |]

      test64
        Opcode.SSUBW2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, FourS)),
          OprSIMD (SIMDVecReg (R.V3, FourS)),
          OprSIMD (SIMDVecReg (R.V3, EightH))
        ))
        [| 0x4euy; 0x63uy; 0x30uy; 0x79uy |]

      test64
        Opcode.ADDHN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, EightH)),
          OprSIMD (SIMDVecReg (R.V3, FourS)),
          OprSIMD (SIMDVecReg (R.V3, FourS))
        ))
        [| 0x4euy; 0x63uy; 0x40uy; 0x79uy |]

      test64
        Opcode.SABAL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, FourS)),
          OprSIMD (SIMDVecReg (R.V3, EightH)),
          OprSIMD (SIMDVecReg (R.V3, EightH))
        ))
        [| 0x4euy; 0x63uy; 0x50uy; 0x79uy |]

      test64
        Opcode.SUBHN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, EightH)),
          OprSIMD (SIMDVecReg (R.V3, FourS)),
          OprSIMD (SIMDVecReg (R.V3, FourS))
        ))
        [| 0x4euy; 0x63uy; 0x60uy; 0x79uy |]

      test64
        Opcode.SABDL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, FourS)),
          OprSIMD (SIMDVecReg (R.V3, EightH)),
          OprSIMD (SIMDVecReg (R.V3, EightH))
        ))
        [| 0x4euy; 0x63uy; 0x70uy; 0x79uy |]

      test64
        Opcode.SMLAL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V24, TwoD)),
          OprSIMD (SIMDVecReg (R.V18, TwoS)),
          OprSIMD (SIMDVecReg (R.V6, TwoS))
        ))
        [| 0x0euy; 0xa6uy; 0x82uy; 0x58uy |]

      test64
        Opcode.SQDMLAL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V26, TwoD)),
          OprSIMD (SIMDVecReg (R.V23, FourS)),
          OprSIMD (SIMDVecReg (R.V6, FourS))
        ))
        [| 0x4euy; 0xa6uy; 0x92uy; 0xfauy |]

      test64
        Opcode.SMLSL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V12, FourS)),
          OprSIMD (SIMDVecReg (R.V17, EightH)),
          OprSIMD (SIMDVecReg (R.V6, EightH))
        ))
        [| 0x4euy; 0x66uy; 0xa2uy; 0x2cuy |]

      test64
        Opcode.SQDMLSL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V3, TwoD)),
          OprSIMD (SIMDVecReg (R.V22, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0xb2uy; 0xc3uy |]

      test64
        Opcode.SMULL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V28, FourS)),
          OprSIMD (SIMDVecReg (R.V11, FourH)),
          OprSIMD (SIMDVecReg (R.V5, FourH))
        ))
        [| 0x0euy; 0x65uy; 0xc1uy; 0x7cuy |]

      test64
        Opcode.SQDMULL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, TwoD)),
          OprSIMD (SIMDVecReg (R.V3, TwoS)),
          OprSIMD (SIMDVecReg (R.V8, TwoS))
        ))
        [| 0x0euy; 0xa8uy; 0xd0uy; 0x79uy |]

      test64
        Opcode.PMULL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, OneQ)),
          OprSIMD (SIMDVecReg (R.V18, TwoD)),
          OprSIMD (SIMDVecReg (R.V3, TwoD))
        ))
        [| 0x4euy; 0xe3uy; 0xe2uy; 0x45uy |]

      test64
        Opcode.UADDL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V11, EightH)),
          OprSIMD (SIMDVecReg (R.V19, EightB)),
          OprSIMD (SIMDVecReg (R.V14, EightB))
        ))
        [| 0x2euy; 0x2euy; 0x02uy; 0x6buy |]

      test64
        Opcode.UADDW2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V18, TwoD)),
          OprSIMD (SIMDVecReg (R.V18, TwoD)),
          OprSIMD (SIMDVecReg (R.V14, FourS))
        ))
        [| 0x6euy; 0xaeuy; 0x12uy; 0x52uy |]

      test64
        Opcode.USUBL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V29, TwoD)),
          OprSIMD (SIMDVecReg (R.V21, TwoS)),
          OprSIMD (SIMDVecReg (R.V1, TwoS))
        ))
        [| 0x2euy; 0xa1uy; 0x22uy; 0xbduy |]

      test64
        Opcode.USUBW2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, EightH)),
          OprSIMD (SIMDVecReg (R.V28, EightH)),
          OprSIMD (SIMDVecReg (R.V7, SixteenB))
        ))
        [| 0x6euy; 0x27uy; 0x33uy; 0x9buy |]

      test64
        Opcode.RADDHN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, SixteenB)),
          OprSIMD (SIMDVecReg (R.V28, EightH)),
          OprSIMD (SIMDVecReg (R.V7, EightH))
        ))
        [| 0x6euy; 0x27uy; 0x43uy; 0x9buy |]

      test64
        Opcode.UABAL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, EightH)),
          OprSIMD (SIMDVecReg (R.V28, SixteenB)),
          OprSIMD (SIMDVecReg (R.V7, SixteenB))
        ))
        [| 0x6euy; 0x27uy; 0x53uy; 0x9buy |]

      test64
        Opcode.RSUBHN2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, SixteenB)),
          OprSIMD (SIMDVecReg (R.V28, EightH)),
          OprSIMD (SIMDVecReg (R.V7, EightH))
        ))
        [| 0x6euy; 0x27uy; 0x63uy; 0x9buy |]

      test64
        Opcode.UABDL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, EightH)),
          OprSIMD (SIMDVecReg (R.V28, SixteenB)),
          OprSIMD (SIMDVecReg (R.V7, SixteenB))
        ))
        [| 0x6euy; 0x27uy; 0x73uy; 0x9buy |]

      test64
        Opcode.UMLAL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, EightH)),
          OprSIMD (SIMDVecReg (R.V28, SixteenB)),
          OprSIMD (SIMDVecReg (R.V7, SixteenB))
        ))
        [| 0x6euy; 0x27uy; 0x83uy; 0x9buy |]

      test64
        Opcode.UMLSL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, EightH)),
          OprSIMD (SIMDVecReg (R.V28, SixteenB)),
          OprSIMD (SIMDVecReg (R.V7, SixteenB))
        ))
        [| 0x6euy; 0x27uy; 0xa3uy; 0x9buy |]

      test64
        Opcode.UMULL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, EightH)),
          OprSIMD (SIMDVecReg (R.V28, SixteenB)),
          OprSIMD (SIMDVecReg (R.V7, SixteenB))
        ))
        [| 0x6euy; 0x27uy; 0xc3uy; 0x9buy |]

    /// C4.6.16 Advanced SIMD three same
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD three same Parse Test`` () =
      test64
        Opcode.SHADD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x25uy; 0x04uy; 0xb5uy |]

      test64
        Opcode.SQADD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x4euy; 0x65uy; 0x0cuy; 0xb5uy |]

      test64
        Opcode.SRHADD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0x14uy; 0xb5uy |]

      test64
        Opcode.SHSUB
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x25uy; 0x24uy; 0xb5uy |]

      test64
        Opcode.SQSUB
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x4euy; 0x65uy; 0x2cuy; 0xb5uy |]

      test64
        Opcode.CMGT
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0x34uy; 0xb5uy |]

      test64
        Opcode.CMGE
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x25uy; 0x3cuy; 0xb5uy |]

      test64
        Opcode.SSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x4euy; 0x65uy; 0x44uy; 0xb5uy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0x4cuy; 0xb5uy |]

      test64
        Opcode.SRSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x25uy; 0x54uy; 0xb5uy |]

      test64
        Opcode.SQRSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x4euy; 0x65uy; 0x5cuy; 0xb5uy |]

      test64
        Opcode.SMAX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0x64uy; 0xb5uy |]

      test64
        Opcode.SMIN
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x25uy; 0x6cuy; 0xb5uy |]

      test64
        Opcode.SABD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x4euy; 0x65uy; 0x74uy; 0xb5uy |]

      test64
        Opcode.SABA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0x7cuy; 0xb5uy |]

      test64
        Opcode.ADD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x25uy; 0x84uy; 0xb5uy |]

      test64
        Opcode.CMTST
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x4euy; 0x65uy; 0x8cuy; 0xb5uy |]

      test64
        Opcode.MLA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0x94uy; 0xb5uy |]

      test64
        Opcode.MUL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x25uy; 0x9cuy; 0xb5uy |]

      test64
        Opcode.SMAXP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x4euy; 0x65uy; 0xa4uy; 0xb5uy |]

      test64
        Opcode.SMINP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0xacuy; 0xb5uy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0xb4uy; 0xb5uy |]

      test64
        Opcode.ADDP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x4euy; 0x65uy; 0xbcuy; 0xb5uy |]

      test64
        Opcode.FMAXNM
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0x25uy; 0xc6uy; 0xb5uy |]

      test64
        Opcode.FMLA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V13, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x4euy; 0x65uy; 0xcduy; 0xb5uy |]

      test64
        Opcode.FADD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0x25uy; 0xd4uy; 0xb5uy |]

      test64
        Opcode.FMULX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V17, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x4euy; 0x65uy; 0xdcuy; 0xb1uy |]

      test64
        Opcode.FCMEQ
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V2, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0x25uy; 0xe4uy; 0x55uy |]

      test64
        Opcode.FMAX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V13, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x4euy; 0x65uy; 0xf5uy; 0xb5uy |]

      test64
        Opcode.FRECPS
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V13, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0x25uy; 0xfduy; 0xb5uy |]

      test64
        Opcode.AND
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V17, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x25uy; 0x1cuy; 0xb1uy |]

      test64
        Opcode.BIC
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, SixteenB)),
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x65uy; 0x1euy; 0xb9uy |]

      test64
        Opcode.FMINNM
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V29, FourS)),
          OprSIMD (SIMDVecReg (R.V1, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0xc4uy; 0x3duy |]

      test64
        Opcode.FMLS
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V20, TwoD)),
          OprSIMD (SIMDVecReg (R.V29, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x4euy; 0xe5uy; 0xcfuy; 0xb4uy |]

      test64
        Opcode.FSUB
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0xd4uy; 0xb5uy |]

      test64
        Opcode.FMIN
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V1, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x4euy; 0xe5uy; 0xf4uy; 0x25uy |]

      test64
        Opcode.FRSQRTS
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V29, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0xa5uy; 0xfcuy; 0xbduy |]

      test64
        Opcode.MOV
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0xa5uy; 0x1cuy; 0xb5uy |]

      test64
        Opcode.ORN
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V9, SixteenB)),
          OprSIMD (SIMDVecReg (R.V13, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0xe5uy; 0x1duy; 0xa9uy |]

      test64
        Opcode.UHADD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x25uy; 0x04uy; 0xb5uy |]

      test64
        Opcode.UQADD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x6euy; 0x65uy; 0x0cuy; 0xb5uy |]

      test64
        Opcode.URHADD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0x14uy; 0xb5uy |]

      test64
        Opcode.UHSUB
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x25uy; 0x24uy; 0xb5uy |]

      test64
        Opcode.UQSUB
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x6euy; 0x65uy; 0x2cuy; 0xb5uy |]

      test64
        Opcode.CMHI
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0x34uy; 0xb5uy |]

      test64
        Opcode.CMHS
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x25uy; 0x3cuy; 0xb5uy |]

      test64
        Opcode.USHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x6euy; 0x65uy; 0x44uy; 0xb5uy |]

      test64
        Opcode.UQSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0x4cuy; 0xb5uy |]

      test64
        Opcode.URSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x25uy; 0x54uy; 0xb5uy |]

      test64
        Opcode.UQRSHL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x6euy; 0x65uy; 0x5cuy; 0xb5uy |]

      test64
        Opcode.UMAX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0x64uy; 0xb5uy |]

      test64
        Opcode.UMIN
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x25uy; 0x6cuy; 0xb5uy |]

      test64
        Opcode.UABD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x6euy; 0x65uy; 0x74uy; 0xb5uy |]

      test64
        Opcode.UABA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0x7cuy; 0xb5uy |]

      test64
        Opcode.SUB
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x25uy; 0x84uy; 0xb5uy |]

      test64
        Opcode.CMEQ
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x6euy; 0x65uy; 0x8cuy; 0xb5uy |]

      test64
        Opcode.MLS
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0x94uy; 0xb5uy |]

      test64
        Opcode.PMUL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x25uy; 0x9cuy; 0xb5uy |]

      test64
        Opcode.UMAXP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x6euy; 0x65uy; 0xa4uy; 0xb5uy |]

      test64
        Opcode.UMINP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0xacuy; 0xb5uy |]

      test64
        Opcode.SQRDMULH
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH)),
          OprSIMD (SIMDVecReg (R.V5, EightH))
        ))
        [| 0x6euy; 0x65uy; 0xb4uy; 0xb5uy |]

      test64
        Opcode.FMAXNMP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0x25uy; 0xc4uy; 0xb5uy |]

      test64
        Opcode.FADDP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x6euy; 0x65uy; 0xd4uy; 0xb5uy |]

      test64
        Opcode.FMUL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0x25uy; 0xdcuy; 0xb5uy |]

      test64
        Opcode.FCMGE
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x6euy; 0x65uy; 0xe4uy; 0xb5uy |]

      test64
        Opcode.FACGE
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0x25uy; 0xecuy; 0xb5uy |]

      test64
        Opcode.FMAXP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x6euy; 0x65uy; 0xf4uy; 0xb5uy |]

      test64
        Opcode.FDIV
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0x25uy; 0xfcuy; 0xb5uy |]

      test64
        Opcode.EOR
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x25uy; 0x1cuy; 0xb5uy |]

      test64
        Opcode.BSL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0x65uy; 0x1cuy; 0xb5uy |]

      test64
        Opcode.FMINNMP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0xc4uy; 0xb5uy |]

      test64
        Opcode.FABD
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x6euy; 0xe5uy; 0xd4uy; 0xb5uy |]

      test64
        Opcode.FCMGT
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0xe4uy; 0xb5uy |]

      test64
        Opcode.FACGT
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x6euy; 0xe5uy; 0xecuy; 0xb5uy |]

      test64
        Opcode.FMINP
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa5uy; 0xf4uy; 0xb5uy |]

      test64
        Opcode.BIT
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0xa5uy; 0x1cuy; 0xb5uy |]

      test64
        Opcode.BIF
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x6euy; 0xe5uy; 0x1cuy; 0xb5uy |]

    /// C4.6.17 Advanced SIMD two-register miscellaneous
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD two-reg miscellaneous Parse Test`` () =
      test64
        Opcode.REV64
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V3, EightH)),
          OprSIMD (SIMDVecReg (R.V12, EightH))
        ))
        [| 0x4euy; 0x60uy; 0x09uy; 0x83uy |]

      test64
        Opcode.REV16
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V18, SixteenB)),
          OprSIMD (SIMDVecReg (R.V5, SixteenB))
        ))
        [| 0x4euy; 0x20uy; 0x18uy; 0xb2uy |]

      test64
        Opcode.SADDLP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V3, FourS)),
          OprSIMD (SIMDVecReg (R.V12, EightH))
        ))
        [| 0x4euy; 0x60uy; 0x29uy; 0x83uy |]

      test64
        Opcode.SUQADD
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V19, EightH)),
          OprSIMD (SIMDVecReg (R.V17, EightH))
        ))
        [| 0x4euy; 0x60uy; 0x3auy; 0x33uy |]

      test64
        Opcode.CLS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V28, FourS)),
          OprSIMD (SIMDVecReg (R.V3, FourS))
        ))
        [| 0x4euy; 0xa0uy; 0x48uy; 0x7cuy |]

      test64
        Opcode.SADDLP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V13, OneD)),
          OprSIMD (SIMDVecReg (R.V6, TwoS))
        ))
        [| 0x0euy; 0xa0uy; 0x28uy; 0xcduy |]

      test64
        Opcode.SQABS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V6, TwoD)),
          OprSIMD (SIMDVecReg (R.V18, TwoD))
        ))
        [| 0x4euy; 0xe0uy; 0x7auy; 0x46uy |]

      test64
        Opcode.CMGT
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V7, SixteenB)),
          OprSIMD (SIMDVecReg (R.V3, SixteenB)),
          OprImm 0L
        ))
        [| 0x4euy; 0x20uy; 0x88uy; 0x67uy |]

      test64
        Opcode.CMEQ
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, FourH)),
          OprSIMD (SIMDVecReg (R.V3, FourH)),
          OprImm 0L
        ))
        [| 0x0euy; 0x60uy; 0x98uy; 0x79uy |]

      test64
        Opcode.CMLT
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V1, FourS)),
          OprSIMD (SIMDVecReg (R.V2, FourS)),
          OprImm 0L
        ))
        [| 0x4euy; 0xa0uy; 0xa8uy; 0x41uy |]

      test64
        Opcode.ABS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V29, SixteenB)),
          OprSIMD (SIMDVecReg (R.V27, SixteenB))
        ))
        [| 0x4euy; 0x20uy; 0xbbuy; 0x7duy |]

      test64
        Opcode.XTN
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V25, TwoS)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x0euy; 0xa1uy; 0x28uy; 0xb9uy |]

      test64
        Opcode.XTN2
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V24, FourS)),
          OprSIMD (SIMDVecReg (R.V7, TwoD))
        ))
        [| 0x4euy; 0xa1uy; 0x28uy; 0xf8uy |]

      test64
        Opcode.SQXTN
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V3, EightB)),
          OprSIMD (SIMDVecReg (R.V6, EightH))
        ))
        [| 0x0euy; 0x21uy; 0x48uy; 0xc3uy |]


      test64
        Opcode.SQXTN2
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, SixteenB)),
          OprSIMD (SIMDVecReg (R.V10, EightH))
        ))
        [| 0x4euy; 0x21uy; 0x49uy; 0x45uy |]

      test64
        Opcode.FCVTN
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, TwoS)),
          OprSIMD (SIMDVecReg (R.V4, TwoD))
        ))
        [| 0x0euy; 0x61uy; 0x68uy; 0x85uy |]

      test64
        Opcode.FCVTN2
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V24, EightH)),
          OprSIMD (SIMDVecReg (R.V7, FourS))
        ))
        [| 0x4euy; 0x21uy; 0x68uy; 0xf8uy |]

      test64
        Opcode.FCVTL
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V28, FourS)),
          OprSIMD (SIMDVecReg (R.V19, FourH))
        ))
        [| 0x0euy; 0x21uy; 0x7auy; 0x7cuy |]

      test64
        Opcode.FCVTL2
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V3, TwoD)),
          OprSIMD (SIMDVecReg (R.V26, FourS))
        ))
        [| 0x4euy; 0x61uy; 0x7buy; 0x43uy |]

      test64
        Opcode.FRINTN
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V24, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x4euy; 0x61uy; 0x88uy; 0xb8uy |]

      test64
        Opcode.FRINTM
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, TwoS)),
          OprSIMD (SIMDVecReg (R.V3, TwoS))
        ))
        [| 0x0euy; 0x21uy; 0x98uy; 0x65uy |]

      test64
        Opcode.FCVTNS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V13, FourS)),
          OprSIMD (SIMDVecReg (R.V3, FourS))
        ))
        [| 0x4euy; 0x21uy; 0xa8uy; 0x6duy |]

      test64
        Opcode.FCVTMS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V30, TwoS)),
          OprSIMD (SIMDVecReg (R.V3, TwoS))
        ))
        [| 0x0euy; 0x21uy; 0xb8uy; 0x7euy |]

      test64
        Opcode.FCVTAS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V22, TwoD)),
          OprSIMD (SIMDVecReg (R.V3, TwoD))
        ))
        [| 0x4euy; 0x61uy; 0xc8uy; 0x76uy |]

      test64
        Opcode.SCVTF
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V18, FourS)),
          OprSIMD (SIMDVecReg (R.V4, FourS))
        ))
        [| 0x4euy; 0x21uy; 0xd8uy; 0x92uy |]

      test64
        Opcode.FCMGT
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V29, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprFPImm 0.0
        ))
        [| 0x4euy; 0xa0uy; 0xc8uy; 0xbduy |]

      test64
        Opcode.FCMEQ
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V30, TwoS)),
          OprSIMD (SIMDVecReg (R.V1, TwoS)),
          OprFPImm 0.0
        ))
        [| 0x0euy; 0xa0uy; 0xd8uy; 0x3euy |]

      test64
        Opcode.FCMLT
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V25, TwoD)),
          OprSIMD (SIMDVecReg (R.V9, TwoD)),
          OprFPImm 0.0
        ))
        [| 0x4euy; 0xe0uy; 0xe9uy; 0x39uy |]

      test64
        Opcode.FABS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V14, FourS)),
          OprSIMD (SIMDVecReg (R.V4, FourS))
        ))
        [| 0x4euy; 0xa0uy; 0xf8uy; 0x8euy |]

      test64
        Opcode.FRINTP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V22, TwoS)),
          OprSIMD (SIMDVecReg (R.V4, TwoS))
        ))
        [| 0x0euy; 0xa1uy; 0x88uy; 0x96uy |]

      test64
        Opcode.FRINTZ
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V9, TwoD)),
          OprSIMD (SIMDVecReg (R.V2, TwoD))
        ))
        [| 0x4euy; 0xe1uy; 0x98uy; 0x49uy |]

      test64
        Opcode.FCVTPS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V3, FourS)),
          OprSIMD (SIMDVecReg (R.V22, FourS))
        ))
        [| 0x4euy; 0xa1uy; 0xaauy; 0xc3uy |]

      test64
        Opcode.FCVTZS
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V26, TwoS)),
          OprSIMD (SIMDVecReg (R.V19, TwoS))
        ))
        [| 0x0euy; 0xa1uy; 0xbauy; 0x7auy |]

      test64
        Opcode.URECPE
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V7, TwoS)),
          OprSIMD (SIMDVecReg (R.V6, TwoS))
        ))
        [| 0x0euy; 0xa1uy; 0xc8uy; 0xc7uy |]

      test64
        Opcode.FRECPE
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V3, TwoD)),
          OprSIMD (SIMDVecReg (R.V4, TwoD))
        ))
        [| 0x4euy; 0xe1uy; 0xd8uy; 0x83uy |]

      test64
        Opcode.REV32
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V30, EightH)),
          OprSIMD (SIMDVecReg (R.V1, EightH))
        ))
        [| 0x6euy; 0x60uy; 0x08uy; 0x3euy |]

      test64
        Opcode.UADDLP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V28, TwoD)),
          OprSIMD (SIMDVecReg (R.V7, FourS))
        ))
        [| 0x6euy; 0xa0uy; 0x28uy; 0xfcuy |]

      test64
        Opcode.USQADD
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V3, TwoD)),
          OprSIMD (SIMDVecReg (R.V4, TwoD))
        ))
        [| 0x6euy; 0xe0uy; 0x38uy; 0x83uy |]

      test64
        Opcode.CLZ
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V9, FourS)),
          OprSIMD (SIMDVecReg (R.V6, FourS))
        ))
        [| 0x6euy; 0xa0uy; 0x48uy; 0xc9uy |]

      test64
        Opcode.UADALP
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V30, FourS)),
          OprSIMD (SIMDVecReg (R.V1, EightH))
        ))
        [| 0x6euy; 0x60uy; 0x68uy; 0x3euy |]

      test64
        Opcode.SQNEG
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V15, TwoS)),
          OprSIMD (SIMDVecReg (R.V7, TwoS))
        ))
        [| 0x2euy; 0xa0uy; 0x78uy; 0xefuy |]

      test64
        Opcode.CMGE
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V20, SixteenB)),
          OprSIMD (SIMDVecReg (R.V3, SixteenB)),
          OprImm 0L
        ))
        [| 0x6euy; 0x20uy; 0x88uy; 0x74uy |]

      test64
        Opcode.CMLE
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V29, EightB)),
          OprSIMD (SIMDVecReg (R.V7, EightB)),
          OprImm 0L
        ))
        [| 0x2euy; 0x20uy; 0x98uy; 0xfduy |]

      test64
        Opcode.NEG
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V10, EightH)),
          OprSIMD (SIMDVecReg (R.V6, EightH))
        ))
        [| 0x6euy; 0x60uy; 0xb8uy; 0xcauy |]

      test64
        Opcode.SQXTN
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V7, TwoS)),
          OprSIMD (SIMDVecReg (R.V4, TwoD))
        ))
        [| 0x0euy; 0xa1uy; 0x48uy; 0x87uy |]

      test64
        Opcode.SQXTN2
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V20, EightH)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x4euy; 0x61uy; 0x48uy; 0xb4uy |]

      test64
        Opcode.SHLL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V19, TwoS)),
          OprShift (SRTypeLSL, Imm 32L)
        ))
        [| 0x2euy; 0xa1uy; 0x3auy; 0x75uy |]

      test64
        Opcode.SHLL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V29, FourS)),
          OprSIMD (SIMDVecReg (R.V19, EightH)),
          OprShift (SRTypeLSL, Imm 16L)
        ))
        [| 0x6euy; 0x61uy; 0x3auy; 0x7duy |]

      test64
        Opcode.UQXTN
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V9, TwoS)),
          OprSIMD (SIMDVecReg (R.V7, TwoD))
        ))
        [| 0x2euy; 0xa1uy; 0x48uy; 0xe9uy |]

      test64
        Opcode.UQXTN2
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V2, EightH)),
          OprSIMD (SIMDVecReg (R.V6, FourS))
        ))
        [| 0x6euy; 0x61uy; 0x48uy; 0xc2uy |]

      test64
        Opcode.FCVTXN
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V10, TwoS)),
          OprSIMD (SIMDVecReg (R.V6, TwoD))
        ))
        [| 0x2euy; 0x61uy; 0x68uy; 0xcauy |]

      test64
        Opcode.FCVTXN2
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V14, TwoD))
        ))
        [| 0x6euy; 0x61uy; 0x69uy; 0xc5uy |]

      test64
        Opcode.FRINTA
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V26, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0x21uy; 0x88uy; 0xbauy |]

      test64
        Opcode.FRINTX
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V28, TwoD)),
          OprSIMD (SIMDVecReg (R.V5, TwoD))
        ))
        [| 0x6euy; 0x61uy; 0x98uy; 0xbcuy |]

      test64
        Opcode.FCVTNU
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, TwoS)),
          OprSIMD (SIMDVecReg (R.V6, TwoS))
        ))
        [| 0x2euy; 0x21uy; 0xa8uy; 0xc5uy |]

      test64
        Opcode.FCVTMU
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V6, FourS)),
          OprSIMD (SIMDVecReg (R.V22, FourS))
        ))
        [| 0x6euy; 0x21uy; 0xbauy; 0xc6uy |]

      test64
        Opcode.FCVTAU
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, TwoS)),
          OprSIMD (SIMDVecReg (R.V27, TwoS))
        ))
        [| 0x2euy; 0x21uy; 0xcbuy; 0x65uy |]

      test64
        Opcode.UCVTF
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V22, FourS)),
          OprSIMD (SIMDVecReg (R.V4, FourS))
        ))
        [| 0x6euy; 0x21uy; 0xd8uy; 0x96uy |]

      test64
        Opcode.MVN
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V26, SixteenB)),
          OprSIMD (SIMDVecReg (R.V9, SixteenB))
        ))
        [| 0x6euy; 0x20uy; 0x59uy; 0x3auy |]

      test64
        Opcode.RBIT
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V18, EightB)),
          OprSIMD (SIMDVecReg (R.V7, EightB))
        ))
        [| 0x2euy; 0x60uy; 0x58uy; 0xf2uy |]

      test64
        Opcode.FCMGE
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V23, FourS)),
          OprFPImm 0.0
        ))
        [| 0x6euy; 0xa0uy; 0xcauy; 0xe5uy |]

      test64
        Opcode.FCMLE
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V14, TwoS)),
          OprSIMD (SIMDVecReg (R.V18, TwoS)),
          OprFPImm 0.0
        ))
        [| 0x2euy; 0xa0uy; 0xdauy; 0x4euy |]

      test64
        Opcode.FNEG
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V21, TwoD)),
          OprSIMD (SIMDVecReg (R.V19, TwoD))
        ))
        [| 0x6euy; 0xe0uy; 0xfauy; 0x75uy |]

      test64
        Opcode.FRINTI
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V30, TwoS)),
          OprSIMD (SIMDVecReg (R.V21, TwoS))
        ))
        [| 0x2euy; 0xa1uy; 0x9auy; 0xbeuy |]

      test64
        Opcode.FCVTPU
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V9, TwoD)),
          OprSIMD (SIMDVecReg (R.V4, TwoD))
        ))
        [| 0x6euy; 0xe1uy; 0xa8uy; 0x89uy |]

      test64
        Opcode.FCVTZU
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V30, TwoS)),
          OprSIMD (SIMDVecReg (R.V15, TwoS))
        ))
        [| 0x2euy; 0xa1uy; 0xb9uy; 0xfeuy |]

      test64
        Opcode.URSQRTE
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V29, FourS))
        ))
        [| 0x6euy; 0xa1uy; 0xcbuy; 0xa5uy |]

      test64
        Opcode.FRSQRTE
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V18, TwoS)),
          OprSIMD (SIMDVecReg (R.V25, TwoS))
        ))
        [| 0x2euy; 0xa1uy; 0xdbuy; 0x32uy |]

      test64
        Opcode.FSQRT
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V6, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS))
        ))
        [| 0x6euy; 0xa1uy; 0xf8uy; 0xa6uy |]

    /// C4.6.18 Advanced SIMD vector x indexed element
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD vector x indexed elem Parse Test`` () =
      test64
        Opcode.SMLAL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V26, FourS)),
          OprSIMD (SIMDVecReg (R.V6, EightH)),
          OprSIMD (sVRegIdx R.V2 VecH 6uy)
        ))
        [| 0x4fuy; 0x62uy; 0x28uy; 0xdauy |]

      test64
        Opcode.SQDMLAL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V2, TwoD)),
          OprSIMD (SIMDVecReg (R.V26, FourS)),
          OprSIMD (sVRegIdx R.V17 VecS 3uy)
        ))
        [| 0x4fuy; 0xb1uy; 0x3buy; 0x42uy |]

      test64
        Opcode.SMLSL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V10, FourS)),
          OprSIMD (SIMDVecReg (R.V14, EightH)),
          OprSIMD (sVRegIdx R.V9 VecH 3uy)
        ))
        [| 0x4fuy; 0x79uy; 0x61uy; 0xcauy |]

      test64
        Opcode.SQDMLSL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V15, TwoD)),
          OprSIMD (SIMDVecReg (R.V1, TwoS)),
          OprSIMD (sVRegIdx R.V18 VecS 0uy)
        ))
        [| 0x0fuy; 0x92uy; 0x70uy; 0x2fuy |]

      test64
        Opcode.MUL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V2, FourH)),
          OprSIMD (SIMDVecReg (R.V26, FourH)),
          OprSIMD (sVRegIdx R.V3 VecH 3uy)
        ))
        [| 0x0fuy; 0x73uy; 0x83uy; 0x42uy |]

      test64
        Opcode.SMULL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V6, FourH)),
          OprSIMD (sVRegIdx R.V12 VecH 6uy)
        ))
        [| 0x0fuy; 0x6cuy; 0xa8uy; 0xc5uy |]

      test64
        Opcode.SQDMULL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V2, TwoD)),
          OprSIMD (SIMDVecReg (R.V26, FourS)),
          OprSIMD (sVRegIdx R.V29 VecS 3uy)
        ))
        [| 0x4fuy; 0xbduy; 0xbbuy; 0x42uy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V29, FourS)),
          OprSIMD (SIMDVecReg (R.V26, FourS)),
          OprSIMD (sVRegIdx R.V29 VecS 2uy)
        ))
        [| 0x4fuy; 0x9duy; 0xcbuy; 0x5duy |]

      test64
        Opcode.SQRDMULH
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V26, FourH)),
          OprSIMD (SIMDVecReg (R.V30, FourH)),
          OprSIMD (sVRegIdx R.V13 VecH 1uy)
        ))
        [| 0x0fuy; 0x5duy; 0xd3uy; 0xdauy |]

      test64
        Opcode.FMLA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, FourS)),
          OprSIMD (SIMDVecReg (R.V26, FourS)),
          OprSIMD (sVRegIdx R.V3 VecS 3uy)
        ))
        [| 0x4fuy; 0xa3uy; 0x1buy; 0x5buy |]

      test64
        Opcode.FMLS
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, TwoD)),
          OprSIMD (SIMDVecReg (R.V26, TwoD)),
          OprSIMD (sVRegIdx R.V19 VecD 0uy)
        ))
        [| 0x4fuy; 0xd3uy; 0x53uy; 0x5buy |]

      test64
        Opcode.FMUL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V27, FourS)),
          OprSIMD (SIMDVecReg (R.V26, FourS)),
          OprSIMD (sVRegIdx R.V3 VecS 2uy)
        ))
        [| 0x4fuy; 0x83uy; 0x9buy; 0x5buy |]

      test64
        Opcode.MLA
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V30, FourS)),
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (sVRegIdx R.V13 VecS 3uy)
        ))
        [| 0x6fuy; 0xaduy; 0x08uy; 0xbeuy |]

      test64
        Opcode.UMLAL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V22, FourS)),
          OprSIMD (SIMDVecReg (R.V26, EightH)),
          OprSIMD (sVRegIdx R.V15 VecH 7uy)
        ))
        [| 0x6fuy; 0x7fuy; 0x2buy; 0x56uy |]

      test64
        Opcode.MLS
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V10, FourS)),
          OprSIMD (SIMDVecReg (R.V4, FourS)),
          OprSIMD (sVRegIdx R.V23 VecS 2uy)
        ))
        [| 0x6fuy; 0x97uy; 0x48uy; 0x8auy |]

      test64
        Opcode.UMLSL
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V30, FourS)),
          OprSIMD (SIMDVecReg (R.V6, FourH)),
          OprSIMD (sVRegIdx R.V14 VecH 2uy)
        ))
        [| 0x2fuy; 0x6euy; 0x60uy; 0xdeuy |]

      test64
        Opcode.UMULL2
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V10, TwoD)),
          OprSIMD (SIMDVecReg (R.V7, FourS)),
          OprSIMD (sVRegIdx R.V31 VecS 3uy)
        ))
        [| 0x6fuy; 0xbfuy; 0xa8uy; 0xeauy |]

      test64
        Opcode.FMULX
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V5, FourS)),
          OprSIMD (SIMDVecReg (R.V22, FourS)),
          OprSIMD (sVRegIdx R.V13 VecS 1uy)
        ))
        [| 0x6fuy; 0xaduy; 0x92uy; 0xc5uy |]

    /// C4.6.19 Cryptographic AES
    [<TestMethod>]
    member __.``[AArch64] Cryptographic AES Parse Test`` () =
      test64
        Opcode.AESE
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V21, SixteenB))
        ))
        [| 0x4euy; 0x28uy; 0x4auy; 0xb5uy |]

      test64
        Opcode.AESD
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V21, SixteenB))
        ))
        [| 0x4euy; 0x28uy; 0x5auy; 0xb5uy |]

      test64
        Opcode.AESMC
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V21, SixteenB))
        ))
        [| 0x4euy; 0x28uy; 0x6auy; 0xb5uy |]

      test64
        Opcode.AESIMC
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V21, SixteenB)),
          OprSIMD (SIMDVecReg (R.V21, SixteenB))
        ))
        [| 0x4euy; 0x28uy; 0x7auy; 0xb5uy |]

    /// C4.6.20 Cryptographic three-register SHA
    [<TestMethod>]
    member __.``[AArch64] Cryptographic three-register SHA Parse Test`` () =
      test64
        Opcode.SHA1C
        (ThreeOperands (
          scalReg R.Q24,
          scalReg R.S27,
          OprSIMD (SIMDVecReg (R.V25, FourS))
        ))
        [| 0x5euy; 0x19uy; 0x03uy; 0x78uy |]

      test64
        Opcode.SHA1P
        (ThreeOperands (
          scalReg R.Q31,
          scalReg R.S31,
          OprSIMD (SIMDVecReg (R.V19, FourS))
        ))
        [| 0x5euy; 0x13uy; 0x13uy; 0xffuy |]

      test64
        Opcode.SHA1M
        (ThreeOperands (
          scalReg R.Q28,
          scalReg R.S21,
          OprSIMD (SIMDVecReg (R.V14, FourS))
        ))
        [| 0x5euy; 0x0euy; 0x22uy; 0xbcuy |]

      test64
        Opcode.SHA1SU0
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V7, FourS)),
          OprSIMD (SIMDVecReg (R.V16, FourS)),
          OprSIMD (SIMDVecReg (R.V23, FourS))
        ))
        [| 0x5euy; 0x17uy; 0x32uy; 0x07uy |]

      test64
        Opcode.SHA256H
        (ThreeOperands (
          scalReg R.Q30,
          scalReg R.Q30,
          OprSIMD (SIMDVecReg (R.V17, FourS))
        ))
        [| 0x5euy; 0x11uy; 0x43uy; 0xdeuy |]

      test64
        Opcode.SHA256H2
        (ThreeOperands (
          scalReg R.Q30,
          scalReg R.Q24,
          OprSIMD (SIMDVecReg (R.V25, FourS))
        ))
        [| 0x5euy; 0x19uy; 0x53uy; 0x1euy |]

      test64
        Opcode.SHA1SU0
        (ThreeOperands (
          OprSIMD (SIMDVecReg (R.V31, FourS)),
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V23, FourS))
        ))
        [| 0x5euy; 0x17uy; 0x32uy; 0xbfuy |]

    /// C4.6.21 Cryptographic two-register SHA
    [<TestMethod>]
    member __.``[AArch64] Cryptographic two-register SHA Parse Test`` () =
      test64
        Opcode.SHA1H
        (TwoOperands (scalReg R.S31, scalReg R.S10))
        [| 0x5euy; 0x28uy; 0x09uy; 0x5fuy |]

      test64
        Opcode.SHA1SU1
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V23, FourS)),
          OprSIMD (SIMDVecReg (R.V30, FourS))
        ))
        [| 0x5euy; 0x28uy; 0x1buy; 0xd7uy |]

      test64
        Opcode.SHA256SU0
        (TwoOperands (
          OprSIMD (SIMDVecReg (R.V21, FourS)),
          OprSIMD (SIMDVecReg (R.V10, FourS))
        ))
        [| 0x5euy; 0x28uy; 0x29uy; 0x55uy |]

    /// C4.6.22 Floating-point compare
    [<TestMethod>]
    member __.``[AArch64] Floating-point compare Parse Test`` () =
      test64
        Opcode.FCMP
        (TwoOperands (scalReg R.S7, scalReg R.S21))
        [| 0x1euy; 0x35uy; 0x20uy; 0xe0uy |]

      test64
        Opcode.FCMP
        (TwoOperands (scalReg R.S28, OprFPImm 0.0))
        [| 0x1euy; 0x31uy; 0x23uy; 0x88uy |]

      test64
        Opcode.FCMPE
        (TwoOperands (scalReg R.S22, scalReg R.S11))
        [| 0x1euy; 0x2buy; 0x22uy; 0xd0uy |]

      test64
        Opcode.FCMPE
        (TwoOperands (scalReg R.S17, OprFPImm 0.0))
        [| 0x1euy; 0x39uy; 0x22uy; 0x38uy |]

      test64
        Opcode.FCMP
        (TwoOperands (scalReg R.D6, scalReg R.D2))
        [| 0x1euy; 0x62uy; 0x20uy; 0xc0uy |]

      test64
        Opcode.FCMP
        (TwoOperands (scalReg R.D14, OprFPImm 0.0))
        [| 0x1euy; 0x79uy; 0x21uy; 0xc8uy |]

      test64
        Opcode.FCMPE
        (TwoOperands (scalReg R.D11, scalReg R.D20))
        [| 0x1euy; 0x74uy; 0x21uy; 0x70uy |]

      test64
        Opcode.FCMPE
        (TwoOperands (scalReg R.D29, OprFPImm 0.0))
        [| 0x1euy; 0x63uy; 0x23uy; 0xb8uy |]

    /// C4.6.23 Floating-point conditional compare
    [<TestMethod>]
    member __.``[AArch64] Floating-point conditional compare Parse Test`` () =
      test64
        Opcode.FCCMP
        (FourOperands (scalReg R.S26, scalReg R.S13, OprNZCV 0xDuy, OprCond CS))
        [| 0x1euy; 0x2duy; 0x27uy; 0x4duy |]

      test64
        Opcode.FCCMPE
        (FourOperands (scalReg R.S26, scalReg R.S10, OprNZCV 6uy, OprCond AL))
        [| 0x1euy; 0x2auy; 0xe7uy; 0x56uy |]

      test64
        Opcode.FCCMP
        (FourOperands (scalReg R.D18, scalReg R.D9, OprNZCV 9uy, OprCond CC))
        [| 0x1euy; 0x69uy; 0x36uy; 0x49uy |]

      test64
        Opcode.FCCMPE
        (FourOperands (scalReg R.D26, scalReg R.D14, OprNZCV 2uy, OprCond AL))
        [| 0x1euy; 0x6euy; 0xe7uy; 0x52uy |]

    /// C4.6.24 Floating-point conditional select
    [<TestMethod>]
    member __.``[AArch64] Floating-point conditional select Parse Test`` () =
      test64
        Opcode.FCSEL
        (FourOperands (scalReg R.S27, scalReg R.S2, scalReg R.S9, OprCond CS))
        [| 0x1euy; 0x29uy; 0x2cuy; 0x5buy |]

      test64
        Opcode.FCSEL
        (FourOperands (scalReg R.D19, scalReg R.D10, scalReg R.D28, OprCond AL))
        [| 0x1euy; 0x7cuy; 0xeduy; 0x53uy |]

    /// C4.6.25 Floating-point data-processing (1 source)
    [<TestMethod>]
    member __.``[AArch64] FP data-processing (1 source) Parse Test`` () =
      test64
        Opcode.FMOV
        (TwoOperands (scalReg R.S26, scalReg R.S17))
        [| 0x1euy; 0x20uy; 0x42uy; 0x3auy |]

      test64
        Opcode.FABS
        (TwoOperands (scalReg R.S10, scalReg R.S7))
        [| 0x1euy; 0x20uy; 0xc0uy; 0xeauy |]

      test64
        Opcode.FNEG
        (TwoOperands (scalReg R.S14, scalReg R.S8))
        [| 0x1euy; 0x21uy; 0x41uy; 0x0euy |]

      test64
        Opcode.FSQRT
        (TwoOperands (scalReg R.S24, scalReg R.S11))
        [| 0x1euy; 0x21uy; 0xc1uy; 0x78uy |]

      test64
        Opcode.FCVT
        (TwoOperands (scalReg R.D10, scalReg R.S22))
        [| 0x1euy; 0x22uy; 0xc2uy; 0xcauy |]

      test64
        Opcode.FCVT
        (TwoOperands (scalReg R.H16, scalReg R.S15))
        [| 0x1euy; 0x23uy; 0xc1uy; 0xf0uy |]

      test64
        Opcode.FRINTN
        (TwoOperands (scalReg R.S1, scalReg R.S19))
        [| 0x1euy; 0x24uy; 0x42uy; 0x61uy |]

      test64
        Opcode.FRINTP
        (TwoOperands (scalReg R.S28, scalReg R.S10))
        [| 0x1euy; 0x24uy; 0xc1uy; 0x5cuy |]

      test64
        Opcode.FRINTM
        (TwoOperands (scalReg R.S24, scalReg R.S14))
        [| 0x1euy; 0x25uy; 0x41uy; 0xd8uy |]

      test64
        Opcode.FRINTZ
        (TwoOperands (scalReg R.S14, scalReg R.S6))
        [| 0x1euy; 0x25uy; 0xc0uy; 0xceuy |]

      test64
        Opcode.FRINTA
        (TwoOperands (scalReg R.S12, scalReg R.S10))
        [| 0x1euy; 0x26uy; 0x41uy; 0x4cuy |]

      test64
        Opcode.FRINTX
        (TwoOperands (scalReg R.S24, scalReg R.S11))
        [| 0x1euy; 0x27uy; 0x41uy; 0x78uy |]

      test64
        Opcode.FRINTI
        (TwoOperands (scalReg R.S2, scalReg R.S15))
        [| 0x1euy; 0x27uy; 0xc1uy; 0xe2uy |]

      test64
        Opcode.FMOV
        (TwoOperands (scalReg R.D20, scalReg R.D17))
        [| 0x1euy; 0x60uy; 0x42uy; 0x34uy |]

      test64
        Opcode.FABS
        (TwoOperands (scalReg R.D2, scalReg R.D17))
        [| 0x1euy; 0x60uy; 0xc2uy; 0x22uy |]

      test64
        Opcode.FNEG
        (TwoOperands (scalReg R.D2, scalReg R.D21))
        [| 0x1euy; 0x61uy; 0x42uy; 0xa2uy |]

      test64
        Opcode.FSQRT
        (TwoOperands (scalReg R.D6, scalReg R.D13))
        [| 0x1euy; 0x61uy; 0xc1uy; 0xa6uy |]

      test64
        Opcode.FCVT
        (TwoOperands (scalReg R.S13, scalReg R.D14))
        [| 0x1euy; 0x62uy; 0x41uy; 0xcduy |]

      test64
        Opcode.FCVT
        (TwoOperands (scalReg R.H10, scalReg R.D21))
        [| 0x1euy; 0x63uy; 0xc2uy; 0xaauy |]

      test64
        Opcode.FRINTN
        (TwoOperands (scalReg R.D3, scalReg R.D15))
        [| 0x1euy; 0x64uy; 0x41uy; 0xe3uy |]

      test64
        Opcode.FRINTP
        (TwoOperands (scalReg R.D18, scalReg R.D21))
        [| 0x1euy; 0x64uy; 0xc2uy; 0xb2uy |]

      test64
        Opcode.FRINTM
        (TwoOperands (scalReg R.D20, scalReg R.D27))
        [| 0x1euy; 0x65uy; 0x43uy; 0x74uy |]

      test64
        Opcode.FRINTZ
        (TwoOperands (scalReg R.D2, scalReg R.D23))
        [| 0x1euy; 0x65uy; 0xc2uy; 0xe2uy |]

      test64
        Opcode.FRINTA
        (TwoOperands (scalReg R.D17, scalReg R.D26))
        [| 0x1euy; 0x66uy; 0x43uy; 0x51uy |]

      test64
        Opcode.FRINTX
        (TwoOperands (scalReg R.D24, scalReg R.D21))
        [| 0x1euy; 0x67uy; 0x42uy; 0xb8uy |]

      test64
        Opcode.FRINTI
        (TwoOperands (scalReg R.D21, scalReg R.D27))
        [| 0x1euy; 0x67uy; 0xc3uy; 0x75uy |]

      test64
        Opcode.FCVT
        (TwoOperands (scalReg R.S20, scalReg R.H14))
        [| 0x1euy; 0xe2uy; 0x41uy; 0xd4uy |]

      test64
        Opcode.FCVT
        (TwoOperands (scalReg R.D8, scalReg R.H28))
        [| 0x1euy; 0xe2uy; 0xc3uy; 0x88uy |]

    /// C4.6.26 Floating-point data-processing (2 source)
    [<TestMethod>]
    member __.``[AArch64] FP data-processing (2 source) Parse Test`` () =
      test64
        Opcode.FMUL
        (ThreeOperands (scalReg R.S2, scalReg R.S1, scalReg R.S1))
        [| 0x1euy; 0x21uy; 0x08uy; 0x22uy |]

      test64
        Opcode.FDIV
        (ThreeOperands (scalReg R.S8, scalReg R.S20, scalReg R.S2))
        [| 0x1euy; 0x22uy; 0x1auy; 0x88uy |]

      test64
        Opcode.FADD
        (ThreeOperands (scalReg R.S14, scalReg R.S5, scalReg R.S2))
        [| 0x1euy; 0x22uy; 0x28uy; 0xaeuy |]

      test64
        Opcode.FSUB
        (ThreeOperands (scalReg R.S22, scalReg R.S10, scalReg R.S3))
        [| 0x1euy; 0x23uy; 0x39uy; 0x56uy |]

      test64
        Opcode.FMAX
        (ThreeOperands (scalReg R.S20, scalReg R.S23, scalReg R.S4))
        [| 0x1euy; 0x24uy; 0x4auy; 0xf4uy |]

      test64
        Opcode.FMIN
        (ThreeOperands (scalReg R.S21, scalReg R.S8, scalReg R.S5))
        [| 0x1euy; 0x25uy; 0x59uy; 0x15uy |]

      test64
        Opcode.FMAXNM
        (ThreeOperands (scalReg R.S18, scalReg R.S9, scalReg R.S6))
        [| 0x1euy; 0x26uy; 0x69uy; 0x32uy |]

      test64
        Opcode.FMINNM
        (ThreeOperands (scalReg R.S26, scalReg R.S5, scalReg R.S7))
        [| 0x1euy; 0x27uy; 0x78uy; 0xbauy |]

      test64
        Opcode.FNMUL
        (ThreeOperands (scalReg R.S26, scalReg R.S21, scalReg R.S8))
        [| 0x1euy; 0x28uy; 0x8auy; 0xbauy |]

      test64
        Opcode.FMUL
        (ThreeOperands (scalReg R.D27, scalReg R.D21, scalReg R.D9))
        [| 0x1euy; 0x69uy; 0x0auy; 0xbbuy |]

      test64
        Opcode.FDIV
        (ThreeOperands (scalReg R.D2, scalReg R.D5, scalReg R.D10))
        [| 0x1euy; 0x6auy; 0x18uy; 0xa2uy |]

      test64
        Opcode.FADD
        (ThreeOperands (scalReg R.D26, scalReg R.D21, scalReg R.D11))
        [| 0x1euy; 0x6buy; 0x2auy; 0xbauy |]

      test64
        Opcode.FSUB
        (ThreeOperands (scalReg R.D30, scalReg R.D13, scalReg R.D12))
        [| 0x1euy; 0x6cuy; 0x39uy; 0xbeuy |]

      test64
        Opcode.FMAX
        (ThreeOperands (scalReg R.D26, scalReg R.D5, scalReg R.D13))
        [| 0x1euy; 0x6duy; 0x48uy; 0xbauy |]

      test64
        Opcode.FMIN
        (ThreeOperands (scalReg R.D27, scalReg R.D21, scalReg R.D14))
        [| 0x1euy; 0x6euy; 0x5auy; 0xbbuy |]

      test64
        Opcode.FMAXNM
        (ThreeOperands (scalReg R.D2, scalReg R.D23, scalReg R.D18))
        [| 0x1euy; 0x72uy; 0x6auy; 0xe2uy |]

      test64
        Opcode.FMINNM
        (ThreeOperands (scalReg R.D2, scalReg R.D4, scalReg R.D31))
        [| 0x1euy; 0x7fuy; 0x78uy; 0x82uy |]

      test64
        Opcode.FNMUL
        (ThreeOperands (scalReg R.D20, scalReg R.D30, scalReg R.D0))
        [| 0x1euy; 0x60uy; 0x8buy; 0xd4uy |]

    /// C4.6.27 Floating-point data-processing (3 source)
    [<TestMethod>]
    member __.``[AArch64] FP data-processing (3 source) Parse Test`` () =
      test64
        Opcode.FMADD
        (FourOperands (
          scalReg R.S25,
          scalReg R.S26,
          scalReg R.S31,
          scalReg R.S1
        ))
        [| 0x1fuy; 0x1fuy; 0x07uy; 0x59uy |]

      test64
        Opcode.FMSUB
        (FourOperands (
          scalReg R.S4,
          scalReg R.S26,
          scalReg R.S30,
          scalReg R.S2
        ))
        [| 0x1fuy; 0x1euy; 0x8buy; 0x44uy |]

      test64
        Opcode.FNMADD
        (FourOperands (
          scalReg R.S22,
          scalReg R.S8,
          scalReg R.S28,
          scalReg R.S4
        ))
        [| 0x1fuy; 0x3cuy; 0x11uy; 0x16uy |]

      test64
        Opcode.FNMSUB
        (FourOperands (
          scalReg R.S21,
          scalReg R.S14,
          scalReg R.S24,
          scalReg R.S8
        ))
        [| 0x1fuy; 0x38uy; 0xa1uy; 0xd5uy |]

      test64
        Opcode.FMADD
        (FourOperands (
          scalReg R.D25,
          scalReg R.D10,
          scalReg R.D16,
          scalReg R.D16
        ))
        [| 0x1fuy; 0x50uy; 0x41uy; 0x59uy |]

      test64
        Opcode.FMSUB
        (FourOperands (
          scalReg R.D29,
          scalReg R.D14,
          scalReg R.D8,
          scalReg R.D24
        ))
        [| 0x1fuy; 0x48uy; 0xe1uy; 0xdduy |]

      test64
        Opcode.FNMADD
        (FourOperands (
          scalReg R.D17,
          scalReg R.D11,
          scalReg R.D4,
          scalReg R.D28
        ))
        [| 0x1fuy; 0x64uy; 0x71uy; 0x71uy |]

      test64
        Opcode.FNMSUB
        (FourOperands (
          scalReg R.D17,
          scalReg R.D3,
          scalReg R.D2,
          scalReg R.D30
        ))
        [| 0x1fuy; 0x62uy; 0xf8uy; 0x71uy |]

    /// C4.6.28 Floating-point immediate
    [<TestMethod>]
    member __.``[AArch64] Floating-point immediate Parse Test`` () =
      test64
        Opcode.FMOV
        (TwoOperands (scalReg R.S21, OprFPImm 2.0))
        [| 0x1euy; 0x20uy; 0x10uy; 0x15uy |]

      test64
        Opcode.FMOV
        (TwoOperands (scalReg R.D25, OprFPImm 10.5))
        [| 0x1euy; 0x64uy; 0xb0uy; 0x19uy |]

    /// C4.6.29 Conversion between floating-point and fixed-point
    [<TestMethod>]
    member __.``[AArch64] Conversion between FP and fixed-pt Parse Test`` () =
      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.S28, OprRegister R.W5, OprFbits 0x16uy))
        [| 0x1euy; 0x02uy; 0xa8uy; 0xbcuy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.S5, OprRegister R.W5, OprFbits 2uy))
        [| 0x1euy; 0x03uy; 0xf8uy; 0xa5uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (OprRegister R.W17, scalReg R.S4, OprFbits 1uy))
        [| 0x1euy; 0x18uy; 0xfcuy; 0x91uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (OprRegister R.W5, scalReg R.S14, OprFbits 0x1Fuy))
        [| 0x1euy; 0x19uy; 0x85uy; 0xc5uy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.D5, OprRegister R.W14, OprFbits 0xFuy))
        [| 0x1euy; 0x42uy; 0xc5uy; 0xc5uy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.D5, OprRegister R.W14, OprFbits 0x17uy))
        [| 0x1euy; 0x43uy; 0xa5uy; 0xc5uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (OprRegister R.W5, scalReg R.D14, OprFbits 0x1Buy))
        [| 0x1euy; 0x58uy; 0x95uy; 0xc5uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (OprRegister R.W5, scalReg R.D26, OprFbits 0x16uy))
        [| 0x1euy; 0x59uy; 0xabuy; 0x45uy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.S17, OprRegister R.X6, OprFbits 0xFuy))
        [| 0x9euy; 0x02uy; 0xc4uy; 0xd1uy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.S5, OprRegister R.X13, OprFbits 0x13uy))
        [| 0x9euy; 0x03uy; 0xb5uy; 0xa5uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (OprRegister R.X13, scalReg R.S6, OprFbits 4uy))
        [| 0x9euy; 0x18uy; 0xf0uy; 0xcduy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (OprRegister R.X13, scalReg R.S14, OprFbits 0x1Buy))
        [| 0x9euy; 0x19uy; 0x95uy; 0xcduy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.D5, OprRegister R.X28, OprFbits 0x1Euy))
        [| 0x9euy; 0x42uy; 0x8buy; 0x85uy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.D5, OprRegister R.X14, OprFbits 0xFuy))
        [| 0x9euy; 0x43uy; 0xc5uy; 0xc5uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (OprRegister R.X17, scalReg R.D22, OprFbits 7uy))
        [| 0x9euy; 0x58uy; 0xe6uy; 0xd1uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (OprRegister R.X18, scalReg R.D14, OprFbits 0xCuy))
        [| 0x9euy; 0x59uy; 0xd1uy; 0xd2uy |]

    /// C4.6.30 Conversion between floating-point and integer
    [<TestMethod>]
    member __.``[AArch64] Conversion between FP and integer Parse Test`` () =
      test64
        Opcode.FCVTNS
        (TwoOperands (OprRegister R.W20, scalReg R.S10))
        [| 0x1euy; 0x20uy; 0x01uy; 0x54uy |]

      test64
        Opcode.FCVTNS
        (TwoOperands (OprRegister R.W10, scalReg R.D26))
        [| 0x1euy; 0x60uy; 0x03uy; 0x4auy |]

      test64
        Opcode.FCVTNS
        (TwoOperands (OprRegister R.X2, scalReg R.S11))
        [| 0x9euy; 0x20uy; 0x01uy; 0x62uy |]

      test64
        Opcode.FCVTNS
        (TwoOperands (OprRegister R.X23, scalReg R.D18))
        [| 0x9euy; 0x60uy; 0x02uy; 0x57uy |]

      test64
        Opcode.FCVTNU
        (TwoOperands (OprRegister R.W24, scalReg R.S5))
        [| 0x1euy; 0x21uy; 0x00uy; 0xb8uy |]

      test64
        Opcode.FCVTNU
        (TwoOperands (OprRegister R.W18, scalReg R.D21))
        [| 0x1euy; 0x61uy; 0x02uy; 0xb2uy |]

      test64
        Opcode.FCVTNU
        (TwoOperands (OprRegister R.X27, scalReg R.S5))
        [| 0x9euy; 0x21uy; 0x00uy; 0xbbuy |]

      test64
        Opcode.FCVTNU
        (TwoOperands (OprRegister R.X28, scalReg R.D13))
        [| 0x9euy; 0x61uy; 0x01uy; 0xbcuy |]

      test64
        Opcode.SCVTF
        (TwoOperands (scalReg R.S26, OprRegister R.W5))
        [| 0x1euy; 0x22uy; 0x00uy; 0xbauy |]

      test64
        Opcode.SCVTF
        (TwoOperands (scalReg R.D8, OprRegister R.W15))
        [| 0x1euy; 0x62uy; 0x01uy; 0xe8uy |]

      test64
        Opcode.SCVTF
        (TwoOperands (scalReg R.S2, OprRegister R.X14))
        [| 0x9euy; 0x22uy; 0x01uy; 0xc2uy |]

      test64
        Opcode.SCVTF
        (TwoOperands (scalReg R.D29, OprRegister R.X14))
        [| 0x9euy; 0x62uy; 0x01uy; 0xdduy |]

      test64
        Opcode.UCVTF
        (TwoOperands (scalReg R.S29, OprRegister R.W21))
        [| 0x1euy; 0x23uy; 0x02uy; 0xbduy |]

      test64
        Opcode.UCVTF
        (TwoOperands (scalReg R.D7, OprRegister R.W14))
        [| 0x1euy; 0x63uy; 0x01uy; 0xc7uy |]

      test64
        Opcode.UCVTF
        (TwoOperands (scalReg R.S30, OprRegister R.X14))
        [| 0x9euy; 0x23uy; 0x01uy; 0xdeuy |]

      test64
        Opcode.UCVTF
        (TwoOperands (scalReg R.D25, OprRegister R.X21))
        [| 0x9euy; 0x63uy; 0x02uy; 0xb9uy |]

      test64
        Opcode.FCVTAS
        (TwoOperands (OprRegister R.W10, scalReg R.S12))
        [| 0x1euy; 0x24uy; 0x01uy; 0x8auy |]

      test64
        Opcode.FCVTAS
        (TwoOperands (OprRegister R.W25, scalReg R.D20))
        [| 0x1euy; 0x64uy; 0x02uy; 0x99uy |]

      test64
        Opcode.FCVTAS
        (TwoOperands (OprRegister R.X21, scalReg R.S18))
        [| 0x9euy; 0x24uy; 0x02uy; 0x55uy |]

      test64
        Opcode.FCVTAS
        (TwoOperands (OprRegister R.X24, scalReg R.D25))
        [| 0x9euy; 0x64uy; 0x03uy; 0x38uy |]

      test64
        Opcode.FCVTAU
        (TwoOperands (OprRegister R.W29, scalReg R.S26))
        [| 0x1euy; 0x25uy; 0x03uy; 0x5duy |]

      test64
        Opcode.FCVTAU
        (TwoOperands (OprRegister R.W5, scalReg R.D26))
        [| 0x1euy; 0x65uy; 0x03uy; 0x45uy |]

      test64
        Opcode.FCVTAU
        (TwoOperands (OprRegister R.X17, scalReg R.S24))
        [| 0x9euy; 0x25uy; 0x03uy; 0x11uy |]

      test64
        Opcode.FCVTAU
        (TwoOperands (OprRegister R.X20, scalReg R.D27))
        [| 0x9euy; 0x65uy; 0x03uy; 0x74uy |]

      test64
        Opcode.FMOV
        (TwoOperands (OprRegister R.W14, scalReg R.S25))
        [| 0x1euy; 0x26uy; 0x03uy; 0x2euy |]

      test64
        Opcode.FMOV
        (TwoOperands (scalReg R.S3, OprRegister R.W14))
        [| 0x1euy; 0x27uy; 0x01uy; 0xc3uy |]

      test64
        Opcode.FMOV
        (TwoOperands (OprRegister R.X11, scalReg R.D21))
        [| 0x9euy; 0x66uy; 0x02uy; 0xabuy |]

      test64
        Opcode.FMOV
        (TwoOperands (scalReg R.D3, OprRegister R.X15))
        [| 0x9euy; 0x67uy; 0x01uy; 0xe3uy |]

      test64
        Opcode.FMOV
        (TwoOperands (
          OprRegister R.X29,
          OprSIMD (sVRegIdx R.V16 VecD 1uy)
        ))
        [| 0x9euy; 0xaeuy; 0x02uy; 0x1duy |]

      test64
        Opcode.FMOV
        (TwoOperands (
          OprSIMD (sVRegIdx R.V24 VecD 1uy),
          OprRegister R.X23
        ))
        [| 0x9euy; 0xafuy; 0x02uy; 0xf8uy |]

      test64
        Opcode.FCVTPS
        (TwoOperands (OprRegister R.W14, scalReg R.S6))
        [| 0x1euy; 0x28uy; 0x00uy; 0xceuy |]

      test64
        Opcode.FCVTPS
        (TwoOperands (OprRegister R.W6, scalReg R.D3))
        [| 0x1euy; 0x68uy; 0x00uy; 0x66uy |]

      test64
        Opcode.FCVTPS
        (TwoOperands (OprRegister R.X3, scalReg R.S17))
        [| 0x9euy; 0x28uy; 0x02uy; 0x23uy |]

      test64
        Opcode.FCVTPS
        (TwoOperands (OprRegister R.X26, scalReg R.D27))
        [| 0x9euy; 0x68uy; 0x03uy; 0x7auy |]

      test64
        Opcode.FCVTPU
        (TwoOperands (OprRegister R.W28, scalReg R.S16))
        [| 0x1euy; 0x29uy; 0x02uy; 0x1cuy |]

      test64
        Opcode.FCVTPU
        (TwoOperands (OprRegister R.W19, scalReg R.D9))
        [| 0x1euy; 0x69uy; 0x01uy; 0x33uy |]

      test64
        Opcode.FCVTPU
        (TwoOperands (OprRegister R.X9, scalReg R.S3))
        [| 0x9euy; 0x29uy; 0x00uy; 0x69uy |]

      test64
        Opcode.FCVTPU
        (TwoOperands (OprRegister R.X21, scalReg R.D19))
        [| 0x9euy; 0x69uy; 0x02uy; 0x75uy |]

      test64
        Opcode.FCVTMS
        (TwoOperands (OprRegister R.W29, scalReg R.S14))
        [| 0x1euy; 0x30uy; 0x01uy; 0xdduy |]

      test64
        Opcode.FCVTMS
        (TwoOperands (OprRegister R.W2, scalReg R.D27))
        [| 0x1euy; 0x70uy; 0x03uy; 0x62uy |]

      test64
        Opcode.FCVTMS
        (TwoOperands (OprRegister R.X25, scalReg R.S3))
        [| 0x9euy; 0x30uy; 0x00uy; 0x79uy |]

      test64
        Opcode.FCVTMS
        (TwoOperands (OprRegister R.X6, scalReg R.D4))
        [| 0x9euy; 0x70uy; 0x00uy; 0x86uy |]

      test64
        Opcode.FCVTMU
        (TwoOperands (OprRegister R.W5, scalReg R.S12))
        [| 0x1euy; 0x31uy; 0x01uy; 0x85uy |]

      test64
        Opcode.FCVTMU
        (TwoOperands (OprRegister R.W29, scalReg R.D19))
        [| 0x1euy; 0x71uy; 0x02uy; 0x7duy |]

      test64
        Opcode.FCVTMU
        (TwoOperands (OprRegister R.XZR, scalReg R.S31))
        [| 0x9euy; 0x31uy; 0x03uy; 0xffuy |]

      test64
        Opcode.FCVTMU
        (TwoOperands (OprRegister R.X0, scalReg R.D0))
        [| 0x9euy; 0x71uy; 0x00uy; 0x00uy |]

      test64
        Opcode.FCVTZS
        (TwoOperands (OprRegister R.W3, scalReg R.S26))
        [| 0x1euy; 0x38uy; 0x03uy; 0x43uy |]

      test64
        Opcode.FCVTZS
        (TwoOperands (OprRegister R.W13, scalReg R.D6))
        [| 0x1euy; 0x78uy; 0x00uy; 0xcduy |]

      test64
        Opcode.FCVTZS
        (TwoOperands (OprRegister R.X25, scalReg R.S19))
        [| 0x9euy; 0x38uy; 0x02uy; 0x79uy |]

      test64
        Opcode.FCVTZS
        (TwoOperands (OprRegister R.X6, scalReg R.D10))
        [| 0x9euy; 0x78uy; 0x01uy; 0x46uy |]

      test64
        Opcode.FCVTZU
        (TwoOperands (OprRegister R.W1, scalReg R.S19))
        [| 0x1euy; 0x39uy; 0x02uy; 0x61uy |]

      test64
        Opcode.FCVTZU
        (TwoOperands (OprRegister R.W27, scalReg R.D25))
        [| 0x1euy; 0x79uy; 0x03uy; 0x3buy |]

      test64
        Opcode.FCVTZU
        (TwoOperands (OprRegister R.X19, scalReg R.S2))
        [| 0x9euy; 0x39uy; 0x00uy; 0x53uy |]

      test64
        Opcode.FCVTZU
        (TwoOperands (OprRegister R.X2, scalReg R.D19))
        [| 0x9euy; 0x79uy; 0x02uy; 0x62uy |]
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

module SPARC =

  open Microsoft.VisualStudio.TestTools.UnitTesting
  open B2R2
  open B2R2.FrontEnd.BinLifter.SPARC
  open B2R2.FrontEnd.BinLifter
  open B2R2.FrontEnd.BinInterface

  let private test opcode oprs (bytes: byte[]) =
    let reader = BinReader.binReaderLE
    let span = System.ReadOnlySpan bytes
    let ins = Parser.parse span reader 0UL
    Assert.AreEqual (ins.Info.Opcode, opcode)
    Assert.AreEqual (ins.Info.Operands, oprs)

  [<TestClass>]
  type SPARCUnitTest () =
    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands ADD Parse Test`` () =
      test Opcode.ADD
          (ThreeOperands (OprReg R.O2, OprReg R.O5, OprReg R.O7))
          [| 0x0duy; 0x80uy; 0x02uy; 0x9euy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Op, One Imm Op ADD Parse Test`` () =
      test Opcode.ADD
          (ThreeOperands (OprReg R.O2, OprImm -2422, OprReg R.O7))
          [| 0x8auy; 0xb6uy; 0x02uy; 0x9euy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands SUB Parse Test`` () =
      test Opcode.SUB
          (ThreeOperands (OprReg R.I2, OprReg R.L1, OprReg R.O1))
          [| 0x11uy; 0x80uy; 0x26uy; 0x92uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands SUBcc Parse Test`` () =
      test Opcode.SUBcc
          (ThreeOperands (OprReg R.O2, OprReg R.L3, OprReg R.I5))
          [| 0x13uy; 0x80uy; 0xa2uy; 0xbauy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands UMULcc Parse Test`` () =
      test Opcode.UMULcc
          (ThreeOperands (OprReg R.L5, OprReg R.O3, OprReg R.I1))
          [| 0x0buy; 0x40uy; 0xd5uy; 0xb2uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands 64-bit MULX Parse Test`` () =
      test Opcode.MULX
          (ThreeOperands (OprReg R.O5, OprReg R.G5, OprReg R.I3))
          [| 0x05uy; 0x40uy; 0x4buy; 0xb6uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands SMUL Parse Test`` () =
      test Opcode.SMUL
          (ThreeOperands (OprReg R.G6, OprReg R.I6, OprReg R.L3))
          [| 0x1euy; 0x80uy; 0x59uy; 0xa6uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands SDIVcc Parse Test`` () =
      test Opcode.SDIVcc
          (ThreeOperands (OprReg R.I3, OprReg R.O3, OprReg R.L6))
          [| 0x0buy; 0xc0uy; 0xfeuy; 0xacuy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands UDIVX Parse Test`` () =
      test Opcode.UDIVX
          (ThreeOperands (OprReg R.O5, OprReg R.L3, OprReg R.I2))
          [| 0x13uy; 0x40uy; 0x6buy; 0xb4uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Ops, One Imm Op XOR Parse Test`` () =
      test Opcode.XOR
          (ThreeOperands (OprReg R.I1, OprImm 1023, OprReg R.L1))
          [| 0xffuy; 0x63uy; 0x1euy; 0xa2uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands ANDN Parse Test`` () =
      test Opcode.ANDN
          (ThreeOperands (OprReg R.L2, OprReg R.O2, OprReg R.I2))
          [| 0x0auy; 0x80uy; 0x2cuy; 0xb4uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Operands NEG Parse Test`` () =
      test Opcode.SUB
          (ThreeOperands (OprReg R.G0, OprReg R.O2, OprReg R.O3))
          [| 0x0auy; 0x00uy; 0x20uy; 0x96uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands SLL Parse Test`` () =
      test Opcode.SLL
          (ThreeOperands (OprReg R.O2, OprImm 15, OprReg R.G4))
          [| 0x0fuy; 0xa0uy; 0x2auy; 0x89uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands SRL Parse Test`` () =
      test Opcode.SRL
          (ThreeOperands (OprReg R.I3, OprReg R.L6, OprReg R.O1))
          [| 0x16uy; 0xc0uy; 0x36uy; 0x93uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Ops, One Imme Op 64-bit SRAX Parse Test`` () =
      test Opcode.SRAX
          (ThreeOperands (OprReg R.L0, OprImm 63, OprReg R.G1))
          [| 0x3fuy; 0x30uy; 0x3cuy; 0x83uy |]

    [<TestMethod>]
    member __.``[SPARC] One Reg Op, One Imm Op SETHI Parse Test`` () =
      test Opcode.SETHI
          (TwoOperands (OprImm -1024, OprReg R.L1))
          [| 0xffuy; 0xffuy; 0x3fuy; 0x23uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands LDSB Parse Test`` () =
      test Opcode.LDSB
          (ThreeOperands (OprReg R.I2, OprImm -1, OprReg R.I6))
          [| 0xffuy; 0xbfuy; 0x4euy; 0xfcuy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands LDUH Parse Test`` () =
      test Opcode.LDUH
          (ThreeOperands (OprReg R.I5, OprReg R.L2, OprReg R.O4))
          [| 0x12uy; 0x40uy; 0x17uy; 0xd8uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands LDD Parse Test`` () =
      test Opcode.LDD
          (ThreeOperands (OprReg R.G0, OprImm -1, OprReg R.L7))
          [| 0xffuy; 0x3fuy; 0x18uy; 0xeeuy |]
    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands STB Parse Test`` () =
      test Opcode.STB
          (ThreeOperands (OprReg R.L4, OprReg R.G0, OprImm 341))
          [| 0x55uy; 0x21uy; 0x28uy; 0xe8uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Op, One Imm Op ST Parse Test`` () =
      test Opcode.STW
          (ThreeOperands (OprReg R.I4, OprReg R.L3, OprImm 42))
          [| 0x2auy; 0xe0uy; 0x24uy; 0xf8uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands STD Parse Test`` () =
      test Opcode.STD
          (ThreeOperands (OprReg R.G1, OprReg R.L1, OprReg R.O2))
          [| 0x0auy; 0x40uy; 0x3cuy; 0xc2uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Operands JMPL Parse Test`` () =
      test Opcode.JMPL
          (ThreeOperands (OprReg R.G0, OprReg R.G6, OprReg R.O7))
          [| 0x06uy; 0x00uy; 0xc0uy; 0x9fuy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Op, One Imm Op JMPL Parse Test`` () =
      test Opcode.JMPL
          (ThreeOperands (OprReg R.I7, OprImm 8, OprReg R.G0))
          [| 0x08uy; 0xe0uy; 0xc7uy; 0x81uy |]

    // [<TestMethod>]
    // member __.``[SPARC] Two Reg Operands BNE Parse Test`` () =
    //   test Opcode.BNE
    //       (TwoOperands (OprImm 0, OprImm 16))
    //       [| 0x04uy; 0x00uy; 0x80uy; 0x12uy |]

    [<TestMethod>]
    member __.``[SPARC] No Operands NOP Parse Test`` () =
      test Opcode.NOP
          (NoOperand)
          [| 0x00uy; 0x00uy; 0x00uy; 0x01uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Operands FMOVS Parse Test`` () =
      test Opcode.FMOVs
          (TwoOperands (OprReg R.F2, OprReg R.F2))
          [| 0x22uy; 0x00uy; 0xa0uy; 0x85uy |]

    [<TestMethod>]
    member __.``[SPARC] One Imm Op, One FLoat Reg Op LD Parse Test`` () =
      test Opcode.LDF
          (ThreeOperands (OprReg R.G0, OprImm 0, OprReg R.F27))
          [| 0x00uy; 0x20uy; 0x00uy; 0xf7uy |]

    [<TestMethod>]
    member __.``[SPARC] One FLoat Reg Op, One Imm Op STDF Parse Test`` () =
      test Opcode.STDF
          (ThreeOperands (OprReg R.F6, OprReg R.G0, OprImm 10))
          [| 0x0auy; 0x20uy; 0x38uy; 0xcduy |]

    [<TestMethod>]
    member __.``[SPARC] Three Float Reg Op Single FADDs Parse Test`` () =
      test Opcode.FADDs
          (ThreeOperands (OprReg R.F0, OprReg R.F1, OprReg R.F2))
          [| 0x21uy; 0x08uy; 0xa0uy; 0x85uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Float Reg Op FNEGd Parse Test`` () =
      test Opcode.FNEGd
          (TwoOperands (OprReg R.F32, OprReg R.F2))
          [| 0xc1uy; 0x00uy; 0xa0uy; 0x85uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Float Reg Op FSQRTq Parse Test`` () =
      test Opcode.FSQRTq
          (TwoOperands (OprReg R.F36, OprReg R.F4))
          [| 0x65uy; 0x05uy; 0xa0uy; 0x89uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Float Reg Op FiTOs Parse Test`` () =
      test Opcode.FiTOs
          (TwoOperands (OprReg R.F2, OprReg R.F2))
          [| 0x82uy; 0x18uy; 0xa0uy; 0x85uy |]

    [<TestMethod>]
    member __.``[SPARC] One CC Op, Two Reg Op FCMPs Parse Test`` () =
      test Opcode.FCMPs
          (ThreeOperands (OprCC ConditionCode.Fcc0, OprReg R.F2, OprReg R.F3))
          [| 0x23uy; 0x8auy; 0xa8uy; 0x81uy |]

    [<TestMethod>]
    member __.``[SPARC] One CC Op, Two Reg Op FMOVFsE Parse Test`` () =
      test Opcode.FMOVFsE
          (ThreeOperands (OprCC ConditionCode.Fcc2, OprReg R.F0, OprReg R.F3))
          [| 0x20uy; 0x50uy; 0xaauy; 0x87uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Op FMOVRqGZ Parse Test`` () =
      test Opcode.FMOVRqGZ
          (ThreeOperands (OprReg R.G0, OprReg R.F0, OprReg R.F0))
          [| 0xe0uy; 0x18uy; 0xa8uy; 0x81uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Op, 1 Imm STF Parse Test`` () =
      test Opcode.STF
          (ThreeOperands (OprReg R.F4, OprReg R.G0, OprImm 1))
          [| 0x01uy; 0x20uy; 0x20uy; 0xc9uy |]

    [<TestMethod>]
    member __.``[SPARC] Two Reg Op, 1 Imm Op LDDF Parse Test`` () =
      test Opcode.LDDF
          (ThreeOperands (OprReg R.L2, OprImm 1, OprReg R.F2))
          [| 0x01uy; 0xa0uy; 0x1cuy; 0xc5uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Op STFQ Parse Test`` () =
      test Opcode.STQF
          (ThreeOperands (OprReg R.F56, OprReg R.L4, OprReg R.G0))
          [| 0x00uy; 0x00uy; 0x35uy; 0xf3uy |]

    [<TestMethod>]
    member __.``[SPARC] Three Reg Op LDFSR Parse Test`` () =
      test Opcode.LDFSR
          (ThreeOperands (OprReg R.L4, OprReg R.I5, OprReg R.FSR))
          [| 0x1duy; 0x00uy; 0x0duy; 0xc1uy |]
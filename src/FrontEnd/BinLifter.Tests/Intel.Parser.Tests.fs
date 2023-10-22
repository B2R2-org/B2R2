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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter

module Intel =
  open B2R2.FrontEnd.BinLifter.Intel

  let private test prefs segment wordSize opcode oprs length (bytes: byte[]) =
    let parser = IntelParser (wordSize) :> IInstructionParsable
    let ins = parser.Parse (bytes, 0UL) :?> IntelInternalInstruction
    Assert.AreEqual (ins.Prefixes, prefs)
    Assert.AreEqual (Helper.getSegment ins.Prefixes, segment)
    Assert.AreEqual (ins.Opcode, opcode)
    Assert.AreEqual (ins.Operands, oprs)
    Assert.AreEqual (ins.Length, length)

  let private test32 = test Prefix.PrxNone None WordSize.Bit32
  let private test32WithPrx prefix = test prefix None WordSize.Bit32
  let private test64 = test Prefix.PrxNone None WordSize.Bit64

  /// 5.1 GENERAL-PURPOSE INSTRUCTIONS
  [<TestClass>]
  type GeneralPurposeClass () =
    /// 5.1.1 Data Transfer Instruction
    [<TestMethod>]
    member __.``Intel Data Transfer Parse Test`` () =
      test32
        Opcode.MOV
        (TwoOperands (
          OprMem (None, None, Some 2210584L, 32<rt>),
          OprImm (2L, 32<rt>)
        ))
        10ul
        [| 0xc7uy
           0x05uy
           0x18uy
           0xbbuy
           0x21uy
           0x00uy
           0x02uy
           0x00uy
           0x00uy
           0x00uy |]

      test64
        Opcode.PUSH
        (OneOperand (OprImm (0x44332211L, 32<rt>)))
        5ul
        [| 0x68uy; 0x11uy; 0x22uy; 0x33uy; 0x44uy |]

      test32
        Opcode.MOVSX
        (TwoOperands (OprReg R.EDI, OprMem (Some R.EDI, None, Some -1L, 8<rt>)))
        4ul
        [| 0x0fuy; 0xbeuy; 0x7fuy; 0xffuy |]

      test64
        Opcode.MOVSXD
        (TwoOperands (OprReg R.RCX, OprReg R.EAX))
        3ul
        [| 0x48uy; 0x63uy; 0xc8uy |]

    /// 5.1.2 Binary Arithmetic Instructions
    [<TestMethod>]
    member __.``Intel Binary Arithmetic Parse Test`` () =
      test64
        Opcode.ADD
        (TwoOperands (OprReg R.RCX, OprReg R.RAX))
        3ul
        [| 0x48uy; 0x03uy; 0xc8uy |]

      test32
        Opcode.IMUL
        (ThreeOperands (OprReg R.EDI, OprReg R.EDX, OprImm (10L, 8<rt>)))
        3ul
        [| 0x6buy; 0xfauy; 0x0auy |]

      test32
        Opcode.MUL
        (OneOperand (OprMem (Some R.EAX, None, None, 32<rt>)))
        2ul
        [| 0xf7uy; 0x20uy |]

      test32 Opcode.DIV (OneOperand (OprReg R.ECX)) 2ul [| 0xf7uy; 0xf1uy |]

    /// 5.1.3 Decimal Arithmetic Instructions
    [<TestMethod>]
    member __.``Decimal Arithmetic Parse Test`` () =
      test32 Opcode.AAA NoOperand 1ul [| 0x37uy |]

      test32 Opcode.AAS NoOperand 1ul [| 0x3Fuy |]

    /// 5.1.4 Logical Instructions
    [<TestMethod>]
    member __.``Intel Logical Parse Test`` () =
      test32
        Opcode.AND
        (TwoOperands (
          OprMem (Some R.ESP, Some (R.EDX, Scale.X1), None, 32<rt>),
          OprReg R.ESP
        ))
        3ul
        [| 0x21uy; 0x24uy; 0x14uy |]

      test32
        Opcode.AND
        (TwoOperands (
          OprMem (None, None, Some 1111638594L, 32<rt>),
          OprReg R.ESP
        ))
        6ul
        [| 0x21uy; 0x25uy; 0x42uy; 0x42uy; 0x42uy; 0x42uy |]

    /// 5.1.5 Shift and Rotate Instructions
    [<TestMethod>]
    member __.``Intel Shift And Rotate Parse Test`` () =
      test32
        Opcode.ROL
        (TwoOperands (
          OprMem (Some R.EAX, None, None, 32<rt>),
          OprImm (10L, 8<rt>)
        ))
        3ul
        [| 0xc1uy; 0x00uy; 0x0auy |]

      test32
        Opcode.ROL
        (TwoOperands (
          OprMem (Some R.EAX, None, None, 8<rt>),
          OprImm (10L, 8<rt>)
        ))
        3ul
        [| 0xc0uy; 0x00uy; 0x0auy |]

    /// 5.1.6 Bit and Byte Instructions
    [<TestMethod>]
    member __.``Intel Bit And Byte Parse Test`` () =
      test32
        Opcode.TEST
        (TwoOperands (
          OprMem (Some R.EAX, None, None, 8<rt>),
          OprImm (10L, 8<rt>)
        ))
        3ul
        [| 0xf6uy; 0x00uy; 0x0auy |]

    /// 5.1.7 Control Transfer Instructions
    [<TestMethod>]
    member __.``Intel Control Transfer Parse Test`` () =
      test32
        Opcode.JMPNear
        (OneOperand (OprReg R.ESP))
        2ul
        [| 0xffuy; 0xe4uy |]

      test32
        Opcode.JMPFar
        (OneOperand (OprDirAddr (Absolute (0x90s, 0x78563412UL, 32<rt>))))
        7ul
        [| 0xeauy; 0x12uy; 0x34uy; 0x56uy; 0x78uy; 0x90uy; 0x00uy |]

      test
        Prefix.PrxGS
        (Some R.GS)
        WordSize.Bit32
        Opcode.CALLNear
        (OneOperand (OprMem (None, None, Some 16L, 32<rt>)))
        7ul
        [| 0x65uy; 0xffuy; 0x15uy; 0x10uy; 0x00uy; 0x00uy; 0x00uy |]

      test32
        Opcode.CALLFar
        (OneOperand (OprDirAddr (Absolute (0x10s, 0x32547698UL, 32<rt>))))
        7ul
        [| 0x9auy; 0x98uy; 0x76uy; 0x54uy; 0x32uy; 0x10uy; 0x00uy |]

      test32
        Opcode.INT
        (OneOperand (OprImm (1L, 8<rt>)))
        2ul
        [| 0xcduy; 0x01uy |]

    /// 5.1.9 I/O Instructions
    [<TestMethod>]
    member __.``I/O Instructions Parse Test`` () =
      test32
        Opcode.IN
        (TwoOperands (OprReg R.EAX, OprReg R.DX))
        1ul
        [| 0xEDuy |]

      test32
        Opcode.OUT
        (TwoOperands (OprReg R.DX, OprReg R.AL))
        1ul
        [| 0xEEuy |]

      test32WithPrx
        Prefix.PrxOPSIZE
        Opcode.OUT
        (TwoOperands (OprReg R.DX, OprReg R.AX))
        2ul
        [| 0x66uy; 0xEFuy |]

      test32
        Opcode.OUT
        (TwoOperands (OprReg R.DX, OprReg R.EAX))
        1ul
        [| 0xEFuy |]

    /// 5.1.12 Segment Register Instructions
    [<TestMethod>]
    member __.``Segment Register Parse Test`` () =
      test32
        Opcode.LES
        (TwoOperands (OprReg R.ECX, OprMem (Some R.EDI, None, None, 48<rt>)))
        2ul
        [| 0xc4uy; 0x0fuy |]

      test32
        Opcode.LDS
        (TwoOperands (OprReg R.EDX, OprMem (Some R.ECX, None, None, 48<rt>)))
        2ul
        [| 0xc5uy; 0x11uy |]

  /// 5.2 X87 FPU INSTRUCTIONS
  [<TestClass>]
  type X87FPUClass () =
    /// 5.2.1 x87 FPU Data Transfer Instructions
    [<TestMethod>]
    member __.``Intel FPU Data Transfer Parse Test`` () =
      test32
        Opcode.FILD
        (OneOperand (
          OprMem (Some R.EDX, Some (R.ECX, Scale.X8), Some 67305985L, 16<rt>)
        ))
        7ul
        [| 0xdfuy; 0x84uy; 0xcauy; 0x01uy; 0x02uy; 0x03uy; 0x04uy |]

      test32
        Opcode.FBLD
        (OneOperand (OprMem (Some R.EAX, None, None, 80<rt>)))
        2ul
        [| 0xdfuy; 0x20uy |]

    /// 5.2.3 x87 FPU Comparison Instructions
    [<TestMethod>]
    member __.``Intel FPU Comparision Parse Test`` () =
      test32
        Opcode.FCOMIP
        (TwoOperands (OprReg R.ST0, OprReg R.ST1))
        2ul
        [| 0xdfuy; 0xf1uy |]

      test32
        Opcode.FUCOMIP
        (TwoOperands (OprReg R.ST0, OprReg R.ST1))
        2ul
        [| 0xdfuy; 0xe9uy |]

  /// 5.4 MMX INSTRUCTIONS
  [<TestClass>]
  type MMXClass () =
    /// 5.4.1 MMX Conversion Instructions
    [<TestMethod>]
    member __.``Intel MMX Conversion Parse Test`` () =
      test64
        Opcode.VMOVQ
        (TwoOperands (
          OprMem (Some R.RAX, None, Some 67305985L, 64<rt>),
          OprReg (R.XMM2)
        ))
        9ul
        [| 0xc4uy
           0xe1uy
           0xf9uy
           0xd6uy
           0x90uy
           0x01uy
           0x02uy
           0x03uy
           0x04uy |]

      test64
        Opcode.VMOVQ
        (TwoOperands (OprReg (R.XMM0), OprReg (R.XMM2)))
        5ul
        [| 0xc4uy; 0xe1uy; 0xf9uy; 0xd6uy; 0xd0uy |]

    /// 5.4.4 MMX Comparison Instructions
    [<TestMethod>]
    member __.``Intel MMX Comparison Parse Test`` () =
      test64
        Opcode.PCMPEQW
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        3u
        [| 0x0Fuy; 0x75uy; 0x01uy |]

      test64
        Opcode.PCMPEQW
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        3u
        [| 0x0Fuy; 0x75uy; 0xc1uy |]

      test64
        Opcode.PCMPEQW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        4u
        [| 0x66uy; 0x0Fuy; 0x75uy; 0x01uy |]

      test64
        Opcode.PCMPEQW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        4u
        [| 0x66uy; 0x0Fuy; 0x75uy; 0xc1uy |]

  /// 5.5 SSE INSTRUCTIONS
  [<TestClass>]
  type SSEClass () =
    /// 5.5.1 SSE SIMD Single-Precision Floating-Point Instructions
    /// 5.5.1.6 SSE Conversion Instructions
    [<TestMethod>]
    member __.``Intel SSE Conversion Parse Test`` () =
      test64
        Opcode.VCVTSS2SI
        (TwoOperands (
          OprReg R.RDX,
          OprMem (Some R.RAX, None, Some 67305985L, 32<rt>)
        ))
        9ul
        [| 0xc4uy
           0xe1uy
           0xfauy
           0x2duy
           0x90uy
           0x01uy
           0x02uy
           0x03uy
           0x04uy |]

      test64
        Opcode.VCVTSD2SI
        (TwoOperands (
          OprReg R.EDX,
          OprMem (Some R.RAX, None, Some 67305985L, 64<rt>)
        ))
        9ul
        [| 0xc4uy
           0xe1uy
           0x7buy
           0x2duy
           0x90uy
           0x01uy
           0x02uy
           0x03uy
           0x04uy |]

  /// 5.6 SSE2 INSTRUCTIONS
  [<TestClass>]
  type SSE2Class () =
    /// 5.6.3 SSE2 128-Bits SIMD Integer Instructions
    [<TestMethod>]
    member __.``Intel SSE 128-Bits SIMD Interger Parse Test`` () =
      test64
        Opcode.VMOVDQA64
        (TwoOperands (
          OprReg R.ZMM1,
          OprMem (Some R.RSP, None, Some 64L, 512<rt>)
        ))
        8ul
        [| 0x62uy; 0xf1uy; 0xfduy; 0x48uy; 0x6fuy; 0x4cuy; 0x24uy; 0x01uy |]

  /// 5.8 SUPPLEMENTAL STREAMING SIMD EXTENSIONS 3 (SSSE3) INSTRUCTIONS
  [<TestClass>]
  type SSSE3Class () =
    /// 5.8.1 Horizontal Addition/Subtraction
    [<TestMethod>]
    member __.``Intel Horizontal Addition/Subtraction Parse Test`` () =
      test64
        Opcode.PHADDW
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x01uy; 0x01uy |]

      test64
        Opcode.PHADDW
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x01uy; 0xc1uy |]

      test64
        Opcode.PHADDW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x01uy; 0x01uy |]

      test64
        Opcode.PHADDW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x01uy; 0xc1uy |]

      test64
        Opcode.PHADDSW
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x03uy; 0x01uy |]

      test64
        Opcode.PHADDSW
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x03uy; 0xc1uy |]

      test64
        Opcode.PHADDSW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x03uy; 0x01uy |]

      test64
        Opcode.PHADDSW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x03uy; 0xc1uy |]

      test64
        Opcode.PHADDD
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x02uy; 0x01uy |]

      test64
        Opcode.PHADDD
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x02uy; 0xc1uy |]

      test64
        Opcode.PHADDD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x02uy; 0x01uy |]

      test64
        Opcode.PHADDD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x02uy; 0xc1uy |]

      test64
        Opcode.PHSUBW
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x05uy; 0x01uy |]

      test64
        Opcode.PHSUBW
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x05uy; 0xc1uy |]

      test64
        Opcode.PHSUBW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x05uy; 0x01uy |]

      test64
        Opcode.PHSUBW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x05uy; 0xc1uy |]

      test64
        Opcode.PHSUBSW
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x07uy; 0x01uy |]

      test64
        Opcode.PHSUBSW
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x07uy; 0xc1uy |]

      test64
        Opcode.PHSUBSW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x07uy; 0x01uy |]

      test64
        Opcode.PHSUBSW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x07uy; 0xc1uy |]

      test64
        Opcode.PHSUBD
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x06uy; 0x01uy |]

      test64
        Opcode.PHSUBD
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x06uy; 0xc1uy |]

      test64
        Opcode.PHSUBD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x06uy; 0x01uy |]

      test64
        Opcode.PHSUBD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x06uy; 0xc1uy |]

    /// 5.8.2 Packed Absolute Values
    [<TestMethod>]
    member __.``Intel Packed Absolute Values Parse Test`` () =
      test64
        Opcode.PABSB
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x1Cuy; 0x01uy |]

      test64
        Opcode.PABSB
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x1Cuy; 0xc1uy |]

      test64
        Opcode.PABSB
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x1Cuy; 0x01uy |]

      test64
        Opcode.PABSB
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x1Cuy; 0xc1uy |]

      test64
        Opcode.PABSD
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x1Euy; 0x01uy |]

      test64
        Opcode.PABSD
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x1Euy; 0xc1uy |]

      test64
        Opcode.PABSD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x1Euy; 0x01uy |]

      test64
        Opcode.PABSD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x1Euy; 0xc1uy |]

      test64
        Opcode.PABSW
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x1Duy; 0x01uy |]

      test64
        Opcode.PABSW
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x1Duy; 0xc1uy |]

      test64
        Opcode.PABSW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x1Duy; 0x01uy |]

      test64
        Opcode.PABSW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x1Duy; 0xc1uy |]

    /// 5.8.4 Packed Multiply High with Round and Scale
    [<TestMethod>]
    member __.``Intel Packed Mul High with Round and Scale Parse Test`` () =
      test64
        Opcode.PMULHRSW
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x0Buy; 0x01uy |]

      test64
        Opcode.PMULHRSW
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x0Buy; 0xc1uy |]

      test64
        Opcode.PMULHRSW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x0Buy; 0x01uy |]

      test64
        Opcode.PMULHRSW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x0Buy; 0xc1uy |]

    /// 5.8.6 Packed Sign
    [<TestMethod>]
    member __.``Intel Packed Sign Parse Test`` () =
      test64
        Opcode.PSIGNB
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x08uy; 0x01uy |]

      test64
        Opcode.PSIGNB
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x08uy; 0xc1uy |]

      test64
        Opcode.PSIGNB
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x08uy; 0x01uy |]

      test64
        Opcode.PSIGNB
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x08uy; 0xc1uy |]

      test64
        Opcode.PSIGNW
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x09uy; 0x01uy |]

      test64
        Opcode.PSIGNW
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x09uy; 0xc1uy |]

      test64
        Opcode.PSIGNW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x09uy; 0x01uy |]

      test64
        Opcode.PSIGNW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x09uy; 0xc1uy |]

      test64
        Opcode.PSIGND
        (TwoOperands (OprReg R.MM0, OprMem (Some R.RCX, None, None, 64<rt>)))
        4u
        [| 0x0Fuy; 0x38uy; 0x0Auy; 0x01uy |]

      test64
        Opcode.PSIGND
        (TwoOperands (OprReg R.MM0, OprReg R.MM1))
        4u
        [| 0x0Fuy; 0x38uy; 0x0Auy; 0xc1uy |]

      test64
        Opcode.PSIGND
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RCX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x0Auy; 0x01uy |]

      test64
        Opcode.PSIGND
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM1))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x0Auy; 0xc1uy |]

    /// 5.8.7 Packed Align Right
    [<TestMethod>]
    member __.``Intel Packed Align Right Parse Test`` () =
      test64
        Opcode.PALIGNR
        (ThreeOperands (OprReg R.XMM2, OprReg R.XMM1, OprImm (1L, 8<rt>)))
        6ul
        [| 0x66uy; 0x0fuy; 0x3auy; 0x0fuy; 0xd1uy; 0x01uy |]

  /// 5.10 SSE4.1 INSTRUCTIONS
  [<TestClass>]
  type SSSE41Class () =
    /// 5.10.1 Dword Multiply Instructions
    [<TestMethod>]
    member __.``Intel Dword Multiply Parse Test`` () =
      test64
        Opcode.PMULLD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x40uy; 0x02uy |]

      test64
        Opcode.PMULLD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x40uy; 0xc2uy |]

      test64
        Opcode.PMULDQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x28uy; 0x02uy |]

      test64
        Opcode.PMULDQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x28uy; 0xc2uy |]

    /// 5.10.5 Packed Integer MIN/MAX Instructions
    [<TestMethod>]
    member __.``Intel Packed Integer MIN/MAX Parse Test`` () =
      test64
        Opcode.PMINUW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Auy; 0x02uy |]

      test64
        Opcode.PMINUW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Auy; 0xc2uy |]

      test64
        Opcode.PMINSD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x39uy; 0x02uy |]

      test64
        Opcode.PMINSD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x39uy; 0xc2uy |]

      test64
        Opcode.PMAXUW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Euy; 0x02uy |]

      test64
        Opcode.PMAXUW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Euy; 0xc2uy |]

      test64
        Opcode.PMAXUD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Fuy; 0x02uy |]

      test64
        Opcode.PMAXUD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Fuy; 0xc2uy |]

      test64
        Opcode.PMAXSB
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Cuy; 0x02uy |]

      test64
        Opcode.PMAXSB
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Cuy; 0xc2uy |]

      test64
        Opcode.PMAXSD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Duy; 0x02uy |]

      test64
        Opcode.PMAXSD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x3Duy; 0xc2uy |]

    /// 5.10.8 Packed Integer Format Conversions
    [<TestMethod>]
    member __.``Intel Packed Integer Format Conversions Parse Test`` () =
      test64
        Opcode.PMOVSXBD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 32<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x21uy; 0x02uy |]

      test64
        Opcode.PMOVSXBD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x21uy; 0xc2uy |]

      test64
        Opcode.PMOVSXBQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 16<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x22uy; 0x02uy |]

      test64
        Opcode.PMOVSXBQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x22uy; 0xc2uy |]

      test64
        Opcode.PMOVSXBW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 64<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x20uy; 0x02uy |]

      test64
        Opcode.PMOVSXBW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x20uy; 0xc2uy |]

      test64
        Opcode.PMOVSXDQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 64<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x25uy; 0x02uy |]

      test64
        Opcode.PMOVSXDQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x25uy; 0xc2uy |]

      test64
        Opcode.PMOVSXWD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 64<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x23uy; 0x02uy |]

      test64
        Opcode.PMOVSXWD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x23uy; 0xc2uy |]

      test64
        Opcode.PMOVSXWQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 32<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x24uy; 0x02uy |]

      test64
        Opcode.PMOVSXWQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x24uy; 0xc2uy |]

      test64
        Opcode.PMOVZXBD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 32<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x31uy; 0x02uy |]

      test64
        Opcode.PMOVZXBD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x31uy; 0xc2uy |]

      test64
        Opcode.PMOVZXBQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 16<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x32uy; 0x02uy |]

      test64
        Opcode.PMOVZXBQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x32uy; 0xc2uy |]

      test64
        Opcode.PMOVZXBW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 64<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x30uy; 0x02uy |]

      test64
        Opcode.PMOVZXBW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x30uy; 0xc2uy |]

      test64
        Opcode.PMOVZXDQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 64<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x35uy; 0x02uy |]

      test64
        Opcode.PMOVZXDQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x35uy; 0xc2uy |]

      test64
        Opcode.PMOVZXWD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 64<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x33uy; 0x02uy |]

      test64
        Opcode.PMOVZXWD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x33uy; 0xc2uy |]

      test64
        Opcode.PMOVZXWQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 32<rt>)))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x34uy; 0x02uy |]

      test64
        Opcode.PMOVZXWQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0fuy; 0x38uy; 0x34uy; 0xc2uy |]

    /// 5.10.10 Horizontal Search
    [<TestMethod>]
    member __.``Intel Horizontal Search Parse Test`` () =
      test64
        Opcode.PHMINPOSUW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x41uy; 0x02uy |]

      test64
        Opcode.PHMINPOSUW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x41uy; 0xc2uy |]

    /// 5.10.13 Dword Packing With Unsigned Saturation
    [<TestMethod>]
    member __.``Intel Dword Packing With Unsigned Saturation Parse Test`` () =
      test64
        Opcode.PACKUSDW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x2Buy; 0x02uy |]

      test64
        Opcode.PACKUSDW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x2Buy; 0xc2uy |]

  /// 5.11 SSE4.2 INSTRUCTION SET
  [<TestClass>]
  type SSSE42Class () =
    /// 5.11.2 Packed Comparison SIMD integer Instruction
    [<TestMethod>]
    member __.``Intel Packed Comparison SIMD integer Parse Test`` () =
      test64
        Opcode.PCMPGTQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RDX, None, None, 128<rt>)))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x37uy; 0x02uy |]

      test64
        Opcode.PCMPGTQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM2))
        5u
        [| 0x66uy; 0x0Fuy; 0x38uy; 0x37uy; 0xc2uy |]

  /// 5.22 INTEL MEMORY PROTECTION EXTENSIONS
  [<TestClass>]
  type IntelMemoryProtectionClass () =
    [<TestMethod>]
    member __.``Intel Memory Protection Extensions Parse Test`` () =
      test64
        Opcode.BNDMOV
        (TwoOperands (
          OprMem (Some R.RSP, None, Some 512L, 128<rt>),
          OprReg R.BND0
        ))
        9ul
        [| 0x66uy
           0x0fuy
           0x1buy
           0x84uy
           0x24uy
           0x00uy
           0x02uy
           0x00uy
           0x00uy |]

  /// INTEL ADVANCED VECTOR EXTENSIONS
  [<TestClass>]
  type AVXClass () =
    [<TestMethod>]
    member __.``Intel AVX Parse Test`` () =
      test64
        Opcode.VPCMPEQW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM10,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE1uy; 0x29uy; 0x75uy; 0x03uy |]

      test64
        Opcode.VPCMPEQW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM10, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE1uy; 0x29uy; 0x75uy; 0xc3uy |]

      test64
        Opcode.VPCMPEQW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM10,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE1uy; 0x2Duy; 0x75uy; 0x03uy |]

      test64
        Opcode.VPCMPEQW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM10, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE1uy; 0x2Duy; 0x75uy; 0xc3uy |]

      test64
        Opcode.VPABSB
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x1Cuy; 0x03uy |]

      test64
        Opcode.VPABSB
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x1Cuy; 0xc3uy |]

      test64
        Opcode.VPABSB
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 256<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x1Cuy; 0x03uy |]

      test64
        Opcode.VPABSB
        (TwoOperands (OprReg R.YMM0, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x1Cuy; 0xc3uy |]

      test64
        Opcode.VPABSD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x1Euy; 0x03uy |]

      test64
        Opcode.VPABSD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x1Euy; 0xc3uy |]

      test64
        Opcode.VPABSD
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 256<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x1Euy; 0x03uy |]

      test64
        Opcode.VPABSD
        (TwoOperands (OprReg R.YMM0, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x1Euy; 0xc3uy |]

      test64
        Opcode.VPABSW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x1Duy; 0x03uy |]

      test64
        Opcode.VPABSW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x1Duy; 0xc3uy |]

      test64
        Opcode.VPABSW
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 256<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x1Duy; 0x03uy |]

      test64
        Opcode.VPABSW
        (TwoOperands (OprReg R.YMM0, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x1Duy; 0xc3uy |]

      test64
        Opcode.VPHADDD
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x02uy; 0x03uy |]

      test64
        Opcode.VPHADDD
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x02uy; 0xc3uy |]

      test64
        Opcode.VPHADDD
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x02uy; 0x03uy |]

      test64
        Opcode.VPHADDD
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x02uy; 0xc3uy |]

      test64
        Opcode.VPHADDSW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x03uy; 0x03uy |]

      test64
        Opcode.VPHADDSW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x03uy; 0xc3uy |]

      test64
        Opcode.VPHADDSW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x03uy; 0x03uy |]

      test64
        Opcode.VPHADDSW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x03uy; 0xc3uy |]

      test64
        Opcode.VPHADDW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x01uy; 0x03uy |]

      test64
        Opcode.VPHADDW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x01uy; 0xc3uy |]

      test64
        Opcode.VPHADDW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x01uy; 0x03uy |]

      test64
        Opcode.VPHADDW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x01uy; 0xc3uy |]

      test64
        Opcode.VPHSUBD
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x06uy; 0x03uy |]

      test64
        Opcode.VPHSUBD
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x06uy; 0xc3uy |]

      test64
        Opcode.VPHSUBD
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x06uy; 0x03uy |]

      test64
        Opcode.VPHSUBD
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x06uy; 0xc3uy |]

      test64
        Opcode.VPHSUBSW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x07uy; 0x03uy |]

      test64
        Opcode.VPHSUBSW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x07uy; 0xc3uy |]

      test64
        Opcode.VPHSUBSW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x07uy; 0x03uy |]

      test64
        Opcode.VPHSUBSW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x07uy; 0xc3uy |]

      test64
        Opcode.VPHSUBW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x05uy; 0x03uy |]

      test64
        Opcode.VPHSUBW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x05uy; 0xc3uy |]

      test64
        Opcode.VPHSUBW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x05uy; 0x03uy |]

      test64
        Opcode.VPHSUBW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x05uy; 0xc3uy |]

      test64
        Opcode.VPMULHRSW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x0Buy; 0x03uy |]

      test64
        Opcode.VPMULHRSW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x0Buy; 0xc3uy |]

      test64
        Opcode.VPMULHRSW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x0Buy; 0x03uy |]

      test64
        Opcode.VPMULHRSW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x0Buy; 0xc3uy |]

      test64
        Opcode.VPSIGNB
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x08uy; 0x03uy |]

      test64
        Opcode.VPSIGNB
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x08uy; 0xc3uy |]

      test64
        Opcode.VPSIGNB
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x08uy; 0x03uy |]

      test64
        Opcode.VPSIGNB
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x08uy; 0xc3uy |]

      test64
        Opcode.VPSIGND
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x0Auy; 0x03uy |]

      test64
        Opcode.VPSIGND
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x0Auy; 0xc3uy |]

      test64
        Opcode.VPSIGND
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x0Auy; 0x03uy |]

      test64
        Opcode.VPSIGND
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x0Auy; 0xc3uy |]

      test64
        Opcode.VPSIGNW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x09uy; 0x03uy |]

      test64
        Opcode.VPSIGNW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x09uy; 0xc3uy |]

      test64
        Opcode.VPSIGNW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x09uy; 0x03uy |]

      test64
        Opcode.VPSIGNW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x09uy; 0xc3uy |]

      test64
        Opcode.VPACKUSDW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x2Buy; 0x03uy |]

      test64
        Opcode.VPACKUSDW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x2Buy; 0xc3uy |]

      test64
        Opcode.VPACKUSDW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x2Buy; 0x03uy |]

      test64
        Opcode.VPACKUSDW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x2Buy; 0xc3uy |]

      test64
        Opcode.VPCMPGTQ
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x37uy; 0x03uy |]

      test64
        Opcode.VPCMPGTQ
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x37uy; 0xc3uy |]

      test64
        Opcode.VPCMPGTQ
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x37uy; 0x03uy |]

      test64
        Opcode.VPCMPGTQ
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x37uy; 0xc3uy |]

      test64
        Opcode.VPHMINPOSUW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x41uy; 0x03uy |]

      test64
        Opcode.VPHMINPOSUW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x41uy; 0xc3uy |]

      test64
        Opcode.VPMAXSB
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Cuy; 0x03uy |]

      test64
        Opcode.VPMAXSB
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Cuy; 0xc3uy |]

      test64
        Opcode.VPMAXSB
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Cuy; 0x03uy |]

      test64
        Opcode.VPMAXSB
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Cuy; 0xc3uy |]

      test64
        Opcode.VPMAXSD
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Duy; 0x03uy |]

      test64
        Opcode.VPMAXSD
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Duy; 0xc3uy |]

      test64
        Opcode.VPMAXSD
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Duy; 0x03uy |]

      test64
        Opcode.VPMAXSD
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Duy; 0xc3uy |]

      test64
        Opcode.VPMAXUD
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Fuy; 0x03uy |]

      test64
        Opcode.VPMAXUD
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Fuy; 0xc3uy |]

      test64
        Opcode.VPMAXUD
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Fuy; 0x03uy |]

      test64
        Opcode.VPMAXUD
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Fuy; 0xc3uy |]

      test64
        Opcode.VPMAXUW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Euy; 0x03uy |]

      test64
        Opcode.VPMAXUW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Euy; 0xc3uy |]

      test64
        Opcode.VPMAXUW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Euy; 0x03uy |]

      test64
        Opcode.VPMAXUW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Euy; 0xc3uy |]

      test64
        Opcode.VPMINSB
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x38uy; 0x03uy |]

      test64
        Opcode.VPMINSB
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x38uy; 0xc3uy |]

      test64
        Opcode.VPMINSB
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x38uy; 0x03uy |]

      test64
        Opcode.VPMINSB
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x38uy; 0xc3uy |]

      test64
        Opcode.VPMINSD
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x39uy; 0x03uy |]

      test64
        Opcode.VPMINSD
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x39uy; 0xc3uy |]

      test64
        Opcode.VPMINSD
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x39uy; 0x03uy |]

      test64
        Opcode.VPMINSD
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x39uy; 0xc3uy |]

      test64
        Opcode.VPMINUW
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Auy; 0x03uy |]

      test64
        Opcode.VPMINUW
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x3Auy; 0xc3uy |]

      test64
        Opcode.VPMINUW
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Auy; 0x03uy |]

      test64
        Opcode.VPMINUW
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x3Auy; 0xc3uy |]

      test64
        Opcode.VPMOVSXBD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 32<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x21uy; 0x03uy |]

      test64
        Opcode.VPMOVSXBD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x21uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXBD
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x21uy; 0x03uy |]

      test64
        Opcode.VPMOVSXBD
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x21uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXBQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 16<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x22uy; 0x03uy |]

      test64
        Opcode.VPMOVSXBQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x22uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXBQ
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 32<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x22uy; 0x03uy |]

      test64
        Opcode.VPMOVSXBQ
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x22uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXBW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x20uy; 0x03uy |]

      test64
        Opcode.VPMOVSXBW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x20uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXBW
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x20uy; 0x03uy |]

      test64
        Opcode.VPMOVSXBW
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x20uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXDQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x25uy; 0x03uy |]

      test64
        Opcode.VPMOVSXDQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x25uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXDQ
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x25uy; 0x03uy |]

      test64
        Opcode.VPMOVSXDQ
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x25uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXWD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x23uy; 0x03uy |]

      test64
        Opcode.VPMOVSXWD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x23uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXWD
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x23uy; 0x03uy |]

      test64
        Opcode.VPMOVSXWD
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x23uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXWQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 32<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x24uy; 0x03uy |]

      test64
        Opcode.VPMOVSXWQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x24uy; 0xc3uy |]

      test64
        Opcode.VPMOVSXWQ
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x24uy; 0x03uy |]

      test64
        Opcode.VPMOVSXWQ
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x24uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXBD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 32<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x31uy; 0x03uy |]

      test64
        Opcode.VPMOVZXBD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x31uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXBD
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x31uy; 0x03uy |]

      test64
        Opcode.VPMOVZXBD
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x31uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXBQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 16<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x32uy; 0x03uy |]

      test64
        Opcode.VPMOVZXBQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x32uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXBQ
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 32<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x32uy; 0x03uy |]

      test64
        Opcode.VPMOVZXBQ
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x32uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXBW
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x30uy; 0x03uy |]

      test64
        Opcode.VPMOVZXBW
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x30uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXBW
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x30uy; 0x03uy |]

      test64
        Opcode.VPMOVZXBW
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x30uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXDQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x35uy; 0x03uy |]

      test64
        Opcode.VPMOVZXDQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x35uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXDQ
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x35uy; 0x03uy |]

      test64
        Opcode.VPMOVZXDQ
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x35uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXWD
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x33uy; 0x03uy |]

      test64
        Opcode.VPMOVZXWD
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x33uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXWD
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 128<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x33uy; 0x03uy |]

      test64
        Opcode.VPMOVZXWD
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x33uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXWQ
        (TwoOperands (OprReg R.XMM0, OprMem (Some R.RBX, None, None, 32<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x34uy; 0x03uy |]

      test64
        Opcode.VPMOVZXWQ
        (TwoOperands (OprReg R.XMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x34uy; 0xc3uy |]

      test64
        Opcode.VPMOVZXWQ
        (TwoOperands (OprReg R.YMM0, OprMem (Some R.RBX, None, None, 64<rt>)))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x34uy; 0x03uy |]

      test64
        Opcode.VPMOVZXWQ
        (TwoOperands (OprReg R.YMM0, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x34uy; 0xc3uy |]

      test64
        Opcode.VPMULDQ
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x28uy; 0x03uy |]

      test64
        Opcode.VPMULDQ
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x28uy; 0xc3uy |]

      test64
        Opcode.VPMULDQ
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x28uy; 0x03uy |]

      test64
        Opcode.VPMULDQ
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x28uy; 0xc3uy |]

      test64
        Opcode.VPMULLD
        (ThreeOperands (
          OprReg R.XMM0,
          OprReg R.XMM3,
          OprMem (Some R.RBX, None, None, 128<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x40uy; 0x03uy |]

      test64
        Opcode.VPMULLD
        (ThreeOperands (OprReg R.XMM0, OprReg R.XMM3, OprReg R.XMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x61uy; 0x40uy; 0xc3uy |]

      test64
        Opcode.VPMULLD
        (ThreeOperands (
          OprReg R.YMM0,
          OprReg R.YMM3,
          OprMem (Some R.RBX, None, None, 256<rt>)
        ))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x40uy; 0x03uy |]

      test64
        Opcode.VPMULLD
        (ThreeOperands (OprReg R.YMM0, OprReg R.YMM3, OprReg R.YMM3))
        5u
        [| 0xC4uy; 0xE2uy; 0x65uy; 0x40uy; 0xc3uy |]

#if !EMULATION
  /// Exception Test
  [<TestClass>]
  type ExceptionTestClass () =
    [<TestMethod>]
    [<ExpectedException(typedefof<ParsingFailureException>)>]
    member __.``Size cond ParsingFailure Test`` () =
      test64 Opcode.AAA NoOperand 1ul [| 0x37uy |]

      test64 Opcode.AAS NoOperand 1ul [| 0x3Fuy |]

      test64
        Opcode.JMPFar
        (OneOperand (OprDirAddr (Absolute (0x90s, 0x78563412UL, 32<rt>))))
        7ul
        [| 0xeauy; 0x12uy; 0x34uy; 0x56uy; 0x78uy; 0x90uy; 0x00uy |]

      test64
        Opcode.CALLFar
        (OneOperand (OprDirAddr (Absolute (0x10s, 0x32547698UL, 32<rt>))))
        7ul
        [| 0x9auy; 0x98uy; 0x76uy; 0x54uy; 0x32uy; 0x10uy; 0x00uy |]

      test64
        Opcode.LES
        (TwoOperands (OprReg R.ECX, OprMem (Some R.EDI, None, None, 48<rt>)))
        2ul
        [| 0xc4uy; 0x0fuy |]

      test64
        Opcode.LDS
        (TwoOperands (OprReg R.EDX, OprMem (Some R.ECX, None, None, 48<rt>)))
        2ul
        [| 0xc5uy; 0x11uy |]

  /// IR Test
  [<TestClass>]
  type TestClass () =
    [<TestMethod>]
    member __.``Intel IL Test`` () =
      let isa = ISA.Init Arch.IntelX86 Endian.Little
      let hdl = BinHandle (isa)
      Assert.AreEqual (0, hdl.File.Length)
#endif

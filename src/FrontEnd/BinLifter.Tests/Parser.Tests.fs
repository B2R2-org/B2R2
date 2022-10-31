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

module Intel =
  open B2R2.FrontEnd.BinLifter.Intel

  let private test prefs segment wordSize opcode oprs length (bytes: byte[]) =
    let parser = IntelParser (wordSize)
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
      let hdl = BinHandle.Init (isa)
      Assert.AreEqual (0, hdl.BinFile.Span.Length)
#endif

module ARMv7 =
  open B2R2.FrontEnd.BinLifter.ARM32

  let private test arch endian cond op w q simd oprs (bytes: byte[]) =
    let mode = ArchOperationMode.ARMMode
    let parser = ARM32Parser (ISA.Init arch endian, mode, None)
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

module ARM64 =
  open B2R2.FrontEnd.BinLifter.ARM64
  open B2R2.FrontEnd.BinLifter.ARM64.OperandHelper

  let private test endian opcode oprs bytes =
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
          Immediate 0x371L,
          Shift (SRTypeLSL, Imm 12L)
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
          Immediate 0x1L,
          Immediate 0x1L
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
          LSB 0x1uy
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
          Immediate 0x80000001L
        ))
        [| 0x12uy; 0x01uy; 0x04uy; 0x01uy |]

      test64
        Opcode.AND
        (ThreeOperands (
          OprRegister R.W1,
          OprRegister R.W0,
          Immediate 0xE0000001L
        ))
        [| 0x12uy; 0x03uy; 0x0cuy; 0x01uy |]

      test64
        Opcode.AND
        (ThreeOperands (OprRegister R.W1, OprRegister R.W0, Immediate 0x3L))
        [| 0x12uy; 0x20uy; 0x04uy; 0x01uy |]

      test64
        Opcode.AND
        (ThreeOperands (
          OprRegister R.W1,
          OprRegister R.W1,
          Immediate 0xffffffdfL
        ))
        [| 0x12uy; 0x1auy; 0x78uy; 0x21uy |]

      test64
        Opcode.AND
        (ThreeOperands (
          OprRegister R.X1,
          OprRegister R.X0,
          Immediate 0x300000003L
        ))
        [| 0x92uy; 0x20uy; 0x04uy; 0x01uy |]

    /// C4.2.5 Move wide (immediate)
    [<TestMethod>]
    member __.``[AArch64] Move wide (immediate) Parse Test`` () =
      test64
        Opcode.MOVN
        (ThreeOperands (
          OprRegister R.X21,
          Immediate 0x0L,
          Shift (SRTypeLSL, Imm 0x10L)
        ))
        [| 0x92uy; 0xa0uy; 0x00uy; 0x15uy |]

      test64
        Opcode.MOV
        (TwoOperands (OprRegister R.XZR, Immediate 0XE002FFFFFFFFFFFFL))
        [| 0x92uy; 0xe3uy; 0xffuy; 0xbfuy |] (* Alias of MOVN *)

      test64
        Opcode.MOV
        (TwoOperands (OprRegister R.W26, Immediate 0x7FFFFFFFL))
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
        (OneOperand (Immediate 0x3L))
        [| 0xd4uy; 0x00uy; 0x00uy; 0x61uy |]

    /// C4.3.4 System
    [<TestMethod>]
    member __.``[AArch64] System Parse Test`` () =
      test64
        Opcode.MSR
        (TwoOperands (Pstate SPSEL, Immediate 0x2L))
        [| 0xd5uy; 0x00uy; 0x42uy; 0xbfuy |]

      test64
        Opcode.MSR
        (TwoOperands (Pstate DAIFSET, Immediate 0x2L))
        [| 0xd5uy; 0x03uy; 0x42uy; 0xdfuy |]

      test64
        Opcode.HINT
        (OneOperand (Immediate 0x6L))
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
          Immediate 0L,
          OprRegister R.C15,
          OprRegister R.C4,
          Immediate 6L
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
        (ThreeOperands (OprRegister R.X3, Immediate 0x21L, memLabel 0x8L))
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
          SIMDOpr (
            FourRegs (
              SIMDVecReg (R.V5, EightB),
              SIMDVecReg (R.V6, EightB),
              SIMDVecReg (R.V7, EightB),
              SIMDVecReg (R.V8, EightB)
            )
          ),
          memBaseImm (R.X14, None)
        ))
        [| 0x0cuy; 0x00uy; 0x01uy; 0xc5uy |]

      test64
        Opcode.ST2
        (TwoOperands (
          SIMDOpr (
            TwoRegs (SIMDVecReg (R.V24, EightB), SIMDVecReg (R.V25, EightB))
          ),
          memBaseImm (R.X15, None)
        ))
        [| 0x0cuy; 0x00uy; 0x81uy; 0xf8uy |]

      test64
        Opcode.LD1
        (TwoOperands (
          SIMDOpr (
            FourRegs (
              SIMDVecReg (R.V29, OneD),
              SIMDVecReg (R.V30, OneD),
              SIMDVecReg (R.V31, OneD),
              SIMDVecReg (R.V0, OneD)
            )
          ),
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
          SIMDOpr (
            FourRegs (
              SIMDVecReg (R.V1, FourH),
              SIMDVecReg (R.V2, FourH),
              SIMDVecReg (R.V3, FourH),
              SIMDVecReg (R.V4, FourH)
            )
          ),
          memPostIdxReg (R.X1, R.X0, None)
        ))
        [| 0x0cuy; 0x80uy; 0x04uy; 0x21uy |]

      test64
        Opcode.ST4
        (TwoOperands (
          SIMDOpr (
            FourRegs (
              SIMDVecReg (R.V25, FourH),
              SIMDVecReg (R.V26, FourH),
              SIMDVecReg (R.V27, FourH),
              SIMDVecReg (R.V28, FourH)
            )
          ),
          memPostIdxReg (R.X9, R.X21, None)
        ))
        [| 0x0cuy; 0x95uy; 0x05uy; 0x39uy |]

      test64
        Opcode.ST4
        (TwoOperands (
          SIMDOpr (
            FourRegs (
              SIMDVecReg (R.V4, EightH),
              SIMDVecReg (R.V5, EightH),
              SIMDVecReg (R.V6, EightH),
              SIMDVecReg (R.V7, EightH)
            )
          ),
          memPostIdxImm (R.X20, Some 0x40L)
        ))
        [| 0x4cuy; 0x9fuy; 0x06uy; 0x84uy |]

      test64
        Opcode.LD3
        (TwoOperands (
          SIMDOpr (
            ThreeRegs (
              SIMDVecReg (R.V30, EightH),
              SIMDVecReg (R.V31, EightH),
              SIMDVecReg (R.V0, EightH)
            )
          ),
          memPostIdxReg (R.X21, R.X10, None)
        ))
        [| 0x4cuy; 0xcauy; 0x46uy; 0xbeuy |]

      test64
        Opcode.LD4
        (TwoOperands (
          SIMDOpr (
            FourRegs (
              SIMDVecReg (R.V4, EightH),
              SIMDVecReg (R.V5, EightH),
              SIMDVecReg (R.V6, EightH),
              SIMDVecReg (R.V7, EightH)
            )
          ),
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
          SIMDOpr (OneReg (sVRegIdx R.V30 VecB 5uy)),
          memBaseImm (R.X3, None)
        ))
        [| 0x0duy; 0x00uy; 0x14uy; 0x7euy |]

      test64
        Opcode.ST3
        (TwoOperands (
          SIMDOpr (
            ThreeRegs (
              sVRegIdx R.V3 VecB 1uy,
              sVRegIdx R.V4 VecB 1uy,
              sVRegIdx R.V5 VecB 1uy
            )
          ),
          memBaseImm (R.X14, None)
        ))
        [| 0x0duy; 0x00uy; 0x25uy; 0xc3uy |]

      test64
        Opcode.ST4
        (TwoOperands (
          SIMDOpr (
            FourRegs (
              sVRegIdx R.V29 VecS 3uy,
              sVRegIdx R.V30 VecS 3uy,
              sVRegIdx R.V31 VecS 3uy,
              sVRegIdx R.V0 VecS 3uy
            )
          ),
          memBaseImm (R.X21, None)
        ))
        [| 0x4duy; 0x20uy; 0xb2uy; 0xbduy |]

      test64
        Opcode.LD2
        (TwoOperands (
          SIMDOpr (
            TwoRegs (sVRegIdx R.V10 VecB 0xfuy, sVRegIdx R.V11 VecB 0xfuy)
          ),
          memBaseImm (R.X10, None)
        ))
        [| 0x4duy; 0x60uy; 0x1duy; 0x4auy |]

      test64
        Opcode.LD3R
        (TwoOperands (
          SIMDOpr (
            ThreeRegs (
              SIMDVecReg (R.V21, EightH),
              SIMDVecReg (R.V22, EightH),
              SIMDVecReg (R.V23, EightH)
            )
          ),
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
          SIMDOpr (OneReg (sVRegIdx R.V30 VecB 1uy)),
          memPostIdxReg (R.X21, R.X10, None)
        ))
        [| 0x0duy; 0x8auy; 0x06uy; 0xbeuy |]

      test64
        Opcode.ST1
        (TwoOperands (
          SIMDOpr (OneReg (sVRegIdx R.V30 VecH 7uy)),
          memPostIdxImm (R.X11, Some 0x2L)
        ))
        [| 0x4duy; 0x9fuy; 0x59uy; 0x7euy |]

      test64
        Opcode.ST2
        (TwoOperands (
          SIMDOpr (TwoRegs (sVRegIdx R.V29 VecS 2uy, sVRegIdx R.V30 VecS 2uy)),
          memPostIdxReg (R.X13, R.X21, None)
        ))
        [| 0x4duy; 0xb5uy; 0x81uy; 0xbduy |]

      test64
        Opcode.LD1
        (TwoOperands (
          SIMDOpr (OneReg (sVRegIdx R.V30 VecB 1uy)),
          memPostIdxReg (R.X21, R.X10, None)
        ))
        [| 0x0duy; 0xcauy; 0x06uy; 0xbeuy |]

      test64
        Opcode.LD4
        (TwoOperands (
          SIMDOpr (
            FourRegs (
              sVRegIdx R.V29 VecB 0xeuy,
              sVRegIdx R.V30 VecB 0xeuy,
              sVRegIdx R.V31 VecB 0xeuy,
              sVRegIdx R.V0 VecB 0xeuy
            )
          ),
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
        (TwoOperands (PrfOp PLIL2STRM, memLabel 0x1004L))
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
          Immediate 0x7L,
          memBaseReg (R.X3, R.W3, Some (ExtRegOffset (ExtUXTW, Some 0x3L)))
        ))
        [| 0xf8uy; 0xa3uy; 0x58uy; 0x67uy |]

      test64
        Opcode.PRFM
        (TwoOperands (
          PrfOp PLIL3KEEP,
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
        (TwoOperands (Immediate 0x1cL, memBaseImm (R.X3, Some 0x1fL)))
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
        (TwoOperands (PrfOp PSTL2KEEP, memBaseImm (R.X15, Some 0x7c00L)))
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
          ExtReg None
        ))
        [| 0x0buy; 0x3fuy; 0x43uy; 0xffuy |]

      test64
        Opcode.ADD
        (FourOperands (
          OprRegister R.WSP,
          OprRegister R.WSP,
          OprRegister R.WZR,
          ExtReg (Some (ShiftOffset (SRTypeLSL, Imm 2L)))
        ))
        [| 0x0buy; 0x3fuy; 0x4buy; 0xffuy |]

      test64
        Opcode.ADD
        (FourOperands (
          OprRegister R.SP,
          OprRegister R.X10,
          OprRegister R.W10,
          ExtReg (Some (ExtRegOffset (ExtUXTW, Some 2L)))
        ))
        [| 0x8buy; 0x2auy; 0x49uy; 0x5fuy |]

      test64
        Opcode.CMN
        (ThreeOperands (
          OprRegister R.SP,
          OprRegister R.X14,
          ExtReg (Some (ShiftOffset (SRTypeLSL, Imm 1L)))
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
          Shift (SRTypeASR, Imm 23L)
        ))
        [| 0x0buy; 0x8euy; 0x5fuy; 0x9buy |]

      test64
        Opcode.SUBS
        (FourOperands (
          OprRegister R.W11,
          OprRegister R.W29,
          OprRegister R.W14,
          Shift (SRTypeLSR, Imm 7L)
        ))
        [| 0x6buy; 0x4euy; 0x1fuy; 0xabuy |]

      test64
        Opcode.ADDS
        (FourOperands (
          OprRegister R.X18,
          OprRegister R.X29,
          OprRegister R.X14,
          Shift (SRTypeASR, Imm 7L)
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
        (FourOperands (OprRegister R.X3, Immediate 0x15L, NZCV 8uy, Cond GT))
        [| 0xbauy; 0x55uy; 0xc8uy; 0x68uy |]

    /// C4.5.5 Conditional compare (register)
    [<TestMethod>]
    member __.``[AArch64] Conditional compare (register) Parse Test`` () =
      test64
        Opcode.CCMN
        (FourOperands (
          OprRegister R.X15,
          OprRegister R.X28,
          NZCV 0xfuy,
          Cond PL
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
          Cond LS
        ))
        [| 0x9auy; 0x86uy; 0x92uy; 0xfcuy |]

      test64
        Opcode.CSINC
        (FourOperands (
          OprRegister R.W21,
          OprRegister R.W0,
          OprRegister R.W16,
          Cond CS
        )) // HS
        [| 0x1auy; 0x90uy; 0x24uy; 0x15uy |]

      test64
        Opcode.CINC
        (ThreeOperands (OprRegister R.W21, OprRegister R.W16, Cond CC)) // LO
        [| 0x1auy; 0x90uy; 0x26uy; 0x15uy |]

      test64
        Opcode.CSET
        (TwoOperands (OprRegister R.W7, Cond LE))
        [| 0x1auy; 0x9fuy; 0xc7uy; 0xe7uy |]

      test64
        Opcode.CINV
        (ThreeOperands (OprRegister R.X10, OprRegister R.X7, Cond LE))
        [| 0xdauy; 0x87uy; 0xc0uy; 0xeauy |]

      test64
        Opcode.CSETM
        (TwoOperands (OprRegister R.X10, Cond LE))
        [| 0xdauy; 0x9fuy; 0xc3uy; 0xeauy |]

      test64
        Opcode.CSINV
        (FourOperands (
          OprRegister R.X10,
          OprRegister R.X27,
          OprRegister R.XZR,
          Cond GT
        ))
        [| 0xdauy; 0x9fuy; 0xc3uy; 0x6auy |]

      test64
        Opcode.CSNEG
        (FourOperands (
          OprRegister R.W30,
          OprRegister R.W21,
          OprRegister R.W10,
          Cond AL
        ))
        [| 0x5auy; 0x8auy; 0xe6uy; 0xbeuy |]

      test64
        Opcode.CNEG
        (ThreeOperands (OprRegister R.W30, OprRegister R.W21, Cond LE))
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
          Shift (SRTypeLSR, Imm 14L)
        ))
        [| 0x8auy; 0x58uy; 0x39uy; 0x45uy |]

      test64
        Opcode.ORN
        (FourOperands (
          OprRegister R.W26,
          OprRegister R.W29,
          OprRegister R.W22,
          Shift (SRTypeROR, Imm 7L)
        ))
        [| 0x2auy; 0xf6uy; 0x1fuy; 0xbauy |]

      test64
        Opcode.MVN
        (ThreeOperands (
          OprRegister R.W26,
          OprRegister R.W22,
          Shift (SRTypeROR, Imm 0x7L)
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
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS)))
        ))
        [| 0x4euy; 0xb0uy; 0x3auy; 0xc2uy |]

      test64
        Opcode.SMAXV
        (TwoOperands (
          scalReg R.B18,
          SIMDOpr (SFReg (SIMDVecReg (R.V6, EightB)))
        ))
        [| 0x0euy; 0x30uy; 0xa8uy; 0xd2uy |]

      test64
        Opcode.SMINV
        (TwoOperands (
          scalReg R.H10,
          SIMDOpr (SFReg (SIMDVecReg (R.V16, FourH)))
        ))
        [| 0x0euy; 0x71uy; 0xaauy; 0x0auy |]

      test64
        Opcode.ADDV
        (TwoOperands (
          scalReg R.H26,
          SIMDOpr (SFReg (SIMDVecReg (R.V4, EightH)))
        ))
        [| 0x4euy; 0x71uy; 0xb8uy; 0x9auy |]

      test64
        Opcode.UADDLV
        (TwoOperands (
          scalReg R.D17,
          SIMDOpr (SFReg (SIMDVecReg (R.V9, FourS)))
        ))
        [| 0x6euy; 0xb0uy; 0x39uy; 0x31uy |]

      test64
        Opcode.UMAXV
        (TwoOperands (
          scalReg R.H8,
          SIMDOpr (SFReg (SIMDVecReg (R.V28, FourH)))
        ))
        [| 0x2euy; 0x70uy; 0xabuy; 0x88uy |]

      test64
        Opcode.UMINV
        (TwoOperands (
          scalReg R.S10,
          SIMDOpr (SFReg (SIMDVecReg (R.V23, FourS)))
        ))
        [| 0x6euy; 0xb1uy; 0xaauy; 0xeauy |]

      test64
        Opcode.FMAXNMV
        (TwoOperands (
          scalReg R.S11,
          SIMDOpr (SFReg (SIMDVecReg (R.V18, FourS)))
        ))
        [| 0x6euy; 0x30uy; 0xcauy; 0x4buy |]

      test64
        Opcode.FMAXV
        (TwoOperands (
          scalReg R.S8,
          SIMDOpr (SFReg (SIMDVecReg (R.V10, FourS)))
        ))
        [| 0x6euy; 0x30uy; 0xf9uy; 0x48uy |]

      test64
        Opcode.FMINNMV
        (TwoOperands (
          scalReg R.S12,
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS)))
        ))
        [| 0x6euy; 0xb0uy; 0xcauy; 0xccuy |]

      test64
        Opcode.FMINV
        (TwoOperands (
          scalReg R.S2,
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS)))
        ))
        [| 0x6euy; 0xb0uy; 0xfauy; 0xc2uy |]

    /// C4.6.2 Advanced SIMD copy
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD copy Parse Test`` () =
      test64
        Opcode.DUP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoD))),
          SIMDOpr (SFReg (sVRegIdx R.V4 VecD 1uy))
        ))
        [| 0x4euy; 0x18uy; 0x04uy; 0x86uy |]

      test64
        Opcode.DUP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V1, TwoD))),
          OprRegister R.X3
        ))
        [| 0x4euy; 0x08uy; 0x0cuy; 0x61uy |]

      test64
        Opcode.DUP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, FourH))),
          OprRegister R.WZR
        )) // Online HEX To ARM Conv error
        [| 0x0euy; 0x1euy; 0x0fuy; 0xfcuy |]

      test64
        Opcode.DUP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, FourH))),
          OprRegister R.WZR
        ))
        [| 0x0euy; 0x02uy; 0x0fuy; 0xfcuy |]

      test64
        Opcode.SMOV
        (TwoOperands (
          OprRegister R.W26,
          SIMDOpr (SFReg (sVRegIdx R.V7 VecH 0uy))
        ))
        [| 0x0euy; 0x02uy; 0x2cuy; 0xfauy |]

      test64
        Opcode.UMOV
        (TwoOperands (
          OprRegister R.W3,
          SIMDOpr (SFReg (sVRegIdx R.V14 VecB 0uy))
        ))
        [| 0x0euy; 0x01uy; 0x3duy; 0xc3uy |]

      test64
        Opcode.MOV
        (TwoOperands (
          OprRegister R.W3,
          SIMDOpr (SFReg (sVRegIdx R.V14 VecS 0uy))
        ))
        [| 0x0euy; 0x04uy; 0x3duy; 0xc3uy |]

      test64
        Opcode.MOV
        (TwoOperands (
          OprRegister R.X3,
          SIMDOpr (SFReg (sVRegIdx R.V14 VecD 0uy))
        ))
        [| 0x4euy; 0x08uy; 0x3duy; 0xc3uy |]

      test64
        Opcode.INS
        (TwoOperands (
          SIMDOpr (SFReg (sVRegIdx R.V9 VecS 0uy)),
          OprRegister R.W1
        ))
        [| 0x4euy; 0x04uy; 0x1cuy; 0x29uy |]

      test64
        Opcode.INS
        (TwoOperands (
          SIMDOpr (SFReg (sVRegIdx R.V5 VecH 0uy)),
          SIMDOpr (SFReg (sVRegIdx R.V6 VecH 7uy))
        ))
        [| 0x6euy; 0x02uy; 0x74uy; 0xc5uy |]

    /// C4.6.3 Advanced SIMD extract
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD extract Parse Test`` () =
      test64
        Opcode.EXT
        (FourOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V12, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, SixteenB))),
          Immediate 9L
        ))
        [| 0x6euy; 0x06uy; 0x49uy; 0x83uy |]

      test64
        Opcode.EXT
        (FourOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, EightB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, EightB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, EightB))),
          Immediate 7L
        ))
        [| 0x2euy; 0x07uy; 0x38uy; 0xfcuy |]

    /// C4.6.4 Advanced SIMD modified immediate
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD modified immediate Parse Test`` () =
      test64
        Opcode.MOVI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS))),
          Immediate 0xAAL,
          Shift (SRTypeLSL, Imm 24L)
        ))
        [| 0x4fuy; 0x05uy; 0x65uy; 0x59uy |]

      test64
        Opcode.MOVI
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS))),
          Immediate 0xAAL
        ))
        [| 0x4fuy; 0x05uy; 0x05uy; 0x59uy |]

      test64
        Opcode.ORR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          Immediate 0x46L,
          Shift (SRTypeLSL, Imm 8L)
        ))
        [| 0x4fuy; 0x02uy; 0x34uy; 0xc5uy |]

      test64
        Opcode.MOVI
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, SixteenB))),
          Immediate 0x2EL
        ))
        [| 0x4fuy; 0x01uy; 0xe5uy; 0xd9uy |]

      test64
        Opcode.ORR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourH))),
          Immediate 0xC7L,
          Shift (SRTypeLSL, Imm 8L)
        ))
        [| 0x0fuy; 0x06uy; 0xb4uy; 0xe5uy |]

      test64
        Opcode.MOVI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, EightH))),
          Immediate 0x9AL,
          Shift (SRTypeLSL, Imm 8L)
        ))
        [| 0x4fuy; 0x04uy; 0xa7uy; 0x59uy |]

      test64
        Opcode.MOVI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          Immediate 0xB2L,
          Shift (SRTypeMSL, Imm 8L)
        ))
        [| 0x4fuy; 0x05uy; 0xc6uy; 0x55uy |]

      test64
        Opcode.FMOV
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          FPImmediate -11.5
        ))
        [| 0x4fuy; 0x05uy; 0xf4uy; 0xe5uy |]

      test64
        Opcode.MVNI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          Immediate 0xE6L,
          Shift (SRTypeLSL, Imm 8L)
        ))
        [| 0x6fuy; 0x07uy; 0x24uy; 0xd5uy |]

      test64
        Opcode.BIC
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoS))),
          Immediate 0xB5L,
          Shift (SRTypeLSL, Imm 8L)
        ))
        [| 0x2fuy; 0x05uy; 0x36uy; 0xa7uy |]

      test64
        Opcode.MVNI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          Immediate 0xE6L,
          Shift (SRTypeLSL, Imm 8L)
        ))
        [| 0x6fuy; 0x07uy; 0xa4uy; 0xd5uy |]

      test64
        Opcode.BIC
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V7, FourH))),
          Immediate 0xB5L
        ))
        [| 0x2fuy; 0x05uy; 0x96uy; 0xa7uy |]

      test64
        Opcode.MVNI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          Immediate 0xE6L,
          Shift (SRTypeMSL, Imm 8L)
        ))
        [| 0x6fuy; 0x07uy; 0xc4uy; 0xd5uy |]

      test64
        Opcode.MOVI
        (TwoOperands (scalReg R.D27, Immediate 0xFF00FFFFFF00FF00L))
        [| 0x2fuy; 0x05uy; 0xe7uy; 0x5buy |]

      test64
        Opcode.MOVI
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V23, TwoD))),
          Immediate 0xFF00FFFFFF00FF00L
        ))
        [| 0x6fuy; 0x05uy; 0xe7uy; 0x57uy |]

      test64
        Opcode.FMOV
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          FPImmediate -11.5
        ))
        [| 0x6fuy; 0x05uy; 0xf4uy; 0xe5uy |]

    /// C4.6.5 Advanced SIMD permute
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD permute Parse Test`` () =
      test64
        Opcode.UZP1
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V12, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, EightH)))
        ))
        [| 0x4euy; 0x4euy; 0x19uy; 0x83uy |]

      test64
        Opcode.TRN1
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoS)))
        ))
        [| 0x0euy; 0x87uy; 0x28uy; 0xfeuy |]

      test64
        Opcode.ZIP1
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, SixteenB)))
        ))
        [| 0x4euy; 0x03uy; 0x38uy; 0x3cuy |]

      test64
        Opcode.ZIP1
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V1, EightB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, EightB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, EightB)))
        ))
        [| 0x0euy; 0x07uy; 0x38uy; 0xc1uy |]

      test64
        Opcode.UZP2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, TwoD)))
        ))
        [| 0x4euy; 0xc1uy; 0x58uy; 0xc6uy |]

      test64
        Opcode.TRN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoS)))
        ))
        [| 0x0euy; 0x87uy; 0x68uy; 0xc3uy |]

      test64
        Opcode.ZIP2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, SixteenB)))
        ))
        [| 0x4euy; 0x01uy; 0x78uy; 0x85uy |]

    /// C4.6.6 Advanced SIMD scalar copy
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar copy Parse Test`` () =
      test64
        Opcode.MOV
        (TwoOperands (scalReg R.D10, SIMDOpr (SFReg (sVRegIdx R.V10 VecD 0uy))))
        [| 0x5euy; 0x08uy; 0x05uy; 0x4auy |]

      test64
        Opcode.MOV
        (TwoOperands (scalReg R.B1, SIMDOpr (SFReg (sVRegIdx R.V10 VecB 3uy))))
        [| 0x5euy; 0x07uy; 0x05uy; 0x41uy |]

    /// C4.6.7 Advanced SIMD scalar pairwise
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar pairwise Parse Test`` () =
      test64
        Opcode.ADDP
        (TwoOperands (scalReg R.D7, SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoD)))))
        [| 0x5euy; 0xf1uy; 0xb8uy; 0x67uy |]

      test64
        Opcode.FMAXNMP
        (TwoOperands (
          scalReg R.D15,
          SIMDOpr (SFReg (SIMDVecReg (R.V14, TwoD)))
        ))
        [| 0x7euy; 0x70uy; 0xc9uy; 0xcfuy |]

      test64
        Opcode.FADDP
        (TwoOperands (
          scalReg R.S31,
          SIMDOpr (SFReg (SIMDVecReg (R.V15, TwoS)))
        ))
        [| 0x7euy; 0x30uy; 0xd9uy; 0xffuy |]

      test64
        Opcode.FMAXP
        (TwoOperands (
          scalReg R.D18,
          SIMDOpr (SFReg (SIMDVecReg (R.V17, TwoD)))
        ))
        [| 0x7euy; 0x70uy; 0xfauy; 0x32uy |]

      test64
        Opcode.FMINNMP
        (TwoOperands (scalReg R.S1, SIMDOpr (SFReg (SIMDVecReg (R.V14, TwoS)))))
        [| 0x7euy; 0xb0uy; 0xc9uy; 0xc1uy |]

      test64
        Opcode.FMINP
        (TwoOperands (scalReg R.D7, SIMDOpr (SFReg (SIMDVecReg (R.V1, TwoD)))))
        [| 0x7euy; 0xf0uy; 0xf8uy; 0x27uy |]

    /// C4.6.8 Advanced SIMD scalar shift by immediate
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD scalar shift by imm Parse Test`` () =
      test64
        Opcode.SSHR
        (ThreeOperands (scalReg R.D1, scalReg R.D10, Immediate 0x3eL))
        [| 0x5fuy; 0x42uy; 0x05uy; 0x41uy |]

      test64
        Opcode.SSRA
        (ThreeOperands (scalReg R.D28, scalReg R.D3, Immediate 0x1cL))
        [| 0x5fuy; 0x64uy; 0x14uy; 0x7cuy |]

      test64
        Opcode.SRSHR
        (ThreeOperands (scalReg R.D1, scalReg R.D7, Immediate 0x27L))
        [| 0x5fuy; 0x59uy; 0x24uy; 0xe1uy |]

      test64
        Opcode.SRSRA
        (ThreeOperands (scalReg R.D3, scalReg R.D6, Immediate 1L))
        [| 0x5fuy; 0x7fuy; 0x34uy; 0xc3uy |]

      test64
        Opcode.SHL
        (ThreeOperands (scalReg R.D13, scalReg R.D7, Immediate 2L))
        [| 0x5fuy; 0x42uy; 0x54uy; 0xeduy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (scalReg R.S25, scalReg R.S16, Immediate 4L))
        [| 0x5fuy; 0x24uy; 0x76uy; 0x19uy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (scalReg R.D25, scalReg R.D16, Immediate 0x24L))
        [| 0x5fuy; 0x64uy; 0x76uy; 0x19uy |]

      test64
        Opcode.SQSHRN
        (ThreeOperands (scalReg R.S7, scalReg R.D12, Immediate 0x17L))
        [| 0x5fuy; 0x29uy; 0x95uy; 0x87uy |]

      test64
        Opcode.SQRSHRN
        (ThreeOperands (scalReg R.H25, scalReg R.S7, Immediate 1L))
        [| 0x5fuy; 0x1fuy; 0x9cuy; 0xf9uy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.D1, scalReg R.D6, Fbits 0x1fuy))
        [| 0x5fuy; 0x61uy; 0xe4uy; 0xc1uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (scalReg R.D11, scalReg R.D8, Fbits 0x25uy))
        [| 0x5fuy; 0x5buy; 0xfduy; 0x0buy |]

      test64
        Opcode.USHR
        (ThreeOperands (scalReg R.D7, scalReg R.D14, Immediate 0x17L))
        [| 0x7fuy; 0x69uy; 0x05uy; 0xc7uy |]

      test64
        Opcode.USRA
        (ThreeOperands (scalReg R.D17, scalReg R.D1, Immediate 0x36L))
        [| 0x7fuy; 0x4auy; 0x14uy; 0x31uy |]

      test64
        Opcode.URSHR
        (ThreeOperands (scalReg R.D9, scalReg R.D2, Immediate 0x20L))
        [| 0x7fuy; 0x60uy; 0x24uy; 0x49uy |]

      test64
        Opcode.URSRA
        (ThreeOperands (scalReg R.D9, scalReg R.D6, Immediate 0x3cL))
        [| 0x7fuy; 0x44uy; 0x34uy; 0xc9uy |]

      test64
        Opcode.SRI
        (ThreeOperands (scalReg R.D3, scalReg R.D14, Immediate 0x1fL))
        [| 0x7fuy; 0x61uy; 0x45uy; 0xc3uy |]

      test64
        Opcode.SLI
        (ThreeOperands (scalReg R.D3, scalReg R.D6, Immediate 0xeL))
        [| 0x7fuy; 0x4euy; 0x54uy; 0xc3uy |]

      test64
        Opcode.SQSHLU
        (ThreeOperands (scalReg R.S7, scalReg R.S20, Immediate 0xbL))
        [| 0x7fuy; 0x2buy; 0x66uy; 0x87uy |]

      test64
        Opcode.UQSHL
        (ThreeOperands (scalReg R.B24, scalReg R.B7, Immediate 3L))
        [| 0x7fuy; 0x0buy; 0x74uy; 0xf8uy |]

      test64
        Opcode.SQSHRUN
        (ThreeOperands (scalReg R.S13, scalReg R.D12, Immediate 0x11L))
        [| 0x7fuy; 0x2fuy; 0x85uy; 0x8duy |]

      test64
        Opcode.SQRSHRUN
        (ThreeOperands (scalReg R.S16, scalReg R.D1, Immediate 6L))
        [| 0x7fuy; 0x3auy; 0x8cuy; 0x30uy |]

      test64
        Opcode.UQSHRN
        (ThreeOperands (scalReg R.H13, scalReg R.S6, Immediate 0xbL))
        [| 0x7fuy; 0x15uy; 0x94uy; 0xcduy |]

      test64
        Opcode.UQRSHRN
        (ThreeOperands (scalReg R.B6, scalReg R.H2, Immediate 4L))
        [| 0x7fuy; 0x0cuy; 0x9cuy; 0x46uy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.S1, scalReg R.S6, Fbits 0x1cuy))
        [| 0x7fuy; 0x24uy; 0xe4uy; 0xc1uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (scalReg R.D3, scalReg R.D4, Fbits 0x2fuy))
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
        (ThreeOperands (scalReg R.D30, scalReg R.D15, Immediate 0L))
        [| 0x5euy; 0xe0uy; 0x89uy; 0xfeuy |]

      test64
        Opcode.CMEQ
        (ThreeOperands (scalReg R.D20, scalReg R.D23, Immediate 0L))
        [| 0x5euy; 0xe0uy; 0x9auy; 0xf4uy |]

      test64
        Opcode.CMLT
        (ThreeOperands (scalReg R.D28, scalReg R.D30, Immediate 0L))
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
        (ThreeOperands (scalReg R.S28, scalReg R.S21, FPImmediate 0.0))
        [| 0x5euy; 0xa0uy; 0xcauy; 0xbcuy |]

      test64
        Opcode.FCMEQ
        (ThreeOperands (scalReg R.D25, scalReg R.D17, FPImmediate 0.0))
        [| 0x5euy; 0xe0uy; 0xdauy; 0x39uy |]

      test64
        Opcode.FCMGT
        (ThreeOperands (scalReg R.D30, scalReg R.D15, FPImmediate 0.0))
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
        (ThreeOperands (scalReg R.D1, scalReg R.D20, Immediate 0L))
        [| 0x7euy; 0xe0uy; 0x8auy; 0x81uy |]

      test64
        Opcode.CMLE
        (ThreeOperands (scalReg R.D24, scalReg R.D17, Immediate 0L))
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
        (ThreeOperands (scalReg R.S30, scalReg R.S23, FPImmediate 0.0))
        [| 0x7euy; 0xa0uy; 0xcauy; 0xfeuy |]

      test64
        Opcode.FCMLE
        (ThreeOperands (scalReg R.D8, scalReg R.D6, FPImmediate 0.0))
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
          SIMDOpr (SFReg (sVRegIdx R.V8 VecS 2uy))
        ))
        [| 0x5fuy; 0x88uy; 0x3auy; 0x21uy |]

      test64
        Opcode.SQDMLSL
        (ThreeOperands (
          scalReg R.S26,
          scalReg R.H24,
          SIMDOpr (SFReg (sVRegIdx R.V6 VecH 7uy))
        ))
        [| 0x5fuy; 0x76uy; 0x7buy; 0x1auy |]

      test64
        Opcode.SQDMULL
        (ThreeOperands (
          scalReg R.D7,
          scalReg R.S19,
          SIMDOpr (SFReg (sVRegIdx R.V12 VecS 3uy))
        ))
        [| 0x5fuy; 0xacuy; 0xbauy; 0x67uy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (
          scalReg R.H3,
          scalReg R.H16,
          SIMDOpr (SFReg (sVRegIdx R.V14 VecH 3uy))
        ))
        [| 0x5fuy; 0x7euy; 0xc2uy; 0x03uy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (
          scalReg R.S27,
          scalReg R.S27,
          SIMDOpr (SFReg (sVRegIdx R.V31 VecS 3uy))
        ))
        [| 0x5fuy; 0xbfuy; 0xcbuy; 0x7buy |]

      test64
        Opcode.SQRDMULH
        (ThreeOperands (
          scalReg R.H28,
          scalReg R.H19,
          SIMDOpr (SFReg (sVRegIdx R.V15 VecH 7uy))
        ))
        [| 0x5fuy; 0x7fuy; 0xdauy; 0x7cuy |]

      test64
        Opcode.FMLA
        (ThreeOperands (
          scalReg R.D3,
          scalReg R.D6,
          SIMDOpr (SFReg (sVRegIdx R.V19 VecD 1uy))
        ))
        [| 0x5fuy; 0xd3uy; 0x18uy; 0xc3uy |]

      test64
        Opcode.FMLS
        (ThreeOperands (
          scalReg R.S2,
          scalReg R.S1,
          SIMDOpr (SFReg (sVRegIdx R.V16 VecS 3uy))
        ))
        [| 0x5fuy; 0xb0uy; 0x58uy; 0x22uy |]

      test64
        Opcode.FMUL
        (ThreeOperands (
          scalReg R.D30,
          scalReg R.D3,
          SIMDOpr (SFReg (sVRegIdx R.V17 VecD 1uy))
        ))
        [| 0x5fuy; 0xd1uy; 0x98uy; 0x7euy |]

      test64
        Opcode.FMULX
        (ThreeOperands (
          scalReg R.S25,
          scalReg R.S6,
          SIMDOpr (SFReg (sVRegIdx R.V30 VecS 1uy))
        ))
        [| 0x7fuy; 0xbeuy; 0x90uy; 0xd9uy |]

    /// C4.6.13 Advanced SIMD shift by immediate
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD shift by immediate Parse Test`` () =
      test64
        Opcode.SSHR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 3L
        ))
        [| 0x4fuy; 0x0duy; 0x05uy; 0xc5uy |]

      test64
        Opcode.SSHR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, EightH))),
          Immediate 0xBL
        ))
        [| 0x4fuy; 0x15uy; 0x05uy; 0xc5uy |]

      test64
        Opcode.SSHR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS))),
          Immediate 0xBL
        ))
        [| 0x4fuy; 0x35uy; 0x05uy; 0xc5uy |]

      test64
        Opcode.SSHR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, TwoD))),
          Immediate 0x2EL
        ))
        [| 0x4fuy; 0x52uy; 0x05uy; 0xc5uy |]

      test64
        Opcode.SSRA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 3L
        ))
        [| 0x4fuy; 0x0duy; 0x15uy; 0xc5uy |]

      test64
        Opcode.SRSHR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, EightH))),
          Immediate 0xBL
        ))
        [| 0x4fuy; 0x15uy; 0x25uy; 0xc5uy |]

      test64
        Opcode.SRSRA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS))),
          Immediate 0xBL
        ))
        [| 0x4fuy; 0x35uy; 0x35uy; 0xc5uy |]

      test64
        Opcode.SHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 5L
        ))
        [| 0x4fuy; 0x0duy; 0x55uy; 0xc5uy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 5L
        ))
        [| 0x4fuy; 0x0duy; 0x75uy; 0xc5uy |]

      test64
        Opcode.SHRN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, TwoD))),
          Immediate 0x12L
        ))
        [| 0x4fuy; 0x2euy; 0x85uy; 0xc5uy |]

      test64
        Opcode.RSHRN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, EightH))),
          Immediate 3L
        ))
        [| 0x4fuy; 0x0duy; 0x8duy; 0xc5uy |]

      test64
        Opcode.SQSHRN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, EightH))),
          Immediate 3L
        ))
        [| 0x4fuy; 0x0duy; 0x95uy; 0xc5uy |]

      test64
        Opcode.SQRSHRN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, EightH))),
          Immediate 3L
        ))
        [| 0x4fuy; 0x0duy; 0x9duy; 0xc5uy |]

      test64
        Opcode.SSHLL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 5L
        ))
        [| 0x4fuy; 0x0duy; 0xa5uy; 0xc5uy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V13, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V10, TwoD))),
          Fbits 0x31uy
        ))
        [| 0x4fuy; 0x4fuy; 0xe5uy; 0x4duy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V13, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V10, TwoD))),
          Fbits 0x31uy
        ))
        [| 0x4fuy; 0x4fuy; 0xfduy; 0x4duy |]

      test64
        Opcode.USHR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 3L
        ))
        [| 0x6fuy; 0x0duy; 0x05uy; 0xc5uy |]

      test64
        Opcode.USRA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 3L
        ))
        [| 0x6fuy; 0x0duy; 0x15uy; 0xc5uy |]

      test64
        Opcode.URSHR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 3L
        ))
        [| 0x6fuy; 0x0duy; 0x25uy; 0xc5uy |]

      test64
        Opcode.URSRA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 3L
        ))
        [| 0x6fuy; 0x0duy; 0x35uy; 0xc5uy |]

      test64
        Opcode.SRI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 3L
        ))
        [| 0x6fuy; 0x0duy; 0x45uy; 0xc5uy |]

      test64
        Opcode.SLI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 5L
        ))
        [| 0x6fuy; 0x0duy; 0x55uy; 0xc5uy |]

      test64
        Opcode.SQSHLU
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 5L
        ))
        [| 0x6fuy; 0x0duy; 0x65uy; 0xc5uy |]

      test64
        Opcode.UQSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, SixteenB))),
          Immediate 5L
        ))
        [| 0x6fuy; 0x0duy; 0x75uy; 0xc5uy |]

      test64
        Opcode.SQSHRUN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, TwoD))),
          Immediate 0x17L
        ))
        [| 0x6fuy; 0x29uy; 0x85uy; 0xc5uy |]

      test64
        Opcode.SQRSHRUN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS))),
          Immediate 5L
        ))
        [| 0x6fuy; 0x1buy; 0x8duy; 0xc5uy |]

      test64
        Opcode.UQSHRN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, TwoD))),
          Immediate 0x1AL
        ))
        [| 0x6fuy; 0x26uy; 0x95uy; 0xc5uy |]

      test64
        Opcode.UQRSHRN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS))),
          Immediate 1L
        ))
        [| 0x6fuy; 0x1fuy; 0x9duy; 0xc5uy |]

      test64
        Opcode.USHLL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoS))),
          Immediate 0xDL
        ))
        [| 0x2fuy; 0x2duy; 0xa4uy; 0xbbuy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS))),
          Fbits 7uy
        ))
        [| 0x6fuy; 0x39uy; 0xe5uy; 0xc5uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS))),
          Fbits 0x1Auy
        ))
        [| 0x6fuy; 0x26uy; 0xfduy; 0xc5uy |]

    /// C4.6.14 Advanced SIMD table lookup
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD table lookup Parse Test`` () =
      test64
        Opcode.TBL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V1, SixteenB))),
          SIMDOpr (
            TwoRegs (SIMDVecReg (R.V6, SixteenB), SIMDVecReg (R.V7, SixteenB))
          ),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, SixteenB)))
        ))
        [| 0x4euy; 0x03uy; 0x20uy; 0xc1uy |]

      test64
        Opcode.TBL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V9, EightB))),
          SIMDOpr (
            ThreeRegs (
              SIMDVecReg (R.V22, SixteenB),
              SIMDVecReg (R.V23, SixteenB),
              SIMDVecReg (R.V24, SixteenB)
            )
          ),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightB)))
        ))
        [| 0x0euy; 0x03uy; 0x42uy; 0xc9uy |]

      test64
        Opcode.TBL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (
            FourRegs (
              SIMDVecReg (R.V31, SixteenB),
              SIMDVecReg (R.V0, SixteenB),
              SIMDVecReg (R.V1, SixteenB),
              SIMDVecReg (R.V2, SixteenB)
            )
          ),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, SixteenB)))
        ))
        [| 0x4euy; 0x03uy; 0x63uy; 0xe5uy |]

      test64
        Opcode.TBL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V17, EightB))),
          SIMDOpr (OneReg (SIMDVecReg (R.V27, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightB)))
        ))
        [| 0x0euy; 0x03uy; 0x03uy; 0x71uy |]

      test64
        Opcode.TBX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, EightB))),
          SIMDOpr (
            TwoRegs (SIMDVecReg (R.V7, SixteenB), SIMDVecReg (R.V8, SixteenB))
          ),
          SIMDOpr (SFReg (SIMDVecReg (R.V25, EightB)))
        ))
        [| 0x0euy; 0x19uy; 0x30uy; 0xfcuy |]

      test64
        Opcode.TBX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, SixteenB))),
          SIMDOpr (
            ThreeRegs (
              SIMDVecReg (R.V7, SixteenB),
              SIMDVecReg (R.V8, SixteenB),
              SIMDVecReg (R.V9, SixteenB)
            )
          ),
          SIMDOpr (SFReg (SIMDVecReg (R.V25, SixteenB)))
        ))
        [| 0x4euy; 0x19uy; 0x50uy; 0xfcuy |]

      test64
        Opcode.TBX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, EightB))),
          SIMDOpr (
            FourRegs (
              SIMDVecReg (R.V7, SixteenB),
              SIMDVecReg (R.V8, SixteenB),
              SIMDVecReg (R.V9, SixteenB),
              SIMDVecReg (R.V10, SixteenB)
            )
          ),
          SIMDOpr (SFReg (SIMDVecReg (R.V25, EightB)))
        ))
        [| 0x0euy; 0x19uy; 0x70uy; 0xfcuy |]

      test64
        Opcode.TBX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, SixteenB))),
          SIMDOpr (OneReg (SIMDVecReg (R.V7, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V25, SixteenB)))
        ))
        [| 0x4euy; 0x19uy; 0x10uy; 0xfcuy |]

    /// C4.6.15 Advanced SIMD three different
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD three different Parse Test`` () =
      test64
        Opcode.SADDL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, FourH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V11, FourH)))
        ))
        [| 0x0euy; 0x6buy; 0x03uy; 0x9auy |]

      test64
        Opcode.SADDL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0x03uy; 0x25uy |]

      test64
        Opcode.SADDW
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V26, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, EightB)))
        ))
        [| 0x0euy; 0x27uy; 0x12uy; 0xbauy |]

      test64
        Opcode.SADDW2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH)))
        ))
        [| 0x4euy; 0x63uy; 0x10uy; 0x79uy |]

      test64
        Opcode.SSUBL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH)))
        ))
        [| 0x4euy; 0x63uy; 0x20uy; 0x79uy |]

      test64
        Opcode.SSUBW2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH)))
        ))
        [| 0x4euy; 0x63uy; 0x30uy; 0x79uy |]

      test64
        Opcode.ADDHN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS)))
        ))
        [| 0x4euy; 0x63uy; 0x40uy; 0x79uy |]

      test64
        Opcode.SABAL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH)))
        ))
        [| 0x4euy; 0x63uy; 0x50uy; 0x79uy |]

      test64
        Opcode.SUBHN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS)))
        ))
        [| 0x4euy; 0x63uy; 0x60uy; 0x79uy |]

      test64
        Opcode.SABDL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH)))
        ))
        [| 0x4euy; 0x63uy; 0x70uy; 0x79uy |]

      test64
        Opcode.SMLAL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V24, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V18, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoS)))
        ))
        [| 0x0euy; 0xa6uy; 0x82uy; 0x58uy |]

      test64
        Opcode.SQDMLAL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V26, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V23, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, FourS)))
        ))
        [| 0x4euy; 0xa6uy; 0x92uy; 0xfauy |]

      test64
        Opcode.SMLSL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V12, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V17, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, EightH)))
        ))
        [| 0x4euy; 0x66uy; 0xa2uy; 0x2cuy |]

      test64
        Opcode.SQDMLSL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0xb2uy; 0xc3uy |]

      test64
        Opcode.SMULL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V11, FourH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourH)))
        ))
        [| 0x0euy; 0x65uy; 0xc1uy; 0x7cuy |]

      test64
        Opcode.SQDMULL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V8, TwoS)))
        ))
        [| 0x0euy; 0xa8uy; 0xd0uy; 0x79uy |]

      test64
        Opcode.PMULL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, OneQ))),
          SIMDOpr (SFReg (SIMDVecReg (R.V18, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoD)))
        ))
        [| 0x4euy; 0xe3uy; 0xe2uy; 0x45uy |]

      test64
        Opcode.UADDL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V11, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V19, EightB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, EightB)))
        ))
        [| 0x2euy; 0x2euy; 0x02uy; 0x6buy |]

      test64
        Opcode.UADDW2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V18, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V18, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS)))
        ))
        [| 0x6euy; 0xaeuy; 0x12uy; 0x52uy |]

      test64
        Opcode.USUBL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V29, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, TwoS)))
        ))
        [| 0x2euy; 0xa1uy; 0x22uy; 0xbduy |]

      test64
        Opcode.USUBW2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, SixteenB)))
        ))
        [| 0x6euy; 0x27uy; 0x33uy; 0x9buy |]

      test64
        Opcode.RADDHN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, EightH)))
        ))
        [| 0x6euy; 0x27uy; 0x43uy; 0x9buy |]

      test64
        Opcode.UABAL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, SixteenB)))
        ))
        [| 0x6euy; 0x27uy; 0x53uy; 0x9buy |]

      test64
        Opcode.RSUBHN2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, EightH)))
        ))
        [| 0x6euy; 0x27uy; 0x63uy; 0x9buy |]

      test64
        Opcode.UABDL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, SixteenB)))
        ))
        [| 0x6euy; 0x27uy; 0x73uy; 0x9buy |]

      test64
        Opcode.UMLAL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, SixteenB)))
        ))
        [| 0x6euy; 0x27uy; 0x83uy; 0x9buy |]

      test64
        Opcode.UMLSL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, SixteenB)))
        ))
        [| 0x6euy; 0x27uy; 0xa3uy; 0x9buy |]

      test64
        Opcode.UMULL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V28, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, SixteenB)))
        ))
        [| 0x6euy; 0x27uy; 0xc3uy; 0x9buy |]

    /// C4.6.16 Advanced SIMD three same
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD three same Parse Test`` () =
      test64
        Opcode.SHADD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x25uy; 0x04uy; 0xb5uy |]

      test64
        Opcode.SQADD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x4euy; 0x65uy; 0x0cuy; 0xb5uy |]

      test64
        Opcode.SRHADD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0x14uy; 0xb5uy |]

      test64
        Opcode.SHSUB
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x25uy; 0x24uy; 0xb5uy |]

      test64
        Opcode.SQSUB
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x4euy; 0x65uy; 0x2cuy; 0xb5uy |]

      test64
        Opcode.CMGT
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0x34uy; 0xb5uy |]

      test64
        Opcode.CMGE
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x25uy; 0x3cuy; 0xb5uy |]

      test64
        Opcode.SSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x4euy; 0x65uy; 0x44uy; 0xb5uy |]

      test64
        Opcode.SQSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0x4cuy; 0xb5uy |]

      test64
        Opcode.SRSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x25uy; 0x54uy; 0xb5uy |]

      test64
        Opcode.SQRSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x4euy; 0x65uy; 0x5cuy; 0xb5uy |]

      test64
        Opcode.SMAX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0x64uy; 0xb5uy |]

      test64
        Opcode.SMIN
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x25uy; 0x6cuy; 0xb5uy |]

      test64
        Opcode.SABD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x4euy; 0x65uy; 0x74uy; 0xb5uy |]

      test64
        Opcode.SABA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0x7cuy; 0xb5uy |]

      test64
        Opcode.ADD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x25uy; 0x84uy; 0xb5uy |]

      test64
        Opcode.CMTST
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x4euy; 0x65uy; 0x8cuy; 0xb5uy |]

      test64
        Opcode.MLA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0x94uy; 0xb5uy |]

      test64
        Opcode.MUL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x25uy; 0x9cuy; 0xb5uy |]

      test64
        Opcode.SMAXP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x4euy; 0x65uy; 0xa4uy; 0xb5uy |]

      test64
        Opcode.SMINP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0xacuy; 0xb5uy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0xb4uy; 0xb5uy |]

      test64
        Opcode.ADDP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x4euy; 0x65uy; 0xbcuy; 0xb5uy |]

      test64
        Opcode.FMAXNM
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0x25uy; 0xc6uy; 0xb5uy |]

      test64
        Opcode.FMLA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V13, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x4euy; 0x65uy; 0xcduy; 0xb5uy |]

      test64
        Opcode.FADD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0x25uy; 0xd4uy; 0xb5uy |]

      test64
        Opcode.FMULX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V17, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x4euy; 0x65uy; 0xdcuy; 0xb1uy |]

      test64
        Opcode.FCMEQ
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V2, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0x25uy; 0xe4uy; 0x55uy |]

      test64
        Opcode.FMAX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V13, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x4euy; 0x65uy; 0xf5uy; 0xb5uy |]

      test64
        Opcode.FRECPS
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V13, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0x25uy; 0xfduy; 0xb5uy |]

      test64
        Opcode.AND
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V17, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x25uy; 0x1cuy; 0xb1uy |]

      test64
        Opcode.BIC
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x65uy; 0x1euy; 0xb9uy |]

      test64
        Opcode.FMINNM
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V29, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0xc4uy; 0x3duy |]

      test64
        Opcode.FMLS
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V20, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V29, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x4euy; 0xe5uy; 0xcfuy; 0xb4uy |]

      test64
        Opcode.FSUB
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0xd4uy; 0xb5uy |]

      test64
        Opcode.FMIN
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x4euy; 0xe5uy; 0xf4uy; 0x25uy |]

      test64
        Opcode.FRSQRTS
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V29, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0xa5uy; 0xfcuy; 0xbduy |]

      test64
        Opcode.MOV
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0xa5uy; 0x1cuy; 0xb5uy |]

      test64
        Opcode.ORN
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V9, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V13, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0xe5uy; 0x1duy; 0xa9uy |]

      test64
        Opcode.UHADD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x25uy; 0x04uy; 0xb5uy |]

      test64
        Opcode.UQADD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x6euy; 0x65uy; 0x0cuy; 0xb5uy |]

      test64
        Opcode.URHADD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0x14uy; 0xb5uy |]

      test64
        Opcode.UHSUB
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x25uy; 0x24uy; 0xb5uy |]

      test64
        Opcode.UQSUB
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x6euy; 0x65uy; 0x2cuy; 0xb5uy |]

      test64
        Opcode.CMHI
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0x34uy; 0xb5uy |]

      test64
        Opcode.CMHS
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x25uy; 0x3cuy; 0xb5uy |]

      test64
        Opcode.USHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x6euy; 0x65uy; 0x44uy; 0xb5uy |]

      test64
        Opcode.UQSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0x4cuy; 0xb5uy |]

      test64
        Opcode.URSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x25uy; 0x54uy; 0xb5uy |]

      test64
        Opcode.UQRSHL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x6euy; 0x65uy; 0x5cuy; 0xb5uy |]

      test64
        Opcode.UMAX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0x64uy; 0xb5uy |]

      test64
        Opcode.UMIN
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x25uy; 0x6cuy; 0xb5uy |]

      test64
        Opcode.UABD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x6euy; 0x65uy; 0x74uy; 0xb5uy |]

      test64
        Opcode.UABA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0x7cuy; 0xb5uy |]

      test64
        Opcode.SUB
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x25uy; 0x84uy; 0xb5uy |]

      test64
        Opcode.CMEQ
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x6euy; 0x65uy; 0x8cuy; 0xb5uy |]

      test64
        Opcode.MLS
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0x94uy; 0xb5uy |]

      test64
        Opcode.PMUL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x25uy; 0x9cuy; 0xb5uy |]

      test64
        Opcode.UMAXP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x6euy; 0x65uy; 0xa4uy; 0xb5uy |]

      test64
        Opcode.UMINP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0xacuy; 0xb5uy |]

      test64
        Opcode.SQRDMULH
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, EightH)))
        ))
        [| 0x6euy; 0x65uy; 0xb4uy; 0xb5uy |]

      test64
        Opcode.FMAXNMP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0x25uy; 0xc4uy; 0xb5uy |]

      test64
        Opcode.FADDP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x6euy; 0x65uy; 0xd4uy; 0xb5uy |]

      test64
        Opcode.FMUL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0x25uy; 0xdcuy; 0xb5uy |]

      test64
        Opcode.FCMGE
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x6euy; 0x65uy; 0xe4uy; 0xb5uy |]

      test64
        Opcode.FACGE
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0x25uy; 0xecuy; 0xb5uy |]

      test64
        Opcode.FMAXP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x6euy; 0x65uy; 0xf4uy; 0xb5uy |]

      test64
        Opcode.FDIV
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0x25uy; 0xfcuy; 0xb5uy |]

      test64
        Opcode.EOR
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x25uy; 0x1cuy; 0xb5uy |]

      test64
        Opcode.BSL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0x65uy; 0x1cuy; 0xb5uy |]

      test64
        Opcode.FMINNMP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0xc4uy; 0xb5uy |]

      test64
        Opcode.FABD
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x6euy; 0xe5uy; 0xd4uy; 0xb5uy |]

      test64
        Opcode.FCMGT
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0xe4uy; 0xb5uy |]

      test64
        Opcode.FACGT
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x6euy; 0xe5uy; 0xecuy; 0xb5uy |]

      test64
        Opcode.FMINP
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa5uy; 0xf4uy; 0xb5uy |]

      test64
        Opcode.BIT
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0xa5uy; 0x1cuy; 0xb5uy |]

      test64
        Opcode.BIF
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x6euy; 0xe5uy; 0x1cuy; 0xb5uy |]

    /// C4.6.17 Advanced SIMD two-register miscellaneous
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD two-reg miscellaneous Parse Test`` () =
      test64
        Opcode.REV64
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V12, EightH)))
        ))
        [| 0x4euy; 0x60uy; 0x09uy; 0x83uy |]

      test64
        Opcode.REV16
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V18, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB)))
        ))
        [| 0x4euy; 0x20uy; 0x18uy; 0xb2uy |]

      test64
        Opcode.SADDLP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V12, EightH)))
        ))
        [| 0x4euy; 0x60uy; 0x29uy; 0x83uy |]

      test64
        Opcode.SUQADD
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V19, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V17, EightH)))
        ))
        [| 0x4euy; 0x60uy; 0x3auy; 0x33uy |]

      test64
        Opcode.CLS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS)))
        ))
        [| 0x4euy; 0xa0uy; 0x48uy; 0x7cuy |]

      test64
        Opcode.SADDLP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V13, OneD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoS)))
        ))
        [| 0x0euy; 0xa0uy; 0x28uy; 0xcduy |]

      test64
        Opcode.SQABS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V18, TwoD)))
        ))
        [| 0x4euy; 0xe0uy; 0x7auy; 0x46uy |]

      test64
        Opcode.CMGT
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V7, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, SixteenB))),
          Immediate 0L
        ))
        [| 0x4euy; 0x20uy; 0x88uy; 0x67uy |]

      test64
        Opcode.CMEQ
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourH))),
          Immediate 0L
        ))
        [| 0x0euy; 0x60uy; 0x98uy; 0x79uy |]

      test64
        Opcode.CMLT
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V1, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V2, FourS))),
          Immediate 0L
        ))
        [| 0x4euy; 0xa0uy; 0xa8uy; 0x41uy |]

      test64
        Opcode.ABS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V29, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V27, SixteenB)))
        ))
        [| 0x4euy; 0x20uy; 0xbbuy; 0x7duy |]

      test64
        Opcode.XTN
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x0euy; 0xa1uy; 0x28uy; 0xb9uy |]

      test64
        Opcode.XTN2
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V24, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoD)))
        ))
        [| 0x4euy; 0xa1uy; 0x28uy; 0xf8uy |]

      test64
        Opcode.SQXTN
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, EightB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, EightH)))
        ))
        [| 0x0euy; 0x21uy; 0x48uy; 0xc3uy |]


      test64
        Opcode.SQXTN2
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V10, EightH)))
        ))
        [| 0x4euy; 0x21uy; 0x49uy; 0x45uy |]

      test64
        Opcode.FCVTN
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, TwoD)))
        ))
        [| 0x0euy; 0x61uy; 0x68uy; 0x85uy |]

      test64
        Opcode.FCVTN2
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V24, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, FourS)))
        ))
        [| 0x4euy; 0x21uy; 0x68uy; 0xf8uy |]

      test64
        Opcode.FCVTL
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V19, FourH)))
        ))
        [| 0x0euy; 0x21uy; 0x7auy; 0x7cuy |]

      test64
        Opcode.FCVTL2
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS)))
        ))
        [| 0x4euy; 0x61uy; 0x7buy; 0x43uy |]

      test64
        Opcode.FRINTN
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V24, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x4euy; 0x61uy; 0x88uy; 0xb8uy |]

      test64
        Opcode.FRINTM
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoS)))
        ))
        [| 0x0euy; 0x21uy; 0x98uy; 0x65uy |]

      test64
        Opcode.FCVTNS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V13, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS)))
        ))
        [| 0x4euy; 0x21uy; 0xa8uy; 0x6duy |]

      test64
        Opcode.FCVTMS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoS)))
        ))
        [| 0x0euy; 0x21uy; 0xb8uy; 0x7euy |]

      test64
        Opcode.FCVTAS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V22, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoD)))
        ))
        [| 0x4euy; 0x61uy; 0xc8uy; 0x76uy |]

      test64
        Opcode.SCVTF
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V18, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, FourS)))
        ))
        [| 0x4euy; 0x21uy; 0xd8uy; 0x92uy |]

      test64
        Opcode.FCMGT
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V29, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          FPImmediate 0.0
        ))
        [| 0x4euy; 0xa0uy; 0xc8uy; 0xbduy |]

      test64
        Opcode.FCMEQ
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, TwoS))),
          FPImmediate 0.0
        ))
        [| 0x0euy; 0xa0uy; 0xd8uy; 0x3euy |]

      test64
        Opcode.FCMLT
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V25, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V9, TwoD))),
          FPImmediate 0.0
        ))
        [| 0x4euy; 0xe0uy; 0xe9uy; 0x39uy |]

      test64
        Opcode.FABS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, FourS)))
        ))
        [| 0x4euy; 0xa0uy; 0xf8uy; 0x8euy |]

      test64
        Opcode.FRINTP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V22, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, TwoS)))
        ))
        [| 0x0euy; 0xa1uy; 0x88uy; 0x96uy |]

      test64
        Opcode.FRINTZ
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V9, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V2, TwoD)))
        ))
        [| 0x4euy; 0xe1uy; 0x98uy; 0x49uy |]

      test64
        Opcode.FCVTPS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS)))
        ))
        [| 0x4euy; 0xa1uy; 0xaauy; 0xc3uy |]

      test64
        Opcode.FCVTZS
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V26, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V19, TwoS)))
        ))
        [| 0x0euy; 0xa1uy; 0xbauy; 0x7auy |]

      test64
        Opcode.URECPE
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoS)))
        ))
        [| 0x0euy; 0xa1uy; 0xc8uy; 0xc7uy |]

      test64
        Opcode.FRECPE
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, TwoD)))
        ))
        [| 0x4euy; 0xe1uy; 0xd8uy; 0x83uy |]

      test64
        Opcode.REV32
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, EightH)))
        ))
        [| 0x6euy; 0x60uy; 0x08uy; 0x3euy |]

      test64
        Opcode.UADDLP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, FourS)))
        ))
        [| 0x6euy; 0xa0uy; 0x28uy; 0xfcuy |]

      test64
        Opcode.USQADD
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V3, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, TwoD)))
        ))
        [| 0x6euy; 0xe0uy; 0x38uy; 0x83uy |]

      test64
        Opcode.CLZ
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V9, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, FourS)))
        ))
        [| 0x6euy; 0xa0uy; 0x48uy; 0xc9uy |]

      test64
        Opcode.UADALP
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, EightH)))
        ))
        [| 0x6euy; 0x60uy; 0x68uy; 0x3euy |]

      test64
        Opcode.SQNEG
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V15, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoS)))
        ))
        [| 0x2euy; 0xa0uy; 0x78uy; 0xefuy |]

      test64
        Opcode.CMGE
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V20, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V3, SixteenB))),
          Immediate 0L
        ))
        [| 0x6euy; 0x20uy; 0x88uy; 0x74uy |]

      test64
        Opcode.CMLE
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V29, EightB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, EightB))),
          Immediate 0L
        ))
        [| 0x2euy; 0x20uy; 0x98uy; 0xfduy |]

      test64
        Opcode.NEG
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V10, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, EightH)))
        ))
        [| 0x6euy; 0x60uy; 0xb8uy; 0xcauy |]

      test64
        Opcode.SQXTN
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, TwoD)))
        ))
        [| 0x0euy; 0xa1uy; 0x48uy; 0x87uy |]

      test64
        Opcode.SQXTN2
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V20, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x4euy; 0x61uy; 0x48uy; 0xb4uy |]

      test64
        Opcode.SHLL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V19, TwoS))),
          Shift (SRTypeLSL, Imm 32L)
        ))
        [| 0x2euy; 0xa1uy; 0x3auy; 0x75uy |]

      test64
        Opcode.SHLL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V29, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V19, EightH))),
          Shift (SRTypeLSL, Imm 16L)
        ))
        [| 0x6euy; 0x61uy; 0x3auy; 0x7duy |]

      test64
        Opcode.UQXTN
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V9, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, TwoD)))
        ))
        [| 0x2euy; 0xa1uy; 0x48uy; 0xe9uy |]

      test64
        Opcode.UQXTN2
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V2, EightH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, FourS)))
        ))
        [| 0x6euy; 0x61uy; 0x48uy; 0xc2uy |]

      test64
        Opcode.FCVTXN
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V10, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoD)))
        ))
        [| 0x2euy; 0x61uy; 0x68uy; 0xcauy |]

      test64
        Opcode.FCVTXN2
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, TwoD)))
        ))
        [| 0x6euy; 0x61uy; 0x69uy; 0xc5uy |]

      test64
        Opcode.FRINTA
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0x21uy; 0x88uy; 0xbauy |]

      test64
        Opcode.FRINTX
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V28, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoD)))
        ))
        [| 0x6euy; 0x61uy; 0x98uy; 0xbcuy |]

      test64
        Opcode.FCVTNU
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, TwoS)))
        ))
        [| 0x2euy; 0x21uy; 0xa8uy; 0xc5uy |]

      test64
        Opcode.FCVTMU
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V6, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS)))
        ))
        [| 0x6euy; 0x21uy; 0xbauy; 0xc6uy |]

      test64
        Opcode.FCVTAU
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V27, TwoS)))
        ))
        [| 0x2euy; 0x21uy; 0xcbuy; 0x65uy |]

      test64
        Opcode.UCVTF
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, FourS)))
        ))
        [| 0x6euy; 0x21uy; 0xd8uy; 0x96uy |]

      test64
        Opcode.MVN
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V26, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V9, SixteenB)))
        ))
        [| 0x6euy; 0x20uy; 0x59uy; 0x3auy |]

      test64
        Opcode.RBIT
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V18, EightB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, EightB)))
        ))
        [| 0x2euy; 0x60uy; 0x58uy; 0xf2uy |]

      test64
        Opcode.FCMGE
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V23, FourS))),
          FPImmediate 0.0
        ))
        [| 0x6euy; 0xa0uy; 0xcauy; 0xe5uy |]

      test64
        Opcode.FCMLE
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V14, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V18, TwoS))),
          FPImmediate 0.0
        ))
        [| 0x2euy; 0xa0uy; 0xdauy; 0x4euy |]

      test64
        Opcode.FNEG
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V19, TwoD)))
        ))
        [| 0x6euy; 0xe0uy; 0xfauy; 0x75uy |]

      test64
        Opcode.FRINTI
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, TwoS)))
        ))
        [| 0x2euy; 0xa1uy; 0x9auy; 0xbeuy |]

      test64
        Opcode.FCVTPU
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V9, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, TwoD)))
        ))
        [| 0x6euy; 0xe1uy; 0xa8uy; 0x89uy |]

      test64
        Opcode.FCVTZU
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V15, TwoS)))
        ))
        [| 0x2euy; 0xa1uy; 0xb9uy; 0xfeuy |]

      test64
        Opcode.URSQRTE
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V29, FourS)))
        ))
        [| 0x6euy; 0xa1uy; 0xcbuy; 0xa5uy |]

      test64
        Opcode.FRSQRTE
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V18, TwoS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V25, TwoS)))
        ))
        [| 0x2euy; 0xa1uy; 0xdbuy; 0x32uy |]

      test64
        Opcode.FSQRT
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V6, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS)))
        ))
        [| 0x6euy; 0xa1uy; 0xf8uy; 0xa6uy |]

    /// C4.6.18 Advanced SIMD vector x indexed element
    [<TestMethod>]
    member __.``[AArch64] Advanced SIMD vector x indexed elem Parse Test`` () =
      test64
        Opcode.SMLAL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, EightH))),
          SIMDOpr (SFReg (sVRegIdx R.V2 VecH 6uy))
        ))
        [| 0x4fuy; 0x62uy; 0x28uy; 0xdauy |]

      test64
        Opcode.SQDMLAL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V2, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V17 VecS 3uy))
        ))
        [| 0x4fuy; 0xb1uy; 0x3buy; 0x42uy |]

      test64
        Opcode.SMLSL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V10, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V14, EightH))),
          SIMDOpr (SFReg (sVRegIdx R.V9 VecH 3uy))
        ))
        [| 0x4fuy; 0x79uy; 0x61uy; 0xcauy |]

      test64
        Opcode.SQDMLSL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V15, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V1, TwoS))),
          SIMDOpr (SFReg (sVRegIdx R.V18 VecS 0uy))
        ))
        [| 0x0fuy; 0x92uy; 0x70uy; 0x2fuy |]

      test64
        Opcode.MUL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V2, FourH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourH))),
          SIMDOpr (SFReg (sVRegIdx R.V3 VecH 3uy))
        ))
        [| 0x0fuy; 0x73uy; 0x83uy; 0x42uy |]

      test64
        Opcode.SMULL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, FourH))),
          SIMDOpr (SFReg (sVRegIdx R.V12 VecH 6uy))
        ))
        [| 0x0fuy; 0x6cuy; 0xa8uy; 0xc5uy |]

      test64
        Opcode.SQDMULL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V2, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V29 VecS 3uy))
        ))
        [| 0x4fuy; 0xbduy; 0xbbuy; 0x42uy |]

      test64
        Opcode.SQDMULH
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V29, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V29 VecS 2uy))
        ))
        [| 0x4fuy; 0x9duy; 0xcbuy; 0x5duy |]

      test64
        Opcode.SQRDMULH
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourH))),
          SIMDOpr (SFReg (SIMDVecReg (R.V30, FourH))),
          SIMDOpr (SFReg (sVRegIdx R.V13 VecH 1uy))
        ))
        [| 0x0fuy; 0x5duy; 0xd3uy; 0xdauy |]

      test64
        Opcode.FMLA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V3 VecS 3uy))
        ))
        [| 0x4fuy; 0xa3uy; 0x1buy; 0x5buy |]

      test64
        Opcode.FMLS
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, TwoD))),
          SIMDOpr (SFReg (sVRegIdx R.V19 VecD 0uy))
        ))
        [| 0x4fuy; 0xd3uy; 0x53uy; 0x5buy |]

      test64
        Opcode.FMUL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V27, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V3 VecS 2uy))
        ))
        [| 0x4fuy; 0x83uy; 0x9buy; 0x5buy |]

      test64
        Opcode.MLA
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V13 VecS 3uy))
        ))
        [| 0x6fuy; 0xaduy; 0x08uy; 0xbeuy |]

      test64
        Opcode.UMLAL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V26, EightH))),
          SIMDOpr (SFReg (sVRegIdx R.V15 VecH 7uy))
        ))
        [| 0x6fuy; 0x7fuy; 0x2buy; 0x56uy |]

      test64
        Opcode.MLS
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V10, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V4, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V23 VecS 2uy))
        ))
        [| 0x6fuy; 0x97uy; 0x48uy; 0x8auy |]

      test64
        Opcode.UMLSL
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V30, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V6, FourH))),
          SIMDOpr (SFReg (sVRegIdx R.V14 VecH 2uy))
        ))
        [| 0x2fuy; 0x6euy; 0x60uy; 0xdeuy |]

      test64
        Opcode.UMULL2
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V10, TwoD))),
          SIMDOpr (SFReg (SIMDVecReg (R.V7, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V31 VecS 3uy))
        ))
        [| 0x6fuy; 0xbfuy; 0xa8uy; 0xeauy |]

      test64
        Opcode.FMULX
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V5, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V22, FourS))),
          SIMDOpr (SFReg (sVRegIdx R.V13 VecS 1uy))
        ))
        [| 0x6fuy; 0xaduy; 0x92uy; 0xc5uy |]

    /// C4.6.19 Cryptographic AES
    [<TestMethod>]
    member __.``[AArch64] Cryptographic AES Parse Test`` () =
      test64
        Opcode.AESE
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB)))
        ))
        [| 0x4euy; 0x28uy; 0x4auy; 0xb5uy |]

      test64
        Opcode.AESD
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB)))
        ))
        [| 0x4euy; 0x28uy; 0x5auy; 0xb5uy |]

      test64
        Opcode.AESMC
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB)))
        ))
        [| 0x4euy; 0x28uy; 0x6auy; 0xb5uy |]

      test64
        Opcode.AESIMC
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, SixteenB)))
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
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS)))
        ))
        [| 0x5euy; 0x19uy; 0x03uy; 0x78uy |]

      test64
        Opcode.SHA1P
        (ThreeOperands (
          scalReg R.Q31,
          scalReg R.S31,
          SIMDOpr (SFReg (SIMDVecReg (R.V19, FourS)))
        ))
        [| 0x5euy; 0x13uy; 0x13uy; 0xffuy |]

      test64
        Opcode.SHA1M
        (ThreeOperands (
          scalReg R.Q28,
          scalReg R.S21,
          SIMDOpr (SFReg (SIMDVecReg (R.V14, FourS)))
        ))
        [| 0x5euy; 0x0euy; 0x22uy; 0xbcuy |]

      test64
        Opcode.SHA1SU0
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V7, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V16, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V23, FourS)))
        ))
        [| 0x5euy; 0x17uy; 0x32uy; 0x07uy |]

      test64
        Opcode.SHA256H
        (ThreeOperands (
          scalReg R.Q30,
          scalReg R.Q30,
          SIMDOpr (SFReg (SIMDVecReg (R.V17, FourS)))
        ))
        [| 0x5euy; 0x11uy; 0x43uy; 0xdeuy |]

      test64
        Opcode.SHA256H2
        (ThreeOperands (
          scalReg R.Q30,
          scalReg R.Q24,
          SIMDOpr (SFReg (SIMDVecReg (R.V25, FourS)))
        ))
        [| 0x5euy; 0x19uy; 0x53uy; 0x1euy |]

      test64
        Opcode.SHA1SU0
        (ThreeOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V31, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V23, FourS)))
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
          SIMDOpr (SFReg (SIMDVecReg (R.V23, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V30, FourS)))
        ))
        [| 0x5euy; 0x28uy; 0x1buy; 0xd7uy |]

      test64
        Opcode.SHA256SU0
        (TwoOperands (
          SIMDOpr (SFReg (SIMDVecReg (R.V21, FourS))),
          SIMDOpr (SFReg (SIMDVecReg (R.V10, FourS)))
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
        (TwoOperands (scalReg R.S28, FPImmediate 0.0))
        [| 0x1euy; 0x31uy; 0x23uy; 0x88uy |]

      test64
        Opcode.FCMPE
        (TwoOperands (scalReg R.S22, scalReg R.S11))
        [| 0x1euy; 0x2buy; 0x22uy; 0xd0uy |]

      test64
        Opcode.FCMPE
        (TwoOperands (scalReg R.S17, FPImmediate 0.0))
        [| 0x1euy; 0x39uy; 0x22uy; 0x38uy |]

      test64
        Opcode.FCMP
        (TwoOperands (scalReg R.D6, scalReg R.D2))
        [| 0x1euy; 0x62uy; 0x20uy; 0xc0uy |]

      test64
        Opcode.FCMP
        (TwoOperands (scalReg R.D14, FPImmediate 0.0))
        [| 0x1euy; 0x79uy; 0x21uy; 0xc8uy |]

      test64
        Opcode.FCMPE
        (TwoOperands (scalReg R.D11, scalReg R.D20))
        [| 0x1euy; 0x74uy; 0x21uy; 0x70uy |]

      test64
        Opcode.FCMPE
        (TwoOperands (scalReg R.D29, FPImmediate 0.0))
        [| 0x1euy; 0x63uy; 0x23uy; 0xb8uy |]

    /// C4.6.23 Floating-point conditional compare
    [<TestMethod>]
    member __.``[AArch64] Floating-point conditional compare Parse Test`` () =
      test64
        Opcode.FCCMP
        (FourOperands (scalReg R.S26, scalReg R.S13, NZCV 0xDuy, Cond CS)) // HS
        [| 0x1euy; 0x2duy; 0x27uy; 0x4duy |]

      test64
        Opcode.FCCMPE
        (FourOperands (scalReg R.S26, scalReg R.S10, NZCV 6uy, Cond AL))
        [| 0x1euy; 0x2auy; 0xe7uy; 0x56uy |]

      test64
        Opcode.FCCMP
        (FourOperands (scalReg R.D18, scalReg R.D9, NZCV 9uy, Cond CC))
        [| 0x1euy; 0x69uy; 0x36uy; 0x49uy |] // LO

      test64
        Opcode.FCCMPE
        (FourOperands (scalReg R.D26, scalReg R.D14, NZCV 2uy, Cond AL))
        [| 0x1euy; 0x6euy; 0xe7uy; 0x52uy |]

    /// C4.6.24 Floating-point conditional select
    [<TestMethod>]
    member __.``[AArch64] Floating-point conditional select Parse Test`` () =
      test64
        Opcode.FCSEL
        (FourOperands (scalReg R.S27, scalReg R.S2, scalReg R.S9, Cond CS))
        [| 0x1euy; 0x29uy; 0x2cuy; 0x5buy |]

      test64
        Opcode.FCSEL
        (FourOperands (scalReg R.D19, scalReg R.D10, scalReg R.D28, Cond AL))
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
        (TwoOperands (scalReg R.S21, FPImmediate 2.0))
        [| 0x1euy; 0x20uy; 0x10uy; 0x15uy |]

      test64
        Opcode.FMOV
        (TwoOperands (scalReg R.D25, FPImmediate 10.5))
        [| 0x1euy; 0x64uy; 0xb0uy; 0x19uy |]

    /// C4.6.29 Conversion between floating-point and fixed-point
    [<TestMethod>]
    member __.``[AArch64] Conversion between FP and fixed-pt Parse Test`` () =
      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.S28, OprRegister R.W5, Fbits 0x16uy))
        [| 0x1euy; 0x02uy; 0xa8uy; 0xbcuy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.S5, OprRegister R.W5, Fbits 2uy))
        [| 0x1euy; 0x03uy; 0xf8uy; 0xa5uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (OprRegister R.W17, scalReg R.S4, Fbits 1uy))
        [| 0x1euy; 0x18uy; 0xfcuy; 0x91uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (OprRegister R.W5, scalReg R.S14, Fbits 0x1Fuy))
        [| 0x1euy; 0x19uy; 0x85uy; 0xc5uy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.D5, OprRegister R.W14, Fbits 0xFuy))
        [| 0x1euy; 0x42uy; 0xc5uy; 0xc5uy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.D5, OprRegister R.W14, Fbits 0x17uy))
        [| 0x1euy; 0x43uy; 0xa5uy; 0xc5uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (OprRegister R.W5, scalReg R.D14, Fbits 0x1Buy))
        [| 0x1euy; 0x58uy; 0x95uy; 0xc5uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (OprRegister R.W5, scalReg R.D26, Fbits 0x16uy))
        [| 0x1euy; 0x59uy; 0xabuy; 0x45uy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.S17, OprRegister R.X6, Fbits 0xFuy))
        [| 0x9euy; 0x02uy; 0xc4uy; 0xd1uy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.S5, OprRegister R.X13, Fbits 0x13uy))
        [| 0x9euy; 0x03uy; 0xb5uy; 0xa5uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (OprRegister R.X13, scalReg R.S6, Fbits 4uy))
        [| 0x9euy; 0x18uy; 0xf0uy; 0xcduy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (OprRegister R.X13, scalReg R.S14, Fbits 0x1Buy))
        [| 0x9euy; 0x19uy; 0x95uy; 0xcduy |]

      test64
        Opcode.SCVTF
        (ThreeOperands (scalReg R.D5, OprRegister R.X28, Fbits 0x1Euy))
        [| 0x9euy; 0x42uy; 0x8buy; 0x85uy |]

      test64
        Opcode.UCVTF
        (ThreeOperands (scalReg R.D5, OprRegister R.X14, Fbits 0xFuy))
        [| 0x9euy; 0x43uy; 0xc5uy; 0xc5uy |]

      test64
        Opcode.FCVTZS
        (ThreeOperands (OprRegister R.X17, scalReg R.D22, Fbits 7uy))
        [| 0x9euy; 0x58uy; 0xe6uy; 0xd1uy |]

      test64
        Opcode.FCVTZU
        (ThreeOperands (OprRegister R.X18, scalReg R.D14, Fbits 0xCuy))
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
          SIMDOpr (SFReg (sVRegIdx R.V16 VecD 1uy))
        ))
        [| 0x9euy; 0xaeuy; 0x02uy; 0x1duy |]

      test64
        Opcode.FMOV
        (TwoOperands (
          SIMDOpr (SFReg (sVRegIdx R.V24 VecD 1uy)),
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

module ARMThumb =
  open B2R2.FrontEnd.BinLifter.ARM32

  let private test arch e c op w q (s: SIMDDataTypes option) oprs (b: byte[]) =
    let mode = ArchOperationMode.ThumbMode
    let parser = ARM32Parser (ISA.Init arch e, mode, None)
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

  let private testThumb = test Arch.ARMv7 Endian.Big

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

module MIPS64 =
  open B2R2.FrontEnd.BinLifter.MIPS

  let private test arch endian opcode oprs bytes =
    let reader =
      if endian = Endian.Little then
        BinReader.binReaderLE
      else
        BinReader.binReaderBE

    let span = System.ReadOnlySpan bytes
    let ins = Parser.parse span reader arch WordSize.Bit64 0UL
    let opcode' = ins.Info.Opcode
    let oprs' = ins.Info.Operands
    Assert.AreEqual (opcode', opcode)
    Assert.AreEqual (oprs', oprs)

  let private test64R2 = test Arch.MIPS64 Endian.Big

  /// Arithmetic operations
  [<TestClass>]
  type ArithmeticClass () =
    [<TestMethod>]
    member __.``[MIPS64] Arithmetic operations Parse Test`` () =
      test64R2
        Op.DADDU
        (ThreeOperands (OpReg R.R15, OpReg R.R21, OpReg R.R29))
        [| 0x02uy; 0xbduy; 0x78uy; 0x2duy |]

      test64R2
        Op.DADDIU
        (ThreeOperands (OpReg R.R13, OpReg R.R6, OpImm 0xffffffffffffccd5UL))
        [| 0x64uy; 0xcduy; 0xccuy; 0xd5uy |]

      test64R2
        Op.DSUBU
        (ThreeOperands (OpReg R.R26, OpReg R.R17, OpReg R.R9))
        [| 0x02uy; 0x29uy; 0xd0uy; 0x2fuy |]

  /// Shift And Rotate operations
  [<TestClass>]
  type ShiftAndRotateClass () =
    [<TestMethod>]
    member __.``[MIPS64] Shift And Rotate operations Parse Test`` () =
      test64R2
        Op.DROTR
        (ThreeOperands (OpReg R.R30, OpReg R.R13, OpShiftAmount 0x1aUL))
        [| 0x00uy; 0x2duy; 0xf6uy; 0xbauy |]

      test64R2
        Op.DSLL
        (ThreeOperands (OpReg R.R29, OpReg R.R14, OpShiftAmount 0x1bUL))
        [| 0x00uy; 0x0euy; 0xeeuy; 0xf8uy |]

      test64R2
        Op.DSLL32
        (ThreeOperands (OpReg R.R28, OpReg R.R17, OpShiftAmount 0x15UL))
        [| 0x00uy; 0x11uy; 0xe5uy; 0x7cuy |]

      test64R2
        Op.DSLLV
        (ThreeOperands (OpReg R.R30, OpReg R.R26, OpReg R.R21))
        [| 0x02uy; 0xbauy; 0xf0uy; 0x14uy |]

      test64R2
        Op.DSRA
        (ThreeOperands (OpReg R.R30, OpReg R.R14, OpShiftAmount 0x1fUL))
        [| 0x00uy; 0x0euy; 0xf7uy; 0xfbuy |]

      test64R2
        Op.DSRA32
        (ThreeOperands (OpReg R.R26, OpReg R.R15, OpShiftAmount 0x7UL))
        [| 0x00uy; 0x0fuy; 0xd1uy; 0xffuy |]

  /// Logical and Bit-Field Operations
  [<TestClass>]
  type LogicalAndBitFieldClass () =
    [<TestMethod>]
    member __.``[MIPS64] Logical and Bit-Field operations Parse Test`` () =
      test64R2
        Op.DEXT
        (FourOperands (OpReg R.R29, OpReg R.R10, OpImm 0x2UL, OpImm 0xeUL))
        [| 0x7duy; 0x5duy; 0x68uy; 0x83uy |]

      test64R2
        Op.DINS
        (FourOperands (OpReg R.R21, OpReg R.R15, OpImm 0x9UL, OpImm 0x11UL))
        [| 0x7duy; 0xf5uy; 0xcauy; 0x47uy |]

  /// Multiply and Divide operations
  [<TestClass>]
  type MultiplyAndDivideClass () =
    [<TestMethod>]
    member __.``[MIPS64] Multiply and Divide operations Parse Test`` () =
      test64R2
        Op.DDIVU
        (TwoOperands (OpReg R.R30, OpReg R.R3))
        [| 0x03uy; 0xc3uy; 0x00uy; 0x1fuy |]

      test64R2
        Op.DMULT
        (TwoOperands (OpReg R.R24, OpReg R.R14))
        [| 0x03uy; 0x0euy; 0x00uy; 0x1cuy |]

      test64R2
        Op.DMULTU
        (TwoOperands (OpReg R.R17, OpReg R.R18))
        [| 0x02uy; 0x32uy; 0x00uy; 0x1duy |]

  /// Load and Store operations
  [<TestClass>]
  type LoadAndStoreClass () =
    [<TestMethod>]
    member __.``[MIPS64] Load and Store operations Parse Test`` () =
      test64R2
        Op.LD
        (TwoOperands (OpReg R.R29, OpMem (R.R26, Imm 0x2afdL, 64<rt>)))
        [| 0xdfuy; 0x5duy; 0x2auy; 0xfduy |]

      test64R2
        Op.LWU
        (TwoOperands (OpReg R.R17, OpMem (R.R24, Imm -0x52ffL, 32<rt>)))
        [| 0x9fuy; 0x11uy; 0xaduy; 0x01uy |]

      test64R2
        Op.SD
        (TwoOperands (OpReg R.R5, OpMem (R.R17, Imm 0x380aL, 64<rt>)))
        [| 0xfeuy; 0x25uy; 0x38uy; 0x0auy |]

      test64R2
        Op.SDL
        (TwoOperands (OpReg R.R12, OpMem (R.R26, Imm 0x3f02L, 64<rt>)))
        [| 0xb3uy; 0x4cuy; 0x3fuy; 0x02uy |]

      test64R2
        Op.SDR
        (TwoOperands (OpReg R.R11, OpMem (R.R6, Imm -0x78ebL, 64<rt>)))
        [| 0xb4uy; 0xcbuy; 0x87uy; 0x15uy |]

module MIPS32 =
  open B2R2.FrontEnd.BinLifter.MIPS

  let private test arch endian opcode cond fmt oprs bytes =
    let reader =
      if endian = Endian.Little then
        BinReader.binReaderLE
      else
        BinReader.binReaderBE

    let span = System.ReadOnlySpan bytes
    let ins = Parser.parse span reader arch WordSize.Bit32 0UL
    let opcode' = ins.Info.Opcode
    let cond' = ins.Info.Condition
    let fmt' = ins.Info.Fmt
    let oprs' = ins.Info.Operands
    Assert.AreEqual (opcode', opcode)
    Assert.AreEqual (cond', cond)
    Assert.AreEqual (fmt', fmt)
    Assert.AreEqual (oprs', oprs)

  let private test32R2 = test Arch.MIPS32 Endian.Big

  /// Arithmetic Operations
  [<TestClass>]
  type ArithmeticClass () =
    [<TestMethod>]
    member __.``[MIPS32] Arithmetic Operations Parse Test`` () =
      test32R2
        Op.ADDIU
        None
        None
        (ThreeOperands (OpReg R.R28, OpReg R.R28, OpImm 0xffffffffffff85bcUL))
        [| 0x27uy; 0x9cuy; 0x85uy; 0xbcuy |]

      test32R2
        Op.CLZ
        None
        None
        (TwoOperands (OpReg R.R2, OpReg R.R7))
        [| 0x70uy; 0xe2uy; 0x10uy; 0x20uy |]

      test32R2
        Op.LUI
        None
        None
        (TwoOperands (OpReg R.R28, OpImm 4UL))
        [| 0x3cuy; 0x1cuy; 0x00uy; 0x04uy |]

      test32R2
        Op.SEB
        None
        None
        (TwoOperands (OpReg R.R10, OpReg R.R10))
        [| 0x7cuy; 0x0auy; 0x54uy; 0x20uy |]

      test32R2
        Op.SUBU
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R16, OpReg R.R19))
        [| 0x02uy; 0x13uy; 0x10uy; 0x23uy |]

  /// Shift And Rotate Operations
  [<TestClass>]
  type ShiftAndRotateClass () =
    [<TestMethod>]
    member __.``[MIPS32] Shift And Rotate Operations Parse Test`` () =
      test32R2
        Op.ROTR
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R4, OpShiftAmount 3UL))
        [| 0x00uy; 0x24uy; 0x10uy; 0xc2uy |]

      test32R2
        Op.SLL
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R2, OpShiftAmount 2UL))
        [| 0x00uy; 0x02uy; 0x10uy; 0x80uy |]

      test32R2
        Op.SRA
        None
        None
        (ThreeOperands (OpReg R.R5, OpReg R.R5, OpShiftAmount 2UL))
        [| 0x00uy; 0x05uy; 0x28uy; 0x83uy |]

      test32R2
        Op.SRL
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R5, OpShiftAmount 31UL))
        [| 0x00uy; 0x05uy; 0x17uy; 0xc2uy |]

  /// Logical And Bit-Field Operations
  [<TestClass>]
  type LogicalAndBitFieldClass () =
    [<TestMethod>]
    member __.``[MIPS32] Logical And Bit-Field operations Parse Test`` () =
      test32R2
        Op.AND
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R19, OpReg R.R2))
        [| 0x02uy; 0x62uy; 0x10uy; 0x24uy |]

      test32R2
        Op.ANDI
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R2, OpImm 1UL))
        [| 0x30uy; 0x42uy; 0x00uy; 0x01uy |]

      test32R2
        Op.EXT
        None
        None
        (FourOperands (OpReg R.R2, OpReg R.R2, OpImm 6UL, OpImm 1UL))
        [| 0x7cuy; 0x42uy; 0x01uy; 0x80uy |]

      test32R2
        Op.INS
        None
        None
        (FourOperands (OpReg R.R3, OpReg R.R6, OpImm 6UL, OpImm 1UL))
        [| 0x7cuy; 0xc3uy; 0x31uy; 0x84uy |]

      test32R2
        Op.NOR
        None
        None
        (ThreeOperands (OpReg R.R6, OpReg R.R0, OpReg R.R6))
        [| 0x00uy; 0x06uy; 0x30uy; 0x27uy |]

      test32R2
        Op.OR
        None
        None
        (ThreeOperands (OpReg R.R19, OpReg R.R3, OpReg R.R0))
        [| 0x00uy; 0x60uy; 0x98uy; 0x25uy |]

      test32R2
        Op.ORI
        None
        None
        (ThreeOperands (OpReg R.R19, OpReg R.R19, OpImm 65535UL))
        [| 0x36uy; 0x73uy; 0xffuy; 0xffuy |]

      test32R2
        Op.XOR
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R2, OpReg R.R6))
        [| 0x00uy; 0x46uy; 0x10uy; 0x26uy |]

      test32R2
        Op.XORI
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R19, OpImm 6UL))
        [| 0x3auy; 0x62uy; 0x00uy; 0x06uy |]

  /// Condition Testing And Conditional Move Operations
  [<TestClass>]
  type CondTestAndCondMoveClass () =
    [<TestMethod>]
    member __.``[MIPS32] Condition Testing And .. Operations Parse Test`` () =
      test32R2
        Op.MOVN
        None
        None
        (ThreeOperands (OpReg R.R3, OpReg R.R4, OpReg R.R2))
        [| 0x00uy; 0x82uy; 0x18uy; 0x0buy |]

      test32R2
        Op.MOVZ
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R0, OpReg R.R5))
        [| 0x00uy; 0x05uy; 0x10uy; 0x0auy |]

      test32R2
        Op.SLT
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R19, OpReg R.R16))
        [| 0x02uy; 0x70uy; 0x10uy; 0x2auy |]

      test32R2
        Op.SLTI
        None
        None
        (ThreeOperands (OpReg R.R23, OpReg R.R2, OpImm 2UL))
        [| 0x28uy; 0x57uy; 0x00uy; 0x02uy |]

      test32R2
        Op.SLTIU
        None
        None
        (ThreeOperands (OpReg R.R3, OpReg R.R2, OpImm 275UL))
        [| 0x2cuy; 0x43uy; 0x01uy; 0x13uy |]

      test32R2
        Op.SLTU
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R0, OpReg R.R2))
        [| 0x00uy; 0x02uy; 0x10uy; 0x2buy |]

  /// Multiply and Divide operations
  [<TestClass>]
  type MultiplyAndDivideClass () =
    [<TestMethod>]
    member __.``[MIPS32] Multiply and Divide operations Parse Test`` () =
      test32R2
        Op.DIVU
        None
        None
        (TwoOperands (OpReg R.R3, OpReg R.R2))
        [| 0x00uy; 0x62uy; 0x00uy; 0x1buy |]

      test32R2
        Op.MUL
        None
        None
        (ThreeOperands (OpReg R.R3, OpReg R.R4, OpReg R.R8))
        [| 0x70uy; 0x88uy; 0x18uy; 0x02uy |]

      test32R2
        Op.MULTU
        None
        None
        (TwoOperands (OpReg R.R23, OpReg R.R5))
        [| 0x02uy; 0xe5uy; 0x00uy; 0x19uy |]

  /// Accumulator Access operations
  [<TestClass>]
  type AccumulatorAccessClass () =
    [<TestMethod>]
    member __.``[MIPS32] Accumulator Access operations Parse Test`` () =
      test32R2
        Op.MFHI
        None
        None
        (OneOperand (OpReg R.R2))
        [| 0x00uy; 0x00uy; 0x10uy; 0x10uy |]

      test32R2
        Op.MFLO
        None
        None
        (OneOperand (OpReg R.R3))
        [| 0x00uy; 0x00uy; 0x18uy; 0x12uy |]

  /// Jumps And Branches Operations
  [<TestClass>]
  type JumpAndBranchesClass () =
    [<TestMethod>]
    member __.``[MIPS32] Jump And Branches operations Parse Test`` () =
      test32R2
        Op.BNE
        None
        None
        (ThreeOperands (OpReg R.R2, OpReg R.R0, OpAddr (Relative 4100L)))
        [| 0x14uy; 0x40uy; 0x04uy; 0x00uy |]

      test32R2
        Op.BLEZ
        None
        None
        (TwoOperands (OpReg R.R23, OpAddr (Relative 4444L)))
        [| 0x1auy; 0xe0uy; 0x04uy; 0x56uy |]

      test32R2
        Op.BGTZ
        None
        None
        (TwoOperands (OpReg R.R2, OpAddr (Relative -48L)))
        [| 0x1cuy; 0x40uy; 0xffuy; 0xf3uy |]

      test32R2
        Op.JR
        None
        None
        (OneOperand (OpReg R.R31))
        [| 0x03uy; 0xe0uy; 0x00uy; 0x08uy |]

      test32R2
        Op.JALR
        None
        None
        (OneOperand (OpReg R.R25))
        [| 0x03uy; 0x20uy; 0xf8uy; 0x09uy |]

      test32R2
        Op.BAL
        None
        None
        (OneOperand (OpAddr (Relative 63608L)))
        [| 0x04uy; 0x11uy; 0x3euy; 0x1duy |]

      test32R2
        Op.BLTZ
        None
        None
        (TwoOperands (OpReg R.R2, OpAddr (Relative 424L)))
        [| 0x04uy; 0x40uy; 0x00uy; 0x69uy |]

      test32R2
        Op.BGEZ
        None
        None
        (TwoOperands (OpReg R.R22, OpAddr (Relative 1404L)))
        [| 0x06uy; 0xc1uy; 0x01uy; 0x5euy |]

  /// Load And Store operations
  [<TestClass>]
  type LoadAndStoreClass () =
    [<TestMethod>]
    member __.``[MIPS32] Load And Store operations Parse Test`` () =
      test32R2
        Op.LB
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R2, Imm 0L, 8<rt>)))
        [| 0x80uy; 0x42uy; 0x00uy; 0x00uy |]

      test32R2
        Op.LBU
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R19, Imm 17432L, 8<rt>)))
        [| 0x92uy; 0x62uy; 0x44uy; 0x18uy |]

      test32R2
        Op.LHU
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R29, Imm 170L, 16<rt>)))
        [| 0x97uy; 0xa2uy; 0x00uy; 0xaauy |]

      test32R2
        Op.LW
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R28, Imm -032060L, 32<rt>)))
        [| 0x8fuy; 0x82uy; 0x82uy; 0xc4uy |]

      test32R2
        Op.SB
        None
        None
        (TwoOperands (OpReg R.R4, OpMem (R.R22, Imm 17372L, 8<rt>)))
        [| 0xa2uy; 0xc4uy; 0x43uy; 0xdcuy |]

      test32R2
        Op.SH
        None
        None
        (TwoOperands (OpReg R.R2, OpMem (R.R29, Imm 184L, 16<rt>)))
        [| 0xa7uy; 0xa2uy; 0x00uy; 0xb8uy |]

      test32R2
        Op.SW
        None
        None
        (TwoOperands (OpReg R.R28, OpMem (R.R29, Imm 16L, 32<rt>)))
        [| 0xafuy; 0xbcuy; 0x00uy; 0x10uy |]

      test32R2
        Op.SWL
        None
        None
        (TwoOperands (OpReg R.R4, OpMem (R.R2, Imm 0L, 32<rt>)))
        [| 0xa8uy; 0x44uy; 0x00uy; 0x00uy |]

      test32R2
        Op.SWR
        None
        None
        (TwoOperands (OpReg R.R4, OpMem (R.R2, Imm 3L, 32<rt>)))
        [| 0xb8uy; 0x44uy; 0x00uy; 0x03uy |]

  /// Floating Point operations
  [<TestClass>]
  type FloatingPointClass () =
    [<TestMethod>]
    member __.``[MIPS32] Floating Point operations Parse Test`` () =
      test32R2
        Op.ADD
        None
        (Some Fmt.S)
        (ThreeOperands (OpReg R.F2, OpReg R.F4, OpReg R.F2))
        [| 0x46uy; 0x02uy; 0x20uy; 0x80uy |]

      test32R2
        Op.ADD
        None
        (Some Fmt.D)
        (ThreeOperands (OpReg R.F0, OpReg R.F0, OpReg R.F2))
        [| 0x46uy; 0x22uy; 0x00uy; 0x00uy |]

      test32R2
        Op.SUB
        None
        (Some Fmt.D)
        (ThreeOperands (OpReg R.F12, OpReg R.F12, OpReg R.F0))
        [| 0x46uy; 0x20uy; 0x63uy; 0x01uy |]

      test32R2
        Op.DIV
        None
        (Some Fmt.D)
        (ThreeOperands (OpReg R.F0, OpReg R.F0, OpReg R.F2))
        [| 0x46uy; 0x22uy; 0x00uy; 0x03uy |]

      test32R2
        Op.DIV
        None
        (Some Fmt.S)
        (ThreeOperands (OpReg R.F0, OpReg R.F0, OpReg R.F2))
        [| 0x46uy; 0x02uy; 0x00uy; 0x03uy |]

      test32R2
        Op.MOV
        None
        (Some Fmt.D)
        (TwoOperands (OpReg R.F20, OpReg R.F0))
        [| 0x46uy; 0x20uy; 0x05uy; 0x06uy |]

      test32R2
        Op.MFC1
        None
        None
        (TwoOperands (OpReg R.R20, OpReg R.F0))
        [| 0x44uy; 0x14uy; 0x00uy; 0x00uy |]

      test32R2
        Op.MTC1
        None
        None
        (TwoOperands (OpReg R.R0, OpReg R.F6))
        [| 0x44uy; 0x80uy; 0x30uy; 0x00uy |]

      test32R2
        Op.LDC1
        None
        None
        (TwoOperands (OpReg R.F4, OpMem (R.R2, Imm 2632L, 32<rt>)))
        [| 0xd4uy; 0x44uy; 0x0auy; 0x48uy |]

      test32R2
        Op.LWC1
        None
        None
        (TwoOperands (OpReg R.F0, OpMem (R.R3, Imm 8L, 32<rt>)))
        [| 0xc4uy; 0x60uy; 0x00uy; 0x08uy |]

      test32R2
        Op.SDC1
        None
        None
        (TwoOperands (OpReg R.F0, OpMem (R.R29, Imm 16L, 32<rt>)))
        [| 0xf7uy; 0xa0uy; 0x00uy; 0x10uy |]

      test32R2
        Op.SWC1
        None
        None
        (TwoOperands (OpReg R.F0, OpMem (R.R4, Imm 4L, 32<rt>)))
        [| 0xe4uy; 0x80uy; 0x00uy; 0x04uy |]

      test32R2
        Op.C
        (Some Condition.LT)
        (Some Fmt.S)
        (TwoOperands (OpReg R.F2, OpReg R.F0))
        [| 0x46uy; 0x00uy; 0x10uy; 0x3cuy |]

      test32R2
        Op.CVTD
        None
        (Some Fmt.W)
        (TwoOperands (OpReg R.F0, OpReg R.F0))
        [| 0x46uy; 0x80uy; 0x00uy; 0x21uy |]

      test32R2
        Op.CVTS
        None
        (Some Fmt.D)
        (TwoOperands (OpReg R.F0, OpReg R.F0))
        [| 0x46uy; 0x20uy; 0x00uy; 0x20uy |]

      test32R2
        Op.TRUNCW
        None
        (Some Fmt.D)
        (TwoOperands (OpReg R.F0, OpReg R.F0))
        [| 0x46uy; 0x20uy; 0x00uy; 0x0duy |]

      test32R2
        Op.TRUNCW
        None
        (Some Fmt.S)
        (TwoOperands (OpReg R.F0, OpReg R.F0))
        [| 0x46uy; 0x00uy; 0x00uy; 0x0duy |]

  /// ETC Operations
  [<TestClass>]
  type ETCClass () =
    [<TestMethod>]
    member __.``[MIPS32] ETC Operations Parse Test`` () =
      test32R2
        Op.TEQ
        None
        None
        (TwoOperands (OpReg R.R2, OpReg R.R0))
        [| 0x00uy; 0x40uy; 0x01uy; 0xf4uy |]

      test32R2
        Op.BC1T
        None
        None
        (TwoOperands (OpImm 6UL, OpAddr (Relative 20L)))
        [| 0x45uy; 0x19uy; 0x00uy; 0x04uy |]

      test32R2
        Op.BC1F
        None
        None
        (OneOperand (OpAddr (Relative 108L)))
        [| 0x45uy; 0x00uy; 0x00uy; 0x1auy |]

module EVM =
  open B2R2.FrontEnd.BinLifter.EVM

  let private test opcode bytes =
    let reader = BinReader.binReaderLE
    let span = System.ReadOnlySpan bytes
    let ins = Parser.parse span reader 0UL WordSize.Bit64 0UL
    let opcode' = ins.Info.Opcode
    Assert.AreEqual (opcode', opcode)

  /// 60s & 70s: Push Operations
  [<TestClass>]
  type PUSHClass () =
    [<TestMethod>]
    member __.``[EVM] Push Parse Test`` () =
      test
        (Opcode.PUSH10 <| (BitVector.OfBInt 316059037807746189465I 80<rt>))
        [| 0x69uy
           0x00uy
           0x11uy
           0x22uy
           0x33uy
           0x44uy
           0x55uy
           0x66uy
           0x77uy
           0x88uy
           0x99uy |]

// vim: set tw=80 sts=2 sw=2:

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
open B2R2.FrontEnd.Intel
open type Opcode

/// Shortcut for creating operands.
[<AutoOpen>]
module private IntelShortcut =
  type O =
    static member Reg (r) =
      OprReg r

    static member Mem (bReg, rt) =
      OprMem (Some bReg, None, None, rt)

    static member Mem (bReg, disp: Disp, rt) =
      OprMem (Some bReg, None, Some disp, rt)

    static member Mem (bReg, idx, scale, rt) =
      OprMem (Some bReg, Some (idx, scale), None, rt)

    static member Mem (bReg, idx, scale, disp, rt) =
      OprMem (Some bReg, Some (idx, scale), Some disp, rt)

    static member Mem (disp: Disp, rt) =
      OprMem (None, None, Some disp, rt)

    static member Imm (v, rt) =
      OprImm (v, rt)

    static member Addr (selector, addr, rt) =
      OprDirAddr (Absolute (selector, addr, rt))

/// - 5.1 GENERAL-PURPOSE INSTRUCTIONS
/// - 5.2 X87 FPU INSTRUCTIONS
/// - 5.4 MMX INSTRUCTIONS
/// - 5.5 SSE INSTRUCTIONS
/// - 5.6 SSE2 INSTRUCTIONS
/// - 5.8 SUPPLEMENTAL STREAMING SIMD EXTENSIONS 3 (SSSE3) INSTRUCTIONS
/// - 5.10 SSE4.1 INSTRUCTIONS
/// - 5.11 SSE4.2 INSTRUCTION SET
/// - 5.22 INTEL MEMORY PROTECTION EXTENSIONS
/// - INTEL ADVANCED VECTOR EXTENSIONS (AVX)
/// - Exception Test
[<TestClass>]
type IntelParserTests () =
  let test prefs segment wordSize opcode (oprs: Operands) bytes =
    let parser = IntelParser wordSize :> IInstructionParsable
    let ins = parser.Parse (bs=bytes, addr=0UL) :?> IntelInternalInstruction
    Assert.AreEqual<Prefix> (ins.Prefixes, prefs)
    Assert.AreEqual<Register option> (Helper.getSegment ins.Prefixes, segment)
    Assert.AreEqual<Opcode> (ins.Opcode, opcode)
    Assert.AreEqual<Operands> (ins.Operands, oprs)
    Assert.AreEqual<uint32> (ins.Length, uint32 bytes.Length)

  let testX86NoPrefixNoSeg (bytes: byte[]) (opcode, operands) =
    test Prefix.PrxNone None WordSize.Bit32 opcode operands bytes

  let testX86Prefix pref (bytes: byte[]) (opcode, operands) =
    test pref None WordSize.Bit32 opcode operands bytes

  let testX86 pref seg (bytes: byte[]) (opcode, operands) =
    test pref (Some seg) WordSize.Bit32 opcode operands bytes

  let testX64NoPrefixNoSeg (bytes: byte[]) (opcode, operands) =
    test Prefix.PrxNone None WordSize.Bit64 opcode operands bytes

  let operandsFromArray oprList =
    let oprArray = Array.ofList oprList
    match oprArray.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArray[0]
    | 2 -> TwoOperands (oprArray[0], oprArray[1])
    | 3 -> ThreeOperands (oprArray[0], oprArray[1], oprArray[2])
    | 4 -> FourOperands (oprArray[0], oprArray[1], oprArray[2], oprArray[3])
    | _ -> Utils.impossible ()

  let ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  [<TestMethod>]
  member __.``5.1.1 Data Transfer Instructions (1)`` () =
    "c70518bb210002000000"
    ++ MOV ** [ O.Mem (2210584L, 32<rt>); O.Imm (2L, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.1 Data Transfer Instructions (2)`` () =
    "6811223344"
    ++ PUSH ** [ O.Imm (0x44332211L, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.1 Data Transfer Instructions (3)`` () =
    "0fbe7fff"
    ++ MOVSX ** [ O.Reg R.EDI; O.Mem (R.EDI, -1L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.1 Data Transfer Instructions (4)`` () =
    "4863c8"
    ++ MOVSXD ** [ O.Reg R.RCX; O.Reg R.EAX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.2 Binary Arithmetic Instructions (1)`` () =
    "4803c8"
    ++ ADD ** [ O.Reg R.RCX; O.Reg R.RAX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.2 Binary Arithmetic Instructions (2)`` () =
    "6bfa0a"
    ++ IMUL ** [ O.Reg R.EDI; O.Reg R.EDX; O.Imm (10L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.2 Binary Arithmetic Instructions (3)`` () =
    "f720"
    ++ MUL ** [ O.Mem (R.EAX, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.2 Binary Arithmetic Instructions (4)`` () =
    "f7f1"
    ++ DIV ** [ O.Reg R.ECX ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.3 Decimal Arithmetic Instructions (1)`` () =
    "37"
    ++ AAA ** []
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.3 Decimal Arithmetic Instructions (2)`` () =
    "3F"
    ++ AAS ** []
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.4 Logical Instructions (1)`` () =
    "212414"
    ++ AND ** [ O.Mem (R.ESP, R.EDX, Scale.X1, 32<rt>); O.Reg R.ESP ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.4 Logical Instructions (2)`` () =
    "212542424242"
    ++ AND ** [ O.Mem (1111638594L, 32<rt>); O.Reg R.ESP ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.5 Shift and Rotate Instructions (1)`` () =
    "c1000a"
    ++ ROL ** [ O.Mem (R.EAX, 32<rt>); O.Imm (10L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.5 Shift and Rotate Instructions (2)`` () =
    "c0000a"
    ++ ROL ** [ O.Mem (R.EAX, 8<rt>); O.Imm (10L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.6 Bit and Byte Instructions (1)`` () =
    "f6000a"
    ++ TEST ** [ O.Mem (R.EAX, 8<rt>); O.Imm (10L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.7 Control Transfer Instructions (1)`` () =
    "ffe4"
    ++ JMPNear ** [ O.Reg R.ESP ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.7 Control Transfer Instructions (2)`` () =
    "ea123456789000"
    ++ JMPFar ** [ O.Addr (0x90s, 0x78563412UL, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.7 Control Transfer Instructions (3)`` () =
    "65ff1510000000"
    ++ CALLNear ** [ O.Mem (16L, 32<rt>) ]
    ||> testX86 (Prefix.PrxGS) R.GS

  [<TestMethod>]
  member __.``5.1.7 Control Transfer Instructions (4)`` () =
    "9a987654321000"
    ++ CALLFar ** [ O.Addr (0x10s, 0x32547698UL, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.7 Control Transfer Instructions (5)`` () =
    "cd01"
    ++ INT ** [ O.Imm (1L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.9 I/O Instructions (1)`` () =
    "ed"
    ++ IN ** [ O.Reg R.EAX; O.Reg R.DX ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.9 I/O Instructions (2)`` () =
    "ee"
    ++ OUT ** [ O.Reg R.DX; O.Reg R.AL ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.9 I/O Instructions (3)`` () =
    "66ef"
    ++ OUT ** [ O.Reg R.DX; O.Reg R.AX ]
    ||> testX86Prefix Prefix.PrxOPSIZE

  [<TestMethod>]
  member __.``5.1.9 I/O Instructions (4)`` () =
    "ef"
    ++ OUT ** [ O.Reg R.DX; O.Reg R.EAX ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.12 Segment Register Instructions (1)`` () =
    "c40f"
    ++ LES ** [ O.Reg R.ECX; O.Mem (R.EDI, 48<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.1.12 Segment Register Instructions (2)`` () =
    "c511"
    ++ LDS ** [ O.Reg R.EDX; O.Mem (R.ECX, 48<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.2.1 x87 FPU Data Transfer Instructions (1)`` () =
    "df84ca01020304"
    ++ FILD ** [ O.Mem (R.EDX, R.ECX, Scale.X8, 67305985L, 16<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.2.1 x87 FPU Data Transfer Instructions (2)`` () =
    "df20"
    ++ FBLD ** [ O.Mem (R.EAX, 80<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.2.3 x87 FPU Comparison Instructions (1)`` () =
    "dff1"
    ++ FCOMIP ** [ O.Reg R.ST0; O.Reg R.ST1 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.2.3 x87 FPU Comparison Instructions (2)`` () =
    "dfe9"
    ++ FUCOMIP ** [ O.Reg R.ST0; O.Reg R.ST1 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.4.1 MMX Conversion Instructions (1)`` () =
    "c4e1f9d69001020304;"
    ++ VMOVQ ** [ O.Mem (R.RAX, 67305985L, 64<rt>); O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.4.1 MMX Conversion Instructions (2)`` () =
    "c4e1f9d6d0"
    ++ VMOVQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.4.4 MMX Comparison Instructions (1)`` () =
    "0f7501"
    ++ PCMPEQW ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.4.4 MMX Comparison Instructions (2)`` () =
    "0f75c1"
    ++ PCMPEQW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.4.4 MMX Comparison Instructions (3)`` () =
    "660f7501"
    ++ PCMPEQW ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.4.4 MMX Comparison Instructions (4)`` () =
    "660f75c1"
    ++ PCMPEQW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.5.1.6 SSE Conversion Instructions (1)`` () =
    "c4e1fa2d9001020304;"
    ++ VCVTSS2SI ** [ O.Reg R.RDX; O.Mem (R.RAX, 67305985L, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.5.1.6 SSE Conversion Instructions (2)`` () =
    "c4e17b2d9001020304;"
    ++ VCVTSD2SI ** [ O.Reg R.EDX; O.Mem (R.RAX, 67305985L, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``Intel SSE 128-Bits SIMD Interger Instructions (1)`` () =
    "62f1fd486f4c2401"
    ++ VMOVDQA64 ** [ O.Reg R.ZMM1; O.Mem (R.RSP, 64L, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (1)`` () =
    "0f380101"
    ++ PHADDW ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (2)`` () =
    "0f3801c1"
    ++ PHADDW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (3)`` () =
    "660f380101"
    ++ PHADDW ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (4)`` () =
    "660f3801c1"
    ++ PHADDW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (5)`` () =
    "0f380301"
    ++ PHADDSW ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (6)`` () =
    "0f3803c1"
    ++ PHADDSW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (7)`` () =
    "660f380301"
    ++ PHADDSW ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (8)`` () =
    "660f3803c1"
    ++ PHADDSW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (9)`` () =
    "0f380201"
    ++ PHADDD ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (10)`` () =
    "0f3802c1"
    ++ PHADDD ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (11)`` () =
    "660f380201"
    ++ PHADDD ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (12)`` () =
    "660f3802c1"
    ++ PHADDD ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (13)`` () =
    "0f380501"
    ++ PHSUBW ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (14)`` () =
    "0f3805c1"
    ++ PHSUBW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (15)`` () =
    "660f380501"
    ++ PHSUBW ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (16)`` () =
    "660f3805c1"
    ++ PHSUBW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (17)`` () =
    "0f380701"
    ++ PHSUBSW ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (18)`` () =
    "0f3807c1"
    ++ PHSUBSW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (19)`` () =
    "660f380701"
    ++ PHSUBSW ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (20)`` () =
    "660f3807c1"
    ++ PHSUBSW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (21)`` () =
    "0f380601"
    ++ PHSUBD ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (22)`` () =
    "0f3806c1"
    ++ PHSUBD ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (23)`` () =
    "660f380601"
    ++ PHSUBD ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.1 Horizontal Addition/Subtraction (24)`` () =
    "660f3806c1"
    ++ PHSUBD ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (1)`` () =
    "0f381c01"
    ++ PABSB ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (2)`` () =
    "0f381cc1"
    ++ PABSB ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (3)`` () =
    "660f381c01"
    ++ PABSB ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (4)`` () =
    "660f381cc1"
    ++ PABSB ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (5)`` () =
    "0f381e01"
    ++ PABSD ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (6)`` () =
    "0f381ec1"
    ++ PABSD ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (7)`` () =
    "660f381e01"
    ++ PABSD ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (8)`` () =
    "660f381ec1"
    ++ PABSD ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (9)`` () =
    "0f381d01"
    ++ PABSW ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (10)`` () =
    "0f381dc1"
    ++ PABSW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (11)`` () =
    "660f381d01"
    ++ PABSW ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.2. Packed Absolute Values (12)`` () =
    "660f381dc1"
    ++ PABSW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.4 Packed Multiply High with Round and Scale (1)`` () =
    "0f380b01"
    ++ PMULHRSW ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.4 Packed Multiply High with Round and Scale (2)`` () =
    "0f380bc1"
    ++ PMULHRSW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.4 Packed Multiply High with Round and Scale (3)`` () =
    "660f380b01"
    ++ PMULHRSW ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.4 Packed Multiply High with Round and Scale (4)`` () =
    "660f380bc1"
    ++ PMULHRSW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (1)`` () =
    "0f380801"
    ++ PSIGNB ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (2)`` () =
    "0f3808c1"
    ++ PSIGNB ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (3)`` () =
    "660f380801"
    ++ PSIGNB ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (4)`` () =
    "660f3808c1"
    ++ PSIGNB ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (5)`` () =
    "0f380901"
    ++ PSIGNW ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (6)`` () =
    "0f3809c1"
    ++ PSIGNW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (7)`` () =
    "660f380901"
    ++ PSIGNW ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (8)`` () =
    "660f3809c1"
    ++ PSIGNW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (9)`` () =
    "0f380a01"
    ++ PSIGND ** [ O.Reg R.MM0; O.Mem (R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (10)`` () =
    "0f380ac1"
    ++ PSIGND ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (11)`` () =
    "660f380a01"
    ++ PSIGND ** [ O.Reg R.XMM0; O.Mem (R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.6 Packed Sign (12)`` () =
    "660f380ac1"
    ++ PSIGND ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.8.7 Packed Align Right (1)`` () =
    "660f3a0fd101"
    ++ PALIGNR ** [ O.Reg R.XMM2; O.Reg R.XMM1; O.Imm (1L, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.1 Dword Multiply Instructions (1)`` () =
    "660f384002"
    ++ PMULLD ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.1 Dword Multiply Instructions (2)`` () =
    "660f3840c2"
    ++ PMULLD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.1 Dword Multiply Instructions (3)`` () =
    "660f382802"
    ++ PMULDQ ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.1 Dword Multiply Instructions (4)`` () =
    "660f3828c2"
    ++ PMULDQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (1)`` () =
    "660f383a02"
    ++ PMINUW ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (2)`` () =
    "660f383ac2"
    ++ PMINUW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (3)`` () =
    "660f383902"
    ++ PMINSD ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (4)`` () =
    "660f3839c2"
    ++ PMINSD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (5)`` () =
    "660f383e02"
    ++ PMAXUW ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (6)`` () =
    "660f383ec2"
    ++ PMAXUW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (7)`` () =
    "660f383f02"
    ++ PMAXUD ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (8)`` () =
    "660f383fc2"
    ++ PMAXUD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (9)`` () =
    "660f383c02"
    ++ PMAXSB ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (10)`` () =
    "660f383cc2"
    ++ PMAXSB ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (11)`` () =
    "660f383d02"
    ++ PMAXSD ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.5 Packed Integer MIN/MAX Instructions (12)`` () =
    "660f383dc2"
    ++ PMAXSD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (1)`` () =
    "660f382102"
    ++ PMOVSXBD ** [ O.Reg R.XMM0; O.Mem (R.RDX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (2)`` () =
    "660f3821c2"
    ++ PMOVSXBD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (3)`` () =
    "660f382202"
    ++ PMOVSXBQ ** [ O.Reg R.XMM0; O.Mem (R.RDX, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (4)`` () =
    "660f3822c2"
    ++ PMOVSXBQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (5)`` () =
    "660f382002"
    ++ PMOVSXBW ** [ O.Reg R.XMM0; O.Mem (R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (6)`` () =
    "660f3820c2"
    ++ PMOVSXBW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (7)`` () =
    "660f382502"
    ++ PMOVSXDQ ** [ O.Reg R.XMM0; O.Mem (R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (8)`` () =
    "660f3825c2"
    ++ PMOVSXDQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (9)`` () =
    "660f382302"
    ++ PMOVSXWD ** [ O.Reg R.XMM0; O.Mem (R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (10)`` () =
    "660f3823c2"
    ++ PMOVSXWD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (11)`` () =
    "660f382402"
    ++ PMOVSXWQ ** [ O.Reg R.XMM0; O.Mem (R.RDX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (12)`` () =
    "660f3824c2"
    ++ PMOVSXWQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (13)`` () =
    "660f383102"
    ++ PMOVZXBD ** [ O.Reg R.XMM0; O.Mem (R.RDX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (14)`` () =
    "660f3831c2"
    ++ PMOVZXBD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (15)`` () =
    "660f383202"
    ++ PMOVZXBQ ** [ O.Reg R.XMM0; O.Mem (R.RDX, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (16)`` () =
    "660f3832c2"
    ++ PMOVZXBQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (17)`` () =
    "660f383002"
    ++ PMOVZXBW ** [ O.Reg R.XMM0; O.Mem (R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (18)`` () =
    "660f3830c2"
    ++ PMOVZXBW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (19)`` () =
    "660f383502"
    ++ PMOVZXDQ ** [ O.Reg R.XMM0; O.Mem (R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (20)`` () =
    "660f3835c2"
    ++ PMOVZXDQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (21)`` () =
    "660f383302"
    ++ PMOVZXWD ** [ O.Reg R.XMM0; O.Mem (R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (22)`` () =
    "660f3833c2"
    ++ PMOVZXWD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (23)`` () =
    "660f383402"
    ++ PMOVZXWQ ** [ O.Reg R.XMM0; O.Mem (R.RDX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.8 Packed Integer Format Conversions (24)`` () =
    "660f3834c2"
    ++ PMOVZXWQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.10 Horizontal Search (1)`` () =
    "660f384102"
    ++ PHMINPOSUW ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.10 Horizontal Search (2)`` () =
    "660f3841c2"
    ++ PHMINPOSUW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.13 Dword Packing With Unsigned Saturation (1)`` () =
    "660f382b02"
    ++ PACKUSDW ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.10.13 Dword Packing With Unsigned Saturation (2)`` () =
    "660f382bc2"
    ++ PACKUSDW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.11.2 Packed Comparison SIMD integer Instruction (1)`` () =
    "660f383702"
    ++ PCMPGTQ ** [ O.Reg R.XMM0; O.Mem (R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``5.11.2 Packed Comparison SIMD integer Instruction (2)`` () =
    "660f3837c2"
    ++ PCMPGTQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``Intel Memory Protection Extension Instruction (1)`` () =
    "660f1b842400020000"
    ++ BNDMOV ** [ O.Mem (R.RSP, 512L, 128<rt>); O.Reg R.BND0 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (1)`` () =
    "c4e1297503"
    ++ VPCMPEQW ** [ O.Reg R.XMM0; O.Reg R.XMM10; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (2)`` () =
    "c4e12975c3"
    ++ VPCMPEQW ** [ O.Reg R.XMM0; O.Reg R.XMM10; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (3)`` () =
    "c4e12d7503"
    ++ VPCMPEQW ** [ O.Reg R.YMM0; O.Reg R.YMM10; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (4)`` () =
    "c4e12d75c3"
    ++ VPCMPEQW ** [ O.Reg R.YMM0; O.Reg R.YMM10; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (5)`` () =
    "c4e2611c03"
    ++ VPABSB ** [ O.Reg R.XMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (6)`` () =
    "c4e2611cc3"
    ++ VPABSB ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (7)`` () =
    "c4e2651c03"
    ++ VPABSB ** [ O.Reg R.YMM0; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (8)`` () =
    "c4e2651cc3"
    ++ VPABSB ** [ O.Reg R.YMM0; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (9)`` () =
    "c4e2611e03"
    ++ VPABSD ** [ O.Reg R.XMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (10)`` () =
    "c4e2611ec3"
    ++ VPABSD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (11)`` () =
    "c4e2651e03"
    ++ VPABSD ** [ O.Reg R.YMM0; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (12)`` () =
    "c4e2651ec3"
    ++ VPABSD ** [ O.Reg R.YMM0; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (13)`` () =
    "c4e2611d03"
    ++ VPABSW ** [ O.Reg R.XMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (14)`` () =
    "c4e2611dc3"
    ++ VPABSW ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (15)`` () =
    "c4e2651d03"
    ++ VPABSW ** [ O.Reg R.YMM0; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (16)`` () =
    "c4e2651dc3"
    ++ VPABSW ** [ O.Reg R.YMM0; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (17)`` () =
    "c4e2610203"
    ++ VPHADDD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (18)`` () =
    "c4e26102c3"
    ++ VPHADDD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (19)`` () =
    "c4e2650203"
    ++ VPHADDD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (20)`` () =
    "c4e26502c3"
    ++ VPHADDD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (21)`` () =
    "c4e2610303"
    ++ VPHADDSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (22)`` () =
    "c4e26103c3"
    ++ VPHADDSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (23)`` () =
    "c4e2650303"
    ++ VPHADDSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (24)`` () =
    "c4e26503c3"
    ++ VPHADDSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (25)`` () =
    "c4e2610103"
    ++ VPHADDW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (26)`` () =
    "c4e26101c3"
    ++ VPHADDW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (27)`` () =
    "c4e2650103"
    ++ VPHADDW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (28)`` () =
    "c4e26501c3"
    ++ VPHADDW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (29)`` () =
    "c4e2610603"
    ++ VPHSUBD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (30)`` () =
    "c4e26106c3"
    ++ VPHSUBD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (31)`` () =
    "c4e2650603"
    ++ VPHSUBD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (32)`` () =
    "c4e26506c3"
    ++ VPHSUBD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (33)`` () =
    "c4e2610703"
    ++ VPHSUBSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (34)`` () =
    "c4e26107c3"
    ++ VPHSUBSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (35)`` () =
    "c4e2650703"
    ++ VPHSUBSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (36)`` () =
    "c4e26507c3"
    ++ VPHSUBSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (37)`` () =
    "c4e2610503"
    ++ VPHSUBW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (38)`` () =
    "c4e26105c3"
    ++ VPHSUBW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (39)`` () =
    "c4e2650503"
    ++ VPHSUBW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (40)`` () =
    "c4e26505c3"
    ++ VPHSUBW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (41)`` () =
    "c4e2610b03"
    ++ VPMULHRSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (42)`` () =
    "c4e2610bc3"
    ++ VPMULHRSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (43)`` () =
    "c4e2650b03"
    ++ VPMULHRSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (44)`` () =
    "c4e2650bc3"
    ++ VPMULHRSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (45)`` () =
    "c4e2610803"
    ++ VPSIGNB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (46)`` () =
    "c4e26108c3"
    ++ VPSIGNB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (47)`` () =
    "c4e2650803"
    ++ VPSIGNB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (48)`` () =
    "c4e26508c3"
    ++ VPSIGNB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (49)`` () =
    "c4e2610a03"
    ++ VPSIGND ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (50)`` () =
    "c4e2610ac3"
    ++ VPSIGND ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (51)`` () =
    "c4e2650a03"
    ++ VPSIGND ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (52)`` () =
    "c4e2650ac3"
    ++ VPSIGND ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (53)`` () =
    "c4e2610903"
    ++ VPSIGNW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (54)`` () =
    "c4e26109c3"
    ++ VPSIGNW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (55)`` () =
    "c4e2650903"
    ++ VPSIGNW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (56)`` () =
    "c4e26509c3"
    ++ VPSIGNW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (57)`` () =
    "c4e2612b03"
    ++ VPACKUSDW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (58)`` () =
    "c4e2612bc3"
    ++ VPACKUSDW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (59)`` () =
    "c4e2652b03"
    ++ VPACKUSDW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (60)`` () =
    "c4e2652bc3"
    ++ VPACKUSDW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (61)`` () =
    "c4e2613703"
    ++ VPCMPGTQ ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (62)`` () =
    "c4e26137c3"
    ++ VPCMPGTQ ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (63)`` () =
    "c4e2653703"
    ++ VPCMPGTQ ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (64)`` () =
    "c4e26537c3"
    ++ VPCMPGTQ ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (65)`` () =
    "c4e2614103"
    ++ VPHMINPOSUW ** [ O.Reg R.XMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (66)`` () =
    "c4e26141c3"
    ++ VPHMINPOSUW ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (67)`` () =
    "c4e2613c03"
    ++ VPMAXSB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (68)`` () =
    "c4e2613cc3"
    ++ VPMAXSB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (69)`` () =
    "c4e2653c03"
    ++ VPMAXSB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (70)`` () =
    "c4e2653cc3"
    ++ VPMAXSB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (71)`` () =
    "c4e2613d03"
    ++ VPMAXSD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (72)`` () =
    "c4e2613dc3"
    ++ VPMAXSD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (73)`` () =
    "c4e2653d03"
    ++ VPMAXSD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (74)`` () =
    "c4e2653dc3"
    ++ VPMAXSD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (75)`` () =
    "c4e2613f03"
    ++ VPMAXUD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (76)`` () =
    "c4e2613fc3"
    ++ VPMAXUD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (77)`` () =
    "c4e2653f03"
    ++ VPMAXUD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (78)`` () =
    "c4e2653fc3"
    ++ VPMAXUD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (79)`` () =
    "c4e2613e03"
    ++ VPMAXUW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (80)`` () =
    "c4e2613ec3"
    ++ VPMAXUW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (81)`` () =
    "c4e2653e03"
    ++ VPMAXUW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (82)`` () =
    "c4e2653ec3"
    ++ VPMAXUW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (83)`` () =
    "c4e2613803"
    ++ VPMINSB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (84)`` () =
    "c4e26138c3"
    ++ VPMINSB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (85)`` () =
    "c4e2653803"
    ++ VPMINSB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (86)`` () =
    "c4e26538c3"
    ++ VPMINSB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (87)`` () =
    "c4e2613903"
    ++ VPMINSD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (88)`` () =
    "c4e26139c3"
    ++ VPMINSD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (89)`` () =
    "c4e2653903"
    ++ VPMINSD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (90)`` () =
    "c4e26539c3"
    ++ VPMINSD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (91)`` () =
    "c4e2613a03"
    ++ VPMINUW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (92)`` () =
    "c4e2613ac3"
    ++ VPMINUW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (93)`` () =
    "c4e2653a03"
    ++ VPMINUW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (94)`` () =
    "c4e2653ac3"
    ++ VPMINUW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (95)`` () =
    "c4e2612103"
    ++ VPMOVSXBD ** [ O.Reg R.XMM0; O.Mem (R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (96)`` () =
    "c4e26121c3"
    ++ VPMOVSXBD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (97)`` () =
    "c4e2652103"
    ++ VPMOVSXBD ** [ O.Reg R.YMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (98)`` () =
    "c4e26521c3"
    ++ VPMOVSXBD ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (99)`` () =
    "c4e2612203"
    ++ VPMOVSXBQ ** [ O.Reg R.XMM0; O.Mem (R.RBX, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (100)`` () =
    "c4e26122c3"
    ++ VPMOVSXBQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (101)`` () =
    "c4e2652203"
    ++ VPMOVSXBQ ** [ O.Reg R.YMM0; O.Mem (R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (102)`` () =
    "c4e26522c3"
    ++ VPMOVSXBQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (103)`` () =
    "c4e2612003"
    ++ VPMOVSXBW ** [ O.Reg R.XMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (104)`` () =
    "c4e26120c3"
    ++ VPMOVSXBW ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (105)`` () =
    "c4e2652003"
    ++ VPMOVSXBW ** [ O.Reg R.YMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (106)`` () =
    "c4e26520c3"
    ++ VPMOVSXBW ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (107)`` () =
    "c4e2612503"
    ++ VPMOVSXDQ ** [ O.Reg R.XMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (108)`` () =
    "c4e26125c3"
    ++ VPMOVSXDQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (109)`` () =
    "c4e2652503"
    ++ VPMOVSXDQ ** [ O.Reg R.YMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (110)`` () =
    "c4e26525c3"
    ++ VPMOVSXDQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (111)`` () =
    "c4e2612303"
    ++ VPMOVSXWD ** [ O.Reg R.XMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (112)`` () =
    "c4e26123c3"
    ++ VPMOVSXWD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (113)`` () =
    "c4e2652303"
    ++ VPMOVSXWD ** [ O.Reg R.YMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (114)`` () =
    "c4e26523c3"
    ++ VPMOVSXWD ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (115)`` () =
    "c4e2612403"
    ++ VPMOVSXWQ ** [ O.Reg R.XMM0; O.Mem (R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (116)`` () =
    "c4e26124c3"
    ++ VPMOVSXWQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (117)`` () =
    "c4e2652403"
    ++ VPMOVSXWQ ** [ O.Reg R.YMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (118)`` () =
    "c4e26524c3"
    ++ VPMOVSXWQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (119)`` () =
    "c4e2613103"
    ++ VPMOVZXBD ** [ O.Reg R.XMM0; O.Mem (R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (120)`` () =
    "c4e26131c3"
    ++ VPMOVZXBD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (121)`` () =
    "c4e2653103"
    ++ VPMOVZXBD ** [ O.Reg R.YMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (122)`` () =
    "c4e26531c3"
    ++ VPMOVZXBD ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (123)`` () =
    "c4e2613203"
    ++ VPMOVZXBQ ** [ O.Reg R.XMM0; O.Mem (R.RBX, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (124)`` () =
    "c4e26132c3"
    ++ VPMOVZXBQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (125)`` () =
    "c4e2653203"
    ++ VPMOVZXBQ ** [ O.Reg R.YMM0; O.Mem (R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (126)`` () =
    "c4e26532c3"
    ++ VPMOVZXBQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (127)`` () =
    "c4e2613003"
    ++ VPMOVZXBW ** [ O.Reg R.XMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (128)`` () =
    "c4e26130c3"
    ++ VPMOVZXBW ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (129)`` () =
    "c4e2653003"
    ++ VPMOVZXBW ** [ O.Reg R.YMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (130)`` () =
    "c4e26530c3"
    ++ VPMOVZXBW ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (131)`` () =
    "c4e2613503"
    ++ VPMOVZXDQ ** [ O.Reg R.XMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (132)`` () =
    "c4e26135c3"
    ++ VPMOVZXDQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (133)`` () =
    "c4e2653503"
    ++ VPMOVZXDQ ** [ O.Reg R.YMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (134)`` () =
    "c4e26535c3"
    ++ VPMOVZXDQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (135)`` () =
    "c4e2613303"
    ++ VPMOVZXWD ** [ O.Reg R.XMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (136)`` () =
    "c4e26133c3"
    ++ VPMOVZXWD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (137)`` () =
    "c4e2653303"
    ++ VPMOVZXWD ** [ O.Reg R.YMM0; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (138)`` () =
    "c4e26533c3"
    ++ VPMOVZXWD ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (139)`` () =
    "c4e2613403"
    ++ VPMOVZXWQ ** [ O.Reg R.XMM0; O.Mem (R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (140)`` () =
    "c4e26134c3"
    ++ VPMOVZXWQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (141)`` () =
    "c4e2653403"
    ++ VPMOVZXWQ ** [ O.Reg R.YMM0; O.Mem (R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (142)`` () =
    "c4e26534c3"
    ++ VPMOVZXWQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (143)`` () =
    "c4e2612803"
    ++ VPMULDQ ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (144)`` () =
    "c4e26128c3"
    ++ VPMULDQ ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (145)`` () =
    "c4e2652803"
    ++ VPMULDQ ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (146)`` () =
    "c4e26528c3"
    ++ VPMULDQ ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (147)`` () =
    "c4e2614003"
    ++ VPMULLD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem (R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (148)`` () =
    "c4e26140c3"
    ++ VPMULLD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (149)`` () =
    "c4e2654003"
    ++ VPMULLD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem (R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member __.``AVX (150)`` () =
    "c4e26540c3"
    ++ VPMULLD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

#if !EMULATION
  [<TestMethod>]
  [<ExpectedException(typedefof<ParsingFailureException>)>]
  member __.``Size cond ParsingFailure Test (1)`` () =
    "37"
    ++ AAA ** []
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  [<ExpectedException(typedefof<ParsingFailureException>)>]
  member __.``Size cond ParsingFailure Test (2)`` () =
    "3F"
    ++ AAS ** []
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  [<ExpectedException(typedefof<ParsingFailureException>)>]
  member __.``Size cond ParsingFailure Test (3)`` () =
    "ea123456789000"
    ++ JMPFar ** [ O.Addr (0x90s, 0x78563412UL, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  [<ExpectedException(typedefof<ParsingFailureException>)>]
  member __.``Size cond ParsingFailure Test (4)`` () =
    "9a987654321000"
    ++ CALLFar ** [ O.Addr (0x10s, 0x32547698UL, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  [<ExpectedException(typedefof<System.IndexOutOfRangeException>)>]
  member __.``Size cond ParsingFailure Test (5)`` () =
    "c40f"
    ++ LES ** [ O.Reg R.ECX; O.Mem (R.EDI, 48<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  [<ExpectedException(typedefof<System.IndexOutOfRangeException>)>]
  member __.``Size cond ParsingFailure Test (6)`` () =
    "c511"
    ++ LDS ** [ O.Reg R.EDX; O.Mem (R.ECX, 48<rt>) ]
    ||> testX64NoPrefixNoSeg
#endif

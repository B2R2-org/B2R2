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

namespace B2R2.FrontEnd.Intel.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel
open type Opcode

/// Shortcut for creating operands.
[<AutoOpen>]
module private Shortcut =
  type O =
    static member Reg(r) = OprReg r

    static member Mem(bReg, rt) = OprMem(Some bReg, None, None, rt)

    static member Mem(bReg, disp: Displacement, rt) =
      OprMem(Some bReg, None, Some disp, rt)

    static member Mem(bReg, idx, scale, rt) =
      OprMem(Some bReg, Some(idx, scale), None, rt)

    static member Mem(bReg, idx, scale, disp, rt) =
      OprMem(Some bReg, Some(idx, scale), Some disp, rt)

    static member Mem(disp: Displacement, rt) =
      OprMem(None, None, Some disp, rt)

    static member Imm(v, rt) = OprImm(v, rt)

    static member Addr(selector, addr, rt) =
      OprDirAddr(Absolute(selector, addr, rt))

/// - 5.1 GENERAL-PURPOSE INSTRUCTIONS
/// - 5.2 X87 FPU INSTRUCTIONS
/// - 5.4 MMX INSTRUCTIONS
/// - 5.5 SSE INSTRUCTIONS
/// - 5.6 SSE2 INSTRUCTIONS
/// - 5.8 SUPPLEMENTAL STREAMING SIMD EXTENSIONS 3 (SSSE3) INSTRUCTIONS
/// - 5.10 SSE4.1 INSTRUCTIONS
/// - 5.11 SSE4.2 INSTRUCTION SET
/// - 5.19 SYSTEM INSTRUCTIONS
/// - 5.22 INTEL MEMORY PROTECTION EXTENSIONS
/// - INTEL ADVANCED VECTOR EXTENSIONS (AVX)
/// - Exception Test
[<TestClass>]
type ParserTests() =
  let test prefs segment wordSize opcode (oprs: Operands) bytes =
    let reader = BinReader.Init Endian.Little
    let parser = IntelParser(wordSize, reader) :> IInstructionParsable
    let ins = parser.Parse(bs = bytes, addr = 0UL) :?> Instruction
    Assert.AreEqual<Prefix>(ins.Prefixes, prefs)
    Assert.AreEqual<Register option>(Prefix.getSegment ins.Prefixes, segment)
    Assert.AreEqual<Opcode>(ins.Opcode, opcode)
    Assert.AreEqual<Operands>(ins.Operands, oprs)
    Assert.AreEqual<uint32>(ins.Length, uint32 bytes.Length)

  let testX86NoPrefixNoSeg (bytes: byte[]) (opcode, operands) =
    test Prefix.None None WordSize.Bit32 opcode operands bytes

  let testX86Prefix pref (bytes: byte[]) (opcode, operands) =
    test pref None WordSize.Bit32 opcode operands bytes

  let testX86 pref seg (bytes: byte[]) (opcode, operands) =
    test pref (Some seg) WordSize.Bit32 opcode operands bytes

  let testX64NoPrefixNoSeg (bytes: byte[]) (opcode, operands) =
    test Prefix.None None WordSize.Bit64 opcode operands bytes

  let operandsFromArray oprList =
    let oprArray = Array.ofList oprList
    match oprArray.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArray[0]
    | 2 -> TwoOperands(oprArray[0], oprArray[1])
    | 3 -> ThreeOperands(oprArray[0], oprArray[1], oprArray[2])
    | 4 -> FourOperands(oprArray[0], oprArray[1], oprArray[2], oprArray[3])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

  let testException testFn bytes (opcode, operands) =
    Assert.Throws(fun () -> testFn bytes (opcode, operands) |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``5.1.1 Data Transfer Instructions (1)``() =
    "c70518bb210002000000"
    ++ MOV ** [ O.Mem(2210584L, 32<rt>); O.Imm(2L, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.1 Data Transfer Instructions (2)``() =
    "6811223344"
    ++ PUSH ** [ O.Imm(0x44332211L, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.1 Data Transfer Instructions (3)``() =
    "0fbe7fff"
    ++ MOVSX ** [ O.Reg R.EDI; O.Mem(R.EDI, -1L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.1 Data Transfer Instructions (4)``() =
    "4863c8"
    ++ MOVSXD ** [ O.Reg R.RCX; O.Reg R.EAX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.2 Binary Arithmetic Instructions (1)``() =
    "4803c8"
    ++ ADD ** [ O.Reg R.RCX; O.Reg R.RAX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.2 Binary Arithmetic Instructions (2)``() =
    "6bfa0a"
    ++ IMUL ** [ O.Reg R.EDI; O.Reg R.EDX; O.Imm(10L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.2 Binary Arithmetic Instructions (3)``() =
    "f720"
    ++ MUL ** [ O.Mem(R.EAX, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.2 Binary Arithmetic Instructions (4)``() =
    "f7f1"
    ++ DIV ** [ O.Reg R.ECX ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.3 Decimal Arithmetic Instructions (1)``() =
    "37"
    ++ AAA ** []
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.3 Decimal Arithmetic Instructions (2)``() =
    "3F"
    ++ AAS ** []
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.4 Logical Instructions (1)``() =
    "212414"
    ++ AND ** [ O.Mem(R.ESP, R.EDX, Scale.X1, 32<rt>); O.Reg R.ESP ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.4 Logical Instructions (2)``() =
    "212542424242"
    ++ AND ** [ O.Mem(1111638594L, 32<rt>); O.Reg R.ESP ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.5 Shift and Rotate Instructions (1)``() =
    "c1000a"
    ++ ROL ** [ O.Mem(R.EAX, 32<rt>); O.Imm(10L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.5 Shift and Rotate Instructions (2)``() =
    "c0000a"
    ++ ROL ** [ O.Mem(R.EAX, 8<rt>); O.Imm(10L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.6 Bit and Byte Instructions (1)``() =
    "f6000a"
    ++ TEST ** [ O.Mem(R.EAX, 8<rt>); O.Imm(10L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.6 Bit and Byte Instructions (2)``() =
    "f30fbcf6"
    ++ TZCNT ** [ O.Reg R.ESI; O.Reg R.ESI ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.6 Bit and Byte Instructions (3)``() =
    "660fbcf6"
    ++ BSF ** [ O.Reg R.SI; O.Reg R.SI ]
    ||> testX86Prefix Prefix.OPSIZE

  [<TestMethod>]
  member _.``5.1.7 Control Transfer Instructions (1)``() =
    "ffe4"
    ++ JMP ** [ O.Reg R.ESP ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.7 Control Transfer Instructions (2)``() =
    "ea123456789000"
    ++ JMP ** [ O.Addr(0x90s, 0x78563412UL, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.7 Control Transfer Instructions (3)``() =
    "65ff1510000000"
    ++ CALL ** [ O.Mem(16L, 32<rt>) ]
    ||> testX86 (Prefix.GS) R.GS

  [<TestMethod>]
  member _.``5.1.7 Control Transfer Instructions (4)``() =
    "9a987654321000"
    ++ CALL ** [ O.Addr(0x10s, 0x32547698UL, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.7 Control Transfer Instructions (5)``() =
    "cd01"
    ++ INT ** [ O.Imm(1L, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  (* The SDM writes the SETcc opcode column as "0F 94", leaving out the "/r"
     that every other ModRM instruction carries, so the r/m8 operand is the
     only thing saying a ModRM byte follows. *)
  [<TestMethod>]
  member _.``5.1.8 Bit and Byte Instructions (1)``() =
    "0f94c1"
    ++ SETE ** [ O.Reg R.CL ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.8 Bit and Byte Instructions (2)``() =
    "0f9701"
    ++ SETA ** [ O.Mem(R.ECX, 8<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.9 I/O Instructions (1)``() =
    "ed"
    ++ IN ** [ O.Reg R.EAX; O.Reg R.DX ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.9 I/O Instructions (2)``() =
    "ee"
    ++ OUT ** [ O.Reg R.DX; O.Reg R.AL ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.9 I/O Instructions (3)``() =
    "66ef"
    ++ OUT ** [ O.Reg R.DX; O.Reg R.AX ]
    ||> testX86Prefix Prefix.OPSIZE

  [<TestMethod>]
  member _.``5.1.9 I/O Instructions (4)``() =
    "ef"
    ++ OUT ** [ O.Reg R.DX; O.Reg R.EAX ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.12 Segment Register Instructions (1)``() =
    "c40f"
    ++ LES ** [ O.Reg R.ECX; O.Mem(R.EDI, 48<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.1.12 Segment Register Instructions (2)``() =
    "c511"
    ++ LDS ** [ O.Reg R.EDX; O.Mem(R.ECX, 48<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.2.1 x87 FPU Data Transfer Instructions (1)``() =
    "df84ca01020304"
    ++ FILD ** [ O.Mem(R.EDX, R.ECX, Scale.X8, 67305985L, 16<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.2.1 x87 FPU Data Transfer Instructions (2)``() =
    "df20"
    ++ FBLD ** [ O.Mem(R.EAX, 80<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.2.3 x87 FPU Comparison Instructions (1)``() =
    "dff1"
    ++ FCOMIP ** [ O.Reg R.ST0; O.Reg R.ST1 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.2.3 x87 FPU Comparison Instructions (2)``() =
    "dfe9"
    ++ FUCOMIP ** [ O.Reg R.ST0; O.Reg R.ST1 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.4.1 MMX Conversion Instructions (1)``() =
    "c4e1f9d69001020304;"
    ++ VMOVQ ** [ O.Mem(R.RAX, 67305985L, 64<rt>); O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.4.1 MMX Conversion Instructions (2)``() =
    "c4e1f9d6d0"
    ++ VMOVQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.4.4 MMX Comparison Instructions (1)``() =
    "0f7501"
    ++ PCMPEQW ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.4.4 MMX Comparison Instructions (2)``() =
    "0f75c1"
    ++ PCMPEQW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.4.4 MMX Comparison Instructions (3)``() =
    "660f7501"
    ++ PCMPEQW ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.4.4 MMX Comparison Instructions (4)``() =
    "660f75c1"
    ++ PCMPEQW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.5.1.6 SSE Conversion Instructions (1)``() =
    "c4e1fa2d9001020304;"
    ++ VCVTSS2SI ** [ O.Reg R.RDX; O.Mem(R.RAX, 67305985L, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.5.1.6 SSE Conversion Instructions (2)``() =
    "c4e17b2d9001020304;"
    ++ VCVTSD2SI ** [ O.Reg R.EDX; O.Mem(R.RAX, 67305985L, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Intel SSE 128-Bits SIMD Interger Instructions (1)``() =
    "62f1fd486f4c2401"
    ++ VMOVDQA64 ** [ O.Reg R.ZMM1; O.Mem(R.RSP, 64L, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (1)``() =
    "0f380101"
    ++ PHADDW ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (2)``() =
    "0f3801c1"
    ++ PHADDW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (3)``() =
    "660f380101"
    ++ PHADDW ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (4)``() =
    "660f3801c1"
    ++ PHADDW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (5)``() =
    "0f380301"
    ++ PHADDSW ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (6)``() =
    "0f3803c1"
    ++ PHADDSW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (7)``() =
    "660f380301"
    ++ PHADDSW ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (8)``() =
    "660f3803c1"
    ++ PHADDSW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (9)``() =
    "0f380201"
    ++ PHADDD ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (10)``() =
    "0f3802c1"
    ++ PHADDD ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (11)``() =
    "660f380201"
    ++ PHADDD ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (12)``() =
    "660f3802c1"
    ++ PHADDD ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (13)``() =
    "0f380501"
    ++ PHSUBW ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (14)``() =
    "0f3805c1"
    ++ PHSUBW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (15)``() =
    "660f380501"
    ++ PHSUBW ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (16)``() =
    "660f3805c1"
    ++ PHSUBW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (17)``() =
    "0f380701"
    ++ PHSUBSW ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (18)``() =
    "0f3807c1"
    ++ PHSUBSW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (19)``() =
    "660f380701"
    ++ PHSUBSW ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (20)``() =
    "660f3807c1"
    ++ PHSUBSW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (21)``() =
    "0f380601"
    ++ PHSUBD ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (22)``() =
    "0f3806c1"
    ++ PHSUBD ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (23)``() =
    "660f380601"
    ++ PHSUBD ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.1 Horizontal Addition/Subtraction (24)``() =
    "660f3806c1"
    ++ PHSUBD ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (1)``() =
    "0f381c01"
    ++ PABSB ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (2)``() =
    "0f381cc1"
    ++ PABSB ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (3)``() =
    "660f381c01"
    ++ PABSB ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (4)``() =
    "660f381cc1"
    ++ PABSB ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (5)``() =
    "0f381e01"
    ++ PABSD ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (6)``() =
    "0f381ec1"
    ++ PABSD ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (7)``() =
    "660f381e01"
    ++ PABSD ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (8)``() =
    "660f381ec1"
    ++ PABSD ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (9)``() =
    "0f381d01"
    ++ PABSW ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (10)``() =
    "0f381dc1"
    ++ PABSW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (11)``() =
    "660f381d01"
    ++ PABSW ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.2. Packed Absolute Values (12)``() =
    "660f381dc1"
    ++ PABSW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.4 Packed Multiply High with Round and Scale (1)``() =
    "0f380b01"
    ++ PMULHRSW ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.4 Packed Multiply High with Round and Scale (2)``() =
    "0f380bc1"
    ++ PMULHRSW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.4 Packed Multiply High with Round and Scale (3)``() =
    "660f380b01"
    ++ PMULHRSW ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.4 Packed Multiply High with Round and Scale (4)``() =
    "660f380bc1"
    ++ PMULHRSW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (1)``() =
    "0f380801"
    ++ PSIGNB ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (2)``() =
    "0f3808c1"
    ++ PSIGNB ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (3)``() =
    "660f380801"
    ++ PSIGNB ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (4)``() =
    "660f3808c1"
    ++ PSIGNB ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (5)``() =
    "0f380901"
    ++ PSIGNW ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (6)``() =
    "0f3809c1"
    ++ PSIGNW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (7)``() =
    "660f380901"
    ++ PSIGNW ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (8)``() =
    "660f3809c1"
    ++ PSIGNW ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (9)``() =
    "0f380a01"
    ++ PSIGND ** [ O.Reg R.MM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (10)``() =
    "0f380ac1"
    ++ PSIGND ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (11)``() =
    "660f380a01"
    ++ PSIGND ** [ O.Reg R.XMM0; O.Mem(R.RCX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.6 Packed Sign (12)``() =
    "660f380ac1"
    ++ PSIGND ** [ O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.8.7 Packed Align Right (1)``() =
    "660f3a0fd101"
    ++ PALIGNR ** [ O.Reg R.XMM2; O.Reg R.XMM1; O.Imm(1L, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.1 Dword Multiply Instructions (1)``() =
    "660f384002"
    ++ PMULLD ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.1 Dword Multiply Instructions (2)``() =
    "660f3840c2"
    ++ PMULLD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.1 Dword Multiply Instructions (3)``() =
    "660f382802"
    ++ PMULDQ ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.1 Dword Multiply Instructions (4)``() =
    "660f3828c2"
    ++ PMULDQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (1)``() =
    "660f383a02"
    ++ PMINUW ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (2)``() =
    "660f383ac2"
    ++ PMINUW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (3)``() =
    "660f383902"
    ++ PMINSD ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (4)``() =
    "660f3839c2"
    ++ PMINSD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (5)``() =
    "660f383e02"
    ++ PMAXUW ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (6)``() =
    "660f383ec2"
    ++ PMAXUW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (7)``() =
    "660f383f02"
    ++ PMAXUD ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (8)``() =
    "660f383fc2"
    ++ PMAXUD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (9)``() =
    "660f383c02"
    ++ PMAXSB ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (10)``() =
    "660f383cc2"
    ++ PMAXSB ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (11)``() =
    "660f383d02"
    ++ PMAXSD ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.5 Packed Integer MIN/MAX Instructions (12)``() =
    "660f383dc2"
    ++ PMAXSD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (1)``() =
    "660f382102"
    ++ PMOVSXBD ** [ O.Reg R.XMM0; O.Mem(R.RDX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (2)``() =
    "660f3821c2"
    ++ PMOVSXBD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (3)``() =
    "660f382202"
    ++ PMOVSXBQ ** [ O.Reg R.XMM0; O.Mem(R.RDX, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (4)``() =
    "660f3822c2"
    ++ PMOVSXBQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (5)``() =
    "660f382002"
    ++ PMOVSXBW ** [ O.Reg R.XMM0; O.Mem(R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (6)``() =
    "660f3820c2"
    ++ PMOVSXBW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (7)``() =
    "660f382502"
    ++ PMOVSXDQ ** [ O.Reg R.XMM0; O.Mem(R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (8)``() =
    "660f3825c2"
    ++ PMOVSXDQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (9)``() =
    "660f382302"
    ++ PMOVSXWD ** [ O.Reg R.XMM0; O.Mem(R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (10)``() =
    "660f3823c2"
    ++ PMOVSXWD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (11)``() =
    "660f382402"
    ++ PMOVSXWQ ** [ O.Reg R.XMM0; O.Mem(R.RDX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (12)``() =
    "660f3824c2"
    ++ PMOVSXWQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (13)``() =
    "660f383102"
    ++ PMOVZXBD ** [ O.Reg R.XMM0; O.Mem(R.RDX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (14)``() =
    "660f3831c2"
    ++ PMOVZXBD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (15)``() =
    "660f383202"
    ++ PMOVZXBQ ** [ O.Reg R.XMM0; O.Mem(R.RDX, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (16)``() =
    "660f3832c2"
    ++ PMOVZXBQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (17)``() =
    "660f383002"
    ++ PMOVZXBW ** [ O.Reg R.XMM0; O.Mem(R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (18)``() =
    "660f3830c2"
    ++ PMOVZXBW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (19)``() =
    "660f383502"
    ++ PMOVZXDQ ** [ O.Reg R.XMM0; O.Mem(R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (20)``() =
    "660f3835c2"
    ++ PMOVZXDQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (21)``() =
    "660f383302"
    ++ PMOVZXWD ** [ O.Reg R.XMM0; O.Mem(R.RDX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (22)``() =
    "660f3833c2"
    ++ PMOVZXWD ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (23)``() =
    "660f383402"
    ++ PMOVZXWQ ** [ O.Reg R.XMM0; O.Mem(R.RDX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.8 Packed Integer Format Conversions (24)``() =
    "660f3834c2"
    ++ PMOVZXWQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.10 Horizontal Search (1)``() =
    "660f384102"
    ++ PHMINPOSUW ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.10 Horizontal Search (2)``() =
    "660f3841c2"
    ++ PHMINPOSUW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.13 Dword Packing With Unsigned Saturation (1)``() =
    "660f382b02"
    ++ PACKUSDW ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.10.13 Dword Packing With Unsigned Saturation (2)``() =
    "660f382bc2"
    ++ PACKUSDW ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.11.2 Packed Comparison SIMD integer Instruction (1)``() =
    "660f383702"
    ++ PCMPGTQ ** [ O.Reg R.XMM0; O.Mem(R.RDX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.11.2 Packed Comparison SIMD integer Instruction (2)``() =
    "660f3837c2"
    ++ PCMPGTQ ** [ O.Reg R.XMM0; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (1)``() =
    "0f20d1"
    ++ MOV ** [ O.Reg R.ECX; O.Reg R.CR2 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (2)``() =
    "0f20e1"
    ++ MOV ** [ O.Reg R.ECX; O.Reg R.CR4 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (3)``() =
    "0f22d1"
    ++ MOV ** [ O.Reg R.CR2; O.Reg R.ECX ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (4)``() =
    "440f20c1"
    ++ MOV ** [ O.Reg R.RCX; O.Reg R.CR8 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (5)``() =
    "440f22c1"
    ++ MOV ** [ O.Reg R.CR8; O.Reg R.RCX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (6)``() =
    "0f21c9"
    ++ MOV ** [ O.Reg R.ECX; O.Reg R.DR1 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (7)``() =
    "0f21f1"
    ++ MOV ** [ O.Reg R.ECX; O.Reg R.DR6 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (8)``() =
    "0f23f9"
    ++ MOV ** [ O.Reg R.DR7; O.Reg R.ECX ]
    ||> testX86NoPrefixNoSeg

  (* DR4 and DR5 are aliases of DR6 and DR7 while CR4.DE is clear, which is the
     register those accesses reach. *)
  [<TestMethod>]
  member _.``5.19 System Instructions (9)``() =
    "0f21e1"
    ++ MOV ** [ O.Reg R.ECX; O.Reg R.DR6 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``5.19 System Instructions (10)``() =
    "0f23e9"
    ++ MOV ** [ O.Reg R.DR7; O.Reg R.ECX ]
    ||> testX86NoPrefixNoSeg

  (* Carries no ModRM byte, so the length is the opcode's own two bytes. A
     third would swallow whatever instruction follows. *)
  [<TestMethod>]
  member _.``5.19 System Instructions (11)``() =
    "0f37"
    ++ GETSEC ** []
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``Intel Memory Protection Extension Instruction (1)``() =
    "660f1b842400020000"
    ++ BNDMOV ** [ O.Mem(R.RSP, 512L, 128<rt>); O.Reg R.BND0 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (1)``() =
    "c4e1297503"
    ++ VPCMPEQW ** [ O.Reg R.XMM0; O.Reg R.XMM10; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (2)``() =
    "c4e12975c3"
    ++ VPCMPEQW ** [ O.Reg R.XMM0; O.Reg R.XMM10; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (3)``() =
    "c4e12d7503"
    ++ VPCMPEQW ** [ O.Reg R.YMM0; O.Reg R.YMM10; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (4)``() =
    "c4e12d75c3"
    ++ VPCMPEQW ** [ O.Reg R.YMM0; O.Reg R.YMM10; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (5)``() =
    "c4e2611c03"
    ++ VPABSB ** [ O.Reg R.XMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (6)``() =
    "c4e2611cc3"
    ++ VPABSB ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (7)``() =
    "c4e2651c03"
    ++ VPABSB ** [ O.Reg R.YMM0; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (8)``() =
    "c4e2651cc3"
    ++ VPABSB ** [ O.Reg R.YMM0; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (9)``() =
    "c4e2611e03"
    ++ VPABSD ** [ O.Reg R.XMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (10)``() =
    "c4e2611ec3"
    ++ VPABSD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (11)``() =
    "c4e2651e03"
    ++ VPABSD ** [ O.Reg R.YMM0; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (12)``() =
    "c4e2651ec3"
    ++ VPABSD ** [ O.Reg R.YMM0; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (13)``() =
    "c4e2611d03"
    ++ VPABSW ** [ O.Reg R.XMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (14)``() =
    "c4e2611dc3"
    ++ VPABSW ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (15)``() =
    "c4e2651d03"
    ++ VPABSW ** [ O.Reg R.YMM0; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (16)``() =
    "c4e2651dc3"
    ++ VPABSW ** [ O.Reg R.YMM0; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (17)``() =
    "c4e2610203"
    ++ VPHADDD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (18)``() =
    "c4e26102c3"
    ++ VPHADDD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (19)``() =
    "c4e2650203"
    ++ VPHADDD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (20)``() =
    "c4e26502c3"
    ++ VPHADDD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (21)``() =
    "c4e2610303"
    ++ VPHADDSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (22)``() =
    "c4e26103c3"
    ++ VPHADDSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (23)``() =
    "c4e2650303"
    ++ VPHADDSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (24)``() =
    "c4e26503c3"
    ++ VPHADDSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (25)``() =
    "c4e2610103"
    ++ VPHADDW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (26)``() =
    "c4e26101c3"
    ++ VPHADDW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (27)``() =
    "c4e2650103"
    ++ VPHADDW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (28)``() =
    "c4e26501c3"
    ++ VPHADDW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (29)``() =
    "c4e2610603"
    ++ VPHSUBD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (30)``() =
    "c4e26106c3"
    ++ VPHSUBD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (31)``() =
    "c4e2650603"
    ++ VPHSUBD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (32)``() =
    "c4e26506c3"
    ++ VPHSUBD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (33)``() =
    "c4e2610703"
    ++ VPHSUBSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (34)``() =
    "c4e26107c3"
    ++ VPHSUBSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (35)``() =
    "c4e2650703"
    ++ VPHSUBSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (36)``() =
    "c4e26507c3"
    ++ VPHSUBSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (37)``() =
    "c4e2610503"
    ++ VPHSUBW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (38)``() =
    "c4e26105c3"
    ++ VPHSUBW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (39)``() =
    "c4e2650503"
    ++ VPHSUBW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (40)``() =
    "c4e26505c3"
    ++ VPHSUBW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (41)``() =
    "c4e2610b03"
    ++ VPMULHRSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (42)``() =
    "c4e2610bc3"
    ++ VPMULHRSW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (43)``() =
    "c4e2650b03"
    ++ VPMULHRSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (44)``() =
    "c4e2650bc3"
    ++ VPMULHRSW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (45)``() =
    "c4e2610803"
    ++ VPSIGNB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (46)``() =
    "c4e26108c3"
    ++ VPSIGNB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (47)``() =
    "c4e2650803"
    ++ VPSIGNB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (48)``() =
    "c4e26508c3"
    ++ VPSIGNB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (49)``() =
    "c4e2610a03"
    ++ VPSIGND ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (50)``() =
    "c4e2610ac3"
    ++ VPSIGND ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (51)``() =
    "c4e2650a03"
    ++ VPSIGND ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (52)``() =
    "c4e2650ac3"
    ++ VPSIGND ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (53)``() =
    "c4e2610903"
    ++ VPSIGNW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (54)``() =
    "c4e26109c3"
    ++ VPSIGNW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (55)``() =
    "c4e2650903"
    ++ VPSIGNW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (56)``() =
    "c4e26509c3"
    ++ VPSIGNW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (57)``() =
    "c4e2612b03"
    ++ VPACKUSDW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (58)``() =
    "c4e2612bc3"
    ++ VPACKUSDW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (59)``() =
    "c4e2652b03"
    ++ VPACKUSDW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (60)``() =
    "c4e2652bc3"
    ++ VPACKUSDW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (61)``() =
    "c4e2613703"
    ++ VPCMPGTQ ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (62)``() =
    "c4e26137c3"
    ++ VPCMPGTQ ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (63)``() =
    "c4e2653703"
    ++ VPCMPGTQ ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (64)``() =
    "c4e26537c3"
    ++ VPCMPGTQ ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (65)``() =
    "c4e2614103"
    ++ VPHMINPOSUW ** [ O.Reg R.XMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (66)``() =
    "c4e26141c3"
    ++ VPHMINPOSUW ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (67)``() =
    "c4e2613c03"
    ++ VPMAXSB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (68)``() =
    "c4e2613cc3"
    ++ VPMAXSB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (69)``() =
    "c4e2653c03"
    ++ VPMAXSB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (70)``() =
    "c4e2653cc3"
    ++ VPMAXSB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (71)``() =
    "c4e2613d03"
    ++ VPMAXSD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (72)``() =
    "c4e2613dc3"
    ++ VPMAXSD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (73)``() =
    "c4e2653d03"
    ++ VPMAXSD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (74)``() =
    "c4e2653dc3"
    ++ VPMAXSD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (75)``() =
    "c4e2613f03"
    ++ VPMAXUD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (76)``() =
    "c4e2613fc3"
    ++ VPMAXUD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (77)``() =
    "c4e2653f03"
    ++ VPMAXUD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (78)``() =
    "c4e2653fc3"
    ++ VPMAXUD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (79)``() =
    "c4e2613e03"
    ++ VPMAXUW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (80)``() =
    "c4e2613ec3"
    ++ VPMAXUW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (81)``() =
    "c4e2653e03"
    ++ VPMAXUW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (82)``() =
    "c4e2653ec3"
    ++ VPMAXUW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (83)``() =
    "c4e2613803"
    ++ VPMINSB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (84)``() =
    "c4e26138c3"
    ++ VPMINSB ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (85)``() =
    "c4e2653803"
    ++ VPMINSB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (86)``() =
    "c4e26538c3"
    ++ VPMINSB ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (87)``() =
    "c4e2613903"
    ++ VPMINSD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (88)``() =
    "c4e26139c3"
    ++ VPMINSD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (89)``() =
    "c4e2653903"
    ++ VPMINSD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (90)``() =
    "c4e26539c3"
    ++ VPMINSD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (91)``() =
    "c4e2613a03"
    ++ VPMINUW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (92)``() =
    "c4e2613ac3"
    ++ VPMINUW ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (93)``() =
    "c4e2653a03"
    ++ VPMINUW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (94)``() =
    "c4e2653ac3"
    ++ VPMINUW ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (95)``() =
    "c4e2612103"
    ++ VPMOVSXBD ** [ O.Reg R.XMM0; O.Mem(R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (96)``() =
    "c4e26121c3"
    ++ VPMOVSXBD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (97)``() =
    "c4e2652103"
    ++ VPMOVSXBD ** [ O.Reg R.YMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (98)``() =
    "c4e26521c3"
    ++ VPMOVSXBD ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (99)``() =
    "c4e2612203"
    ++ VPMOVSXBQ ** [ O.Reg R.XMM0; O.Mem(R.RBX, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (100)``() =
    "c4e26122c3"
    ++ VPMOVSXBQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (101)``() =
    "c4e2652203"
    ++ VPMOVSXBQ ** [ O.Reg R.YMM0; O.Mem(R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (102)``() =
    "c4e26522c3"
    ++ VPMOVSXBQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (103)``() =
    "c4e2612003"
    ++ VPMOVSXBW ** [ O.Reg R.XMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (104)``() =
    "c4e26120c3"
    ++ VPMOVSXBW ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (105)``() =
    "c4e2652003"
    ++ VPMOVSXBW ** [ O.Reg R.YMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (106)``() =
    "c4e26520c3"
    ++ VPMOVSXBW ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (107)``() =
    "c4e2612503"
    ++ VPMOVSXDQ ** [ O.Reg R.XMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (108)``() =
    "c4e26125c3"
    ++ VPMOVSXDQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (109)``() =
    "c4e2652503"
    ++ VPMOVSXDQ ** [ O.Reg R.YMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (110)``() =
    "c4e26525c3"
    ++ VPMOVSXDQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (111)``() =
    "c4e2612303"
    ++ VPMOVSXWD ** [ O.Reg R.XMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (112)``() =
    "c4e26123c3"
    ++ VPMOVSXWD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (113)``() =
    "c4e2652303"
    ++ VPMOVSXWD ** [ O.Reg R.YMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (114)``() =
    "c4e26523c3"
    ++ VPMOVSXWD ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (115)``() =
    "c4e2612403"
    ++ VPMOVSXWQ ** [ O.Reg R.XMM0; O.Mem(R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (116)``() =
    "c4e26124c3"
    ++ VPMOVSXWQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (117)``() =
    "c4e2652403"
    ++ VPMOVSXWQ ** [ O.Reg R.YMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (118)``() =
    "c4e26524c3"
    ++ VPMOVSXWQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (119)``() =
    "c4e2613103"
    ++ VPMOVZXBD ** [ O.Reg R.XMM0; O.Mem(R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (120)``() =
    "c4e26131c3"
    ++ VPMOVZXBD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (121)``() =
    "c4e2653103"
    ++ VPMOVZXBD ** [ O.Reg R.YMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (122)``() =
    "c4e26531c3"
    ++ VPMOVZXBD ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (123)``() =
    "c4e2613203"
    ++ VPMOVZXBQ ** [ O.Reg R.XMM0; O.Mem(R.RBX, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (124)``() =
    "c4e26132c3"
    ++ VPMOVZXBQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (125)``() =
    "c4e2653203"
    ++ VPMOVZXBQ ** [ O.Reg R.YMM0; O.Mem(R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (126)``() =
    "c4e26532c3"
    ++ VPMOVZXBQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (127)``() =
    "c4e2613003"
    ++ VPMOVZXBW ** [ O.Reg R.XMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (128)``() =
    "c4e26130c3"
    ++ VPMOVZXBW ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (129)``() =
    "c4e2653003"
    ++ VPMOVZXBW ** [ O.Reg R.YMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (130)``() =
    "c4e26530c3"
    ++ VPMOVZXBW ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (131)``() =
    "c4e2613503"
    ++ VPMOVZXDQ ** [ O.Reg R.XMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (132)``() =
    "c4e26135c3"
    ++ VPMOVZXDQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (133)``() =
    "c4e2653503"
    ++ VPMOVZXDQ ** [ O.Reg R.YMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (134)``() =
    "c4e26535c3"
    ++ VPMOVZXDQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (135)``() =
    "c4e2613303"
    ++ VPMOVZXWD ** [ O.Reg R.XMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (136)``() =
    "c4e26133c3"
    ++ VPMOVZXWD ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (137)``() =
    "c4e2653303"
    ++ VPMOVZXWD ** [ O.Reg R.YMM0; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (138)``() =
    "c4e26533c3"
    ++ VPMOVZXWD ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (139)``() =
    "c4e2613403"
    ++ VPMOVZXWQ ** [ O.Reg R.XMM0; O.Mem(R.RBX, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (140)``() =
    "c4e26134c3"
    ++ VPMOVZXWQ ** [ O.Reg R.XMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (141)``() =
    "c4e2653403"
    ++ VPMOVZXWQ ** [ O.Reg R.YMM0; O.Mem(R.RBX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (142)``() =
    "c4e26534c3"
    ++ VPMOVZXWQ ** [ O.Reg R.YMM0; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (143)``() =
    "c4e2612803"
    ++ VPMULDQ ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (144)``() =
    "c4e26128c3"
    ++ VPMULDQ ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (145)``() =
    "c4e2652803"
    ++ VPMULDQ ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (146)``() =
    "c4e26528c3"
    ++ VPMULDQ ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (147)``() =
    "c4e2614003"
    ++ VPMULLD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Mem(R.RBX, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (148)``() =
    "c4e26140c3"
    ++ VPMULLD ** [ O.Reg R.XMM0; O.Reg R.XMM3; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (149)``() =
    "c4e2654003"
    ++ VPMULLD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Mem(R.RBX, 256<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX (150)``() =
    "c4e26540c3"
    ++ VPMULLD ** [ O.Reg R.YMM0; O.Reg R.YMM3; O.Reg R.YMM3 ]
    ||> testX64NoPrefixNoSeg

  (* VEX.W is what tells the single-precision form from the double: W0 here
     and W1 for VFMADD132PD at the same opcode byte. The prefix also carries
     R, which is what makes the difference visible - with no register needing
     R, X or B the whole prefix reads as absent and the W0 row is reached
     anyway. *)
  [<TestMethod>]
  member _.``VEX W bit selects the operand kind (1)``() =
    "c4625198e3"
    ++ VFMADD132PS ** [ O.Reg R.XMM12; O.Reg R.XMM5; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VEX W bit selects the operand kind (2)``() =
    "c462d198e3"
    ++ VFMADD132PD ** [ O.Reg R.XMM12; O.Reg R.XMM5; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  (* An /is4 operand names its register in imm8[7:4]. Those four bits already
     reach every register the mode has, so no REX or VEX bit extends them
     further - here imm8 is 0x10, which is ymm1 and not ymm9. *)
  [<TestMethod>]
  member _.``Register from imm8 bits 7 to 4 (1)``() =
    "c4630d4b5d1010"
    ++ VBLENDVPD **
      [ O.Reg R.YMM11
        O.Reg R.YMM14
        O.Mem(R.RBP, 16L, 256<rt>)
        O.Reg R.YMM1 ]
    ||> testX64NoPrefixNoSeg

  (* Tuple1 Scalar scales the compressed displacement by the width of the
     scalar element, which for these is the byte or word the operand names.
     REX.W says nothing here - both forms are WIG. *)
  [<TestMethod>]
  member _.``Compressed displacement of a scalar element (1)``() =
    "62f37d08154908ef"
    ++ VPEXTRW **
      [ O.Mem(R.RCX, 16L, 16<rt>); O.Reg R.XMM1; O.Imm(0xefL, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Compressed displacement of a scalar element (2)``() =
    "62733d08204b083a"
    ++ VPINSRB **
      [ O.Reg R.XMM9
        O.Reg R.XMM8
        O.Mem(R.RBX, 8L, 8<rt>)
        O.Imm(0x3aL, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  (* A segment selector is two bytes wherever it comes from. REX.W widens the
     register the value may arrive in, not the memory read, which is how the
     paired store at 8C is written. The 8E row prints r/m64 instead, and the
     patch file records why the tables depart from it. *)
  [<TestMethod>]
  member _.``Segment register loaded from memory (1)``() =
    "488e5e10"
    ++ MOV ** [ O.Reg R.DS; O.Mem(R.RSI, 16L, 16<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``MOV to/from control registers (1)``() =
    "0f20c0"
    ++ MOV ** [ O.Reg R.EAX; O.Reg R.CR0 ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``MOV to/from control registers (2)``() =
    "0f20c0"
    ++ MOV ** [ O.Reg R.RAX; O.Reg R.CR0 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``MOV to/from control registers (3)``() =
    "440f20c0"
    ++ MOV ** [ O.Reg R.RAX; O.Reg R.CR8 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``MOV to/from control registers (4)``() =
    "0f22d9"
    ++ MOV ** [ O.Reg R.CR3; O.Reg R.RCX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``MOV to/from debug registers (1)``() =
    "0f21c0"
    ++ MOV ** [ O.Reg R.RAX; O.Reg R.DR0 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``MOV to/from debug registers (2)``() =
    "0f21fa"
    ++ MOV ** [ O.Reg R.RDX; O.Reg R.DR7 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``MOV to/from debug registers (3)``() =
    "0f23f6"
    ++ MOV ** [ O.Reg R.DR6; O.Reg R.RSI ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512 embedded rounding (1)``() =
    "62f17f082dc1"
    ++ VCVTSD2SI ** [ O.Reg R.EAX; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512 SAE on conversion (1)``() =
    "62f17f082cc1"
    ++ VCVTTSD2SI ** [ O.Reg R.EAX; O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512 broadcast with embedded rounding (1)``() =
    "62f1f54858c2"
    ++ VADDPD ** [ O.Reg R.ZMM0; O.Reg R.ZMM1; O.Reg R.ZMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512 broadcast with SAE (1)``() =
    "62f1f548c2d300"
    ++ VCMPPD ** [ O.Reg R.K2; O.Reg R.ZMM1; O.Reg R.ZMM3; O.Imm(0L, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512 register operand with SAE (1)``() =
    "62f37d481dca00"
    ++ VCVTPS2PH ** [ O.Reg R.YMM2; O.Reg R.ZMM1; O.Imm(0L, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Address-size-dependent register operand (1)``() =
    "f30faef0"
    ++ UMONITOR ** [ O.Reg R.RAX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Address-size-dependent register operand (2)``() =
    "f20f38f808"
    ++ ENQCMD ** [ O.Reg R.RCX; O.Mem(R.RAX, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Address-size-dependent register operand (3)``() =
    "f30f38f81a"
    ++ ENQCMDS ** [ O.Reg R.RBX; O.Mem(R.RDX, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Address-size-dependent register operand (4)``() =
    "660f38f811"
    ++ MOVDIR64B ** [ O.Reg R.RDX; O.Mem(R.RCX, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather, VEX, no displacement (1)``() =
    "c4e269900408"
    ++ VPGATHERDD **
      [ O.Reg R.XMM0; O.Mem(R.RAX, R.XMM1, Scale.X1, 128<rt>); O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather, VEX, disp8 (1)``() =
    "c4e251905c6110"
    ++ VPGATHERDD **
      [ O.Reg R.XMM3
        O.Mem(R.RCX, R.XMM4, Scale.X2, 16L, 128<rt>)
        O.Reg R.XMM5 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather, VEX, no base (mod00/RBP slot) (1)``() =
    "c4e26990041d11223344"
    ++ VPGATHERDD **
      [ O.Reg R.XMM0
        OprMem(None, Some(R.XMM3, Scale.X1), Some 0x44332211L, 128<rt>)
        O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather, VEX, narrower index (D+64-bit data) (1)``() =
    "c4e2ed900408"
    ++ VPGATHERDQ **
      [ O.Reg R.YMM0; O.Mem(R.RAX, R.XMM1, Scale.X1, 256<rt>); O.Reg R.YMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather, EVEX, compressed disp8 (1)``() =
    "62f27d0990440a02"
    ++ VPGATHERDD **
      [ O.Reg R.XMM0; O.Mem(R.RDX, R.XMM1, Scale.X1, 8L, 128<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB scatter, EVEX, no displacement (1)``() =
    "62f2fd09a20c13"
    ++ VSCATTERDPD **
      [ O.Mem(R.RBX, R.XMM2, Scale.X1, 128<rt>); O.Reg R.XMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather, EVEX, narrower index (D+64-bit data) (1)``() =
    "62f2fd4990040a"
    ++ VPGATHERDQ **
      [ O.Reg R.ZMM0; O.Mem(R.RDX, R.YMM1, Scale.X1, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather, VEX, narrower memory (Q+32-bit data) (1)``() =
    "c4e26d930408"
    ++ VGATHERQPS **
      [ O.Reg R.XMM0; O.Mem(R.RAX, R.YMM1, Scale.X1, 128<rt>); O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB prefetch, EVEX, narrower index (1)``() =
    "62f2fd49c60c11"
    ++ VGATHERPF0DPD **
      [ O.Mem(R.RCX, R.YMM2, Scale.X1, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather below one full vector, VEX (1)``() =
    "c4e269910408"
    ++ VPGATHERQD **
      [ O.Reg R.XMM0; O.Mem(R.RAX, R.XMM1, Scale.X1, 64<rt>); O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``VSIB gather below one full vector, EVEX (1)``() =
    "62f27d09910c0a"
    ++ VPGATHERQD **
      [ O.Reg R.XMM1; O.Mem(R.RDX, R.XMM1, Scale.X1, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512-FP16 map 5 (1)``() =
    "62f56c4858cb"
    ++ VADDPH ** [ O.Reg R.ZMM1; O.Reg R.ZMM2; O.Reg R.ZMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512-FP16 map 5 (2)``() =
    "62f56e0858cb"
    ++ VADDSH ** [ O.Reg R.XMM1; O.Reg R.XMM2; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512-FP16 map 5, memory operand (1)``() =
    "62f56c485e08"
    ++ VDIVPH ** [ O.Reg R.ZMM1; O.Reg R.ZMM2; O.Mem(R.RAX, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``AVX512-FP16 map 6 (1)``() =
    "62f66d4898cb"
    ++ VFMADD132PH ** [ O.Reg R.ZMM1; O.Reg R.ZMM2; O.Reg R.ZMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX R' extends ModRM reg (1)``() =
    "62e1744858c2"
    ++ VADDPS ** [ O.Reg R.ZMM16; O.Reg R.ZMM1; O.Reg R.ZMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX X extends a register-form ModRM rm (1)``() =
    "62b17c4858c0"
    ++ VADDPS ** [ O.Reg R.ZMM0; O.Reg R.ZMM0; O.Reg R.ZMM16 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX V' extends vvvv (1)``() =
    "62f17c4058c1"
    ++ VADDPS ** [ O.Reg R.ZMM0; O.Reg R.ZMM16; O.Reg R.ZMM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX V' extends the VSIB index (1)``() =
    "62f27d41900c02"
    ++ VPGATHERDD **
      [ O.Reg R.ZMM1; O.Mem(R.RDX, R.ZMM16, Scale.X1, 512<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX high registers, all four fields (1)``() =
    "62010c4058ff"
    ++ VADDPS ** [ O.Reg R.ZMM31; O.Reg R.ZMM30; O.Reg R.ZMM31 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``BOUND is not an EVEX prefix in 32-bit mode (1)``() =
    "6201"
    ++ BOUND ** [ O.Reg R.EAX; O.Mem(R.ECX, 64<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``ModRM byte spelled out after a VEX opcode (1)``() =
    "c4e27849c0"
    ++ TILERELEASE ** []
    ||> testX64NoPrefixNoSeg

  (* The manual writes EAX and XMM0 in angle brackets here: the encoding has
     no field to name them, but the instruction reads them all the same. *)
  [<TestMethod>]
  member _.``Register-only bit pattern 11:rrr:bbb (1)``() =
    "f30f38dcc1"
    ++ LOADIWKEY ** [ O.Reg R.XMM0; O.Reg R.XMM1; O.Reg R.EAX; O.Reg R.XMM0 ]
    ||> testX64NoPrefixNoSeg

  (* The same angle brackets, on the instructions where dropping them was
     caught: SSELifter reads all three operands, so a two-operand decoding
     parses and then fails the moment anything lifts it. *)
  [<TestMethod>]
  member _.``Implicit operand from the manual (1)``() =
    "660f3810c1"
    ++ PBLENDVB ** [ O.Reg R.XMM0; O.Reg R.XMM1; O.Reg R.XMM0 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Implicit operand from the manual (2)``() =
    "660f3815c1"
    ++ BLENDVPD ** [ O.Reg R.XMM0; O.Reg R.XMM1; O.Reg R.XMM0 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Implicit operand from the manual (3)``() =
    "0f38cbc1"
    ++ SHA256RNDS2 ** [ O.Reg R.XMM0; O.Reg R.XMM1; O.Reg R.XMM0 ]
    ||> testX64NoPrefixNoSeg

  (* Two implicit registers rather than one, and both general-purpose. *)
  [<TestMethod>]
  member _.``Implicit operand from the manual (4)``() =
    "660faef1"
    ++ TPAUSE ** [ O.Reg R.ECX; O.Reg R.EDX; O.Reg R.EAX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Group entry pinned to a register form (1)``() =
    "f30faef1"
    ++ UMONITOR ** [ O.Reg R.RCX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Register-only ModRM form (1)``() =
    "0f12ca"
    ++ MOVHLPS ** [ O.Reg R.XMM1; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Memory-only ModRM form (1)``() =
    "0f1208"
    ++ MOVLPS ** [ O.Reg R.XMM1; O.Mem(R.RAX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Register-only ModRM form (2)``() =
    "0f16ca"
    ++ MOVLHPS ** [ O.Reg R.XMM1; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Memory-only ModRM form (2)``() =
    "0f1608"
    ++ MOVHPS ** [ O.Reg R.XMM1; O.Mem(R.RAX, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Register-only ModRM form, VEX (1)``() =
    "c5e812cb"
    ++ VMOVHLPS ** [ O.Reg R.XMM1; O.Reg R.XMM2; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  (* The 256-bit half of the vector length pair below: this is the length the
     manual gives VEXTRACTF128, and the only one it decodes at. *)
  [<TestMethod>]
  member _.``Register-only ModRM form, VEX (2)``() =
    "c4e37d19c100"
    ++ VEXTRACTF128 ** [ O.Reg R.XMM1; O.Reg R.YMM0; O.Imm(0L, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``GPR operand from VEX.vvvv (1)``() =
    "c4e270f2c2"
    ++ ANDN ** [ O.Reg R.EAX; O.Reg R.ECX; O.Reg R.EDX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``GPR operand from VEX.vvvv (2)``() =
    "c4e268f5c1"
    ++ BZHI ** [ O.Reg R.EAX; O.Reg R.ECX; O.Reg R.EDX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``GPR operand from VEX.vvvv (3)``() =
    "c4e273f6c2"
    ++ MULX ** [ O.Reg R.EAX; O.Reg R.ECX; O.Reg R.EDX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``GPR operand from VEX.vvvv (4)``() =
    "c4e2e9f7c1"
    ++ SHLX ** [ O.Reg R.RAX; O.Reg R.RCX; O.Reg R.RDX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Opcode E3 outside the one-byte map (1)``() =
    "0fe3c1"
    ++ PAVGW ** [ O.Reg R.MM0; O.Reg R.MM1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Opcode E3 outside the one-byte map (2)``() =
    "c5f1e3c2"
    ++ VPAVGW ** [ O.Reg R.XMM0; O.Reg R.XMM1; O.Reg R.XMM2 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Opcode E3 outside the one-byte map (3)``() =
    "c4e269e308"
    ++ CMPNBXADD **
      [ O.Mem(R.RAX, 32<rt>); O.Reg R.ECX; O.Reg R.EDX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``JCXZ family still selected by address size (1)``() =
    "e300"
    ++ JRCXZ ** [ OprDirAddr(Relative 2L) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Sole 16-bit variant needs no 66h (1)``() =
    "0f00c2"
    ++ SLDT ** [ O.Reg R.DX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Sole 16-bit variant needs no 66h (2)``() =
    "0f00e2"
    ++ VERR ** [ O.Reg R.DX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Sole 16-bit variant needs no 66h (3)``() =
    "0f01f2"
    ++ LMSW ** [ O.Reg R.DX ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Sole 16-bit variant needs no 66h (4)``() =
    "c5f89108"
    ++ KMOVW ** [ O.Mem(R.RAX, 16<rt>); O.Reg R.K1 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Widest 16-bit variant still needs 66h (1)``() =
    "6601ca"
    ++ ADD ** [ O.Reg R.DX; O.Reg R.CX ]
    ||> testX86Prefix Prefix.OPSIZE

  [<TestMethod>]
  member _.``Widest 16-bit variant still needs 66h (2)``() =
    "01ca"
    ++ ADD ** [ O.Reg R.EDX; O.Reg R.ECX ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``Far pointer in memory (1)``() =
    "ff18"
    ++ CALL ** [ O.Mem(R.RAX, 48<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Far pointer in memory (2)``() =
    "ff28"
    ++ JMP ** [ O.Mem(R.RAX, 48<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Far pointer in memory (3)``() =
    "48ff18"
    ++ CALL ** [ O.Mem(R.RAX, 80<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Far pointer in memory (4)``() =
    "66ff2e"
    ++ JMP ** [ O.Mem(R.ESI, 32<rt>) ]
    ||> testX86Prefix Prefix.OPSIZE

  [<TestMethod>]
  member _.``Far pointer as an immediate (1)``() =
    "9a123456789000"
    ++ CALL ** [ O.Addr(0x90s, 0x78563412UL, 32<rt>) ]
    ||> testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``Far pointer as an immediate (2)``() =
    "669a12349000"
    ++ CALL ** [ O.Addr(0x90s, 0x3412UL, 16<rt>) ]
    ||> testX86Prefix Prefix.OPSIZE

  [<TestMethod>]
  member _.``EVEX static rounding, L'L is the mode (1)``() =
    "62f1ed1858cb"
    ++ VADDPD ** [ O.Reg R.ZMM1; O.Reg R.ZMM2; O.Reg R.ZMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX static rounding, L'L is the mode (2)``() =
    "62f1ed7858cb"
    ++ VADDPD ** [ O.Reg R.ZMM1; O.Reg R.ZMM2; O.Reg R.ZMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX static rounding, L'L is the mode (3)``() =
    "62f1ed5858cb"
    ++ VADDPD ** [ O.Reg R.ZMM1; O.Reg R.ZMM2; O.Reg R.ZMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX static rounding on a scalar form (1)``() =
    "62f1ef1858cb"
    ++ VADDSD ** [ O.Reg R.XMM1; O.Reg R.XMM2; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX vector length without rounding (1)``() =
    "62f1ed0858cb"
    ++ VADDPD ** [ O.Reg R.XMM1; O.Reg R.XMM2; O.Reg R.XMM3 ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``EVEX sae leaves the vector length alone (1)``() =
    "62f1ed58c2cb00"
    ++ VCMPPD **
      [ O.Reg R.K1; O.Reg R.ZMM2; O.Reg R.ZMM3; O.Imm(0L, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``FP16 scalar tuple scales disp8 by two (1)``() =
    "62f36e09c2480200"
    ++ VCMPSH **
      [ O.Reg R.K1
        O.Reg R.XMM2
        O.Mem(R.RAX, 4L, 16<rt>)
        O.Imm(0L, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``FP16 broadcast element is 16 bits (1)``() =
    "62f36c59c2480200"
    ++ VCMPPH **
      [ O.Reg R.K1
        O.Reg R.ZMM2
        O.Mem(R.RAX, 4L, 16<rt>)
        O.Imm(0L, 8<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Broadcast element size from the table (1)``() =
    "62f16c58584802"
    ++ VADDPS **
      [ O.Reg R.ZMM1; O.Reg R.ZMM2; O.Mem(R.RAX, 8L, 32<rt>) ]
    ||> testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Broadcast element size from the table (2)``() =
    "62f1ed58584802"
    ++ VADDPD **
      [ O.Reg R.ZMM1; O.Reg R.ZMM2; O.Mem(R.RAX, 16L, 64<rt>) ]
    ||> testX64NoPrefixNoSeg

#if !EMULATION
  [<TestMethod>]
  member _.``Size cond ParsingFailure Test (1)``() =
    "37"
    ++ AAA ** []
    ||> testException testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Size cond ParsingFailure Test (2)``() =
    "3F"
    ++ AAS ** []
    ||> testException testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Size cond ParsingFailure Test (3)``() =
    "ea123456789000"
    ++ JMP ** [ O.Addr(0x90s, 0x78563412UL, 32<rt>) ]
    ||> testException testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Size cond ParsingFailure Test (4)``() =
    "9a987654321000"
    ++ CALL ** [ O.Addr(0x10s, 0x32547698UL, 32<rt>) ]
    ||> testException testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Size cond ParsingFailure Test (5)``() =
    "c40f"
    ++ LES ** [ O.Reg R.ECX; O.Mem(R.EDI, 48<rt>) ]
    ||> testException testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Size cond ParsingFailure Test (6)``() =
    "c511"
    ++ LDS ** [ O.Reg R.EDX; O.Mem(R.ECX, 48<rt>) ]
    ||> testException testX64NoPrefixNoSeg

  (* The control and debug register moves select their register with the
     ModRM.reg field, and the indices the manual reserves name no register at
     all: a processor raises #UD for them. The exception is DR4 and DR5, which
     alias DR6 and DR7 and so do decode. *)
  [<TestMethod>]
  member _.``Reserved register ParsingFailure Test (1)``() = (* CR1 *)
    "0f20c9"
    ++ MOV ** [ O.Reg R.ECX; O.Reg R.CR0 ]
    ||> testException testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``Reserved register ParsingFailure Test (2)``() = (* CR5 *)
    "0f20e9"
    ++ MOV ** [ O.Reg R.ECX; O.Reg R.CR0 ]
    ||> testException testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``Reserved register ParsingFailure Test (3)``() = (* CR7 *)
    "0f22f9"
    ++ MOV ** [ O.Reg R.CR0; O.Reg R.ECX ]
    ||> testException testX86NoPrefixNoSeg

  [<TestMethod>]
  member _.``Reserved register ParsingFailure Test (4)``() = (* DR8 *)
    "440f21c1"
    ++ MOV ** [ O.Reg R.RCX; O.Reg R.DR0 ]
    ||> testException testX64NoPrefixNoSeg

  (* An instruction the manual gives one vector length raises #UD at any other,
     which VEX.L or EVEX.L'L selects (Vol. 2A Table 2-17). The table records
     that length per entry, so the check reaches every such instruction rather
     than the handful a list would name; these pin both directions of it. *)
  [<TestMethod>]
  member _.``Vector length ParsingFailure Test (1)``() = (* VMOVHLPS, L=1 *)
    "c5fc12c1"
    ++ VMOVHLPS ** [ O.Reg R.XMM0; O.Reg R.XMM0; O.Reg R.XMM1 ]
    ||> testException testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Vector length ParsingFailure Test (2)``() = (* VMOVLPD, L=1 *)
    "c5fd1201"
    ++ VMOVLPD ** [ O.Reg R.XMM0; O.Reg R.XMM0; O.Mem(R.RCX, 64<rt>) ]
    ||> testException testX64NoPrefixNoSeg

  [<TestMethod>]
  member _.``Vector length ParsingFailure Test (3)``() = (* VDPPD, L=1 *)
    "c4e37541c200"
    ++ VDPPD ** [ O.Reg R.XMM0; O.Reg R.XMM1; O.Reg R.XMM2; O.Imm(0L, 8<rt>) ]
    ||> testException testX64NoPrefixNoSeg

  (* The other direction: VEXTRACTF128 exists only at 256 bits, so VEX.L=0
     names nothing. No list ever covered this one. *)
  [<TestMethod>]
  member _.``Vector length ParsingFailure Test (4)``() =
    "c4e37919c100"
    ++ VEXTRACTF128 ** [ O.Reg R.XMM1; O.Reg R.YMM0; O.Imm(0L, 8<rt>) ]
    ||> testException testX64NoPrefixNoSeg
#endif

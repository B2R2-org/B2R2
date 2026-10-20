(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.FrontEnd.PPC.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PPC
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private Shortcut =
  type O =
    static member Reg(reg) = OprReg reg

    static member Mem(disp, reg) = OprMem(disp, reg)

    static member Imm(imm) = OprImm imm

    static member Addr(addr) = OprAddr addr

    static member BI(bi) = OprBI bi

  let test (isa: ISA) opcode (opr: Operands) bytes =
    let reader = BinReader.Init isa.Endian
    let parser = Parser(isa.WordSize, reader) :> IInstructionParsable
    let span = System.ReadOnlySpan(bytes: byte[])
    let ins = parser.Parse(span, 0UL) :?> Instruction
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<Operands>(opr, ins.Operands)

  let testPPC wordSz bytes (opcode, operands) =
    let isa = ISA(Architecture.PPC, Endian.Big, wordSz)
    test isa opcode operands bytes

  /// The 64-bit-only forms must stay unrecognized on a 32-bit guest, whose
  /// architecture does not define them.
  let testUnsupported wordSz (byteString: string) =
    let isa = ISA(Architecture.PPC, Endian.Big, wordSz)
    let reader = BinReader.Init isa.Endian
    let parser = Parser(isa.WordSize, reader) :> IInstructionParsable
    let bytes = ByteArray.ofHexString byteString
    Assert.Throws<ParsingFailureException>(fun () ->
      parser.Parse(System.ReadOnlySpan(bytes: byte[]), 0UL) |> ignore)
    |> ignore

  /// A word read the same way on every processor: 32-bit and 64-bit
  /// big-endian, and 64-bit little-endian, which keeps the word's bytes the
  /// other way round in memory.
  let testEveryTarget (bytes: byte[]) (opcode, operands) =
    for wordSz, endian in
      [ WordSize.Bit32, Endian.Big
        WordSize.Bit64, Endian.Big
        WordSize.Bit64, Endian.Little ] do
      let isa = ISA(Architecture.PPC, endian, wordSz)
      let inMemory = if endian = Endian.Big then bytes else Array.rev bytes
      test isa opcode operands inMemory

  /// A form only a 64-bit processor has, read on both of them and refused on
  /// a 32-bit one.
  let test64Only (bytes: byte[]) (opcode, operands) =
    let big = ISA(Architecture.PPC, Endian.Big, WordSize.Bit64)
    let little = ISA(Architecture.PPC, Endian.Little, WordSize.Bit64)
    test big opcode operands bytes
    test little opcode operands (Array.rev bytes)
    testUnsupported WordSize.Bit32 (ByteArray.toHexString bytes)

  let operandsFromArray oprList =
    let oprArr = Array.ofList oprList
    match oprArr.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArr[0]
    | 2 -> TwoOperands(oprArr[0], oprArr[1])
    | 3 -> ThreeOperands(oprArr[0], oprArr[1], oprArr[2])
    | 4 -> FourOperands(oprArr[0], oprArr[1], oprArr[2], oprArr[3])
    | _ -> Terminator.futureFeature ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

[<TestClass>]
type ParserTests() =
  [<TestMethod>]
  member _.``[PPC32] ADD (register)``() =
    "7c642a14"
    ++ (ADD ** [ O.Reg R3; O.Reg R4; O.Reg R5 ])
    ||> testPPC WordSize.Bit32

  [<TestMethod>]
  member _.``[PPC32] ADDI (immediate)``() =
    "38640008"
    ++ (ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0x8UL ])
    ||> testPPC WordSize.Bit32

  [<TestMethod>]
  member _.``[PPC32] LWZ (load word and zero)``() =
    "80640008"
    ++ (LWZ ** [ O.Reg R3; O.Mem(8, R4) ])
    ||> testPPC WordSize.Bit32

  [<TestMethod>]
  member _.``[PPC32] MR (move register)``() =
    "7c832378"
    ++ (MR ** [ O.Reg R3; O.Reg R4 ])
    ||> testPPC WordSize.Bit32

  [<TestMethod>]
  member _.``[PPC32] BCLR (branch to LR)``() =
    "4e800020"
    ++ (BCLR ** [ O.Imm 0x14UL; O.BI 0u ])
    ||> testPPC WordSize.Bit32

  [<TestMethod>]
  member _.``[PPC64] LD (load doubleword)``() =
    "e8830008"
    ++ (LD ** [ O.Reg R4; O.Mem(8, R3) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] STDU (store doubleword with update)``() =
    "f821ff91"
    ++ (STDU ** [ O.Reg R1; O.Mem(-112, R1) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] RLDICL (rotate left doubleword and clear left)``() =
    "78840022"
    ++ (RLDICL ** [ O.Reg R4; O.Reg R4; O.Imm 0x20UL; O.Imm 0x20UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] SRADI (shift right algebraic doubleword immediate)``() =
    "7c841e74"
    ++ (SRADI ** [ O.Reg R4; O.Reg R4; O.Imm 0x3UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] CMPDI (compare doubleword immediate)``() =
    "2c230000"
    ++ (CMPDI ** [ O.Reg CR0; O.Reg R3; O.Imm 0x0UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] EXTSW (extend sign word)``() =
    "7c8407b4"
    ++ (EXTSW ** [ O.Reg R4; O.Reg R4 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] STXVD2X (store VSX vector doubleword pair)``() =
    "7c004f98"
    ++ (STXVD2X ** [ O.Reg F0; O.Reg R0; O.Reg R9 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] VXOR (vector logical xor)``() =
    "100004c4"
    ++ (VXOR ** [ O.Reg V0A; O.Reg V0A; O.Reg V0A ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] LD is not a 32-bit form``() =
    testUnsupported WordSize.Bit32 "e8830008"

  [<TestMethod>]
  member _.``[PPC] VPKUHUS (Pack Unsigned Halfword Unsigned Saturate)``() =
    "1022188e"
    ++ (VPKUHUS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKUWUS (Vector Pack Unsigned Word Unsigned Saturate)``() =
    "102218ce"
    ++ (VPKUWUS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKSHSS (Vector Pack Signed Halfword Signed Saturate)``() =
    "1022198e"
    ++ (VPKSHSS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKSWSS (Vector Pack Signed Word Signed Saturate)``() =
    "102219ce"
    ++ (VPKSWSS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKSHUS (Vector Pack Signed Halfword Unsigned Saturate)``() =
    "1022190e"
    ++ (VPKSHUS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKSWUS (Vector Pack Signed Word Unsigned Saturate)``() =
    "1022194e"
    ++ (VPKSWUS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKPX (Vector Pack Pixel)``() =
    "10221b0e"
    ++ (VPKPX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VUPKHPX (Vector Unpack High Pixel)``() =
    "10201b4e"
    ++ (VUPKHPX ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VUPKLPX (Vector Unpack Low Pixel)``() =
    "10201bce"
    ++ (VUPKLPX ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMHADDSHS (Multiply-High-Add Signed Halfword Saturate)``() =
    "10221920"
    ++ (VMHADDSHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMHRADDSHS (Multiply-High-Round-Add Signed Halfword)``() =
    "10221921"
    ++ (VMHRADDSHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMLADDUHM (Multiply-Low-Add Unsigned Halfword Modulo)``() =
    "10221922"
    ++ (VMLADDUHM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMSUMUBM (Vector Multiply-Sum Unsigned Byte Modulo)``() =
    "10221924"
    ++ (VMSUMUBM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMSUMMBM (Vector Multiply-Sum Mixed Byte Modulo)``() =
    "10221925"
    ++ (VMSUMMBM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMSUMUHM (Vector Multiply-Sum Unsigned Halfword Modulo)``() =
    "10221926"
    ++ (VMSUMUHM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMSUMUHS (Multiply-Sum Unsigned Halfword Saturate)``() =
    "10221927"
    ++ (VMSUMUHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMSUMSHM (Vector Multiply-Sum Signed Halfword Modulo)``() =
    "10221928"
    ++ (VMSUMSHM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMSUMSHS (Vector Multiply-Sum Signed Halfword Saturate)``() =
    "10221929"
    ++ (VMSUMSHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMSUMUDM (Multiply-Sum Unsigned Doubleword Modulo)``() =
    "10221923"
    ++ (VMSUMUDM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMSUMCUD (Multiply-Sum & write Carry-out Unsigned)``() =
    "10221917"
    ++ (VMSUMCUD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKUDUM (Pack Unsigned Doubleword Unsigned Modulo)``() =
    "10221c4e"
    ++ (VPKUDUM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKSDSS (Vector Pack Signed Doubleword Signed Saturate)``() =
    "10221dce"
    ++ (VPKSDSS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKSDUS (Pack Signed Doubleword Unsigned Saturate)``() =
    "10221d4e"
    ++ (VPKSDUS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPKUDUS (Pack Unsigned Doubleword Unsigned Saturate)``() =
    "10221cce"
    ++ (VPKUDUS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULEUB (Vector Multiply Even Unsigned Byte)``() =
    "10221a08"
    ++ (VMULEUB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULOUB (Vector Multiply Odd Unsigned Byte)``() =
    "10221808"
    ++ (VMULOUB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULESB (Vector Multiply Even Signed Byte)``() =
    "10221b08"
    ++ (VMULESB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULOSB (Vector Multiply Odd Signed Byte)``() =
    "10221908"
    ++ (VMULOSB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULEUH (Vector Multiply Even Unsigned Halfword)``() =
    "10221a48"
    ++ (VMULEUH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULOUH (Vector Multiply Odd Unsigned Halfword)``() =
    "10221848"
    ++ (VMULOUH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULESH (Vector Multiply Even Signed Halfword)``() =
    "10221b48"
    ++ (VMULESH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULOSH (Vector Multiply Odd Signed Halfword)``() =
    "10221948"
    ++ (VMULOSH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULEUW (Vector Multiply Even Unsigned Word)``() =
    "10221a88"
    ++ (VMULEUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULOUW (Vector Multiply Odd Unsigned Word)``() =
    "10221888"
    ++ (VMULOUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULEUD (Vector Multiply Even Unsigned Doubleword)``() =
    "10221ac8"
    ++ (VMULEUD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULOUD (Vector Multiply Odd Unsigned Doubleword)``() =
    "102218c8"
    ++ (VMULOUD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULESD (Vector Multiply Even Signed Doubleword)``() =
    "10221bc8"
    ++ (VMULESD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULOSD (Vector Multiply Odd Signed Doubleword)``() =
    "102219c8"
    ++ (VMULOSD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDUQM (Vector Add Unsigned Quadword Modulo)``() =
    "10221900"
    ++ (VADDUQM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDCUQ (Vector Add & write Carry Unsigned Quadword)``() =
    "10221940"
    ++ (VADDCUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDEUQM (Vector Add Extended Unsigned Quadword Modulo)``() =
    "1022193c"
    ++ (VADDEUQM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDECUQ (Add Extended & write Carry Unsigned Quadword)``() =
    "1022193d"
    ++ (VADDECUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBUQM (Vector Subtract Unsigned Quadword Modulo)``() =
    "10221d00"
    ++ (VSUBUQM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBCUQ (Subtract & write Carry-out Unsigned Quadword)``() =
    "10221d40"
    ++ (VSUBCUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBEUQM (Subtract Extended Unsigned Quadword Modulo)``() =
    "1022193e"
    ++ (VSUBEUQM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBECUQ (Subtract Extended & write Carry-out Unsigned)``() =
    "1022193f"
    ++ (VSUBECUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCIPHER (Vector AES Cipher)``() =
    "10221d08"
    ++ (VCIPHER ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCIPHERLAST (Vector AES Cipher Last)``() =
    "10221d09"
    ++ (VCIPHERLAST ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VNCIPHER (Vector AES Inverse Cipher)``() =
    "10221d48"
    ++ (VNCIPHER ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VNCIPHERLAST (Vector AES Inverse Cipher Last)``() =
    "10221d49"
    ++ (VNCIPHERLAST ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSBOX (Vector AES SubBytes)``() =
    "102205c8"
    ++ (VSBOX ** [ O.Reg V1A; O.Reg V2A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSHASIGMAW (Vector SHA-256 Sigma Word)``() =
    "10220682"
    ++ (VSHASIGMAW ** [ O.Reg V1A; O.Reg V2A; O.Imm 0x0UL; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSHASIGMAD (Vector SHA-512 Sigma Doubleword)``() =
    "102206c2"
    ++ (VSHASIGMAD ** [ O.Reg V1A; O.Reg V2A; O.Imm 0x0UL; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPMSUMB (Vector Polynomial Multiply-Sum Byte)``() =
    "10221c08"
    ++ (VPMSUMB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPMSUMH (Vector Polynomial Multiply-Sum Halfword)``() =
    "10221c48"
    ++ (VPMSUMH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPMSUMW (Vector Polynomial Multiply-Sum Word)``() =
    "10221c88"
    ++ (VPMSUMW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPMSUMD (Vector Polynomial Multiply-Sum Doubleword)``() =
    "10221cc8"
    ++ (VPMSUMD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPERMXOR (Vector Permute & Exclusive-OR)``() =
    "1022192d"
    ++ (VPERMXOR ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDADDdot (Decimal Add Modulo)``() =
    "10221c01"
    ++ (BCDADDdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDSUBdot (Decimal Subtract Modulo)``() =
    "10221c41"
    ++ (BCDSUBdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDSBS (Vector Add Signed Byte Saturate)``() =
    "10221b00"
    ++ (VADDSBS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDSHS (Vector Add Signed Halfword Saturate)``() =
    "10221b40"
    ++ (VADDSHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDSWS (Vector Add Signed Word Saturate)``() =
    "10221b80"
    ++ (VADDSWS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDUHS (Vector Add Unsigned Halfword Saturate)``() =
    "10221a40"
    ++ (VADDUHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDUWS (Vector Add Unsigned Word Saturate)``() =
    "10221a80"
    ++ (VADDUWS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBSBS (Vector Subtract Signed Byte Saturate)``() =
    "10221f00"
    ++ (VSUBSBS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBSHS (Vector Subtract Signed Halfword Saturate)``() =
    "10221f40"
    ++ (VSUBSHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBSWS (Vector Subtract Signed Word Saturate)``() =
    "10221f80"
    ++ (VSUBSWS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBUHS (Vector Subtract Unsigned Halfword Saturate)``() =
    "10221e40"
    ++ (VSUBUHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBUWS (Vector Subtract Unsigned Word Saturate)``() =
    "10221e80"
    ++ (VSUBUWS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDCUW (Vector Add & write Carry Unsigned Word)``() =
    "10221980"
    ++ (VADDCUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBCUW (Subtract & Write Carry-out Unsigned Word)``() =
    "10221d80"
    ++ (VSUBCUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VAVGSB (Vector Average Signed Byte)``() =
    "10221d02"
    ++ (VAVGSB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VAVGSH (Vector Average Signed Halfword)``() =
    "10221d42"
    ++ (VAVGSH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VAVGSW (Vector Average Signed Word)``() =
    "10221d82"
    ++ (VAVGSW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VAVGUB (Vector Average Unsigned Byte)``() =
    "10221c02"
    ++ (VAVGUB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VAVGUH (Vector Average Unsigned Halfword)``() =
    "10221c42"
    ++ (VAVGUH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VAVGUW (Vector Average Unsigned Word)``() =
    "10221c82"
    ++ (VAVGUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VABSDUB (Vector Absolute Difference Unsigned Byte)``() =
    "10221c03"
    ++ (VABSDUB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VABSDUH (Vector Absolute Difference Unsigned Halfword)``() =
    "10221c43"
    ++ (VABSDUH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VABSDUW (Vector Absolute Difference Unsigned Word)``() =
    "10221c83"
    ++ (VABSDUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPEQUQ (Vector Compare Equal Quadword)``() =
    "102219c7"
    ++ (VCMPEQUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPEQUQdot (Vector Compare Equal Quadword)``() =
    "10221dc7"
    ++ (VCMPEQUQdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPGTUQ (Compare Greater Than Unsigned Quadword)``() =
    "10221a87"
    ++ (VCMPGTUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPGTUQdot (Compare Greater Than Unsigned Quadword)``() =
    "10221e87"
    ++ (VCMPGTUQdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPGTSQ (Vector Compare Greater Than Signed Quadword)``() =
    "10221b87"
    ++ (VCMPGTSQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPGTSQdot (Compare Greater Than Signed Quadword)``() =
    "10221f87"
    ++ (VCMPGTSQdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPSQ (Vector Compare Signed Quadword)``() =
    "11021941"
    ++ (VCMPSQ ** [ O.Reg CR2; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPUQ (Vector Compare Unsigned Quadword)``() =
    "11021901"
    ++ (VCMPUQ ** [ O.Reg CR2; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEB (Vector Compare Not Equal Byte)``() =
    "10221807"
    ++ (VCMPNEB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEBdot (Vector Compare Not Equal Byte)``() =
    "10221c07"
    ++ (VCMPNEBdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEH (Vector Compare Not Equal Halfword)``() =
    "10221847"
    ++ (VCMPNEH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEHdot (Vector Compare Not Equal Halfword)``() =
    "10221c47"
    ++ (VCMPNEHdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEW (Vector Compare Not Equal Word)``() =
    "10221887"
    ++ (VCMPNEW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEWdot (Vector Compare Not Equal Word)``() =
    "10221c87"
    ++ (VCMPNEWdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEZB (Vector Compare Not Equal or Zero Byte)``() =
    "10221907"
    ++ (VCMPNEZB ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEZBdot (Vector Compare Not Equal or Zero Byte)``() =
    "10221d07"
    ++ (VCMPNEZBdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEZH (Vector Compare Not Equal or Zero Halfword)``() =
    "10221947"
    ++ (VCMPNEZH ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEZHdot (Vector Compare Not Equal or Zero Halfword)``() =
    "10221d47"
    ++ (VCMPNEZHdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEZW (Vector Compare Not Equal or Zero Word)``() =
    "10221987"
    ++ (VCMPNEZW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPNEZWdot (Vector Compare Not Equal or Zero Word)``() =
    "10221d87"
    ++ (VCMPNEZWdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULHSW (Vector Multiply High Signed Word)``() =
    "10221b89"
    ++ (VMULHSW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULHUW (Vector Multiply High Unsigned Word)``() =
    "10221a89"
    ++ (VMULHUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULHSD (Vector Multiply High Signed Doubleword)``() =
    "10221bc9"
    ++ (VMULHSD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULHUD (Vector Multiply High Unsigned Doubleword)``() =
    "10221ac9"
    ++ (VMULHUD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMULLD (Vector Multiply Low Doubleword)``() =
    "102219c9"
    ++ (VMULLD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MADDHD (Multiply-Add High Doubleword)``() =
    "10a63a70"
    ++ (MADDHD ** [ O.Reg R5; O.Reg R6; O.Reg R7; O.Reg R9 ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] MADDHDU (Multiply-Add High Doubleword Unsigned)``() =
    "10a63a71"
    ++ (MADDHDU ** [ O.Reg R5; O.Reg R6; O.Reg R7; O.Reg R9 ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] MADDLD (Multiply-Add Low Doubleword)``() =
    "10a63a73"
    ++ (MADDLD ** [ O.Reg R5; O.Reg R6; O.Reg R7; O.Reg R9 ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VDIVSW (Vector Divide Signed Word)``() =
    "1022198b"
    ++ (VDIVSW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVUW (Vector Divide Unsigned Word)``() =
    "1022188b"
    ++ (VDIVUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVSD (Vector Divide Signed Doubleword)``() =
    "102219cb"
    ++ (VDIVSD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVUD (Vector Divide Unsigned Doubleword)``() =
    "102218cb"
    ++ (VDIVUD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVSQ (Vector Divide Signed Quadword)``() =
    "1022190b"
    ++ (VDIVSQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVUQ (Vector Divide Unsigned Quadword)``() =
    "1022180b"
    ++ (VDIVUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVESW (Vector Divide Extended Signed Word)``() =
    "10221b8b"
    ++ (VDIVESW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVEUW (Vector Divide Extended Unsigned Word)``() =
    "10221a8b"
    ++ (VDIVEUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVESD (Vector Divide Extended Signed Doubleword)``() =
    "10221bcb"
    ++ (VDIVESD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVEUD (Vector Divide Extended Unsigned Doubleword)``() =
    "10221acb"
    ++ (VDIVEUD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVESQ (Vector Divide Extended Signed Quadword)``() =
    "10221b0b"
    ++ (VDIVESQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VDIVEUQ (Vector Divide Extended Unsigned Quadword)``() =
    "10221a0b"
    ++ (VDIVEUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMODSW (Vector Modulo Signed Word)``() =
    "10221f8b"
    ++ (VMODSW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMODUW (Vector Modulo Unsigned Word)``() =
    "10221e8b"
    ++ (VMODUW ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMODSD (Vector Modulo Signed Doubleword)``() =
    "10221fcb"
    ++ (VMODSD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMODUD (Vector Modulo Unsigned Doubleword)``() =
    "10221ecb"
    ++ (VMODUD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMODSQ (Vector Modulo Signed Quadword)``() =
    "10221f0b"
    ++ (VMODSQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMODUQ (Vector Modulo Unsigned Quadword)``() =
    "10221e0b"
    ++ (VMODUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUM4UBS (Sum across Quarter Unsigned Byte Saturate)``() =
    "10221e08"
    ++ (VSUM4UBS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUM4SBS (Sum across Quarter Signed Byte Saturate)``() =
    "10221f08"
    ++ (VSUM4SBS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUM4SHS (Sum across Quarter Signed Halfword Saturate)``() =
    "10221e48"
    ++ (VSUM4SHS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUM2SWS (Vector Sum across Half Signed Word Saturate)``() =
    "10221e88"
    ++ (VSUM2SWS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUMSWS (Vector Sum across Signed Word Saturate)``() =
    "10221f88"
    ++ (VSUMSWS ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

/// What lane F's tests check a word against: one decode per target, from the
/// bytes as that target holds them.
[<AutoOpen>]
module private FloatShortcut =
  /// Asserts what a word decodes to on 32-bit and 64-bit big-endian PowerPC,
  /// from the bytes the big-endian words file holds, and on 64-bit
  /// little-endian PowerPC, from the bytes the little-endian one holds.
  let testAll (be: string) (le: string) (opcode, operands) =
    let bigBytes = ByteArray.ofHexString be
    let littleBytes = ByteArray.ofHexString le
    let ppc32 = ISA(Architecture.PPC, Endian.Big, WordSize.Bit32)
    let ppc64 = ISA(Architecture.PPC, Endian.Big, WordSize.Bit64)
    let ppc64le = ISA(Architecture.PPC, Endian.Little, WordSize.Bit64)
    test ppc32 opcode operands bigBytes
    test ppc64 opcode operands bigBytes
    test ppc64le opcode operands littleBytes

/// The binary floating-point instructions added after the first PowerPC, and
/// the floating-point register pair accesses: each word is the one the words
/// files hold, decoded on every target the manual defines it for.
[<TestClass>]
type FloatParserTests() =
  [<TestMethod>]
  member _.``[PPC] FCPSGN. (copy sign, record)``() =
    FCPSGNdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ]
    |> testAll "fc221811" "111822fc"

  [<TestMethod>]
  member _.``[PPC] FMRGEW (merge even word)``() =
    FMRGEW ** [ O.Reg F1; O.Reg F2; O.Reg F3 ]
    |> testAll "fc221f8c" "8c1f22fc"

  [<TestMethod>]
  member _.``[PPC] FMRGOW (merge odd word)``() =
    FMRGOW ** [ O.Reg F1; O.Reg F2; O.Reg F3 ]
    |> testAll "fc221e8c" "8c1e22fc"

  [<TestMethod>]
  member _.``[PPC] FRE (reciprocal estimate)``() =
    FRE ** [ O.Reg F1; O.Reg F3 ] |> testAll "fc201830" "301820fc"

  [<TestMethod>]
  member _.``[PPC] FRE. (reciprocal estimate, record)``() =
    FREdot ** [ O.Reg F1; O.Reg F3 ] |> testAll "fc201831" "311820fc"

  /// <summary>
  /// frsqrte. reserves frA and frC as frsqrte does; frB is a register like
  /// any other, which an earlier reading required to be f0.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] FRSQRTE. (reciprocal square root estimate, record)``() =
    FRSQRTEdot ** [ O.Reg F1; O.Reg F3 ] |> testAll "fc201835" "351820fc"

  [<TestMethod>]
  member _.``[PPC] FRSQRTES (reciprocal square root estimate single)``() =
    FRSQRTES ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201834" "341820ec"

  [<TestMethod>]
  member _.``[PPC] FRSQRTES. (estimate single, record)``() =
    FRSQRTESdot ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201835" "351820ec"

  [<TestMethod>]
  member _.``[PPC] FTDIV (test for software divide)``() =
    FTDIV ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ]
    |> testAll "fd021900" "001902fd"

  [<TestMethod>]
  member _.``[PPC] FTSQRT (test for software square root)``() =
    FTSQRT ** [ O.Reg CR2; O.Reg F3 ] |> testAll "fd001940" "401900fd"

  [<TestMethod>]
  member _.``[PPC] LFDP (load double pair)``() =
    LFDP ** [ O.Reg F2; O.Mem(8, R6) ] |> testAll "e4460008" "080046e4"

  [<TestMethod>]
  member _.``[PPC] LFDPX (load double pair indexed)``() =
    LFDPX ** [ O.Reg F2; O.Reg R6; O.Reg R7 ]
    |> testAll "7c463e2e" "2e3e467c"

  [<TestMethod>]
  member _.``[PPC] STFDP (store double pair)``() =
    STFDP ** [ O.Reg F2; O.Mem(8, R6) ] |> testAll "f4460008" "080046f4"

  [<TestMethod>]
  member _.``[PPC] STFDPX (store double pair indexed)``() =
    STFDPX ** [ O.Reg F2; O.Reg R6; O.Reg R7 ]
    |> testAll "7c463f2e" "2e3f467c"

  /// <summary>
  /// A register pair is named by its even register: an odd one (lfdp f3 here)
  /// makes the form invalid, on every target.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] LFDP of an odd register is invalid``() =
    testUnsupported WordSize.Bit32 "e4660008"
    testUnsupported WordSize.Bit64 "e4660008"

  [<TestMethod>]
  member _.``[PPC] MFFSCE (move from FPSCR and clear enables)``() =
    MFFSCE ** [ O.Reg F1 ] |> testAll "fc21048e" "8e0421fc"

  [<TestMethod>]
  member _.``[PPC] MFFSCDRN (move from FPSCR control and set DRN)``() =
    MFFSCDRN ** [ O.Reg F1; O.Reg F3 ] |> testAll "fc341c8e" "8e1c34fc"

  [<TestMethod>]
  member _.``[PPC] MFFSCDRNI (move from FPSCR control, set DRN immediate)``() =
    MFFSCDRNI ** [ O.Reg F1; O.Imm 1UL ] |> testAll "fc350c8e" "8e0c35fc"

  /// <summary>
  /// mtfsfi with W = 1 (mtfsfi 7,1,1) writes a field of the FPSCR's high
  /// word; an earlier reading refused it. With W = 0 the extended form is
  /// what prints.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTFSFI with W names the high word``() =
    MTFSFI ** [ O.Imm 7UL; O.Imm 1UL; O.Imm 1UL ]
    |> testAll "ff81110c" "0c1181ff"
    MTFSFIdot ** [ O.Imm 2UL; O.Imm 0UL ] |> testAll "fd00010d" "0d0100fd"

  /// <summary>
  /// mtfsf with L = 1 (mtfsf 255,f3,1,0) writes the whole FPSCR; the L and W
  /// operands print only where one of them is 1.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MTFSF with L writes the whole FPSCR``() =
    MTFSF ** [ O.Imm 0xffUL; O.Reg F3; O.Imm 1UL; O.Imm 0UL ]
    |> testAll "fffe1d8e" "8e1dfeff"
    MTFSF ** [ O.Imm 0xffUL; O.Reg F3 ] |> testAll "fdfe1d8e" "8e1dfefd"

  /// <summary>
  /// mfocrf rD, FXM keeps the field mask, which names the field it reads.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] MFOCRF (move from one condition register field)``() =
    MFOCRF ** [ O.Reg R5; O.Imm 0x20UL ] |> testAll "7cb20026" "2600b27c"

  [<TestMethod>]
  member _.``[PPC] DADD (DFP add)``() =
    DADD ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221804" "041822ec"

  [<TestMethod>]
  member _.``[PPC] DADD. (DFP add, record)``() =
    DADDdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221805" "051822ec"

  [<TestMethod>]
  member _.``[PPC] DADDQ (DFP add quad)``() =
    DADDQ ** [ O.Reg F2; O.Reg F4; O.Reg F6 ] |> testAll "fc443004" "043044fc"

  [<TestMethod>]
  member _.``[PPC] DADDQ. (DFP add quad, record)``() =
    DADDQdot ** [ O.Reg F2; O.Reg F4; O.Reg F6 ]
    |> testAll "fc443005" "053044fc"

  [<TestMethod>]
  member _.``[PPC] DCFFIX (DFP convert from fixed)``() =
    DCFFIX ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201e44" "441e20ec"

  [<TestMethod>]
  member _.``[PPC] DCFFIX. (DFP convert from fixed, record)``() =
    DCFFIXdot ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201e45" "451e20ec"

  [<TestMethod>]
  member _.``[PPC] DCFFIXQ (DFP convert from fixed quad)``() =
    DCFFIXQ ** [ O.Reg F2; O.Reg F3 ] |> testAll "fc401e44" "441e40fc"

  [<TestMethod>]
  member _.``[PPC] DCFFIXQ. (DFP convert from fixed quad, record)``() =
    DCFFIXQdot ** [ O.Reg F2; O.Reg F3 ] |> testAll "fc401e45" "451e40fc"

  [<TestMethod>]
  member _.``[PPC] DCFFIXQQ (DFP convert from fixed quadword quad)``() =
    DCFFIXQQ ** [ O.Reg F2; O.Reg V3A ] |> testAll "fc401fc4" "c41f40fc"

  [<TestMethod>]
  member _.``[PPC] DCMPO (DFP compare ordered)``() =
    DCMPO ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ] |> testAll "ed021904" "041902ed"

  [<TestMethod>]
  member _.``[PPC] DCMPOQ (DFP compare ordered quad)``() =
    DCMPOQ ** [ O.Reg CR2; O.Reg F4; O.Reg F6 ] |> testAll "fd043104" "043104fd"

  [<TestMethod>]
  member _.``[PPC] DCMPU (DFP compare unordered)``() =
    DCMPU ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ] |> testAll "ed021d04" "041d02ed"

  [<TestMethod>]
  member _.``[PPC] DCMPUQ (DFP compare unordered quad)``() =
    DCMPUQ ** [ O.Reg CR2; O.Reg F4; O.Reg F6 ] |> testAll "fd043504" "043504fd"

  [<TestMethod>]
  member _.``[PPC] DCTDP (DFP convert to DFP long)``() =
    DCTDP ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201a04" "041a20ec"

  [<TestMethod>]
  member _.``[PPC] DCTDP. (DFP convert to DFP long, record)``() =
    DCTDPdot ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201a05" "051a20ec"

  [<TestMethod>]
  member _.``[PPC] DCTFIX (DFP convert to fixed)``() =
    DCTFIX ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201a44" "441a20ec"

  [<TestMethod>]
  member _.``[PPC] DCTFIX. (DFP convert to fixed, record)``() =
    DCTFIXdot ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201a45" "451a20ec"

  [<TestMethod>]
  member _.``[PPC] DCTFIXQ (DFP convert to fixed quad)``() =
    DCTFIXQ ** [ O.Reg F1; O.Reg F6 ] |> testAll "fc203244" "443220fc"

  [<TestMethod>]
  member _.``[PPC] DCTFIXQ. (DFP convert to fixed quad, record)``() =
    DCTFIXQdot ** [ O.Reg F1; O.Reg F6 ] |> testAll "fc203245" "453220fc"

  [<TestMethod>]
  member _.``[PPC] DCTFIXQQ (DFP convert to fixed quadword quad)``() =
    DCTFIXQQ ** [ O.Reg V1A; O.Reg F6 ] |> testAll "fc2137c4" "c43721fc"

  [<TestMethod>]
  member _.``[PPC] DCTQPQ (DFP convert to DFP extended)``() =
    DCTQPQ ** [ O.Reg F2; O.Reg F3 ] |> testAll "fc401a04" "041a40fc"

  [<TestMethod>]
  member _.``[PPC] DCTQPQ. (DFP convert to DFP extended, record)``() =
    DCTQPQdot ** [ O.Reg F2; O.Reg F3 ] |> testAll "fc401a05" "051a40fc"

  [<TestMethod>]
  member _.``[PPC] DDEDPD (DFP decode DPD to BCD)``() =
    DDEDPD ** [ O.Imm 0x0UL; O.Reg F1; O.Reg F3 ]
    |> testAll "ec201a84" "841a20ec"

  [<TestMethod>]
  member _.``[PPC] DDEDPD. (DFP decode DPD to BCD, record)``() =
    DDEDPDdot ** [ O.Imm 0x0UL; O.Reg F1; O.Reg F3 ]
    |> testAll "ec201a85" "851a20ec"

  [<TestMethod>]
  member _.``[PPC] DDEDPDQ (DFP decode DPD to BCD quad)``() =
    DDEDPDQ ** [ O.Imm 0x0UL; O.Reg F2; O.Reg F6 ]
    |> testAll "fc403284" "843240fc"

  [<TestMethod>]
  member _.``[PPC] DDEDPDQ. (DFP decode DPD to BCD quad, record)``() =
    DDEDPDQdot ** [ O.Imm 0x0UL; O.Reg F2; O.Reg F6 ]
    |> testAll "fc403285" "853240fc"

  [<TestMethod>]
  member _.``[PPC] DDIV (DFP divide)``() =
    DDIV ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221c44" "441c22ec"

  [<TestMethod>]
  member _.``[PPC] DDIV. (DFP divide, record)``() =
    DDIVdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221c45" "451c22ec"

  [<TestMethod>]
  member _.``[PPC] DDIVQ (DFP divide quad)``() =
    DDIVQ ** [ O.Reg F2; O.Reg F4; O.Reg F6 ] |> testAll "fc443444" "443444fc"

  [<TestMethod>]
  member _.``[PPC] DDIVQ. (DFP divide quad, record)``() =
    DDIVQdot ** [ O.Reg F2; O.Reg F4; O.Reg F6 ]
    |> testAll "fc443445" "453444fc"

  [<TestMethod>]
  member _.``[PPC] DENBCD (DFP encode BCD to DPD)``() =
    DENBCD ** [ O.Imm 0x0UL; O.Reg F1; O.Reg F3 ]
    |> testAll "ec201e84" "841e20ec"

  [<TestMethod>]
  member _.``[PPC] DENBCD. (DFP encode BCD to DPD, record)``() =
    DENBCDdot ** [ O.Imm 0x0UL; O.Reg F1; O.Reg F3 ]
    |> testAll "ec201e85" "851e20ec"

  [<TestMethod>]
  member _.``[PPC] DENBCDQ (DFP encode BCD to DPD quad)``() =
    DENBCDQ ** [ O.Imm 0x0UL; O.Reg F2; O.Reg F6 ]
    |> testAll "fc403684" "843640fc"

  [<TestMethod>]
  member _.``[PPC] DENBCDQ. (DFP encode BCD to DPD quad, record)``() =
    DENBCDQdot ** [ O.Imm 0x0UL; O.Reg F2; O.Reg F6 ]
    |> testAll "fc403685" "853640fc"

  [<TestMethod>]
  member _.``[PPC] DIEX (DFP insert biased exponent)``() =
    DIEX ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221ec4" "c41e22ec"

  [<TestMethod>]
  member _.``[PPC] DIEX. (DFP insert biased exponent, record)``() =
    DIEXdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221ec5" "c51e22ec"

  [<TestMethod>]
  member _.``[PPC] DIEXQ (DFP insert biased exponent quad)``() =
    DIEXQ ** [ O.Reg F2; O.Reg F2; O.Reg F6 ] |> testAll "fc4236c4" "c43642fc"

  [<TestMethod>]
  member _.``[PPC] DIEXQ. (DFP insert biased exponent quad, record)``() =
    DIEXQdot ** [ O.Reg F2; O.Reg F2; O.Reg F6 ]
    |> testAll "fc4236c5" "c53642fc"

  [<TestMethod>]
  member _.``[PPC] DMUL (DFP multiply)``() =
    DMUL ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221844" "441822ec"

  [<TestMethod>]
  member _.``[PPC] DMUL. (DFP multiply, record)``() =
    DMULdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221845" "451822ec"

  [<TestMethod>]
  member _.``[PPC] DMULQ (DFP multiply quad)``() =
    DMULQ ** [ O.Reg F2; O.Reg F4; O.Reg F6 ] |> testAll "fc443044" "443044fc"

  [<TestMethod>]
  member _.``[PPC] DMULQ. (DFP multiply quad, record)``() =
    DMULQdot ** [ O.Reg F2; O.Reg F4; O.Reg F6 ]
    |> testAll "fc443045" "453044fc"

  [<TestMethod>]
  member _.``[PPC] DQUA (DFP quantize)``() =
    DQUA ** [ O.Reg F1; O.Reg F2; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec221a06" "061a22ec"

  [<TestMethod>]
  member _.``[PPC] DQUA. (DFP quantize, record)``() =
    DQUAdot ** [ O.Reg F1; O.Reg F2; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec221a07" "071a22ec"

  [<TestMethod>]
  member _.``[PPC] DQUAI (DFP quantize immediate)``() =
    DQUAI ** [ O.Imm 0x3UL; O.Reg F1; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec231a86" "861a23ec"

  [<TestMethod>]
  member _.``[PPC] DQUAI. (DFP quantize immediate, record)``() =
    DQUAIdot ** [ O.Imm 0x3UL; O.Reg F1; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec231a87" "871a23ec"

  [<TestMethod>]
  member _.``[PPC] DQUAIQ (DFP quantize immediate quad)``() =
    DQUAIQ ** [ O.Imm 0x3UL; O.Reg F2; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc433286" "863243fc"

  [<TestMethod>]
  member _.``[PPC] DQUAIQ. (DFP quantize immediate quad, record)``() =
    DQUAIQdot ** [ O.Imm 0x3UL; O.Reg F2; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc433287" "873243fc"

  [<TestMethod>]
  member _.``[PPC] DQUAQ (DFP quantize quad)``() =
    DQUAQ ** [ O.Reg F2; O.Reg F4; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc443206" "063244fc"

  [<TestMethod>]
  member _.``[PPC] DQUAQ. (DFP quantize quad, record)``() =
    DQUAQdot ** [ O.Reg F2; O.Reg F4; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc443207" "073244fc"

  [<TestMethod>]
  member _.``[PPC] DRDPQ (DFP round to DFP long)``() =
    DRDPQ ** [ O.Reg F2; O.Reg F6 ] |> testAll "fc403604" "043640fc"

  [<TestMethod>]
  member _.``[PPC] DRDPQ. (DFP round to DFP long, record)``() =
    DRDPQdot ** [ O.Reg F2; O.Reg F6 ] |> testAll "fc403605" "053640fc"

  [<TestMethod>]
  member _.``[PPC] DRINTN (DFP round to integer no inexact)``() =
    DRINTN ** [ O.Imm 0x0UL; O.Reg F1; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec201bc6" "c61b20ec"

  [<TestMethod>]
  member _.``[PPC] DRINTN. (DFP round to integer no inexact, record)``() =
    DRINTNdot ** [ O.Imm 0x0UL; O.Reg F1; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec201bc7" "c71b20ec"

  [<TestMethod>]
  member _.``[PPC] DRINTNQ (DFP round to integer no inexact quad)``() =
    DRINTNQ ** [ O.Imm 0x0UL; O.Reg F2; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc4033c6" "c63340fc"

  [<TestMethod>]
  member _.``[PPC] DRINTNQ. (DFP round to integer no inexact quad, record)``() =
    DRINTNQdot ** [ O.Imm 0x0UL; O.Reg F2; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc4033c7" "c73340fc"

  [<TestMethod>]
  member _.``[PPC] DRINTX (DFP round to integer inexact)``() =
    DRINTX ** [ O.Imm 0x0UL; O.Reg F1; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec201ac6" "c61a20ec"

  [<TestMethod>]
  member _.``[PPC] DRINTX. (DFP round to integer inexact, record)``() =
    DRINTXdot ** [ O.Imm 0x0UL; O.Reg F1; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec201ac7" "c71a20ec"

  [<TestMethod>]
  member _.``[PPC] DRINTXQ (DFP round to integer inexact quad)``() =
    DRINTXQ ** [ O.Imm 0x0UL; O.Reg F2; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc4032c6" "c63240fc"

  [<TestMethod>]
  member _.``[PPC] DRINTXQ. (DFP round to integer inexact quad, record)``() =
    DRINTXQdot ** [ O.Imm 0x0UL; O.Reg F2; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc4032c7" "c73240fc"

  [<TestMethod>]
  member _.``[PPC] DRRND (DFP reround)``() =
    DRRND ** [ O.Reg F1; O.Reg F2; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec221a46" "461a22ec"

  [<TestMethod>]
  member _.``[PPC] DRRND. (DFP reround, record)``() =
    DRRNDdot ** [ O.Reg F1; O.Reg F2; O.Reg F3; O.Imm 0x1UL ]
    |> testAll "ec221a47" "471a22ec"

  [<TestMethod>]
  member _.``[PPC] DRRNDQ (DFP reround quad)``() =
    DRRNDQ ** [ O.Reg F2; O.Reg F2; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc423246" "463242fc"

  [<TestMethod>]
  member _.``[PPC] DRRNDQ. (DFP reround quad, record)``() =
    DRRNDQdot ** [ O.Reg F2; O.Reg F2; O.Reg F6; O.Imm 0x1UL ]
    |> testAll "fc423247" "473242fc"

  [<TestMethod>]
  member _.``[PPC] DRSP (DFP round to DFP short)``() =
    DRSP ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201e04" "041e20ec"

  [<TestMethod>]
  member _.``[PPC] DRSP. (DFP round to DFP short, record)``() =
    DRSPdot ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201e05" "051e20ec"

  [<TestMethod>]
  member _.``[PPC] DSCLI (DFP shift significand left)``() =
    DSCLI ** [ O.Reg F1; O.Reg F2; O.Imm 0x5UL ]
    |> testAll "ec221484" "841422ec"

  [<TestMethod>]
  member _.``[PPC] DSCLI. (DFP shift significand left, record)``() =
    DSCLIdot ** [ O.Reg F1; O.Reg F2; O.Imm 0x5UL ]
    |> testAll "ec221485" "851422ec"

  [<TestMethod>]
  member _.``[PPC] DSCLIQ (DFP shift significand left quad)``() =
    DSCLIQ ** [ O.Reg F2; O.Reg F4; O.Imm 0x5UL ]
    |> testAll "fc441484" "841444fc"

  [<TestMethod>]
  member _.``[PPC] DSCLIQ. (DFP shift significand left quad, record)``() =
    DSCLIQdot ** [ O.Reg F2; O.Reg F4; O.Imm 0x5UL ]
    |> testAll "fc441485" "851444fc"

  [<TestMethod>]
  member _.``[PPC] DSCRI (DFP shift significand right)``() =
    DSCRI ** [ O.Reg F1; O.Reg F2; O.Imm 0x5UL ]
    |> testAll "ec2214c4" "c41422ec"

  [<TestMethod>]
  member _.``[PPC] DSCRI. (DFP shift significand right, record)``() =
    DSCRIdot ** [ O.Reg F1; O.Reg F2; O.Imm 0x5UL ]
    |> testAll "ec2214c5" "c51422ec"

  [<TestMethod>]
  member _.``[PPC] DSCRIQ (DFP shift significand right quad)``() =
    DSCRIQ ** [ O.Reg F2; O.Reg F4; O.Imm 0x5UL ]
    |> testAll "fc4414c4" "c41444fc"

  [<TestMethod>]
  member _.``[PPC] DSCRIQ. (DFP shift significand right quad, record)``() =
    DSCRIQdot ** [ O.Reg F2; O.Reg F4; O.Imm 0x5UL ]
    |> testAll "fc4414c5" "c51444fc"

  [<TestMethod>]
  member _.``[PPC] DSUB (DFP subtract)``() =
    DSUB ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221c04" "041c22ec"

  [<TestMethod>]
  member _.``[PPC] DSUB. (DFP subtract, record)``() =
    DSUBdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ] |> testAll "ec221c05" "051c22ec"

  [<TestMethod>]
  member _.``[PPC] DSUBQ (DFP subtract quad)``() =
    DSUBQ ** [ O.Reg F2; O.Reg F4; O.Reg F6 ] |> testAll "fc443404" "043444fc"

  [<TestMethod>]
  member _.``[PPC] DSUBQ. (DFP subtract quad, record)``() =
    DSUBQdot ** [ O.Reg F2; O.Reg F4; O.Reg F6 ]
    |> testAll "fc443405" "053444fc"

  [<TestMethod>]
  member _.``[PPC] DTSTDC (DFP test data class)``() =
    DTSTDC ** [ O.Reg CR2; O.Reg F2; O.Imm 0x1UL ]
    |> testAll "ed020584" "840502ed"

  [<TestMethod>]
  member _.``[PPC] DTSTDCQ (DFP test data class quad)``() =
    DTSTDCQ ** [ O.Reg CR2; O.Reg F4; O.Imm 0x1UL ]
    |> testAll "fd040584" "840504fd"

  [<TestMethod>]
  member _.``[PPC] DTSTDG (DFP test data group)``() =
    DTSTDG ** [ O.Reg CR2; O.Reg F2; O.Imm 0x1UL ]
    |> testAll "ed0205c4" "c40502ed"

  [<TestMethod>]
  member _.``[PPC] DTSTDGQ (DFP test data group quad)``() =
    DTSTDGQ ** [ O.Reg CR2; O.Reg F4; O.Imm 0x1UL ]
    |> testAll "fd0405c4" "c40504fd"

  [<TestMethod>]
  member _.``[PPC] DTSTEX (DFP test exponent)``() =
    DTSTEX ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ] |> testAll "ed021944" "441902ed"

  [<TestMethod>]
  member _.``[PPC] DTSTEXQ (DFP test exponent quad)``() =
    DTSTEXQ ** [ O.Reg CR2; O.Reg F4; O.Reg F6 ]
    |> testAll "fd043144" "443104fd"

  [<TestMethod>]
  member _.``[PPC] DTSTSF (DFP test significance)``() =
    DTSTSF ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ] |> testAll "ed021d44" "441d02ed"

  [<TestMethod>]
  member _.``[PPC] DTSTSFI (DFP test significance immediate)``() =
    DTSTSFI ** [ O.Reg CR2; O.Imm 0x1UL; O.Reg F3 ]
    |> testAll "ed011d46" "461d01ed"

  [<TestMethod>]
  member _.``[PPC] DTSTSFIQ (DFP test significance immediate quad)``() =
    DTSTSFIQ ** [ O.Reg CR2; O.Imm 0x1UL; O.Reg F6 ]
    |> testAll "fd013546" "463501fd"

  [<TestMethod>]
  member _.``[PPC] DTSTSFQ (DFP test significance quad)``() =
    DTSTSFQ ** [ O.Reg CR2; O.Reg F2; O.Reg F6 ]
    |> testAll "fd023544" "443502fd"

  [<TestMethod>]
  member _.``[PPC] DXEX (DFP extract biased exponent)``() =
    DXEX ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201ac4" "c41a20ec"

  [<TestMethod>]
  member _.``[PPC] DXEX. (DFP extract biased exponent, record)``() =
    DXEXdot ** [ O.Reg F1; O.Reg F3 ] |> testAll "ec201ac5" "c51a20ec"

  [<TestMethod>]
  member _.``[PPC] DXEXQ (DFP extract biased exponent quad)``() =
    DXEXQ ** [ O.Reg F1; O.Reg F6 ] |> testAll "fc2032c4" "c43220fc"

  [<TestMethod>]
  member _.``[PPC] DXEXQ. (DFP extract biased exponent quad, record)``() =
    DXEXQdot ** [ O.Reg F1; O.Reg F6 ] |> testAll "fc2032c5" "c53220fc"

  /// <summary>
  /// A decimal128 operand is named by the even register of the pair holding
  /// it: an odd one (daddq f3, f4, f6 here) makes the form invalid, on every
  /// target.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DADDQ of an odd register pair is invalid``() =
    testUnsupported WordSize.Bit32 "fc643004"
    testUnsupported WordSize.Bit64 "fc643004"

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
  let refuse wordSz (bytes: byte[]) =
    let isa = ISA(Architecture.PPC, Endian.Big, wordSz)
    let reader = BinReader.Init isa.Endian
    let parser = Parser(isa.WordSize, reader) :> IInstructionParsable
    Assert.Throws<ParsingFailureException>(fun () ->
      parser.Parse(System.ReadOnlySpan bytes, 0UL) |> ignore)
    |> ignore

  /// The same, for a word given as hex.
  let testUnsupported wordSz (byteString: string) =
    refuse wordSz (ByteArray.ofHexString byteString)

  /// Decodes a word on a 64-bit processor in both byte orders. The bytes are
  /// the word as the Power ISA draws it, which a little-endian processor
  /// keeps in memory the other way round.
  let testPPC64 bytes (opcode, operands) =
    testPPC WordSize.Bit64 bytes (opcode, operands)
    let isa = ISA(Architecture.PPC, Endian.Little, WordSize.Bit64)
    test isa opcode operands (Array.rev bytes)

  /// Decodes a word the 32-bit and the 64-bit processors both define.
  let testAllPPC bytes (opcode, operands) =
    testPPC WordSize.Bit32 bytes (opcode, operands)
    testPPC64 bytes (opcode, operands)

  /// Decodes a word only the 64-bit processor defines, which the 32-bit one
  /// must refuse.
  let testOnlyPPC64 bytes (opcode, operands) =
    testPPC64 bytes (opcode, operands)
    refuse WordSize.Bit32 bytes
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

  (* Lane X: VSX, MMA and quad precision. *)
  /// A 64-bit form decoded from both byte orders. The hex is the word as the
  /// Power ISA draws it, most significant byte first, which a little-endian
  /// guest keeps in memory reversed.
  let testBoth (hex: string) (opcode, operands) =
    let word = ByteArray.ofHexString hex
    let big = ISA(Architecture.PPC, Endian.Big, WordSize.Bit64)
    let little = ISA(Architecture.PPC, Endian.Little, WordSize.Bit64)
    test big opcode operands word
    test little opcode operands (Array.rev word)

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

  [<TestMethod>]
  member _.``[PPC] VCTZB (Vector Count Trailing Zeros Byte)``() =
    "103c1e02"
    ++ (VCTZB ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCTZH (Vector Count Trailing Zeros Halfword)``() =
    "103d1e02"
    ++ (VCTZH ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCTZW (Vector Count Trailing Zeros Word)``() =
    "103e1e02"
    ++ (VCTZW ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCTZD (Vector Count Trailing Zeros Doubleword)``() =
    "103f1e02"
    ++ (VCTZD ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCLZLSBB (Count Leading Zero Least-Significant Bits)``() =
    "10a01e02"
    ++ (VCLZLSBB ** [ O.Reg R5; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCTZLSBB (Count Trailing Zero Least-Significant Bits)``() =
    "10a11e02"
    ++ (VCTZLSBB ** [ O.Reg R5; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VNEGW (Vector Negate Word)``() =
    "10261e02"
    ++ (VNEGW ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VNEGD (Vector Negate Doubleword)``() =
    "10271e02"
    ++ (VNEGD ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPRTYBW (Vector Parity Byte Word)``() =
    "10281e02"
    ++ (VPRTYBW ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPRTYBD (Vector Parity Byte Doubleword)``() =
    "10291e02"
    ++ (VPRTYBD ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPRTYBQ (Vector Parity Byte Quadword)``() =
    "102a1e02"
    ++ (VPRTYBQ ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTSB2W (Vector Extend Sign Byte To Word)``() =
    "10301e02"
    ++ (VEXTSB2W ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTSH2W (Vector Extend Sign Halfword To Word)``() =
    "10311e02"
    ++ (VEXTSH2W ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTSB2D (Vector Extend Sign Byte To Doubleword)``() =
    "10381e02"
    ++ (VEXTSB2D ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTSH2D (Vector Extend Sign Halfword To Doubleword)``() =
    "10391e02"
    ++ (VEXTSH2D ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTSW2D (Vector Extend Sign Word To Doubleword)``() =
    "103a1e02"
    ++ (VEXTSW2D ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTSD2Q (Vector Extend Sign Doubleword to Quadword)``() =
    "103b1e02"
    ++ (VEXTSD2Q ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRLWNM (Vector Rotate Left Word then AND with Mask)``() =
    "10221985"
    ++ (VRLWNM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRLDNM (Rotate Left Doubleword then AND with Mask)``() =
    "102219c5"
    ++ (VRLDNM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRLQNM (Vector Rotate Left Quadword then AND with Mask)``() =
    "10221945"
    ++ (VRLQNM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRLWMI (Vector Rotate Left Word then Mask Insert)``() =
    "10221885"
    ++ (VRLWMI ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRLDMI (Vector Rotate Left Doubleword then Mask Insert)``() =
    "102218c5"
    ++ (VRLDMI ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRLQMI (Vector Rotate Left Quadword then Mask Insert)``() =
    "10221845"
    ++ (VRLQMI ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSLQ (Vector Shift Left Quadword)``() =
    "10221905"
    ++ (VSLQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSRQ (Vector Shift Right Quadword)``() =
    "10221a05"
    ++ (VSRQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSRAQ (Vector Shift Right Algebraic Quadword)``() =
    "10221b05"
    ++ (VSRAQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRLQ (Vector Rotate Left Quadword)``() =
    "10221805"
    ++ (VRLQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSLV (Vector Shift Left Variable)``() =
    "10221f44"
    ++ (VSLV ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSRV (Vector Shift Right Variable)``() =
    "10221f04"
    ++ (VSRV ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSLDBI (Vector Shift Left Double by Bit Immediate)``() =
    "10221896"
    ++ (VSLDBI ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Imm 0x2UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSRDBI (Vector Shift Right Double by Bit Immediate)``() =
    "10221a96"
    ++ (VSRDBI ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Imm 0x2UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXPANDBM (Vector Expand Byte Mask)``() =
    "10201e42"
    ++ (VEXPANDBM ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXPANDHM (Vector Expand Halfword Mask)``() =
    "10211e42"
    ++ (VEXPANDHM ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXPANDWM (Vector Expand Word Mask)``() =
    "10221e42"
    ++ (VEXPANDWM ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXPANDDM (Vector Expand Doubleword Mask)``() =
    "10231e42"
    ++ (VEXPANDDM ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXPANDQM (Vector Expand Quadword Mask)``() =
    "10241e42"
    ++ (VEXPANDQM ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTBM (Vector Extract Byte Mask)``() =
    "10a81e42"
    ++ (VEXTRACTBM ** [ O.Reg R5; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTHM (Vector Extract Halfword Mask)``() =
    "10a91e42"
    ++ (VEXTRACTHM ** [ O.Reg R5; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTWM (Vector Extract Word Mask)``() =
    "10aa1e42"
    ++ (VEXTRACTWM ** [ O.Reg R5; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTDM (Vector Extract Doubleword Mask)``() =
    "10ab1e42"
    ++ (VEXTRACTDM ** [ O.Reg R5; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTQM (Vector Extract Quadword Mask)``() =
    "10ac1e42"
    ++ (VEXTRACTQM ** [ O.Reg R5; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTVSRBM (Move to VSR Byte Mask)``() =
    "10303e42"
    ++ (MTVSRBM ** [ O.Reg V1A; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTVSRHM (Move to VSR Halfword Mask)``() =
    "10313e42"
    ++ (MTVSRHM ** [ O.Reg V1A; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTVSRWM (Move to VSR Word Mask)``() =
    "10323e42"
    ++ (MTVSRWM ** [ O.Reg V1A; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTVSRDM (Move to VSR Doubleword Mask)``() =
    "10333e42"
    ++ (MTVSRDM ** [ O.Reg V1A; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTVSRQM (Move to VSR Quadword Mask)``() =
    "10343e42"
    ++ (MTVSRQM ** [ O.Reg V1A; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTVSRBMI (Move To VSR Byte Mask Immediate)``() =
    "103a1214"
    ++ (MTVSRBMI ** [ O.Reg V1A; O.Imm 0x1234UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCNTMBB (Vector Count Mask Bits Byte)``() =
    "10b91e42"
    ++ (VCNTMBB ** [ O.Reg R5; O.Reg V3A; O.Imm 0x1UL ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VCNTMBH (Vector Count Mask Bits Halfword)``() =
    "10bb1e42"
    ++ (VCNTMBH ** [ O.Reg R5; O.Reg V3A; O.Imm 0x1UL ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VCNTMBW (Vector Count Mask Bits Word)``() =
    "10bd1e42"
    ++ (VCNTMBW ** [ O.Reg R5; O.Reg V3A; O.Imm 0x1UL ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VCNTMBD (Vector Count Mask Bits Doubleword)``() =
    "10bf1e42"
    ++ (VCNTMBD ** [ O.Reg R5; O.Reg V3A; O.Imm 0x1UL ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VSTRIBL (Vector String Isolate Byte Left-justified)``() =
    "1020180d"
    ++ (VSTRIBL ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSTRIBLdot (Vector String Isolate Byte Left-justified)``() =
    "10201c0d"
    ++ (VSTRIBLdot ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSTRIBR (Vector String Isolate Byte Right-justified)``() =
    "1021180d"
    ++ (VSTRIBR ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSTRIBRdot (Vector String Isolate Byte Right-justified)``() =
    "10211c0d"
    ++ (VSTRIBRdot ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSTRIHL (Vector String Isolate Halfword Left-justified)``() =
    "1022180d"
    ++ (VSTRIHL ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSTRIHLdot (String Isolate Halfword Left-justified)``() =
    "10221c0d"
    ++ (VSTRIHLdot ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSTRIHR (String Isolate Halfword Right-justified)``() =
    "1023180d"
    ++ (VSTRIHR ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSTRIHRdot (String Isolate Halfword Right-justified)``() =
    "10231c0d"
    ++ (VSTRIHRdot ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPERMR (Vector Permute Right-indexed)``() =
    "1022193b"
    ++ (VPERMR ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg V4A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VGNB (Vector Gather every Nth Bit)``() =
    "10a21ccc"
    ++ (VGNB ** [ O.Reg R5; O.Reg V3A; O.Imm 0x2UL ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VBPERMD (Vector Bit Permute Doubleword)``() =
    "10221dcc"
    ++ (VBPERMD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCFUGED (Vector Centrifuge Doubleword)``() =
    "10221d4d"
    ++ (VCFUGED ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPDEPD (Vector Parallel Bits Deposit Doubleword)``() =
    "10221dcd"
    ++ (VPDEPD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VPEXTD (Vector Parallel Bits Extract Doubleword)``() =
    "10221d8d"
    ++ (VPEXTD ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCLZDM (Count Leading Zeros Doubleword under bit Mask)``() =
    "10221f84"
    ++ (VCLZDM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCTZDM (Count Trailing Zeros Doubleword under bit Mask)``() =
    "10221fc4"
    ++ (VCTZDM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VADDFP (Vector Add Floating-Point)``() =
    "1022180a"
    ++ (VADDFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VSUBFP (Vector Subtract Floating-Point)``() =
    "1022184a"
    ++ (VSUBFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMADDFP (Vector Multiply-Add Floating-Point)``() =
    "1022192e"
    ++ (VMADDFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V4A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VNMSUBFP (Negative Multiply-Subtract Floating-Point)``() =
    "1022192f"
    ++ (VNMSUBFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V4A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMAXFP (Vector Maximum Floating-Point)``() =
    "10221c0a"
    ++ (VMAXFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMINFP (Vector Minimum Floating-Point)``() =
    "10221c4a"
    ++ (VMINFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VREFP (Vector Reciprocal Estimate Floating-Point)``() =
    "1020190a"
    ++ (VREFP ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRSQRTEFP (Reciprocal Square Root Estimate)``() =
    "1020194a"
    ++ (VRSQRTEFP ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXPTEFP (2 Raised to the Exponent Estimate)``() =
    "1020198a"
    ++ (VEXPTEFP ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VLOGEFP (Vector Log Base 2 Estimate Floating-Point)``() =
    "102019ca"
    ++ (VLOGEFP ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRFIN (Vector Round to Floating-Point Integer Nearest)``() =
    "10201a0a"
    ++ (VRFIN ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRFIZ (Round to Floating-Point Integer toward Zero)``() =
    "10201a4a"
    ++ (VRFIZ ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRFIP (Round to Floating-Point Integer toward)``() =
    "10201a8a"
    ++ (VRFIP ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VRFIM (Round to Floating-Point Integer toward)``() =
    "10201aca"
    ++ (VRFIM ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCFSX (Convert with round to nearest From Signed Word)``() =
    "10211b4a"
    ++ (VCFSX ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCFUX (Convert with round to nearest From Unsigned)``() =
    "10211b0a"
    ++ (VCFUX ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCTSXS (Convert with round to zero from floating-point)``() =
    "10211bca"
    ++ (VCTSXS ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCTUXS (Convert with round to zero from floating-point)``() =
    "10211b8a"
    ++ (VCTUXS ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPEQFP (Vector Compare Equal Floating-Point)``() =
    "102218c6"
    ++ (VCMPEQFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPEQFPdot (Vector Compare Equal Floating-Point)``() =
    "10221cc6"
    ++ (VCMPEQFPdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPGEFP (Compare Greater Than or Equal Floating-Point)``() =
    "102219c6"
    ++ (VCMPGEFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPGEFPdot (Compare Greater Than or Equal)``() =
    "10221dc6"
    ++ (VCMPGEFPdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPGTFP (Vector Compare Greater Than Floating-Point)``() =
    "10221ac6"
    ++ (VCMPGTFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPGTFPdot (Compare Greater Than Floating-Point)``() =
    "10221ec6"
    ++ (VCMPGTFPdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPBFP (Vector Compare Bounds Floating-Point)``() =
    "10221bc6"
    ++ (VCMPBFP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCMPBFPdot (Vector Compare Bounds Floating-Point)``() =
    "10221fc6"
    ++ (VCMPBFPdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDCPSGNdot (Decimal Copy Sign)``() =
    "10221b41"
    ++ (BCDCPSGNdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDSETSGNdot (Decimal Set Sign)``() =
    "103f1d81"
    ++ (BCDSETSGNdot ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDCFSQdot (Decimal Convert From Signed Quadword)``() =
    "10221d81"
    ++ (BCDCFSQdot ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDCTSQdot (Decimal Convert To Signed Quadword)``() =
    "10201d81"
    ++ (BCDCTSQdot ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDSdot (Decimal Shift)``() =
    "10221cc1"
    ++ (BCDSdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDUSdot (Decimal Unsigned Shift)``() =
    "10221c81"
    ++ (BCDUSdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDSRdot (Decimal Shift and Round)``() =
    "10221dc1"
    ++ (BCDSRdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDTRUNCdot (Decimal Truncate)``() =
    "10221d01"
    ++ (BCDTRUNCdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDUTRUNCdot (Decimal Unsigned Truncate)``() =
    "10221d41"
    ++ (BCDUTRUNCdot ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDCFNdot (Decimal Convert From National)``() =
    "10271d81"
    ++ (BCDCFNdot ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDCTNdot (Decimal Convert To National)``() =
    "10251d81"
    ++ (BCDCTNdot ** [ O.Reg V1A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDCFZdot (Decimal Convert From Zoned)``() =
    "10261d81"
    ++ (BCDCFZdot ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] BCDCTZdot (Decimal Convert To Zoned)``() =
    "10241d81"
    ++ (BCDCTZdot ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMUL10UQ (Vector Multiply-by-10 Unsigned Quadword)``() =
    "10220201"
    ++ (VMUL10UQ ** [ O.Reg V1A; O.Reg V2A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMUL10CUQ (Multiply-by-10 & write Carry-out Unsigned)``() =
    "10220001"
    ++ (VMUL10CUQ ** [ O.Reg V1A; O.Reg V2A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMUL10EUQ (Multiply-by-10 Extended Unsigned Quadword)``() =
    "10221a41"
    ++ (VMUL10EUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VMUL10ECUQ (Multiply-by-10 Extended & write Carry-out)``() =
    "10221841"
    ++ (VMUL10ECUQ ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTUB (Extract Unsigned Byte to VSR using)``() =
    "10211a0d"
    ++ (VEXTRACTUB ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTUH (Extract Unsigned Halfword to VSR using)``() =
    "10211a4d"
    ++ (VEXTRACTUH ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTUW (Extract Unsigned Word to VSR using)``() =
    "10211a8d"
    ++ (VEXTRACTUW ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTRACTD (Extract Doubleword to VSR using)``() =
    "10211acd"
    ++ (VEXTRACTD ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSERTB (Insert Byte from VSR using)``() =
    "10211b0d"
    ++ (VINSERTB ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSERTH (Insert Halfword from VSR using)``() =
    "10211b4d"
    ++ (VINSERTH ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSERTW (Insert Word from VSR using)``() =
    "10211b8d"
    ++ (VINSERTW ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSERTD (Insert Doubleword from VSR using)``() =
    "10211bcd"
    ++ (VINSERTD ** [ O.Reg V1A; O.Reg V3A; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSW (Insert Word from GPR using immediate-specified)``() =
    "102138cf"
    ++ (VINSW ** [ O.Reg V1A; O.Reg R7; O.Imm 0x1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSD (Insert Doubleword from GPR using)``() =
    "102139cf"
    ++ (VINSD ** [ O.Reg V1A; O.Reg R7; O.Imm 0x1UL ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VEXTUBLX (Extract Unsigned Byte to GPR using)``() =
    "10a61e0d"
    ++ (VEXTUBLX ** [ O.Reg R5; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTUHLX (Extract Unsigned Halfword to GPR using)``() =
    "10a61e4d"
    ++ (VEXTUHLX ** [ O.Reg R5; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTUWLX (Extract Unsigned Word to GPR using)``() =
    "10a61e8d"
    ++ (VEXTUWLX ** [ O.Reg R5; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTUBRX (Extract Unsigned Byte to GPR using)``() =
    "10a61f0d"
    ++ (VEXTUBRX ** [ O.Reg R5; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTUHRX (Extract Unsigned Halfword to GPR using)``() =
    "10a61f4d"
    ++ (VEXTUHRX ** [ O.Reg R5; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTUWRX (Extract Unsigned Word to GPR using)``() =
    "10a61f8d"
    ++ (VEXTUWRX ** [ O.Reg R5; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTDUBVLX (Extract Double Unsigned Byte to VSR using)``() =
    "10221a58"
    ++ (VEXTDUBVLX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg R9 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTDUBVRX (Extract Double Unsigned Byte to VSR using)``() =
    "10221a59"
    ++ (VEXTDUBVRX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg R9 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTDUHVLX (Extract Double Unsigned Halfword to VSR)``() =
    "10221a5a"
    ++ (VEXTDUHVLX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg R9 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTDUHVRX (Extract Double Unsigned Halfword to VSR)``() =
    "10221a5b"
    ++ (VEXTDUHVRX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg R9 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTDUWVLX (Extract Double Unsigned Word to VSR using)``() =
    "10221a5c"
    ++ (VEXTDUWVLX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg R9 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTDUWVRX (Extract Double Unsigned Word to VSR using)``() =
    "10221a5d"
    ++ (VEXTDUWVRX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg R9 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTDDVLX (Extract Double Doubleword to VSR using)``() =
    "10221a5e"
    ++ (VEXTDDVLX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg R9 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VEXTDDVRX (Extract Double Doubleword to VSR using)``() =
    "10221a5f"
    ++ (VEXTDDVRX ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A; O.Reg R9 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSBLX (Insert Byte from GPR using GPR-specified)``() =
    "10263a0f"
    ++ (VINSBLX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSHLX (Insert Halfword from GPR using GPR-specified)``() =
    "10263a4f"
    ++ (VINSHLX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSWLX (Insert Word from GPR using GPR-specified)``() =
    "10263a8f"
    ++ (VINSWLX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSDLX (Insert Doubleword from GPR using)``() =
    "10263acf"
    ++ (VINSDLX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VINSBRX (Insert Byte from GPR using GPR-specified)``() =
    "10263b0f"
    ++ (VINSBRX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSHRX (Insert Halfword from GPR using GPR-specified)``() =
    "10263b4f"
    ++ (VINSHRX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSWRX (Insert Word from GPR using GPR-specified)``() =
    "10263b8f"
    ++ (VINSWRX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSDRX (Insert Doubleword from GPR using)``() =
    "10263bcf"
    ++ (VINSDRX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] VINSBVLX (Insert Byte from VSR using GPR-specified)``() =
    "1026180f"
    ++ (VINSBVLX ** [ O.Reg V1A; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSHVLX (Insert Halfword from VSR using GPR-specified)``() =
    "1026184f"
    ++ (VINSHVLX ** [ O.Reg V1A; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSWVLX (Insert Word from VSR using GPR-specified)``() =
    "1026188f"
    ++ (VINSWVLX ** [ O.Reg V1A; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSBVRX (Insert Byte from VSR using GPR-specified)``() =
    "1026190f"
    ++ (VINSBVRX ** [ O.Reg V1A; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSHVRX (Insert Halfword from VSR using GPR-specified)``() =
    "1026194f"
    ++ (VINSHVRX ** [ O.Reg V1A; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VINSWVRX (Insert Word from VSR using GPR-specified)``() =
    "1026198f"
    ++ (VINSWVRX ** [ O.Reg V1A; O.Reg R6; O.Reg V3A ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCLRLB (Vector Clear Leftmost Bytes)``() =
    "1022398d"
    ++ (VCLRLB ** [ O.Reg V1A; O.Reg V2A; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] VCLRRB (Vector Clear Rightmost Bytes)``() =
    "102239cd"
    ++ (VCLRRB ** [ O.Reg V1A; O.Reg V2A; O.Reg R7 ])
    ||> testEveryTarget

  (* Lane X: VSX, MMA and quad precision. *)
  [<TestMethod>]
  member _.``[PPC64] LXSIBZX``() =
    testBoth "7c263e1a" (LXSIBZX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXSIHZX``() =
    testBoth "7c263e5a" (LXSIHZX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXSIWAX``() =
    testBoth "7c263898" (LXSIWAX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXSIWZX``() =
    testBoth "7c263818" (LXSIWZX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXSSP (load VSX scalar single-precision)``() =
    testBoth "e426000b" (LXSSP ** [ O.Reg V1A; O.Mem(8, R6) ])

  [<TestMethod>]
  member _.``[PPC64] LXSSPX (load VSX scalar single-precision indexed)``() =
    testBoth "7c263c18" (LXSSPX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXV (load VSX vector)``() =
    testBoth "f4260011" (LXV ** [ O.Reg F1; O.Mem(16, R6) ])

  [<TestMethod>]
  member _.``[PPC64] LXVB16X (load VSX vector byte*16 indexed)``() =
    testBoth "7c263ed8" (LXVB16X ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVH8X (load VSX vector halfword*8 indexed)``() =
    testBoth "7c263e58" (LXVH8X ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVKQ (load VSX vector special value quadword)``() =
    testBoth "f03f0ad0" (LXVKQ ** [ O.Reg F1; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] LXVL (load VSX vector with length)``() =
    testBoth "7c263a1a" (LXVL ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVLL (load VSX vector with length left-justified)``() =
    testBoth "7c263a5a" (LXVLL ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVP (load VSX vector paired)``() =
    testBoth "18460010" (LXVP ** [ O.Reg F2; O.Mem(16, R6) ])

  [<TestMethod>]
  member _.``[PPC64] LXVPX (load VSX vector paired indexed)``() =
    testBoth "7c463a9a" (LXVPX ** [ O.Reg F2; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVRBX (load VSX vector rightmost byte indexed)``() =
    testBoth "7c26381a" (LXVRBX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVRDX (load VSX vector rightmost doubleword indexed)``() =
    testBoth "7c2638da" (LXVRDX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVRHX (load VSX vector rightmost halfword indexed)``() =
    testBoth "7c26385a" (LXVRHX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVRWX (load VSX vector rightmost word indexed)``() =
    testBoth "7c26389a" (LXVRWX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVWSX (load VSX vector word and splat indexed)``() =
    testBoth "7c263ad8" (LXVWSX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVX (load VSX vector indexed)``() =
    testBoth "7c263a18" (LXVX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] MTVSRWS (move to VSR word and splat)``() =
    testBoth "7c260326" (MTVSRWS ** [ O.Reg F1; O.Reg R6 ])

  [<TestMethod>]
  member _.``[PPC64] STXSIBX (store VSX scalar as integer byte indexed)``() =
    testBoth "7c263f1a" (STXSIBX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXSIHX``() =
    testBoth "7c263f5a" (STXSIHX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXSIWX (store VSX scalar as integer word indexed)``() =
    testBoth "7c263918" (STXSIWX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXSSP (store VSX scalar single)``() =
    testBoth "f426000b" (STXSSP ** [ O.Reg V1A; O.Mem(8, R6) ])

  [<TestMethod>]
  member _.``[PPC64] STXSSPX (store VSX scalar single-precision indexed)``() =
    testBoth "7c263d18" (STXSSPX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXV (store VSX vector)``() =
    testBoth "f4260015" (STXV ** [ O.Reg F1; O.Mem(16, R6) ])

  [<TestMethod>]
  member _.``[PPC64] STXVB16X (store VSX vector byte*16 indexed)``() =
    testBoth "7c263fd8" (STXVB16X ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVH8X (store VSX vector halfword*8 indexed)``() =
    testBoth "7c263f58" (STXVH8X ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVL (store VSX vector with length)``() =
    testBoth "7c263b1a" (STXVL ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVLL (store VSX vector with length left-justified)``() =
    testBoth "7c263b5a" (STXVLL ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVP (store VSX vector paired)``() =
    testBoth "18460011" (STXVP ** [ O.Reg F2; O.Mem(16, R6) ])

  [<TestMethod>]
  member _.``[PPC64] STXVPX (store VSX vector paired indexed)``() =
    testBoth "7c463b9a" (STXVPX ** [ O.Reg F2; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVRBX (store VSX vector rightmost byte indexed)``() =
    testBoth "7c26391a" (STXVRBX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVRDX``() =
    testBoth "7c2639da" (STXVRDX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVRHX (store VSX vector rightmost halfword indexed)``() =
    testBoth "7c26395a" (STXVRHX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVRWX (store VSX vector rightmost word indexed)``() =
    testBoth "7c26399a" (STXVRWX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] STXVX (store VSX vector indexed)``() =
    testBoth "7c263b18" (STXVX ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXVX names VSR32-63 by its last bit``() =
    testBoth "7c263a19" (LXVX ** [ O.Reg V1A; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] LXV names VSR32-63 by the bit above its form``() =
    testBoth "f4260019" (LXV ** [ O.Reg V1A; O.Mem(16, R6) ])

  [<TestMethod>]
  member _.``[PPC64] LXVP names a pair of VSR32-63 by its bit 10``() =
    testBoth "18660010" (LXVP ** [ O.Reg V2A; O.Mem(16, R6) ])

  [<TestMethod>]
  member _.``[PPC64] LXVP takes a negative displacement``() =
    testBoth "1846fff0" (LXVP ** [ O.Reg F2; O.Mem(-16, R6) ])

  [<TestMethod>]
  member _.``[PPC64] LXVKQ is not XXSPLTIB``() =
    testBoth "f03f8ad0" (LXVKQ ** [ O.Reg F1; O.Imm 0x11UL ])

  [<TestMethod>]
  member _.``[PPC64] LXVKQ refuses a reserved constant``() =
    testUnsupported WordSize.Bit64 "f03f52d0"

  [<TestMethod>]
  member _.``[PPC64] XXSPLTIB keeps the forms with its two high bits clear``() =
    testBoth "f0278ad0" (XXSPLTIB ** [ O.Reg F1; O.Imm 0xf1UL ])

  [<TestMethod>]
  member _.``[PPC64] LXVP refuses the low bits no form has``() =
    testUnsupported WordSize.Bit64 "18460012"

  [<TestMethod>]
  member _.``[PPC64] XSRESP``() =
    testBoth "f0201868" (XSRESP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSRSQRTESP``() =
    testBoth "f0201828" (XSRSQRTESP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXBRH (VSX vector byte-reverse halfword)``() =
    testBoth "f0271f6c" (XXBRH ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXBRW (VSX vector byte-reverse word)``() =
    testBoth "f02f1f6c" (XXBRW ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXBRD (VSX vector byte-reverse doubleword)``() =
    testBoth "f0371f6c" (XXBRD ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXBRQ (VSX vector byte-reverse quadword)``() =
    testBoth "f03f1f6c" (XXBRQ ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXEXTRACTUW (VSX vector extract unsigned word)``() =
    testBoth "f0211a94" (XXEXTRACTUW ** [ O.Reg F1; O.Reg F3; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XXINSERTW (VSX vector insert word)``() =
    testBoth "f0211ad4" (XXINSERTW ** [ O.Reg F1; O.Reg F3; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XXPERM (VSX vector permute)``() =
    testBoth "f02218d0" (XXPERM ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXPERMR (VSX vector permute right-indexed)``() =
    testBoth "f02219d0" (XXPERMR ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXGENPCVBM (VSX vector generate PCV from byte mask)``() =
    testBoth "f0211f28" (XXGENPCVBM ** [ O.Reg F1; O.Reg V3A; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XXGENPCVHM``() =
    testBoth "f0211f2a" (XXGENPCVHM ** [ O.Reg F1; O.Reg V3A; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XXGENPCVWM (VSX vector generate PCV from word mask)``() =
    testBoth "f0211f68" (XXGENPCVWM ** [ O.Reg F1; O.Reg V3A; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XXGENPCVDM``() =
    testBoth "f0211f6a" (XXGENPCVDM ** [ O.Reg F1; O.Reg V3A; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XVTLSBB``() =
    testBoth "f1021f6c" (XVTLSBB ** [ O.Reg CR2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXPERM names VSR32-63 by its three last bits``() =
    testBoth "f02218d7" (XXPERM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XXGENPCVBM refuses an IMM past 3``() =
    testUnsupported WordSize.Bit64 "f0241f28"

  [<TestMethod>]
  member _.``[PPC64] XXBRQ refuses an A field no form has``() =
    testUnsupported WordSize.Bit64 "f0261f6c"

  [<TestMethod>]
  member _.``[PPC64] XVADDSP (VSX vector add single-precision)``() =
    testBoth "f0221a00" (XVADDSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVSUBSP (VSX vector subtract single-precision)``() =
    testBoth "f0221a40" (XVSUBSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMULSP (VSX vector multiply single-precision)``() =
    testBoth "f0221a80" (XVMULSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVDIVSP (VSX vector divide single-precision)``() =
    testBoth "f0221ac0" (XVDIVSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVSQRTSP (VSX vector square root single-precision)``() =
    testBoth "f0201a2c" (XVSQRTSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVSQRTDP (VSX vector square root double-precision)``() =
    testBoth "f0201b2c" (XVSQRTDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVABSDP (VSX vector absolute value double-precision)``() =
    testBoth "f0201f64" (XVABSDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVABSSP (VSX vector absolute value single-precision)``() =
    testBoth "f0201e64" (XVABSSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNABSDP``() =
    testBoth "f0201fa4" (XVNABSDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNABSSP``() =
    testBoth "f0201ea4" (XVNABSSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNEGSP (VSX vector negate single-precision)``() =
    testBoth "f0201ee4" (XVNEGSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCPSGNDP (VSX vector copy sign double-precision)``() =
    testBoth "f0221f80" (XVCPSGNDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCPSGNSP (VSX vector copy sign single-precision)``() =
    testBoth "f0221e80" (XVCPSGNSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMAXDP (VSX vector maximum double-precision)``() =
    testBoth "f0221f00" (XVMAXDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMAXSP (VSX vector maximum single-precision)``() =
    testBoth "f0221e00" (XVMAXSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMINDP (VSX vector minimum double-precision)``() =
    testBoth "f0221f40" (XVMINDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMINSP (VSX vector minimum single-precision)``() =
    testBoth "f0221e40" (XVMINSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSMAXCDP``() =
    testBoth "f0221c00" (XSMAXCDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSMAXJDP``() =
    testBoth "f0221c80" (XSMAXJDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSMINCDP``() =
    testBoth "f0221c40" (XSMINCDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSMINJDP``() =
    testBoth "f0221cc0" (XSMINJDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMADDADP``() =
    testBoth "f0221b08" (XVMADDADP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMADDASP``() =
    testBoth "f0221a08" (XVMADDASP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMADDMDP``() =
    testBoth "f0221b48" (XVMADDMDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMADDMSP``() =
    testBoth "f0221a48" (XVMADDMSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMSUBADP``() =
    testBoth "f0221b88" (XVMSUBADP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMSUBASP``() =
    testBoth "f0221a88" (XVMSUBASP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMSUBMDP``() =
    testBoth "f0221bc8" (XVMSUBMDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVMSUBMSP``() =
    testBoth "f0221ac8" (XVMSUBMSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNMADDADP (double-precision)``() =
    testBoth "f0221f08" (XVNMADDADP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNMADDASP (single-precision)``() =
    testBoth "f0221e08" (XVNMADDASP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNMADDMDP (double-precision)``() =
    testBoth "f0221f48" (XVNMADDMDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNMADDMSP (single-precision)``() =
    testBoth "f0221e48" (XVNMADDMSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNMSUBADP (double-precision)``() =
    testBoth "f0221f88" (XVNMSUBADP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNMSUBASP (single-precision)``() =
    testBoth "f0221e88" (XVNMSUBASP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNMSUBMDP (double-precision)``() =
    testBoth "f0221fc8" (XVNMSUBMDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVNMSUBMSP (single-precision)``() =
    testBoth "f0221ec8" (XVNMSUBMSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVREDP``() =
    testBoth "f0201b68" (XVREDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRESP``() =
    testBoth "f0201a68" (XVRESP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRSQRTEDP``() =
    testBoth "f0201b28" (XVRSQRTEDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRSQRTESP``() =
    testBoth "f0201a28" (XVRSQRTESP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSREDP``() =
    testBoth "f0201968" (XSREDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSRSQRTEDP``() =
    testBoth "f0201928" (XSRSQRTEDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRDPI (round to nearest away)``() =
    testBoth "f0201b24" (XVRDPI ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRDPIC (using current rounding mode)``() =
    testBoth "f0201bac" (XVRDPIC ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRDPIM (round toward -infinity)``() =
    testBoth "f0201be4" (XVRDPIM ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRDPIP (round toward +infinity)``() =
    testBoth "f0201ba4" (XVRDPIP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRDPIZ``() =
    testBoth "f0201b64" (XVRDPIZ ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRSPI``() =
    testBoth "f0201a24" (XVRSPI ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRSPIC``() =
    testBoth "f0201aac" (XVRSPIC ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRSPIM``() =
    testBoth "f0201ae4" (XVRSPIM ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRSPIP``() =
    testBoth "f0201aa4" (XVRSPIP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVRSPIZ``() =
    testBoth "f0201a64" (XVRSPIZ ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSRDPIC (using current rounding mode)``() =
    testBoth "f02019ac" (XSRDPIC ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPEQDP (VSX scalar compare equal double-precision)``() =
    testBoth "f0221818" (XSCMPEQDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPGTDP``() =
    testBoth "f0221858" (XSCMPGTDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPGEDP (VSX scalar compare greater than or equal)``() =
    testBoth "f0221898" (XSCMPGEDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPODP``() =
    testBoth "f1021958" (XSCMPODP ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPEXPDP``() =
    testBoth "f10219d8" (XSCMPEXPDP ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCMPEQDP``() =
    testBoth "f0221b18" (XVCMPEQDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCMPEQDPdot``() =
    testBoth "f0221f18" (XVCMPEQDPdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCMPEQSP``() =
    testBoth "f0221a18" (XVCMPEQSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCMPEQSPdot``() =
    testBoth "f0221e18" (XVCMPEQSPdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCMPGESP (single-precision)``() =
    testBoth "f0221a98" (XVCMPGESP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCMPGESPdot (single-precision)``() =
    testBoth "f0221e98" (XVCMPGESPdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCMPGTSP``() =
    testBoth "f0221a58" (XVCMPGTSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCMPGTSPdot``() =
    testBoth "f0221e58" (XVCMPGTSPdot ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSTDIVDP``() =
    testBoth "f10219e8" (XSTDIVDP ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSTSQRTDP (double-precision)``() =
    testBoth "f10019a8" (XSTSQRTDP ** [ O.Reg CR2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVTDIVDP``() =
    testBoth "f1021be8" (XVTDIVDP ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVTDIVSP``() =
    testBoth "f1021ae8" (XVTDIVSP ** [ O.Reg CR2; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVTSQRTDP (VSX vector test for software square root)``() =
    testBoth "f1001ba8" (XVTSQRTDP ** [ O.Reg CR2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVTSQRTSP (VSX vector test for software square root)``() =
    testBoth "f1001aa8" (XVTSQRTSP ** [ O.Reg CR2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSTSTDCDP``() =
    testBoth "f1011da8" (XSTSTDCDP ** [ O.Reg CR2; O.Reg F3; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XSTSTDCSP``() =
    testBoth "f1011ca8" (XSTSTDCSP ** [ O.Reg CR2; O.Reg F3; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XVTSTDCDP``() =
    testBoth "f0211fa8" (XVTSTDCDP ** [ O.Reg F1; O.Reg F3; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XVTSTDCSP``() =
    testBoth "f0211ea8" (XVTSTDCSP ** [ O.Reg F1; O.Reg F3; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XSIEXPDP``() =
    testBoth "f0263f2c" (XSIEXPDP ** [ O.Reg F1; O.Reg R6; O.Reg R7 ])

  [<TestMethod>]
  member _.``[PPC64] XSXEXPDP``() =
    testBoth "f0a01d6c" (XSXEXPDP ** [ O.Reg R5; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSXSIGDP``() =
    testBoth "f0a11d6c" (XSXSIGDP ** [ O.Reg R5; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVIEXPDP``() =
    testBoth "f0221fc0" (XVIEXPDP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVIEXPSP``() =
    testBoth "f0221ec0" (XVIEXPSP ** [ O.Reg F1; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVXEXPDP``() =
    testBoth "f0201f6c" (XVXEXPDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVXEXPSP``() =
    testBoth "f0281f6c" (XVXEXPSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVXSIGDP``() =
    testBoth "f0211f6c" (XVXSIGDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVXSIGSP``() =
    testBoth "f0291f6c" (XVXSIGSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVTSTDCDP gathers DCMX from three fields``() =
    testBoth "f07f1fec" (XVTSTDCDP ** [ O.Reg F3; O.Reg F3; O.Imm 0x7fUL ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPODP refuses the bits below BF set``() =
    testUnsupported WordSize.Bit64 "f1221958"

  [<TestMethod>]
  member _.``[PPC64] XSCVDPHP (half-precision format)``() =
    testBoth "f0311d6c" (XSCVDPHP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSCVHPDP (format)``() =
    testBoth "f0301d6c" (XSCVHPDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVHPSP``() =
    testBoth "f0381f6c" (XVCVHPSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSPHP``() =
    testBoth "f0391f6c" (XVCVSPHP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVBF16SPN``() =
    testBoth "f0301f6c" (XVCVBF16SPN ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSPBF16 (bfloat16 format)``() =
    testBoth "f0311f6c" (XVCVSPBF16 ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVDPSP``() =
    testBoth "f0201e24" (XVCVDPSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSPDP``() =
    testBoth "f0201f24" (XVCVSPDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVDPSXDS``() =
    testBoth "f0201f60" (XVCVDPSXDS ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVDPSXWS (VSX vector convert with round to zero)``() =
    testBoth "f0201b60" (XVCVDPSXWS ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVDPUXDS``() =
    testBoth "f0201f20" (XVCVDPUXDS ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVDPUXWS (double-precision to unsigned word format)``() =
    testBoth "f0201b20" (XVCVDPUXWS ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSPSXDS (to signed doubleword format)``() =
    testBoth "f0201e60" (XVCVSPSXDS ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSPSXWS``() =
    testBoth "f0201a60" (XVCVSPSXWS ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSPUXDS``() =
    testBoth "f0201e20" (XVCVSPUXDS ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSPUXWS``() =
    testBoth "f0201a20" (XVCVSPUXWS ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSXDDP``() =
    testBoth "f0201fe0" (XVCVSXDDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSXDSP``() =
    testBoth "f0201ee0" (XVCVSXDSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVSXWSP``() =
    testBoth "f0201ae0" (XVCVSXWSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVUXDDP``() =
    testBoth "f0201fa0" (XVCVUXDDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVUXDSP``() =
    testBoth "f0201ea0" (XVCVUXDSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVUXWDP``() =
    testBoth "f0201ba0" (XVCVUXWDP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVCVUXWSP (single-precision format)``() =
    testBoth "f0201aa0" (XVCVUXWSP ** [ O.Reg F1; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XSABSQP (VSX scalar absolute quad-precision)``() =
    testBoth "fc201e48" (XSABSQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSADDQP``() =
    testBoth "fc221808" (XSADDQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSADDQPO``() =
    testBoth "fc221809" (XSADDQPO ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPEQQP (VSX scalar compare equal quad-precision)``() =
    testBoth "fc221888" (XSCMPEQQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPEXPQP``() =
    testBoth "fd021948" (XSCMPEXPQP ** [ O.Reg CR2; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPGEQP``() =
    testBoth "fc221988" (XSCMPGEQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPGTQP``() =
    testBoth "fc2219c8" (XSCMPGTQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPOQP (VSX scalar compare ordered quad-precision)``() =
    testBoth "fd021908" (XSCMPOQP ** [ O.Reg CR2; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCMPUQP``() =
    testBoth "fd021d08" (XSCMPUQP ** [ O.Reg CR2; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCPSGNQP (VSX scalar copy sign quad-precision)``() =
    testBoth "fc2218c8" (XSCPSGNQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVDPQP``() =
    testBoth "fc361e88" (XSCVDPQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVQPDP``() =
    testBoth "fc341e88" (XSCVQPDP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVQPDPO``() =
    testBoth "fc341e89" (XSCVQPDPO ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVQPSDZ``() =
    testBoth "fc391e88" (XSCVQPSDZ ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVQPSQZ``() =
    testBoth "fc281e88" (XSCVQPSQZ ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVQPSWZ``() =
    testBoth "fc291e88" (XSCVQPSWZ ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVQPUDZ``() =
    testBoth "fc311e88" (XSCVQPUDZ ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVQPUQZ``() =
    testBoth "fc201e88" (XSCVQPUQZ ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVQPUWZ``() =
    testBoth "fc211e88" (XSCVQPUWZ ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVSDQP``() =
    testBoth "fc2a1e88" (XSCVSDQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVSQQP``() =
    testBoth "fc2b1e88" (XSCVSQQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVUDQP``() =
    testBoth "fc221e88" (XSCVUDQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSCVUQQP``() =
    testBoth "fc231e88" (XSCVUQQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSDIVQP``() =
    testBoth "fc221c48" (XSDIVQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSDIVQPO``() =
    testBoth "fc221c49" (XSDIVQPO ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSIEXPQP (VSX scalar insert exponent quad-precision)``() =
    testBoth "fc221ec8" (XSIEXPQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSMADDQP``() =
    testBoth "fc221b08" (XSMADDQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSMADDQPO``() =
    testBoth "fc221b09" (XSMADDQPO ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSMAXCQP (VSX scalar maximum type-c quad-precision)``() =
    testBoth "fc221d48" (XSMAXCQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSMINCQP (VSX scalar minimum type-c quad-precision)``() =
    testBoth "fc221dc8" (XSMINCQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSMSUBQP``() =
    testBoth "fc221b48" (XSMSUBQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSMSUBQPO``() =
    testBoth "fc221b49" (XSMSUBQPO ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSMULQP``() =
    testBoth "fc221848" (XSMULQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSMULQPO``() =
    testBoth "fc221849" (XSMULQPO ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSNABSQP``() =
    testBoth "fc281e48" (XSNABSQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSNEGQP (VSX scalar negate quad-precision)``() =
    testBoth "fc301e48" (XSNEGQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSNMADDQP``() =
    testBoth "fc221b88" (XSNMADDQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSNMADDQPO``() =
    testBoth "fc221b89" (XSNMADDQPO ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSNMSUBQP``() =
    testBoth "fc221bc8" (XSNMSUBQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSNMSUBQPO``() =
    testBoth "fc221bc9" (XSNMSUBQPO ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSRQPI``() =
    let oprs = [ O.Imm 1UL; O.Reg V1A; O.Reg V3A; O.Imm 1UL ]
    testBoth "fc211a0a" (XSRQPI ** oprs)

  [<TestMethod>]
  member _.``[PPC64] XSRQPIX``() =
    let oprs = [ O.Imm 1UL; O.Reg V1A; O.Reg V3A; O.Imm 1UL ]
    testBoth "fc211a0b" (XSRQPIX ** oprs)

  [<TestMethod>]
  member _.``[PPC64] XSRQPXP``() =
    let oprs = [ O.Imm 1UL; O.Reg V1A; O.Reg V3A; O.Imm 1UL ]
    testBoth "fc211a4a" (XSRQPXP ** oprs)

  [<TestMethod>]
  member _.``[PPC64] XSSQRTQP``() =
    testBoth "fc3b1e48" (XSSQRTQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSSQRTQPO``() =
    testBoth "fc3b1e49" (XSSQRTQPO ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSSUBQP``() =
    testBoth "fc221c08" (XSSUBQP ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSSUBQPO``() =
    testBoth "fc221c09" (XSSUBQPO ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSTSTDCQP (VSX scalar test data class quad-precision)``() =
    testBoth "fd011d88" (XSTSTDCQP ** [ O.Reg CR2; O.Reg V3A; O.Imm 1UL ])

  [<TestMethod>]
  member _.``[PPC64] XSXEXPQP (VSX scalar extract exponent quad-precision)``() =
    testBoth "fc221e48" (XSXEXPQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSXSIGQP``() =
    testBoth "fc321e48" (XSXSIGQP ** [ O.Reg V1A; O.Reg V3A ])

  [<TestMethod>]
  member _.``[PPC64] XSRQPI refuses R = 0 with RMC = 1``() =
    testUnsupported WordSize.Bit64 "fc201a0a"

  [<TestMethod>]
  member _.``[PPC64] XSRQPI with R = 0 rounds by FPSCR with RMC = 3``() =
    let oprs = [ O.Imm 0UL; O.Reg V1A; O.Reg V3A; O.Imm 3UL ]
    testBoth "fc201e0a" (XSRQPI ** oprs)

  [<TestMethod>]
  member _.``[PPC64] XSABSQP refuses its last bit set``() =
    testUnsupported WordSize.Bit64 "fc201e49"

  [<TestMethod>]
  member _.``[PPC64] XVBF16GER2 (VSX vector bfloat16 GER (rank-2 update))``() =
    testBoth "ee021998" (XVBF16GER2 ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVBF16GER2NN``() =
    testBoth "ee021f90" (XVBF16GER2NN ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVBF16GER2NP``() =
    testBoth "ee021b90" (XVBF16GER2NP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVBF16GER2PN``() =
    testBoth "ee021d90" (XVBF16GER2PN ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVBF16GER2PP``() =
    testBoth "ee021990" (XVBF16GER2PP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF16GER2``() =
    testBoth "ee021898" (XVF16GER2 ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF16GER2NN``() =
    testBoth "ee021e90" (XVF16GER2NN ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF16GER2NP``() =
    testBoth "ee021a90" (XVF16GER2NP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF16GER2PN``() =
    testBoth "ee021c90" (XVF16GER2PN ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF16GER2PP``() =
    testBoth "ee021890" (XVF16GER2PP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF32GER``() =
    testBoth "ee0218d8" (XVF32GER ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF32GERNN``() =
    testBoth "ee021ed0" (XVF32GERNN ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF32GERNP``() =
    testBoth "ee021ad0" (XVF32GERNP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF32GERPN``() =
    testBoth "ee021cd0" (XVF32GERPN ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF32GERPP``() =
    testBoth "ee0218d0" (XVF32GERPP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF64GER``() =
    testBoth "ee0619d8" (XVF64GER ** [ O.Reg ACC4; O.Reg F6; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF64GERNN``() =
    testBoth "ee061fd0" (XVF64GERNN ** [ O.Reg ACC4; O.Reg F6; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF64GERNP``() =
    testBoth "ee061bd0" (XVF64GERNP ** [ O.Reg ACC4; O.Reg F6; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF64GERPN``() =
    testBoth "ee061dd0" (XVF64GERPN ** [ O.Reg ACC4; O.Reg F6; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVF64GERPP``() =
    testBoth "ee0619d0" (XVF64GERPP ** [ O.Reg ACC4; O.Reg F6; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI16GER2``() =
    testBoth "ee021a58" (XVI16GER2 ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI16GER2PP``() =
    testBoth "ee021b58" (XVI16GER2PP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI16GER2S``() =
    testBoth "ee021958" (XVI16GER2S ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI16GER2SPP``() =
    testBoth "ee021950" (XVI16GER2SPP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI4GER8``() =
    testBoth "ee021918" (XVI4GER8 ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI4GER8PP``() =
    testBoth "ee021910" (XVI4GER8PP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI8GER4``() =
    testBoth "ee021818" (XVI8GER4 ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI8GER4PP``() =
    testBoth "ee021810" (XVI8GER4PP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XVI8GER4SPP``() =
    testBoth "ee021b18" (XVI8GER4SPP ** [ O.Reg ACC4; O.Reg F2; O.Reg F3 ])

  [<TestMethod>]
  member _.``[PPC64] XXMFACC (VSX move from accumulator)``() =
    testBoth "7e000162" (XXMFACC ** [ O.Reg ACC4 ])

  [<TestMethod>]
  member _.``[PPC64] XXMTACC (VSX move to accumulator)``() =
    testBoth "7e010162" (XXMTACC ** [ O.Reg ACC4 ])

  [<TestMethod>]
  member _.``[PPC64] XXSETACCZ (VSX set accumulator to zero)``() =
    testBoth "7e030162" (XXSETACCZ ** [ O.Reg ACC4 ])

  [<TestMethod>]
  member _.``[PPC64] XVF32GERPP refuses xA inside its accumulator``() =
    testUnsupported WordSize.Bit64 "ee1018d0"

  [<TestMethod>]
  member _.``[PPC64] XVF64GERPP refuses a pair at an odd register``() =
    testUnsupported WordSize.Bit64 "ee0719d0"

  [<TestMethod>]
  member _.``[PPC64] XXMTACC refuses its B field set``() =
    testUnsupported WordSize.Bit64 "7e010962"

  [<TestMethod>]
  member _.``[PPC64] DIVDO (divide doubleword, recording OV)``() =
    "7ca63fd2"
    ++ (DIVDO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDO. (divide doubleword, recording OV and CR0)``() =
    "7ca63fd3"
    ++ (DIVDOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDUO (divide doubleword unsigned, recording OV)``() =
    "7ca63f92"
    ++ (DIVDUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDUO. (divide doubleword unsigned, OV and CR0)``() =
    "7ca63f93"
    ++ (DIVDUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] MULLDO (multiply low doubleword, recording OV)``() =
    "7ca63dd2"
    ++ (MULLDO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] MULLDO. (multiply low doubleword, OV and CR0)``() =
    "7ca63dd3"
    ++ (MULLDOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] BCTAR (branch conditional to TAR)``() =
    "4e890460"
    ++ (BCTAR ** [ O.Imm 0x14UL; O.BI 9u ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] BCTARL (branch conditional to TAR and link)``() =
    "4e890461"
    ++ (BCTARL ** [ O.Imm 0x14UL; O.BI 9u ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] BCTAR with a BH hint``() =
    "4d821460"
    ++ (BCTAR ** [ O.Imm 0xcUL; O.BI 2u; O.Imm 2UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] CLRBHRB (clear the branch history rolling buffer)``() =
    "7c00035c"
    ++ (CLRBHRB ** [])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] ICBT (instruction cache block touch)``() =
    "7c06382c"
    ++ (ICBT ** [ O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] ICBT with a CT hint``() =
    "7c46382c"
    ++ (ICBT ** [ O.Imm 2UL; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] LQARX (load quadword and reserve indexed)``() =
    "7d463a28"
    ++ (LQARX ** [ O.Reg R10; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  /// An odd first register of the pair, and a pair that rA names too, are
  /// invalid forms of lqarx; an odd one is of stqcx.
  [<TestMethod>]
  member _.``[PPC64] LQARX and STQCX. refuse the invalid forms``() =
    for hex in [ "7d663a28"; "7cc63a28"; "7d66396d" ] do
      testUnsupported WordSize.Bit64 hex

  [<TestMethod>]
  member _.``[PPC64] MFBHRBE (move from a BHRB entry)``() =
    "7ca0025c"
    ++ (MFBHRBE ** [ O.Reg R5; O.Imm 0UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] RFEBB (return from event-based branch)``() =
    "4c000124"
    ++ (RFEBB ** [ O.Imm 0UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] STQCX. (store quadword conditional indexed)``() =
    "7d46396d"
    ++ (STQCXdot ** [ O.Reg R10; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] LQ (load quadword)``() =
    "e1460010"
    ++ (LQ ** [ O.Reg R10; O.Mem(16, R6) ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] LQ with a negative displacement``() =
    "e146fff0"
    ++ (LQ ** [ O.Reg R10; O.Mem(-16, R6) ])
    ||> testOnlyPPC64

  /// The low four bits of lq are reserved, which the processor ignores (Book
  /// I 1.3.3); QEMU loads the same pair with them set.
  [<TestMethod>]
  member _.``[PPC64] LQ ignores its reserved bits``() =
    "e146001f"
    ++ (LQ ** [ O.Reg R10; O.Mem(16, R6) ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] STQ (store quadword)``() =
    "f986000a"
    ++ (STQ ** [ O.Reg R12; O.Mem(8, R6) ])
    ||> testOnlyPPC64

  /// An odd first register of the pair, and a pair that rA names too -- r0
  /// with rA = 0 among them -- are invalid forms of lq; an odd one is of stq.
  /// QEMU refuses all of them as illegal instructions.
  [<TestMethod>]
  member _.``[PPC64] LQ and STQ refuse the invalid forms``() =
    for hex in [ "e1660010"; "e0c60010"; "e0000010"; "f9a60012" ] do
      testUnsupported WordSize.Bit64 hex

  [<TestMethod>]
  member _.``[PPC64] DIVDE (extended divide)``() =
    "7ca63b52"
    ++ (DIVDE ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDE. (extended divide, CR0)``() =
    "7ca63b53"
    ++ (DIVDEdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDEO (extended divide, OV)``() =
    "7ca63f52"
    ++ (DIVDEO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDEO. (extended divide, OV, CR0)``() =
    "7ca63f53"
    ++ (DIVDEOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDEU (extended unsigned divide)``() =
    "7ca63b12"
    ++ (DIVDEU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDEU. (extended unsigned divide, CR0)``() =
    "7ca63b13"
    ++ (DIVDEUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDEUO (extended unsigned divide, OV)``() =
    "7ca63f12"
    ++ (DIVDEUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] DIVDEUO. (extended unsigned divide, OV, CR0)``() =
    "7ca63f13"
    ++ (DIVDEUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] DIVWE (extended word divide)``() =
    "7ca63b56"
    ++ (DIVWE ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DIVWE. (extended word divide, CR0)``() =
    "7ca63b57"
    ++ (DIVWEdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DIVWEO (extended word divide, OV)``() =
    "7ca63f56"
    ++ (DIVWEO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DIVWEO. (extended word divide, OV, CR0)``() =
    "7ca63f57"
    ++ (DIVWEOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DIVWEU (extended unsigned word divide)``() =
    "7ca63b16"
    ++ (DIVWEU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DIVWEU. (extended unsigned word divide, CR0)``() =
    "7ca63b17"
    ++ (DIVWEUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DIVWEUO (extended unsigned word divide, OV)``() =
    "7ca63f16"
    ++ (DIVWEUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DIVWEUO. (extended unsigned word divide, OV, CR0)``() =
    "7ca63f17"
    ++ (DIVWEUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] ADDG6S (add and generate sixes)``() =
    "7ca63894"
    ++ (ADDG6S ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] CBCDTD (convert BCD to declets)``() =
    "7d060274"
    ++ (CBCDTD ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] CDTBCD (convert declets to BCD)``() =
    "7d060234"
    ++ (CDTBCD ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] ADDEX (add extended using OV)``() =
    "7ca63954"
    ++ (ADDEX ** [ O.Reg R5; O.Reg R6; O.Reg R7; O.Imm 0UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] ADDPCIS (add PC immediate shifted)``() =
    "4ca00005"
    ++ (ADDPCIS ** [ O.Reg R5; O.Imm 1UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] CMPEQB (compare equal byte)``() =
    "7d0639c0"
    ++ (CMPEQB ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] CMPRB (compare ranged byte)``() =
    "7d063980"
    ++ (CMPRB ** [ O.Reg CR2; O.Imm 0UL; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] CNTTZD (count trailing zeros doubleword)``() =
    "7d060474"
    ++ (CNTTZD ** [ O.Reg R6; O.Reg R8 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] CNTTZD. (count trailing zeros dword, CR0)``() =
    "7d060475"
    ++ (CNTTZDdot ** [ O.Reg R6; O.Reg R8 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] CNTTZW (count trailing zeros word)``() =
    "7d060434"
    ++ (CNTTZW ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] CNTTZW. (count trailing zeros word, CR0)``() =
    "7d060435"
    ++ (CNTTZWdot ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] DARN (deliver a random number)``() =
    "7ca105e6"
    ++ (DARN ** [ O.Reg R5; O.Imm 1UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] EXTSWSLI (extend sign word, shift left)``() =
    "7d062ef4"
    ++ (EXTSWSLI ** [ O.Reg R6; O.Reg R8; O.Imm 5UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] EXTSWSLI. (extend sign word, shift, CR0)``() =
    "7d062ef5"
    ++ (EXTSWSLIdot ** [ O.Reg R6; O.Reg R8; O.Imm 5UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] MCRXRX (move to CR from XER extended)``() =
    "7d000480"
    ++ (MCRXRX ** [ O.Reg CR2 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] MODSD (modulo signed doubleword)``() =
    "7ca63e12"
    ++ (MODSD ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] MODSW (modulo signed word)``() =
    "7ca63e16"
    ++ (MODSW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] MODUD (modulo unsigned doubleword)``() =
    "7ca63a12"
    ++ (MODUD ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] MODUW (modulo unsigned word)``() =
    "7ca63a16"
    ++ (MODUW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] SETB (set boolean)``() =
    "7cac0100"
    ++ (SETB ** [ O.Reg R5; O.Reg CR3 ])
    ||> testAllPPC

  /// The reserved values: addex with CY other than 0, darn with L = 3.
  [<TestMethod>]
  member _.``[PPC64] ADDEX and DARN refuse their reserved operands``() =
    for hex in [ "7ca63b54"; "7ca63d54"; "7ca63f54"; "7ca305e6" ] do
      testUnsupported WordSize.Bit64 hex

  [<TestMethod>]
  member _.``[PPC64] BRD (byte-reverse doubleword)``() =
    "7d060176"
    ++ (BRD ** [ O.Reg R6; O.Reg R8 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] BRH (byte-reverse halfword)``() =
    "7d0601b6"
    ++ (BRH ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] BRW (byte-reverse word)``() =
    "7d060136"
    ++ (BRW ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] CFUGED (centrifuge doubleword)``() =
    "7d0639b8"
    ++ (CFUGED ** [ O.Reg R6; O.Reg R8; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] CNTLZDM (count leading zeros under a mask)``() =
    "7d063876"
    ++ (CNTLZDM ** [ O.Reg R6; O.Reg R8; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] CNTTZDM (count trailing zeros under a mask)``() =
    "7d063c76"
    ++ (CNTTZDM ** [ O.Reg R6; O.Reg R8; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] PDEPD (parallel bits deposit)``() =
    "7d063938"
    ++ (PDEPD ** [ O.Reg R6; O.Reg R8; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] PEXTD (parallel bits extract)``() =
    "7d063978"
    ++ (PEXTD ** [ O.Reg R6; O.Reg R8; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] SETBC (set boolean condition)``() =
    "7ca90300"
    ++ (SETBC ** [ O.Reg R5; O.BI 9u ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] SETBCR (set boolean condition reverse)``() =
    "7ca90340"
    ++ (SETBCR ** [ O.Reg R5; O.BI 9u ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] SETNBC (set negative boolean condition)``() =
    "7ca90380"
    ++ (SETNBC ** [ O.Reg R5; O.BI 9u ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] SETNBCR (set negative boolean condition reverse)``() =
    "7ca903c0"
    ++ (SETNBCR ** [ O.Reg R5; O.BI 9u ])
    ||> testAllPPC

  /// The reserved fields of the ISA 3.1 X forms: rB of brd, brh and brw, and
  /// of setbc and its kin.
  [<TestMethod>]
  member _.``[PPC64] The ISA 3.1 X forms refuse their reserved bits``() =
    for hex in [ "7d063976"; "7d0639b6"; "7d063936"; "7ca90b00"; "7ca90bc0" ] do
      testUnsupported WordSize.Bit64 hex

  [<TestMethod>]
  member _.``[PPC] POPCNTB (population count bytes)``() =
    "7d0600f4"
    ++ (POPCNTB ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] POPCNTW (population count words)``() =
    "7d0602f4"
    ++ (POPCNTW ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] POPCNTD (population count doubleword)``() =
    "7d0603f4"
    ++ (POPCNTD ** [ O.Reg R6; O.Reg R8 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC] PRTYW (parity word)``() =
    "7d060134"
    ++ (PRTYW ** [ O.Reg R6; O.Reg R8 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] CMPB (compare bytes)``() =
    "7d063bf8"
    ++ (CMPB ** [ O.Reg R6; O.Reg R8; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] LBARX (load byte and reserve indexed)``() =
    "7ca63868"
    ++ (LBARX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] LHARX (load halfword and reserve indexed)``() =
    "7ca638e8"
    ++ (LHARX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] STBCX. (store byte conditional indexed)``() =
    "7d063d6d"
    ++ (STBCXdot ** [ O.Reg R8; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] STHCX. (store halfword conditional indexed)``() =
    "7d063dad"
    ++ (STHCXdot ** [ O.Reg R8; O.Reg R6; O.Reg R7 ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DCBT with a TH hint``() =
    "7e063a2c"
    ++ (DCBT ** [ O.Reg R6; O.Reg R7; O.Imm 16UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DCBTST with a TH hint``() =
    "7c2639ec"
    ++ (DCBTST ** [ O.Reg R6; O.Reg R7; O.Imm 1UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DCBF with L = 1 (dcbfl)``() =
    "7c2638ac"
    ++ (DCBF ** [ O.Reg R6; O.Reg R7; O.Imm 1UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DCBF with L = 3 (dcbflp)``() =
    "7c6638ac"
    ++ (DCBF ** [ O.Reg R6; O.Reg R7; O.Imm 3UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DCBF with L = 4 (dcbfps)``() =
    "7c8638ac"
    ++ (DCBF ** [ O.Reg R6; O.Reg R7; O.Imm 4UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] DCBF with L = 6 (dcbstps)``() =
    "7cc638ac"
    ++ (DCBF ** [ O.Reg R6; O.Reg R7; O.Imm 6UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] PTESYNC (sync 2,0)``() =
    "7c4004ac"
    ++ (PTESYNC ** [])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] PHWSYNC (sync 4,0)``() =
    "7c8004ac"
    ++ (PHWSYNC ** [])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] PLWSYNC (sync 5,0)``() =
    "7ca004ac"
    ++ (PLWSYNC ** [])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] STNCISYNC (sync 1,1)``() =
    "7c2104ac"
    ++ (STNCISYNC ** [])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] STCISYNC (sync 0,2)``() =
    "7c0204ac"
    ++ (STCISYNC ** [])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] STSYNC (sync 0,3)``() =
    "7c0304ac"
    ++ (STSYNC ** [])
    ||> testAllPPC

  /// <summary>
  /// The invalid forms of dcbf and sync: an L of 2, 5 or 7 for dcbf, which
  /// the ISA reserves; the combinations of L and SC Figure 5 of Book II does
  /// not list for sync; and a reserved bit set in either. QEMU refuses them
  /// all but sync 3,0, which it reads as a two-bit L.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC] DCBF and SYNC refuse their invalid forms``() =
    let words =
      [ "7c4638ac"
        "7ca638ac"
        "7ce638ac"
        "7d0638ac"
        "7c6004ac"
        "7cc004ac"
        "7c0104ac"
        "7c2204ac"
        "7c200cac"
        "7d0004ac" ]
    for hex in words do
      testUnsupported WordSize.Bit64 hex
      testUnsupported WordSize.Bit32 hex

  [<TestMethod>]
  member _.``[PPC] MFSPR of DSCR (mfudscr)``() =
    "7ca302a6"
    ++ (MFSPR ** [ O.Reg R5; O.Imm 3UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] MFSPR of AMR (mfuamr)``() =
    "7cad02a6"
    ++ (MFSPR ** [ O.Reg R5; O.Imm 13UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] MFSPR of CTRL (mfctrl)``() =
    "7ca822a6"
    ++ (MFSPR ** [ O.Reg R5; O.Imm 136UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] MFSPR of SPRG3 (mfusprg3)``() =
    "7ca342a6"
    ++ (MFSPR ** [ O.Reg R5; O.Imm 259UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] MFSPR of the reserved SPR 808``() =
    "7ca8caa6"
    ++ (MFSPR ** [ O.Reg R5; O.Imm 808UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] MFSPR of PPR (mfppr)``() =
    "7ca0e2a6"
    ++ (MFSPR ** [ O.Reg R5; O.Imm 896UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC] MFSPR of PPR32 (mfppr32)``() =
    "7ca2e2a6"
    ++ (MFSPR ** [ O.Reg R5; O.Imm 898UL ])
    ||> testAllPPC

  [<TestMethod>]
  member _.``[PPC64] LWAT (load word atomic)``() =
    "7d46048c"
    ++ (LWAT ** [ O.Reg R10; O.Reg R6; O.Imm 0UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] LDAT (load doubleword atomic)``() =
    "7d46c4cc"
    ++ (LDAT ** [ O.Reg R10; O.Reg R6; O.Imm 24UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] STWAT (store word atomic)``() =
    "7d66058c"
    ++ (STWAT ** [ O.Reg R11; O.Reg R6; O.Imm 0UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] STDAT (store doubleword atomic)``() =
    "7d66c5cc"
    ++ (STDAT ** [ O.Reg R11; O.Reg R6; O.Imm 24UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] COPY (copy a block to the copy buffer)``() =
    "7c263e0c"
    ++ (COPY ** [ O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] PASTE (paste the copy buffer)``() =
    "7c263f0c"
    ++ (PASTE ** [ O.Reg R6; O.Reg R7; O.Imm 1UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] PASTE. (paste the copy buffer, recording)``() =
    "7c263f0d"
    ++ (PASTEdot ** [ O.Reg R6; O.Reg R7; O.Imm 1UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] CPABORT (copy-paste abort)``() =
    "7c00068c"
    ++ (CPABORT ** [])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] WAIT (wait 0,0)``() =
    "7c00003c"
    ++ (WAIT ** [ O.Imm 0UL; O.Imm 0UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] WAIT with WC = 2 (pause_short)``() =
    "7c40003c"
    ++ (WAIT ** [ O.Imm 2UL; O.Imm 0UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] SCV (system call vectored)``() =
    "44000001"
    ++ (SCV ** [ O.Imm 0UL ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] SCV with LEV = 1``() =
    "44000021"
    ++ (SCV ** [ O.Imm 1UL ])
    ||> testOnlyPPC64

  /// <summary>
  /// The invalid forms: copy with bit 10 clear, which v3.1 fixes at 1; wait
  /// with WC = 3, a reserved value; and cpabort with a reserved field set.
  /// </summary>
  [<TestMethod>]
  member _.``[PPC64] COPY, WAIT and CPABORT refuse their invalid forms``() =
    for hex in [ "7c063e0c"; "7c60003c"; "7c06068c" ] do
      testUnsupported WordSize.Bit64 hex

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

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
    | 0 ->
      NoOperand
    | 1 ->
      OneOperand oprArr[0]
    | 2 ->
      TwoOperands(oprArr[0], oprArr[1])
    | 3 ->
      ThreeOperands(oprArr[0], oprArr[1], oprArr[2])
    | 4 ->
      FourOperands(oprArr[0], oprArr[1], oprArr[2], oprArr[3])
    | 5 ->
      FiveOperands(oprArr[0], oprArr[1], oprArr[2], oprArr[3], oprArr[4])
    | _ ->
      Terminator.futureFeature ()

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
    ++ (PASTE ** [ O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] PASTE. (paste the copy buffer, recording)``() =
    "7c263f0d"
    ++ (PASTEdot ** [ O.Reg R6; O.Reg R7 ])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] CPABORT (copy-paste abort)``() =
    "7c00068c"
    ++ (CPABORT ** [])
    ||> testOnlyPPC64

  [<TestMethod>]
  member _.``[PPC64] WAIT (wait 0,0)``() =
    "7c00003c"
    ++ (WAIT ** [])
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

/// What lane E's tests check a word against: processors whose categories
/// read it, which the ISA's flags name.
[<AutoOpen>]
module private LegacyShortcut =
  /// A PowerPC ISA of the given byte order and word size whose flags name
  /// the given categories.
  let isaOf endian wordSize (category: Category) =
    ISA(Architecture.PPC, endian, wordSize, int category)

  /// Decodes a word, given most significant byte first, on the processor an
  /// ISA names.
  let parse (isa: ISA) (hex: string) =
    let word = ByteArray.ofHexString hex
    let bytes = if isa.Endian = Endian.Big then word else Array.rev word
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    parser.Parse(System.ReadOnlySpan(bytes: byte[]), 0UL) :?> Instruction

  /// The three processors a word is read on: 32-bit and 64-bit big-endian,
  /// and 64-bit little-endian.
  let targets =
    [ Endian.Big, WordSize.Bit32
      Endian.Big, WordSize.Bit64
      Endian.Little, WordSize.Bit64 ]

  /// Asserts what a word decodes to on each target with the categories
  /// given.
  let testCategory category hex (opcode: Opcode, operands: Operands) =
    for endian, wordSize in targets do
      let ins = parse (isaOf endian wordSize category) hex
      Assert.AreEqual<Opcode>(opcode, ins.Opcode)
      Assert.AreEqual<Operands>(operands, ins.Operands)

  /// What a word is on a server processor, or InvalOP where it is nothing.
  let serverReading hex =
    let isa = isaOf Endian.Big WordSize.Bit32 Category.Server
    try (parse isa hex).Opcode with :? ParsingFailureException -> InvalOP

  /// Asserts what a word of primary opcode 31 decodes to where the Legacy
  /// Move Assist category is, and that the server reading, which gives such a
  /// word with rS and rA zero to msgsndu, is not that.
  let testMoveAssist hex (opcode, operands) =
    testCategory Category.LegacyMoveAssist hex (opcode, operands)
    Assert.AreNotEqual<Opcode>(opcode, serverReading hex)

  /// Asserts what a word of primary opcode 4 decodes to where the Legacy
  /// Integer Multiply-Accumulate category takes the opcode, and that the
  /// server reading, which gives it to the vector facility, is not that.
  let testLegacyMultiply hex (opcode, operands) =
    let category = Category.LegacyIntegerMultiplyAccumulate
    testCategory category hex (opcode, operands)
    Assert.AreNotEqual<Opcode>(opcode, serverReading hex)

/// The instructions of the Power ISA 2.07B categories 3.1 dropped: each word
/// is the one binutils assembles for the processor that has the category
/// (objdump -M440 for the multiply-accumulates), decoded on every target.
[<TestClass>]
type LegacyParserTests() =
  [<TestMethod>]
  member _.``[PPC] MACCHW (legacy multiply-accumulate)``() =
    MACCHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63958"

  [<TestMethod>]
  member _.``[PPC] MACCHW. (legacy multiply-accumulate)``() =
    MACCHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63959"

  [<TestMethod>]
  member _.``[PPC] MACCHWO (legacy multiply-accumulate)``() =
    MACCHWO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63d58"

  [<TestMethod>]
  member _.``[PPC] MACCHWO. (legacy multiply-accumulate)``() =
    MACCHWOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63d59"

  [<TestMethod>]
  member _.``[PPC] MACCHWS (legacy multiply-accumulate)``() =
    MACCHWS ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a639d8"

  [<TestMethod>]
  member _.``[PPC] MACCHWS. (legacy multiply-accumulate)``() =
    MACCHWSdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a639d9"

  [<TestMethod>]
  member _.``[PPC] MACCHWSO (legacy multiply-accumulate)``() =
    MACCHWSO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63dd8"

  [<TestMethod>]
  member _.``[PPC] MACCHWSO. (legacy multiply-accumulate)``() =
    MACCHWSOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63dd9"

  [<TestMethod>]
  member _.``[PPC] MACCHWSU (legacy multiply-accumulate)``() =
    MACCHWSU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63998"

  [<TestMethod>]
  member _.``[PPC] MACCHWSU. (legacy multiply-accumulate)``() =
    MACCHWSUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63999"

  [<TestMethod>]
  member _.``[PPC] MACCHWSUO (legacy multiply-accumulate)``() =
    MACCHWSUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63d98"

  [<TestMethod>]
  member _.``[PPC] MACCHWSUO. (legacy multiply-accumulate)``() =
    MACCHWSUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63d99"

  [<TestMethod>]
  member _.``[PPC] MACCHWU (legacy multiply-accumulate)``() =
    MACCHWU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63918"

  [<TestMethod>]
  member _.``[PPC] MACCHWU. (legacy multiply-accumulate)``() =
    MACCHWUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63919"

  [<TestMethod>]
  member _.``[PPC] MACCHWUO (legacy multiply-accumulate)``() =
    MACCHWUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63d18"

  [<TestMethod>]
  member _.``[PPC] MACCHWUO. (legacy multiply-accumulate)``() =
    MACCHWUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63d19"

  [<TestMethod>]
  member _.``[PPC] NMACCHW (legacy negative multiply-accumulate)``() =
    NMACCHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a6395c"

  [<TestMethod>]
  member _.``[PPC] NMACCHW. (legacy negative multiply-accumulate)``() =
    NMACCHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a6395d"

  [<TestMethod>]
  member _.``[PPC] NMACCHWO (legacy negative multiply-accumulate)``() =
    NMACCHWO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63d5c"

  [<TestMethod>]
  member _.``[PPC] NMACCHWO. (legacy negative multiply-accumulate)``() =
    NMACCHWOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63d5d"

  [<TestMethod>]
  member _.``[PPC] NMACCHWS (legacy negative multiply-accumulate)``() =
    NMACCHWS ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a639dc"

  [<TestMethod>]
  member _.``[PPC] NMACCHWS. (legacy negative multiply-accumulate)``() =
    NMACCHWSdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a639dd"

  [<TestMethod>]
  member _.``[PPC] NMACCHWSO (legacy negative multiply-accumulate)``() =
    NMACCHWSO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63ddc"

  [<TestMethod>]
  member _.``[PPC] NMACCHWSO. (legacy negative multiply-accumulate)``() =
    NMACCHWSOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63ddd"

  [<TestMethod>]
  member _.``[PPC] MULCHW (legacy halfword multiply)``() =
    MULCHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63950"

  [<TestMethod>]
  member _.``[PPC] MULCHW. (legacy halfword multiply)``() =
    MULCHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63951"

  [<TestMethod>]
  member _.``[PPC] MULCHWU (legacy halfword multiply)``() =
    MULCHWU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63910"

  [<TestMethod>]
  member _.``[PPC] MULCHWU. (legacy halfword multiply)``() =
    MULCHWUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63911"

  [<TestMethod>]
  member _.``[PPC] MACHHW (legacy multiply-accumulate)``() =
    MACHHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63858"

  [<TestMethod>]
  member _.``[PPC] MACHHW. (legacy multiply-accumulate)``() =
    MACHHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63859"

  [<TestMethod>]
  member _.``[PPC] MACHHWO (legacy multiply-accumulate)``() =
    MACHHWO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63c58"

  [<TestMethod>]
  member _.``[PPC] MACHHWO. (legacy multiply-accumulate)``() =
    MACHHWOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63c59"

  [<TestMethod>]
  member _.``[PPC] MACHHWS (legacy multiply-accumulate)``() =
    MACHHWS ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a638d8"

  [<TestMethod>]
  member _.``[PPC] MACHHWS. (legacy multiply-accumulate)``() =
    MACHHWSdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a638d9"

  [<TestMethod>]
  member _.``[PPC] MACHHWSO (legacy multiply-accumulate)``() =
    MACHHWSO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63cd8"

  [<TestMethod>]
  member _.``[PPC] MACHHWSO. (legacy multiply-accumulate)``() =
    MACHHWSOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63cd9"

  [<TestMethod>]
  member _.``[PPC] MACHHWSU (legacy multiply-accumulate)``() =
    MACHHWSU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63898"

  [<TestMethod>]
  member _.``[PPC] MACHHWSU. (legacy multiply-accumulate)``() =
    MACHHWSUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63899"

  [<TestMethod>]
  member _.``[PPC] MACHHWSUO (legacy multiply-accumulate)``() =
    MACHHWSUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63c98"

  [<TestMethod>]
  member _.``[PPC] MACHHWSUO. (legacy multiply-accumulate)``() =
    MACHHWSUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63c99"

  [<TestMethod>]
  member _.``[PPC] MACHHWU (legacy multiply-accumulate)``() =
    MACHHWU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63818"

  [<TestMethod>]
  member _.``[PPC] MACHHWU. (legacy multiply-accumulate)``() =
    MACHHWUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63819"

  [<TestMethod>]
  member _.``[PPC] MACHHWUO (legacy multiply-accumulate)``() =
    MACHHWUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63c18"

  [<TestMethod>]
  member _.``[PPC] MACHHWUO. (legacy multiply-accumulate)``() =
    MACHHWUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63c19"

  [<TestMethod>]
  member _.``[PPC] NMACHHW (legacy negative multiply-accumulate)``() =
    NMACHHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a6385c"

  [<TestMethod>]
  member _.``[PPC] NMACHHW. (legacy negative multiply-accumulate)``() =
    NMACHHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a6385d"

  [<TestMethod>]
  member _.``[PPC] NMACHHWO (legacy negative multiply-accumulate)``() =
    NMACHHWO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63c5c"

  [<TestMethod>]
  member _.``[PPC] NMACHHWO. (legacy negative multiply-accumulate)``() =
    NMACHHWOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63c5d"

  [<TestMethod>]
  member _.``[PPC] NMACHHWS (legacy negative multiply-accumulate)``() =
    NMACHHWS ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a638dc"

  [<TestMethod>]
  member _.``[PPC] NMACHHWS. (legacy negative multiply-accumulate)``() =
    NMACHHWSdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a638dd"

  [<TestMethod>]
  member _.``[PPC] NMACHHWSO (legacy negative multiply-accumulate)``() =
    NMACHHWSO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63cdc"

  [<TestMethod>]
  member _.``[PPC] NMACHHWSO. (legacy negative multiply-accumulate)``() =
    NMACHHWSOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63cdd"

  [<TestMethod>]
  member _.``[PPC] MULHHW (legacy halfword multiply)``() =
    MULHHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63850"

  [<TestMethod>]
  member _.``[PPC] MULHHW. (legacy halfword multiply)``() =
    MULHHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63851"

  [<TestMethod>]
  member _.``[PPC] MULHHWU (legacy halfword multiply)``() =
    MULHHWU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63810"

  [<TestMethod>]
  member _.``[PPC] MULHHWU. (legacy halfword multiply)``() =
    MULHHWUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63811"

  [<TestMethod>]
  member _.``[PPC] MACLHW (legacy multiply-accumulate)``() =
    MACLHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b58"

  [<TestMethod>]
  member _.``[PPC] MACLHW. (legacy multiply-accumulate)``() =
    MACLHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b59"

  [<TestMethod>]
  member _.``[PPC] MACLHWO (legacy multiply-accumulate)``() =
    MACLHWO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63f58"

  [<TestMethod>]
  member _.``[PPC] MACLHWO. (legacy multiply-accumulate)``() =
    MACLHWOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63f59"

  [<TestMethod>]
  member _.``[PPC] MACLHWS (legacy multiply-accumulate)``() =
    MACLHWS ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63bd8"

  [<TestMethod>]
  member _.``[PPC] MACLHWS. (legacy multiply-accumulate)``() =
    MACLHWSdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63bd9"

  [<TestMethod>]
  member _.``[PPC] MACLHWSO (legacy multiply-accumulate)``() =
    MACLHWSO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63fd8"

  [<TestMethod>]
  member _.``[PPC] MACLHWSO. (legacy multiply-accumulate)``() =
    MACLHWSOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63fd9"

  [<TestMethod>]
  member _.``[PPC] MACLHWSU (legacy multiply-accumulate)``() =
    MACLHWSU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b98"

  [<TestMethod>]
  member _.``[PPC] MACLHWSU. (legacy multiply-accumulate)``() =
    MACLHWSUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b99"

  [<TestMethod>]
  member _.``[PPC] MACLHWSUO (legacy multiply-accumulate)``() =
    MACLHWSUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63f98"

  [<TestMethod>]
  member _.``[PPC] MACLHWSUO. (legacy multiply-accumulate)``() =
    MACLHWSUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63f99"

  [<TestMethod>]
  member _.``[PPC] MACLHWU (legacy multiply-accumulate)``() =
    MACLHWU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b18"

  [<TestMethod>]
  member _.``[PPC] MACLHWU. (legacy multiply-accumulate)``() =
    MACLHWUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b19"

  [<TestMethod>]
  member _.``[PPC] MACLHWUO (legacy multiply-accumulate)``() =
    MACLHWUO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63f18"

  [<TestMethod>]
  member _.``[PPC] MACLHWUO. (legacy multiply-accumulate)``() =
    MACLHWUOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63f19"

  [<TestMethod>]
  member _.``[PPC] NMACLHW (legacy negative multiply-accumulate)``() =
    NMACLHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b5c"

  [<TestMethod>]
  member _.``[PPC] NMACLHW. (legacy negative multiply-accumulate)``() =
    NMACLHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b5d"

  [<TestMethod>]
  member _.``[PPC] NMACLHWO (legacy negative multiply-accumulate)``() =
    NMACLHWO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63f5c"

  [<TestMethod>]
  member _.``[PPC] NMACLHWO. (legacy negative multiply-accumulate)``() =
    NMACLHWOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63f5d"

  [<TestMethod>]
  member _.``[PPC] NMACLHWS (legacy negative multiply-accumulate)``() =
    NMACLHWS ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63bdc"

  [<TestMethod>]
  member _.``[PPC] NMACLHWS. (legacy negative multiply-accumulate)``() =
    NMACLHWSdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63bdd"

  [<TestMethod>]
  member _.``[PPC] NMACLHWSO (legacy negative multiply-accumulate)``() =
    NMACLHWSO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63fdc"

  [<TestMethod>]
  member _.``[PPC] NMACLHWSO. (legacy negative multiply-accumulate)``() =
    NMACLHWSOdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63fdd"

  [<TestMethod>]
  member _.``[PPC] MULLHW (legacy halfword multiply)``() =
    MULLHW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b50"

  [<TestMethod>]
  member _.``[PPC] MULLHW. (legacy halfword multiply)``() =
    MULLHWdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b51"

  [<TestMethod>]
  member _.``[PPC] MULLHWU (legacy halfword multiply)``() =
    MULLHWU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b10"

  [<TestMethod>]
  member _.``[PPC] MULLHWU. (legacy halfword multiply)``() =
    MULLHWUdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testLegacyMultiply "10a63b11"

  [<TestMethod>]
  member _.``[PPC] DLMZB (determine leftmost zero byte)``() =
    DLMZB ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testMoveAssist "7cc5389c"
    (* with rS and rA zero it is the word msgsndu is on a server processor *)
    DLMZB ** [ O.Reg R0; O.Reg R0; O.Reg R7 ]
    |> testMoveAssist "7c00389c"

  [<TestMethod>]
  member _.``[PPC] DLMZB. (determine leftmost zero byte)``() =
    DLMZBdot ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testMoveAssist "7cc5389d"

/// The instructions the embedded environment adds to primary opcode 31
/// (Power ISA 2.07B Book II and Book III-E), each word the one binutils
/// assembles for the processor that has the category (-me500mc, -me6500
/// where the e500mc has no such instruction). No server instruction has these
/// encodings, so each is read the same on every processor.
[<TestClass>]
type EmbeddedParserTests() =
  [<TestMethod>]
  member _.``[PPC] DCBLC (data cache block lock clear)``() =
    "7c263b0c"
    ++ (DCBLC ** [ O.Imm 1UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] DCBLQ. (data cache block lock query)``() =
    "7c263b4d"
    ++ (DCBLQdot ** [ O.Imm 1UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] DCBTLS (data cache block touch and lock set)``() =
    "7c46394c"
    ++ (DCBTLS ** [ O.Imm 2UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] DCBTSTLS (data cache block touch for store, lock set)``() =
    "7c46390c"
    ++ (DCBTSTLS ** [ O.Imm 2UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] ICBLC (instruction cache block lock clear)``() =
    "7c2639cc"
    ++ (ICBLC ** [ O.Imm 1UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] ICBLQ. (instruction cache block lock query)``() =
    "7c26398d"
    ++ (ICBLQdot ** [ O.Imm 1UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] ICBTLS (instruction cache block touch and lock set)``() =
    "7c463bcc"
    ++ (ICBTLS ** [ O.Imm 2UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] cache locking with a reserved bit wrong is refused``() =
    (* bit 6 set; the record bit set on a form without one, and clear on a
       query, which has one *)
    for hex in
      [ "7e263b0c"
        "7c263b0d"
        "7c263b4c"
        "7e46394c"
        "7c46394d"
        "7e46390c"
        "7c46390d"
        "7e2639cc"
        "7c2639cd"
        "7c26398c"
        "7e26398d"
        "7e463bcc"
        "7c463bcd"
        "7e263b4d" ] do
      testUnsupported WordSize.Bit32 hex
      testUnsupported WordSize.Bit64 hex

  /// What a word of primary opcode 31 that a server processor reads as eieio
  /// is on a processor with the embedded environment, and that the two
  /// readings differ.
  [<TestMethod>]
  member _.``[PPC] MBAR (memory barrier)``() =
    for hex, mo in [ "7c0006ac", 0UL; "7c2006ac", 1UL; "7fe006ac", 31UL ] do
      testCategory Category.Embedded hex (MBAR ** [ O.Imm mo ])
      Assert.AreNotEqual<Opcode>(MBAR, serverReading hex)
    Assert.AreEqual<Opcode>(EIEIO, serverReading "7c0006ac")

  /// mbar's reserved bits are refused, as eieio's are.
  [<TestMethod>]
  member _.``[PPC] MBAR with a reserved bit set is refused``() =
    for hex in [ "7c2106ac"; "7c2006ad"; "7c20f6ac" ] do
      let isa = isaOf Endian.Big WordSize.Bit32 Category.Embedded
      Assert.Throws<ParsingFailureException>(fun () -> parse isa hex |> ignore)
      |> ignore

  [<TestMethod>]
  member _.``[PPC] DNH (debugger notify halt)``() =
    "4c20118c"
    ++ (DNH ** [ O.Imm 1UL; O.Imm 2UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] EHPRIV (embedded hypervisor privilege)``() =
    "7c00021c"
    ++ (EHPRIV ** [ O.Imm 0UL ])
    ||> testEveryTarget
    "7c002a1c"
    ++ (EHPRIV ** [ O.Imm 5UL ])
    ||> testEveryTarget
    "7ffffa1c"
    ++ (EHPRIV ** [ O.Imm 0x7fffUL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MFPMR (move from performance monitor register)``() =
    "7cb0029c"
    ++ (MFPMR ** [ O.Reg R5; O.Imm 16UL ])
    ||> testEveryTarget
    (* pmrn 400 is the two halves 0b01100 and 0b10000 *)
    "7cb0629c"
    ++ (MFPMR ** [ O.Reg R5; O.Imm 400UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTPMR (move to performance monitor register)``() =
    "7cb0039c"
    ++ (MTPMR ** [ O.Imm 16UL; O.Reg R5 ])
    ||> testEveryTarget
    "7cb0639c"
    ++ (MTPMR ** [ O.Imm 400UL; O.Reg R5 ])
    ||> testEveryTarget

  /// The operands of mfdcrux are rT, rA.
  [<TestMethod>]
  member _.``[PPC] MFDCRUX (move from device control register)``() =
    "7ca60246"
    ++ (MFDCRUX ** [ O.Reg R5; O.Reg R6 ])
    ||> testEveryTarget

  /// objdump writes the operands of mtdcrux rA, rS, the manual rS, rA; the
  /// word has rS = r6 and rA = r5.
  [<TestMethod>]
  member _.``[PPC] MTDCRUX (move to device control register)``() =
    "7cc50346"
    ++ (MTDCRUX ** [ O.Reg R5; O.Reg R6 ])
    ||> testEveryTarget

  /// xnop is xori 0, 0, 0, as nop is ori 0, 0, 0, and any other xori is not.
  [<TestMethod>]
  member _.``[PPC] XNOP (executed no-op)``() =
    "68000000"
    ++ (XNOP ** [])
    ||> testEveryTarget
    "68000001"
    ++ (XORI ** [ O.Reg R0; O.Reg R0; O.Imm 1UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] DCBA (data cache block allocate)``() =
    "7c063dec"
    ++ (DCBA ** [ O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MCRXR (move to condition register from XER)``() =
    "7d800400"
    ++ (MCRXR ** [ O.Reg CR3 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] ECIWX (external control in word indexed)``() =
    "7ca63a6c"
    ++ (ECIWX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] ECOWX (external control out word indexed)``() =
    "7ca63b6c"
    ++ (ECOWX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] LBDX (load byte with decoration indexed)``() =
    "7ca63c06"
    ++ (LBDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] LHDX (load halfword with decoration indexed)``() =
    "7ca63c46"
    ++ (LHDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] LWDX (load word with decoration indexed)``() =
    "7ca63c86"
    ++ (LWDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  /// The doubleword forms of decorated storage are the 64-bit category's.
  [<TestMethod>]
  member _.``[PPC] LDDX (load doubleword with decoration indexed)``() =
    "7ca63cc6"
    ++ (LDDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] LFDDX (load floating doubleword, decorated)``() =
    "7ca63e46"
    ++ (LFDDX ** [ O.Reg F5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] STBDX (store byte with decoration indexed)``() =
    "7ca63d06"
    ++ (STBDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] STHDX (store halfword with decoration indexed)``() =
    "7ca63d46"
    ++ (STHDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] STWDX (store word with decoration indexed)``() =
    "7ca63d86"
    ++ (STWDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] STDDX (store doubleword with decoration indexed)``() =
    "7ca63dc6"
    ++ (STDDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ])
    ||> test64Only

  [<TestMethod>]
  member _.``[PPC] STFDDX (store floating doubleword, decorated)``() =
    "7ca63f46"
    ++ (STFDDX ** [ O.Reg F5; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] DSN (decorated storage notify)``() =
    "7c063bc6"
    ++ (DSN ** [ O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  /// Bit 31 is reserved in every decorated access, and so is the field above
  /// rA in dsn.
  [<TestMethod>]
  member _.``[PPC] decorated storage with a reserved bit set is refused``() =
    for hex in
      [ "7ca63c07"
        "7ca63c47"
        "7ca63c87"
        "7ca63cc7"
        "7ca63e47"
        "7ca63d07"
        "7ca63d47"
        "7ca63d87"
        "7ca63dc7"
        "7ca63f47"
        "7c063bc7"
        "7ca63bc6" ] do
      testUnsupported WordSize.Bit32 hex
      testUnsupported WordSize.Bit64 hex

/// The instructions of the Transactional Memory category (Power ISA 2.07B Book
/// II chapter 5), each word the one binutils assembles for POWER8. No server
/// instruction shares their encodings, so each reads the same on every
/// processor.
[<TestClass>]
type TransactionParserTests() =
  /// A word with a signed five-bit immediate, which reads as the number at the
  /// width of the processor's registers: the same bits, on each target.
  let testImmediate hex opcode (ct: uint64) ra (si: int) =
    for wordSz, endian, wide in
      [ WordSize.Bit32, Endian.Big, 0xffffffffUL
        WordSize.Bit64, Endian.Big, 0xffffffffffffffffUL
        WordSize.Bit64, Endian.Little, 0xffffffffffffffffUL ] do
      let isa = ISA(Architecture.PPC, endian, wordSz)
      let bytes = ByteArray.ofHexString hex
      let inMemory = if endian = Endian.Big then bytes else Array.rev bytes
      let low = uint64 (si &&& 31)
      let value = if si < 0 then ((wide <<< 5) &&& wide) ||| low else low
      let operands = operandsFromArray [ O.Imm ct; O.Reg ra; O.Imm value ]
      test isa opcode operands inMemory

  [<TestMethod>]
  member _.``[PPC] TBEGIN. (transaction begin)``() =
    "7c20051d"
    ++ (TBEGINdot ** [ O.Imm 1UL ])
    ||> testEveryTarget
    "7c00051d"
    ++ (TBEGINdot ** [ O.Imm 0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] TEND. (transaction end)``() =
    "7e00055d"
    ++ (TENDdot ** [ O.Imm 1UL ])
    ||> testEveryTarget
    "7c00055d"
    ++ (TENDdot ** [ O.Imm 0UL ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] TABORT. (transaction abort)``() =
    "7c05071d"
    ++ (TABORTdot ** [ O.Reg R5 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] TABORTDC. (transaction abort doubleword conditional)``() =
    "7ca63e5d"
    ++ (TABORTDCdot ** [ O.Imm 5UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] TABORTDCI. (abort doubleword conditional immediate)``() =
    testImmediate "7ca6cedd" TABORTDCIdot 5UL R6 (-7)
    testImmediate "7ca61edd" TABORTDCIdot 5UL R6 3

  [<TestMethod>]
  member _.``[PPC] TABORTWC. (transaction abort word conditional)``() =
    "7ca63e1d"
    ++ (TABORTWCdot ** [ O.Imm 5UL; O.Reg R6; O.Reg R7 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] TABORTWCI. (abort word conditional immediate)``() =
    testImmediate "7ca6ce9d" TABORTWCIdot 5UL R6 (-7)
    testImmediate "7ca61e9d" TABORTWCIdot 5UL R6 3
    testImmediate "7ca6869d" TABORTWCIdot 5UL R6 (-16)

  [<TestMethod>]
  member _.``[PPC] TCHECK (transaction check)``() =
    "7d00059c"
    ++ (TCHECK ** [ O.Reg CR2 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] TSR. (transaction suspend or resume)``() =
    "7c2005dd"
    ++ (TSRdot ** [ O.Imm 1UL ])
    ||> testEveryTarget
    "7c0005dd"
    ++ (TSRdot ** [ O.Imm 0UL ])
    ||> testEveryTarget

  /// A reserved bit set, or a record bit wrong (tcheck has none, every other
  /// form has one), makes the word nothing.
  [<TestMethod>]
  member _.``[PPC] reserved bits of transactional words are checked``() =
    for hex in
      [ "7e20051d"
        "7c20051c"
        "7c20851d"
        "7c20055d"
        "7e00055c"
        "7c00455d"
        "7c05871d"
        "7ca5071d"
        "7c05071c"
        "7ca63e5c"
        "7ca63e1c"
        "7ca6cedc"
        "7ca6ce9c"
        "7d00059d"
        "7d40059c"
        "7d00859c"
        "7c2005dc"
        "7e2005dd" ] do
      testUnsupported WordSize.Bit32 hex
      testUnsupported WordSize.Bit64 hex

  [<TestMethod>]
  member _.``[PPC] MFTFHAR (move from TFHAR)``() =
    "7ca022a6"
    ++ (MFTFHAR ** [ O.Reg R5 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MFTFIAR (move from TFIAR)``() =
    "7ca122a6"
    ++ (MFTFIAR ** [ O.Reg R5 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MFTEXASR (move from TEXASR)``() =
    "7ca222a6"
    ++ (MFTEXASR ** [ O.Reg R5 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MFTEXASRU (move from TEXASRU)``() =
    "7ca322a6"
    ++ (MFTEXASRU ** [ O.Reg R5 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTTFHAR (move to TFHAR)``() =
    "7ca023a6"
    ++ (MTTFHAR ** [ O.Reg R5 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTTFIAR (move to TFIAR)``() =
    "7ca123a6"
    ++ (MTTFIAR ** [ O.Reg R5 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTTEXASR (move to TEXASR)``() =
    "7ca223a6"
    ++ (MTTEXASR ** [ O.Reg R5 ])
    ||> testEveryTarget

  [<TestMethod>]
  member _.``[PPC] MTTEXASRU (move to TEXASRU)``() =
    "7ca323a6"
    ++ (MTTEXASRU ** [ O.Reg R5 ])
    ||> testEveryTarget

  /// Any other special register is not the category's, and the word is what it
  /// was: mfspr of SPR 272 and of the XER, and the reserved bit of an mfspr
  /// of SPR 128, which is refused.
  [<TestMethod>]
  member _.``[PPC] only SPRs 128 to 131 are the category's``() =
    "7cb042a6"
    ++ (MFSPR ** [ O.Reg R5; O.Imm 272UL ])
    ||> testEveryTarget
    "7ca102a6"
    ++ (MFXER ** [ O.Reg R5 ])
    ||> testEveryTarget
    testUnsupported WordSize.Bit32 "7ca022a7"
    testUnsupported WordSize.Bit64 "7ca022a7"

(* Lane S: the Signal Processing Engine. *)

/// What lane S's tests read a word as: a processor with the Signal
/// Processing Engine, which the ISA's flags name.
[<AutoOpen>]
module private SignalProcessingShortcut =
  /// The four processors a word is read on: 32-bit and 64-bit, each in either
  /// byte order.
  let processors =
    [ Endian.Big, WordSize.Bit32
      Endian.Little, WordSize.Bit32
      Endian.Big, WordSize.Bit64
      Endian.Little, WordSize.Bit64 ]

  /// The categories of a processor with the engine.
  let engine = int Category.SignalProcessing

  /// What a word is on a processor of the given byte order and word size
  /// whose categories include the Signal Processing Engine.
  let engineParse (endian: Endian) wordSize (hex: string) =
    let isa = ISA(Architecture.PPC, endian, wordSize, engine)
    let word = ByteArray.ofHexString hex
    let bytes = if endian = Endian.Big then word else Array.rev word
    let parser = Parser(isa, BinReader.Init endian) :> IInstructionParsable
    parser.Parse(System.ReadOnlySpan(bytes: byte[]), 0UL) :?> Instruction

  /// What a word is on a server processor, or InvalOP where it is nothing.
  let serverOpcode (hex: string) =
    let isa = ISA(Architecture.PPC, Endian.Big, WordSize.Bit32)
    let parser = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    try
      let span = System.ReadOnlySpan(ByteArray.ofHexString hex)
      (parser.Parse(span, 0UL) :?> Instruction).Opcode
    with :? ParsingFailureException ->
      InvalOP

  /// Asserts what a word decodes to on every processor with the engine, and
  /// that the server reading, which gives primary opcode 4 to the vector
  /// facility, is something else.
  let testEngine (hex: string) (opcode: Opcode, operands: Operands) =
    for endian, wordSize in processors do
      let ins = engineParse endian wordSize hex
      Assert.AreEqual<Opcode>(opcode, ins.Opcode)
      Assert.AreEqual<Operands>(operands, ins.Operands)
    Assert.AreNotEqual<Opcode>(opcode, serverOpcode hex)

/// The instructions of the Signal Processing Engine: each word is the one GNU
/// as encodes for the e500 (objdump -M e500 reads it back), decoded on every
/// processor with the engine.
[<TestClass>]
type SignalProcessingParserTests() =

  [<TestMethod>]
  member _.``[PPC] EVADDIW (Add Immediate Word)``() =
    EVADDIW ** [ O.Reg R5; O.Reg R7; O.Imm 0xcUL ]
    |> testEngine "10ac3a02"

  [<TestMethod>]
  member _.``[PPC] EVADDW (Add Word)``() =
    EVADDW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a00"

  [<TestMethod>]
  member _.``[PPC] EVAND (AND)``() =
    EVAND ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a11"

  [<TestMethod>]
  member _.``[PPC] EVANDC (AND with Complement)``() =
    EVANDC ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a12"

  [<TestMethod>]
  member _.``[PPC] EVEQV (Equivalent)``() =
    EVEQV ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a19"

  [<TestMethod>]
  member _.``[PPC] EVNAND (NAND)``() =
    EVNAND ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a1e"

  [<TestMethod>]
  member _.``[PPC] EVNOR (NOR)``() =
    EVNOR ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a18"

  [<TestMethod>]
  member _.``[PPC] EVOR (OR)``() =
    EVOR ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a17"

  [<TestMethod>]
  member _.``[PPC] EVORC (OR with Complement)``() =
    EVORC ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a1b"

  [<TestMethod>]
  member _.``[PPC] EVSUBFW (Subtract from Word)``() =
    EVSUBFW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a04"

  [<TestMethod>]
  member _.``[PPC] EVSUBIFW (Subtract Immediate from Word)``() =
    EVSUBIFW ** [ O.Reg R5; O.Imm 0xcUL; O.Reg R7 ]
    |> testEngine "10ac3a06"

  [<TestMethod>]
  member _.``[PPC] EVXOR (XOR)``() =
    EVXOR ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a16"

  [<TestMethod>]
  member _.``[PPC] BRINC (Bit Reversed Increment)``() =
    BRINC ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a0f"

  [<TestMethod>]
  member _.``[PPC] EVABS (Absolute Value)``() =
    EVABS ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a60208"

  [<TestMethod>]
  member _.``[PPC] EVCNTLSW (Count Leading Signed Bits Word)``() =
    EVCNTLSW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a6020e"

  [<TestMethod>]
  member _.``[PPC] EVCNTLZW (Count Leading Zeros Word)``() =
    EVCNTLZW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a6020d"

  [<TestMethod>]
  member _.``[PPC] EVEXTSB (Extend Sign Byte)``() =
    EVEXTSB ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a6020a"

  [<TestMethod>]
  member _.``[PPC] EVEXTSH (Extend Sign Half Word)``() =
    EVEXTSH ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a6020b"

  [<TestMethod>]
  member _.``[PPC] EVMERGEHI (Merge High)``() =
    EVMERGEHI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a2c"

  [<TestMethod>]
  member _.``[PPC] EVMERGEHILO (Merge High/Low)``() =
    EVMERGEHILO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a2e"

  [<TestMethod>]
  member _.``[PPC] EVMERGELO (Merge Low)``() =
    EVMERGELO ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a2d"

  [<TestMethod>]
  member _.``[PPC] EVMERGELOHI (Merge Low/High)``() =
    EVMERGELOHI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a2f"

  [<TestMethod>]
  member _.``[PPC] EVNEG (Negate)``() =
    EVNEG ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a60209"

  [<TestMethod>]
  member _.``[PPC] EVRLW (Rotate Left Word)``() =
    EVRLW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a28"

  [<TestMethod>]
  member _.``[PPC] EVRLWI (Rotate Left Word Immediate)``() =
    EVRLWI ** [ O.Reg R5; O.Reg R6; O.Imm 0xcUL ]
    |> testEngine "10a6622a"

  [<TestMethod>]
  member _.``[PPC] EVRNDW (Round Word)``() =
    EVRNDW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a6020c"

  [<TestMethod>]
  member _.``[PPC] EVSLW (Shift Left Word)``() =
    EVSLW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a24"

  [<TestMethod>]
  member _.``[PPC] EVSLWI (Shift Left Word Immediate)``() =
    EVSLWI ** [ O.Reg R5; O.Reg R6; O.Imm 0xcUL ]
    |> testEngine "10a66226"

  [<TestMethod>]
  member _.``[PPC] EVSPLATFI (Splat Fractional Immediate)``() =
    EVSPLATFI ** [ O.Reg R5; O.Imm 0xfffffffffffffffdUL ]
    |> testEngine "10bd022b"

  [<TestMethod>]
  member _.``[PPC] EVSPLATI (Splat Immediate)``() =
    EVSPLATI ** [ O.Reg R5; O.Imm 0xfffffffffffffffdUL ]
    |> testEngine "10bd0229"

  [<TestMethod>]
  member _.``[PPC] EVSRWIS (Shift Right Word Immediate Signed)``() =
    EVSRWIS ** [ O.Reg R5; O.Reg R6; O.Imm 0xcUL ]
    |> testEngine "10a66223"

  [<TestMethod>]
  member _.``[PPC] EVSRWIU (Shift Right Word Immediate Unsigned)``() =
    EVSRWIU ** [ O.Reg R5; O.Reg R6; O.Imm 0xcUL ]
    |> testEngine "10a66222"

  [<TestMethod>]
  member _.``[PPC] EVSRWS (Shift Right Word Signed)``() =
    EVSRWS ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a21"

  [<TestMethod>]
  member _.``[PPC] EVSRWU (Shift Right Word Unsigned)``() =
    EVSRWU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a20"

  [<TestMethod>]
  member _.``[PPC] EVCMPEQ (Compare Equal)``() =
    EVCMPEQ ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a34"

  [<TestMethod>]
  member _.``[PPC] EVCMPGTS (Compare Greater Than Signed)``() =
    EVCMPGTS ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a31"

  [<TestMethod>]
  member _.``[PPC] EVCMPGTU (Compare Greater Than Unsigned)``() =
    EVCMPGTU ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a30"

  [<TestMethod>]
  member _.``[PPC] EVCMPLTS (Compare Less Than Signed)``() =
    EVCMPLTS ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a33"

  [<TestMethod>]
  member _.``[PPC] EVCMPLTU (Compare Less Than Unsigned)``() =
    EVCMPLTU ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a32"

  [<TestMethod>]
  member _.``[PPC] EVSEL (Select)``() =
    EVSEL ** [ O.Reg R5; O.Reg R6; O.Reg R7; O.Reg CR2 ]
    |> testEngine "10a63a7a"

  [<TestMethod>]
  member _.``[PPC] EVLDD (Load Double Word into Double Word)``() =
    EVLDD ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a60b01"

  [<TestMethod>]
  member _.``[PPC] EVLDDX (Load Double Word into Double Word Indexed)``() =
    EVLDDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b00"

  [<TestMethod>]
  member _.``[PPC] EVLDH (Load Double into Four Half Words)``() =
    EVLDH ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a60b05"

  [<TestMethod>]
  member _.``[PPC] EVLDHX (Load Double into Four Half Words Indexed)``() =
    EVLDHX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b04"

  [<TestMethod>]
  member _.``[PPC] EVLDW (Load Double into Two Words)``() =
    EVLDW ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a60b03"

  [<TestMethod>]
  member _.``[PPC] EVLDWX (Load Double into Two Words Indexed)``() =
    EVLDWX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b02"

  [<TestMethod>]
  member _.``[PPC] EVLHHESPLAT (Load Half Word into Half Words Even...)``() =
    EVLHHESPLAT ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a62309"

  [<TestMethod>]
  member _.``[PPC] EVLHHESPLATX (Load Half Word into Half Words Even...)``() =
    EVLHHESPLATX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b08"

  [<TestMethod>]
  member _.``[PPC] EVLHHOSSPLAT (Load Half Word into Half Word Odd...)``() =
    EVLHHOSSPLAT ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a6230f"

  [<TestMethod>]
  member _.``[PPC] EVLHHOSSPLATX (Load Half Word into Half Word Odd...)``() =
    EVLHHOSSPLATX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b0e"

  [<TestMethod>]
  member _.``[PPC] EVLHHOUSPLAT (Load Half Word into Half Word Odd...)``() =
    EVLHHOUSPLAT ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a6230d"

  [<TestMethod>]
  member _.``[PPC] EVLHHOUSPLATX (Load Half Word into Half Word Odd...)``() =
    EVLHHOUSPLATX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b0c"

  [<TestMethod>]
  member _.``[PPC] EVLWHE (Load Word into Two Half Words Even)``() =
    EVLWHE ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a61311"

  [<TestMethod>]
  member _.``[PPC] EVLWHEX (Load Word into Two Half Words Even Indexed)``() =
    EVLWHEX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b10"

  [<TestMethod>]
  member _.``[PPC] EVLWHOS (Load Word into Two Half Words Odd Signed...)``() =
    EVLWHOS ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a61317"

  [<TestMethod>]
  member _.``[PPC] EVLWHOSX (Load Word into Two Half Words Odd Signed...)``() =
    EVLWHOSX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b16"

  [<TestMethod>]
  member _.``[PPC] EVLWHOU (Load Word into Two Half Words Odd Unsigned...)``() =
    EVLWHOU ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a61315"

  [<TestMethod>]
  member _.``[PPC] EVLWHOUX (Load Word into Two Half Words Odd...)``() =
    EVLWHOUX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b14"

  [<TestMethod>]
  member _.``[PPC] EVLWHSPLAT (Load Word into Two Half Words and Splat)``() =
    EVLWHSPLAT ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a6131d"

  [<TestMethod>]
  member _.``[PPC] EVLWHSPLATX (Load Word into Two Half Words and...)``() =
    EVLWHSPLATX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b1c"

  [<TestMethod>]
  member _.``[PPC] EVLWWSPLAT (Load Word into Word and Splat)``() =
    EVLWWSPLAT ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a61319"

  [<TestMethod>]
  member _.``[PPC] EVLWWSPLATX (Load Word into Word and Splat Indexed)``() =
    EVLWWSPLATX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b18"

  [<TestMethod>]
  member _.``[PPC] EVSTDD (Store Double of Double)``() =
    EVSTDD ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a60b21"

  [<TestMethod>]
  member _.``[PPC] EVSTDDX (Store Double of Double Indexed)``() =
    EVSTDDX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b20"

  [<TestMethod>]
  member _.``[PPC] EVSTDH (Store Double of Four Half Words)``() =
    EVSTDH ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a60b25"

  [<TestMethod>]
  member _.``[PPC] EVSTDHX (Store Double of Four Half Words Indexed)``() =
    EVSTDHX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b24"

  [<TestMethod>]
  member _.``[PPC] EVSTDW (Store Double of Two Words)``() =
    EVSTDW ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a60b23"

  [<TestMethod>]
  member _.``[PPC] EVSTDWX (Store Double of Two Words Indexed)``() =
    EVSTDWX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b22"

  [<TestMethod>]
  member _.``[PPC] EVSTWHE (Store Word of Two Half Words from Even)``() =
    EVSTWHE ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a61331"

  [<TestMethod>]
  member _.``[PPC] EVSTWHEX (Store Word of Two Half Words from Even...)``() =
    EVSTWHEX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b30"

  [<TestMethod>]
  member _.``[PPC] EVSTWHO (Store Word of Two Half Words from Odd)``() =
    EVSTWHO ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a61335"

  [<TestMethod>]
  member _.``[PPC] EVSTWHOX (Store Word of Two Half Words from Odd...)``() =
    EVSTWHOX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b34"

  [<TestMethod>]
  member _.``[PPC] EVSTWWE (Store Word of Word from Even)``() =
    EVSTWWE ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a61339"

  [<TestMethod>]
  member _.``[PPC] EVSTWWEX (Store Word of Word from Even Indexed)``() =
    EVSTWWEX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b38"

  [<TestMethod>]
  member _.``[PPC] EVSTWWO (Store Word of Word from Odd)``() =
    EVSTWWO ** [ O.Reg R5; O.Mem(8, R6) ]
    |> testEngine "10a6133d"

  [<TestMethod>]
  member _.``[PPC] EVSTWWOX (Store Word of Word from Odd Indexed)``() =
    EVSTWWOX ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63b3c"

  [<TestMethod>]
  member _.``[PPC] EVMHEGSMFAA (Multiply Half Words, Even, Guarded,...)``() =
    EVMHEGSMFAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d2b"

  [<TestMethod>]
  member _.``[PPC] EVMHEGSMFAN (Multiply Half Words, Even, Guarded,...)``() =
    EVMHEGSMFAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dab"

  [<TestMethod>]
  member _.``[PPC] EVMHEGSMIAA (Multiply Half Words, Even, Guarded,...)``() =
    EVMHEGSMIAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d29"

  [<TestMethod>]
  member _.``[PPC] EVMHEGSMIAN (Multiply Half Words, Even, Guarded,...)``() =
    EVMHEGSMIAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63da9"

  [<TestMethod>]
  member _.``[PPC] EVMHEGUMIAA (Multiply Half Words, Even, Guarded,...)``() =
    EVMHEGUMIAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d28"

  [<TestMethod>]
  member _.``[PPC] EVMHEGUMIAN (Multiply Half Words, Even, Guarded,...)``() =
    EVMHEGUMIAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63da8"

  [<TestMethod>]
  member _.``[PPC] EVMHESMF (Multiply Half Words, Even, Signed,...)``() =
    EVMHESMF ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c0b"

  [<TestMethod>]
  member _.``[PPC] EVMHESMFA (Multiply Half Words, Even, Signed,...)``() =
    EVMHESMFA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c2b"

  [<TestMethod>]
  member _.``[PPC] EVMHESMFAAW (Multiply Half Words, Even, Signed,...)``() =
    EVMHESMFAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d0b"

  [<TestMethod>]
  member _.``[PPC] EVMHESMFANW (Multiply Half Words, Even, Signed,...)``() =
    EVMHESMFANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d8b"

  [<TestMethod>]
  member _.``[PPC] EVMHESMI (Multiply Half Words, Even, Signed,...)``() =
    EVMHESMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c09"

  [<TestMethod>]
  member _.``[PPC] EVMHESMIA (Multiply Half Words, Even, Signed,...)``() =
    EVMHESMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c29"

  [<TestMethod>]
  member _.``[PPC] EVMHESMIAAW (Multiply Half Words, Even, Signed,...)``() =
    EVMHESMIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d09"

  [<TestMethod>]
  member _.``[PPC] EVMHESMIANW (Multiply Half Words, Even, Signed,...)``() =
    EVMHESMIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d89"

  [<TestMethod>]
  member _.``[PPC] EVMHESSF (Multiply Half Words, Even, Signed,...)``() =
    EVMHESSF ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c03"

  [<TestMethod>]
  member _.``[PPC] EVMHESSFA (Multiply Half Words, Even, Signed,...)``() =
    EVMHESSFA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c23"

  [<TestMethod>]
  member _.``[PPC] EVMHESSFAAW (Multiply Half Words, Even, Signed,...)``() =
    EVMHESSFAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d03"

  [<TestMethod>]
  member _.``[PPC] EVMHESSFANW (Multiply Half Words, Even, Signed,...)``() =
    EVMHESSFANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d83"

  [<TestMethod>]
  member _.``[PPC] EVMHESSIAAW (Multiply Half Words, Even, Signed,...)``() =
    EVMHESSIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d01"

  [<TestMethod>]
  member _.``[PPC] EVMHESSIANW (Multiply Half Words, Even, Signed,...)``() =
    EVMHESSIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d81"

  [<TestMethod>]
  member _.``[PPC] EVMHEUMI (Multiply Half Words, Even, Unsigned,...)``() =
    EVMHEUMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c08"

  [<TestMethod>]
  member _.``[PPC] EVMHEUMIA (Multiply Half Words, Even, Unsigned,...)``() =
    EVMHEUMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c28"

  [<TestMethod>]
  member _.``[PPC] EVMHEUMIAAW (Multiply Half Words, Even, Unsigned,...)``() =
    EVMHEUMIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d08"

  [<TestMethod>]
  member _.``[PPC] EVMHEUMIANW (Multiply Half Words, Even, Unsigned,...)``() =
    EVMHEUMIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d88"

  [<TestMethod>]
  member _.``[PPC] EVMHEUSIAAW (Multiply Half Words, Even, Unsigned,...)``() =
    EVMHEUSIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d00"

  [<TestMethod>]
  member _.``[PPC] EVMHEUSIANW (Multiply Half Words, Even, Unsigned,...)``() =
    EVMHEUSIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d80"

  [<TestMethod>]
  member _.``[PPC] EVMHOGSMFAA (Multiply Half Words, Odd, Guarded,...)``() =
    EVMHOGSMFAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d2f"

  [<TestMethod>]
  member _.``[PPC] EVMHOGSMFAN (Multiply Half Words, Odd, Guarded,...)``() =
    EVMHOGSMFAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63daf"

  [<TestMethod>]
  member _.``[PPC] EVMHOGSMIAA (Multiply Half Words, Odd, Guarded,...)``() =
    EVMHOGSMIAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d2d"

  [<TestMethod>]
  member _.``[PPC] EVMHOGSMIAN (Multiply Half Words, Odd, Guarded,...)``() =
    EVMHOGSMIAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dad"

  [<TestMethod>]
  member _.``[PPC] EVMHOGUMIAA (Multiply Half Words, Odd, Guarded,...)``() =
    EVMHOGUMIAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d2c"

  [<TestMethod>]
  member _.``[PPC] EVMHOGUMIAN (Multiply Half Words, Odd, Guarded,...)``() =
    EVMHOGUMIAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dac"

  [<TestMethod>]
  member _.``[PPC] EVMHOSMF (Multiply Half Words, Odd, Signed, Modulo,...)``() =
    EVMHOSMF ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c0f"

  [<TestMethod>]
  member _.``[PPC] EVMHOSMFA (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSMFA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c2f"

  [<TestMethod>]
  member _.``[PPC] EVMHOSMFAAW (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSMFAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d0f"

  [<TestMethod>]
  member _.``[PPC] EVMHOSMFANW (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSMFANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d8f"

  [<TestMethod>]
  member _.``[PPC] EVMHOSMI (Multiply Half Words, Odd, Signed, Modulo,...)``() =
    EVMHOSMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c0d"

  [<TestMethod>]
  member _.``[PPC] EVMHOSMIA (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c2d"

  [<TestMethod>]
  member _.``[PPC] EVMHOSMIAAW (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSMIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d0d"

  [<TestMethod>]
  member _.``[PPC] EVMHOSMIANW (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSMIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d8d"

  [<TestMethod>]
  member _.``[PPC] EVMHOSSF (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSSF ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c07"

  [<TestMethod>]
  member _.``[PPC] EVMHOSSFA (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSSFA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c27"

  [<TestMethod>]
  member _.``[PPC] EVMHOSSFAAW (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSSFAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d07"

  [<TestMethod>]
  member _.``[PPC] EVMHOSSFANW (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSSFANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d87"

  [<TestMethod>]
  member _.``[PPC] EVMHOSSIAAW (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSSIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d05"

  [<TestMethod>]
  member _.``[PPC] EVMHOSSIANW (Multiply Half Words, Odd, Signed,...)``() =
    EVMHOSSIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d85"

  [<TestMethod>]
  member _.``[PPC] EVMHOUMI (Multiply Half Words, Odd, Unsigned,...)``() =
    EVMHOUMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c0c"

  [<TestMethod>]
  member _.``[PPC] EVMHOUMIA (Multiply Half Words, Odd, Unsigned,...)``() =
    EVMHOUMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c2c"

  [<TestMethod>]
  member _.``[PPC] EVMHOUMIAAW (Multiply Half Words, Odd, Unsigned,...)``() =
    EVMHOUMIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d0c"

  [<TestMethod>]
  member _.``[PPC] EVMHOUMIANW (Multiply Half Words, Odd, Unsigned,...)``() =
    EVMHOUMIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d8c"

  [<TestMethod>]
  member _.``[PPC] EVMHOUSIAAW (Multiply Half Words, Odd, Unsigned,...)``() =
    EVMHOUSIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d04"

  [<TestMethod>]
  member _.``[PPC] EVMHOUSIANW (Multiply Half Words, Odd, Unsigned,...)``() =
    EVMHOUSIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d84"

  [<TestMethod>]
  member _.``[PPC] EVMWHSMF (Multiply Word High Signed, Modulo,...)``() =
    EVMWHSMF ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c4f"

  [<TestMethod>]
  member _.``[PPC] EVMWHSMFA (Multiply Word High Signed, Modulo,...)``() =
    EVMWHSMFA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c6f"

  [<TestMethod>]
  member _.``[PPC] EVMWHSMI (Multiply Word High Signed, Modulo, Integer)``() =
    EVMWHSMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c4d"

  [<TestMethod>]
  member _.``[PPC] EVMWHSMIA (Multiply Word High Signed, Modulo,...)``() =
    EVMWHSMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c6d"

  [<TestMethod>]
  member _.``[PPC] EVMWHSSF (Multiply Word High Signed, Saturate,...)``() =
    EVMWHSSF ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c47"

  [<TestMethod>]
  member _.``[PPC] EVMWHSSFA (Multiply Word High Signed, Saturate,...)``() =
    EVMWHSSFA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c67"

  [<TestMethod>]
  member _.``[PPC] EVMWHUMI (Multiply Word High Unsigned, Modulo, Integer)``() =
    EVMWHUMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c4c"

  [<TestMethod>]
  member _.``[PPC] EVMWHUMIA (Multiply Word High Unsigned, Modulo,...)``() =
    EVMWHUMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c6c"

  [<TestMethod>]
  member _.``[PPC] EVMWLSMIAAW (Multiply Word Low Signed, Modulo,...)``() =
    EVMWLSMIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d49"

  [<TestMethod>]
  member _.``[PPC] EVMWLSMIANW (Multiply Word Low Signed, Modulo,...)``() =
    EVMWLSMIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dc9"

  [<TestMethod>]
  member _.``[PPC] EVMWLSSIAAW (Multiply Word Low Signed, Saturate,...)``() =
    EVMWLSSIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d41"

  [<TestMethod>]
  member _.``[PPC] EVMWLSSIANW (Multiply Word Low Signed, Saturate,...)``() =
    EVMWLSSIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dc1"

  [<TestMethod>]
  member _.``[PPC] EVMWLUMI (Multiply Word Low Unsigned, Modulo, Integer)``() =
    EVMWLUMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c48"

  [<TestMethod>]
  member _.``[PPC] EVMWLUMIA (Multiply Word Low Unsigned, Modulo,...)``() =
    EVMWLUMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c68"

  [<TestMethod>]
  member _.``[PPC] EVMWLUMIAAW (Multiply Word Low Unsigned, Modulo,...)``() =
    EVMWLUMIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d48"

  [<TestMethod>]
  member _.``[PPC] EVMWLUMIANW (Multiply Word Low Unsigned, Modulo,...)``() =
    EVMWLUMIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dc8"

  [<TestMethod>]
  member _.``[PPC] EVMWLUSIAAW (Multiply Word Low Unsigned, Saturate,...)``() =
    EVMWLUSIAAW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d40"

  [<TestMethod>]
  member _.``[PPC] EVMWLUSIANW (Multiply Word Low Unsigned, Saturate,...)``() =
    EVMWLUSIANW ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dc0"

  [<TestMethod>]
  member _.``[PPC] EVMWSMF (Multiply Word Signed, Modulo, Fractional)``() =
    EVMWSMF ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c5b"

  [<TestMethod>]
  member _.``[PPC] EVMWSMFA (Multiply Word Signed, Modulo, Fractional...)``() =
    EVMWSMFA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c7b"

  [<TestMethod>]
  member _.``[PPC] EVMWSMFAA (Multiply Word Signed, Modulo, Fractional...)``() =
    EVMWSMFAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d5b"

  [<TestMethod>]
  member _.``[PPC] EVMWSMFAN (Multiply Word Signed, Modulo, Fractional...)``() =
    EVMWSMFAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ddb"

  [<TestMethod>]
  member _.``[PPC] EVMWSMI (Multiply Word Signed, Modulo, Integer)``() =
    EVMWSMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c59"

  [<TestMethod>]
  member _.``[PPC] EVMWSMIA (Multiply Word Signed, Modulo, Integer to...)``() =
    EVMWSMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c79"

  [<TestMethod>]
  member _.``[PPC] EVMWSMIAA (Multiply Word Signed, Modulo, Integer...)``() =
    EVMWSMIAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d59"

  [<TestMethod>]
  member _.``[PPC] EVMWSMIAN (Multiply Word Signed, Modulo, Integer...)``() =
    EVMWSMIAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dd9"

  [<TestMethod>]
  member _.``[PPC] EVMWSSF (Multiply Word Signed, Saturate, Fractional)``() =
    EVMWSSF ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c53"

  [<TestMethod>]
  member _.``[PPC] EVMWSSFA (Multiply Word Signed, Saturate,...)``() =
    EVMWSSFA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c73"

  [<TestMethod>]
  member _.``[PPC] EVMWSSFAA (Multiply Word Signed, Saturate,...)``() =
    EVMWSSFAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d53"

  [<TestMethod>]
  member _.``[PPC] EVMWSSFAN (Multiply Word Signed, Saturate,...)``() =
    EVMWSSFAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dd3"

  [<TestMethod>]
  member _.``[PPC] EVMWUMI (Multiply Word Unsigned, Modulo, Integer)``() =
    EVMWUMI ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c58"

  [<TestMethod>]
  member _.``[PPC] EVMWUMIA (Multiply Word Unsigned, Modulo, Integer...)``() =
    EVMWUMIA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63c78"

  [<TestMethod>]
  member _.``[PPC] EVMWUMIAA (Multiply Word Unsigned, Modulo, Integer...)``() =
    EVMWUMIAA ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63d58"

  [<TestMethod>]
  member _.``[PPC] EVMWUMIAN (Multiply Word Unsigned, Modulo, Integer...)``() =
    EVMWUMIAN ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63dd8"

  [<TestMethod>]
  member _.``[PPC] EVADDSMIAAW (Add Signed, Modulo, Integer to...)``() =
    EVADDSMIAAW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604c9"

  [<TestMethod>]
  member _.``[PPC] EVADDSSIAAW (Add Signed, Saturate, Integer to...)``() =
    EVADDSSIAAW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604c1"

  [<TestMethod>]
  member _.``[PPC] EVADDUMIAAW (Add Unsigned, Modulo, Integer to...)``() =
    EVADDUMIAAW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604c8"

  [<TestMethod>]
  member _.``[PPC] EVADDUSIAAW (Add Unsigned, Saturate, Integer to...)``() =
    EVADDUSIAAW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604c0"

  [<TestMethod>]
  member _.``[PPC] EVDIVWS (Divide Word Signed)``() =
    EVDIVWS ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63cc6"

  [<TestMethod>]
  member _.``[PPC] EVDIVWU (Divide Word Unsigned)``() =
    EVDIVWU ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63cc7"

  [<TestMethod>]
  member _.``[PPC] EVMRA (Initialize Accumulator)``() =
    EVMRA ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604c4"

  [<TestMethod>]
  member _.``[PPC] EVSUBFSMIAAW (Subtract Signed, Modulo, Integer to...)``() =
    EVSUBFSMIAAW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604cb"

  [<TestMethod>]
  member _.``[PPC] EVSUBFSSIAAW (Subtract Signed, Saturate, Integer to...)``() =
    EVSUBFSSIAAW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604c3"

  [<TestMethod>]
  member _.``[PPC] EVSUBFUMIAAW (Subtract Unsigned, Modulo, Integer to...)``() =
    EVSUBFUMIAAW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604ca"

  [<TestMethod>]
  member _.``[PPC] EVSUBFUSIAAW (Subtract Unsigned, Saturate, Integer...)``() =
    EVSUBFUSIAAW ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a604c2"

  [<TestMethod>]
  member _.``[PPC] EFDABS (Value)``() =
    EFDABS ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a602e4"

  [<TestMethod>]
  member _.``[PPC] EFDNABS (Absolute Value)``() =
    EFDNABS ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a602e5"

  [<TestMethod>]
  member _.``[PPC] EFDNEG (Floating-Point Double-Precision Negate)``() =
    EFDNEG ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a602e6"

  [<TestMethod>]
  member _.``[PPC] EFSABS (Floating-Point Absolute Value)``() =
    EFSABS ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a602c4"

  [<TestMethod>]
  member _.``[PPC] EFSNABS (Floating-Point Negative Absolute Value)``() =
    EFSNABS ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a602c5"

  [<TestMethod>]
  member _.``[PPC] EFSNEG (Floating-Point Negate)``() =
    EFSNEG ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a602c6"

  [<TestMethod>]
  member _.``[PPC] EVFSABS (Floating-Point Absolute Value)``() =
    EVFSABS ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a60284"

  [<TestMethod>]
  member _.``[PPC] EVFSNABS (Floating-Point Negative Absolute Value)``() =
    EVFSNABS ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a60285"

  [<TestMethod>]
  member _.``[PPC] EVFSNEG (Floating-Point Negate)``() =
    EVFSNEG ** [ O.Reg R5; O.Reg R6 ]
    |> testEngine "10a60286"

  [<TestMethod>]
  member _.``[PPC] EFDCMPEQ (Equal)``() =
    EFDCMPEQ ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063aee"

  [<TestMethod>]
  member _.``[PPC] EFDCMPGT (Greater Than)``() =
    EFDCMPGT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063aec"

  [<TestMethod>]
  member _.``[PPC] EFDCMPLT (Less Than)``() =
    EFDCMPLT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063aed"

  [<TestMethod>]
  member _.``[PPC] EFDTSTEQ (Floating-Point Double-Precision Test Equal)``() =
    EFDTSTEQ ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063afe"

  [<TestMethod>]
  member _.``[PPC] EFDTSTGT (Than)``() =
    EFDTSTGT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063afc"

  [<TestMethod>]
  member _.``[PPC] EFDTSTLT (Than)``() =
    EFDTSTLT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063afd"

  [<TestMethod>]
  member _.``[PPC] EFSCMPEQ (Floating-Point Compare Equal)``() =
    EFSCMPEQ ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063ace"

  [<TestMethod>]
  member _.``[PPC] EFSCMPGT (Floating-Point Compare Greater Than)``() =
    EFSCMPGT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063acc"

  [<TestMethod>]
  member _.``[PPC] EFSCMPLT (Floating-Point Compare Less Than)``() =
    EFSCMPLT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063acd"

  [<TestMethod>]
  member _.``[PPC] EFSTSTEQ (Floating-Point Test Equal)``() =
    EFSTSTEQ ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063ade"

  [<TestMethod>]
  member _.``[PPC] EFSTSTGT (Floating-Point Test Greater Than)``() =
    EFSTSTGT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063adc"

  [<TestMethod>]
  member _.``[PPC] EFSTSTLT (Floating-Point Test Less Than)``() =
    EFSTSTLT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063add"

  [<TestMethod>]
  member _.``[PPC] EVFSCMPEQ (Floating-Point Compare Equal)``() =
    EVFSCMPEQ ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a8e"

  [<TestMethod>]
  member _.``[PPC] EVFSCMPGT (Floating-Point Compare Greater Than)``() =
    EVFSCMPGT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a8c"

  [<TestMethod>]
  member _.``[PPC] EVFSCMPLT (Floating-Point Compare Less Than)``() =
    EVFSCMPLT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a8d"

  [<TestMethod>]
  member _.``[PPC] EVFSTSTEQ (Floating-Point Test Equal)``() =
    EVFSTSTEQ ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a9e"

  [<TestMethod>]
  member _.``[PPC] EVFSTSTGT (Floating-Point Test Greater Than)``() =
    EVFSTSTGT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a9c"

  [<TestMethod>]
  member _.``[PPC] EVFSTSTLT (Floating-Point Test Less Than)``() =
    EVFSTSTLT ** [ O.Reg CR2; O.Reg R6; O.Reg R7 ]
    |> testEngine "11063a9d"

  [<TestMethod>]
  member _.``[PPC] EFDCFS (Single-Precision)``() =
    EFDCFS ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03aef"

  [<TestMethod>]
  member _.``[PPC] EFDCFSF (Signed Fraction)``() =
    EFDCFSF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af3"

  [<TestMethod>]
  member _.``[PPC] EFDCFSI (Signed Integer)``() =
    EFDCFSI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af1"

  [<TestMethod>]
  member _.``[PPC] EFDCFSID (Signed Integer Doubleword)``() =
    EFDCFSID ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ae3"

  [<TestMethod>]
  member _.``[PPC] EFDCFUF (Unsigned Fraction)``() =
    EFDCFUF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af2"

  [<TestMethod>]
  member _.``[PPC] EFDCFUI (Unsigned Integer)``() =
    EFDCFUI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af0"

  [<TestMethod>]
  member _.``[PPC] EFDCFUID (Unsigned Integer Doubleword)``() =
    EFDCFUID ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ae2"

  [<TestMethod>]
  member _.``[PPC] EFSCFD (Double-Precision)``() =
    EFSCFD ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03acf"

  [<TestMethod>]
  member _.``[PPC] EFSCFSF (Convert Floating-Point from Signed Fraction)``() =
    EFSCFSF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad3"

  [<TestMethod>]
  member _.``[PPC] EFSCFSI (Convert Floating-Point from Signed Integer)``() =
    EFSCFSI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad1"

  [<TestMethod>]
  member _.``[PPC] EFSCFUF (Convert Floating-Point from Unsigned Fraction)``() =
    EFSCFUF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad2"

  [<TestMethod>]
  member _.``[PPC] EFSCFUI (Convert Floating-Point from Unsigned Integer)``() =
    EFSCFUI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad0"

  [<TestMethod>]
  member _.``[PPC] EVFSCFSF (Convert Floating-Point from Signed Fraction)``() =
    EVFSCFSF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a93"

  [<TestMethod>]
  member _.``[PPC] EVFSCFSI (Convert Floating-Point from Signed Integer)``() =
    EVFSCFSI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a91"

  [<TestMethod>]
  member _.``[PPC] EVFSCFUF (Convert Floating-Point from Unsigned...)``() =
    EVFSCFUF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a92"

  [<TestMethod>]
  member _.``[PPC] EVFSCFUI (Convert Floating-Point from Unsigned Integer)``() =
    EVFSCFUI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a90"

  [<TestMethod>]
  member _.``[PPC] EFDCTSF (Signed Fraction)``() =
    EFDCTSF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af7"

  [<TestMethod>]
  member _.``[PPC] EFDCTSI (Signed Integer)``() =
    EFDCTSI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af5"

  [<TestMethod>]
  member _.``[PPC] EFDCTSIDZ (Signed Integer Doubleword with Round)``() =
    EFDCTSIDZ ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03aeb"

  [<TestMethod>]
  member _.``[PPC] EFDCTSIZ (Signed Integer with Round toward Zero)``() =
    EFDCTSIZ ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03afa"

  [<TestMethod>]
  member _.``[PPC] EFDCTUF (Unsigned Fraction)``() =
    EFDCTUF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af6"

  [<TestMethod>]
  member _.``[PPC] EFDCTUI (Unsigned Integer)``() =
    EFDCTUI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af4"

  [<TestMethod>]
  member _.``[PPC] EFDCTUIDZ (Unsigned Integer Doubleword with Round)``() =
    EFDCTUIDZ ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03aea"

  [<TestMethod>]
  member _.``[PPC] EFDCTUIZ (Unsigned Integer with Round toward Zero)``() =
    EFDCTUIZ ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03af8"

  [<TestMethod>]
  member _.``[PPC] EFSCTSF (Convert Floating-Point to Signed Fraction)``() =
    EFSCTSF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad7"

  [<TestMethod>]
  member _.``[PPC] EFSCTSI (Convert Floating-Point to Signed Integer)``() =
    EFSCTSI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad5"

  [<TestMethod>]
  member _.``[PPC] EFSCTSIZ (Convert Floating-Point to Signed Integer...)``() =
    EFSCTSIZ ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ada"

  [<TestMethod>]
  member _.``[PPC] EFSCTUF (Convert Floating-Point to Unsigned Fraction)``() =
    EFSCTUF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad6"

  [<TestMethod>]
  member _.``[PPC] EFSCTUI (Convert Floating-Point to Unsigned Integer)``() =
    EFSCTUI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad4"

  [<TestMethod>]
  member _.``[PPC] EFSCTUIZ (Convert Floating-Point to Unsigned...)``() =
    EFSCTUIZ ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03ad8"

  [<TestMethod>]
  member _.``[PPC] EVFSCTSF (Convert Floating-Point to Signed Fraction)``() =
    EVFSCTSF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a97"

  [<TestMethod>]
  member _.``[PPC] EVFSCTSI (Convert Floating-Point to Signed Integer)``() =
    EVFSCTSI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a95"

  [<TestMethod>]
  member _.``[PPC] EVFSCTSIZ (Convert Floating-Point to Signed Integer...)``() =
    EVFSCTSIZ ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a9a"

  [<TestMethod>]
  member _.``[PPC] EVFSCTUF (Convert Floating-Point to Unsigned Fraction)``() =
    EVFSCTUF ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a96"

  [<TestMethod>]
  member _.``[PPC] EVFSCTUI (Convert Floating-Point to Unsigned Integer)``() =
    EVFSCTUI ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a94"

  [<TestMethod>]
  member _.``[PPC] EVFSCTUIZ (Convert Floating-Point to Unsigned...)``() =
    EVFSCTUIZ ** [ O.Reg R5; O.Reg R7 ]
    |> testEngine "10a03a98"

  [<TestMethod>]
  member _.``[PPC] EFSADD (Floating-Point Add)``() =
    EFSADD ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ac0"

  [<TestMethod>]
  member _.``[PPC] EFSDIV (Floating-Point Divide)``() =
    EFSDIV ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ac9"

  [<TestMethod>]
  member _.``[PPC] EFSMUL (Floating-Point Multiply)``() =
    EFSMUL ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ac8"

  [<TestMethod>]
  member _.``[PPC] EFSSUB (Floating-Point Subtract)``() =
    EFSSUB ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ac1"

  [<TestMethod>]
  member _.``[PPC] EVFSADD (Floating-Point Add)``() =
    EVFSADD ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a80"

  [<TestMethod>]
  member _.``[PPC] EVFSDIV (Floating-Point Divide)``() =
    EVFSDIV ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a89"

  [<TestMethod>]
  member _.``[PPC] EVFSMUL (Floating-Point Multiply)``() =
    EVFSMUL ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a88"

  [<TestMethod>]
  member _.``[PPC] EVFSSUB (Floating-Point Subtract)``() =
    EVFSSUB ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63a81"

  [<TestMethod>]
  member _.``[PPC] EFDADD (Floating-Point Double-Precision Add)``() =
    EFDADD ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ae0"

  [<TestMethod>]
  member _.``[PPC] EFDDIV (Floating-Point Double-Precision Divide)``() =
    EFDDIV ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ae9"

  [<TestMethod>]
  member _.``[PPC] EFDMUL (Floating-Point Double-Precision Multiply)``() =
    EFDMUL ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ae8"

  [<TestMethod>]
  member _.``[PPC] EFDSUB (Floating-Point Double-Precision Subtract)``() =
    EFDSUB ** [ O.Reg R5; O.Reg R6; O.Reg R7 ]
    |> testEngine "10a63ae1"

/// The engine's extra register widths are part of the register API as well
/// as of the variables used directly by its lifters.
[<TestClass>]
type SignalProcessingRegisterTests() =
  [<TestMethod>]
  member _.``[PPC] SPE registers expose their operand widths``() =
    let high = [ for i in 0 .. 31 -> enum<Register> (int R0H + i) ]
    for width in [ WordSize.Bit32; WordSize.Bit64 ] do
      let isa = ISA(Architecture.PPC, Endian.Big, width)
      let factory = RegisterFactory isa :> IRegisterFactory
      for reg in high @ [ ACC; SPEFSCR ] do
        let expected = if reg = ACC then 64<rt> else 32<rt>
        let actual = factory.GetRegType(Register.toRegID reg)
        Assert.AreEqual(box expected, box actual, $"{reg} {width}")

/// The non-SPE state registers keep their declared widths on both targets.
[<TestClass>]
type StateRegisterTests() =
  [<TestMethod>]
  member _.``[PPC] State registers expose their operand widths``() =
    for width in [ WordSize.Bit32; WordSize.Bit64 ] do
      let isa = ISA(Architecture.PPC, Endian.Big, width)
      let factory = RegisterFactory isa :> IRegisterFactory
      let rt = WordSize.toRegType width
      let registers =
        [ FPSCRH, 32<rt>
          TAR, rt
          BESCR, rt
          EBBHR, rt
          EBBRR, rt
          ExMonVal2, rt
          DSCR, rt
          AMR, rt
          CTRL, 32<rt>
          SPRG3, rt
          PPR, rt
          TEXASR, 64<rt>
          TFHAR, 64<rt>
          TFIAR, 64<rt> ]
      for reg, expected in registers do
        let actual = factory.GetRegType(Register.toRegID reg)
        Assert.AreEqual(box expected, box actual, $"{reg} {width}")

/// What the tests of Variable Length Encoding check a halfword or two against:
/// the bytes as a page of VLE code holds them, which are big-endian whatever
/// the order of the data is.
[<AutoOpen>]
module private VLEShortcut =
  /// A parser of Variable Length Encoding, at a word size.
  let vleParser wordSz =
    Parser(wordSz, Category.VLE, BinReader.Init Endian.Big)
    :> IInstructionParsable

  /// Asserts what the bytes decode to on a processor of the word size, and
  /// that the instruction takes all of them.
  let testVLEOn wordSz (hex: string) (opcode: Opcode, operands: Operands) =
    let bytes = ByteArray.ofHexString hex
    let ins = (vleParser wordSz).Parse(bytes, 0UL) :?> Instruction
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<Operands>(operands, ins.Operands)
    Assert.AreEqual<uint32>(uint32 bytes.Length, ins.Length)

  /// A form that reads the same on a 32-bit processor and a 64-bit one.
  let testVLE hex pair =
    testVLEOn WordSize.Bit32 hex pair
    testVLEOn WordSize.Bit64 hex pair

  /// Asserts that the bytes are no instruction of VLE.
  let testVLEUnsupported (hex: string) =
    let bytes = ByteArray.ofHexString hex
    Assert.Throws<ParsingFailureException>(fun () ->
      (vleParser WordSize.Bit32).Parse(bytes, 0UL) |> ignore)
    |> ignore

/// The instructions of Variable Length Encoding, the second encoding of the
/// Power ISA, which are one halfword or two. Each word is the one GNU as
/// writes for the instruction (powerpc-linux-gnu-as -mvle), and B2R2's reading
/// of it is the one GNU objdump (-M vle) gives it.
[<TestClass>]
type VLEParserTests() =
  /// A parser reads the instructions at the alignment of the encoding it
  /// reads: a halfword for VLE and a word for the base encoding.
  [<TestMethod>]
  member _.``[PPC VLE] The ISA flag selects halfword alignment``() =
    let reader = BinReader.Init Endian.Big
    let plain = Parser(WordSize.Bit32, reader) :> IInstructionParsable
    let vle = vleParser WordSize.Bit32
    Assert.AreEqual<int>(4, plain.InstructionAlignment)
    Assert.AreEqual<int>(2, vle.InstructionAlignment)
    Assert.AreEqual<int>(4, vle.MaxInstructionSize)

  /// The mode is what the ISA said until something moves it, and moving it
  /// changes how the same bytes are read.
  [<TestMethod>]
  member _.``[PPC VLE] A parser can be moved between the encodings``() =
    let parser = Parser(WordSize.Bit32, BinReader.Init Endian.Big)
    let parsable = parser :> IInstructionParsable
    let opcodeOf hex =
      (parsable.Parse(ByteArray.ofHexString hex, 0UL) :?> Instruction).Opcode
    Assert.IsFalse parser.IsVLE
    Assert.AreEqual<Opcode>(MR, opcodeOf "7c832378")
    Assert.AreEqual<int>(4, parsable.InstructionAlignment)
    parser.IsVLE <- true
    Assert.AreEqual<Opcode>(SE_BLR, opcodeOf "0004")
    Assert.AreEqual<int>(2, parsable.InstructionAlignment)
    parser.IsVLE <- false
    Assert.AreEqual<Opcode>(MR, opcodeOf "7c832378")

  /// Nothing in the stream says how long an instruction is but its first
  /// halfword, so a decoder advances by what each one reports.
  [<TestMethod>]
  member _.``[PPC VLE] A stream mixes halfword and word instructions``() =
    let parser = vleParser WordSize.Bit32
    (* se_blr, vaddubm v1, v2, v3 and se_isync *)
    let bytes = ByteArray.ofHexString "0004102218000001"
    let rec walk offset =
      if offset >= bytes.Length then
        []
      else
        let span = System.ReadOnlySpan(bytes, offset, bytes.Length - offset)
        let ins = parser.Parse(span, uint64 offset) :?> Instruction
        (ins.Opcode, ins.Address, ins.Length) :: walk (offset + int ins.Length)
    let expected = [ SE_BLR, 0UL, 2u; VADDUBM, 2UL, 4u; SE_ISYNC, 6UL, 2u ]
    Assert.AreEqual<(Opcode * Addr * uint32) list>(expected, walk 0)

  /// The vector facility has the same encodings in VLE: primary opcode 4 is
  /// read as it is read outside it.
  [<TestMethod>]
  member _.``[PPC VLE] Vector instructions are read as the base encoding``() =
    testVLE "10221800"
    <| (VADDUBM ** [ O.Reg V1A; O.Reg V2A; O.Reg V3A ])

  /// What the Power ISA leaves undefined is refused: the halfwords between the
  /// control instructions and the opcode space that is reserved.
  [<TestMethod>]
  member _.``[PPC VLE] Reserved halfwords are refused``() =
    for hex in [ "0003"; "000d"; "ffff" ] do
      testVLEUnsupported hex

  /// A page of VLE code is big-endian, and fetching from it in a
  /// little-endian mode is an exception of the architecture, so a parser
  /// given a little-endian reader reads nothing.
  [<TestMethod>]
  member _.``[PPC VLE] A little-endian reader is refused``() =
    let parser =
      Parser(WordSize.Bit32, Category.VLE, BinReader.Init Endian.Little)
      :> IInstructionParsable
    Assert.Throws<ParsingFailureException>(fun () ->
      parser.Parse([| 4uy; 0uy |], 0UL) |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[PPC VLE] SE_ILLEGAL (illegal)``() =
    testVLE "0000" <| (SE_ILLEGAL ** [])

  [<TestMethod>]
  member _.``[PPC VLE] SE_ISYNC (instruction synchronize)``() =
    testVLE "0001" <| (SE_ISYNC ** [])

  [<TestMethod>]
  member _.``[PPC VLE] SE_SC (system call)``() =
    testVLE "0002" <| (SE_SC ** [])

  [<TestMethod>]
  member _.``[PPC VLE] SE_BLR (branch to LR)``() =
    testVLE "0004" <| (SE_BLR ** [])

  [<TestMethod>]
  member _.``[PPC VLE] SE_BLRL (branch to LR and link)``() =
    testVLE "0005" <| (SE_BLRL ** [])

  [<TestMethod>]
  member _.``[PPC VLE] SE_BCTR (branch to CTR)``() =
    testVLE "0006" <| (SE_BCTR ** [])

  [<TestMethod>]
  member _.``[PPC VLE] SE_BCTRL (branch to CTR and link)``() =
    testVLE "0007" <| (SE_BCTRL ** [])

  [<TestMethod>]
  member _.``[PPC VLE] SE_MR (move register)``() =
    SE_MR ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0143"
    SE_MR ** [ O.Reg R30; O.Reg R25 ]
    |> testVLE "019e"

  [<TestMethod>]
  member _.``[PPC VLE] SE_MTAR (move to alternate register)``() =
    SE_MTAR ** [ O.Reg R10; O.Reg R4 ]
    |> testVLE "0242"
    SE_MTAR ** [ O.Reg R8; O.Reg R31 ]
    |> testVLE "02f0"

  [<TestMethod>]
  member _.``[PPC VLE] SE_MFAR (move from alternate register)``() =
    SE_MFAR ** [ O.Reg R3; O.Reg R10 ]
    |> testVLE "0323"
    SE_MFAR ** [ O.Reg R24; O.Reg R23 ]
    |> testVLE "03f8"

  [<TestMethod>]
  member _.``[PPC VLE] SE_MFLR (move from LR)``() =
    SE_MFLR ** [ O.Reg R3 ]
    |> testVLE "0083"

  [<TestMethod>]
  member _.``[PPC VLE] SE_MTLR (move to LR)``() =
    SE_MTLR ** [ O.Reg R3 ]
    |> testVLE "0093"

  [<TestMethod>]
  member _.``[PPC VLE] SE_MFCTR (move from CTR)``() =
    SE_MFCTR ** [ O.Reg R3 ]
    |> testVLE "00a3"

  [<TestMethod>]
  member _.``[PPC VLE] SE_MTCTR (move to CTR)``() =
    SE_MTCTR ** [ O.Reg R3 ]
    |> testVLE "00b3"

  [<TestMethod>]
  member _.``[PPC VLE] SE_LI (load immediate)``() =
    SE_LI ** [ O.Reg R3; O.Imm 0x64UL ]
    |> testVLE "4e43"

  [<TestMethod>]
  member _.``[PPC VLE] SE_EXTZB (extend zero byte)``() =
    SE_EXTZB ** [ O.Reg R3 ]
    |> testVLE "00c3"

  [<TestMethod>]
  member _.``[PPC VLE] SE_EXTZH (extend zero halfword)``() =
    SE_EXTZH ** [ O.Reg R3 ]
    |> testVLE "00e3"

  [<TestMethod>]
  member _.``[PPC VLE] SE_EXTSB (extend sign byte)``() =
    SE_EXTSB ** [ O.Reg R3 ]
    |> testVLE "00d3"

  [<TestMethod>]
  member _.``[PPC VLE] SE_EXTSH (extend sign halfword)``() =
    SE_EXTSH ** [ O.Reg R3 ]
    |> testVLE "00f3"

  [<TestMethod>]
  member _.``[PPC VLE] SE_ADD (add)``() =
    SE_ADD ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0443"
    SE_ADD ** [ O.Reg R31; O.Reg R24 ]
    |> testVLE "048f"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SUB (subtract)``() =
    SE_SUB ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0643"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SUBF (subtract from)``() =
    SE_SUBF ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0743"

  [<TestMethod>]
  member _.``[PPC VLE] SE_MULLW (multiply low word)``() =
    SE_MULLW ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0543"

  [<TestMethod>]
  member _.``[PPC VLE] SE_NEG (negate)``() =
    SE_NEG ** [ O.Reg R3 ]
    |> testVLE "0033"

  [<TestMethod>]
  member _.``[PPC VLE] SE_NOT (NOT)``() =
    SE_NOT ** [ O.Reg R3 ]
    |> testVLE "0023"

  [<TestMethod>]
  member _.``[PPC VLE] SE_AND (AND)``() =
    SE_AND ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "4643"

  [<TestMethod>]
  member _.``[PPC VLE] SE_AND. (AND, record)``() =
    SE_ANDdot ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "4743"

  [<TestMethod>]
  member _.``[PPC VLE] SE_ANDC (AND with complement)``() =
    SE_ANDC ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "4543"

  [<TestMethod>]
  member _.``[PPC VLE] SE_OR (OR)``() =
    SE_OR ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "4443"

  [<TestMethod>]
  member _.``[PPC VLE] SE_ADDI (add immediate)``() =
    SE_ADDI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "2043"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SUBI (subtract immediate)``() =
    SE_SUBI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "2443"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SUBI. (subtract immediate, record)``() =
    SE_SUBIdot ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "2643"

  [<TestMethod>]
  member _.``[PPC VLE] SE_ANDI (AND immediate)``() =
    SE_ANDI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "2e53"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SLW (shift left word)``() =
    SE_SLW ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "4243"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SRW (shift right word)``() =
    SE_SRW ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "4043"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SRAW (shift right algebraic word)``() =
    SE_SRAW ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "4143"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SLWI (shift left word immediate)``() =
    SE_SLWI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "6c53"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SRWI (shift right word immediate)``() =
    SE_SRWI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "6853"

  [<TestMethod>]
  member _.``[PPC VLE] SE_SRAWI (shift right algebraic word immediate)``() =
    SE_SRAWI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "6a53"

  [<TestMethod>]
  member _.``[PPC VLE] SE_BCLRI (bit clear immediate)``() =
    SE_BCLRI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "6053"

  [<TestMethod>]
  member _.``[PPC VLE] SE_BGENI (bit generate immediate)``() =
    SE_BGENI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "6253"

  [<TestMethod>]
  member _.``[PPC VLE] SE_BMASKI (bit mask generate immediate)``() =
    SE_BMASKI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "2c53"

  [<TestMethod>]
  member _.``[PPC VLE] SE_BSETI (bit set immediate)``() =
    SE_BSETI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "6453"

  [<TestMethod>]
  member _.``[PPC VLE] SE_BTSTI (bit test immediate)``() =
    SE_BTSTI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "6653"

  [<TestMethod>]
  member _.``[PPC VLE] SE_CMP (compare word)``() =
    SE_CMP ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0c43"

  [<TestMethod>]
  member _.``[PPC VLE] SE_CMPL (compare logical word)``() =
    SE_CMPL ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0d43"

  [<TestMethod>]
  member _.``[PPC VLE] SE_CMPH (compare halfword)``() =
    SE_CMPH ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0e43"

  [<TestMethod>]
  member _.``[PPC VLE] SE_CMPHL (compare halfword logical)``() =
    SE_CMPHL ** [ O.Reg R3; O.Reg R4 ]
    |> testVLE "0f43"

  [<TestMethod>]
  member _.``[PPC VLE] SE_CMPI (compare immediate word)``() =
    SE_CMPI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "2a53"

  [<TestMethod>]
  member _.``[PPC VLE] SE_CMPLI (compare logical immediate word)``() =
    SE_CMPLI ** [ O.Reg R3; O.Imm 0x5UL ]
    |> testVLE "2243"

  [<TestMethod>]
  member _.``[PPC VLE] SE_B (branch)``() =
    SE_B ** [ O.Addr 0x8UL ]
    |> testVLE "e804"
    SE_B ** [ O.Addr 0xfffffff8UL ]
    |> testVLEOn WordSize.Bit32 "e8fc"
    SE_B ** [ O.Addr 0xfffffffffffffff8UL ]
    |> testVLEOn WordSize.Bit64 "e8fc"

  [<TestMethod>]
  member _.``[PPC VLE] SE_BL (branch and link)``() =
    SE_BL ** [ O.Addr 0x8UL ]
    |> testVLE "e904"
    SE_BL ** [ O.Addr 0xfffffff8UL ]
    |> testVLEOn WordSize.Bit32 "e9fc"
    SE_BL ** [ O.Addr 0xfffffffffffffff8UL ]
    |> testVLEOn WordSize.Bit64 "e9fc"

  [<TestMethod>]
  member _.``[PPC VLE] SE_BC (branch conditional)``() =
    SE_BC ** [ O.Imm 0x1UL; O.BI 2u; O.Addr 0x8UL ]
    |> testVLE "e604"
    SE_BC ** [ O.Imm 0x0UL; O.BI 3u; O.Addr 0xfffffff8UL ]
    |> testVLEOn WordSize.Bit32 "e3fc"
    SE_BC ** [ O.Imm 0x0UL; O.BI 3u; O.Addr 0xfffffffffffffff8UL ]
    |> testVLEOn WordSize.Bit64 "e3fc"

  [<TestMethod>]
  member _.``[PPC VLE] SE_LBZ (load byte and zero)``() =
    SE_LBZ ** [ O.Reg R3; O.Mem(4, R5) ]
    |> testVLE "8435"
    SE_LBZ ** [ O.Reg R3; O.Mem(4, R0) ]
    |> testVLE "8430"

  [<TestMethod>]
  member _.``[PPC VLE] SE_LHZ (load halfword and zero)``() =
    SE_LHZ ** [ O.Reg R3; O.Mem(4, R5) ]
    |> testVLE "a235"
    SE_LHZ ** [ O.Reg R3; O.Mem(4, R0) ]
    |> testVLE "a230"

  [<TestMethod>]
  member _.``[PPC VLE] SE_LWZ (load word and zero)``() =
    SE_LWZ ** [ O.Reg R3; O.Mem(4, R5) ]
    |> testVLE "c135"
    SE_LWZ ** [ O.Reg R3; O.Mem(4, R0) ]
    |> testVLE "c130"
    SE_LWZ ** [ O.Reg R31; O.Mem(60, R24) ]
    |> testVLE "cff8"

  [<TestMethod>]
  member _.``[PPC VLE] SE_STB (store byte)``() =
    SE_STB ** [ O.Reg R3; O.Mem(4, R5) ]
    |> testVLE "9435"
    SE_STB ** [ O.Reg R3; O.Mem(4, R0) ]
    |> testVLE "9430"
    SE_STB ** [ O.Reg R31; O.Mem(15, R24) ]
    |> testVLE "9ff8"

  [<TestMethod>]
  member _.``[PPC VLE] SE_STH (store halfword)``() =
    SE_STH ** [ O.Reg R3; O.Mem(4, R5) ]
    |> testVLE "b235"
    SE_STH ** [ O.Reg R3; O.Mem(4, R0) ]
    |> testVLE "b230"
    SE_STH ** [ O.Reg R31; O.Mem(30, R24) ]
    |> testVLE "bff8"

  [<TestMethod>]
  member _.``[PPC VLE] SE_STW (store word)``() =
    SE_STW ** [ O.Reg R3; O.Mem(4, R5) ]
    |> testVLE "d135"
    SE_STW ** [ O.Reg R3; O.Mem(4, R0) ]
    |> testVLE "d130"

  [<TestMethod>]
  member _.``[PPC VLE] E_LBZ (load byte and zero)``() =
    E_LBZ ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "3064fff8"
    E_LBZ ** [ O.Reg R31; O.Mem(32767, R0) ]
    |> testVLE "33e07fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_LBZU (load byte and zero with update)``() =
    E_LBZU ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "186400f8"

  [<TestMethod>]
  member _.``[PPC VLE] E_LHA (load halfword algebraic)``() =
    E_LHA ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "3864fff8"
    E_LHA ** [ O.Reg R31; O.Mem(32767, R0) ]
    |> testVLE "3be07fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_LHAU (load halfword algebraic with update)``() =
    E_LHAU ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "186403f8"

  [<TestMethod>]
  member _.``[PPC VLE] E_LHZ (load halfword and zero)``() =
    E_LHZ ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "5864fff8"
    E_LHZ ** [ O.Reg R31; O.Mem(32767, R0) ]
    |> testVLE "5be07fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_LHZU (load halfword and zero with update)``() =
    E_LHZU ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "186401f8"

  [<TestMethod>]
  member _.``[PPC VLE] E_LMW (load multiple word)``() =
    E_LMW ** [ O.Reg R28; O.Mem(-8, R4) ]
    |> testVLE "1b8408f8"
    E_LMW ** [ O.Reg R24; O.Mem(127, R3) ]
    |> testVLE "1b03087f"

  [<TestMethod>]
  member _.``[PPC VLE] E_LWZ (load word and zero)``() =
    E_LWZ ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "5064fff8"
    E_LWZ ** [ O.Reg R31; O.Mem(32767, R0) ]
    |> testVLE "53e07fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_LWZU (load word and zero with update)``() =
    E_LWZU ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "186402f8"

  [<TestMethod>]
  member _.``[PPC VLE] E_STB (store byte)``() =
    E_STB ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "3464fff8"
    E_STB ** [ O.Reg R31; O.Mem(32767, R0) ]
    |> testVLE "37e07fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_STBU (store byte with update)``() =
    E_STBU ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "186404f8"

  [<TestMethod>]
  member _.``[PPC VLE] E_STH (store halfword)``() =
    E_STH ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "5c64fff8"
    E_STH ** [ O.Reg R31; O.Mem(32767, R0) ]
    |> testVLE "5fe07fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_STHU (store halfword with update)``() =
    E_STHU ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "186405f8"

  [<TestMethod>]
  member _.``[PPC VLE] E_STMW (store multiple word)``() =
    E_STMW ** [ O.Reg R28; O.Mem(-8, R4) ]
    |> testVLE "1b8409f8"
    E_STMW ** [ O.Reg R24; O.Mem(127, R3) ]
    |> testVLE "1b03097f"

  [<TestMethod>]
  member _.``[PPC VLE] E_STW (store word)``() =
    E_STW ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "5464fff8"
    E_STW ** [ O.Reg R31; O.Mem(32767, R0) ]
    |> testVLE "57e07fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_STWU (store word with update)``() =
    E_STWU ** [ O.Reg R3; O.Mem(-8, R4) ]
    |> testVLE "186406f8"

  [<TestMethod>]
  member _.``[PPC VLE] E_B (branch)``() =
    E_B ** [ O.Addr 0x8UL ]
    |> testVLE "78000008"
    E_B ** [ O.Addr 0xfffffff8UL ]
    |> testVLEOn WordSize.Bit32 "79fffff8"
    E_B ** [ O.Addr 0xfffffffffffffff8UL ]
    |> testVLEOn WordSize.Bit64 "79fffff8"

  [<TestMethod>]
  member _.``[PPC VLE] E_BL (branch and link)``() =
    E_BL ** [ O.Addr 0x8UL ]
    |> testVLE "78000009"
    E_BL ** [ O.Addr 0xfffffff8UL ]
    |> testVLEOn WordSize.Bit32 "79fffff9"
    E_BL ** [ O.Addr 0xfffffffffffffff8UL ]
    |> testVLEOn WordSize.Bit64 "79fffff9"

  [<TestMethod>]
  member _.``[PPC VLE] E_BC (branch conditional)``() =
    E_BC ** [ O.Imm 0x1UL; O.BI 2u; O.Addr 0x8UL ]
    |> testVLE "7a120008"
    E_BC ** [ O.Imm 0x2UL; O.BI 1u; O.Addr 0x8UL ]
    |> testVLE "7a210008"
    E_BC ** [ O.Imm 0x3UL; O.BI 1u; O.Addr 0x8UL ]
    |> testVLE "7a310008"
    E_BC ** [ O.Imm 0x0UL; O.BI 15u; O.Addr 0xfffffff8UL ]
    |> testVLEOn WordSize.Bit32 "7a0ffff8"
    E_BC ** [ O.Imm 0x0UL; O.BI 15u; O.Addr 0xfffffffffffffff8UL ]
    |> testVLEOn WordSize.Bit64 "7a0ffff8"

  [<TestMethod>]
  member _.``[PPC VLE] E_BCL (branch conditional and link)``() =
    E_BCL ** [ O.Imm 0x0UL; O.BI 9u; O.Addr 0x8UL ]
    |> testVLE "7a090009"
    E_BCL ** [ O.Imm 0x2UL; O.BI 5u; O.Addr 0xfffffff8UL ]
    |> testVLEOn WordSize.Bit32 "7a25fff9"
    E_BCL ** [ O.Imm 0x2UL; O.BI 5u; O.Addr 0xfffffffffffffff8UL ]
    |> testVLEOn WordSize.Bit64 "7a25fff9"

  [<TestMethod>]
  member _.``[PPC VLE] E_SC (system call)``() =
    E_SC ** []
    |> testVLE "7c000048"
    E_SC ** [ O.Imm 0x1UL ]
    |> testVLE "7c000848"

  [<TestMethod>]
  member _.``[PPC VLE] E_CRAND (condition register AND)``() =
    E_CRAND ** [ O.BI 1u; O.BI 2u; O.BI 3u ]
    |> testVLE "7c221a02"
    E_CRAND ** [ O.BI 5u; O.BI 10u; O.BI 31u ]
    |> testVLE "7caafa02"

  [<TestMethod>]
  member _.``[PPC VLE] E_CRANDC (condition register AND with complement)``() =
    E_CRANDC ** [ O.BI 1u; O.BI 2u; O.BI 3u ]
    |> testVLE "7c221902"
    E_CRANDC ** [ O.BI 5u; O.BI 10u; O.BI 31u ]
    |> testVLE "7caaf902"

  [<TestMethod>]
  member _.``[PPC VLE] E_CREQV (condition register equivalent)``() =
    E_CREQV ** [ O.BI 1u; O.BI 2u; O.BI 3u ]
    |> testVLE "7c221a42"
    E_CREQV ** [ O.BI 5u; O.BI 10u; O.BI 31u ]
    |> testVLE "7caafa42"

  [<TestMethod>]
  member _.``[PPC VLE] E_CRNAND (condition register NAND)``() =
    E_CRNAND ** [ O.BI 1u; O.BI 2u; O.BI 3u ]
    |> testVLE "7c2219c2"
    E_CRNAND ** [ O.BI 5u; O.BI 10u; O.BI 31u ]
    |> testVLE "7caaf9c2"

  [<TestMethod>]
  member _.``[PPC VLE] E_CRNOR (condition register NOR)``() =
    E_CRNOR ** [ O.BI 1u; O.BI 2u; O.BI 3u ]
    |> testVLE "7c221842"
    E_CRNOR ** [ O.BI 5u; O.BI 10u; O.BI 31u ]
    |> testVLE "7caaf842"

  [<TestMethod>]
  member _.``[PPC VLE] E_CROR (condition register OR)``() =
    E_CROR ** [ O.BI 1u; O.BI 2u; O.BI 3u ]
    |> testVLE "7c221b82"
    E_CROR ** [ O.BI 5u; O.BI 10u; O.BI 31u ]
    |> testVLE "7caafb82"

  [<TestMethod>]
  member _.``[PPC VLE] E_CRORC (condition register OR with complement)``() =
    E_CRORC ** [ O.BI 1u; O.BI 2u; O.BI 3u ]
    |> testVLE "7c221b42"
    E_CRORC ** [ O.BI 5u; O.BI 10u; O.BI 31u ]
    |> testVLE "7caafb42"

  [<TestMethod>]
  member _.``[PPC VLE] E_CRXOR (condition register XOR)``() =
    E_CRXOR ** [ O.BI 1u; O.BI 2u; O.BI 3u ]
    |> testVLE "7c221982"
    E_CRXOR ** [ O.BI 5u; O.BI 10u; O.BI 31u ]
    |> testVLE "7caaf982"

  [<TestMethod>]
  member _.``[PPC VLE] E_MCRF (move CR field)``() =
    E_MCRF ** [ O.Reg CR1; O.Reg CR2 ]
    |> testVLE "7c880020"
    E_MCRF ** [ O.Reg CR5; O.Reg CR2 ]
    |> testVLE "7e880020"

  [<TestMethod>]
  member _.``[PPC VLE] E_ADDI (add scaled immediate)``() =
    E_ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1864800c"
    E_ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0x3400UL ]
    |> testVLE "18648134"
    E_ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0x560000UL ]
    |> testVLE "18648256"
    E_ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0x78000000UL ]
    |> testVLE "18648378"
    E_ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffff9cUL ]
    |> testVLEOn WordSize.Bit32 "1864849c"
    E_ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffffffffffff9cUL ]
    |> testVLEOn WordSize.Bit64 "1864849c"
    E_ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffff12ffUL ]
    |> testVLEOn WordSize.Bit32 "18648512"
    E_ADDI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffffffffff12ffUL ]
    |> testVLEOn WordSize.Bit64 "18648512"

  [<TestMethod>]
  member _.``[PPC VLE] E_ADDI. (add scaled immediate, record)``() =
    E_ADDIdot ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1864880c"

  [<TestMethod>]
  member _.``[PPC VLE] E_ADDIC (add scaled immediate carrying)``() =
    E_ADDIC ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1864900c"
    E_ADDIC ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffff9cUL ]
    |> testVLEOn WordSize.Bit32 "1864949c"
    E_ADDIC ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffffffffffff9cUL ]
    |> testVLEOn WordSize.Bit64 "1864949c"

  [<TestMethod>]
  member _.``[PPC VLE] E_ADDIC. (add scaled immediate carrying, record)``() =
    E_ADDICdot ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1864980c"

  [<TestMethod>]
  member _.``[PPC VLE] E_ANDI (AND scaled immediate)``() =
    E_ANDI ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1883c00c"
    E_ANDI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffff12ffUL ]
    |> testVLEOn WordSize.Bit32 "1883c512"
    E_ANDI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffffffffff12ffUL ]
    |> testVLEOn WordSize.Bit64 "1883c512"

  [<TestMethod>]
  member _.``[PPC VLE] E_ANDI. (AND scaled immediate, record)``() =
    E_ANDIdot ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1883c80c"

  [<TestMethod>]
  member _.``[PPC VLE] E_ORI (OR scaled immediate)``() =
    E_ORI ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1883d00c"
    E_ORI ** [ O.Reg R3; O.Reg R4; O.Imm 0x3400UL ]
    |> testVLE "1883d134"

  [<TestMethod>]
  member _.``[PPC VLE] E_ORI. (OR scaled immediate, record)``() =
    E_ORIdot ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1883d80c"

  [<TestMethod>]
  member _.``[PPC VLE] E_XORI (XOR scaled immediate)``() =
    E_XORI ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1883e00c"
    E_XORI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffff12ffUL ]
    |> testVLEOn WordSize.Bit32 "1883e512"
    E_XORI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffffffffff12ffUL ]
    |> testVLEOn WordSize.Bit64 "1883e512"

  [<TestMethod>]
  member _.``[PPC VLE] E_XORI. (XOR scaled immediate, record)``() =
    E_XORIdot ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1883e80c"

  [<TestMethod>]
  member _.``[PPC VLE] E_SUBFIC (subtract from scaled immediate carrying)``() =
    E_SUBFIC ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1864b00c"
    E_SUBFIC ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffff9cUL ]
    |> testVLEOn WordSize.Bit32 "1864b49c"
    E_SUBFIC ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffffffffffff9cUL ]
    |> testVLEOn WordSize.Bit64 "1864b49c"

  [<TestMethod>]
  member _.``[PPC VLE] E_SUBFIC. (subtract from scaled immediate, record)``() =
    E_SUBFICdot ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1864b80c"

  [<TestMethod>]
  member _.``[PPC VLE] E_MULLI (multiply low scaled immediate)``() =
    E_MULLI ** [ O.Reg R3; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1864a00c"
    E_MULLI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffff9cUL ]
    |> testVLEOn WordSize.Bit32 "1864a49c"
    E_MULLI ** [ O.Reg R3; O.Reg R4; O.Imm 0xffffffffffffff9cUL ]
    |> testVLEOn WordSize.Bit64 "1864a49c"

  [<TestMethod>]
  member _.``[PPC VLE] E_CMPI (compare scaled immediate word)``() =
    E_CMPI ** [ O.Reg CR1; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "1824a80c"
    E_CMPI ** [ O.Reg CR3; O.Reg R31; O.Imm 0xffffff9cUL ]
    |> testVLEOn WordSize.Bit32 "187fac9c"
    E_CMPI ** [ O.Reg CR3; O.Reg R31; O.Imm 0xffffffffffffff9cUL ]
    |> testVLEOn WordSize.Bit64 "187fac9c"

  [<TestMethod>]
  member _.``[PPC VLE] E_CMPLI (compare logical scaled immediate word)``() =
    E_CMPLI ** [ O.Reg CR1; O.Reg R4; O.Imm 0xcUL ]
    |> testVLE "18a4a80c"
    E_CMPLI ** [ O.Reg CR3; O.Reg R31; O.Imm 0xffffff9cUL ]
    |> testVLEOn WordSize.Bit32 "18ffac9c"
    E_CMPLI ** [ O.Reg CR3; O.Reg R31; O.Imm 0xffffffffffffff9cUL ]
    |> testVLEOn WordSize.Bit64 "18ffac9c"

  [<TestMethod>]
  member _.``[PPC VLE] E_ADD16I (add immediate)``() =
    E_ADD16I ** [ O.Reg R3; O.Reg R4; O.Imm 0x64UL ]
    |> testVLE "1c640064"
    E_ADD16I ** [ O.Reg R31; O.Reg R24; O.Imm 0xffffff9cUL ]
    |> testVLEOn WordSize.Bit32 "1ff8ff9c"
    E_ADD16I ** [ O.Reg R31; O.Reg R24; O.Imm 0xffffffffffffff9cUL ]
    |> testVLEOn WordSize.Bit64 "1ff8ff9c"
    E_ADD16I ** [ O.Reg R3; O.Reg R0; O.Imm 0x7fffUL ]
    |> testVLE "1c607fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_ADD2I. (add immediate, 2 operand, record)``() =
    E_ADD2Idot ** [ O.Reg R5; O.Imm 0xffffff9cUL ]
    |> testVLEOn WordSize.Bit32 "73e58f9c"
    E_ADD2Idot ** [ O.Reg R5; O.Imm 0xffffffffffffff9cUL ]
    |> testVLEOn WordSize.Bit64 "73e58f9c"

  [<TestMethod>]
  member _.``[PPC VLE] E_ADD2IS (add immediate shifted, 2 operand)``() =
    E_ADD2IS ** [ O.Reg R6; O.Imm 0x64UL ]
    |> testVLE "70069064"
    E_ADD2IS ** [ O.Reg R6; O.Imm 0xffffffffUL ]
    |> testVLEOn WordSize.Bit32 "73e697ff"
    E_ADD2IS ** [ O.Reg R6; O.Imm 0xffffffffffffffffUL ]
    |> testVLEOn WordSize.Bit64 "73e697ff"

  [<TestMethod>]
  member _.``[PPC VLE] E_AND2I. (AND immediate, 2 operand, record)``() =
    E_AND2Idot ** [ O.Reg R7; O.Imm 0x1234UL ]
    |> testVLE "70e2ca34"

  [<TestMethod>]
  member _.``[PPC VLE] E_AND2IS. (AND shifted immediate and record)``() =
    E_AND2ISdot ** [ O.Reg R7; O.Imm 0x1234UL ]
    |> testVLE "70e2ea34"

  [<TestMethod>]
  member _.``[PPC VLE] E_OR2I (OR immediate, 2 operand)``() =
    E_OR2I ** [ O.Reg R7; O.Imm 0x1234UL ]
    |> testVLE "70e2c234"

  [<TestMethod>]
  member _.``[PPC VLE] E_OR2IS (OR immediate shifted, 2 operand)``() =
    E_OR2IS ** [ O.Reg R7; O.Imm 0x1234UL ]
    |> testVLE "70e2d234"

  [<TestMethod>]
  member _.``[PPC VLE] E_LI (load immediate)``() =
    E_LI ** [ O.Reg R3; O.Imm 0xfffe7960UL ]
    |> testVLEOn WordSize.Bit32 "706f7160"
    E_LI ** [ O.Reg R3; O.Imm 0xfffffffffffe7960UL ]
    |> testVLEOn WordSize.Bit64 "706f7160"
    E_LI ** [ O.Reg R3; O.Imm 0x64UL ]
    |> testVLE "70600064"
    E_LI ** [ O.Reg R31; O.Imm 0x7ffffUL ]
    |> testVLE "73ff3fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_LIS (load immediate shifted)``() =
    E_LIS ** [ O.Reg R3; O.Imm 0x1234UL ]
    |> testVLE "7062e234"

  [<TestMethod>]
  member _.``[PPC VLE] E_MULL2I (multiply low immediate, 2 operand)``() =
    E_MULL2I ** [ O.Reg R4; O.Imm 0xfffffffbUL ]
    |> testVLEOn WordSize.Bit32 "73e4a7fb"
    E_MULL2I ** [ O.Reg R4; O.Imm 0xfffffffffffffffbUL ]
    |> testVLEOn WordSize.Bit64 "73e4a7fb"

  [<TestMethod>]
  member _.``[PPC VLE] E_CMP16I (compare immediate word)``() =
    E_CMP16I ** [ O.Reg R4; O.Imm 0xfffffffbUL ]
    |> testVLEOn WordSize.Bit32 "73e49ffb"
    E_CMP16I ** [ O.Reg R4; O.Imm 0xfffffffffffffffbUL ]
    |> testVLEOn WordSize.Bit64 "73e49ffb"
    E_CMP16I ** [ O.Reg R4; O.Imm 0x7fffUL ]
    |> testVLE "71e49fff"

  [<TestMethod>]
  member _.``[PPC VLE] E_CMPH16I (compare halfword immediate)``() =
    E_CMPH16I ** [ O.Reg R4; O.Imm 0xfffffffbUL ]
    |> testVLEOn WordSize.Bit32 "73e4b7fb"
    E_CMPH16I ** [ O.Reg R4; O.Imm 0xfffffffffffffffbUL ]
    |> testVLEOn WordSize.Bit64 "73e4b7fb"

  [<TestMethod>]
  member _.``[PPC VLE] E_CMPHL16I (compare halfword logical immediate)``() =
    E_CMPHL16I ** [ O.Reg R4; O.Imm 0x8005UL ]
    |> testVLE "7204b805"

  [<TestMethod>]
  member _.``[PPC VLE] E_CMPL16I (compare logical immediate word)``() =
    E_CMPL16I ** [ O.Reg R4; O.Imm 0x8005UL ]
    |> testVLE "7204a805"

  [<TestMethod>]
  member _.``[PPC VLE] E_RLW (rotate left word)``() =
    E_RLW ** [ O.Reg R3; O.Reg R4; O.Reg R5 ]
    |> testVLE "7c832a30"

  [<TestMethod>]
  member _.``[PPC VLE] E_RLW. (rotate left word, record)``() =
    E_RLWdot ** [ O.Reg R3; O.Reg R4; O.Reg R5 ]
    |> testVLE "7c832a31"

  [<TestMethod>]
  member _.``[PPC VLE] E_RLWI (rotate left word immediate)``() =
    E_RLWI ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL ]
    |> testVLE "7c832a70"
    E_RLWI ** [ O.Reg R3; O.Reg R4; O.Imm 0x0UL ]
    |> testVLE "7c830270"

  [<TestMethod>]
  member _.``[PPC VLE] E_RLWI. (rotate left word immediate, record)``() =
    E_RLWIdot ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL ]
    |> testVLE "7c832a71"

  [<TestMethod>]
  member _.``[PPC VLE] E_RLWIMI (rotate and insert)``() =
    E_RLWIMI ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL; O.Imm 0x6UL; O.Imm 0x7UL ]
    |> testVLE "7483298e"
    E_RLWIMI ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL; O.Imm 0x1cUL; O.Imm 0x3UL ]
    |> testVLE "74832f06"

  [<TestMethod>]
  member _.``[PPC VLE] E_RLWINM (rotate and mask)``() =
    E_RLWINM ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL; O.Imm 0x6UL; O.Imm 0x7UL ]
    |> testVLE "7483298f"
    E_RLWINM ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL; O.Imm 0x1cUL; O.Imm 0x3UL ]
    |> testVLE "74832f07"

  [<TestMethod>]
  member _.``[PPC VLE] E_SLWI (shift left word immediate)``() =
    E_SLWI ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL ]
    |> testVLE "7c832870"
    E_SLWI ** [ O.Reg R3; O.Reg R4; O.Imm 0x0UL ]
    |> testVLE "7c830070"
    E_SLWI ** [ O.Reg R3; O.Reg R4; O.Imm 0x1fUL ]
    |> testVLE "7c83f870"

  [<TestMethod>]
  member _.``[PPC VLE] E_SLWI. (shift left word immediate, record)``() =
    E_SLWIdot ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL ]
    |> testVLE "7c832871"

  [<TestMethod>]
  member _.``[PPC VLE] E_SRWI (shift right word immediate)``() =
    E_SRWI ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL ]
    |> testVLE "7c832c70"
    E_SRWI ** [ O.Reg R3; O.Reg R4; O.Imm 0x0UL ]
    |> testVLE "7c830470"
    E_SRWI ** [ O.Reg R3; O.Reg R4; O.Imm 0x1fUL ]
    |> testVLE "7c83fc70"

  [<TestMethod>]
  member _.``[PPC VLE] E_SRWI. (shift right word immediate, record)``() =
    E_SRWIdot ** [ O.Reg R3; O.Reg R4; O.Imm 0x5UL ]
    |> testVLE "7c832c71"

  [<TestMethod>]
  member _.``[PPC VLE] E_CMPH (compare halfword)``() =
    E_CMPH ** [ O.Reg CR1; O.Reg R4; O.Reg R5 ]
    |> testVLE "7c84281c"
    E_CMPH ** [ O.Reg CR3; O.Reg R31; O.Reg R30 ]
    |> testVLE "7d9ff01c"

  [<TestMethod>]
  member _.``[PPC VLE] E_CMPHL (compare halfword logical)``() =
    E_CMPHL ** [ O.Reg CR1; O.Reg R4; O.Reg R5 ]
    |> testVLE "7c84285c"
    E_CMPHL ** [ O.Reg CR3; O.Reg R31; O.Reg R30 ]
    |> testVLE "7d9ff05c"

  [<TestMethod>]
  member _.``[PPC VLE] Retains base integer instructions``() =
    ADD ** [ O.Reg R3; O.Reg R4; O.Reg R5 ]
    |> testVLE "7c642a14"
    LWZX ** [ O.Reg R3; O.Reg R4; O.Reg R5 ]
    |> testVLE "7c64282e"


/// Prefixed instructions fetch their prefix and suffix in the selected order.
[<TestClass>]
type PrefixedParserTests() =
  let check hex expected =
    let words = ByteArray.ofHexString hex |> Array.chunkBySize 4
    for endian in [ Endian.Big; Endian.Little ] do
      let bytes =
        words |> Array.collect (fun w ->
          if endian = Endian.Big then w else Array.rev w)
      let reader = BinReader.Init endian
      let parser = Parser(WordSize.Bit64, reader) :> IInstructionParsable
      let ins = parser.Parse(bytes, 0x20100000UL) :?> Instruction
      Assert.AreEqual(box expected, box (ins.Opcode, ins.Operands))
      Assert.AreEqual<uint32>(8u, ins.Length)
      let small = Parser(WordSize.Bit32, reader) :> IInstructionParsable
      Assert.Throws<ParsingFailureException>(fun () ->
        small.Parse(bytes, 0x20100000UL) |> ignore)
      |> ignore

  [<TestMethod>]
  member _.``[PPC] PADDI prefixed decoding``() =
    let operands =
      FourOperands(OprReg R5, OprReg R6, OprImm 12UL, OprImm 0UL)
    check "0600000038a6000c" (PADDI, operands)

  [<TestMethod>]
  member _.``[PPC] PLBZ prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R5, OprMem64(8L, R6), OprImm 0UL)
    check "0600000088a60008" (PLBZ, operands)

  [<TestMethod>]
  member _.``[PPC] PLD prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R5, OprMem64(8L, R6), OprImm 0UL)
    check "04000000e4a60008" (PLD, operands)

  [<TestMethod>]
  member _.``[PPC] PLFD prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg F1, OprMem64(8L, R6), OprImm 0UL)
    check "06000000c8260008" (PLFD, operands)

  [<TestMethod>]
  member _.``[PPC] PLFS prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg F1, OprMem64(8L, R6), OprImm 0UL)
    check "06000000c0260008" (PLFS, operands)

  [<TestMethod>]
  member _.``[PPC] PLHA prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R5, OprMem64(8L, R6), OprImm 0UL)
    check "06000000a8a60008" (PLHA, operands)

  [<TestMethod>]
  member _.``[PPC] PLHZ prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R5, OprMem64(8L, R6), OprImm 0UL)
    check "06000000a0a60008" (PLHZ, operands)

  [<TestMethod>]
  member _.``[PPC] PLQ prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R10, OprMem64(8L, R6), OprImm 0UL)
    check "04000000e1460008" (PLQ, operands)

  [<TestMethod>]
  member _.``[PPC] PLWA prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R5, OprMem64(8L, R6), OprImm 0UL)
    check "04000000a4a60008" (PLWA, operands)

  [<TestMethod>]
  member _.``[PPC] PLWZ prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R5, OprMem64(8L, R6), OprImm 0UL)
    check "0600000080a60008" (PLWZ, operands)

  [<TestMethod>]
  member _.``[PPC] PLXSD prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg V1A, OprMem64(8L, R6), OprImm 0UL)
    check "04000000a8260008" (PLXSD, operands)

  [<TestMethod>]
  member _.``[PPC] PLXSSP prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg V1A, OprMem64(8L, R6), OprImm 0UL)
    check "04000000ac260008" (PLXSSP, operands)

  [<TestMethod>]
  member _.``[PPC] PLXV prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg F1, OprMem64(8L, R6), OprImm 0UL)
    check "04000000c8260008" (PLXV, operands)

  [<TestMethod>]
  member _.``[PPC] PLXVP prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg F2, OprMem64(8L, R6), OprImm 0UL)
    check "04000000e8460008" (PLXVP, operands)

  [<TestMethod>]
  member _.``[PPC] PNOP prefixed decoding``() =
    let operands =
      NoOperand
    check "0700000000000000" (PNOP, operands)

  [<TestMethod>]
  member _.``[PPC] PSTB prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R8, OprMem64(8L, R6), OprImm 0UL)
    check "0600000099060008" (PSTB, operands)

  [<TestMethod>]
  member _.``[PPC] PSTD prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R8, OprMem64(8L, R6), OprImm 0UL)
    check "04000000f5060008" (PSTD, operands)

  [<TestMethod>]
  member _.``[PPC] PSTFD prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg F1, OprMem64(8L, R6), OprImm 0UL)
    check "06000000d8260008" (PSTFD, operands)

  [<TestMethod>]
  member _.``[PPC] PSTFS prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg F1, OprMem64(8L, R6), OprImm 0UL)
    check "06000000d0260008" (PSTFS, operands)

  [<TestMethod>]
  member _.``[PPC] PSTH prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R8, OprMem64(8L, R6), OprImm 0UL)
    check "06000000b1060008" (PSTH, operands)

  [<TestMethod>]
  member _.``[PPC] PSTQ prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R10, OprMem64(8L, R6), OprImm 0UL)
    check "04000000f1460008" (PSTQ, operands)

  [<TestMethod>]
  member _.``[PPC] PSTW prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg R8, OprMem64(8L, R6), OprImm 0UL)
    check "0600000091060008" (PSTW, operands)

  [<TestMethod>]
  member _.``[PPC] PSTXSD prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg V1A, OprMem64(8L, R6), OprImm 0UL)
    check "04000000b8260008" (PSTXSD, operands)

  [<TestMethod>]
  member _.``[PPC] PSTXSSP prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg V1A, OprMem64(8L, R6), OprImm 0UL)
    check "04000000bc260008" (PSTXSSP, operands)

  [<TestMethod>]
  member _.``[PPC] PSTXV prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg F1, OprMem64(8L, R6), OprImm 0UL)
    check "04000000d8260008" (PSTXV, operands)

  [<TestMethod>]
  member _.``[PPC] PSTXVP prefixed decoding``() =
    let operands =
      ThreeOperands(OprReg F2, OprMem64(8L, R6), OprImm 0UL)
    check "04000000f8460008" (PSTXVP, operands)

  [<TestMethod>]
  member _.``[PPC] Prefixed displacement keeps all 34 bits``() =
    let max =
      FourOperands(OprReg R3, OprReg R0, OprImm 0x1ffffffffUL, OprImm 0UL)
    check "0601ffff3860ffff" (PADDI, max)
    let negative = OprImm 0xfffffffe00000000UL
    let min = FourOperands(OprReg R3, OprReg R0, negative, OprImm 1UL)
    check "0612000038600000" (PADDI, min)
    let address = OprMem64(8589934591L, R0)
    let operands = ThreeOperands(OprReg R5, address, OprImm 1UL)
    check "0611ffff88a0ffff" (PLBZ, operands)

  [<TestMethod>]
  member _.``[PPC] Invalid prefix combinations are refused``() =
    let reader = BinReader.Init Endian.Big
    let parser = Parser(WordSize.Bit64, reader) :> IInstructionParsable
    for hex in
      [ "0610000038a6000c"
        "04000000e1660008"
        "04000000e14a0008"
        "0480000088a60008"
        "0700000048000000"
        "06000000" ] do
      Assert.Throws<ParsingFailureException>(fun () ->
        parser.Parse(ByteArray.ofHexString hex, 0UL) |> ignore)
      |> ignore

  [<TestMethod>]
  member _.``[PPC] Prefix cannot cross a 64 byte boundary``() =
    let reader = BinReader.Init Endian.Big
    let parser = Parser(WordSize.Bit64, reader) :> IInstructionParsable
    let bytes = ByteArray.ofHexString "0600000038a6000c"
    Assert.AreEqual<int>(8, parser.MaxInstructionSize)
    Assert.AreEqual<uint32>(8u, parser.Parse(bytes, 56UL).Length)
    Assert.Throws<ParsingFailureException>(fun () ->
      parser.Parse(bytes, 60UL) |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[PPC] XXBLENDVB prefixed decoding``() =
    let operands =
      FourOperands(
        OprReg F1,
        OprReg F2,
        OprReg F3,
        OprReg F4
      )
    check "0500000084221900" (XXBLENDVB, operands)

  [<TestMethod>]
  member _.``[PPC] XXBLENDVD prefixed decoding``() =
    let operands =
      FourOperands(
        OprReg F1,
        OprReg F2,
        OprReg F3,
        OprReg F4
      )
    check "0500000084221930" (XXBLENDVD, operands)

  [<TestMethod>]
  member _.``[PPC] XXBLENDVH prefixed decoding``() =
    let operands =
      FourOperands(
        OprReg F1,
        OprReg F2,
        OprReg F3,
        OprReg F4
      )
    check "0500000084221910" (XXBLENDVH, operands)

  [<TestMethod>]
  member _.``[PPC] XXBLENDVW prefixed decoding``() =
    let operands =
      FourOperands(
        OprReg F1,
        OprReg F2,
        OprReg F3,
        OprReg F4
      )
    check "0500000084221920" (XXBLENDVW, operands)

  [<TestMethod>]
  member _.``[PPC] XXEVAL prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg F1,
        OprReg F2,
        OprReg F3,
        OprReg F4,
        OprImm 90UL
      )
    check "0500005a88221910" (XXEVAL, operands)

  [<TestMethod>]
  member _.``[PPC] XXPERMX prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg F1,
        OprReg F2,
        OprReg F3,
        OprReg F4,
        OprImm 1UL
      )
    check "0500000188221900" (XXPERMX, operands)

  [<TestMethod>]
  member _.``[PPC] XXSPLTI32DX prefixed decoding``() =
    let operands =
      ThreeOperands(
        OprReg F1,
        OprImm 1UL,
        OprImm 305419896UL
      )
    check "0500123480225678" (XXSPLTI32DX, operands)

  [<TestMethod>]
  member _.``[PPC] XXSPLTIDP prefixed decoding``() =
    let operands =
      TwoOperands(OprReg F1, OprImm 305419896UL)
    check "0500123480245678" (XXSPLTIDP, operands)

  [<TestMethod>]
  member _.``[PPC] XXSPLTIW prefixed decoding``() =
    let operands =
      TwoOperands(OprReg F1, OprImm 305419896UL)
    check "0500123480265678" (XXSPLTIW, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVBF16GER2 prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021998" (PMXVBF16GER2, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVBF16GER2NN prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021f90" (PMXVBF16GER2NN, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVBF16GER2NP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021b90" (PMXVBF16GER2NP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVBF16GER2PN prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021d90" (PMXVBF16GER2PN, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVBF16GER2PP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021990" (PMXVBF16GER2PP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF16GER2 prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021898" (PMXVF16GER2, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF16GER2NN prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021e90" (PMXVF16GER2NN, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF16GER2NP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021a90" (PMXVF16GER2NP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF16GER2PN prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021c90" (PMXVF16GER2PN, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF16GER2PP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021890" (PMXVF16GER2PP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF32GER prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "07900033ee0218d8" (PMXVF32GER, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF32GERNN prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "07900033ee021ed0" (PMXVF32GERNN, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF32GERNP prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "07900033ee021ad0" (PMXVF32GERNP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF32GERPN prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "07900033ee021cd0" (PMXVF32GERPN, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF32GERPP prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "07900033ee0218d0" (PMXVF32GERPP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF64GER prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F6,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "0790003cee0619d8" (PMXVF64GER, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF64GERNN prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F6,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "0790003cee061fd0" (PMXVF64GERNN, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF64GERNP prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F6,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "0790003cee061bd0" (PMXVF64GERNP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF64GERPN prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F6,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "0790003cee061dd0" (PMXVF64GERPN, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVF64GERPP prefixed decoding``() =
    let operands =
      FiveOperands(
        OprReg ACC4,
        OprReg F6,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL
      )
    check "0790003cee0619d0" (PMXVF64GERPP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI16GER2 prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021a58" (PMXVI16GER2, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI16GER2PP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021b58" (PMXVI16GER2PP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI16GER2S prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021958" (PMXVI16GER2S, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI16GER2SPP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07904033ee021950" (PMXVI16GER2SPP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI4GER8 prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07900133ee021918" (PMXVI4GER8, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI4GER8PP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07900133ee021910" (PMXVI4GER8PP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI8GER4 prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07901033ee021818" (PMXVI8GER4, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI8GER4PP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07901033ee021810" (PMXVI8GER4PP, operands)

  [<TestMethod>]
  member _.``[PPC] PMXVI8GER4SPP prefixed decoding``() =
    let operands =
      SixOperands(
        OprReg ACC4,
        OprReg F2,
        OprReg F3,
        OprImm 3UL,
        OprImm 3UL,
        OprImm 1UL
      )
    check "07901033ee021b18" (PMXVI8GER4SPP, operands)

/// Original mnemonics decoded from the independently assembled GNU words.
[<TestClass>]
type BackfillParserTests() =
  let decode hex endian (size: WordSize) opcode =
    let parser = Parser(size, BinReader.Init endian) :> IInstructionParsable
    let bytes = ByteArray.ofHexString hex
    let ins = parser.Parse(bytes, 0x20100000UL) :?> Instruction
    Assert.AreEqual<Opcode>(opcode, ins.Opcode)
    Assert.AreEqual<uint32>(4u, ins.Length)

  let refuse hex =
    let parser = Parser(WordSize.Bit32, BinReader.Init Endian.Big)
                 :> IInstructionParsable
    Assert.Throws<ParsingFailureException>(fun () ->
      parser.Parse(ByteArray.ofHexString hex, 0UL) |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[PPC T] ADDC original decoding``() =
    decode "7ca63814" Endian.Big WordSize.Bit32 ADDC
    decode "7ca63814" Endian.Big WordSize.Bit64 ADDC
    decode "1438a67c" Endian.Little WordSize.Bit64 ADDC

  [<TestMethod>]
  member _.``[PPC T] ADDC. original decoding``() =
    decode "7ca63815" Endian.Big WordSize.Bit32 ADDCdot
    decode "7ca63815" Endian.Big WordSize.Bit64 ADDCdot
    decode "1538a67c" Endian.Little WordSize.Bit64 ADDCdot

  [<TestMethod>]
  member _.``[PPC T] ADDCO original decoding``() =
    decode "7ca63c14" Endian.Big WordSize.Bit32 ADDCO
    decode "7ca63c14" Endian.Big WordSize.Bit64 ADDCO
    decode "143ca67c" Endian.Little WordSize.Bit64 ADDCO

  [<TestMethod>]
  member _.``[PPC T] ADDCO. original decoding``() =
    decode "7ca63c15" Endian.Big WordSize.Bit32 ADDCOdot
    decode "7ca63c15" Endian.Big WordSize.Bit64 ADDCOdot
    decode "153ca67c" Endian.Little WordSize.Bit64 ADDCOdot

  [<TestMethod>]
  member _.``[PPC T] ADD. original decoding``() =
    decode "7ca63a15" Endian.Big WordSize.Bit32 ADDdot
    decode "7ca63a15" Endian.Big WordSize.Bit64 ADDdot
    decode "153aa67c" Endian.Little WordSize.Bit64 ADDdot

  [<TestMethod>]
  member _.``[PPC T] ADDE original decoding``() =
    decode "7ca63914" Endian.Big WordSize.Bit32 ADDE
    decode "7ca63914" Endian.Big WordSize.Bit64 ADDE
    decode "1439a67c" Endian.Little WordSize.Bit64 ADDE

  [<TestMethod>]
  member _.``[PPC T] ADDE. original decoding``() =
    decode "7ca63915" Endian.Big WordSize.Bit32 ADDEdot
    decode "7ca63915" Endian.Big WordSize.Bit64 ADDEdot
    decode "1539a67c" Endian.Little WordSize.Bit64 ADDEdot

  [<TestMethod>]
  member _.``[PPC T] ADDEO original decoding``() =
    decode "7ca63d14" Endian.Big WordSize.Bit32 ADDEO
    decode "7ca63d14" Endian.Big WordSize.Bit64 ADDEO
    decode "143da67c" Endian.Little WordSize.Bit64 ADDEO

  [<TestMethod>]
  member _.``[PPC T] ADDEO. original decoding``() =
    decode "7ca63d15" Endian.Big WordSize.Bit32 ADDEOdot
    decode "7ca63d15" Endian.Big WordSize.Bit64 ADDEOdot
    decode "153da67c" Endian.Little WordSize.Bit64 ADDEOdot

  [<TestMethod>]
  member _.``[PPC T] ADDIC original decoding``() =
    decode "30a6000c" Endian.Big WordSize.Bit32 ADDIC
    decode "30a6000c" Endian.Big WordSize.Bit64 ADDIC
    decode "0c00a630" Endian.Little WordSize.Bit64 ADDIC

  [<TestMethod>]
  member _.``[PPC T] ADDIC. original decoding``() =
    decode "34a6000c" Endian.Big WordSize.Bit32 ADDICdot
    decode "34a6000c" Endian.Big WordSize.Bit64 ADDICdot
    decode "0c00a634" Endian.Little WordSize.Bit64 ADDICdot

  [<TestMethod>]
  member _.``[PPC T] ADDIS original decoding``() =
    decode "3ca6000c" Endian.Big WordSize.Bit32 ADDIS
    decode "3ca6000c" Endian.Big WordSize.Bit64 ADDIS
    decode "0c00a63c" Endian.Little WordSize.Bit64 ADDIS

  [<TestMethod>]
  member _.``[PPC T] ADDME original decoding``() =
    decode "7ca601d4" Endian.Big WordSize.Bit32 ADDME
    decode "7ca601d4" Endian.Big WordSize.Bit64 ADDME
    decode "d401a67c" Endian.Little WordSize.Bit64 ADDME

  [<TestMethod>]
  member _.``[PPC T] ADDME. original decoding``() =
    decode "7ca601d5" Endian.Big WordSize.Bit32 ADDMEdot
    decode "7ca601d5" Endian.Big WordSize.Bit64 ADDMEdot
    decode "d501a67c" Endian.Little WordSize.Bit64 ADDMEdot

  [<TestMethod>]
  member _.``[PPC T] ADDMEO original decoding``() =
    decode "7ca605d4" Endian.Big WordSize.Bit32 ADDMEO
    decode "7ca605d4" Endian.Big WordSize.Bit64 ADDMEO
    decode "d405a67c" Endian.Little WordSize.Bit64 ADDMEO

  [<TestMethod>]
  member _.``[PPC T] ADDMEO. original decoding``() =
    decode "7ca605d5" Endian.Big WordSize.Bit32 ADDMEOdot
    decode "7ca605d5" Endian.Big WordSize.Bit64 ADDMEOdot
    decode "d505a67c" Endian.Little WordSize.Bit64 ADDMEOdot

  [<TestMethod>]
  member _.``[PPC T] ADDO original decoding``() =
    decode "7ca63e14" Endian.Big WordSize.Bit32 ADDO
    decode "7ca63e14" Endian.Big WordSize.Bit64 ADDO
    decode "143ea67c" Endian.Little WordSize.Bit64 ADDO

  [<TestMethod>]
  member _.``[PPC T] ADDO. original decoding``() =
    decode "7ca63e15" Endian.Big WordSize.Bit32 ADDOdot
    decode "7ca63e15" Endian.Big WordSize.Bit64 ADDOdot
    decode "153ea67c" Endian.Little WordSize.Bit64 ADDOdot

  [<TestMethod>]
  member _.``[PPC T] ADDZE original decoding``() =
    decode "7ca60194" Endian.Big WordSize.Bit32 ADDZE
    decode "7ca60194" Endian.Big WordSize.Bit64 ADDZE
    decode "9401a67c" Endian.Little WordSize.Bit64 ADDZE

  [<TestMethod>]
  member _.``[PPC T] ADDZE. original decoding``() =
    decode "7ca60195" Endian.Big WordSize.Bit32 ADDZEdot
    decode "7ca60195" Endian.Big WordSize.Bit64 ADDZEdot
    decode "9501a67c" Endian.Little WordSize.Bit64 ADDZEdot

  [<TestMethod>]
  member _.``[PPC T] ADDZEO original decoding``() =
    decode "7ca60594" Endian.Big WordSize.Bit32 ADDZEO
    decode "7ca60594" Endian.Big WordSize.Bit64 ADDZEO
    decode "9405a67c" Endian.Little WordSize.Bit64 ADDZEO

  [<TestMethod>]
  member _.``[PPC T] ADDZEO. original decoding``() =
    decode "7ca60595" Endian.Big WordSize.Bit32 ADDZEOdot
    decode "7ca60595" Endian.Big WordSize.Bit64 ADDZEOdot
    decode "9505a67c" Endian.Little WordSize.Bit64 ADDZEOdot

  [<TestMethod>]
  member _.``[PPC T] ANDC original decoding``() =
    decode "7d063878" Endian.Big WordSize.Bit32 ANDC
    decode "7d063878" Endian.Big WordSize.Bit64 ANDC
    decode "7838067d" Endian.Little WordSize.Bit64 ANDC

  [<TestMethod>]
  member _.``[PPC T] ANDC. original decoding``() =
    decode "7d063879" Endian.Big WordSize.Bit32 ANDCdot
    decode "7d063879" Endian.Big WordSize.Bit64 ANDCdot
    decode "7938067d" Endian.Little WordSize.Bit64 ANDCdot

  [<TestMethod>]
  member _.``[PPC T] AND. original decoding``() =
    decode "7d063839" Endian.Big WordSize.Bit32 ANDdot
    decode "7d063839" Endian.Big WordSize.Bit64 ANDdot
    decode "3938067d" Endian.Little WordSize.Bit64 ANDdot

  [<TestMethod>]
  member _.``[PPC T] ANDI. original decoding``() =
    decode "71060055" Endian.Big WordSize.Bit32 ANDIdot
    decode "71060055" Endian.Big WordSize.Bit64 ANDIdot
    decode "55000671" Endian.Little WordSize.Bit64 ANDIdot

  [<TestMethod>]
  member _.``[PPC T] ANDIS. original decoding``() =
    decode "75060055" Endian.Big WordSize.Bit32 ANDISdot
    decode "75060055" Endian.Big WordSize.Bit64 ANDISdot
    decode "55000675" Endian.Little WordSize.Bit64 ANDISdot

  [<TestMethod>]
  member _.``[PPC T] BC original decoding``() =
    decode "42890004" Endian.Big WordSize.Bit32 BC
    decode "42890004" Endian.Big WordSize.Bit64 BC
    decode "04008942" Endian.Little WordSize.Bit64 BC

  [<TestMethod>]
  member _.``[PPC T] BCCTR original decoding``() =
    decode "4e890420" Endian.Big WordSize.Bit32 BCCTR
    decode "4e890420" Endian.Big WordSize.Bit64 BCCTR
    decode "2004894e" Endian.Little WordSize.Bit64 BCCTR

  [<TestMethod>]
  member _.``[PPC T] BCCTRL original decoding``() =
    decode "4e890421" Endian.Big WordSize.Bit32 BCCTRL
    decode "4e890421" Endian.Big WordSize.Bit64 BCCTRL
    decode "2104894e" Endian.Little WordSize.Bit64 BCCTRL

  [<TestMethod>]
  member _.``[PPC T] BCL original decoding``() =
    decode "42890005" Endian.Big WordSize.Bit32 BCL
    decode "42890005" Endian.Big WordSize.Bit64 BCL
    decode "05008942" Endian.Little WordSize.Bit64 BCL

  [<TestMethod>]
  member _.``[PPC T] BCLRL original decoding``() =
    decode "4e890021" Endian.Big WordSize.Bit32 BCLRL
    decode "4e890021" Endian.Big WordSize.Bit64 BCLRL
    decode "2100894e" Endian.Little WordSize.Bit64 BCLRL

  [<TestMethod>]
  member _.``[PPC T] BL original decoding``() =
    decode "48000005" Endian.Big WordSize.Bit32 BL
    decode "48000005" Endian.Big WordSize.Bit64 BL
    decode "05000048" Endian.Little WordSize.Bit64 BL

  [<TestMethod>]
  member _.``[PPC T] BPERMD original decoding``() =
    refuse "7d0639f8"
    decode "7d0639f8" Endian.Big WordSize.Bit64 BPERMD
    decode "f839067d" Endian.Little WordSize.Bit64 BPERMD

  [<TestMethod>]
  member _.``[PPC T] CMP original decoding``() =
    decode "7d063800" Endian.Big WordSize.Bit32 CMPW
    decode "7d063800" Endian.Big WordSize.Bit64 CMPW
    decode "0038067d" Endian.Little WordSize.Bit64 CMPW

  [<TestMethod>]
  member _.``[PPC T] CMPI original decoding``() =
    decode "2d06000c" Endian.Big WordSize.Bit32 CMPWI
    decode "2d06000c" Endian.Big WordSize.Bit64 CMPWI
    decode "0c00062d" Endian.Little WordSize.Bit64 CMPWI

  [<TestMethod>]
  member _.``[PPC T] CMPL original decoding``() =
    decode "7d063840" Endian.Big WordSize.Bit32 CMPLW
    decode "7d063840" Endian.Big WordSize.Bit64 CMPLW
    decode "4038067d" Endian.Little WordSize.Bit64 CMPLW

  [<TestMethod>]
  member _.``[PPC T] CMPLI original decoding``() =
    decode "29060055" Endian.Big WordSize.Bit32 CMPLWI
    decode "29060055" Endian.Big WordSize.Bit64 CMPLWI
    decode "55000629" Endian.Little WordSize.Bit64 CMPLWI

  [<TestMethod>]
  member _.``[PPC T] CNTLZD original decoding``() =
    refuse "7d060074"
    decode "7d060074" Endian.Big WordSize.Bit64 CNTLZD
    decode "7400067d" Endian.Little WordSize.Bit64 CNTLZD

  [<TestMethod>]
  member _.``[PPC T] CNTLZD. original decoding``() =
    refuse "7d060075"
    decode "7d060075" Endian.Big WordSize.Bit64 CNTLZDdot
    decode "7500067d" Endian.Little WordSize.Bit64 CNTLZDdot

  [<TestMethod>]
  member _.``[PPC T] CNTLZW original decoding``() =
    decode "7d060034" Endian.Big WordSize.Bit32 CNTLZW
    decode "7d060034" Endian.Big WordSize.Bit64 CNTLZW
    decode "3400067d" Endian.Little WordSize.Bit64 CNTLZW

  [<TestMethod>]
  member _.``[PPC T] CNTLZW. original decoding``() =
    decode "7d060035" Endian.Big WordSize.Bit32 CNTLZWdot
    decode "7d060035" Endian.Big WordSize.Bit64 CNTLZWdot
    decode "3500067d" Endian.Little WordSize.Bit64 CNTLZWdot

  [<TestMethod>]
  member _.``[PPC T] CRAND original decoding``() =
    decode "4d2a5a02" Endian.Big WordSize.Bit32 CRAND
    decode "4d2a5a02" Endian.Big WordSize.Bit64 CRAND
    decode "025a2a4d" Endian.Little WordSize.Bit64 CRAND

  [<TestMethod>]
  member _.``[PPC T] CRANDC original decoding``() =
    decode "4d2a5902" Endian.Big WordSize.Bit32 CRANDC
    decode "4d2a5902" Endian.Big WordSize.Bit64 CRANDC
    decode "02592a4d" Endian.Little WordSize.Bit64 CRANDC

  [<TestMethod>]
  member _.``[PPC T] CREQV original decoding``() =
    decode "4d2a5a42" Endian.Big WordSize.Bit32 CREQV
    decode "4d2a5a42" Endian.Big WordSize.Bit64 CREQV
    decode "425a2a4d" Endian.Little WordSize.Bit64 CREQV

  [<TestMethod>]
  member _.``[PPC T] CRNAND original decoding``() =
    decode "4d2a59c2" Endian.Big WordSize.Bit32 CRNAND
    decode "4d2a59c2" Endian.Big WordSize.Bit64 CRNAND
    decode "c2592a4d" Endian.Little WordSize.Bit64 CRNAND

  [<TestMethod>]
  member _.``[PPC T] CRNOR original decoding``() =
    decode "4d2a5842" Endian.Big WordSize.Bit32 CRNOR
    decode "4d2a5842" Endian.Big WordSize.Bit64 CRNOR
    decode "42582a4d" Endian.Little WordSize.Bit64 CRNOR

  [<TestMethod>]
  member _.``[PPC T] CROR original decoding``() =
    decode "4d2a5b82" Endian.Big WordSize.Bit32 CROR
    decode "4d2a5b82" Endian.Big WordSize.Bit64 CROR
    decode "825b2a4d" Endian.Little WordSize.Bit64 CROR

  [<TestMethod>]
  member _.``[PPC T] CRORC original decoding``() =
    decode "4d2a5b42" Endian.Big WordSize.Bit32 CRORC
    decode "4d2a5b42" Endian.Big WordSize.Bit64 CRORC
    decode "425b2a4d" Endian.Little WordSize.Bit64 CRORC

  [<TestMethod>]
  member _.``[PPC T] CRXOR original decoding``() =
    decode "4d2a5982" Endian.Big WordSize.Bit32 CRXOR
    decode "4d2a5982" Endian.Big WordSize.Bit64 CRXOR
    decode "82592a4d" Endian.Little WordSize.Bit64 CRXOR

  [<TestMethod>]
  member _.``[PPC T] DCBST original decoding``() =
    decode "7c06386c" Endian.Big WordSize.Bit32 DCBST
    decode "7c06386c" Endian.Big WordSize.Bit64 DCBST
    decode "6c38067c" Endian.Little WordSize.Bit64 DCBST

  [<TestMethod>]
  member _.``[PPC T] DCBZ original decoding``() =
    decode "7c063fec" Endian.Big WordSize.Bit32 DCBZ
    decode "7c063fec" Endian.Big WordSize.Bit64 DCBZ
    decode "ec3f067c" Endian.Little WordSize.Bit64 DCBZ

  [<TestMethod>]
  member _.``[PPC T] DIVD original decoding``() =
    refuse "7ca63bd2"
    decode "7ca63bd2" Endian.Big WordSize.Bit64 DIVD
    decode "d23ba67c" Endian.Little WordSize.Bit64 DIVD

  [<TestMethod>]
  member _.``[PPC T] DIVD. original decoding``() =
    refuse "7ca63bd3"
    decode "7ca63bd3" Endian.Big WordSize.Bit64 DIVDdot
    decode "d33ba67c" Endian.Little WordSize.Bit64 DIVDdot

  [<TestMethod>]
  member _.``[PPC T] DIVDU original decoding``() =
    refuse "7ca63b92"
    decode "7ca63b92" Endian.Big WordSize.Bit64 DIVDU
    decode "923ba67c" Endian.Little WordSize.Bit64 DIVDU

  [<TestMethod>]
  member _.``[PPC T] DIVDU. original decoding``() =
    refuse "7ca63b93"
    decode "7ca63b93" Endian.Big WordSize.Bit64 DIVDUdot
    decode "933ba67c" Endian.Little WordSize.Bit64 DIVDUdot

  [<TestMethod>]
  member _.``[PPC T] DIVW original decoding``() =
    decode "7ca63bd6" Endian.Big WordSize.Bit32 DIVW
    decode "7ca63bd6" Endian.Big WordSize.Bit64 DIVW
    decode "d63ba67c" Endian.Little WordSize.Bit64 DIVW

  [<TestMethod>]
  member _.``[PPC T] DIVW. original decoding``() =
    decode "7ca63bd7" Endian.Big WordSize.Bit32 DIVWdot
    decode "7ca63bd7" Endian.Big WordSize.Bit64 DIVWdot
    decode "d73ba67c" Endian.Little WordSize.Bit64 DIVWdot

  [<TestMethod>]
  member _.``[PPC T] DIVWO original decoding``() =
    decode "7ca63fd6" Endian.Big WordSize.Bit32 DIVWO
    decode "7ca63fd6" Endian.Big WordSize.Bit64 DIVWO
    decode "d63fa67c" Endian.Little WordSize.Bit64 DIVWO

  [<TestMethod>]
  member _.``[PPC T] DIVWO. original decoding``() =
    decode "7ca63fd7" Endian.Big WordSize.Bit32 DIVWOdot
    decode "7ca63fd7" Endian.Big WordSize.Bit64 DIVWOdot
    decode "d73fa67c" Endian.Little WordSize.Bit64 DIVWOdot

  [<TestMethod>]
  member _.``[PPC T] DIVWU original decoding``() =
    decode "7ca63b96" Endian.Big WordSize.Bit32 DIVWU
    decode "7ca63b96" Endian.Big WordSize.Bit64 DIVWU
    decode "963ba67c" Endian.Little WordSize.Bit64 DIVWU

  [<TestMethod>]
  member _.``[PPC T] DIVWU. original decoding``() =
    decode "7ca63b97" Endian.Big WordSize.Bit32 DIVWUdot
    decode "7ca63b97" Endian.Big WordSize.Bit64 DIVWUdot
    decode "973ba67c" Endian.Little WordSize.Bit64 DIVWUdot

  [<TestMethod>]
  member _.``[PPC T] DIVWUO original decoding``() =
    decode "7ca63f96" Endian.Big WordSize.Bit32 DIVWUO
    decode "7ca63f96" Endian.Big WordSize.Bit64 DIVWUO
    decode "963fa67c" Endian.Little WordSize.Bit64 DIVWUO

  [<TestMethod>]
  member _.``[PPC T] DIVWUO. original decoding``() =
    decode "7ca63f97" Endian.Big WordSize.Bit32 DIVWUOdot
    decode "7ca63f97" Endian.Big WordSize.Bit64 DIVWUOdot
    decode "973fa67c" Endian.Little WordSize.Bit64 DIVWUOdot

  [<TestMethod>]
  member _.``[PPC T] EIEIO original decoding``() =
    decode "7c0006ac" Endian.Big WordSize.Bit32 EIEIO
    decode "7c0006ac" Endian.Big WordSize.Bit64 EIEIO
    decode "ac06007c" Endian.Little WordSize.Bit64 EIEIO

  [<TestMethod>]
  member _.``[PPC T] EQV original decoding``() =
    decode "7d063a38" Endian.Big WordSize.Bit32 EQV
    decode "7d063a38" Endian.Big WordSize.Bit64 EQV
    decode "383a067d" Endian.Little WordSize.Bit64 EQV

  [<TestMethod>]
  member _.``[PPC T] EQV. original decoding``() =
    decode "7d063a39" Endian.Big WordSize.Bit32 EQVdot
    decode "7d063a39" Endian.Big WordSize.Bit64 EQVdot
    decode "393a067d" Endian.Little WordSize.Bit64 EQVdot

  [<TestMethod>]
  member _.``[PPC T] EXTSB original decoding``() =
    decode "7d060774" Endian.Big WordSize.Bit32 EXTSB
    decode "7d060774" Endian.Big WordSize.Bit64 EXTSB
    decode "7407067d" Endian.Little WordSize.Bit64 EXTSB

  [<TestMethod>]
  member _.``[PPC T] EXTSB. original decoding``() =
    decode "7d060775" Endian.Big WordSize.Bit32 EXTSBdot
    decode "7d060775" Endian.Big WordSize.Bit64 EXTSBdot
    decode "7507067d" Endian.Little WordSize.Bit64 EXTSBdot

  [<TestMethod>]
  member _.``[PPC T] EXTSH original decoding``() =
    decode "7d060734" Endian.Big WordSize.Bit32 EXTSH
    decode "7d060734" Endian.Big WordSize.Bit64 EXTSH
    decode "3407067d" Endian.Little WordSize.Bit64 EXTSH

  [<TestMethod>]
  member _.``[PPC T] EXTSH. original decoding``() =
    decode "7d060735" Endian.Big WordSize.Bit32 EXTSHdot
    decode "7d060735" Endian.Big WordSize.Bit64 EXTSHdot
    decode "3507067d" Endian.Little WordSize.Bit64 EXTSHdot

  [<TestMethod>]
  member _.``[PPC T] EXTSW. original decoding``() =
    refuse "7d0607b5"
    decode "7d0607b5" Endian.Big WordSize.Bit64 EXTSWdot
    decode "b507067d" Endian.Little WordSize.Bit64 EXTSWdot

  [<TestMethod>]
  member _.``[PPC T] FABS original decoding``() =
    decode "fc201a10" Endian.Big WordSize.Bit32 FABS
    decode "fc201a10" Endian.Big WordSize.Bit64 FABS
    decode "101a20fc" Endian.Little WordSize.Bit64 FABS

  [<TestMethod>]
  member _.``[PPC T] FABS. original decoding``() =
    decode "fc201a11" Endian.Big WordSize.Bit32 FABSdot
    decode "fc201a11" Endian.Big WordSize.Bit64 FABSdot
    decode "111a20fc" Endian.Little WordSize.Bit64 FABSdot

  [<TestMethod>]
  member _.``[PPC T] FADD original decoding``() =
    decode "fc22182a" Endian.Big WordSize.Bit32 FADD
    decode "fc22182a" Endian.Big WordSize.Bit64 FADD
    decode "2a1822fc" Endian.Little WordSize.Bit64 FADD

  [<TestMethod>]
  member _.``[PPC T] FADD. original decoding``() =
    decode "fc22182b" Endian.Big WordSize.Bit32 FADDdot
    decode "fc22182b" Endian.Big WordSize.Bit64 FADDdot
    decode "2b1822fc" Endian.Little WordSize.Bit64 FADDdot

  [<TestMethod>]
  member _.``[PPC T] FADDS original decoding``() =
    decode "ec22182a" Endian.Big WordSize.Bit32 FADDS
    decode "ec22182a" Endian.Big WordSize.Bit64 FADDS
    decode "2a1822ec" Endian.Little WordSize.Bit64 FADDS

  [<TestMethod>]
  member _.``[PPC T] FADDS. original decoding``() =
    decode "ec22182b" Endian.Big WordSize.Bit32 FADDSdot
    decode "ec22182b" Endian.Big WordSize.Bit64 FADDSdot
    decode "2b1822ec" Endian.Little WordSize.Bit64 FADDSdot

  [<TestMethod>]
  member _.``[PPC T] FCFID original decoding``() =
    decode "fc201e9c" Endian.Big WordSize.Bit32 FCFID
    decode "fc201e9c" Endian.Big WordSize.Bit64 FCFID
    decode "9c1e20fc" Endian.Little WordSize.Bit64 FCFID

  [<TestMethod>]
  member _.``[PPC T] FCFID. original decoding``() =
    decode "fc201e9d" Endian.Big WordSize.Bit32 FCFIDdot
    decode "fc201e9d" Endian.Big WordSize.Bit64 FCFIDdot
    decode "9d1e20fc" Endian.Little WordSize.Bit64 FCFIDdot

  [<TestMethod>]
  member _.``[PPC T] FCFIDS original decoding``() =
    decode "ec201e9c" Endian.Big WordSize.Bit32 FCFIDS
    decode "ec201e9c" Endian.Big WordSize.Bit64 FCFIDS
    decode "9c1e20ec" Endian.Little WordSize.Bit64 FCFIDS

  [<TestMethod>]
  member _.``[PPC T] FCFIDS. original decoding``() =
    decode "ec201e9d" Endian.Big WordSize.Bit32 FCFIDSdot
    decode "ec201e9d" Endian.Big WordSize.Bit64 FCFIDSdot
    decode "9d1e20ec" Endian.Little WordSize.Bit64 FCFIDSdot

  [<TestMethod>]
  member _.``[PPC T] FCFIDU original decoding``() =
    decode "fc201f9c" Endian.Big WordSize.Bit32 FCFIDU
    decode "fc201f9c" Endian.Big WordSize.Bit64 FCFIDU
    decode "9c1f20fc" Endian.Little WordSize.Bit64 FCFIDU

  [<TestMethod>]
  member _.``[PPC T] FCFIDU. original decoding``() =
    decode "fc201f9d" Endian.Big WordSize.Bit32 FCFIDUdot
    decode "fc201f9d" Endian.Big WordSize.Bit64 FCFIDUdot
    decode "9d1f20fc" Endian.Little WordSize.Bit64 FCFIDUdot

  [<TestMethod>]
  member _.``[PPC T] FCFIDUS original decoding``() =
    decode "ec201f9c" Endian.Big WordSize.Bit32 FCFIDUS
    decode "ec201f9c" Endian.Big WordSize.Bit64 FCFIDUS
    decode "9c1f20ec" Endian.Little WordSize.Bit64 FCFIDUS

  [<TestMethod>]
  member _.``[PPC T] FCFIDUS. original decoding``() =
    decode "ec201f9d" Endian.Big WordSize.Bit32 FCFIDUSdot
    decode "ec201f9d" Endian.Big WordSize.Bit64 FCFIDUSdot
    decode "9d1f20ec" Endian.Little WordSize.Bit64 FCFIDUSdot

  [<TestMethod>]
  member _.``[PPC T] FCMPO original decoding``() =
    decode "fd021840" Endian.Big WordSize.Bit32 FCMPO
    decode "fd021840" Endian.Big WordSize.Bit64 FCMPO
    decode "401802fd" Endian.Little WordSize.Bit64 FCMPO

  [<TestMethod>]
  member _.``[PPC T] FCMPU original decoding``() =
    decode "fd021800" Endian.Big WordSize.Bit32 FCMPU
    decode "fd021800" Endian.Big WordSize.Bit64 FCMPU
    decode "001802fd" Endian.Little WordSize.Bit64 FCMPU

  [<TestMethod>]
  member _.``[PPC T] FCPSGN original decoding``() =
    decode "fc221810" Endian.Big WordSize.Bit32 FCPSGN
    decode "fc221810" Endian.Big WordSize.Bit64 FCPSGN
    decode "101822fc" Endian.Little WordSize.Bit64 FCPSGN

  [<TestMethod>]
  member _.``[PPC T] FCTID original decoding``() =
    decode "fc201e5c" Endian.Big WordSize.Bit32 FCTID
    decode "fc201e5c" Endian.Big WordSize.Bit64 FCTID
    decode "5c1e20fc" Endian.Little WordSize.Bit64 FCTID

  [<TestMethod>]
  member _.``[PPC T] FCTID. original decoding``() =
    decode "fc201e5d" Endian.Big WordSize.Bit32 FCTIDdot
    decode "fc201e5d" Endian.Big WordSize.Bit64 FCTIDdot
    decode "5d1e20fc" Endian.Little WordSize.Bit64 FCTIDdot

  [<TestMethod>]
  member _.``[PPC T] FCTIDU original decoding``() =
    decode "fc201f5c" Endian.Big WordSize.Bit32 FCTIDU
    decode "fc201f5c" Endian.Big WordSize.Bit64 FCTIDU
    decode "5c1f20fc" Endian.Little WordSize.Bit64 FCTIDU

  [<TestMethod>]
  member _.``[PPC T] FCTIDU. original decoding``() =
    decode "fc201f5d" Endian.Big WordSize.Bit32 FCTIDUdot
    decode "fc201f5d" Endian.Big WordSize.Bit64 FCTIDUdot
    decode "5d1f20fc" Endian.Little WordSize.Bit64 FCTIDUdot

  [<TestMethod>]
  member _.``[PPC T] FCTIDUZ original decoding``() =
    decode "fc201f5e" Endian.Big WordSize.Bit32 FCTIDUZ
    decode "fc201f5e" Endian.Big WordSize.Bit64 FCTIDUZ
    decode "5e1f20fc" Endian.Little WordSize.Bit64 FCTIDUZ

  [<TestMethod>]
  member _.``[PPC T] FCTIDUZ. original decoding``() =
    decode "fc201f5f" Endian.Big WordSize.Bit32 FCTIDUZdot
    decode "fc201f5f" Endian.Big WordSize.Bit64 FCTIDUZdot
    decode "5f1f20fc" Endian.Little WordSize.Bit64 FCTIDUZdot

  [<TestMethod>]
  member _.``[PPC T] FCTIDZ original decoding``() =
    decode "fc201e5e" Endian.Big WordSize.Bit32 FCTIDZ
    decode "fc201e5e" Endian.Big WordSize.Bit64 FCTIDZ
    decode "5e1e20fc" Endian.Little WordSize.Bit64 FCTIDZ

  [<TestMethod>]
  member _.``[PPC T] FCTIDZ. original decoding``() =
    decode "fc201e5f" Endian.Big WordSize.Bit32 FCTIDZdot
    decode "fc201e5f" Endian.Big WordSize.Bit64 FCTIDZdot
    decode "5f1e20fc" Endian.Little WordSize.Bit64 FCTIDZdot

  [<TestMethod>]
  member _.``[PPC T] FCTIW original decoding``() =
    decode "fc20181c" Endian.Big WordSize.Bit32 FCTIW
    decode "fc20181c" Endian.Big WordSize.Bit64 FCTIW
    decode "1c1820fc" Endian.Little WordSize.Bit64 FCTIW

  [<TestMethod>]
  member _.``[PPC T] FCTIW. original decoding``() =
    decode "fc20181d" Endian.Big WordSize.Bit32 FCTIWdot
    decode "fc20181d" Endian.Big WordSize.Bit64 FCTIWdot
    decode "1d1820fc" Endian.Little WordSize.Bit64 FCTIWdot

  [<TestMethod>]
  member _.``[PPC T] FCTIWU original decoding``() =
    decode "fc20191c" Endian.Big WordSize.Bit32 FCTIWU
    decode "fc20191c" Endian.Big WordSize.Bit64 FCTIWU
    decode "1c1920fc" Endian.Little WordSize.Bit64 FCTIWU

  [<TestMethod>]
  member _.``[PPC T] FCTIWU. original decoding``() =
    decode "fc20191d" Endian.Big WordSize.Bit32 FCTIWUdot
    decode "fc20191d" Endian.Big WordSize.Bit64 FCTIWUdot
    decode "1d1920fc" Endian.Little WordSize.Bit64 FCTIWUdot

  [<TestMethod>]
  member _.``[PPC T] FCTIWUZ original decoding``() =
    decode "fc20191e" Endian.Big WordSize.Bit32 FCTIWUZ
    decode "fc20191e" Endian.Big WordSize.Bit64 FCTIWUZ
    decode "1e1920fc" Endian.Little WordSize.Bit64 FCTIWUZ

  [<TestMethod>]
  member _.``[PPC T] FCTIWUZ. original decoding``() =
    decode "fc20191f" Endian.Big WordSize.Bit32 FCTIWUZdot
    decode "fc20191f" Endian.Big WordSize.Bit64 FCTIWUZdot
    decode "1f1920fc" Endian.Little WordSize.Bit64 FCTIWUZdot

  [<TestMethod>]
  member _.``[PPC T] FCTIWZ original decoding``() =
    decode "fc20181e" Endian.Big WordSize.Bit32 FCTIWZ
    decode "fc20181e" Endian.Big WordSize.Bit64 FCTIWZ
    decode "1e1820fc" Endian.Little WordSize.Bit64 FCTIWZ

  [<TestMethod>]
  member _.``[PPC T] FCTIWZ. original decoding``() =
    decode "fc20181f" Endian.Big WordSize.Bit32 FCTIWZdot
    decode "fc20181f" Endian.Big WordSize.Bit64 FCTIWZdot
    decode "1f1820fc" Endian.Little WordSize.Bit64 FCTIWZdot

  [<TestMethod>]
  member _.``[PPC T] FDIV original decoding``() =
    decode "fc221824" Endian.Big WordSize.Bit32 FDIV
    decode "fc221824" Endian.Big WordSize.Bit64 FDIV
    decode "241822fc" Endian.Little WordSize.Bit64 FDIV

  [<TestMethod>]
  member _.``[PPC T] FDIV. original decoding``() =
    decode "fc221825" Endian.Big WordSize.Bit32 FDIVdot
    decode "fc221825" Endian.Big WordSize.Bit64 FDIVdot
    decode "251822fc" Endian.Little WordSize.Bit64 FDIVdot

  [<TestMethod>]
  member _.``[PPC T] FDIVS original decoding``() =
    decode "ec221824" Endian.Big WordSize.Bit32 FDIVS
    decode "ec221824" Endian.Big WordSize.Bit64 FDIVS
    decode "241822ec" Endian.Little WordSize.Bit64 FDIVS

  [<TestMethod>]
  member _.``[PPC T] FDIVS. original decoding``() =
    decode "ec221825" Endian.Big WordSize.Bit32 FDIVSdot
    decode "ec221825" Endian.Big WordSize.Bit64 FDIVSdot
    decode "251822ec" Endian.Little WordSize.Bit64 FDIVSdot

  [<TestMethod>]
  member _.``[PPC T] FMADD original decoding``() =
    decode "fc22193a" Endian.Big WordSize.Bit32 FMADD
    decode "fc22193a" Endian.Big WordSize.Bit64 FMADD
    decode "3a1922fc" Endian.Little WordSize.Bit64 FMADD

  [<TestMethod>]
  member _.``[PPC T] FMADD. original decoding``() =
    decode "fc22193b" Endian.Big WordSize.Bit32 FMADDdot
    decode "fc22193b" Endian.Big WordSize.Bit64 FMADDdot
    decode "3b1922fc" Endian.Little WordSize.Bit64 FMADDdot

  [<TestMethod>]
  member _.``[PPC T] FMADDS original decoding``() =
    decode "ec22193a" Endian.Big WordSize.Bit32 FMADDS
    decode "ec22193a" Endian.Big WordSize.Bit64 FMADDS
    decode "3a1922ec" Endian.Little WordSize.Bit64 FMADDS

  [<TestMethod>]
  member _.``[PPC T] FMADDS. original decoding``() =
    decode "ec22193b" Endian.Big WordSize.Bit32 FMADDSdot
    decode "ec22193b" Endian.Big WordSize.Bit64 FMADDSdot
    decode "3b1922ec" Endian.Little WordSize.Bit64 FMADDSdot

  [<TestMethod>]
  member _.``[PPC T] FMR original decoding``() =
    decode "fc201890" Endian.Big WordSize.Bit32 FMR
    decode "fc201890" Endian.Big WordSize.Bit64 FMR
    decode "901820fc" Endian.Little WordSize.Bit64 FMR

  [<TestMethod>]
  member _.``[PPC T] FMR. original decoding``() =
    decode "fc201891" Endian.Big WordSize.Bit32 FMRdot
    decode "fc201891" Endian.Big WordSize.Bit64 FMRdot
    decode "911820fc" Endian.Little WordSize.Bit64 FMRdot

  [<TestMethod>]
  member _.``[PPC T] FMSUB original decoding``() =
    decode "fc221938" Endian.Big WordSize.Bit32 FMSUB
    decode "fc221938" Endian.Big WordSize.Bit64 FMSUB
    decode "381922fc" Endian.Little WordSize.Bit64 FMSUB

  [<TestMethod>]
  member _.``[PPC T] FMSUB. original decoding``() =
    decode "fc221939" Endian.Big WordSize.Bit32 FMSUBdot
    decode "fc221939" Endian.Big WordSize.Bit64 FMSUBdot
    decode "391922fc" Endian.Little WordSize.Bit64 FMSUBdot

  [<TestMethod>]
  member _.``[PPC T] FMSUBS original decoding``() =
    decode "ec221938" Endian.Big WordSize.Bit32 FMSUBS
    decode "ec221938" Endian.Big WordSize.Bit64 FMSUBS
    decode "381922ec" Endian.Little WordSize.Bit64 FMSUBS

  [<TestMethod>]
  member _.``[PPC T] FMSUBS. original decoding``() =
    decode "ec221939" Endian.Big WordSize.Bit32 FMSUBSdot
    decode "ec221939" Endian.Big WordSize.Bit64 FMSUBSdot
    decode "391922ec" Endian.Little WordSize.Bit64 FMSUBSdot

  [<TestMethod>]
  member _.``[PPC T] FMUL original decoding``() =
    decode "fc220132" Endian.Big WordSize.Bit32 FMUL
    decode "fc220132" Endian.Big WordSize.Bit64 FMUL
    decode "320122fc" Endian.Little WordSize.Bit64 FMUL

  [<TestMethod>]
  member _.``[PPC T] FMUL. original decoding``() =
    decode "fc220133" Endian.Big WordSize.Bit32 FMULdot
    decode "fc220133" Endian.Big WordSize.Bit64 FMULdot
    decode "330122fc" Endian.Little WordSize.Bit64 FMULdot

  [<TestMethod>]
  member _.``[PPC T] FMULS original decoding``() =
    decode "ec220132" Endian.Big WordSize.Bit32 FMULS
    decode "ec220132" Endian.Big WordSize.Bit64 FMULS
    decode "320122ec" Endian.Little WordSize.Bit64 FMULS

  [<TestMethod>]
  member _.``[PPC T] FMULS. original decoding``() =
    decode "ec220133" Endian.Big WordSize.Bit32 FMULSdot
    decode "ec220133" Endian.Big WordSize.Bit64 FMULSdot
    decode "330122ec" Endian.Little WordSize.Bit64 FMULSdot

  [<TestMethod>]
  member _.``[PPC T] FNABS original decoding``() =
    decode "fc201910" Endian.Big WordSize.Bit32 FNABS
    decode "fc201910" Endian.Big WordSize.Bit64 FNABS
    decode "101920fc" Endian.Little WordSize.Bit64 FNABS

  [<TestMethod>]
  member _.``[PPC T] FNABS. original decoding``() =
    decode "fc201911" Endian.Big WordSize.Bit32 FNABSdot
    decode "fc201911" Endian.Big WordSize.Bit64 FNABSdot
    decode "111920fc" Endian.Little WordSize.Bit64 FNABSdot

  [<TestMethod>]
  member _.``[PPC T] FNEG original decoding``() =
    decode "fc201850" Endian.Big WordSize.Bit32 FNEG
    decode "fc201850" Endian.Big WordSize.Bit64 FNEG
    decode "501820fc" Endian.Little WordSize.Bit64 FNEG

  [<TestMethod>]
  member _.``[PPC T] FNEG. original decoding``() =
    decode "fc201851" Endian.Big WordSize.Bit32 FNEGdot
    decode "fc201851" Endian.Big WordSize.Bit64 FNEGdot
    decode "511820fc" Endian.Little WordSize.Bit64 FNEGdot

  [<TestMethod>]
  member _.``[PPC T] FNMADD original decoding``() =
    decode "fc22193e" Endian.Big WordSize.Bit32 FNMADD
    decode "fc22193e" Endian.Big WordSize.Bit64 FNMADD
    decode "3e1922fc" Endian.Little WordSize.Bit64 FNMADD

  [<TestMethod>]
  member _.``[PPC T] FNMADD. original decoding``() =
    decode "fc22193f" Endian.Big WordSize.Bit32 FNMADDdot
    decode "fc22193f" Endian.Big WordSize.Bit64 FNMADDdot
    decode "3f1922fc" Endian.Little WordSize.Bit64 FNMADDdot

  [<TestMethod>]
  member _.``[PPC T] FNMADDS original decoding``() =
    decode "ec22193e" Endian.Big WordSize.Bit32 FNMADDS
    decode "ec22193e" Endian.Big WordSize.Bit64 FNMADDS
    decode "3e1922ec" Endian.Little WordSize.Bit64 FNMADDS

  [<TestMethod>]
  member _.``[PPC T] FNMADDS. original decoding``() =
    decode "ec22193f" Endian.Big WordSize.Bit32 FNMADDSdot
    decode "ec22193f" Endian.Big WordSize.Bit64 FNMADDSdot
    decode "3f1922ec" Endian.Little WordSize.Bit64 FNMADDSdot

  [<TestMethod>]
  member _.``[PPC T] FNMSUB original decoding``() =
    decode "fc22193c" Endian.Big WordSize.Bit32 FNMSUB
    decode "fc22193c" Endian.Big WordSize.Bit64 FNMSUB
    decode "3c1922fc" Endian.Little WordSize.Bit64 FNMSUB

  [<TestMethod>]
  member _.``[PPC T] FNMSUB. original decoding``() =
    decode "fc22193d" Endian.Big WordSize.Bit32 FNMSUBdot
    decode "fc22193d" Endian.Big WordSize.Bit64 FNMSUBdot
    decode "3d1922fc" Endian.Little WordSize.Bit64 FNMSUBdot

  [<TestMethod>]
  member _.``[PPC T] FNMSUBS original decoding``() =
    decode "ec22193c" Endian.Big WordSize.Bit32 FNMSUBS
    decode "ec22193c" Endian.Big WordSize.Bit64 FNMSUBS
    decode "3c1922ec" Endian.Little WordSize.Bit64 FNMSUBS

  [<TestMethod>]
  member _.``[PPC T] FNMSUBS. original decoding``() =
    decode "ec22193d" Endian.Big WordSize.Bit32 FNMSUBSdot
    decode "ec22193d" Endian.Big WordSize.Bit64 FNMSUBSdot
    decode "3d1922ec" Endian.Little WordSize.Bit64 FNMSUBSdot

  [<TestMethod>]
  member _.``[PPC T] FRES original decoding``() =
    decode "ec201830" Endian.Big WordSize.Bit32 FRES
    decode "ec201830" Endian.Big WordSize.Bit64 FRES
    decode "301820ec" Endian.Little WordSize.Bit64 FRES

  [<TestMethod>]
  member _.``[PPC T] FRES. original decoding``() =
    decode "ec201831" Endian.Big WordSize.Bit32 FRESdot
    decode "ec201831" Endian.Big WordSize.Bit64 FRESdot
    decode "311820ec" Endian.Little WordSize.Bit64 FRESdot

  [<TestMethod>]
  member _.``[PPC T] FRIM original decoding``() =
    decode "fc201bd0" Endian.Big WordSize.Bit32 FRIM
    decode "fc201bd0" Endian.Big WordSize.Bit64 FRIM
    decode "d01b20fc" Endian.Little WordSize.Bit64 FRIM

  [<TestMethod>]
  member _.``[PPC T] FRIM. original decoding``() =
    decode "fc201bd1" Endian.Big WordSize.Bit32 FRIMdot
    decode "fc201bd1" Endian.Big WordSize.Bit64 FRIMdot
    decode "d11b20fc" Endian.Little WordSize.Bit64 FRIMdot

  [<TestMethod>]
  member _.``[PPC T] FRIN original decoding``() =
    decode "fc201b10" Endian.Big WordSize.Bit32 FRIN
    decode "fc201b10" Endian.Big WordSize.Bit64 FRIN
    decode "101b20fc" Endian.Little WordSize.Bit64 FRIN

  [<TestMethod>]
  member _.``[PPC T] FRIN. original decoding``() =
    decode "fc201b11" Endian.Big WordSize.Bit32 FRINdot
    decode "fc201b11" Endian.Big WordSize.Bit64 FRINdot
    decode "111b20fc" Endian.Little WordSize.Bit64 FRINdot

  [<TestMethod>]
  member _.``[PPC T] FRIP original decoding``() =
    decode "fc201b90" Endian.Big WordSize.Bit32 FRIP
    decode "fc201b90" Endian.Big WordSize.Bit64 FRIP
    decode "901b20fc" Endian.Little WordSize.Bit64 FRIP

  [<TestMethod>]
  member _.``[PPC T] FRIP. original decoding``() =
    decode "fc201b91" Endian.Big WordSize.Bit32 FRIPdot
    decode "fc201b91" Endian.Big WordSize.Bit64 FRIPdot
    decode "911b20fc" Endian.Little WordSize.Bit64 FRIPdot

  [<TestMethod>]
  member _.``[PPC T] FRIZ original decoding``() =
    decode "fc201b50" Endian.Big WordSize.Bit32 FRIZ
    decode "fc201b50" Endian.Big WordSize.Bit64 FRIZ
    decode "501b20fc" Endian.Little WordSize.Bit64 FRIZ

  [<TestMethod>]
  member _.``[PPC T] FRIZ. original decoding``() =
    decode "fc201b51" Endian.Big WordSize.Bit32 FRIZdot
    decode "fc201b51" Endian.Big WordSize.Bit64 FRIZdot
    decode "511b20fc" Endian.Little WordSize.Bit64 FRIZdot

  [<TestMethod>]
  member _.``[PPC T] FRSP original decoding``() =
    decode "fc201818" Endian.Big WordSize.Bit32 FRSP
    decode "fc201818" Endian.Big WordSize.Bit64 FRSP
    decode "181820fc" Endian.Little WordSize.Bit64 FRSP

  [<TestMethod>]
  member _.``[PPC T] FRSP. original decoding``() =
    decode "fc201819" Endian.Big WordSize.Bit32 FRSPdot
    decode "fc201819" Endian.Big WordSize.Bit64 FRSPdot
    decode "191820fc" Endian.Little WordSize.Bit64 FRSPdot

  [<TestMethod>]
  member _.``[PPC T] FRSQRTE original decoding``() =
    decode "fc201834" Endian.Big WordSize.Bit32 FRSQRTE
    decode "fc201834" Endian.Big WordSize.Bit64 FRSQRTE
    decode "341820fc" Endian.Little WordSize.Bit64 FRSQRTE

  [<TestMethod>]
  member _.``[PPC T] FSEL original decoding``() =
    decode "fc22192e" Endian.Big WordSize.Bit32 FSEL
    decode "fc22192e" Endian.Big WordSize.Bit64 FSEL
    decode "2e1922fc" Endian.Little WordSize.Bit64 FSEL

  [<TestMethod>]
  member _.``[PPC T] FSEL. original decoding``() =
    decode "fc22192f" Endian.Big WordSize.Bit32 FSELdot
    decode "fc22192f" Endian.Big WordSize.Bit64 FSELdot
    decode "2f1922fc" Endian.Little WordSize.Bit64 FSELdot

  [<TestMethod>]
  member _.``[PPC T] FSQRT original decoding``() =
    decode "fc20182c" Endian.Big WordSize.Bit32 FSQRT
    decode "fc20182c" Endian.Big WordSize.Bit64 FSQRT
    decode "2c1820fc" Endian.Little WordSize.Bit64 FSQRT

  [<TestMethod>]
  member _.``[PPC T] FSQRT. original decoding``() =
    decode "fc20182d" Endian.Big WordSize.Bit32 FSQRTdot
    decode "fc20182d" Endian.Big WordSize.Bit64 FSQRTdot
    decode "2d1820fc" Endian.Little WordSize.Bit64 FSQRTdot

  [<TestMethod>]
  member _.``[PPC T] FSQRTS original decoding``() =
    decode "ec20182c" Endian.Big WordSize.Bit32 FSQRTS
    decode "ec20182c" Endian.Big WordSize.Bit64 FSQRTS
    decode "2c1820ec" Endian.Little WordSize.Bit64 FSQRTS

  [<TestMethod>]
  member _.``[PPC T] FSQRTS. original decoding``() =
    decode "ec20182d" Endian.Big WordSize.Bit32 FSQRTSdot
    decode "ec20182d" Endian.Big WordSize.Bit64 FSQRTSdot
    decode "2d1820ec" Endian.Little WordSize.Bit64 FSQRTSdot

  [<TestMethod>]
  member _.``[PPC T] FSUB original decoding``() =
    decode "fc221828" Endian.Big WordSize.Bit32 FSUB
    decode "fc221828" Endian.Big WordSize.Bit64 FSUB
    decode "281822fc" Endian.Little WordSize.Bit64 FSUB

  [<TestMethod>]
  member _.``[PPC T] FSUB. original decoding``() =
    decode "fc221829" Endian.Big WordSize.Bit32 FSUBdot
    decode "fc221829" Endian.Big WordSize.Bit64 FSUBdot
    decode "291822fc" Endian.Little WordSize.Bit64 FSUBdot

  [<TestMethod>]
  member _.``[PPC T] FSUBS original decoding``() =
    decode "ec221828" Endian.Big WordSize.Bit32 FSUBS
    decode "ec221828" Endian.Big WordSize.Bit64 FSUBS
    decode "281822ec" Endian.Little WordSize.Bit64 FSUBS

  [<TestMethod>]
  member _.``[PPC T] FSUBS. original decoding``() =
    decode "ec221829" Endian.Big WordSize.Bit32 FSUBSdot
    decode "ec221829" Endian.Big WordSize.Bit64 FSUBSdot
    decode "291822ec" Endian.Little WordSize.Bit64 FSUBSdot

  [<TestMethod>]
  member _.``[PPC T] ICBI original decoding``() =
    decode "7c063fac" Endian.Big WordSize.Bit32 ICBI
    decode "7c063fac" Endian.Big WordSize.Bit64 ICBI
    decode "ac3f067c" Endian.Little WordSize.Bit64 ICBI

  [<TestMethod>]
  member _.``[PPC T] ISEL original decoding``() =
    decode "7ca63a5e" Endian.Big WordSize.Bit32 ISEL
    decode "7ca63a5e" Endian.Big WordSize.Bit64 ISEL
    decode "5e3aa67c" Endian.Little WordSize.Bit64 ISEL

  [<TestMethod>]
  member _.``[PPC T] ISYNC original decoding``() =
    decode "4c00012c" Endian.Big WordSize.Bit32 ISYNC
    decode "4c00012c" Endian.Big WordSize.Bit64 ISYNC
    decode "2c01004c" Endian.Little WordSize.Bit64 ISYNC

  [<TestMethod>]
  member _.``[PPC T] LBZ original decoding``() =
    decode "88a60008" Endian.Big WordSize.Bit32 LBZ
    decode "88a60008" Endian.Big WordSize.Bit64 LBZ
    decode "0800a688" Endian.Little WordSize.Bit64 LBZ

  [<TestMethod>]
  member _.``[PPC T] LBZU original decoding``() =
    decode "8ca60008" Endian.Big WordSize.Bit32 LBZU
    decode "8ca60008" Endian.Big WordSize.Bit64 LBZU
    decode "0800a68c" Endian.Little WordSize.Bit64 LBZU

  [<TestMethod>]
  member _.``[PPC T] LBZUX original decoding``() =
    decode "7ca638ee" Endian.Big WordSize.Bit32 LBZUX
    decode "7ca638ee" Endian.Big WordSize.Bit64 LBZUX
    decode "ee38a67c" Endian.Little WordSize.Bit64 LBZUX

  [<TestMethod>]
  member _.``[PPC T] LBZX original decoding``() =
    decode "7ca638ae" Endian.Big WordSize.Bit32 LBZX
    decode "7ca638ae" Endian.Big WordSize.Bit64 LBZX
    decode "ae38a67c" Endian.Little WordSize.Bit64 LBZX

  [<TestMethod>]
  member _.``[PPC T] LDARX original decoding``() =
    refuse "7ca638a8"
    decode "7ca638a8" Endian.Big WordSize.Bit64 LDARX
    decode "a838a67c" Endian.Little WordSize.Bit64 LDARX

  [<TestMethod>]
  member _.``[PPC T] LDBRX original decoding``() =
    refuse "7ca63c28"
    decode "7ca63c28" Endian.Big WordSize.Bit64 LDBRX
    decode "283ca67c" Endian.Little WordSize.Bit64 LDBRX

  [<TestMethod>]
  member _.``[PPC T] LDU original decoding``() =
    refuse "e8a60009"
    decode "e8a60009" Endian.Big WordSize.Bit64 LDU
    decode "0900a6e8" Endian.Little WordSize.Bit64 LDU

  [<TestMethod>]
  member _.``[PPC T] LDUX original decoding``() =
    refuse "7ca6386a"
    decode "7ca6386a" Endian.Big WordSize.Bit64 LDUX
    decode "6a38a67c" Endian.Little WordSize.Bit64 LDUX

  [<TestMethod>]
  member _.``[PPC T] LDX original decoding``() =
    refuse "7ca6382a"
    decode "7ca6382a" Endian.Big WordSize.Bit64 LDX
    decode "2a38a67c" Endian.Little WordSize.Bit64 LDX

  [<TestMethod>]
  member _.``[PPC T] LFD original decoding``() =
    decode "c8260008" Endian.Big WordSize.Bit32 LFD
    decode "c8260008" Endian.Big WordSize.Bit64 LFD
    decode "080026c8" Endian.Little WordSize.Bit64 LFD

  [<TestMethod>]
  member _.``[PPC T] LFDU original decoding``() =
    decode "cc260008" Endian.Big WordSize.Bit32 LFDU
    decode "cc260008" Endian.Big WordSize.Bit64 LFDU
    decode "080026cc" Endian.Little WordSize.Bit64 LFDU

  [<TestMethod>]
  member _.``[PPC T] LFDUX original decoding``() =
    decode "7c263cee" Endian.Big WordSize.Bit32 LFDUX
    decode "7c263cee" Endian.Big WordSize.Bit64 LFDUX
    decode "ee3c267c" Endian.Little WordSize.Bit64 LFDUX

  [<TestMethod>]
  member _.``[PPC T] LFDX original decoding``() =
    decode "7c263cae" Endian.Big WordSize.Bit32 LFDX
    decode "7c263cae" Endian.Big WordSize.Bit64 LFDX
    decode "ae3c267c" Endian.Little WordSize.Bit64 LFDX

  [<TestMethod>]
  member _.``[PPC T] LFIWAX original decoding``() =
    decode "7c263eae" Endian.Big WordSize.Bit32 LFIWAX
    decode "7c263eae" Endian.Big WordSize.Bit64 LFIWAX
    decode "ae3e267c" Endian.Little WordSize.Bit64 LFIWAX

  [<TestMethod>]
  member _.``[PPC T] LFIWZX original decoding``() =
    decode "7c263eee" Endian.Big WordSize.Bit32 LFIWZX
    decode "7c263eee" Endian.Big WordSize.Bit64 LFIWZX
    decode "ee3e267c" Endian.Little WordSize.Bit64 LFIWZX

  [<TestMethod>]
  member _.``[PPC T] LFS original decoding``() =
    decode "c0260008" Endian.Big WordSize.Bit32 LFS
    decode "c0260008" Endian.Big WordSize.Bit64 LFS
    decode "080026c0" Endian.Little WordSize.Bit64 LFS

  [<TestMethod>]
  member _.``[PPC T] LFSU original decoding``() =
    decode "c4260008" Endian.Big WordSize.Bit32 LFSU
    decode "c4260008" Endian.Big WordSize.Bit64 LFSU
    decode "080026c4" Endian.Little WordSize.Bit64 LFSU

  [<TestMethod>]
  member _.``[PPC T] LFSUX original decoding``() =
    decode "7c263c6e" Endian.Big WordSize.Bit32 LFSUX
    decode "7c263c6e" Endian.Big WordSize.Bit64 LFSUX
    decode "6e3c267c" Endian.Little WordSize.Bit64 LFSUX

  [<TestMethod>]
  member _.``[PPC T] LFSX original decoding``() =
    decode "7c263c2e" Endian.Big WordSize.Bit32 LFSX
    decode "7c263c2e" Endian.Big WordSize.Bit64 LFSX
    decode "2e3c267c" Endian.Little WordSize.Bit64 LFSX

  [<TestMethod>]
  member _.``[PPC T] LHA original decoding``() =
    decode "a8a60008" Endian.Big WordSize.Bit32 LHA
    decode "a8a60008" Endian.Big WordSize.Bit64 LHA
    decode "0800a6a8" Endian.Little WordSize.Bit64 LHA

  [<TestMethod>]
  member _.``[PPC T] LHAU original decoding``() =
    decode "aca60008" Endian.Big WordSize.Bit32 LHAU
    decode "aca60008" Endian.Big WordSize.Bit64 LHAU
    decode "0800a6ac" Endian.Little WordSize.Bit64 LHAU

  [<TestMethod>]
  member _.``[PPC T] LHAUX original decoding``() =
    decode "7ca63aee" Endian.Big WordSize.Bit32 LHAUX
    decode "7ca63aee" Endian.Big WordSize.Bit64 LHAUX
    decode "ee3aa67c" Endian.Little WordSize.Bit64 LHAUX

  [<TestMethod>]
  member _.``[PPC T] LHAX original decoding``() =
    decode "7ca63aae" Endian.Big WordSize.Bit32 LHAX
    decode "7ca63aae" Endian.Big WordSize.Bit64 LHAX
    decode "ae3aa67c" Endian.Little WordSize.Bit64 LHAX

  [<TestMethod>]
  member _.``[PPC T] LHBRX original decoding``() =
    decode "7ca63e2c" Endian.Big WordSize.Bit32 LHBRX
    decode "7ca63e2c" Endian.Big WordSize.Bit64 LHBRX
    decode "2c3ea67c" Endian.Little WordSize.Bit64 LHBRX

  [<TestMethod>]
  member _.``[PPC T] LHZ original decoding``() =
    decode "a0a60008" Endian.Big WordSize.Bit32 LHZ
    decode "a0a60008" Endian.Big WordSize.Bit64 LHZ
    decode "0800a6a0" Endian.Little WordSize.Bit64 LHZ

  [<TestMethod>]
  member _.``[PPC T] LHZU original decoding``() =
    decode "a4a60008" Endian.Big WordSize.Bit32 LHZU
    decode "a4a60008" Endian.Big WordSize.Bit64 LHZU
    decode "0800a6a4" Endian.Little WordSize.Bit64 LHZU

  [<TestMethod>]
  member _.``[PPC T] LHZUX original decoding``() =
    decode "7ca63a6e" Endian.Big WordSize.Bit32 LHZUX
    decode "7ca63a6e" Endian.Big WordSize.Bit64 LHZUX
    decode "6e3aa67c" Endian.Little WordSize.Bit64 LHZUX

  [<TestMethod>]
  member _.``[PPC T] LHZX original decoding``() =
    decode "7ca63a2e" Endian.Big WordSize.Bit32 LHZX
    decode "7ca63a2e" Endian.Big WordSize.Bit64 LHZX
    decode "2e3aa67c" Endian.Little WordSize.Bit64 LHZX

  [<TestMethod>]
  member _.``[PPC T] LMW original decoding``() =
    decode "bba60008" Endian.Big WordSize.Bit32 LMW
    decode "bba60008" Endian.Big WordSize.Bit64 LMW
    decode "0800a6bb" Endian.Little WordSize.Bit64 LMW

  [<TestMethod>]
  member _.``[PPC T] LSWI original decoding``() =
    decode "7ca624aa" Endian.Big WordSize.Bit32 LSWI
    decode "7ca624aa" Endian.Big WordSize.Bit64 LSWI
    decode "aa24a67c" Endian.Little WordSize.Bit64 LSWI

  [<TestMethod>]
  member _.``[PPC T] LSWX original decoding``() =
    decode "7ca63c2a" Endian.Big WordSize.Bit32 LSWX
    decode "7ca63c2a" Endian.Big WordSize.Bit64 LSWX
    decode "2a3ca67c" Endian.Little WordSize.Bit64 LSWX

  [<TestMethod>]
  member _.``[PPC T] LVEBX original decoding``() =
    decode "7c26380e" Endian.Big WordSize.Bit32 LVEBX
    decode "7c26380e" Endian.Big WordSize.Bit64 LVEBX
    decode "0e38267c" Endian.Little WordSize.Bit64 LVEBX

  [<TestMethod>]
  member _.``[PPC T] LVEHX original decoding``() =
    decode "7c26384e" Endian.Big WordSize.Bit32 LVEHX
    decode "7c26384e" Endian.Big WordSize.Bit64 LVEHX
    decode "4e38267c" Endian.Little WordSize.Bit64 LVEHX

  [<TestMethod>]
  member _.``[PPC T] LVEWX original decoding``() =
    decode "7c26388e" Endian.Big WordSize.Bit32 LVEWX
    decode "7c26388e" Endian.Big WordSize.Bit64 LVEWX
    decode "8e38267c" Endian.Little WordSize.Bit64 LVEWX

  [<TestMethod>]
  member _.``[PPC T] LVSL original decoding``() =
    decode "7c26380c" Endian.Big WordSize.Bit32 LVSL
    decode "7c26380c" Endian.Big WordSize.Bit64 LVSL
    decode "0c38267c" Endian.Little WordSize.Bit64 LVSL

  [<TestMethod>]
  member _.``[PPC T] LVSR original decoding``() =
    decode "7c26384c" Endian.Big WordSize.Bit32 LVSR
    decode "7c26384c" Endian.Big WordSize.Bit64 LVSR
    decode "4c38267c" Endian.Little WordSize.Bit64 LVSR

  [<TestMethod>]
  member _.``[PPC T] LVX original decoding``() =
    decode "7c2638ce" Endian.Big WordSize.Bit32 LVX
    decode "7c2638ce" Endian.Big WordSize.Bit64 LVX
    decode "ce38267c" Endian.Little WordSize.Bit64 LVX

  [<TestMethod>]
  member _.``[PPC T] LVXL original decoding``() =
    decode "7c263ace" Endian.Big WordSize.Bit32 LVXL
    decode "7c263ace" Endian.Big WordSize.Bit64 LVXL
    decode "ce3a267c" Endian.Little WordSize.Bit64 LVXL

  [<TestMethod>]
  member _.``[PPC T] LWA original decoding``() =
    refuse "e8a6000a"
    decode "e8a6000a" Endian.Big WordSize.Bit64 LWA
    decode "0a00a6e8" Endian.Little WordSize.Bit64 LWA

  [<TestMethod>]
  member _.``[PPC T] LWARX original decoding``() =
    decode "7ca63828" Endian.Big WordSize.Bit32 LWARX
    decode "7ca63828" Endian.Big WordSize.Bit64 LWARX
    decode "2838a67c" Endian.Little WordSize.Bit64 LWARX

  [<TestMethod>]
  member _.``[PPC T] LWAUX original decoding``() =
    refuse "7ca63aea"
    decode "7ca63aea" Endian.Big WordSize.Bit64 LWAUX
    decode "ea3aa67c" Endian.Little WordSize.Bit64 LWAUX

  [<TestMethod>]
  member _.``[PPC T] LWAX original decoding``() =
    refuse "7ca63aaa"
    decode "7ca63aaa" Endian.Big WordSize.Bit64 LWAX
    decode "aa3aa67c" Endian.Little WordSize.Bit64 LWAX

  [<TestMethod>]
  member _.``[PPC T] LWBRX original decoding``() =
    decode "7ca63c2c" Endian.Big WordSize.Bit32 LWBRX
    decode "7ca63c2c" Endian.Big WordSize.Bit64 LWBRX
    decode "2c3ca67c" Endian.Little WordSize.Bit64 LWBRX

  [<TestMethod>]
  member _.``[PPC T] LWZU original decoding``() =
    decode "84a60008" Endian.Big WordSize.Bit32 LWZU
    decode "84a60008" Endian.Big WordSize.Bit64 LWZU
    decode "0800a684" Endian.Little WordSize.Bit64 LWZU

  [<TestMethod>]
  member _.``[PPC T] LWZUX original decoding``() =
    decode "7ca6386e" Endian.Big WordSize.Bit32 LWZUX
    decode "7ca6386e" Endian.Big WordSize.Bit64 LWZUX
    decode "6e38a67c" Endian.Little WordSize.Bit64 LWZUX

  [<TestMethod>]
  member _.``[PPC T] LWZX original decoding``() =
    decode "7ca6382e" Endian.Big WordSize.Bit32 LWZX
    decode "7ca6382e" Endian.Big WordSize.Bit64 LWZX
    decode "2e38a67c" Endian.Little WordSize.Bit64 LWZX

  [<TestMethod>]
  member _.``[PPC T] LXSD original decoding``() =
    refuse "e426000a"
    decode "e426000a" Endian.Big WordSize.Bit64 LXSD
    decode "0a0026e4" Endian.Little WordSize.Bit64 LXSD

  [<TestMethod>]
  member _.``[PPC T] LXSDX original decoding``() =
    decode "7c263c98" Endian.Big WordSize.Bit32 LXSDX
    decode "7c263c98" Endian.Big WordSize.Bit64 LXSDX
    decode "983c267c" Endian.Little WordSize.Bit64 LXSDX

  [<TestMethod>]
  member _.``[PPC T] LXVD2X original decoding``() =
    decode "7c263e98" Endian.Big WordSize.Bit32 LXVD2X
    decode "7c263e98" Endian.Big WordSize.Bit64 LXVD2X
    decode "983e267c" Endian.Little WordSize.Bit64 LXVD2X

  [<TestMethod>]
  member _.``[PPC T] LXVDSX original decoding``() =
    decode "7c263a98" Endian.Big WordSize.Bit32 LXVDSX
    decode "7c263a98" Endian.Big WordSize.Bit64 LXVDSX
    decode "983a267c" Endian.Little WordSize.Bit64 LXVDSX

  [<TestMethod>]
  member _.``[PPC T] LXVW4X original decoding``() =
    decode "7c263e18" Endian.Big WordSize.Bit32 LXVW4X
    decode "7c263e18" Endian.Big WordSize.Bit64 LXVW4X
    decode "183e267c" Endian.Little WordSize.Bit64 LXVW4X

  [<TestMethod>]
  member _.``[PPC T] MCRF original decoding``() =
    decode "4d0c0000" Endian.Big WordSize.Bit32 MCRF
    decode "4d0c0000" Endian.Big WordSize.Bit64 MCRF
    decode "00000c4d" Endian.Little WordSize.Bit64 MCRF

  [<TestMethod>]
  member _.``[PPC T] MCRFS original decoding``() =
    decode "fd0c0080" Endian.Big WordSize.Bit32 MCRFS
    decode "fd0c0080" Endian.Big WordSize.Bit64 MCRFS
    decode "80000cfd" Endian.Little WordSize.Bit64 MCRFS

  [<TestMethod>]
  member _.``[PPC T] MFCR original decoding``() =
    decode "7ca00026" Endian.Big WordSize.Bit32 MFCR
    decode "7ca00026" Endian.Big WordSize.Bit64 MFCR
    decode "2600a07c" Endian.Little WordSize.Bit64 MFCR

  [<TestMethod>]
  member _.``[PPC T] MFFS original decoding``() =
    decode "fc20048e" Endian.Big WordSize.Bit32 MFFS
    decode "fc20048e" Endian.Big WordSize.Bit64 MFFS
    decode "8e0420fc" Endian.Little WordSize.Bit64 MFFS

  [<TestMethod>]
  member _.``[PPC T] MFFS. original decoding``() =
    decode "fc20048f" Endian.Big WordSize.Bit32 MFFSdot
    decode "fc20048f" Endian.Big WordSize.Bit64 MFFSdot
    decode "8f0420fc" Endian.Little WordSize.Bit64 MFFSdot

  [<TestMethod>]
  member _.``[PPC T] MFFSCRN original decoding``() =
    decode "fc361c8e" Endian.Big WordSize.Bit32 MFFSCRN
    decode "fc361c8e" Endian.Big WordSize.Bit64 MFFSCRN
    decode "8e1c36fc" Endian.Little WordSize.Bit64 MFFSCRN

  [<TestMethod>]
  member _.``[PPC T] MFFSCRNI original decoding``() =
    decode "fc370c8e" Endian.Big WordSize.Bit32 MFFSCRNI
    decode "fc370c8e" Endian.Big WordSize.Bit64 MFFSCRNI
    decode "8e0c37fc" Endian.Little WordSize.Bit64 MFFSCRNI

  [<TestMethod>]
  member _.``[PPC T] MFFSL original decoding``() =
    decode "fc38048e" Endian.Big WordSize.Bit32 MFFSL
    decode "fc38048e" Endian.Big WordSize.Bit64 MFFSL
    decode "8e0438fc" Endian.Little WordSize.Bit64 MFFSL

  [<TestMethod>]
  member _.``[PPC T] MFTB original decoding``() =
    decode "7cac42a6" Endian.Big WordSize.Bit32 MFTB
    decode "7cac42a6" Endian.Big WordSize.Bit64 MFTB
    decode "a642ac7c" Endian.Little WordSize.Bit64 MFTB

  [<TestMethod>]
  member _.``[PPC T] MFVSCR original decoding``() =
    decode "10200604" Endian.Big WordSize.Bit32 MFVSCR
    decode "10200604" Endian.Big WordSize.Bit64 MFVSCR
    decode "04062010" Endian.Little WordSize.Bit64 MFVSCR

  [<TestMethod>]
  member _.``[PPC T] MFVSRD original decoding``() =
    refuse "7c260066"
    decode "7c260066" Endian.Big WordSize.Bit64 MFVSRD
    decode "6600267c" Endian.Little WordSize.Bit64 MFVSRD

  [<TestMethod>]
  member _.``[PPC T] MFVSRLD original decoding``() =
    refuse "7c260266"
    decode "7c260266" Endian.Big WordSize.Bit64 MFVSRLD
    decode "6602267c" Endian.Little WordSize.Bit64 MFVSRLD

  [<TestMethod>]
  member _.``[PPC T] MFVSRWZ original decoding``() =
    refuse "7c2600e6"
    decode "7c2600e6" Endian.Big WordSize.Bit64 MFVSRWZ
    decode "e600267c" Endian.Little WordSize.Bit64 MFVSRWZ

  [<TestMethod>]
  member _.``[PPC T] MTCRF original decoding``() =
    decode "7d021120" Endian.Big WordSize.Bit32 MTCRF
    decode "7d021120" Endian.Big WordSize.Bit64 MTCRF
    decode "2011027d" Endian.Little WordSize.Bit64 MTCRF

  [<TestMethod>]
  member _.``[PPC T] MTFSB0 original decoding``() =
    decode "fd20008c" Endian.Big WordSize.Bit32 MTFSB0
    decode "fd20008c" Endian.Big WordSize.Bit64 MTFSB0
    decode "8c0020fd" Endian.Little WordSize.Bit64 MTFSB0

  [<TestMethod>]
  member _.``[PPC T] MTFSB0. original decoding``() =
    decode "fd20008d" Endian.Big WordSize.Bit32 MTFSB0dot
    decode "fd20008d" Endian.Big WordSize.Bit64 MTFSB0dot
    decode "8d0020fd" Endian.Little WordSize.Bit64 MTFSB0dot

  [<TestMethod>]
  member _.``[PPC T] MTFSB1 original decoding``() =
    decode "fd20004c" Endian.Big WordSize.Bit32 MTFSB1
    decode "fd20004c" Endian.Big WordSize.Bit64 MTFSB1
    decode "4c0020fd" Endian.Little WordSize.Bit64 MTFSB1

  [<TestMethod>]
  member _.``[PPC T] MTFSB1. original decoding``() =
    decode "fd20004d" Endian.Big WordSize.Bit32 MTFSB1dot
    decode "fd20004d" Endian.Big WordSize.Bit64 MTFSB1dot
    decode "4d0020fd" Endian.Little WordSize.Bit64 MTFSB1dot

  [<TestMethod>]
  member _.``[PPC T] MTFSF. original decoding``() =
    decode "fdfe1d8f" Endian.Big WordSize.Bit32 MTFSFdot
    decode "fdfe1d8f" Endian.Big WordSize.Bit64 MTFSFdot
    decode "8f1dfefd" Endian.Little WordSize.Bit64 MTFSFdot

  [<TestMethod>]
  member _.``[PPC T] MTFSFI. original decoding``() =
    decode "fd00010d" Endian.Big WordSize.Bit32 MTFSFIdot
    decode "fd00010d" Endian.Big WordSize.Bit64 MTFSFIdot
    decode "0d0100fd" Endian.Little WordSize.Bit64 MTFSFIdot

  [<TestMethod>]
  member _.``[PPC T] MTOCRF original decoding``() =
    decode "7d120120" Endian.Big WordSize.Bit32 MTOCRF
    decode "7d120120" Endian.Big WordSize.Bit64 MTOCRF
    decode "2001127d" Endian.Little WordSize.Bit64 MTOCRF

  [<TestMethod>]
  member _.``[PPC T] MTSPR original decoding``() =
    decode "7d0903a6" Endian.Big WordSize.Bit32 MTCTR
    decode "7d0903a6" Endian.Big WordSize.Bit64 MTCTR
    decode "a603097d" Endian.Little WordSize.Bit64 MTCTR

  [<TestMethod>]
  member _.``[PPC T] MTVSCR original decoding``() =
    decode "10001e44" Endian.Big WordSize.Bit32 MTVSCR
    decode "10001e44" Endian.Big WordSize.Bit64 MTVSCR
    decode "441e0010" Endian.Little WordSize.Bit64 MTVSCR

  [<TestMethod>]
  member _.``[PPC T] MTVSRD original decoding``() =
    refuse "7c260166"
    decode "7c260166" Endian.Big WordSize.Bit64 MTVSRD
    decode "6601267c" Endian.Little WordSize.Bit64 MTVSRD

  [<TestMethod>]
  member _.``[PPC T] MTVSRDD original decoding``() =
    refuse "7c263b66"
    decode "7c263b66" Endian.Big WordSize.Bit64 MTVSRDD
    decode "663b267c" Endian.Little WordSize.Bit64 MTVSRDD

  [<TestMethod>]
  member _.``[PPC T] MTVSRWA original decoding``() =
    refuse "7c2601a6"
    decode "7c2601a6" Endian.Big WordSize.Bit64 MTVSRWA
    decode "a601267c" Endian.Little WordSize.Bit64 MTVSRWA

  [<TestMethod>]
  member _.``[PPC T] MTVSRWZ original decoding``() =
    refuse "7c2601e6"
    decode "7c2601e6" Endian.Big WordSize.Bit64 MTVSRWZ
    decode "e601267c" Endian.Little WordSize.Bit64 MTVSRWZ

  [<TestMethod>]
  member _.``[PPC T] MULHD original decoding``() =
    refuse "7ca63892"
    decode "7ca63892" Endian.Big WordSize.Bit64 MULHD
    decode "9238a67c" Endian.Little WordSize.Bit64 MULHD

  [<TestMethod>]
  member _.``[PPC T] MULHD. original decoding``() =
    refuse "7ca63893"
    decode "7ca63893" Endian.Big WordSize.Bit64 MULHDdot
    decode "9338a67c" Endian.Little WordSize.Bit64 MULHDdot

  [<TestMethod>]
  member _.``[PPC T] MULHDU original decoding``() =
    refuse "7ca63812"
    decode "7ca63812" Endian.Big WordSize.Bit64 MULHDU
    decode "1238a67c" Endian.Little WordSize.Bit64 MULHDU

  [<TestMethod>]
  member _.``[PPC T] MULHDU. original decoding``() =
    refuse "7ca63813"
    decode "7ca63813" Endian.Big WordSize.Bit64 MULHDUdot
    decode "1338a67c" Endian.Little WordSize.Bit64 MULHDUdot

  [<TestMethod>]
  member _.``[PPC T] MULHW original decoding``() =
    decode "7ca63896" Endian.Big WordSize.Bit32 MULHW
    decode "7ca63896" Endian.Big WordSize.Bit64 MULHW
    decode "9638a67c" Endian.Little WordSize.Bit64 MULHW

  [<TestMethod>]
  member _.``[PPC T] MULHW. original decoding``() =
    decode "7ca63897" Endian.Big WordSize.Bit32 MULHWdot
    decode "7ca63897" Endian.Big WordSize.Bit64 MULHWdot
    decode "9738a67c" Endian.Little WordSize.Bit64 MULHWdot

  [<TestMethod>]
  member _.``[PPC T] MULHWU original decoding``() =
    decode "7ca63816" Endian.Big WordSize.Bit32 MULHWU
    decode "7ca63816" Endian.Big WordSize.Bit64 MULHWU
    decode "1638a67c" Endian.Little WordSize.Bit64 MULHWU

  [<TestMethod>]
  member _.``[PPC T] MULHWU. original decoding``() =
    decode "7ca63817" Endian.Big WordSize.Bit32 MULHWUdot
    decode "7ca63817" Endian.Big WordSize.Bit64 MULHWUdot
    decode "1738a67c" Endian.Little WordSize.Bit64 MULHWUdot

  [<TestMethod>]
  member _.``[PPC T] MULLD original decoding``() =
    refuse "7ca639d2"
    decode "7ca639d2" Endian.Big WordSize.Bit64 MULLD
    decode "d239a67c" Endian.Little WordSize.Bit64 MULLD

  [<TestMethod>]
  member _.``[PPC T] MULLD. original decoding``() =
    refuse "7ca639d3"
    decode "7ca639d3" Endian.Big WordSize.Bit64 MULLDdot
    decode "d339a67c" Endian.Little WordSize.Bit64 MULLDdot

  [<TestMethod>]
  member _.``[PPC T] MULLI original decoding``() =
    decode "1ca6000c" Endian.Big WordSize.Bit32 MULLI
    decode "1ca6000c" Endian.Big WordSize.Bit64 MULLI
    decode "0c00a61c" Endian.Little WordSize.Bit64 MULLI

  [<TestMethod>]
  member _.``[PPC T] MULLW original decoding``() =
    decode "7ca639d6" Endian.Big WordSize.Bit32 MULLW
    decode "7ca639d6" Endian.Big WordSize.Bit64 MULLW
    decode "d639a67c" Endian.Little WordSize.Bit64 MULLW

  [<TestMethod>]
  member _.``[PPC T] MULLW. original decoding``() =
    decode "7ca639d7" Endian.Big WordSize.Bit32 MULLWdot
    decode "7ca639d7" Endian.Big WordSize.Bit64 MULLWdot
    decode "d739a67c" Endian.Little WordSize.Bit64 MULLWdot

  [<TestMethod>]
  member _.``[PPC T] MULLWO original decoding``() =
    decode "7ca63dd6" Endian.Big WordSize.Bit32 MULLWO
    decode "7ca63dd6" Endian.Big WordSize.Bit64 MULLWO
    decode "d63da67c" Endian.Little WordSize.Bit64 MULLWO

  [<TestMethod>]
  member _.``[PPC T] MULLWO. original decoding``() =
    decode "7ca63dd7" Endian.Big WordSize.Bit32 MULLWOdot
    decode "7ca63dd7" Endian.Big WordSize.Bit64 MULLWOdot
    decode "d73da67c" Endian.Little WordSize.Bit64 MULLWOdot

  [<TestMethod>]
  member _.``[PPC T] NAND. original decoding``() =
    decode "7d063bb9" Endian.Big WordSize.Bit32 NANDdot
    decode "7d063bb9" Endian.Big WordSize.Bit64 NANDdot
    decode "b93b067d" Endian.Little WordSize.Bit64 NANDdot

  [<TestMethod>]
  member _.``[PPC T] NEG original decoding``() =
    decode "7ca600d0" Endian.Big WordSize.Bit32 NEG
    decode "7ca600d0" Endian.Big WordSize.Bit64 NEG
    decode "d000a67c" Endian.Little WordSize.Bit64 NEG

  [<TestMethod>]
  member _.``[PPC T] NEG. original decoding``() =
    decode "7ca600d1" Endian.Big WordSize.Bit32 NEGdot
    decode "7ca600d1" Endian.Big WordSize.Bit64 NEGdot
    decode "d100a67c" Endian.Little WordSize.Bit64 NEGdot

  [<TestMethod>]
  member _.``[PPC T] NEGO original decoding``() =
    decode "7ca604d0" Endian.Big WordSize.Bit32 NEGO
    decode "7ca604d0" Endian.Big WordSize.Bit64 NEGO
    decode "d004a67c" Endian.Little WordSize.Bit64 NEGO

  [<TestMethod>]
  member _.``[PPC T] NEGO. original decoding``() =
    decode "7ca604d1" Endian.Big WordSize.Bit32 NEGOdot
    decode "7ca604d1" Endian.Big WordSize.Bit64 NEGOdot
    decode "d104a67c" Endian.Little WordSize.Bit64 NEGOdot

  [<TestMethod>]
  member _.``[PPC T] NOR. original decoding``() =
    decode "7d0638f9" Endian.Big WordSize.Bit32 NORdot
    decode "7d0638f9" Endian.Big WordSize.Bit64 NORdot
    decode "f938067d" Endian.Little WordSize.Bit64 NORdot

  [<TestMethod>]
  member _.``[PPC T] ORC original decoding``() =
    decode "7d063b38" Endian.Big WordSize.Bit32 ORC
    decode "7d063b38" Endian.Big WordSize.Bit64 ORC
    decode "383b067d" Endian.Little WordSize.Bit64 ORC

  [<TestMethod>]
  member _.``[PPC T] ORC. original decoding``() =
    decode "7d063b39" Endian.Big WordSize.Bit32 ORCdot
    decode "7d063b39" Endian.Big WordSize.Bit64 ORCdot
    decode "393b067d" Endian.Little WordSize.Bit64 ORCdot

  [<TestMethod>]
  member _.``[PPC T] OR. original decoding``() =
    decode "7d063b79" Endian.Big WordSize.Bit32 ORdot
    decode "7d063b79" Endian.Big WordSize.Bit64 ORdot
    decode "793b067d" Endian.Little WordSize.Bit64 ORdot

  [<TestMethod>]
  member _.``[PPC T] ORI original decoding``() =
    decode "61060055" Endian.Big WordSize.Bit32 ORI
    decode "61060055" Endian.Big WordSize.Bit64 ORI
    decode "55000661" Endian.Little WordSize.Bit64 ORI

  [<TestMethod>]
  member _.``[PPC T] ORIS original decoding``() =
    decode "65060055" Endian.Big WordSize.Bit32 ORIS
    decode "65060055" Endian.Big WordSize.Bit64 ORIS
    decode "55000665" Endian.Little WordSize.Bit64 ORIS

  [<TestMethod>]
  member _.``[PPC T] PRTYD original decoding``() =
    refuse "7d060174"
    decode "7d060174" Endian.Big WordSize.Bit64 PRTYD
    decode "7401067d" Endian.Little WordSize.Bit64 PRTYD

  [<TestMethod>]
  member _.``[PPC T] RLDCL original decoding``() =
    refuse "790638d0"
    decode "790638d0" Endian.Big WordSize.Bit64 RLDCL
    decode "d0380679" Endian.Little WordSize.Bit64 RLDCL

  [<TestMethod>]
  member _.``[PPC T] RLDCL. original decoding``() =
    refuse "790638d1"
    decode "790638d1" Endian.Big WordSize.Bit64 RLDCLdot
    decode "d1380679" Endian.Little WordSize.Bit64 RLDCLdot

  [<TestMethod>]
  member _.``[PPC T] RLDCR original decoding``() =
    refuse "79063ed2"
    decode "79063ed2" Endian.Big WordSize.Bit64 RLDCR
    decode "d23e0679" Endian.Little WordSize.Bit64 RLDCR

  [<TestMethod>]
  member _.``[PPC T] RLDCR. original decoding``() =
    refuse "79063ed3"
    decode "79063ed3" Endian.Big WordSize.Bit64 RLDCRdot
    decode "d33e0679" Endian.Little WordSize.Bit64 RLDCRdot

  [<TestMethod>]
  member _.``[PPC T] RLDIC original decoding``() =
    refuse "790628c8"
    decode "790628c8" Endian.Big WordSize.Bit64 RLDIC
    decode "c8280679" Endian.Little WordSize.Bit64 RLDIC

  [<TestMethod>]
  member _.``[PPC T] RLDIC. original decoding``() =
    refuse "790628c9"
    decode "790628c9" Endian.Big WordSize.Bit64 RLDICdot
    decode "c9280679" Endian.Little WordSize.Bit64 RLDICdot

  [<TestMethod>]
  member _.``[PPC T] RLDICL. original decoding``() =
    refuse "790628c1"
    decode "790628c1" Endian.Big WordSize.Bit64 RLDICLdot
    decode "c1280679" Endian.Little WordSize.Bit64 RLDICLdot

  [<TestMethod>]
  member _.``[PPC T] RLDICR original decoding``() =
    refuse "79062ec4"
    decode "79062ec4" Endian.Big WordSize.Bit64 RLDICR
    decode "c42e0679" Endian.Little WordSize.Bit64 RLDICR

  [<TestMethod>]
  member _.``[PPC T] RLDICR. original decoding``() =
    refuse "79062ec5"
    decode "79062ec5" Endian.Big WordSize.Bit64 RLDICRdot
    decode "c52e0679" Endian.Little WordSize.Bit64 RLDICRdot

  [<TestMethod>]
  member _.``[PPC T] RLDIMI original decoding``() =
    refuse "790628cc"
    decode "790628cc" Endian.Big WordSize.Bit64 RLDIMI
    decode "cc280679" Endian.Little WordSize.Bit64 RLDIMI

  [<TestMethod>]
  member _.``[PPC T] RLDIMI. original decoding``() =
    refuse "790628cd"
    decode "790628cd" Endian.Big WordSize.Bit64 RLDIMIdot
    decode "cd280679" Endian.Little WordSize.Bit64 RLDIMIdot

  [<TestMethod>]
  member _.``[PPC T] RLWIMI original decoding``() =
    decode "510628f6" Endian.Big WordSize.Bit32 RLWIMI
    decode "510628f6" Endian.Big WordSize.Bit64 RLWIMI
    decode "f6280651" Endian.Little WordSize.Bit64 RLWIMI

  [<TestMethod>]
  member _.``[PPC T] RLWIMI. original decoding``() =
    decode "510628f7" Endian.Big WordSize.Bit32 RLWIMIdot
    decode "510628f7" Endian.Big WordSize.Bit64 RLWIMIdot
    decode "f7280651" Endian.Little WordSize.Bit64 RLWIMIdot

  [<TestMethod>]
  member _.``[PPC T] RLWINM original decoding``() =
    decode "550628f6" Endian.Big WordSize.Bit32 RLWINM
    decode "550628f6" Endian.Big WordSize.Bit64 RLWINM
    decode "f6280655" Endian.Little WordSize.Bit64 RLWINM

  [<TestMethod>]
  member _.``[PPC T] RLWINM. original decoding``() =
    decode "550628f7" Endian.Big WordSize.Bit32 RLWINMdot
    decode "550628f7" Endian.Big WordSize.Bit64 RLWINMdot
    decode "f7280655" Endian.Little WordSize.Bit64 RLWINMdot

  [<TestMethod>]
  member _.``[PPC T] RLWNM original decoding``() =
    decode "5d0638f6" Endian.Big WordSize.Bit32 RLWNM
    decode "5d0638f6" Endian.Big WordSize.Bit64 RLWNM
    decode "f638065d" Endian.Little WordSize.Bit64 RLWNM

  [<TestMethod>]
  member _.``[PPC T] RLWNM. original decoding``() =
    decode "5d0638f7" Endian.Big WordSize.Bit32 RLWNMdot
    decode "5d0638f7" Endian.Big WordSize.Bit64 RLWNMdot
    decode "f738065d" Endian.Little WordSize.Bit64 RLWNMdot

  [<TestMethod>]
  member _.``[PPC T] SC original decoding``() =
    decode "44000002" Endian.Big WordSize.Bit32 SC
    decode "44000002" Endian.Big WordSize.Bit64 SC
    decode "02000044" Endian.Little WordSize.Bit64 SC

  [<TestMethod>]
  member _.``[PPC T] SLD original decoding``() =
    refuse "7d063836"
    decode "7d063836" Endian.Big WordSize.Bit64 SLD
    decode "3638067d" Endian.Little WordSize.Bit64 SLD

  [<TestMethod>]
  member _.``[PPC T] SLD. original decoding``() =
    refuse "7d063837"
    decode "7d063837" Endian.Big WordSize.Bit64 SLDdot
    decode "3738067d" Endian.Little WordSize.Bit64 SLDdot

  [<TestMethod>]
  member _.``[PPC T] SLW original decoding``() =
    decode "7d063830" Endian.Big WordSize.Bit32 SLW
    decode "7d063830" Endian.Big WordSize.Bit64 SLW
    decode "3038067d" Endian.Little WordSize.Bit64 SLW

  [<TestMethod>]
  member _.``[PPC T] SLW. original decoding``() =
    decode "7d063831" Endian.Big WordSize.Bit32 SLWdot
    decode "7d063831" Endian.Big WordSize.Bit64 SLWdot
    decode "3138067d" Endian.Little WordSize.Bit64 SLWdot

  [<TestMethod>]
  member _.``[PPC T] SRAD original decoding``() =
    refuse "7d063e34"
    decode "7d063e34" Endian.Big WordSize.Bit64 SRAD
    decode "343e067d" Endian.Little WordSize.Bit64 SRAD

  [<TestMethod>]
  member _.``[PPC T] SRAD. original decoding``() =
    refuse "7d063e35"
    decode "7d063e35" Endian.Big WordSize.Bit64 SRADdot
    decode "353e067d" Endian.Little WordSize.Bit64 SRADdot

  [<TestMethod>]
  member _.``[PPC T] SRADI. original decoding``() =
    refuse "7d062e75"
    decode "7d062e75" Endian.Big WordSize.Bit64 SRADIdot
    decode "752e067d" Endian.Little WordSize.Bit64 SRADIdot

  [<TestMethod>]
  member _.``[PPC T] SRAW original decoding``() =
    decode "7d063e30" Endian.Big WordSize.Bit32 SRAW
    decode "7d063e30" Endian.Big WordSize.Bit64 SRAW
    decode "303e067d" Endian.Little WordSize.Bit64 SRAW

  [<TestMethod>]
  member _.``[PPC T] SRAW. original decoding``() =
    decode "7d063e31" Endian.Big WordSize.Bit32 SRAWdot
    decode "7d063e31" Endian.Big WordSize.Bit64 SRAWdot
    decode "313e067d" Endian.Little WordSize.Bit64 SRAWdot

  [<TestMethod>]
  member _.``[PPC T] SRAWI original decoding``() =
    decode "7d062e70" Endian.Big WordSize.Bit32 SRAWI
    decode "7d062e70" Endian.Big WordSize.Bit64 SRAWI
    decode "702e067d" Endian.Little WordSize.Bit64 SRAWI

  [<TestMethod>]
  member _.``[PPC T] SRAWI. original decoding``() =
    decode "7d062e71" Endian.Big WordSize.Bit32 SRAWIdot
    decode "7d062e71" Endian.Big WordSize.Bit64 SRAWIdot
    decode "712e067d" Endian.Little WordSize.Bit64 SRAWIdot

  [<TestMethod>]
  member _.``[PPC T] SRD original decoding``() =
    refuse "7d063c36"
    decode "7d063c36" Endian.Big WordSize.Bit64 SRD
    decode "363c067d" Endian.Little WordSize.Bit64 SRD

  [<TestMethod>]
  member _.``[PPC T] SRD. original decoding``() =
    refuse "7d063c37"
    decode "7d063c37" Endian.Big WordSize.Bit64 SRDdot
    decode "373c067d" Endian.Little WordSize.Bit64 SRDdot

  [<TestMethod>]
  member _.``[PPC T] SRW original decoding``() =
    decode "7d063c30" Endian.Big WordSize.Bit32 SRW
    decode "7d063c30" Endian.Big WordSize.Bit64 SRW
    decode "303c067d" Endian.Little WordSize.Bit64 SRW

  [<TestMethod>]
  member _.``[PPC T] SRW. original decoding``() =
    decode "7d063c31" Endian.Big WordSize.Bit32 SRWdot
    decode "7d063c31" Endian.Big WordSize.Bit64 SRWdot
    decode "313c067d" Endian.Little WordSize.Bit64 SRWdot

  [<TestMethod>]
  member _.``[PPC T] STB original decoding``() =
    decode "99060008" Endian.Big WordSize.Bit32 STB
    decode "99060008" Endian.Big WordSize.Bit64 STB
    decode "08000699" Endian.Little WordSize.Bit64 STB

  [<TestMethod>]
  member _.``[PPC T] STBU original decoding``() =
    decode "9d060008" Endian.Big WordSize.Bit32 STBU
    decode "9d060008" Endian.Big WordSize.Bit64 STBU
    decode "0800069d" Endian.Little WordSize.Bit64 STBU

  [<TestMethod>]
  member _.``[PPC T] STBUX original decoding``() =
    decode "7d0639ee" Endian.Big WordSize.Bit32 STBUX
    decode "7d0639ee" Endian.Big WordSize.Bit64 STBUX
    decode "ee39067d" Endian.Little WordSize.Bit64 STBUX

  [<TestMethod>]
  member _.``[PPC T] STBX original decoding``() =
    decode "7d0639ae" Endian.Big WordSize.Bit32 STBX
    decode "7d0639ae" Endian.Big WordSize.Bit64 STBX
    decode "ae39067d" Endian.Little WordSize.Bit64 STBX

  [<TestMethod>]
  member _.``[PPC T] STD original decoding``() =
    refuse "f9060008"
    decode "f9060008" Endian.Big WordSize.Bit64 STD
    decode "080006f9" Endian.Little WordSize.Bit64 STD

  [<TestMethod>]
  member _.``[PPC T] STDBRX original decoding``() =
    refuse "7d063d28"
    decode "7d063d28" Endian.Big WordSize.Bit64 STDBRX
    decode "283d067d" Endian.Little WordSize.Bit64 STDBRX

  [<TestMethod>]
  member _.``[PPC T] STDCX. original decoding``() =
    refuse "7d0639ad"
    decode "7d0639ad" Endian.Big WordSize.Bit64 STDCXdot
    decode "ad39067d" Endian.Little WordSize.Bit64 STDCXdot

  [<TestMethod>]
  member _.``[PPC T] STDUX original decoding``() =
    refuse "7d06396a"
    decode "7d06396a" Endian.Big WordSize.Bit64 STDUX
    decode "6a39067d" Endian.Little WordSize.Bit64 STDUX

  [<TestMethod>]
  member _.``[PPC T] STDX original decoding``() =
    refuse "7d06392a"
    decode "7d06392a" Endian.Big WordSize.Bit64 STDX
    decode "2a39067d" Endian.Little WordSize.Bit64 STDX

  [<TestMethod>]
  member _.``[PPC T] STFD original decoding``() =
    decode "d8260008" Endian.Big WordSize.Bit32 STFD
    decode "d8260008" Endian.Big WordSize.Bit64 STFD
    decode "080026d8" Endian.Little WordSize.Bit64 STFD

  [<TestMethod>]
  member _.``[PPC T] STFDU original decoding``() =
    decode "dc260008" Endian.Big WordSize.Bit32 STFDU
    decode "dc260008" Endian.Big WordSize.Bit64 STFDU
    decode "080026dc" Endian.Little WordSize.Bit64 STFDU

  [<TestMethod>]
  member _.``[PPC T] STFDUX original decoding``() =
    decode "7c263dee" Endian.Big WordSize.Bit32 STFDUX
    decode "7c263dee" Endian.Big WordSize.Bit64 STFDUX
    decode "ee3d267c" Endian.Little WordSize.Bit64 STFDUX

  [<TestMethod>]
  member _.``[PPC T] STFDX original decoding``() =
    decode "7c263dae" Endian.Big WordSize.Bit32 STFDX
    decode "7c263dae" Endian.Big WordSize.Bit64 STFDX
    decode "ae3d267c" Endian.Little WordSize.Bit64 STFDX

  [<TestMethod>]
  member _.``[PPC T] STFIWX original decoding``() =
    decode "7c263fae" Endian.Big WordSize.Bit32 STFIWX
    decode "7c263fae" Endian.Big WordSize.Bit64 STFIWX
    decode "ae3f267c" Endian.Little WordSize.Bit64 STFIWX

  [<TestMethod>]
  member _.``[PPC T] STFS original decoding``() =
    decode "d0260008" Endian.Big WordSize.Bit32 STFS
    decode "d0260008" Endian.Big WordSize.Bit64 STFS
    decode "080026d0" Endian.Little WordSize.Bit64 STFS

  [<TestMethod>]
  member _.``[PPC T] STFSU original decoding``() =
    decode "d4260008" Endian.Big WordSize.Bit32 STFSU
    decode "d4260008" Endian.Big WordSize.Bit64 STFSU
    decode "080026d4" Endian.Little WordSize.Bit64 STFSU

  [<TestMethod>]
  member _.``[PPC T] STFSUX original decoding``() =
    decode "7c263d6e" Endian.Big WordSize.Bit32 STFSUX
    decode "7c263d6e" Endian.Big WordSize.Bit64 STFSUX
    decode "6e3d267c" Endian.Little WordSize.Bit64 STFSUX

  [<TestMethod>]
  member _.``[PPC T] STFSX original decoding``() =
    decode "7c263d2e" Endian.Big WordSize.Bit32 STFSX
    decode "7c263d2e" Endian.Big WordSize.Bit64 STFSX
    decode "2e3d267c" Endian.Little WordSize.Bit64 STFSX

  [<TestMethod>]
  member _.``[PPC T] STH original decoding``() =
    decode "b1060008" Endian.Big WordSize.Bit32 STH
    decode "b1060008" Endian.Big WordSize.Bit64 STH
    decode "080006b1" Endian.Little WordSize.Bit64 STH

  [<TestMethod>]
  member _.``[PPC T] STHBRX original decoding``() =
    decode "7d063f2c" Endian.Big WordSize.Bit32 STHBRX
    decode "7d063f2c" Endian.Big WordSize.Bit64 STHBRX
    decode "2c3f067d" Endian.Little WordSize.Bit64 STHBRX

  [<TestMethod>]
  member _.``[PPC T] STHU original decoding``() =
    decode "b5060008" Endian.Big WordSize.Bit32 STHU
    decode "b5060008" Endian.Big WordSize.Bit64 STHU
    decode "080006b5" Endian.Little WordSize.Bit64 STHU

  [<TestMethod>]
  member _.``[PPC T] STHUX original decoding``() =
    decode "7d063b6e" Endian.Big WordSize.Bit32 STHUX
    decode "7d063b6e" Endian.Big WordSize.Bit64 STHUX
    decode "6e3b067d" Endian.Little WordSize.Bit64 STHUX

  [<TestMethod>]
  member _.``[PPC T] STHX original decoding``() =
    decode "7d063b2e" Endian.Big WordSize.Bit32 STHX
    decode "7d063b2e" Endian.Big WordSize.Bit64 STHX
    decode "2e3b067d" Endian.Little WordSize.Bit64 STHX

  [<TestMethod>]
  member _.``[PPC T] STMW original decoding``() =
    decode "bfa60008" Endian.Big WordSize.Bit32 STMW
    decode "bfa60008" Endian.Big WordSize.Bit64 STMW
    decode "0800a6bf" Endian.Little WordSize.Bit64 STMW

  [<TestMethod>]
  member _.``[PPC T] STSWI original decoding``() =
    decode "7d0625aa" Endian.Big WordSize.Bit32 STSWI
    decode "7d0625aa" Endian.Big WordSize.Bit64 STSWI
    decode "aa25067d" Endian.Little WordSize.Bit64 STSWI

  [<TestMethod>]
  member _.``[PPC T] STSWX original decoding``() =
    decode "7d063d2a" Endian.Big WordSize.Bit32 STSWX
    decode "7d063d2a" Endian.Big WordSize.Bit64 STSWX
    decode "2a3d067d" Endian.Little WordSize.Bit64 STSWX

  [<TestMethod>]
  member _.``[PPC T] STVEBX original decoding``() =
    decode "7c26390e" Endian.Big WordSize.Bit32 STVEBX
    decode "7c26390e" Endian.Big WordSize.Bit64 STVEBX
    decode "0e39267c" Endian.Little WordSize.Bit64 STVEBX

  [<TestMethod>]
  member _.``[PPC T] STVEHX original decoding``() =
    decode "7c26394e" Endian.Big WordSize.Bit32 STVEHX
    decode "7c26394e" Endian.Big WordSize.Bit64 STVEHX
    decode "4e39267c" Endian.Little WordSize.Bit64 STVEHX

  [<TestMethod>]
  member _.``[PPC T] STVEWX original decoding``() =
    decode "7c26398e" Endian.Big WordSize.Bit32 STVEWX
    decode "7c26398e" Endian.Big WordSize.Bit64 STVEWX
    decode "8e39267c" Endian.Little WordSize.Bit64 STVEWX

  [<TestMethod>]
  member _.``[PPC T] STVX original decoding``() =
    decode "7c2639ce" Endian.Big WordSize.Bit32 STVX
    decode "7c2639ce" Endian.Big WordSize.Bit64 STVX
    decode "ce39267c" Endian.Little WordSize.Bit64 STVX

  [<TestMethod>]
  member _.``[PPC T] STVXL original decoding``() =
    decode "7c263bce" Endian.Big WordSize.Bit32 STVXL
    decode "7c263bce" Endian.Big WordSize.Bit64 STVXL
    decode "ce3b267c" Endian.Little WordSize.Bit64 STVXL

  [<TestMethod>]
  member _.``[PPC T] STW original decoding``() =
    decode "91060008" Endian.Big WordSize.Bit32 STW
    decode "91060008" Endian.Big WordSize.Bit64 STW
    decode "08000691" Endian.Little WordSize.Bit64 STW

  [<TestMethod>]
  member _.``[PPC T] STWBRX original decoding``() =
    decode "7d063d2c" Endian.Big WordSize.Bit32 STWBRX
    decode "7d063d2c" Endian.Big WordSize.Bit64 STWBRX
    decode "2c3d067d" Endian.Little WordSize.Bit64 STWBRX

  [<TestMethod>]
  member _.``[PPC T] STWCX. original decoding``() =
    decode "7d06392d" Endian.Big WordSize.Bit32 STWCXdot
    decode "7d06392d" Endian.Big WordSize.Bit64 STWCXdot
    decode "2d39067d" Endian.Little WordSize.Bit64 STWCXdot

  [<TestMethod>]
  member _.``[PPC T] STWU original decoding``() =
    decode "95060008" Endian.Big WordSize.Bit32 STWU
    decode "95060008" Endian.Big WordSize.Bit64 STWU
    decode "08000695" Endian.Little WordSize.Bit64 STWU

  [<TestMethod>]
  member _.``[PPC T] STWUX original decoding``() =
    decode "7d06396e" Endian.Big WordSize.Bit32 STWUX
    decode "7d06396e" Endian.Big WordSize.Bit64 STWUX
    decode "6e39067d" Endian.Little WordSize.Bit64 STWUX

  [<TestMethod>]
  member _.``[PPC T] STWX original decoding``() =
    decode "7d06392e" Endian.Big WordSize.Bit32 STWX
    decode "7d06392e" Endian.Big WordSize.Bit64 STWX
    decode "2e39067d" Endian.Little WordSize.Bit64 STWX

  [<TestMethod>]
  member _.``[PPC T] STXSD original decoding``() =
    refuse "f426000a"
    decode "f426000a" Endian.Big WordSize.Bit64 STXSD
    decode "0a0026f4" Endian.Little WordSize.Bit64 STXSD

  [<TestMethod>]
  member _.``[PPC T] STXSDX original decoding``() =
    decode "7c263d98" Endian.Big WordSize.Bit32 STXSDX
    decode "7c263d98" Endian.Big WordSize.Bit64 STXSDX
    decode "983d267c" Endian.Little WordSize.Bit64 STXSDX

  [<TestMethod>]
  member _.``[PPC T] STXVW4X original decoding``() =
    decode "7c263f18" Endian.Big WordSize.Bit32 STXVW4X
    decode "7c263f18" Endian.Big WordSize.Bit64 STXVW4X
    decode "183f267c" Endian.Little WordSize.Bit64 STXVW4X

  [<TestMethod>]
  member _.``[PPC T] SUBF original decoding``() =
    decode "7ca63850" Endian.Big WordSize.Bit32 SUBF
    decode "7ca63850" Endian.Big WordSize.Bit64 SUBF
    decode "5038a67c" Endian.Little WordSize.Bit64 SUBF

  [<TestMethod>]
  member _.``[PPC T] SUBFC original decoding``() =
    decode "7ca63810" Endian.Big WordSize.Bit32 SUBFC
    decode "7ca63810" Endian.Big WordSize.Bit64 SUBFC
    decode "1038a67c" Endian.Little WordSize.Bit64 SUBFC

  [<TestMethod>]
  member _.``[PPC T] SUBFC. original decoding``() =
    decode "7ca63811" Endian.Big WordSize.Bit32 SUBFCdot
    decode "7ca63811" Endian.Big WordSize.Bit64 SUBFCdot
    decode "1138a67c" Endian.Little WordSize.Bit64 SUBFCdot

  [<TestMethod>]
  member _.``[PPC T] SUBFCO original decoding``() =
    decode "7ca63c10" Endian.Big WordSize.Bit32 SUBFCO
    decode "7ca63c10" Endian.Big WordSize.Bit64 SUBFCO
    decode "103ca67c" Endian.Little WordSize.Bit64 SUBFCO

  [<TestMethod>]
  member _.``[PPC T] SUBFCO. original decoding``() =
    decode "7ca63c11" Endian.Big WordSize.Bit32 SUBFCOdot
    decode "7ca63c11" Endian.Big WordSize.Bit64 SUBFCOdot
    decode "113ca67c" Endian.Little WordSize.Bit64 SUBFCOdot

  [<TestMethod>]
  member _.``[PPC T] SUBF. original decoding``() =
    decode "7ca63851" Endian.Big WordSize.Bit32 SUBFdot
    decode "7ca63851" Endian.Big WordSize.Bit64 SUBFdot
    decode "5138a67c" Endian.Little WordSize.Bit64 SUBFdot

  [<TestMethod>]
  member _.``[PPC T] SUBFE original decoding``() =
    decode "7ca63910" Endian.Big WordSize.Bit32 SUBFE
    decode "7ca63910" Endian.Big WordSize.Bit64 SUBFE
    decode "1039a67c" Endian.Little WordSize.Bit64 SUBFE

  [<TestMethod>]
  member _.``[PPC T] SUBFE. original decoding``() =
    decode "7ca63911" Endian.Big WordSize.Bit32 SUBFEdot
    decode "7ca63911" Endian.Big WordSize.Bit64 SUBFEdot
    decode "1139a67c" Endian.Little WordSize.Bit64 SUBFEdot

  [<TestMethod>]
  member _.``[PPC T] SUBFEO original decoding``() =
    decode "7ca63d10" Endian.Big WordSize.Bit32 SUBFEO
    decode "7ca63d10" Endian.Big WordSize.Bit64 SUBFEO
    decode "103da67c" Endian.Little WordSize.Bit64 SUBFEO

  [<TestMethod>]
  member _.``[PPC T] SUBFEO. original decoding``() =
    decode "7ca63d11" Endian.Big WordSize.Bit32 SUBFEOdot
    decode "7ca63d11" Endian.Big WordSize.Bit64 SUBFEOdot
    decode "113da67c" Endian.Little WordSize.Bit64 SUBFEOdot

  [<TestMethod>]
  member _.``[PPC T] SUBFIC original decoding``() =
    decode "20a6000c" Endian.Big WordSize.Bit32 SUBFIC
    decode "20a6000c" Endian.Big WordSize.Bit64 SUBFIC
    decode "0c00a620" Endian.Little WordSize.Bit64 SUBFIC

  [<TestMethod>]
  member _.``[PPC T] SUBFME original decoding``() =
    decode "7ca601d0" Endian.Big WordSize.Bit32 SUBFME
    decode "7ca601d0" Endian.Big WordSize.Bit64 SUBFME
    decode "d001a67c" Endian.Little WordSize.Bit64 SUBFME

  [<TestMethod>]
  member _.``[PPC T] SUBFME. original decoding``() =
    decode "7ca601d1" Endian.Big WordSize.Bit32 SUBFMEdot
    decode "7ca601d1" Endian.Big WordSize.Bit64 SUBFMEdot
    decode "d101a67c" Endian.Little WordSize.Bit64 SUBFMEdot

  [<TestMethod>]
  member _.``[PPC T] SUBFMEO original decoding``() =
    decode "7ca605d0" Endian.Big WordSize.Bit32 SUBFMEO
    decode "7ca605d0" Endian.Big WordSize.Bit64 SUBFMEO
    decode "d005a67c" Endian.Little WordSize.Bit64 SUBFMEO

  [<TestMethod>]
  member _.``[PPC T] SUBFMEO. original decoding``() =
    decode "7ca605d1" Endian.Big WordSize.Bit32 SUBFMEOdot
    decode "7ca605d1" Endian.Big WordSize.Bit64 SUBFMEOdot
    decode "d105a67c" Endian.Little WordSize.Bit64 SUBFMEOdot

  [<TestMethod>]
  member _.``[PPC T] SUBFO original decoding``() =
    decode "7ca63c50" Endian.Big WordSize.Bit32 SUBFO
    decode "7ca63c50" Endian.Big WordSize.Bit64 SUBFO
    decode "503ca67c" Endian.Little WordSize.Bit64 SUBFO

  [<TestMethod>]
  member _.``[PPC T] SUBFO. original decoding``() =
    decode "7ca63c51" Endian.Big WordSize.Bit32 SUBFOdot
    decode "7ca63c51" Endian.Big WordSize.Bit64 SUBFOdot
    decode "513ca67c" Endian.Little WordSize.Bit64 SUBFOdot

  [<TestMethod>]
  member _.``[PPC T] SUBFZE original decoding``() =
    decode "7ca60190" Endian.Big WordSize.Bit32 SUBFZE
    decode "7ca60190" Endian.Big WordSize.Bit64 SUBFZE
    decode "9001a67c" Endian.Little WordSize.Bit64 SUBFZE

  [<TestMethod>]
  member _.``[PPC T] SUBFZE. original decoding``() =
    decode "7ca60191" Endian.Big WordSize.Bit32 SUBFZEdot
    decode "7ca60191" Endian.Big WordSize.Bit64 SUBFZEdot
    decode "9101a67c" Endian.Little WordSize.Bit64 SUBFZEdot

  [<TestMethod>]
  member _.``[PPC T] SUBFZEO original decoding``() =
    decode "7ca60590" Endian.Big WordSize.Bit32 SUBFZEO
    decode "7ca60590" Endian.Big WordSize.Bit64 SUBFZEO
    decode "9005a67c" Endian.Little WordSize.Bit64 SUBFZEO

  [<TestMethod>]
  member _.``[PPC T] SUBFZEO. original decoding``() =
    decode "7ca60591" Endian.Big WordSize.Bit32 SUBFZEOdot
    decode "7ca60591" Endian.Big WordSize.Bit64 SUBFZEOdot
    decode "9105a67c" Endian.Little WordSize.Bit64 SUBFZEOdot

  [<TestMethod>]
  member _.``[PPC T] TD original decoding``() =
    refuse "7c063888"
    decode "7c063888" Endian.Big WordSize.Bit64 TD
    decode "8838067c" Endian.Little WordSize.Bit64 TD

  [<TestMethod>]
  member _.``[PPC T] TDI original decoding``() =
    refuse "0806000c"
    decode "0806000c" Endian.Big WordSize.Bit64 TDI
    decode "0c000608" Endian.Little WordSize.Bit64 TDI

  [<TestMethod>]
  member _.``[PPC T] TW original decoding``() =
    decode "7c063808" Endian.Big WordSize.Bit32 TW
    decode "7c063808" Endian.Big WordSize.Bit64 TW
    decode "0838067c" Endian.Little WordSize.Bit64 TW

  [<TestMethod>]
  member _.``[PPC T] TWI original decoding``() =
    decode "0c06000c" Endian.Big WordSize.Bit32 TWI
    decode "0c06000c" Endian.Big WordSize.Bit64 TWI
    decode "0c00060c" Endian.Little WordSize.Bit64 TWI

  [<TestMethod>]
  member _.``[PPC T] VADDUBM original decoding``() =
    decode "10221800" Endian.Big WordSize.Bit32 VADDUBM
    decode "10221800" Endian.Big WordSize.Bit64 VADDUBM
    decode "00182210" Endian.Little WordSize.Bit64 VADDUBM

  [<TestMethod>]
  member _.``[PPC T] VADDUBS original decoding``() =
    decode "10221a00" Endian.Big WordSize.Bit32 VADDUBS
    decode "10221a00" Endian.Big WordSize.Bit64 VADDUBS
    decode "001a2210" Endian.Little WordSize.Bit64 VADDUBS

  [<TestMethod>]
  member _.``[PPC T] VADDUDM original decoding``() =
    decode "102218c0" Endian.Big WordSize.Bit32 VADDUDM
    decode "102218c0" Endian.Big WordSize.Bit64 VADDUDM
    decode "c0182210" Endian.Little WordSize.Bit64 VADDUDM

  [<TestMethod>]
  member _.``[PPC T] VADDUHM original decoding``() =
    decode "10221840" Endian.Big WordSize.Bit32 VADDUHM
    decode "10221840" Endian.Big WordSize.Bit64 VADDUHM
    decode "40182210" Endian.Little WordSize.Bit64 VADDUHM

  [<TestMethod>]
  member _.``[PPC T] VADDUWM original decoding``() =
    decode "10221880" Endian.Big WordSize.Bit32 VADDUWM
    decode "10221880" Endian.Big WordSize.Bit64 VADDUWM
    decode "80182210" Endian.Little WordSize.Bit64 VADDUWM

  [<TestMethod>]
  member _.``[PPC T] VAND original decoding``() =
    decode "10221c04" Endian.Big WordSize.Bit32 VAND
    decode "10221c04" Endian.Big WordSize.Bit64 VAND
    decode "041c2210" Endian.Little WordSize.Bit64 VAND

  [<TestMethod>]
  member _.``[PPC T] VANDC original decoding``() =
    decode "10221c44" Endian.Big WordSize.Bit32 VANDC
    decode "10221c44" Endian.Big WordSize.Bit64 VANDC
    decode "441c2210" Endian.Little WordSize.Bit64 VANDC

  [<TestMethod>]
  member _.``[PPC T] VBPERMQ original decoding``() =
    decode "10221d4c" Endian.Big WordSize.Bit32 VBPERMQ
    decode "10221d4c" Endian.Big WordSize.Bit64 VBPERMQ
    decode "4c1d2210" Endian.Little WordSize.Bit64 VBPERMQ

  [<TestMethod>]
  member _.``[PPC T] VCLZB original decoding``() =
    decode "10201f02" Endian.Big WordSize.Bit32 VCLZB
    decode "10201f02" Endian.Big WordSize.Bit64 VCLZB
    decode "021f2010" Endian.Little WordSize.Bit64 VCLZB

  [<TestMethod>]
  member _.``[PPC T] VCLZD original decoding``() =
    decode "10201fc2" Endian.Big WordSize.Bit32 VCLZD
    decode "10201fc2" Endian.Big WordSize.Bit64 VCLZD
    decode "c21f2010" Endian.Little WordSize.Bit64 VCLZD

  [<TestMethod>]
  member _.``[PPC T] VCLZH original decoding``() =
    decode "10201f42" Endian.Big WordSize.Bit32 VCLZH
    decode "10201f42" Endian.Big WordSize.Bit64 VCLZH
    decode "421f2010" Endian.Little WordSize.Bit64 VCLZH

  [<TestMethod>]
  member _.``[PPC T] VCLZW original decoding``() =
    decode "10201f82" Endian.Big WordSize.Bit32 VCLZW
    decode "10201f82" Endian.Big WordSize.Bit64 VCLZW
    decode "821f2010" Endian.Little WordSize.Bit64 VCLZW

  [<TestMethod>]
  member _.``[PPC T] VCMPEQUB original decoding``() =
    decode "10221806" Endian.Big WordSize.Bit32 VCMPEQUB
    decode "10221806" Endian.Big WordSize.Bit64 VCMPEQUB
    decode "06182210" Endian.Little WordSize.Bit64 VCMPEQUB

  [<TestMethod>]
  member _.``[PPC T] VCMPEQUB. original decoding``() =
    decode "10221c06" Endian.Big WordSize.Bit32 VCMPEQUBdot
    decode "10221c06" Endian.Big WordSize.Bit64 VCMPEQUBdot
    decode "061c2210" Endian.Little WordSize.Bit64 VCMPEQUBdot

  [<TestMethod>]
  member _.``[PPC T] VCMPEQUD original decoding``() =
    decode "102218c7" Endian.Big WordSize.Bit32 VCMPEQUD
    decode "102218c7" Endian.Big WordSize.Bit64 VCMPEQUD
    decode "c7182210" Endian.Little WordSize.Bit64 VCMPEQUD

  [<TestMethod>]
  member _.``[PPC T] VCMPEQUD. original decoding``() =
    decode "10221cc7" Endian.Big WordSize.Bit32 VCMPEQUDdot
    decode "10221cc7" Endian.Big WordSize.Bit64 VCMPEQUDdot
    decode "c71c2210" Endian.Little WordSize.Bit64 VCMPEQUDdot

  [<TestMethod>]
  member _.``[PPC T] VCMPEQUH original decoding``() =
    decode "10221846" Endian.Big WordSize.Bit32 VCMPEQUH
    decode "10221846" Endian.Big WordSize.Bit64 VCMPEQUH
    decode "46182210" Endian.Little WordSize.Bit64 VCMPEQUH

  [<TestMethod>]
  member _.``[PPC T] VCMPEQUH. original decoding``() =
    decode "10221c46" Endian.Big WordSize.Bit32 VCMPEQUHdot
    decode "10221c46" Endian.Big WordSize.Bit64 VCMPEQUHdot
    decode "461c2210" Endian.Little WordSize.Bit64 VCMPEQUHdot

  [<TestMethod>]
  member _.``[PPC T] VCMPEQUW original decoding``() =
    decode "10221886" Endian.Big WordSize.Bit32 VCMPEQUW
    decode "10221886" Endian.Big WordSize.Bit64 VCMPEQUW
    decode "86182210" Endian.Little WordSize.Bit64 VCMPEQUW

  [<TestMethod>]
  member _.``[PPC T] VCMPEQUW. original decoding``() =
    decode "10221c86" Endian.Big WordSize.Bit32 VCMPEQUWdot
    decode "10221c86" Endian.Big WordSize.Bit64 VCMPEQUWdot
    decode "861c2210" Endian.Little WordSize.Bit64 VCMPEQUWdot

  [<TestMethod>]
  member _.``[PPC T] VCMPGTSB original decoding``() =
    decode "10221b06" Endian.Big WordSize.Bit32 VCMPGTSB
    decode "10221b06" Endian.Big WordSize.Bit64 VCMPGTSB
    decode "061b2210" Endian.Little WordSize.Bit64 VCMPGTSB

  [<TestMethod>]
  member _.``[PPC T] VCMPGTSB. original decoding``() =
    decode "10221f06" Endian.Big WordSize.Bit32 VCMPGTSBdot
    decode "10221f06" Endian.Big WordSize.Bit64 VCMPGTSBdot
    decode "061f2210" Endian.Little WordSize.Bit64 VCMPGTSBdot

  [<TestMethod>]
  member _.``[PPC T] VCMPGTSD original decoding``() =
    decode "10221bc7" Endian.Big WordSize.Bit32 VCMPGTSD
    decode "10221bc7" Endian.Big WordSize.Bit64 VCMPGTSD
    decode "c71b2210" Endian.Little WordSize.Bit64 VCMPGTSD

  [<TestMethod>]
  member _.``[PPC T] VCMPGTSD. original decoding``() =
    decode "10221fc7" Endian.Big WordSize.Bit32 VCMPGTSDdot
    decode "10221fc7" Endian.Big WordSize.Bit64 VCMPGTSDdot
    decode "c71f2210" Endian.Little WordSize.Bit64 VCMPGTSDdot

  [<TestMethod>]
  member _.``[PPC T] VCMPGTSH original decoding``() =
    decode "10221b46" Endian.Big WordSize.Bit32 VCMPGTSH
    decode "10221b46" Endian.Big WordSize.Bit64 VCMPGTSH
    decode "461b2210" Endian.Little WordSize.Bit64 VCMPGTSH

  [<TestMethod>]
  member _.``[PPC T] VCMPGTSH. original decoding``() =
    decode "10221f46" Endian.Big WordSize.Bit32 VCMPGTSHdot
    decode "10221f46" Endian.Big WordSize.Bit64 VCMPGTSHdot
    decode "461f2210" Endian.Little WordSize.Bit64 VCMPGTSHdot

  [<TestMethod>]
  member _.``[PPC T] VCMPGTSW original decoding``() =
    decode "10221b86" Endian.Big WordSize.Bit32 VCMPGTSW
    decode "10221b86" Endian.Big WordSize.Bit64 VCMPGTSW
    decode "861b2210" Endian.Little WordSize.Bit64 VCMPGTSW

  [<TestMethod>]
  member _.``[PPC T] VCMPGTSW. original decoding``() =
    decode "10221f86" Endian.Big WordSize.Bit32 VCMPGTSWdot
    decode "10221f86" Endian.Big WordSize.Bit64 VCMPGTSWdot
    decode "861f2210" Endian.Little WordSize.Bit64 VCMPGTSWdot

  [<TestMethod>]
  member _.``[PPC T] VCMPGTUB original decoding``() =
    decode "10221a06" Endian.Big WordSize.Bit32 VCMPGTUB
    decode "10221a06" Endian.Big WordSize.Bit64 VCMPGTUB
    decode "061a2210" Endian.Little WordSize.Bit64 VCMPGTUB

  [<TestMethod>]
  member _.``[PPC T] VCMPGTUB. original decoding``() =
    decode "10221e06" Endian.Big WordSize.Bit32 VCMPGTUBdot
    decode "10221e06" Endian.Big WordSize.Bit64 VCMPGTUBdot
    decode "061e2210" Endian.Little WordSize.Bit64 VCMPGTUBdot

  [<TestMethod>]
  member _.``[PPC T] VCMPGTUD original decoding``() =
    decode "10221ac7" Endian.Big WordSize.Bit32 VCMPGTUD
    decode "10221ac7" Endian.Big WordSize.Bit64 VCMPGTUD
    decode "c71a2210" Endian.Little WordSize.Bit64 VCMPGTUD

  [<TestMethod>]
  member _.``[PPC T] VCMPGTUD. original decoding``() =
    decode "10221ec7" Endian.Big WordSize.Bit32 VCMPGTUDdot
    decode "10221ec7" Endian.Big WordSize.Bit64 VCMPGTUDdot
    decode "c71e2210" Endian.Little WordSize.Bit64 VCMPGTUDdot

  [<TestMethod>]
  member _.``[PPC T] VCMPGTUH original decoding``() =
    decode "10221a46" Endian.Big WordSize.Bit32 VCMPGTUH
    decode "10221a46" Endian.Big WordSize.Bit64 VCMPGTUH
    decode "461a2210" Endian.Little WordSize.Bit64 VCMPGTUH

  [<TestMethod>]
  member _.``[PPC T] VCMPGTUH. original decoding``() =
    decode "10221e46" Endian.Big WordSize.Bit32 VCMPGTUHdot
    decode "10221e46" Endian.Big WordSize.Bit64 VCMPGTUHdot
    decode "461e2210" Endian.Little WordSize.Bit64 VCMPGTUHdot

  [<TestMethod>]
  member _.``[PPC T] VCMPGTUW original decoding``() =
    decode "10221a86" Endian.Big WordSize.Bit32 VCMPGTUW
    decode "10221a86" Endian.Big WordSize.Bit64 VCMPGTUW
    decode "861a2210" Endian.Little WordSize.Bit64 VCMPGTUW

  [<TestMethod>]
  member _.``[PPC T] VCMPGTUW. original decoding``() =
    decode "10221e86" Endian.Big WordSize.Bit32 VCMPGTUWdot
    decode "10221e86" Endian.Big WordSize.Bit64 VCMPGTUWdot
    decode "861e2210" Endian.Little WordSize.Bit64 VCMPGTUWdot

  [<TestMethod>]
  member _.``[PPC T] VEQV original decoding``() =
    decode "10221e84" Endian.Big WordSize.Bit32 VEQV
    decode "10221e84" Endian.Big WordSize.Bit64 VEQV
    decode "841e2210" Endian.Little WordSize.Bit64 VEQV

  [<TestMethod>]
  member _.``[PPC T] VGBBD original decoding``() =
    decode "10201d0c" Endian.Big WordSize.Bit32 VGBBD
    decode "10201d0c" Endian.Big WordSize.Bit64 VGBBD
    decode "0c1d2010" Endian.Little WordSize.Bit64 VGBBD

  [<TestMethod>]
  member _.``[PPC T] VMAXSB original decoding``() =
    decode "10221902" Endian.Big WordSize.Bit32 VMAXSB
    decode "10221902" Endian.Big WordSize.Bit64 VMAXSB
    decode "02192210" Endian.Little WordSize.Bit64 VMAXSB

  [<TestMethod>]
  member _.``[PPC T] VMAXSD original decoding``() =
    decode "102219c2" Endian.Big WordSize.Bit32 VMAXSD
    decode "102219c2" Endian.Big WordSize.Bit64 VMAXSD
    decode "c2192210" Endian.Little WordSize.Bit64 VMAXSD

  [<TestMethod>]
  member _.``[PPC T] VMAXSH original decoding``() =
    decode "10221942" Endian.Big WordSize.Bit32 VMAXSH
    decode "10221942" Endian.Big WordSize.Bit64 VMAXSH
    decode "42192210" Endian.Little WordSize.Bit64 VMAXSH

  [<TestMethod>]
  member _.``[PPC T] VMAXSW original decoding``() =
    decode "10221982" Endian.Big WordSize.Bit32 VMAXSW
    decode "10221982" Endian.Big WordSize.Bit64 VMAXSW
    decode "82192210" Endian.Little WordSize.Bit64 VMAXSW

  [<TestMethod>]
  member _.``[PPC T] VMAXUB original decoding``() =
    decode "10221802" Endian.Big WordSize.Bit32 VMAXUB
    decode "10221802" Endian.Big WordSize.Bit64 VMAXUB
    decode "02182210" Endian.Little WordSize.Bit64 VMAXUB

  [<TestMethod>]
  member _.``[PPC T] VMAXUD original decoding``() =
    decode "102218c2" Endian.Big WordSize.Bit32 VMAXUD
    decode "102218c2" Endian.Big WordSize.Bit64 VMAXUD
    decode "c2182210" Endian.Little WordSize.Bit64 VMAXUD

  [<TestMethod>]
  member _.``[PPC T] VMAXUH original decoding``() =
    decode "10221842" Endian.Big WordSize.Bit32 VMAXUH
    decode "10221842" Endian.Big WordSize.Bit64 VMAXUH
    decode "42182210" Endian.Little WordSize.Bit64 VMAXUH

  [<TestMethod>]
  member _.``[PPC T] VMAXUW original decoding``() =
    decode "10221882" Endian.Big WordSize.Bit32 VMAXUW
    decode "10221882" Endian.Big WordSize.Bit64 VMAXUW
    decode "82182210" Endian.Little WordSize.Bit64 VMAXUW

  [<TestMethod>]
  member _.``[PPC T] VMINSB original decoding``() =
    decode "10221b02" Endian.Big WordSize.Bit32 VMINSB
    decode "10221b02" Endian.Big WordSize.Bit64 VMINSB
    decode "021b2210" Endian.Little WordSize.Bit64 VMINSB

  [<TestMethod>]
  member _.``[PPC T] VMINSD original decoding``() =
    decode "10221bc2" Endian.Big WordSize.Bit32 VMINSD
    decode "10221bc2" Endian.Big WordSize.Bit64 VMINSD
    decode "c21b2210" Endian.Little WordSize.Bit64 VMINSD

  [<TestMethod>]
  member _.``[PPC T] VMINSH original decoding``() =
    decode "10221b42" Endian.Big WordSize.Bit32 VMINSH
    decode "10221b42" Endian.Big WordSize.Bit64 VMINSH
    decode "421b2210" Endian.Little WordSize.Bit64 VMINSH

  [<TestMethod>]
  member _.``[PPC T] VMINSW original decoding``() =
    decode "10221b82" Endian.Big WordSize.Bit32 VMINSW
    decode "10221b82" Endian.Big WordSize.Bit64 VMINSW
    decode "821b2210" Endian.Little WordSize.Bit64 VMINSW

  [<TestMethod>]
  member _.``[PPC T] VMINUB original decoding``() =
    decode "10221a02" Endian.Big WordSize.Bit32 VMINUB
    decode "10221a02" Endian.Big WordSize.Bit64 VMINUB
    decode "021a2210" Endian.Little WordSize.Bit64 VMINUB

  [<TestMethod>]
  member _.``[PPC T] VMINUD original decoding``() =
    decode "10221ac2" Endian.Big WordSize.Bit32 VMINUD
    decode "10221ac2" Endian.Big WordSize.Bit64 VMINUD
    decode "c21a2210" Endian.Little WordSize.Bit64 VMINUD

  [<TestMethod>]
  member _.``[PPC T] VMINUH original decoding``() =
    decode "10221a42" Endian.Big WordSize.Bit32 VMINUH
    decode "10221a42" Endian.Big WordSize.Bit64 VMINUH
    decode "421a2210" Endian.Little WordSize.Bit64 VMINUH

  [<TestMethod>]
  member _.``[PPC T] VMINUW original decoding``() =
    decode "10221a82" Endian.Big WordSize.Bit32 VMINUW
    decode "10221a82" Endian.Big WordSize.Bit64 VMINUW
    decode "821a2210" Endian.Little WordSize.Bit64 VMINUW

  [<TestMethod>]
  member _.``[PPC T] VMRGEW original decoding``() =
    decode "10221f8c" Endian.Big WordSize.Bit32 VMRGEW
    decode "10221f8c" Endian.Big WordSize.Bit64 VMRGEW
    decode "8c1f2210" Endian.Little WordSize.Bit64 VMRGEW

  [<TestMethod>]
  member _.``[PPC T] VMRGHB original decoding``() =
    decode "1022180c" Endian.Big WordSize.Bit32 VMRGHB
    decode "1022180c" Endian.Big WordSize.Bit64 VMRGHB
    decode "0c182210" Endian.Little WordSize.Bit64 VMRGHB

  [<TestMethod>]
  member _.``[PPC T] VMRGHH original decoding``() =
    decode "1022184c" Endian.Big WordSize.Bit32 VMRGHH
    decode "1022184c" Endian.Big WordSize.Bit64 VMRGHH
    decode "4c182210" Endian.Little WordSize.Bit64 VMRGHH

  [<TestMethod>]
  member _.``[PPC T] VMRGHW original decoding``() =
    decode "1022188c" Endian.Big WordSize.Bit32 VMRGHW
    decode "1022188c" Endian.Big WordSize.Bit64 VMRGHW
    decode "8c182210" Endian.Little WordSize.Bit64 VMRGHW

  [<TestMethod>]
  member _.``[PPC T] VMRGLB original decoding``() =
    decode "1022190c" Endian.Big WordSize.Bit32 VMRGLB
    decode "1022190c" Endian.Big WordSize.Bit64 VMRGLB
    decode "0c192210" Endian.Little WordSize.Bit64 VMRGLB

  [<TestMethod>]
  member _.``[PPC T] VMRGLH original decoding``() =
    decode "1022194c" Endian.Big WordSize.Bit32 VMRGLH
    decode "1022194c" Endian.Big WordSize.Bit64 VMRGLH
    decode "4c192210" Endian.Little WordSize.Bit64 VMRGLH

  [<TestMethod>]
  member _.``[PPC T] VMRGLW original decoding``() =
    decode "1022198c" Endian.Big WordSize.Bit32 VMRGLW
    decode "1022198c" Endian.Big WordSize.Bit64 VMRGLW
    decode "8c192210" Endian.Little WordSize.Bit64 VMRGLW

  [<TestMethod>]
  member _.``[PPC T] VMRGOW original decoding``() =
    decode "10221e8c" Endian.Big WordSize.Bit32 VMRGOW
    decode "10221e8c" Endian.Big WordSize.Bit64 VMRGOW
    decode "8c1e2210" Endian.Little WordSize.Bit64 VMRGOW

  [<TestMethod>]
  member _.``[PPC T] VMULESW original decoding``() =
    decode "10221b88" Endian.Big WordSize.Bit32 VMULESW
    decode "10221b88" Endian.Big WordSize.Bit64 VMULESW
    decode "881b2210" Endian.Little WordSize.Bit64 VMULESW

  [<TestMethod>]
  member _.``[PPC T] VMULOSW original decoding``() =
    decode "10221988" Endian.Big WordSize.Bit32 VMULOSW
    decode "10221988" Endian.Big WordSize.Bit64 VMULOSW
    decode "88192210" Endian.Little WordSize.Bit64 VMULOSW

  [<TestMethod>]
  member _.``[PPC T] VMULUWM original decoding``() =
    decode "10221889" Endian.Big WordSize.Bit32 VMULUWM
    decode "10221889" Endian.Big WordSize.Bit64 VMULUWM
    decode "89182210" Endian.Little WordSize.Bit64 VMULUWM

  [<TestMethod>]
  member _.``[PPC T] VNAND original decoding``() =
    decode "10221d84" Endian.Big WordSize.Bit32 VNAND
    decode "10221d84" Endian.Big WordSize.Bit64 VNAND
    decode "841d2210" Endian.Little WordSize.Bit64 VNAND

  [<TestMethod>]
  member _.``[PPC T] VNOR original decoding``() =
    decode "10221d04" Endian.Big WordSize.Bit32 VNOR
    decode "10221d04" Endian.Big WordSize.Bit64 VNOR
    decode "041d2210" Endian.Little WordSize.Bit64 VNOR

  [<TestMethod>]
  member _.``[PPC T] VOR original decoding``() =
    decode "10221c84" Endian.Big WordSize.Bit32 VOR
    decode "10221c84" Endian.Big WordSize.Bit64 VOR
    decode "841c2210" Endian.Little WordSize.Bit64 VOR

  [<TestMethod>]
  member _.``[PPC T] VORC original decoding``() =
    decode "10221d44" Endian.Big WordSize.Bit32 VORC
    decode "10221d44" Endian.Big WordSize.Bit64 VORC
    decode "441d2210" Endian.Little WordSize.Bit64 VORC

  [<TestMethod>]
  member _.``[PPC T] VPERM original decoding``() =
    decode "1022192b" Endian.Big WordSize.Bit32 VPERM
    decode "1022192b" Endian.Big WordSize.Bit64 VPERM
    decode "2b192210" Endian.Little WordSize.Bit64 VPERM

  [<TestMethod>]
  member _.``[PPC T] VPKUHUM original decoding``() =
    decode "1022180e" Endian.Big WordSize.Bit32 VPKUHUM
    decode "1022180e" Endian.Big WordSize.Bit64 VPKUHUM
    decode "0e182210" Endian.Little WordSize.Bit64 VPKUHUM

  [<TestMethod>]
  member _.``[PPC T] VPKUWUM original decoding``() =
    decode "1022184e" Endian.Big WordSize.Bit32 VPKUWUM
    decode "1022184e" Endian.Big WordSize.Bit64 VPKUWUM
    decode "4e182210" Endian.Little WordSize.Bit64 VPKUWUM

  [<TestMethod>]
  member _.``[PPC T] VPOPCNTB original decoding``() =
    decode "10201f03" Endian.Big WordSize.Bit32 VPOPCNTB
    decode "10201f03" Endian.Big WordSize.Bit64 VPOPCNTB
    decode "031f2010" Endian.Little WordSize.Bit64 VPOPCNTB

  [<TestMethod>]
  member _.``[PPC T] VPOPCNTD original decoding``() =
    decode "10201fc3" Endian.Big WordSize.Bit32 VPOPCNTD
    decode "10201fc3" Endian.Big WordSize.Bit64 VPOPCNTD
    decode "c31f2010" Endian.Little WordSize.Bit64 VPOPCNTD

  [<TestMethod>]
  member _.``[PPC T] VPOPCNTH original decoding``() =
    decode "10201f43" Endian.Big WordSize.Bit32 VPOPCNTH
    decode "10201f43" Endian.Big WordSize.Bit64 VPOPCNTH
    decode "431f2010" Endian.Little WordSize.Bit64 VPOPCNTH

  [<TestMethod>]
  member _.``[PPC T] VPOPCNTW original decoding``() =
    decode "10201f83" Endian.Big WordSize.Bit32 VPOPCNTW
    decode "10201f83" Endian.Big WordSize.Bit64 VPOPCNTW
    decode "831f2010" Endian.Little WordSize.Bit64 VPOPCNTW

  [<TestMethod>]
  member _.``[PPC T] VRLB original decoding``() =
    decode "10221804" Endian.Big WordSize.Bit32 VRLB
    decode "10221804" Endian.Big WordSize.Bit64 VRLB
    decode "04182210" Endian.Little WordSize.Bit64 VRLB

  [<TestMethod>]
  member _.``[PPC T] VRLD original decoding``() =
    decode "102218c4" Endian.Big WordSize.Bit32 VRLD
    decode "102218c4" Endian.Big WordSize.Bit64 VRLD
    decode "c4182210" Endian.Little WordSize.Bit64 VRLD

  [<TestMethod>]
  member _.``[PPC T] VRLH original decoding``() =
    decode "10221844" Endian.Big WordSize.Bit32 VRLH
    decode "10221844" Endian.Big WordSize.Bit64 VRLH
    decode "44182210" Endian.Little WordSize.Bit64 VRLH

  [<TestMethod>]
  member _.``[PPC T] VRLW original decoding``() =
    decode "10221884" Endian.Big WordSize.Bit32 VRLW
    decode "10221884" Endian.Big WordSize.Bit64 VRLW
    decode "84182210" Endian.Little WordSize.Bit64 VRLW

  [<TestMethod>]
  member _.``[PPC T] VSEL original decoding``() =
    decode "1022192a" Endian.Big WordSize.Bit32 VSEL
    decode "1022192a" Endian.Big WordSize.Bit64 VSEL
    decode "2a192210" Endian.Little WordSize.Bit64 VSEL

  [<TestMethod>]
  member _.``[PPC T] VSL original decoding``() =
    decode "102219c4" Endian.Big WordSize.Bit32 VSL
    decode "102219c4" Endian.Big WordSize.Bit64 VSL
    decode "c4192210" Endian.Little WordSize.Bit64 VSL

  [<TestMethod>]
  member _.``[PPC T] VSLB original decoding``() =
    decode "10221904" Endian.Big WordSize.Bit32 VSLB
    decode "10221904" Endian.Big WordSize.Bit64 VSLB
    decode "04192210" Endian.Little WordSize.Bit64 VSLB

  [<TestMethod>]
  member _.``[PPC T] VSLD original decoding``() =
    decode "10221dc4" Endian.Big WordSize.Bit32 VSLD
    decode "10221dc4" Endian.Big WordSize.Bit64 VSLD
    decode "c41d2210" Endian.Little WordSize.Bit64 VSLD

  [<TestMethod>]
  member _.``[PPC T] VSLDOI original decoding``() =
    decode "102218ac" Endian.Big WordSize.Bit32 VSLDOI
    decode "102218ac" Endian.Big WordSize.Bit64 VSLDOI
    decode "ac182210" Endian.Little WordSize.Bit64 VSLDOI

  [<TestMethod>]
  member _.``[PPC T] VSLH original decoding``() =
    decode "10221944" Endian.Big WordSize.Bit32 VSLH
    decode "10221944" Endian.Big WordSize.Bit64 VSLH
    decode "44192210" Endian.Little WordSize.Bit64 VSLH

  [<TestMethod>]
  member _.``[PPC T] VSLO original decoding``() =
    decode "10221c0c" Endian.Big WordSize.Bit32 VSLO
    decode "10221c0c" Endian.Big WordSize.Bit64 VSLO
    decode "0c1c2210" Endian.Little WordSize.Bit64 VSLO

  [<TestMethod>]
  member _.``[PPC T] VSLW original decoding``() =
    decode "10221984" Endian.Big WordSize.Bit32 VSLW
    decode "10221984" Endian.Big WordSize.Bit64 VSLW
    decode "84192210" Endian.Little WordSize.Bit64 VSLW

  [<TestMethod>]
  member _.``[PPC T] VSPLTB original decoding``() =
    decode "10211a0c" Endian.Big WordSize.Bit32 VSPLTB
    decode "10211a0c" Endian.Big WordSize.Bit64 VSPLTB
    decode "0c1a2110" Endian.Little WordSize.Bit64 VSPLTB

  [<TestMethod>]
  member _.``[PPC T] VSPLTH original decoding``() =
    decode "10211a4c" Endian.Big WordSize.Bit32 VSPLTH
    decode "10211a4c" Endian.Big WordSize.Bit64 VSPLTH
    decode "4c1a2110" Endian.Little WordSize.Bit64 VSPLTH

  [<TestMethod>]
  member _.``[PPC T] VSPLTISB original decoding``() =
    decode "103d030c" Endian.Big WordSize.Bit32 VSPLTISB
    decode "103d030c" Endian.Big WordSize.Bit64 VSPLTISB
    decode "0c033d10" Endian.Little WordSize.Bit64 VSPLTISB

  [<TestMethod>]
  member _.``[PPC T] VSPLTISH original decoding``() =
    decode "103d034c" Endian.Big WordSize.Bit32 VSPLTISH
    decode "103d034c" Endian.Big WordSize.Bit64 VSPLTISH
    decode "4c033d10" Endian.Little WordSize.Bit64 VSPLTISH

  [<TestMethod>]
  member _.``[PPC T] VSPLTISW original decoding``() =
    decode "103d038c" Endian.Big WordSize.Bit32 VSPLTISW
    decode "103d038c" Endian.Big WordSize.Bit64 VSPLTISW
    decode "8c033d10" Endian.Little WordSize.Bit64 VSPLTISW

  [<TestMethod>]
  member _.``[PPC T] VSPLTW original decoding``() =
    decode "10211a8c" Endian.Big WordSize.Bit32 VSPLTW
    decode "10211a8c" Endian.Big WordSize.Bit64 VSPLTW
    decode "8c1a2110" Endian.Little WordSize.Bit64 VSPLTW

  [<TestMethod>]
  member _.``[PPC T] VSRAB original decoding``() =
    decode "10221b04" Endian.Big WordSize.Bit32 VSRAB
    decode "10221b04" Endian.Big WordSize.Bit64 VSRAB
    decode "041b2210" Endian.Little WordSize.Bit64 VSRAB

  [<TestMethod>]
  member _.``[PPC T] VSRAD original decoding``() =
    decode "10221bc4" Endian.Big WordSize.Bit32 VSRAD
    decode "10221bc4" Endian.Big WordSize.Bit64 VSRAD
    decode "c41b2210" Endian.Little WordSize.Bit64 VSRAD

  [<TestMethod>]
  member _.``[PPC T] VSRAH original decoding``() =
    decode "10221b44" Endian.Big WordSize.Bit32 VSRAH
    decode "10221b44" Endian.Big WordSize.Bit64 VSRAH
    decode "441b2210" Endian.Little WordSize.Bit64 VSRAH

  [<TestMethod>]
  member _.``[PPC T] VSRAW original decoding``() =
    decode "10221b84" Endian.Big WordSize.Bit32 VSRAW
    decode "10221b84" Endian.Big WordSize.Bit64 VSRAW
    decode "841b2210" Endian.Little WordSize.Bit64 VSRAW

  [<TestMethod>]
  member _.``[PPC T] VSRB original decoding``() =
    decode "10221a04" Endian.Big WordSize.Bit32 VSRB
    decode "10221a04" Endian.Big WordSize.Bit64 VSRB
    decode "041a2210" Endian.Little WordSize.Bit64 VSRB

  [<TestMethod>]
  member _.``[PPC T] VSRD original decoding``() =
    decode "10221ec4" Endian.Big WordSize.Bit32 VSRD
    decode "10221ec4" Endian.Big WordSize.Bit64 VSRD
    decode "c41e2210" Endian.Little WordSize.Bit64 VSRD

  [<TestMethod>]
  member _.``[PPC T] VSRH original decoding``() =
    decode "10221a44" Endian.Big WordSize.Bit32 VSRH
    decode "10221a44" Endian.Big WordSize.Bit64 VSRH
    decode "441a2210" Endian.Little WordSize.Bit64 VSRH

  [<TestMethod>]
  member _.``[PPC T] VSRO original decoding``() =
    decode "10221c4c" Endian.Big WordSize.Bit32 VSRO
    decode "10221c4c" Endian.Big WordSize.Bit64 VSRO
    decode "4c1c2210" Endian.Little WordSize.Bit64 VSRO

  [<TestMethod>]
  member _.``[PPC T] VSRW original decoding``() =
    decode "10221a84" Endian.Big WordSize.Bit32 VSRW
    decode "10221a84" Endian.Big WordSize.Bit64 VSRW
    decode "841a2210" Endian.Little WordSize.Bit64 VSRW

  [<TestMethod>]
  member _.``[PPC T] VSUBUBM original decoding``() =
    decode "10221c00" Endian.Big WordSize.Bit32 VSUBUBM
    decode "10221c00" Endian.Big WordSize.Bit64 VSUBUBM
    decode "001c2210" Endian.Little WordSize.Bit64 VSUBUBM

  [<TestMethod>]
  member _.``[PPC T] VSUBUBS original decoding``() =
    decode "10221e00" Endian.Big WordSize.Bit32 VSUBUBS
    decode "10221e00" Endian.Big WordSize.Bit64 VSUBUBS
    decode "001e2210" Endian.Little WordSize.Bit64 VSUBUBS

  [<TestMethod>]
  member _.``[PPC T] VSUBUDM original decoding``() =
    decode "10221cc0" Endian.Big WordSize.Bit32 VSUBUDM
    decode "10221cc0" Endian.Big WordSize.Bit64 VSUBUDM
    decode "c01c2210" Endian.Little WordSize.Bit64 VSUBUDM

  [<TestMethod>]
  member _.``[PPC T] VSUBUHM original decoding``() =
    decode "10221c40" Endian.Big WordSize.Bit32 VSUBUHM
    decode "10221c40" Endian.Big WordSize.Bit64 VSUBUHM
    decode "401c2210" Endian.Little WordSize.Bit64 VSUBUHM

  [<TestMethod>]
  member _.``[PPC T] VSUBUWM original decoding``() =
    decode "10221c80" Endian.Big WordSize.Bit32 VSUBUWM
    decode "10221c80" Endian.Big WordSize.Bit64 VSUBUWM
    decode "801c2210" Endian.Little WordSize.Bit64 VSUBUWM

  [<TestMethod>]
  member _.``[PPC T] VUPKHSB original decoding``() =
    decode "10201a0e" Endian.Big WordSize.Bit32 VUPKHSB
    decode "10201a0e" Endian.Big WordSize.Bit64 VUPKHSB
    decode "0e1a2010" Endian.Little WordSize.Bit64 VUPKHSB

  [<TestMethod>]
  member _.``[PPC T] VUPKHSH original decoding``() =
    decode "10201a4e" Endian.Big WordSize.Bit32 VUPKHSH
    decode "10201a4e" Endian.Big WordSize.Bit64 VUPKHSH
    decode "4e1a2010" Endian.Little WordSize.Bit64 VUPKHSH

  [<TestMethod>]
  member _.``[PPC T] VUPKHSW original decoding``() =
    decode "10201e4e" Endian.Big WordSize.Bit32 VUPKHSW
    decode "10201e4e" Endian.Big WordSize.Bit64 VUPKHSW
    decode "4e1e2010" Endian.Little WordSize.Bit64 VUPKHSW

  [<TestMethod>]
  member _.``[PPC T] VUPKLSB original decoding``() =
    decode "10201a8e" Endian.Big WordSize.Bit32 VUPKLSB
    decode "10201a8e" Endian.Big WordSize.Bit64 VUPKLSB
    decode "8e1a2010" Endian.Little WordSize.Bit64 VUPKLSB

  [<TestMethod>]
  member _.``[PPC T] VUPKLSH original decoding``() =
    decode "10201ace" Endian.Big WordSize.Bit32 VUPKLSH
    decode "10201ace" Endian.Big WordSize.Bit64 VUPKLSH
    decode "ce1a2010" Endian.Little WordSize.Bit64 VUPKLSH

  [<TestMethod>]
  member _.``[PPC T] VUPKLSW original decoding``() =
    decode "10201ece" Endian.Big WordSize.Bit32 VUPKLSW
    decode "10201ece" Endian.Big WordSize.Bit64 VUPKLSW
    decode "ce1e2010" Endian.Little WordSize.Bit64 VUPKLSW

  [<TestMethod>]
  member _.``[PPC T] XOR. original decoding``() =
    decode "7d063a79" Endian.Big WordSize.Bit32 XORdot
    decode "7d063a79" Endian.Big WordSize.Bit64 XORdot
    decode "793a067d" Endian.Little WordSize.Bit64 XORdot

  [<TestMethod>]
  member _.``[PPC T] XORI original decoding``() =
    decode "69060055" Endian.Big WordSize.Bit32 XORI
    decode "69060055" Endian.Big WordSize.Bit64 XORI
    decode "55000669" Endian.Little WordSize.Bit64 XORI

  [<TestMethod>]
  member _.``[PPC T] XORIS original decoding``() =
    decode "6d060055" Endian.Big WordSize.Bit32 XORIS
    decode "6d060055" Endian.Big WordSize.Bit64 XORIS
    decode "5500066d" Endian.Little WordSize.Bit64 XORIS

  [<TestMethod>]
  member _.``[PPC T] XSABSDP original decoding``() =
    decode "f0201d64" Endian.Big WordSize.Bit32 XSABSDP
    decode "f0201d64" Endian.Big WordSize.Bit64 XSABSDP
    decode "641d20f0" Endian.Little WordSize.Bit64 XSABSDP

  [<TestMethod>]
  member _.``[PPC T] XSADDDP original decoding``() =
    decode "f0221900" Endian.Big WordSize.Bit32 XSADDDP
    decode "f0221900" Endian.Big WordSize.Bit64 XSADDDP
    decode "001922f0" Endian.Little WordSize.Bit64 XSADDDP

  [<TestMethod>]
  member _.``[PPC T] XSADDSP original decoding``() =
    decode "f0221800" Endian.Big WordSize.Bit32 XSADDSP
    decode "f0221800" Endian.Big WordSize.Bit64 XSADDSP
    decode "001822f0" Endian.Little WordSize.Bit64 XSADDSP

  [<TestMethod>]
  member _.``[PPC T] XSCMPUDP original decoding``() =
    decode "f1021918" Endian.Big WordSize.Bit32 XSCMPUDP
    decode "f1021918" Endian.Big WordSize.Bit64 XSCMPUDP
    decode "181902f1" Endian.Little WordSize.Bit64 XSCMPUDP

  [<TestMethod>]
  member _.``[PPC T] XSCPSGNDP original decoding``() =
    decode "f0221d80" Endian.Big WordSize.Bit32 XSCPSGNDP
    decode "f0221d80" Endian.Big WordSize.Bit64 XSCPSGNDP
    decode "801d22f0" Endian.Little WordSize.Bit64 XSCPSGNDP

  [<TestMethod>]
  member _.``[PPC T] XSCVDPSP original decoding``() =
    decode "f0201c24" Endian.Big WordSize.Bit32 XSCVDPSP
    decode "f0201c24" Endian.Big WordSize.Bit64 XSCVDPSP
    decode "241c20f0" Endian.Little WordSize.Bit64 XSCVDPSP

  [<TestMethod>]
  member _.``[PPC T] XSCVDPSPN original decoding``() =
    decode "f0201c2c" Endian.Big WordSize.Bit32 XSCVDPSPN
    decode "f0201c2c" Endian.Big WordSize.Bit64 XSCVDPSPN
    decode "2c1c20f0" Endian.Little WordSize.Bit64 XSCVDPSPN

  [<TestMethod>]
  member _.``[PPC T] XSCVDPSXDS original decoding``() =
    decode "f0201d60" Endian.Big WordSize.Bit32 XSCVDPSXDS
    decode "f0201d60" Endian.Big WordSize.Bit64 XSCVDPSXDS
    decode "601d20f0" Endian.Little WordSize.Bit64 XSCVDPSXDS

  [<TestMethod>]
  member _.``[PPC T] XSCVDPSXWS original decoding``() =
    decode "f0201960" Endian.Big WordSize.Bit32 XSCVDPSXWS
    decode "f0201960" Endian.Big WordSize.Bit64 XSCVDPSXWS
    decode "601920f0" Endian.Little WordSize.Bit64 XSCVDPSXWS

  [<TestMethod>]
  member _.``[PPC T] XSCVDPUXDS original decoding``() =
    decode "f0201d20" Endian.Big WordSize.Bit32 XSCVDPUXDS
    decode "f0201d20" Endian.Big WordSize.Bit64 XSCVDPUXDS
    decode "201d20f0" Endian.Little WordSize.Bit64 XSCVDPUXDS

  [<TestMethod>]
  member _.``[PPC T] XSCVDPUXWS original decoding``() =
    decode "f0201920" Endian.Big WordSize.Bit32 XSCVDPUXWS
    decode "f0201920" Endian.Big WordSize.Bit64 XSCVDPUXWS
    decode "201920f0" Endian.Little WordSize.Bit64 XSCVDPUXWS

  [<TestMethod>]
  member _.``[PPC T] XSCVSPDP original decoding``() =
    decode "f0201d24" Endian.Big WordSize.Bit32 XSCVSPDP
    decode "f0201d24" Endian.Big WordSize.Bit64 XSCVSPDP
    decode "241d20f0" Endian.Little WordSize.Bit64 XSCVSPDP

  [<TestMethod>]
  member _.``[PPC T] XSCVSPDPN original decoding``() =
    decode "f0201d2c" Endian.Big WordSize.Bit32 XSCVSPDPN
    decode "f0201d2c" Endian.Big WordSize.Bit64 XSCVSPDPN
    decode "2c1d20f0" Endian.Little WordSize.Bit64 XSCVSPDPN

  [<TestMethod>]
  member _.``[PPC T] XSCVSXDDP original decoding``() =
    decode "f0201de0" Endian.Big WordSize.Bit32 XSCVSXDDP
    decode "f0201de0" Endian.Big WordSize.Bit64 XSCVSXDDP
    decode "e01d20f0" Endian.Little WordSize.Bit64 XSCVSXDDP

  [<TestMethod>]
  member _.``[PPC T] XSCVSXDSP original decoding``() =
    decode "f0201ce0" Endian.Big WordSize.Bit32 XSCVSXDSP
    decode "f0201ce0" Endian.Big WordSize.Bit64 XSCVSXDSP
    decode "e01c20f0" Endian.Little WordSize.Bit64 XSCVSXDSP

  [<TestMethod>]
  member _.``[PPC T] XSCVUXDDP original decoding``() =
    decode "f0201da0" Endian.Big WordSize.Bit32 XSCVUXDDP
    decode "f0201da0" Endian.Big WordSize.Bit64 XSCVUXDDP
    decode "a01d20f0" Endian.Little WordSize.Bit64 XSCVUXDDP

  [<TestMethod>]
  member _.``[PPC T] XSCVUXDSP original decoding``() =
    decode "f0201ca0" Endian.Big WordSize.Bit32 XSCVUXDSP
    decode "f0201ca0" Endian.Big WordSize.Bit64 XSCVUXDSP
    decode "a01c20f0" Endian.Little WordSize.Bit64 XSCVUXDSP

  [<TestMethod>]
  member _.``[PPC T] XSDIVDP original decoding``() =
    decode "f02219c0" Endian.Big WordSize.Bit32 XSDIVDP
    decode "f02219c0" Endian.Big WordSize.Bit64 XSDIVDP
    decode "c01922f0" Endian.Little WordSize.Bit64 XSDIVDP

  [<TestMethod>]
  member _.``[PPC T] XSDIVSP original decoding``() =
    decode "f02218c0" Endian.Big WordSize.Bit32 XSDIVSP
    decode "f02218c0" Endian.Big WordSize.Bit64 XSDIVSP
    decode "c01822f0" Endian.Little WordSize.Bit64 XSDIVSP

  [<TestMethod>]
  member _.``[PPC T] XSMADDADP original decoding``() =
    decode "f0221908" Endian.Big WordSize.Bit32 XSMADDADP
    decode "f0221908" Endian.Big WordSize.Bit64 XSMADDADP
    decode "081922f0" Endian.Little WordSize.Bit64 XSMADDADP

  [<TestMethod>]
  member _.``[PPC T] XSMADDASP original decoding``() =
    decode "f0221808" Endian.Big WordSize.Bit32 XSMADDASP
    decode "f0221808" Endian.Big WordSize.Bit64 XSMADDASP
    decode "081822f0" Endian.Little WordSize.Bit64 XSMADDASP

  [<TestMethod>]
  member _.``[PPC T] XSMADDMDP original decoding``() =
    decode "f0221948" Endian.Big WordSize.Bit32 XSMADDMDP
    decode "f0221948" Endian.Big WordSize.Bit64 XSMADDMDP
    decode "481922f0" Endian.Little WordSize.Bit64 XSMADDMDP

  [<TestMethod>]
  member _.``[PPC T] XSMADDMSP original decoding``() =
    decode "f0221848" Endian.Big WordSize.Bit32 XSMADDMSP
    decode "f0221848" Endian.Big WordSize.Bit64 XSMADDMSP
    decode "481822f0" Endian.Little WordSize.Bit64 XSMADDMSP

  [<TestMethod>]
  member _.``[PPC T] XSMAXDP original decoding``() =
    decode "f0221d00" Endian.Big WordSize.Bit32 XSMAXDP
    decode "f0221d00" Endian.Big WordSize.Bit64 XSMAXDP
    decode "001d22f0" Endian.Little WordSize.Bit64 XSMAXDP

  [<TestMethod>]
  member _.``[PPC T] XSMINDP original decoding``() =
    decode "f0221d40" Endian.Big WordSize.Bit32 XSMINDP
    decode "f0221d40" Endian.Big WordSize.Bit64 XSMINDP
    decode "401d22f0" Endian.Little WordSize.Bit64 XSMINDP

  [<TestMethod>]
  member _.``[PPC T] XSMULDP original decoding``() =
    decode "f0221980" Endian.Big WordSize.Bit32 XSMULDP
    decode "f0221980" Endian.Big WordSize.Bit64 XSMULDP
    decode "801922f0" Endian.Little WordSize.Bit64 XSMULDP

  [<TestMethod>]
  member _.``[PPC T] XSMULSP original decoding``() =
    decode "f0221880" Endian.Big WordSize.Bit32 XSMULSP
    decode "f0221880" Endian.Big WordSize.Bit64 XSMULSP
    decode "801822f0" Endian.Little WordSize.Bit64 XSMULSP

  [<TestMethod>]
  member _.``[PPC T] XSMSUBADP original decoding``() =
    decode "f0221988" Endian.Big WordSize.Bit32 XSMSUBADP
    decode "f0221988" Endian.Big WordSize.Bit64 XSMSUBADP
    decode "881922f0" Endian.Little WordSize.Bit64 XSMSUBADP

  [<TestMethod>]
  member _.``[PPC T] XSMSUBASP original decoding``() =
    decode "f0221888" Endian.Big WordSize.Bit32 XSMSUBASP
    decode "f0221888" Endian.Big WordSize.Bit64 XSMSUBASP
    decode "881822f0" Endian.Little WordSize.Bit64 XSMSUBASP

  [<TestMethod>]
  member _.``[PPC T] XSMSUBMDP original decoding``() =
    decode "f02219c8" Endian.Big WordSize.Bit32 XSMSUBMDP
    decode "f02219c8" Endian.Big WordSize.Bit64 XSMSUBMDP
    decode "c81922f0" Endian.Little WordSize.Bit64 XSMSUBMDP

  [<TestMethod>]
  member _.``[PPC T] XSMSUBMSP original decoding``() =
    decode "f02218c8" Endian.Big WordSize.Bit32 XSMSUBMSP
    decode "f02218c8" Endian.Big WordSize.Bit64 XSMSUBMSP
    decode "c81822f0" Endian.Little WordSize.Bit64 XSMSUBMSP

  [<TestMethod>]
  member _.``[PPC T] XSNABSDP original decoding``() =
    decode "f0201da4" Endian.Big WordSize.Bit32 XSNABSDP
    decode "f0201da4" Endian.Big WordSize.Bit64 XSNABSDP
    decode "a41d20f0" Endian.Little WordSize.Bit64 XSNABSDP

  [<TestMethod>]
  member _.``[PPC T] XSNEGDP original decoding``() =
    decode "f0201de4" Endian.Big WordSize.Bit32 XSNEGDP
    decode "f0201de4" Endian.Big WordSize.Bit64 XSNEGDP
    decode "e41d20f0" Endian.Little WordSize.Bit64 XSNEGDP

  [<TestMethod>]
  member _.``[PPC T] XSNMADDADP original decoding``() =
    decode "f0221d08" Endian.Big WordSize.Bit32 XSNMADDADP
    decode "f0221d08" Endian.Big WordSize.Bit64 XSNMADDADP
    decode "081d22f0" Endian.Little WordSize.Bit64 XSNMADDADP

  [<TestMethod>]
  member _.``[PPC T] XSNMADDASP original decoding``() =
    decode "f0221c08" Endian.Big WordSize.Bit32 XSNMADDASP
    decode "f0221c08" Endian.Big WordSize.Bit64 XSNMADDASP
    decode "081c22f0" Endian.Little WordSize.Bit64 XSNMADDASP

  [<TestMethod>]
  member _.``[PPC T] XSNMADDMDP original decoding``() =
    decode "f0221d48" Endian.Big WordSize.Bit32 XSNMADDMDP
    decode "f0221d48" Endian.Big WordSize.Bit64 XSNMADDMDP
    decode "481d22f0" Endian.Little WordSize.Bit64 XSNMADDMDP

  [<TestMethod>]
  member _.``[PPC T] XSNMADDMSP original decoding``() =
    decode "f0221c48" Endian.Big WordSize.Bit32 XSNMADDMSP
    decode "f0221c48" Endian.Big WordSize.Bit64 XSNMADDMSP
    decode "481c22f0" Endian.Little WordSize.Bit64 XSNMADDMSP

  [<TestMethod>]
  member _.``[PPC T] XSNMSUBADP original decoding``() =
    decode "f0221d88" Endian.Big WordSize.Bit32 XSNMSUBADP
    decode "f0221d88" Endian.Big WordSize.Bit64 XSNMSUBADP
    decode "881d22f0" Endian.Little WordSize.Bit64 XSNMSUBADP

  [<TestMethod>]
  member _.``[PPC T] XSNMSUBASP original decoding``() =
    decode "f0221c88" Endian.Big WordSize.Bit32 XSNMSUBASP
    decode "f0221c88" Endian.Big WordSize.Bit64 XSNMSUBASP
    decode "881c22f0" Endian.Little WordSize.Bit64 XSNMSUBASP

  [<TestMethod>]
  member _.``[PPC T] XSNMSUBMDP original decoding``() =
    decode "f0221dc8" Endian.Big WordSize.Bit32 XSNMSUBMDP
    decode "f0221dc8" Endian.Big WordSize.Bit64 XSNMSUBMDP
    decode "c81d22f0" Endian.Little WordSize.Bit64 XSNMSUBMDP

  [<TestMethod>]
  member _.``[PPC T] XSNMSUBMSP original decoding``() =
    decode "f0221cc8" Endian.Big WordSize.Bit32 XSNMSUBMSP
    decode "f0221cc8" Endian.Big WordSize.Bit64 XSNMSUBMSP
    decode "c81c22f0" Endian.Little WordSize.Bit64 XSNMSUBMSP

  [<TestMethod>]
  member _.``[PPC T] XSRDPI original decoding``() =
    decode "f0201924" Endian.Big WordSize.Bit32 XSRDPI
    decode "f0201924" Endian.Big WordSize.Bit64 XSRDPI
    decode "241920f0" Endian.Little WordSize.Bit64 XSRDPI

  [<TestMethod>]
  member _.``[PPC T] XSRDPIM original decoding``() =
    decode "f02019e4" Endian.Big WordSize.Bit32 XSRDPIM
    decode "f02019e4" Endian.Big WordSize.Bit64 XSRDPIM
    decode "e41920f0" Endian.Little WordSize.Bit64 XSRDPIM

  [<TestMethod>]
  member _.``[PPC T] XSRDPIP original decoding``() =
    decode "f02019a4" Endian.Big WordSize.Bit32 XSRDPIP
    decode "f02019a4" Endian.Big WordSize.Bit64 XSRDPIP
    decode "a41920f0" Endian.Little WordSize.Bit64 XSRDPIP

  [<TestMethod>]
  member _.``[PPC T] XSRDPIZ original decoding``() =
    decode "f0201964" Endian.Big WordSize.Bit32 XSRDPIZ
    decode "f0201964" Endian.Big WordSize.Bit64 XSRDPIZ
    decode "641920f0" Endian.Little WordSize.Bit64 XSRDPIZ

  [<TestMethod>]
  member _.``[PPC T] XSSQRTDP original decoding``() =
    decode "f020192c" Endian.Big WordSize.Bit32 XSSQRTDP
    decode "f020192c" Endian.Big WordSize.Bit64 XSSQRTDP
    decode "2c1920f0" Endian.Little WordSize.Bit64 XSSQRTDP

  [<TestMethod>]
  member _.``[PPC T] XSSQRTSP original decoding``() =
    decode "f020182c" Endian.Big WordSize.Bit32 XSSQRTSP
    decode "f020182c" Endian.Big WordSize.Bit64 XSSQRTSP
    decode "2c1820f0" Endian.Little WordSize.Bit64 XSSQRTSP

  [<TestMethod>]
  member _.``[PPC T] XSRSP original decoding``() =
    decode "f0201c64" Endian.Big WordSize.Bit32 XSRSP
    decode "f0201c64" Endian.Big WordSize.Bit64 XSRSP
    decode "641c20f0" Endian.Little WordSize.Bit64 XSRSP

  [<TestMethod>]
  member _.``[PPC T] XSSUBDP original decoding``() =
    decode "f0221940" Endian.Big WordSize.Bit32 XSSUBDP
    decode "f0221940" Endian.Big WordSize.Bit64 XSSUBDP
    decode "401922f0" Endian.Little WordSize.Bit64 XSSUBDP

  [<TestMethod>]
  member _.``[PPC T] XSSUBSP original decoding``() =
    decode "f0221840" Endian.Big WordSize.Bit32 XSSUBSP
    decode "f0221840" Endian.Big WordSize.Bit64 XSSUBSP
    decode "401822f0" Endian.Little WordSize.Bit64 XSSUBSP

  [<TestMethod>]
  member _.``[PPC T] XVADDDP original decoding``() =
    decode "f0221b00" Endian.Big WordSize.Bit32 XVADDDP
    decode "f0221b00" Endian.Big WordSize.Bit64 XVADDDP
    decode "001b22f0" Endian.Little WordSize.Bit64 XVADDDP

  [<TestMethod>]
  member _.``[PPC T] XVCMPGEDP original decoding``() =
    decode "f0221b98" Endian.Big WordSize.Bit32 XVCMPGEDP
    decode "f0221b98" Endian.Big WordSize.Bit64 XVCMPGEDP
    decode "981b22f0" Endian.Little WordSize.Bit64 XVCMPGEDP

  [<TestMethod>]
  member _.``[PPC T] XVCMPGEDP. original decoding``() =
    decode "f0221f98" Endian.Big WordSize.Bit32 XVCMPGEDPdot
    decode "f0221f98" Endian.Big WordSize.Bit64 XVCMPGEDPdot
    decode "981f22f0" Endian.Little WordSize.Bit64 XVCMPGEDPdot

  [<TestMethod>]
  member _.``[PPC T] XVCMPGTDP original decoding``() =
    decode "f0221b58" Endian.Big WordSize.Bit32 XVCMPGTDP
    decode "f0221b58" Endian.Big WordSize.Bit64 XVCMPGTDP
    decode "581b22f0" Endian.Little WordSize.Bit64 XVCMPGTDP

  [<TestMethod>]
  member _.``[PPC T] XVCMPGTDP. original decoding``() =
    decode "f0221f58" Endian.Big WordSize.Bit32 XVCMPGTDPdot
    decode "f0221f58" Endian.Big WordSize.Bit64 XVCMPGTDPdot
    decode "581f22f0" Endian.Little WordSize.Bit64 XVCMPGTDPdot

  [<TestMethod>]
  member _.``[PPC T] XVCVSXWDP original decoding``() =
    decode "f0201be0" Endian.Big WordSize.Bit32 XVCVSXWDP
    decode "f0201be0" Endian.Big WordSize.Bit64 XVCVSXWDP
    decode "e01b20f0" Endian.Little WordSize.Bit64 XVCVSXWDP

  [<TestMethod>]
  member _.``[PPC T] XVDIVDP original decoding``() =
    decode "f0221bc0" Endian.Big WordSize.Bit32 XVDIVDP
    decode "f0221bc0" Endian.Big WordSize.Bit64 XVDIVDP
    decode "c01b22f0" Endian.Little WordSize.Bit64 XVDIVDP

  [<TestMethod>]
  member _.``[PPC T] XVMULDP original decoding``() =
    decode "f0221b80" Endian.Big WordSize.Bit32 XVMULDP
    decode "f0221b80" Endian.Big WordSize.Bit64 XVMULDP
    decode "801b22f0" Endian.Little WordSize.Bit64 XVMULDP

  [<TestMethod>]
  member _.``[PPC T] XVNEGDP original decoding``() =
    decode "f0201fe4" Endian.Big WordSize.Bit32 XVNEGDP
    decode "f0201fe4" Endian.Big WordSize.Bit64 XVNEGDP
    decode "e41f20f0" Endian.Little WordSize.Bit64 XVNEGDP

  [<TestMethod>]
  member _.``[PPC T] XVSUBDP original decoding``() =
    decode "f0221b40" Endian.Big WordSize.Bit32 XVSUBDP
    decode "f0221b40" Endian.Big WordSize.Bit64 XVSUBDP
    decode "401b22f0" Endian.Little WordSize.Bit64 XVSUBDP

  [<TestMethod>]
  member _.``[PPC T] XXLAND original decoding``() =
    decode "f0221c10" Endian.Big WordSize.Bit32 XXLAND
    decode "f0221c10" Endian.Big WordSize.Bit64 XXLAND
    decode "101c22f0" Endian.Little WordSize.Bit64 XXLAND

  [<TestMethod>]
  member _.``[PPC T] XXLANDC original decoding``() =
    decode "f0221c50" Endian.Big WordSize.Bit32 XXLANDC
    decode "f0221c50" Endian.Big WordSize.Bit64 XXLANDC
    decode "501c22f0" Endian.Little WordSize.Bit64 XXLANDC

  [<TestMethod>]
  member _.``[PPC T] XXLEQV original decoding``() =
    decode "f0221dd0" Endian.Big WordSize.Bit32 XXLEQV
    decode "f0221dd0" Endian.Big WordSize.Bit64 XXLEQV
    decode "d01d22f0" Endian.Little WordSize.Bit64 XXLEQV

  [<TestMethod>]
  member _.``[PPC T] XXLNAND original decoding``() =
    decode "f0221d90" Endian.Big WordSize.Bit32 XXLNAND
    decode "f0221d90" Endian.Big WordSize.Bit64 XXLNAND
    decode "901d22f0" Endian.Little WordSize.Bit64 XXLNAND

  [<TestMethod>]
  member _.``[PPC T] XXLNOR original decoding``() =
    decode "f0221d10" Endian.Big WordSize.Bit32 XXLNOR
    decode "f0221d10" Endian.Big WordSize.Bit64 XXLNOR
    decode "101d22f0" Endian.Little WordSize.Bit64 XXLNOR

  [<TestMethod>]
  member _.``[PPC T] XXLOR original decoding``() =
    decode "f0221c90" Endian.Big WordSize.Bit32 XXLOR
    decode "f0221c90" Endian.Big WordSize.Bit64 XXLOR
    decode "901c22f0" Endian.Little WordSize.Bit64 XXLOR

  [<TestMethod>]
  member _.``[PPC T] XXLORC original decoding``() =
    decode "f0221d50" Endian.Big WordSize.Bit32 XXLORC
    decode "f0221d50" Endian.Big WordSize.Bit64 XXLORC
    decode "501d22f0" Endian.Little WordSize.Bit64 XXLORC

  [<TestMethod>]
  member _.``[PPC T] XXLXOR original decoding``() =
    decode "f0221cd0" Endian.Big WordSize.Bit32 XXLXOR
    decode "f0221cd0" Endian.Big WordSize.Bit64 XXLXOR
    decode "d01c22f0" Endian.Little WordSize.Bit64 XXLXOR

  [<TestMethod>]
  member _.``[PPC T] XXMRGHW original decoding``() =
    decode "f0221890" Endian.Big WordSize.Bit32 XXMRGHW
    decode "f0221890" Endian.Big WordSize.Bit64 XXMRGHW
    decode "901822f0" Endian.Little WordSize.Bit64 XXMRGHW

  [<TestMethod>]
  member _.``[PPC T] XXMRGLW original decoding``() =
    decode "f0221990" Endian.Big WordSize.Bit32 XXMRGLW
    decode "f0221990" Endian.Big WordSize.Bit64 XXMRGLW
    decode "901922f0" Endian.Little WordSize.Bit64 XXMRGLW

  [<TestMethod>]
  member _.``[PPC T] XXPERMDI original decoding``() =
    decode "f0221950" Endian.Big WordSize.Bit32 XXPERMDI
    decode "f0221950" Endian.Big WordSize.Bit64 XXPERMDI
    decode "501922f0" Endian.Little WordSize.Bit64 XXPERMDI

  [<TestMethod>]
  member _.``[PPC T] XXSEL original decoding``() =
    decode "f0221930" Endian.Big WordSize.Bit32 XXSEL
    decode "f0221930" Endian.Big WordSize.Bit64 XXSEL
    decode "301922f0" Endian.Little WordSize.Bit64 XXSEL

  [<TestMethod>]
  member _.``[PPC T] XXSLDWI original decoding``() =
    decode "f0221910" Endian.Big WordSize.Bit32 XXSLDWI
    decode "f0221910" Endian.Big WordSize.Bit64 XXSLDWI
    decode "101922f0" Endian.Little WordSize.Bit64 XXSLDWI

  [<TestMethod>]
  member _.``[PPC T] XXSPLTW original decoding``() =
    decode "f0211a90" Endian.Big WordSize.Bit32 XXSPLTW
    decode "f0211a90" Endian.Big WordSize.Bit64 XXSPLTW
    decode "901a21f0" Endian.Little WordSize.Bit64 XXSPLTW

/// GNU aliases that the decoder itself returns as distinct opcodes.
[<TestClass>]
type BackfillAliasParserTests() =
  let decode hex opcode =
    for endian in [ Endian.Big; Endian.Little ] do
      let parser = Parser(WordSize.Bit64, BinReader.Init endian)
                   :> IInstructionParsable
      let bytes = ByteArray.ofHexString hex
      let bytes = if endian = Endian.Big then bytes else Array.rev bytes
      let ins = parser.Parse(bytes, 0x20100000UL) :?> Instruction
      Assert.AreEqual<Opcode>(opcode, ins.Opcode)
      Assert.AreEqual<uint32>(4u, ins.Length)

  [<TestMethod>]
  member _.``[PPC T] BA alias decoding``() =
    decode "48000006" Opcode.BA

  [<TestMethod>]
  member _.``[PPC T] BLA alias decoding``() =
    decode "48000007" Opcode.BLA

  [<TestMethod>]
  member _.``[PPC T] BCA alias decoding``() =
    decode "41800006" Opcode.BCA

  [<TestMethod>]
  member _.``[PPC T] BCLA alias decoding``() =
    decode "41800007" Opcode.BCLA

  [<TestMethod>]
  member _.``[PPC T] CMPD alias decoding``() =
    decode "7d263800" Opcode.CMPD

  [<TestMethod>]
  member _.``[PPC T] CMPW alias decoding``() =
    decode "7d063800" Opcode.CMPW

  [<TestMethod>]
  member _.``[PPC T] CMPLD alias decoding``() =
    decode "7d263840" Opcode.CMPLD

  [<TestMethod>]
  member _.``[PPC T] CMPLW alias decoding``() =
    decode "7d063840" Opcode.CMPLW

  [<TestMethod>]
  member _.``[PPC T] CMPDI alias decoding``() =
    decode "2d26000c" Opcode.CMPDI

  [<TestMethod>]
  member _.``[PPC T] CMPWI alias decoding``() =
    decode "2d06000c" Opcode.CMPWI

  [<TestMethod>]
  member _.``[PPC T] CMPLDI alias decoding``() =
    decode "2926000c" Opcode.CMPLDI

  [<TestMethod>]
  member _.``[PPC T] CMPLWI alias decoding``() =
    decode "2906000c" Opcode.CMPLWI

  [<TestMethod>]
  member _.``[PPC T] CRCLR alias decoding``() =
    decode "4c631982" Opcode.CRCLR

  [<TestMethod>]
  member _.``[PPC T] CRMOVE alias decoding``() =
    decode "4c642382" Opcode.CRMOVE

  [<TestMethod>]
  member _.``[PPC T] CRNOT alias decoding``() =
    decode "4c642042" Opcode.CRNOT

  [<TestMethod>]
  member _.``[PPC T] CRSET alias decoding``() =
    decode "4c631a42" Opcode.CRSET

  [<TestMethod>]
  member _.``[PPC T] LI alias decoding``() =
    decode "38a0000c" Opcode.LI

  [<TestMethod>]
  member _.``[PPC T] LIS alias decoding``() =
    decode "3ca0000c" Opcode.LIS

  [<TestMethod>]
  member _.``[PPC T] LWSYNC alias decoding``() =
    decode "7c2004ac" Opcode.LWSYNC

  [<TestMethod>]
  member _.``[PPC T] MFCTR alias decoding``() =
    decode "7ca902a6" Opcode.MFCTR

  [<TestMethod>]
  member _.``[PPC T] MFLR alias decoding``() =
    decode "7ca802a6" Opcode.MFLR

  [<TestMethod>]
  member _.``[PPC T] MFXER alias decoding``() =
    decode "7ca102a6" Opcode.MFXER

  [<TestMethod>]
  member _.``[PPC T] MFTBU alias decoding``() =
    decode "7cad42a6" Opcode.MFTBU

  [<TestMethod>]
  member _.``[PPC T] MTCTR alias decoding``() =
    decode "7ca903a6" Opcode.MTCTR

  [<TestMethod>]
  member _.``[PPC T] MTLR alias decoding``() =
    decode "7ca803a6" Opcode.MTLR

  [<TestMethod>]
  member _.``[PPC T] MTXER alias decoding``() =
    decode "7ca103a6" Opcode.MTXER

  [<TestMethod>]
  member _.``[PPC T] MR alias decoding``() =
    decode "7cc53378" Opcode.MR

  [<TestMethod>]
  member _.``[PPC T] NOP alias decoding``() =
    decode "60000000" Opcode.NOP

  [<TestMethod>]
  member _.``[PPC T] ROTLW alias decoding``() =
    decode "5cc5383e" Opcode.ROTLW

  [<TestMethod>]
  member _.``[PPC T] TWEQ alias decoding``() =
    decode "7c863808" Opcode.TWEQ

  [<TestMethod>]
  member _.``[PPC T] TWEQI alias decoding``() =
    decode "0c86000c" Opcode.TWEQI

  [<TestMethod>]
  member _.``[PPC T] TWGE alias decoding``() =
    decode "7d863808" Opcode.TWGE

  [<TestMethod>]
  member _.``[PPC T] TWGEI alias decoding``() =
    decode "0d86000c" Opcode.TWGEI

  [<TestMethod>]
  member _.``[PPC T] TWGT alias decoding``() =
    decode "7d063808" Opcode.TWGT

  [<TestMethod>]
  member _.``[PPC T] TWGTI alias decoding``() =
    decode "0d06000c" Opcode.TWGTI

  [<TestMethod>]
  member _.``[PPC T] TWLE alias decoding``() =
    decode "7e863808" Opcode.TWLE

  [<TestMethod>]
  member _.``[PPC T] TWLEI alias decoding``() =
    decode "0e86000c" Opcode.TWLEI

  [<TestMethod>]
  member _.``[PPC T] TWLGT alias decoding``() =
    decode "7c263808" Opcode.TWLGT

  [<TestMethod>]
  member _.``[PPC T] TWLGTI alias decoding``() =
    decode "0c26000c" Opcode.TWLGTI

  [<TestMethod>]
  member _.``[PPC T] TWLLE alias decoding``() =
    decode "7cc63808" Opcode.TWLLE

  [<TestMethod>]
  member _.``[PPC T] TWLLEI alias decoding``() =
    decode "0cc6000c" Opcode.TWLLEI

  [<TestMethod>]
  member _.``[PPC T] TWLLT alias decoding``() =
    decode "7c463808" Opcode.TWLLT

  [<TestMethod>]
  member _.``[PPC T] TWLLTI alias decoding``() =
    decode "0c46000c" Opcode.TWLLTI

  [<TestMethod>]
  member _.``[PPC T] TWLNL alias decoding``() =
    decode "7ca63808" Opcode.TWLNL

  [<TestMethod>]
  member _.``[PPC T] TWLNLI alias decoding``() =
    decode "0ca6000c" Opcode.TWLNLI

  [<TestMethod>]
  member _.``[PPC T] TWLT alias decoding``() =
    decode "7e063808" Opcode.TWLT

  [<TestMethod>]
  member _.``[PPC T] TWLTI alias decoding``() =
    decode "0e06000c" Opcode.TWLTI

  [<TestMethod>]
  member _.``[PPC T] TWNE alias decoding``() =
    decode "7f063808" Opcode.TWNE

  [<TestMethod>]
  member _.``[PPC T] TWNEI alias decoding``() =
    decode "0f06000c" Opcode.TWNEI

  [<TestMethod>]
  member _.``[PPC T] TRAP alias decoding``() =
    decode "7fe00008" Opcode.TRAP

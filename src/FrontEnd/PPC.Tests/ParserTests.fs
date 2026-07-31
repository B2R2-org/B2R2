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
    let parser = PPCParser(isa.WordSize, reader) :> IInstructionParsable
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
    let parser = PPCParser(isa.WordSize, reader) :> IInstructionParsable
    let bytes = ByteArray.ofHexString byteString
    Assert.Throws<ParsingFailureException>(fun () ->
      parser.Parse(System.ReadOnlySpan(bytes: byte[]), 0UL) |> ignore)
    |> ignore

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

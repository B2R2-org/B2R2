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

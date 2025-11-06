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
    static member Reg(reg) =
      OprReg reg

    static member Mem(disp, reg) =
      OprMem(disp, reg)

    static member Imm(imm) =
      OprImm imm

    static member CY(cy) =
      OprCY cy

    static member L(l) =
      OprL l

    static member Addr(addr) =
      OprAddr addr

    static member BO(bo) =
      OprBO bo

    static member BI(bi) =
      OprBI bi

    static member BH(bh) =
      OprBH bh

  let test (isa: ISA) opcode (opr: Operands) bytes =
    let reader = BinReader.Init isa.Endian
    let parser = PPCParser(isa, reader) :> IInstructionParsable
    let span = System.ReadOnlySpan(bytes: byte[])
    let ins = parser.Parse(span, 0UL) :?> Instruction
    let opcode' = ins.Opcode
    let oprs' = ins.Operands
    Assert.AreEqual<Opcode>(opcode, opcode')
    Assert.AreEqual<Operands>(opr, oprs')

  let testPPC wordSz bytes (opcode, operands) =
    let isa = ISA(Architecture.PPC, Endian.Big, wordSz)
    test isa opcode operands bytes

  let operandsFromArray oprList =
    let oprArr = Array.ofList oprList
    match oprArr.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand(oprArr[0])
    | 2 -> TwoOperands(oprArr[0], oprArr[1])
    | 3 -> ThreeOperands(oprArr[0], oprArr[1], oprArr[2])
    | 4 -> FourOperands(oprArr[0], oprArr[1], oprArr[2], oprArr[3])
    | _ -> Terminator.futureFeature ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

[<TestClass>]
type ArithmeticClass() =
  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (1)``() =
    "38622408"
    ++ (ADDI ** [ O.Reg R3; O.Reg R2; O.Imm 0x2408UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (2)``() =
    "3BC889D6"
    ++ (ADDI ** [ O.Reg R30; O.Reg R8; O.Imm 0x89D6UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (3)``() =
    "3D5CDCFE"
    ++ (ADDIS ** [ O.Reg R10; O.Reg R28; O.Imm 0xDCFEUL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (4)``() =
    "4E5A35C5"
    ++ (ADDPCIS ** [ O.Reg R18; O.Imm 0x35F5UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (5)``() =
    "7E80AA14"
    ++ (ADD ** [ O.Reg R20; O.Reg R0; O.Reg R21 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (6)``() =
    "7DDE7A15"
    ++ (ADD_DOT ** [ O.Reg R14; O.Reg R30; O.Reg R15 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (7)``() =
    "7D3DB614"
    ++ (ADDO ** [ O.Reg R9; O.Reg R29; O.Reg R22 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (8)``() =
    "7C46DE15"
    ++ (ADDO_DOT ** [ O.Reg R2; O.Reg R6; O.Reg R27 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (9)``() =
    "7E74B050"
    ++ (SUBF ** [ O.Reg R19; O.Reg R20; O.Reg R22 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (10)``() =
    "7E233051"
    ++ (SUBF_DOT ** [ O.Reg R17; O.Reg R3; O.Reg R6 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (11)``() =
    "7D794450"
    ++ (SUBFO ** [ O.Reg R11; O.Reg R25; O.Reg R8 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (12)``() =
    "7FBC6451"
    ++ (SUBFO_DOT ** [ O.Reg R29; O.Reg R28; O.Reg R12 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (13)``() =
    "31FEE03B"
    ++ (ADDIC ** [ O.Reg R15; O.Reg R30; O.Imm 0xE03BUL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (14)``() =
    "35D210D3"
    ++ (ADDIC_DOT ** [ O.Reg R14; O.Reg R18; O.Imm 0x10D3UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (15)``() =
    "2193E4DB"
    ++ (SUBFIC ** [ O.Reg R12; O.Reg R19; O.Imm 0xE4DBUL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (16)``() =
    "7CB34014"
    ++ (ADDC ** [ O.Reg R5; O.Reg R19; O.Reg R8 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (17)``() =
    "7D22F015"
    ++ (ADDC_DOT ** [ O.Reg R9; O.Reg R2; O.Reg R30 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (18)``() =
    "7E4C2414"
    ++ (ADDCO ** [ O.Reg R18; O.Reg R12; O.Reg R4 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (19)``() =
    "7EDDA415"
    ++ (ADDCO_DOT ** [ O.Reg R22; O.Reg R29; O.Reg R20 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (20)``() =
    "7D43D810"
    ++ (SUBFC ** [ O.Reg R10; O.Reg R3; O.Reg R27 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (21)``() =
    "7CF13011"
    ++ (SUBFC_DOT ** [ O.Reg R7; O.Reg R17; O.Reg R6 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (22)``() =
    "7CF0EC10"
    ++ (SUBFCO ** [ O.Reg R7; O.Reg R16; O.Reg R29 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (23)``() =
    "7C449C11"
    ++ (SUBFCO_DOT ** [ O.Reg R2; O.Reg R4; O.Reg R19 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (24)``() =
    "7CF40114"
    ++ (ADDE ** [ O.Reg R7; O.Reg R20; O.Reg R0 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (25)``() =
    "7E8D6115"
    ++ (ADDE_DOT ** [ O.Reg R20; O.Reg R13; O.Reg R12 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (26)``() =
    "7DF82D14"
    ++ (ADDEO ** [ O.Reg R15; O.Reg R24; O.Reg R5 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (27)``() =
    "7FBAAD15"
    ++ (ADDEO_DOT ** [ O.Reg R29; O.Reg R26; O.Reg R21 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (28)``() =
    "7C98C110"
    ++ (SUBFE ** [ O.Reg R4; O.Reg R24; O.Reg R24 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (29)``() =
    "7FC32111"
    ++ (SUBFE_DOT ** [ O.Reg R30; O.Reg R3; O.Reg R4 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (30)``() =
    "7C4B3D10"
    ++ (SUBFEO ** [ O.Reg R2; O.Reg R11; O.Reg R7 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (31)``() =
    "7CBA1D11"
    ++ (SUBFEO_DOT ** [ O.Reg R5; O.Reg R26; O.Reg R3 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (32)``() =
    "7F1701D4"
    ++ (ADDME ** [ O.Reg R24; O.Reg R23 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (33)``() =
    "7FD601D5"
    ++ (ADDME_DOT ** [ O.Reg R30; O.Reg R22 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (34)``() =
    "7CF005D4"
    ++ (ADDMEO ** [ O.Reg R7; O.Reg R16 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (35)``() =
    "7F9A05D5"
    ++ (ADDMEO_DOT ** [ O.Reg R28; O.Reg R26 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (36)``() =
    "7C3401D0"
    ++ (SUBFME ** [ O.Reg R1; O.Reg R20 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (37)``() =
    "7E5401D1"
    ++ (SUBFME_DOT ** [ O.Reg R18; O.Reg R20 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (38)``() =
    "7DA105D0"
    ++ (SUBFMEO ** [ O.Reg R13; O.Reg R1 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (39)``() =
    "7E7405D1"
    ++ (SUBFMEO_DOT ** [ O.Reg R19; O.Reg R20 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (40)``() =
    "7ECD9154"
    ++ (ADDEX ** [ O.Reg R22; O.Reg R13; O.Reg R18; O.CY 0x0uy ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (41)``() =
    "7D520190"
    ++ (SUBFZE ** [ O.Reg R10; O.Reg R18 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (42)``() =
    "7CBC0191"
    ++ (SUBFZE_DOT ** [ O.Reg R5; O.Reg R28 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (43)``() =
    "7D020590"
    ++ (SUBFZEO ** [ O.Reg R8; O.Reg R2 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (44)``() =
    "7FD90591"
    ++ (SUBFZEO_DOT ** [ O.Reg R30; O.Reg R25 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (45)``() =
    "7D460194"
    ++ (ADDZE ** [ O.Reg R10; O.Reg R6 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (46)``() =
    "7D300195"
    ++ (ADDZE_DOT ** [ O.Reg R9; O.Reg R16 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (47)``() =
    "7FB80594"
    ++ (ADDZEO ** [ O.Reg R29; O.Reg R24 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (48)``() =
    "7E8D0595"
    ++ (ADDZEO_DOT ** [ O.Reg R20; O.Reg R13 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (49)``() =
    "7E3300D0"
    ++ (NEG ** [ O.Reg R17; O.Reg R19 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (50)``() =
    "7CFE00D1"
    ++ (NEG_DOT ** [ O.Reg R7; O.Reg R30 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (51)``() =
    "7C5B04D0"
    ++ (NEGO ** [ O.Reg R2; O.Reg R27 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (52)``() =
    "7E8304D1"
    ++ (NEGO_DOT ** [ O.Reg R20; O.Reg R3 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (53)``() =
    "1D070A8B"
    ++ (MULLI ** [ O.Reg R8; O.Reg R7; O.Imm 0xA8BUL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (54)``() =
    "7DEE4896"
    ++ (MULHW ** [ O.Reg R15; O.Reg R14; O.Reg R9 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (55)``() =
    "7F1AA897"
    ++ (MULHW_DOT ** [ O.Reg R24; O.Reg R26; O.Reg R21 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (56)``() =
    "7DF631D6"
    ++ (MULLW ** [ O.Reg R15; O.Reg R22; O.Reg R6 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (57)``() =
    "7EF409D7"
    ++ (MULLW_DOT ** [ O.Reg R23; O.Reg R20; O.Reg R1 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (58)``() =
    "7DCC85D6"
    ++ (MULLWO ** [ O.Reg R14; O.Reg R12; O.Reg R16 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (59)``() =
    "7CEBA5D7"
    ++ (MULLWO_DOT ** [ O.Reg R7; O.Reg R11; O.Reg R20 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (60)``() =
    "7F22B016"
    ++ (MULHWU ** [ O.Reg R25; O.Reg R2; O.Reg R22 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (61)``() =
    "7C229817"
    ++ (MULHWU_DOT ** [ O.Reg R1; O.Reg R2; O.Reg R19 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (62)``() =
    "7D5EDBD6"
    ++ (DIVW ** [ O.Reg R10; O.Reg R30; O.Reg R27 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (63)``() =
    "7D317BD7"
    ++ (DIVW_DOT ** [ O.Reg R9; O.Reg R17; O.Reg R15 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (64)``() =
    "7D80BFD6"
    ++ (DIVWO ** [ O.Reg R12; O.Reg R0; O.Reg R23 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (65)``() =
    "7DA47FD7"
    ++ (DIVWO_DOT ** [ O.Reg R13; O.Reg R4; O.Reg R15 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (66)``() =
    "7CD0CB96"
    ++ (DIVWU ** [ O.Reg R6; O.Reg R16; O.Reg R25 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (67)``() =
    "7CF2E397"
    ++ (DIVWU_DOT ** [ O.Reg R7; O.Reg R18; O.Reg R28 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (68)``() =
    "7CB81796"
    ++ (DIVWUO ** [ O.Reg R5; O.Reg R24; O.Reg R2 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (69)``() =
    "7D60A797"
    ++ (DIVWUO_DOT ** [ O.Reg R11; O.Reg R0; O.Reg R20 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (70)``() =
    "7C7AAB56"
    ++ (DIVWE ** [ O.Reg R3; O.Reg R26; O.Reg R21 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (71)``() =
    "7CCF4B57"
    ++ (DIVWE_DOT ** [ O.Reg R6; O.Reg R15; O.Reg R9 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (72)``() =
    "7EE4D756"
    ++ (DIVWEO ** [ O.Reg R23; O.Reg R4; O.Reg R26 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (73)``() =
    "7DF94757"
    ++ (DIVWEO_DOT ** [ O.Reg R15; O.Reg R25; O.Reg R8 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (74)``() =
    "7DB92B16"
    ++ (DIVWEU ** [ O.Reg R13; O.Reg R25; O.Reg R5 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (75)``() =
    "7D303317"
    ++ (DIVWEU_DOT ** [ O.Reg R9; O.Reg R16; O.Reg R6 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (76)``() =
    "7C090F16"
    ++ (DIVWEUO ** [ O.Reg R0; O.Reg R9; O.Reg R1 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (77)``() =
    "7E576F17"
    ++ (DIVWEUO_DOT ** [ O.Reg R18; O.Reg R23; O.Reg R13 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (78)``() =
    "7D3D4E16"
    ++ (MODSW ** [ O.Reg R9; O.Reg R29; O.Reg R9 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (79)``() =
    "7E825A16"
    ++ (MODUW ** [ O.Reg R20; O.Reg R2; O.Reg R11 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Arithmetic Instruction Test (80)``() =
    "7F2205E6"
    ++ (DARN ** [ O.Reg R25; O.L 0x2uy ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (1)``() =
    "49F29274"
    ++ (B ** [ O.Addr 0x1F29274UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (2)``() =
    "489D902E"
    ++ (BA ** [ O.Addr 0x9D902CUL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (3)``() =
    "4A946EF5"
    ++ (BL ** [ O.Addr 0xFFFFFFFFFE946EF4UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (4)``() =
    "49D8F883"
    ++ (BLA ** [ O.Addr 0x1D8F880UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (5)``() =
    "42C561B8"
    ++ (BC ** [ O.BO 0x16uy; O.BI 0x5uy; O.Addr 0x61B8UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (6)``() =
    "4066D85A"
    ++ (BCA ** [ O.BO 0x3uy; O.BI 0x6uy; O.Addr 0xFFFFFFFFFFFFD858UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (7)``() =
    "4009FEB9"
    ++ (BCL ** [ O.BO 0x0uy; O.BI 0x9uy; O.Addr 0xFFFFFFFFFFFFFEB8UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (8)``() =
    "42965543"
    ++ (BCLA ** [ O.BO 0x14uy; O.BI 0x16uy; O.Addr 0x5540UL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (9)``() =
    "4F440820"
    ++ (BCLR ** [ O.BO 0x1Auy; O.BI 0x4uy; O.BH 0x1uy ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (10)``() =
    "4E2B1821"
    ++ (BCLRL ** [ O.BO 0x11uy; O.BI 0xBuy; O.BH 0x3uy ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (11)``() =
    "4E4A0420"
    ++ (BCCTR ** [ O.BO 0x12uy; O.BI 0xAuy; O.BH 0x0uy ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (12)``() =
    "4C371C21"
    ++ (BCCTRL ** [ O.BO 0x1uy; O.BI 0x17uy; O.BH 0x3uy ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (13)``() =
    "4DC20460"
    ++ (BCTAR ** [ O.BO 0xEuy; O.BI 0x2uy; O.BH 0x0uy ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Branch Instruction Test (14)``() =
    "4C1A1C61"
    ++ (BCTARL ** [ O.BO 0x0uy; O.BI 0x1Auy; O.BH 0x3uy ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (1)``() =
    "8A8DB26D"
    ++ (LBZ ** [ O.Reg R20; O.Mem (-0x4D93L, R13) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (2)``() =
    "7FE110AE"
    ++ (LBZX ** [ O.Reg R31; O.Reg R1; O.Reg R2 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (3)``() =
    "8DD4C77E"
    ++ (LBZU ** [ O.Reg R14; O.Mem (-0x3882L, R20) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (4)``() =
    "7CADC8EE"
    ++ (LBZUX ** [ O.Reg R5; O.Reg R13; O.Reg R25 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (5)``() =
    "A0B0695D"
    ++ (LHZ ** [ O.Reg R5; O.Mem (0x695DL, R16) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (6)``() =
    "7DD7E22E"
    ++ (LHZX ** [ O.Reg R14; O.Reg R23; O.Reg R28 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (7)``() =
    "A48EE571"
    ++ (LHZU ** [ O.Reg R4; O.Mem (-0x1A8FL, R14) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (8)``() =
    "7CDFF26E"
    ++ (LHZUX ** [ O.Reg R6; O.Reg R31; O.Reg R30 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (9)``() =
    "AAA5190F"
    ++ (LHA ** [ O.Reg R21; O.Mem (0x190FL, R5) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (10)``() =
    "7ED122AE"
    ++ (LHAX ** [ O.Reg R22; O.Reg R17; O.Reg R4 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (11)``() =
    "AE565FC8"
    ++ (LHAU ** [ O.Reg R18; O.Mem (0x5FC8L, R22) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (12)``() =
    "7F2EC2EE"
    ++ (LHAUX ** [ O.Reg R25; O.Reg R14; O.Reg R24 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (13)``() =
    "80017CDF"
    ++ (LWZ ** [ O.Reg R0; O.Mem (0x7CDFL, R1) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (14)``() =
    "7CF1482E"
    ++ (LWZX ** [ O.Reg R7; O.Reg R17; O.Reg R9 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (15)``() =
    "857A7148"
    ++ (LWZU ** [ O.Reg R11; O.Mem (0x7148L, R26) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (16)``() =
    "7C43786E"
    ++ (LWZUX ** [ O.Reg R2; O.Reg R3; O.Reg R15 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (17)``() =
    "EA76DE8A"
    ++ (LWA ** [ O.Reg R19; O.Mem (-0x2178L, R22) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (18)``() =
    "7DD0CAAA"
    ++ (LWAX ** [ O.Reg R14; O.Reg R16; O.Reg R25 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (19)``() =
    "7D8382EA"
    ++ (LWAUX ** [ O.Reg R12; O.Reg R3; O.Reg R16 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (20)``() =
    "EA55ABDC"
    ++ (LD ** [ O.Reg R18; O.Mem (-0x5424L, R21) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (21)``() =
    "7D2EA82A"
    ++ (LDX ** [ O.Reg R9; O.Reg R14; O.Reg R21 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (22)``() =
    "E8E0D551"
    ++ (LDU ** [ O.Reg R7; O.Mem (-0x2AB0L, R0) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (23)``() =
    "7E74406A"
    ++ (LDUX ** [ O.Reg R19; O.Reg R20; O.Reg R8 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (24)``() =
    "9AA52476"
    ++ (STB ** [ O.Reg R21; O.Mem (0x2476L, R5) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (25)``() =
    "7ED6C1AE"
    ++ (STBX ** [ O.Reg R22; O.Reg R22; O.Reg R24 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (26)``() =
    "9DFADA88"
    ++ (STBU ** [ O.Reg R15; O.Mem (-0x2578L, R26) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (27)``() =
    "7E2E29EE"
    ++ (STBUX ** [ O.Reg R17; O.Reg R14; O.Reg R5 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (28)``() =
    "B01B160A"
    ++ (STH ** [ O.Reg R0; O.Mem (0x160AL, R27) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (29)``() =
    "7F25F32E"
    ++ (STHX ** [ O.Reg R25; O.Reg R5; O.Reg R30 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (30)``() =
    "B55BF1F2"
    ++ (STHU ** [ O.Reg R10; O.Mem (-0xE0EL, R27) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (31)``() =
    "7E1FA36E"
    ++ (STHUX ** [ O.Reg R16; O.Reg R31; O.Reg R20 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (32)``() =
    "9084960D"
    ++ (STW ** [ O.Reg R4; O.Mem (-0x69F3L, R4) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (33)``() =
    "7DB7592E"
    ++ (STWX ** [ O.Reg R13; O.Reg R23; O.Reg R11 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (34)``() =
    "967D046A"
    ++ (STWU ** [ O.Reg R19; O.Mem (0x46AL, R29) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (35)``() =
    "7E20816E"
    ++ (STWUX ** [ O.Reg R17; O.Reg R0; O.Reg R16 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (36)``() =
    "F848C0D8"
    ++ (STD ** [ O.Reg R2; O.Mem (-0x3F28L, R8) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (37)``() =
    "7E83512A"
    ++ (STDX ** [ O.Reg R20; O.Reg R3; O.Reg R10 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (38)``() =
    "F9840741"
    ++ (STDU ** [ O.Reg R12; O.Mem (0x740L, R4) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (39)``() =
    "7EF4796A"
    ++ (STDUX ** [ O.Reg R23; O.Reg R20; O.Reg R15 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (40)``() =
    "E140B3F0"
    ++ (LQ ** [ O.Reg R10; O.Mem (-0x4C10L, R0) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (41)``() =
    "F9CE65BE"
    ++ (STQ ** [ O.Reg R14; O.Mem (0x65BCL, R14) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (42)``() =
    "7C516E2C"
    ++ (LHBRX ** [ O.Reg R2; O.Reg R17; O.Reg R13 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (43)``() =
    "7D484F2C"
    ++ (STHBRX ** [ O.Reg R10; O.Reg R8; O.Reg R9 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (44)``() =
    "7FF5B42C"
    ++ (LWBRX ** [ O.Reg R31; O.Reg R21; O.Reg R22 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (45)``() =
    "7F95AD2C"
    ++ (STWBRX ** [ O.Reg R28; O.Reg R21; O.Reg R21 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (46)``() =
    "7F722C28"
    ++ (LDBRX ** [ O.Reg R27; O.Reg R18; O.Reg R5 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (47)``() =
    "7DF4ED28"
    ++ (STDBRX ** [ O.Reg R15; O.Reg R20; O.Reg R29 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (48)``() =
    "B9817027"
    ++ (LMW ** [ O.Reg R12; O.Mem (0x7027L, R1) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (49)``() =
    "BF202D82"
    ++ (STMW ** [ O.Reg R25; O.Mem (0x2D82L, R0) ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (50)``() =
    "7D3DDCAA"
    ++ (LSWI ** [ O.Reg R9; O.Reg R29; O.Imm 0x1BUL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (51)``() =
    "7F8D242A"
    ++ (LSWX ** [ O.Reg R28; O.Reg R13; O.Reg R4 ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (52)``() =
    "7D2DF5AA"
    ++ (STSWI ** [ O.Reg R9; O.Reg R13; O.Imm 0x1EUL ])
    ||> testPPC WordSize.Bit64

  [<TestMethod>]
  member _.``[PPC64] Fixed-Point Load/Store Test (53)``() =
    "7FD55D2A"
    ++ (STSWX ** [ O.Reg R30; O.Reg R21; O.Reg R11 ])
    ||> testPPC WordSize.Bit64
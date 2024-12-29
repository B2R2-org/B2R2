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
module B2R2.FrontEnd.Tests.PARISC

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter.PARISC
open type Opcode
open type Register
open type PARISCCondition

type O =
  static member Reg (r) =
    OpReg r

  static member Imm (v) =
    OpImm v

  static member Mem (r, o: int64, rt) =
    OpMem (r, Some (Imm o), rt)

  static member Addr (t) =
    OpAddr t

  static member Cond (t) =
    OpCond t

let private test arch endian opcode operands (bytes: byte[]) =
  let reader = BinReader.Init endian
  let span = System.ReadOnlySpan bytes
  let ins = ParsingMain.parse span reader arch WordSize.Bit32 0UL
  let opcode' = ins.Info.Opcode
  let operands' = ins.Info.Operands
  Assert.AreEqual (opcode', opcode)
  Assert.AreEqual (operands', operands)

let private testPARISC bytes (opcode, operands) =
  test Architecture.PARISC Endian.Big opcode operands bytes

let private operandsFromArray oprList =
  let oprArray = Array.ofList oprList
  match oprArray.Length with
  | 0 -> NoOperand
  | 1 -> OneOperand oprArray[0]
  | 2 -> TwoOperands (oprArray[0], oprArray[1])
  | 3 -> ThreeOperands (oprArray[0], oprArray[1], oprArray[2])
  | 4 -> FourOperands (oprArray[0], oprArray[1],
                      oprArray[2], oprArray[3])
  | 5 -> FiveOperands (oprArray[0], oprArray[1],
                      oprArray[2], oprArray[3], oprArray[4])
  | _ -> Utils.impossible ()

let private ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

let private ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

[<TestClass>]
type ArithmeticClass () =
  [<TestMethod>]
  member __.``[PARISC] OR Instruction`` () =
    "08190254"
    ++ OR ** [ O.Reg GR20; O.Reg GR25; O.Reg GR0 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] ADD Instruction`` () =
    "0BAE061D"
    ++ ADD ** [ O.Reg GR29; O.Reg GR14; O.Reg GR29 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] ADDC Instruction`` () =
    "0B8D071C"
    ++ ADDC ** [ O.Reg GR28; O.Reg GR13; O.Reg GR28 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] ADDL Instruction`` () =
    "08230A17"
    ++ ADDL ** [ O.Reg GR23; O.Reg GR3; O.Reg GR1 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] SHLADD Instruction`` () =
    "0B3A069A"
    ++ SHLADD ** [ O.Reg GR26; O.Reg GR26; O.Reg GR25 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] SHLADDL Instruction`` () =
    "083A0AC1"
    ++ SHLADDL ** [ O.Reg GR1; O.Reg GR26; O.Reg GR1 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] SUB Instruction`` () =
    "09480407"
    ++ SUB ** [ O.Reg GR7; O.Reg GR8; O.Reg GR10 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] SUBB Instruction`` () =
    "08E30513"
    ++ SUBB ** [ O.Reg GR19; O.Reg GR3; O.Reg GR7 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] AND Instruction`` () =
    "09CD020E"
    ++ AND ** [ O.Reg GR14; O.Reg GR13; O.Reg GR14 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] DS Instruction`` () =
    "0B210441"
    ++ DS ** [ O.Reg GR1; O.Reg GR1; O.Reg GR25 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] CMPCLR Instruction`` () =
    "081A5880"
    ++ CMPCLR ** [ O.Reg GR0; O.Reg GR26; O.Reg GR0 ]
    |> testPARISC

[<TestClass>]
type LoadStoreClass () =
  [<TestMethod>]
  member __.``[PARISC] LDO Instruction`` () =
    "341C0002"
    ++ LDO ** [ O.Reg GR28; O.Mem (GR0, 2L, 64<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] LDW Instruction`` () =
    "0FC9109A"
    ++ LDW ** [ O.Reg GR26; O.Mem (GR30, 9L, 32<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] STW Instruction (1)`` () =
    "0FDD1281"
    ++ STW ** [ O.Reg GR29; O.Mem (GR30, 1L, 32<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] LDB Instruction (1)`` () =
    "0E24101C"
    ++ LDB ** [ O.Reg GR28; O.Mem (GR17, 4L, 8<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] STB Instruction (1)`` () =
    "0CA41200"
    ++ STB ** [ O.Reg GR4; O.Mem (GR5, 0L, 8<rt>) ]
    |> testPARISC

[<TestClass>]
type BranchClass () =
  [<TestMethod>]
  member __.``[PARISC] BV Instruction`` () =
    "E840C000"
    ++ BV ** [ O.Mem (GR2, 0L, 64<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] BLR Instruction`` () =
    "E8194002"
    ++ BLR ** [ O.Reg GR25; O.Reg GR0 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] BB Instruction`` () =
    "C7C9C020"
    ++ BB ** [ O.Cond GTE; O.Reg GR9; O.Imm 30UL; O.Mem (GR30, 16L, 64<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] ADDB Instruction`` () =
    "ABB90008"
    ++ ADDB ** [ O.Cond TR; O.Reg GR25; O.Reg GR29; O.Mem (GR29, 4L, 64<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] MOVB Instruction`` () =
    "CB9CC020"
    ++ MOVB ** [ O.Cond GTE; O.Reg GR28; O.Reg GR28; O.Mem (GR28, 16L, 64<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] CMPB Instruction`` () =
    "8A652010"
    ++ CMPB ** [ O.Cond NEQ; O.Reg GR5; O.Reg GR19; O.Mem (GR19, 8L, 64<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] BL Instruction`` () =
    "E8000010"
    ++ BL ** [ O.Mem (GR0, 128L, 64<rt>); O.Reg GR0 ]
    |> testPARISC

[<TestClass>]
type FloatingLoadStoreClass () =
  [<TestMethod>]
  member __.``[PARISC] FLDD Instruction`` () =
    "2FC11017"
    ++ FLDD ** [ O.Reg GR23; O.Mem (GR30, 1L, 64<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] FLDW Instruction`` () =
    "27801017"
    ++ FLDW ** [ O.Reg GR23; O.Mem (GR28, 0L, 32<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] FSTW Instruction`` () =
    "27C11216"
    ++ FSTW ** [ O.Reg GR22; O.Mem (GR30, 1L, 32<rt>) ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] FSTD Instruction`` () =
    "2FC11218"
    ++ FSTD ** [ O.Reg GR1; O.Mem (GR30, 24L, 64<rt>) ]
    |> testPARISC

[<TestClass>]
type ShiftPairExtractClass () =
  [<TestMethod>]
  member __.``[PARISC] SHRPW Instruction`` () =
    "D3BC0834"
    ++ SHRPW ** [ O.Reg GR28; O.Reg GR29; O.Imm 0x1UL; O.Reg GR20 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] EXTRW Instruction`` () =
    "D0E71C1F"
    ++ EXTRW ** [ O.Reg GR7; O.Imm 0x0UL; O.Imm 0x1FUL; O.Reg GR7 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] DEPW Instruction`` () =
    "D7A20884"
    ++ DEPW ** [ O.Reg GR2; O.Imm 0x4UL; O.Imm 0x4UL; O.Reg GR29 ]
    |> testPARISC

  [<TestMethod>]
  member __.``[PARISC] DEPWI Instruction`` () =
    "D7801C9F"
    ++ DEPWI ** [ O.Imm 0x0UL; O.Imm 0x4UL; O.Imm 0x1FUL; O.Reg GR28 ]
    |> testPARISC
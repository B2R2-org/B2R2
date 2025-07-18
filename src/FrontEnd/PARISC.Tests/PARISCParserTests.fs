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

namespace B2R2.FrontEnd.PARISC.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PARISC
open type Opcode
open type Register
open type Completer

/// Shortcut for creating operands.
[<AutoOpen>]
module private PARISCShortcut =
  type O =
    static member Reg (r) =
      OpReg r

    static member Imm (v) =
      OpImm v

    static member Sat (v) =
      OpShiftAmount v

    static member Mem (r, o: int64, rt) =
      OpMem (r, None, Some (Imm o), rt)

    static member Mem (r, o: int64, rt, space) =
      OpMem (r, Some space, Some (Imm o), rt)

    static member Mem (b, r: Register, rt, space) =
      OpMem (b, Some space, Some (Reg r), rt)

  let test (isa: ISA) opcode (opr: Operands) completer condition uid bytes =
    let reader = BinReader.Init isa.Endian
    let parser = PARISCParser (isa, reader) :> IInstructionParsable
    let span = System.ReadOnlySpan (bytes: byte[])
    let ins = parser.Parse (span, 0UL) :?> Instruction
    let opcode' = ins.Opcode
    let completer' = ins.Completer
    let condition' = ins.Condition
    let uid' = ins.ID
    let oprs' = ins.Operands
    Assert.AreEqual<Opcode> (opcode, opcode')
    Assert.AreEqual<Operands> (opr, oprs')
    Assert.AreEqual (completer, completer')
    Assert.AreEqual (condition, condition')
    Assert.AreEqual (uid, uid')

  let testPARISC wordSz bytes
    ((opcode, operands), cmplt: array<Completer>, cond, uid) =
    let isa = ISA (Architecture.PARISC, Endian.Big, wordSz)
    match cmplt with
    | [||] -> test isa opcode operands None cond uid bytes
    | _ -> test isa opcode operands (Some cmplt) cond uid bytes

  let operandsFromArray oprList =
    let oprArr = Array.ofList oprList
    match oprArr.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArr[0]
    | 2 -> TwoOperands (oprArr[0], oprArr[1])
    | 3 -> ThreeOperands (oprArr[0], oprArr[1], oprArr[2])
    | 4 -> FourOperands (oprArr[0], oprArr[1], oprArr[2], oprArr[3])
    | 5 -> FiveOperands (oprArr[0], oprArr[1], oprArr[2], oprArr[3], oprArr[4])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

[<TestClass>]
type ArithmeticClass () =
  [<TestMethod>]
  member _.``[PARISC64] ADD Instruction Test (1)`` () =
    "0855AA3C"
    ++ (ADD ** [ O.Reg GR21; O.Reg GR2; O.Reg GR28 ], [| L |], Some DZNV, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] ADD Instruction Test (2)`` () =
    "09AAFF28"
    ++ (ADD ** [ O.Reg GR10; O.Reg GR13; O.Reg GR8 ], [| DC; TSV |], Some DEV,
    None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] ADD Instruction Test (3)`` () =
    "0BAAAA15"
    ++ (ADD ** [ O.Reg GR10; O.Reg GR29; O.Reg GR21 ], [| L |], Some ZNV, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SUB Instruction Test (1)`` () =
    "0855553D"
    ++ (SUB ** [ O.Reg GR21; O.Reg GR2; O.Reg GR29 ], [| DB |], Some DGE, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SUB Instruction Test (2)`` () =
    "08FF5501"
    ++ (SUB ** [ O.Reg GR31; O.Reg GR7; O.Reg GR1 ], [| B |], Some GE, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SHLADD Instruction Test (1)`` () =
    "08AAAAAD"
    ++ (SHLADD ** [ O.Reg GR10; O.Sat 2UL; O.Reg GR5; O.Reg GR13 ], [| L |],
    Some DZNV, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SHLADD Instruction Test (2)`` () =
    "08FFAA58"
    ++ (SHLADD ** [ O.Reg GR31; O.Sat 1UL; O.Reg GR7; O.Reg GR24 ], [| L |],
    Some ZNV, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] HSHRADD Instruction Test (1)`` () =
    "09555541"
    ++ (HSHRADD ** [ O.Reg GR21; O.Sat 1UL; O.Reg GR10; O.Reg GR1 ], [||],
    None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] ANDCM Instruction Test (1)`` () =
    "0AAA003F"
    ++ (ANDCM ** [ O.Reg GR10; O.Reg GR21; O.Reg GR31 ], [||], Some DNEVER,
    None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] ADDI Instruction Test (1)`` () =
    "B1FFFFF7"
    ++ (ADDI ** [ O.Imm 0xFFFFFFFFFFFFFFFBUL; O.Reg GR15; O.Reg GR31 ],
    [| TSV; TC |], Some EV, None)
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type LoadStoreClass () =
  [<TestMethod>]
  member _.``[PARISC64] LDWA Instruction Test (1)`` () =
    "0CAA5584"
    ++ (LDWA ** [ O.Mem (GR5, 5L, 64<rt>); O.Reg GR4 ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] LDWA Instruction Test (2)`` () =
    "0D0055B5"
    ++ (LDWA ** [ O.Mem (GR8, 0L, 64<rt>); O.Reg GR21 ], [| Completer.O |],
    None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] LDWA Instruction Test (3)`` () =
    "0DAA55AF"
    ++ (LDWA ** [ O.Mem (GR13, 5L, 64<rt>); O.Reg GR15 ], [| MA |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] STWA Instruction Test (1)`` () =
    "0CFFFFBB"
    ++ (STWA ** [ O.Reg GR31; O.Mem (GR7, -3L, 64<rt>) ], [| MB |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] STWA Instruction Test (2)`` () =
    "0DFFFF90"
    ++ (STWA ** [ O.Reg GR31; O.Mem (GR15, 8L, 64<rt>) ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] LDDA Instruction Test (1)`` () =
    "0D555507"
    ++ (LDDA ** [ O.Mem (GR10, -6L, 64<rt>); O.Reg GR7 ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] LDDA Instruction Test (2)`` () =
    "0F555538"
    ++ (LDDA ** [ O.Mem (GR26, -6L, 64<rt>); O.Reg GR24 ], [| MA |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] STDA Instruction Test (1)`` () =
    "0EFFFFE4"
    ++ (STDA ** [ O.Reg GR31; O.Mem (GR23, 2L, 64<rt>) ], [| MB |], None, None)
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type LoadStoreOffsetClass () =
  [<TestMethod>]
  member _.``[PARISC64] LDO Instruction Test (1)`` () =
    "36AAFFFB"
    ++ (LDO ** [ O.Mem (GR21, -3L, 64<rt>); O.Reg GR10 ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] LDB Instruction Test (1)`` () =
    "40FF000C"
    ++ (LDB ** [ O.Mem (GR7, 6L, 64<rt>, SR0); O.Reg GR31 ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] LDW Instruction Test (1)`` () =
    "4B550012"
    ++ (LDW ** [ O.Mem (GR26, 9L, 64<rt>, SR0); O.Reg GR21 ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] STB Instruction Test (1)`` () =
    "60FF000A"
    ++ (STB ** [ O.Reg GR31; O.Mem (GR7, 5L, 64<rt>, SR0) ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] STH Instruction Test (1)`` () =
    "65FF0002"
    ++ (STH ** [ O.Reg GR31; O.Mem (GR15, 1L, 64<rt>, SR0) ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] STW Instruction Test (1)`` () =
    "6AAA0010"
    ++ (STW ** [ O.Reg GR10; O.Mem (GR21, 8L, 64<rt>, SR0) ], [||], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] STW Instruction Test (2)`` () =
    "6CFF0004"
    ++ (STW ** [ O.Reg GR31; O.Mem (GR7, 2L, 64<rt>, SR0) ], [| MA |], None,
    None)
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type LoadStoreWordClass () =
  [<TestMethod>]
  member _.``[PARISC64] FLDW Instruction Test (1)`` () =
    "5AFF000C"
    ++ (FLDW ** [ O.Mem (GR23, 4L, 64<rt>, SR0); O.Reg FPR31 ], [| MB |], None,
    None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FSTD Instruction Test (1)`` () =
    "70550012"
    ++ (FSTD ** [ O.Reg FPR21; O.Mem (GR2, 8L, 64<rt>, SR0) ], [||], None, None)
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type CorpLoadClass () =
  [<TestMethod>]
  member _.``[PARISC64] CLDD Instruction Test (1)`` () =
    "2D0010FE"
    ++ (CLDD ** [ O.Mem (GR8, 0L, 64<rt>, SR0); O.Reg GR30 ], [| Completer.O |],
    None, Some [| 3UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] CLDD Instruction Test (2)`` () =
    "2E0010D0"
    ++ (CLDD ** [ O.Mem (GR16, 0L, 64<rt>, SR0); O.Reg GR16 ], [||], None,
    Some [| 3UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] CLDD Instruction Test (3)`` () =
    "2F000041"
    ++ (CLDD ** [ O.Mem (GR24, GR0, 64<rt>, SR0); O.Reg GR1 ], [||], None,
    Some [| 1UL |])
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type CorpFPClass () =
  [<TestMethod>]
  member _.``[PARISC64] FCNV Instruction Test (1)`` () =
    "3055AA06"
    ++ (FCNV ** [ O.Reg FPR2; O.Reg FPR6 ], [| T; DBL; DW |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FCNV Instruction Test (2)`` () =
    "32AAAA29"
    ++ (FCNV ** [ O.Reg FPR21; O.Reg FPR9 ], [| UDW; DBL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FCNV Instruction Test (3)`` () =
    "3300AA37"
    ++ (FCNV ** [ O.Reg FPR24; O.Reg FPR23 ], [| DW; DBL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FCMP Instruction Test (1)`` () =
    "3800557F"
    ++ (FCMP ** [ O.Reg FPR0; O.Reg FPR0 ], [| SGL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FCMP Instruction Test (2)`` () =
    "38AA5501"
    ++ (FCMP ** [ O.Reg FPR5; O.Reg FPR10 ], [| SGL |], Some ACC, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FCMP Instruction Test (3)`` () =
    "3A005529"
    ++ (FCMP ** [ O.Reg FPR16; O.Reg FPR0 ], [| SGL |], Some ACC6, None)
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type SpecialClass () =
  [<TestMethod>]
  member _.``[PARISC64] SPOP1 Instruction Test (1)`` () =
    "1000AAF7"
    ++ (SPOP1 ** [ O.Reg GR23 ], [| N |], None, Some [| 3UL; 21UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SPOP1 Instruction Test (2)`` () =
    "1055AAC2"
    ++ (SPOP1 ** [ O.Reg GR2 ], [||], None, Some [| 3UL; 2741UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SPOP1 Instruction Test (3)`` () =
    "10AAAAEB"
    ++ (SPOP1 ** [ O.Reg GR11 ], [| N |], None, Some [| 3UL; 5461UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SPOP2 Instruction Test (1)`` () =
    "10555535"
    ++ (SPOP2 ** [ O.Reg GR2 ], [| N |], None, Some [| 4UL; 21845UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SPOP2 Instruction Test (2)`` () =
    "10AA554D"
    ++ (SPOP2 ** [ O.Reg GR5 ], [||], None, Some [| 5UL; 10573UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SPOP2 Instruction Test (3)`` () =
    "10FF55DA"
    ++ (SPOP2 ** [ O.Reg GR7 ], [||], None, Some [| 7UL; 32090UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SPOP3 Instruction Test (1)`` () =
    "1055FFA2"
    ++ (SPOP3 ** [ O.Reg GR21; O.Reg GR2 ], [| N |], None,
    Some [| 6UL; 994UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SPOP3 Instruction Test (2)`` () =
    "10AAFF4D"
    ++ (SPOP3 ** [ O.Reg GR10; O.Reg GR5 ], [||], None, Some [| 5UL; 1005UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SPOP3 Instruction Test (3)`` () =
    "10FFFF76"
    ++ (SPOP3 ** [ O.Reg GR31; O.Reg GR7 ], [| N |], None,
    Some [| 5UL; 1014UL |])
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type MultipleClass () =
  [<TestMethod>]
  member _.``[PARISC64] FMPYADD Instruction Test (1)`` () =
    "180000D7"
    ++ (FMPYADD ** [ O.Reg FPR0
                     O.Reg FPR0
                     O.Reg FPR23
                     O.Reg FPR3
                     O.Reg FPR0 ], [| DBL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FMPYADD Instruction Test (2)`` () =
    "180055E3"
    ++ (FMPYADD ** [ O.Reg FPR0
                     O.Reg FPR0
                     O.Reg FPR3
                     O.Reg FPR23
                     O.Reg FPR10 ], [| SGL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FMPYSUB Instruction Test (1)`` () =
    "98000040"
    ++ (FMPYSUB ** [ O.Reg FPR0
                     O.Reg FPR0
                     O.Reg FPR0
                     O.Reg FPR1
                     O.Reg FPR0 ], [| DBL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FMPYSUB Instruction Test (2)`` () =
    "980055E7"
    ++ (FMPYSUB ** [ O.Reg FPR0
                     O.Reg FPR0
                     O.Reg FPR7
                     O.Reg FPR23
                     O.Reg FPR10 ], [| SGL |], None, None)
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type FPFusedClass () =
  [<TestMethod>]
  member _.``[PARISC64] FMPYFADD Instruction Test (1)`` () =
    "B80000C8"
    ++ (FMPYFADD ** [ O.Reg FPR0; O.Reg FPR0; O.Reg FPR0; O.Reg FPR8 ],
    [| SGL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FMPYFADD Instruction Test (2)`` () =
    "B800AA82"
    ++ (FMPYFADD ** [ O.Reg FPR0; O.Reg FPR0; O.Reg FPR21; O.Reg FPR2 ],
    [| DBL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FMPYNFADD Instruction Test (1)`` () =
    "B855AA32"
    ++ (FMPYNFADD ** [ O.Reg FPR2; O.Reg FPR21; O.Reg FPR21; O.Reg FPR18 ],
    [| DBL |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] FMPYNFADD Instruction Test (2)`` () =
    "B8FF0024"
    ++ (FMPYNFADD ** [ O.Reg FPR7; O.Reg FPR31; O.Reg FPR0; O.Reg FPR4 ],
    [| SGL |], None, None)
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type ShiftDepositClass () =
  [<TestMethod>]
  member _.``[PARISC64] SHRPW Instruction Test (1)`` () =
    "D05500F5"
    ++ (SHRPW ** [ O.Reg GR21; O.Reg GR2; O.Reg CR11; O.Reg GR21 ], [||],
    Some NEVER, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] SHRPW Instruction Test (2)`` () =
    "D1FFAAF2"
    ++ (SHRPW ** [ O.Reg GR31; O.Reg GR15; O.Sat 8UL; O.Reg GR18 ], [||],
    Some NEQ, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] EXTRW Instruction Test (1)`` () =
    "D055553C"
    ++ (EXTRW ** [ O.Reg GR2; O.Reg CR11; O.Imm 4UL; O.Reg GR21 ], [| S |],
    Some LT, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] DEPW Instruction Test (1)`` () =
    "D4AAAAFD"
    ++ (DEPW ** [ O.Reg GR10; O.Sat 8UL; O.Imm 3UL; O.Reg GR5 ], [| Z |],
    Some NEQ, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] DEPW Instruction Test (2)`` () =
    "D4FF001E"
    ++ (DEPW ** [ O.Reg GR31; O.Reg CR11; O.Imm 2UL; O.Reg GR7 ], [| Z |],
    Some DNEVER, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] DEPWI Instruction Test (1)`` () =
    "D4FFFF9F"
    ++ (DEPWI ** [ O.Imm 0xFFFFFFFFFFFFFFFFUL
                   O.Sat 3UL
                   O.Imm 1UL
                   O.Reg GR7 ], [||], Some EV, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] EXTRD Instruction Test (1)`` () =
    "D8FF007D"
    ++ (EXTRD ** [ O.Reg GR7; O.Imm 3UL; O.Imm 3UL; O.Reg GR31 ], [| U |],
    Some DNEVER, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] DEPD Instruction Test (1)`` () =
    "F055AAF8"
    ++ (DEPD ** [ O.Reg GR21; O.Sat 8UL; O.Imm 8UL; O.Reg GR2 ], [| Z |],
    Some DNEQ, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] DEPDI Instruction Test (1)`` () =
    "F5FFAAD8"
    ++ (DEPDI ** [ O.Imm 0xFFFFFFFFFFFFFFFFUL
                   O.Sat 9UL
                   O.Imm 8UL
                   O.Reg GR15 ], [| Z |], Some DNEQ, None)
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type MultimediaClass () =
  [<TestMethod>]
  member _.``[PARISC64] PERMH Instruction Test (1)`` () =
    "F85500E9"
    ++ (PERMH ** [ O.Reg GR2; O.Reg GR9 ], [||], None, Some [| 3UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] PERMH Instruction Test (2)`` () =
    "F85555F9"
    ++ (PERMH ** [ O.Reg GR2; O.Reg GR25 ], [||], None, Some [| 2113UL |])
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] PERMH Instruction Test (3)`` () =
    "F8AA0031"
    ++ (PERMH ** [ O.Reg GR5; O.Reg GR17 ], [||], None, Some [| 0UL |])
    ||> testPARISC WordSize.Bit64

[<TestClass>]
type CondBranchClass () =
  [<TestMethod>]
  member _.``[PARISC64] CMPB Instruction Test (1)`` () =
    "8A55FFFF"
    ++ (CMPB ** [ O.Reg GR21; O.Reg GR18; O.Imm 4UL ], [| EV |], Some N, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] ADDB Instruction Test (1)`` () =
    "AA09FFFF"
    ++ (ADDB ** [ O.Reg GR9; O.Reg GR16; O.Imm 4UL ], [| EV |], Some N, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] ADDB Instruction Test (2)`` () =
    "AA9EFFFD"
    ++ (ADDB ** [ O.Reg GR30; O.Reg GR20; O.Imm 4UL ], [| EV |], None, None)
    ||> testPARISC WordSize.Bit64

  [<TestMethod>]
  member _.``[PARISC64] ADDB Instruction Test (3)`` () =
    "AAFD0002"
    ++ (ADDB ** [ O.Reg GR29; O.Reg GR23; O.Imm 8UL ], [| TR |], Some N, None)
    ||> testPARISC WordSize.Bit64

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

namespace B2R2.FrontEnd.MIPS.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.MIPS
open type Opcode
open type Register

/// Shortcut for creating operands.
[<AutoOpen>]
module private MIPS64Shortcut =
  type O =
    static member Reg (r) =
      OpReg r

    static member Imm (v) =
      OpImm v

    static member Mem (r, o: int64, rt) =
      OpMem (r, Imm o, rt)

    static member Mem (r, o, rt) =
      OpMem (r, Reg o, rt)

    static member Addr (t) =
      OpAddr t

    static member Shift (s)  =
      OpShiftAmount s

[<TestClass>]
type MIPS64ParserTests () =
  let test arch endian opcode (oprs: Operands) (bytes: byte[]) =
    let isa = ISA.Init arch endian
    let reader = BinReader.Init endian
    let parser = MIPSParser (isa, reader) :> IInstructionParsable
    let span = System.ReadOnlySpan bytes
    let ins = parser.Parse (span, 0UL) :?> MIPSInstruction
    let opcode' = ins.Info.Opcode
    let oprs' = ins.Info.Operands
    Assert.AreEqual<Opcode> (opcode, opcode')
    Assert.AreEqual<Operands> (oprs, oprs')

  let test64R2 (bytes: byte[]) (opcode, operands) =
    test Architecture.MIPS64 Endian.Big opcode operands bytes

  let operandsFromArray oprList =
    let oprArray = Array.ofList oprList
    match oprArray.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArray[0]
    | 2 -> TwoOperands (oprArray[0], oprArray[1])
    | 3 -> ThreeOperands (oprArray[0], oprArray[1], oprArray[2])
    | 4 -> FourOperands (oprArray[0], oprArray[1], oprArray[2], oprArray[3])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

  let ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

  [<TestMethod>]
  member _.``[MIPS64] Arithmetic operations Parse Test (1)`` () =
    "02bd782d"
    ++ DADDU ** [ O.Reg R15; O.Reg R21; O.Reg R29 ]
    ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Arithmetic operations Parse Test (2)`` () =
    "64cdccd5"
      ++ DADDIU ** [ O.Reg R13; O.Reg R6; O.Imm 0xffffffffffffccd5UL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Arithmetic operations Parse Test (3)`` () =
      "0229d02f"
      ++ DSUBU ** [ O.Reg R26; O.Reg R17; O.Reg R9 ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (1)`` () =
      "002df6ba"
      ++ DROTR ** [ O.Reg R30; O.Reg R13; O.Shift 0x1aUL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (2)`` () =
      "000eeef8"
      ++ DSLL ** [ O.Reg R29; O.Reg R14; O.Shift 0x1bUL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (3)`` () =
      "0011e57c"
      ++ DSLL32 ** [ O.Reg R28; O.Reg R17; O.Shift 0x15UL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (4)`` () =
      "02baf014"
      ++ DSLLV ** [ O.Reg R30; O.Reg R26; O.Reg R21 ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (5)`` () =
      "000ef7fb"
      ++ DSRA ** [ O.Reg R30; O.Reg R14; O.Shift 0x1fUL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Shift And Rotate operations Parse Test (6)`` () =
      "000fd1ff"
      ++ DSRA32 ** [ O.Reg R26; O.Reg R15; O.Shift 0x7UL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Logical and Bit-Field operations Parse Test (1)`` () =
    "7d5d6883"
      ++ DEXT ** [ O.Reg R29; O.Reg R10; O.Imm 0x2UL; O.Imm 0xeUL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Logical and Bit-Field operations Parse Test (2)`` () =
    "7df5ca47"
      ++ DINS ** [ O.Reg R21; O.Reg R15; O.Imm 0x9UL; O.Imm 0x11UL ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Multiply and Divide operations Parse Test (1)`` () =
    "03c3001f"
      ++ DDIVU ** [ O.Reg R30; O.Reg R3 ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Multiply and Divide operations Parse Test (2)`` () =
    "030e001c"
      ++ DMULT ** [ O.Reg R24; O.Reg R14 ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Multiply and Divide operations Parse Test (3)`` () =
    "0232001d"
      ++ DMULTU ** [ O.Reg R17; O.Reg R18 ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (1)`` () =
   "df5d2afd"
     ++ LD ** [ O.Reg R29; O.Mem (R26, 0x2afdL, 64<rt>) ]
     ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (2)`` () =
    "9f11ad01"
      ++ LWU ** [ O.Reg R17; O.Mem (R24, -0x52ffL, 32<rt>) ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (3)`` () =
    "fe25380a"
      ++ SD ** [ O.Reg R5; O.Mem (R.R17, 0x380aL, 64<rt>) ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (4)`` () =
    "b34c3f02"
      ++ SDL ** [ O.Reg R12; O.Mem (R26, 0x3f02L, 64<rt>) ]
      ||> test64R2

  [<TestMethod>]
  member _.``[MIPS64] Load and Store operations Parse Test (5)`` () =
    "b4cb8715"
      ++ SDR ** [ O.Reg R11; O.Mem (R6, -0x78ebL, 64<rt>) ]
      ||> test64R2

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

module B2R2.FrontEnd.Tests.MIPS32

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter.MIPS
open type Opcode
open type Register

type O =
  static member Reg (r) =
    OpReg r

  static member Imm (v) =
    OpImm v

  static member Mem (r, o: int64, rt) =
    OpMem (r, Imm o, rt)

  static member Mem (r, o: Register, rt) =
    OpMem (r, Reg o, rt)

  static member Addr (t) =
    OpAddr t

  static member Shift (s)  =
    OpShiftAmount s

let private test arch endian opcode cond fmt oprs (bytes: byte[]) =
  let reader = BinReader.Init endian
  let span = System.ReadOnlySpan bytes
  let ins = ParsingMain.parse span reader arch WordSize.Bit32 0UL
  let opcode' = ins.Info.Opcode
  let cond' = ins.Info.Condition
  let fmt' = ins.Info.Fmt
  let oprs' = ins.Info.Operands
  Assert.AreEqual (opcode', opcode)
  Assert.AreEqual (cond', cond)
  Assert.AreEqual (fmt', fmt)
  Assert.AreEqual (oprs', oprs)

let private test32R2 cond fmt (bs: byte[]) (opcode, operands) =
  test Architecture.MIPS32 Endian.Big opcode (Some cond) (Some fmt) operands bs

let private test32R2NoCond fmt (bytes: byte[]) (opcode, operands) =
  test Architecture.MIPS32 Endian.Big opcode None (Some fmt) operands bytes

let private test32R2NoCondNofmt (bytes: byte[]) (opcode, operands) =
  test Architecture.MIPS32 Endian.Big  opcode None None operands bytes

let private operandsFromArray oprList =
  let oprArray = Array.ofList oprList
  match oprArray.Length with
  | 0 -> NoOperand
  | 1 -> OneOperand oprArray[0]
  | 2 -> TwoOperands (oprArray[0], oprArray[1])
  | 3 -> ThreeOperands (oprArray[0], oprArray[1], oprArray[2])
  | 4 -> FourOperands (oprArray[0], oprArray[1], oprArray[2], oprArray[3])
  | _ -> Utils.impossible ()

let private ( ** ) opcode oprList = (opcode, operandsFromArray oprList)

let private ( ++ ) byteString pair = (ByteArray.ofHexString byteString, pair)

/// Arithmetic Operations
[<TestClass>]
type ArithmeticClass () =
  [<TestMethod>]
  member __.``[MIPS32] Arithmetic Operations Parse Test (1)`` () =
    "279c85bc"
    ++ ADDIU ** [ O.Reg R28; O.Reg R28; O.Imm 0xffffffffffff85bcUL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Arithmetic Operations Parse Test (2)`` () =
    "70e21020"
    ++ CLZ ** [ O.Reg R2; O.Reg R7 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Arithmetic Operations Parse Test (3)`` () =
    "3c1c0004"
    ++ LUI ** [ O.Reg R28; O.Imm 4UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Arithmetic Operations Parse Test (4)`` () =
    "7c0a5420"
    ++ SEB ** [ O.Reg R10; O.Reg R10 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Arithmetic Operations Parse Test (5)`` () =
    "02131023"
    ++ SUBU ** [ O.Reg R2; O.Reg R16; O.Reg R19 ]
    ||> test32R2NoCondNofmt

/// Shift And Rotate Operations
[<TestClass>]
type ShiftAndRotateClass () =
  [<TestMethod>]
  member __.``[MIPS32] Shift And Rotate Operations Parse Test (1)`` () =
    "002410c2"
    ++ ROTR ** [ O.Reg R2; O.Reg R4; O.Shift 3UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Shift And Rotate Operations Parse Test (2)`` () =
    "00021080"
    ++ SLL ** [ O.Reg R2; O.Reg R2; O.Shift 2UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Shift And Rotate Operations Parse Test (3)`` () =
    "00052883"
    ++ SRA ** [ O.Reg R5; O.Reg R5; O.Shift 2UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Shift And Rotate Operations Parse Test (4)`` () =
    "000517c2"
    ++ SRL ** [ O.Reg R2; O.Reg R5; O.Shift 31UL ]
    ||> test32R2NoCondNofmt

/// Logical And Bit-Field Operations
[<TestClass>]
type LogicalAndBitFieldClass () =
  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (1)`` () =
    "02621024"
    ++ AND ** [ O.Reg R2; O.Reg R19; O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (2)`` () =
    "30420001"
    ++ ANDI ** [ O.Reg R2; O.Reg R2; O.Imm 1UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (3)`` () =
    "7c420180"
    ++ EXT ** [ O.Reg R2; O.Reg R2; O.Imm 6UL; O.Imm 1UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (4)`` () =
    "7cc33184"
    ++ INS ** [ O.Reg R3; O.Reg R6; O.Imm 6UL; O.Imm 1UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (5)`` () =
    "00063027"
    ++ NOR ** [ O.Reg R6; O.Reg R0; O.Reg R6 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (6)`` () =
    "00609825"
    ++ OR ** [ O.Reg R19; O.Reg R3; O.Reg R0 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (7)`` () =
    "3673ffff"
    ++ ORI ** [ O.Reg R19; O.Reg R19; O.Imm 65535UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (8)`` () =
    "00461026"
    ++ XOR ** [ O.Reg R2; O.Reg R2; O.Reg R6 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Logical And Bit-Field operations Parse Test (9)`` () =
    "3a620006"
    ++ XORI ** [ O.Reg R2; O.Reg R19; O.Imm 6UL ]
    ||> test32R2NoCondNofmt

/// Condition Testing And Conditional Move Operations
[<TestClass>]
type CondTestAndCondMoveClass () =
  [<TestMethod>]
  member __.``[MIPS32] Condition Testing And .. Operations Parse Test (1)`` () =
    "0082180b"
    ++ MOVN ** [ O.Reg R3; O.Reg R4; O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Condition Testing And .. Operations Parse Test (2)`` () =
    "0005100a"
    ++ MOVZ ** [ O.Reg R2; O.Reg R0; O.Reg R5 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Condition Testing And .. Operations Parse Test (3)`` () =
    "0270102a"
    ++ SLT ** [ O.Reg R2; O.Reg R19; O.Reg R16 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Condition Testing And .. Operations Parse Test (4)`` () =
    "28570002"
    ++ SLTI ** [ O.Reg R23; O.Reg R2; O.Imm 2UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Condition Testing And .. Operations Parse Test (5)`` () =
    "2c430113"
    ++ SLTIU ** [ O.Reg R3; O.Reg R2; O.Imm 275UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Condition Testing And .. Operations Parse Test (6)`` () =
    "0002102b"
    ++ SLTU ** [ O.Reg R2; O.Reg R0; O.Reg R2 ]
    ||> test32R2NoCondNofmt

/// Multiply and Divide operations
[<TestClass>]
type MultiplyAndDivideClass () =
  [<TestMethod>]
  member __.``[MIPS32] Multiply and Divide operations Parse Test (1)`` () =
    "0062001b"
    ++ DIVU ** [ O.Reg R3; O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Multiply and Divide operations Parse Test (2)`` () =
    "70881802"
    ++ MUL ** [ O.Reg R3; O.Reg R4; O.Reg R8 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Multiply and Divide operations Parse Test (3)`` () =
    "02e50019"
    ++ MULTU ** [ O.Reg R23; O.Reg R5 ]
    ||> test32R2NoCondNofmt

/// Accumulator Access operations
[<TestClass>]
type AccumulatorAccessClass () =
  [<TestMethod>]
  member __.``[MIPS32] Accumulator Access operations Parse Test (1)`` () =
    "00001010"
    ++ MFHI ** [ O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Accumulator Access operations Parse Test (2)`` () =
    "00001812"
    ++ MFLO ** [ O.Reg R3 ]
    ||> test32R2NoCondNofmt

/// Jumps And Branches Operations
[<TestClass>]
type JumpAndBranchesClass () =
  [<TestMethod>]
  member __.``[MIPS32] Jump And Branches operations Parse Test (1)`` () =
    "14400400"
    ++ BNE ** [ O.Reg R2; O.Reg R0; O.Addr (Relative 4100L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Jump And Branches operations Parse Test (2)`` () =
    "1ae00456"
    ++ BLEZ ** [ O.Reg R23; O.Addr (Relative 4444L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Jump And Branches operations Parse Test (3)`` () =
    "1c40fff3"
    ++ BGTZ ** [ O.Reg R2; O.Addr (Relative -48L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Jump And Branches operations Parse Test (4)`` () =
    "03e00008"
    ++ JR ** [ O.Reg R31 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Jump And Branches operations Parse Test (5)`` () =
    "0320f809"
    ++ JALR ** [ O.Reg R25 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Jump And Branches operations Parse Test (6)`` () =
    "04113e1d"
    ++ BAL ** [ O.Addr (Relative 63608L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Jump And Branches operations Parse Test (7)`` () =
    "04400069"
    ++ BLTZ ** [ O.Reg R2; O.Addr (Relative 424L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Jump And Branches operations Parse Test (8)`` () =
    "06c1015e"
    ++ BGEZ ** [ O.Reg R22; O.Addr (Relative 1404L) ]
    ||> test32R2NoCondNofmt

/// Load And Store operations
[<TestClass>]
type LoadAndStoreClass () =
  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (1)`` () =
    "80420000"
    ++ LB ** [ O.Reg R2; O.Mem (R.R2, 0L, 8<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (2)`` () =
    "92624418"
    ++ LBU ** [ O.Reg R2; O.Mem (R.R19, 17432L, 8<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (3)`` () =
    "97a200aa"
    ++ LHU ** [ O.Reg R2; O.Mem (R.R29, 170L, 16<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (4)`` () =
    "8f8282c4"
    ++ LW ** [ O.Reg R2; O.Mem (R.R28, -032060L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (5)`` () =
    "a2c443dc"
    ++ SB ** [ O.Reg R4; O.Mem (R.R22, 17372L, 8<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (6)`` () =
    "a7a200b8"
    ++ SH ** [ O.Reg R2; O.Mem (R.R29, 184L, 16<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (7)`` () =
    "afbc0010"
    ++ SW ** [ O.Reg R28; O.Mem (R.R29, 16L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (8)`` () =
    "a8440000"
    ++ SWL ** [ O.Reg R4; O.Mem (R.R2, 0L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Load And Store operations Parse Test (9)`` () =
    "b8440003"
    ++ SWR ** [ O.Reg R4; O.Mem (R.R2, 3L, 32<rt>) ]
    ||> test32R2NoCondNofmt

/// Floating Point operations
[<TestClass>]
type FloatingPointClass () =
  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (1)`` () =
    "46022080"
    ++ ADD ** [ O.Reg F2; O.Reg F4; O.Reg F2 ]
    ||> test32R2NoCond Fmt.S

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (2)`` () =
    "46220000"
    ++ ADD ** [ O.Reg F0; O.Reg F0; O.Reg F2 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (3)`` () =
    "46206301"
    ++ SUB ** [ O.Reg F12; O.Reg F12; O.Reg F0 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (4)`` () =
    "46220003"
    ++ DIV ** [ O.Reg F0; O.Reg F0; O.Reg F2 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (5)`` () =
    "46020003"
    ++ DIV ** [ O.Reg F0; O.Reg F0; O.Reg F2 ]
    ||> test32R2NoCond Fmt.S

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (6)`` () =
    "46200506"
    ++ MOV ** [ O.Reg F20; O.Reg F0 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (7)`` () =
    "44140000"
    ++ MFC1 ** [ O.Reg R20; O.Reg F0 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (8)`` () =
    "44803000"
    ++ MTC1 ** [ O.Reg R0; O.Reg F6 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (9)`` () =
    "d4440a48"
    ++ LDC1 ** [ O.Reg F4; O.Mem (R.R2, 2632L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (10)`` () =
    "c4600008"
    ++ LWC1 ** [ O.Reg F0; O.Mem (R.R3, 8L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (11)`` () =
    "f7a00010"
    ++ SDC1 ** [ O.Reg F0; O.Mem (R.R29, 16L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (12)`` () =
    "e4800004"
    ++ SWC1 ** [ O.Reg F0; O.Mem (R.R4, 4L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (13)`` () =
    "4600103c"
    ++ C ** [ O.Reg F2; O.Reg F0 ]
    ||> test32R2 Condition.LT Fmt.S

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (14)`` () =
    "46800021"
    ++ CVTD ** [ O.Reg F0; O.Reg F0 ]
    ||> test32R2NoCond Fmt.W

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (15)`` () =
    "46200020"
    ++ CVTS ** [ O.Reg F0; O.Reg F0 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (16)`` () =
    "4620000d"
    ++ TRUNCW ** [ O.Reg F0; O.Reg F0 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member __.``[MIPS32] Floating Point operations Parse Test (17)`` () =
    "4600000d"
    ++ TRUNCW ** [ O.Reg F0; O.Reg F0 ]
    ||> test32R2NoCond Fmt.S

/// ETC Operations
[<TestClass>]
type ETCClass () =
  [<TestMethod>]
  member __.``[MIPS32] ETC Operations Parse Test (1)`` () =
    "004001f4"
    ++ TEQ ** [ O.Reg R2; O.Reg R0 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] ETC Operations Parse Test (2)`` () =
    "45190004"
    ++ BC1T ** [ O.Imm 6UL; O.Addr (Relative 20L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member __.``[MIPS32] ETC Operations Parse Test (3)`` () =
    "4500001a"
    ++ BC1F ** [ O.Addr (Relative 108L) ]
    ||> test32R2NoCondNofmt

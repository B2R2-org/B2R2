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
module private MIPS32Shortcut =
  type O =
    static member Reg(r) = OpReg r

    static member Imm(v) = OpImm v

    static member Mem(r, o: int64, rt) = OpMem(r, Imm o, rt)

    static member Mem(r, o, rt) = OpMem(r, Reg o, rt)

    static member Addr(t) = OpAddr t

    static member Shift(s) = OpShiftAmount s

[<TestClass>]
type MIPS32ParserTests() =
  let test endian opcode cond fmt (oprs: Operands) (bytes: byte[]) =
    let isa = ISA(Architecture.MIPS, endian, WordSize.Bit32)
    let reader = BinReader.Init endian
    let parser = Parser(isa, reader) :> IInstructionParsable
    let span = System.ReadOnlySpan bytes
    let ins = parser.Parse(span, 0UL) :?> Instruction
    let opcode' = ins.Opcode
    let cond' = ins.Condition
    let fmt' = ins.Fmt
    let oprs' = ins.Operands
    Assert.AreEqual<Opcode>(opcode, opcode')
    Assert.AreEqual<Condition option>(cond, cond')
    Assert.AreEqual<Fmt option>(fmt, fmt')
    Assert.AreEqual<Operands>(oprs, oprs')

  let test32R2 cond fmt (bs: byte[]) (opcode, oprs) =
    test Endian.Big opcode (Some cond) (Some fmt) oprs bs

  let test32R2NoCond fmt (bytes: byte[]) (opcode, oprs) =
    test Endian.Big opcode None (Some fmt) oprs bytes

  let test32R2NoCondNofmt (bytes: byte[]) (opcode, oprs) =
    test Endian.Big opcode None None oprs bytes

  let operandsFromArray oprList =
    let oprArray = Array.ofList oprList
    match oprArray.Length with
    | 0 -> NoOperand
    | 1 -> OneOperand oprArray[0]
    | 2 -> TwoOperands(oprArray[0], oprArray[1])
    | 3 -> ThreeOperands(oprArray[0], oprArray[1], oprArray[2])
    | 4 -> FourOperands(oprArray[0], oprArray[1], oprArray[2], oprArray[3])
    | _ -> Terminator.impossible ()

  let ( ** ) opcode oprList = opcode, operandsFromArray oprList

  let ( ++ ) byteString pair = ByteArray.ofHexString byteString, pair

  let isaMIPS16 =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit32,
        int MIPSISAMode.MIPS16)

  let disasmMIPS16 (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser =
      Parser(isaMIPS16, BinReader.Init isaMIPS16.Endian)
      :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  let isaMIPS16x64 =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MIPS16)

  let disasmMIPS16x64 (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser =
      Parser(isaMIPS16x64, BinReader.Init isaMIPS16x64.Endian)
      :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  /// MD00087 gives each instruction's availability to the right of its
  /// Format line, and for the whole doubleword family the field reads
  /// MIPS64. MIPS32 has no such instruction, so a word holding one of
  /// those encodings is a Reserved Instruction there and the parser has
  /// to refuse it. The same bytes ARE an instruction at the 64-bit word
  /// size, which is what makes this a property of the ISA rather than of
  /// the encoding.
  [<TestMethod>]
  member _.``[MIPS32] A MIPS64 instruction is not one at this width``() =
    let words =
      [ "012a402c", DADD
        "012a402d", DADDU
        "012a402e", DSUB
        "012a402f", DSUBU
        "000a4038", DSLL
        "7c0a4024", DBITSWAP
        "dd290000", LD
        "fd290000", SD
        "9d290000", LWU ]
    let parserAt wordSize =
      let isa = ISA(Architecture.MIPS, Endian.Big, wordSize)
      Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let parser32 = parserAt WordSize.Bit32
    let parser64 = parserAt WordSize.Bit64
    for hex, opcode in words do
      let bytes = ByteArray.ofHexString hex
      let ins = parser64.Parse(System.ReadOnlySpan bytes, 0UL)
      Assert.AreEqual<Opcode>(opcode, (ins :?> Instruction).Opcode, hex)
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parser32.Parse(System.ReadOnlySpan bytes, 0UL) |> ignore) |> ignore

  /// The same field, read for the paired-single format and for the two
  /// unaligned moves that serve it, reads "MIPS64, MIPS32 Release 2". So
  /// these are instructions at this width and the parser has to read them,
  /// which it did not: they had been listed with the doubleword family on
  /// the grounds that a pair is sixty-four bits wide. That is a statement
  /// about FR, which says whether the RESULT is predictable, and not about
  /// whether the encoding names an instruction. LDXC1 beside them moves a
  /// doubleword as well and was always read here.
  [<TestMethod>]
  member _.``[MIPS32] The paired-single family is one at this width``() =
    let words =
      [ "4d2a0005", LUXC1
        "4d2a100d", SUXC1
        "4d24101e", ALNVPS
        "46041026", CVTPSS
        "46c01028", CVTSPL
        "46c01020", CVTSPU
        "46c4102c", PLLPS
        "46c4102d", PLUPS
        "46c4102e", PULPS
        "46c4102f", PUUPS
        "4d2a0001", LDXC1 ]
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32)
    let parser = Parser(isa, BinReader.Init Endian.Big)
                 :> IInstructionParsable
    for hex, opcode in words do
      let bytes = ByteArray.ofHexString hex
      let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL)
      Assert.AreEqual<Opcode>(opcode, (ins :?> Instruction).Opcode, hex)

  [<TestMethod>]
  member _.``[MIPS32] Arithmetic Operations Parse Test (1)``() =
    "279c85bc"
    ++ ADDIU ** [ O.Reg R28; O.Reg R28; O.Imm 0xffffffffffff85bcUL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Arithmetic Operations Parse Test (2)``() =
    "70e21020"
    ++ CLZ ** [ O.Reg R2; O.Reg R7 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Arithmetic Operations Parse Test (3)``() =
    "3c1c0004"
    ++ LUI ** [ O.Reg R28; O.Imm 4UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Arithmetic Operations Parse Test (4)``() =
    "7c0a5420"
    ++ SEB ** [ O.Reg R10; O.Reg R10 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Arithmetic Operations Parse Test (5)``() =
    "02131023"
    ++ SUBU ** [ O.Reg R2; O.Reg R16; O.Reg R19 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Shift And Rotate Operations Parse Test (1)``() =
    "002410c2"
    ++ ROTR ** [ O.Reg R2; O.Reg R4; O.Shift 3UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Shift And Rotate Operations Parse Test (2)``() =
    "00021080"
    ++ SLL ** [ O.Reg R2; O.Reg R2; O.Shift 2UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Shift And Rotate Operations Parse Test (3)``() =
    "00052883"
    ++ SRA ** [ O.Reg R5; O.Reg R5; O.Shift 2UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Shift And Rotate Operations Parse Test (4)``() =
    "000517c2"
    ++ SRL ** [ O.Reg R2; O.Reg R5; O.Shift 31UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (1)``() =
    "02621024"
    ++ AND ** [ O.Reg R2; O.Reg R19; O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (2)``() =
    "30420001"
    ++ ANDI ** [ O.Reg R2; O.Reg R2; O.Imm 1UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (3)``() =
    "7c420180"
    ++ EXT ** [ O.Reg R2; O.Reg R2; O.Imm 6UL; O.Imm 1UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (4)``() =
    "7cc33184"
    ++ INS ** [ O.Reg R3; O.Reg R6; O.Imm 6UL; O.Imm 1UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (5)``() =
    "00063027"
    ++ NOR ** [ O.Reg R6; O.Reg R0; O.Reg R6 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (6)``() =
    "00609825"
    ++ OR ** [ O.Reg R19; O.Reg R3; O.Reg R0 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (7)``() =
    "3673ffff"
    ++ ORI ** [ O.Reg R19; O.Reg R19; O.Imm 65535UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (8)``() =
    "00461026"
    ++ XOR ** [ O.Reg R2; O.Reg R2; O.Reg R6 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Logical And Bit-Field operations Parse Test (9)``() =
    "3a620006"
    ++ XORI ** [ O.Reg R2; O.Reg R19; O.Imm 6UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Condition Testing And .. Operations Parse Test (1)``() =
    "0082180b"
    ++ MOVN ** [ O.Reg R3; O.Reg R4; O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Condition Testing And .. Operations Parse Test (2)``() =
    "0005100a"
    ++ MOVZ ** [ O.Reg R2; O.Reg R0; O.Reg R5 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Condition Testing And .. Operations Parse Test (3)``() =
    "0270102a"
    ++ SLT ** [ O.Reg R2; O.Reg R19; O.Reg R16 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Condition Testing And .. Operations Parse Test (4)``() =
    "28570002"
    ++ SLTI ** [ O.Reg R23; O.Reg R2; O.Imm 2UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Condition Testing And .. Operations Parse Test (5)``() =
    "2c430113"
    ++ SLTIU ** [ O.Reg R3; O.Reg R2; O.Imm 275UL ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Condition Testing And .. Operations Parse Test (6)``() =
    "0002102b"
    ++ SLTU ** [ O.Reg R2; O.Reg R0; O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Multiply and Divide operations Parse Test (1)``() =
    "0062001b"
    ++ DIVU ** [ O.Reg R3; O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Multiply and Divide operations Parse Test (2)``() =
    "70881802"
    ++ MUL ** [ O.Reg R3; O.Reg R4; O.Reg R8 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Multiply and Divide operations Parse Test (3)``() =
    "02e50019"
    ++ MULTU ** [ O.Reg R23; O.Reg R5 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Accumulator Access operations Parse Test (1)``() =
    "00001010"
    ++ MFHI ** [ O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Accumulator Access operations Parse Test (2)``() =
    "00001812"
    ++ MFLO ** [ O.Reg R3 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Jump And Branches operations Parse Test (1)``() =
    "14400400"
    ++ BNE ** [ O.Reg R2; O.Reg R0; O.Addr(Relative 4100L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Jump And Branches operations Parse Test (2)``() =
    "1ae00456"
    ++ BLEZ ** [ O.Reg R23; O.Addr(Relative 4444L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Jump And Branches operations Parse Test (3)``() =
    "1c40fff3"
    ++ BGTZ ** [ O.Reg R2; O.Addr(Relative -48L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Jump And Branches operations Parse Test (4)``() =
    "03e00008"
    ++ JR ** [ O.Reg R31 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Jump And Branches operations Parse Test (5)``() =
    "0320f809"
    ++ JALR ** [ O.Reg R25 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Jump And Branches operations Parse Test (6)``() =
    "04113e1d"
    ++ BAL ** [ O.Addr(Relative 63608L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Jump And Branches operations Parse Test (7)``() =
    "04400069"
    ++ BLTZ ** [ O.Reg R2; O.Addr(Relative 424L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Jump And Branches operations Parse Test (8)``() =
    "06c1015e"
    ++ BGEZ ** [ O.Reg R22; O.Addr(Relative 1404L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (1)``() =
    "80420000"
    ++ LB ** [ O.Reg R2; O.Mem(R.R2, 0L, 8<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (2)``() =
    "92624418"
    ++ LBU ** [ O.Reg R2; O.Mem(R.R19, 17432L, 8<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (3)``() =
    "97a200aa"
    ++ LHU ** [ O.Reg R2; O.Mem(R.R29, 170L, 16<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (4)``() =
    "8f8282c4"
    ++ LW ** [ O.Reg R2; O.Mem(R.R28, -032060L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (5)``() =
    "a2c443dc"
    ++ SB ** [ O.Reg R4; O.Mem(R.R22, 17372L, 8<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (6)``() =
    "a7a200b8"
    ++ SH ** [ O.Reg R2; O.Mem(R.R29, 184L, 16<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (7)``() =
    "afbc0010"
    ++ SW ** [ O.Reg R28; O.Mem(R.R29, 16L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (8)``() =
    "a8440000"
    ++ SWL ** [ O.Reg R4; O.Mem(R.R2, 0L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Load And Store operations Parse Test (9)``() =
    "b8440003"
    ++ SWR ** [ O.Reg R4; O.Mem(R.R2, 3L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (1)``() =
    "46022080"
    ++ ADD ** [ O.Reg F2; O.Reg F4; O.Reg F2 ]
    ||> test32R2NoCond Fmt.S

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (2)``() =
    "46220000"
    ++ ADD ** [ O.Reg F0; O.Reg F0; O.Reg F2 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (3)``() =
    "46206301"
    ++ SUB ** [ O.Reg F12; O.Reg F12; O.Reg F0 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (4)``() =
    "46220003"
    ++ DIV ** [ O.Reg F0; O.Reg F0; O.Reg F2 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (5)``() =
    "46020003"
    ++ DIV ** [ O.Reg F0; O.Reg F0; O.Reg F2 ]
    ||> test32R2NoCond Fmt.S

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (6)``() =
    "46200506"
    ++ MOV ** [ O.Reg F20; O.Reg F0 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (7)``() =
    "44140000"
    ++ MFC1 ** [ O.Reg R20; O.Reg F0 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (8)``() =
    "44803000"
    ++ MTC1 ** [ O.Reg R0; O.Reg F6 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (9)``() =
    "d4440a48"
    ++ LDC1 ** [ O.Reg F4; O.Mem(R.R2, 2632L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (10)``() =
    "c4600008"
    ++ LWC1 ** [ O.Reg F0; O.Mem(R.R3, 8L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (11)``() =
    "f7a00010"
    ++ SDC1 ** [ O.Reg F0; O.Mem(R.R29, 16L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (12)``() =
    "e4800004"
    ++ SWC1 ** [ O.Reg F0; O.Mem(R.R4, 4L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (13)``() =
    "4600103c"
    ++ C ** [ O.Reg F2; O.Reg F0 ]
    ||> test32R2 Condition.LT Fmt.S

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (14)``() =
    "46800021"
    ++ CVTD ** [ O.Reg F0; O.Reg F0 ]
    ||> test32R2NoCond Fmt.W

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (15)``() =
    "46200020"
    ++ CVTS ** [ O.Reg F0; O.Reg F0 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (16)``() =
    "4620000d"
    ++ TRUNCW ** [ O.Reg F0; O.Reg F0 ]
    ||> test32R2NoCond Fmt.D

  [<TestMethod>]
  member _.``[MIPS32] Floating Point operations Parse Test (17)``() =
    "4600000d"
    ++ TRUNCW ** [ O.Reg F0; O.Reg F0 ]
    ||> test32R2NoCond Fmt.S

  [<TestMethod>]
  member _.``[MIPS32] ETC Operations Parse Test (1)``() =
    "004001f4"
    ++ TEQ ** [ O.Reg R2; O.Reg R0 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] ETC Operations Parse Test (2)``() =
    "45190004"
    ++ BC1T ** [ O.Imm 6UL; O.Addr(Relative 20L) ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[MIPS32] ETC Operations Parse Test (3)``() =
    "4500001a"
    ++ BC1F ** [ O.Addr(Relative 108L) ]
    ||> test32R2NoCondNofmt

  /// <summary>
  /// The SmartMIPS ASE, whose words are three of the base architecture's with
  /// the shift-amount field carrying a number.
  ///
  /// MD00101 spends no function code on MULTP, MADDP or PPERM: each is
  /// MULTU's or MADDU's word with five bits the base architecture holds to
  /// zero set to 10001 or 10010. So these rows are as much a test of the
  /// rejection as of the decode -- the same words with a zero there are the
  /// base instructions, which the tests above already assert.
  ///
  /// Every word is what binutils assembles the mnemonic to under
  /// -msmartmips.
  /// </summary>
  [<TestMethod>]
  member _.``[SmartMIPS] The cryptographic instructions Parse Test``() =
    "00430459"
    ++ MULTP ** [ O.Reg R2; O.Reg R3 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[SmartMIPS] The accumulating multiply Parse Test``() =
    "70430441"
    ++ MADDP ** [ O.Reg R2; O.Reg R3 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[SmartMIPS] The partial permutation Parse Test``() =
    "70430481"
    ++ PPERM ** [ O.Reg R2; O.Reg R3 ]
    ||> test32R2NoCondNofmt

  /// <summary>
  /// MIPS16e's extended PC-relative forms read their sixteen bits signed.
  ///
  /// MD00076 says of both extended ADDIU rx, pc and LW rx, offset(pc) that
  /// "The 16-bit immediate is sign-extended"; read unsigned, the address a
  /// compiler formed for a label behind the instruction came out 64 KiB
  /// ahead of it. The word below is the one GCC wrote for a setjmp label,
  /// which binutils reads as la v1, 0x40061d.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS16e] Extended PC offsets are signed``() =
    let isa = ISA "mips16el"
    let parser =
      Parser(isa, BinReader.Init Endian.Little) :> IInstructionParsable
    let bytes = ByteArray.ofHexString "5ff7150b"
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0x4006caUL)
    let la = ins :?> Instruction
    let target = OpAddr(Relative(0x40061dL - 0x4006caL))
    Assert.AreEqual<Opcode>(ADDIUPC, la.Opcode)
    Assert.AreEqual<Operands>(TwoOperands(O.Reg R3, target), la.Operands)

  /// <summary>
  /// An EXTEND in front of an RRR is ASMACRO, whose six fields -- select and
  /// p0 to p4 -- are the implementation's to read (MD00076 ASMACRO). They
  /// come out as the one number the two halfwords make of them, the
  /// prefix's eleven bits above the RRR's.
  /// </summary>
  [<TestMethod>]
  member _.``[MIPS16e] An EXTEND before an RRR is ASMACRO``() =
    let isa = ISA "mips16el"
    let parser =
      Parser(isa, BinReader.Init Endian.Little) :> IInstructionParsable
    let bytes = ByteArray.ofHexString "fff7ffe7"
    let ins = parser.Parse(System.ReadOnlySpan bytes, 0UL) :?> Instruction
    Assert.AreEqual<Opcode>(ASMACRO, ins.Opcode)
    Assert.AreEqual<Operands>(OneOperand(O.Imm 0x3fffffUL), ins.Operands)

  /// SYNCI, REGIMM with rt 11111, makes instructions written to memory the
  /// ones fetched, and Release 2 lets every mode run it (MD00087 SYNCI).
  [<TestMethod>]
  member _.``[MIPS32] SYNCI Parse Test``() =
    "049f0008"
    ++ SYNCI ** [ O.Mem(R.R4, 8L, 32<rt>) ]
    ||> test32R2NoCondNofmt

  /// <summary>
  /// The two that move the extended accumulator, which share MFLO's and
  /// MTLO's function codes with Release 6's DCLZ and DCLO.
  ///
  /// Nothing in either word tells the two apart, so the release does: the ASE
  /// extends MIPS32 before Release 6, and Release 6 is where DCLZ and DCLO
  /// moved into SPECIAL. These are read as the ASE's because the ISA under
  /// test is not Release 6.
  /// </summary>
  [<TestMethod>]
  member _.``[SmartMIPS] The extended accumulator moves Parse Test``() =
    "00001052"
    ++ MFLHXU ** [ O.Reg R2 ]
    ||> test32R2NoCondNofmt

  [<TestMethod>]
  member _.``[SmartMIPS] The extended accumulator load Parse Test``() =
    "00400053"
    ++ MTLHX ** [ O.Reg R2 ]
    ||> test32R2NoCondNofmt

  /// <summary>
  /// LWXS, the one with a function code of its own and the one microMIPS took
  /// into its base encoding. The index counts words, so the operand printed
  /// inside the parentheses is the base and the one outside is the index.
  /// </summary>
  [<TestMethod>]
  member _.``[SmartMIPS] The scaled indexed load Parse Test``() =
    "70831088"
    ++ LWXS ** [ O.Reg R2; O.Mem(R.R4, R.R3, 32<rt>) ]
    ||> test32R2NoCondNofmt

  (* One test for each MIPS16e instruction MD00076 describes, in the order of
     its sections. Each reads words of the instruction and checks the text, and
     each word is one binutils' objdump reads as the same instruction with the
     same operands, so what is asserted is a reading two decoders agree on. *)
  [<TestMethod>]
  member _.``MD00076 ADDIU``() =
    disasmMIPS16 "00006500" "addiu s0, sp, 0x0"
    disasmMIPS16 "00016500" "addiu s0, sp, 0x4"
    disasmMIPS16 "00026500" "addiu s0, sp, 0x8"
    disasmMIPS16 "00036500" "addiu s0, sp, 0xc"

  [<TestMethod>]
  member _.``MD00076 ADDU``() =
    disasmMIPS16 "e0016500" "addu s0, s0, s0"
    disasmMIPS16 "e0056500" "addu s1, s0, s0"
    disasmMIPS16 "e0096500" "addu v0, s0, s0"
    disasmMIPS16 "e00d6500" "addu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00076 AND``() =
    disasmMIPS16 "e80c6500" "and s0, s0, s0"
    disasmMIPS16 "e82c6500" "and s0, s0, s1"
    disasmMIPS16 "e84c6500" "and s0, s0, v0"
    disasmMIPS16 "e86c6500" "and s0, s0, v1"

  [<TestMethod>]
  member _.``MD00076 B``() =
    disasmMIPS16 "10006500" "b 0x2"
    disasmMIPS16 "10016500" "b 0x4"
    disasmMIPS16 "10026500" "b 0x6"
    disasmMIPS16 "10036500" "b 0x8"

  [<TestMethod>]
  member _.``MD00076 BEQZ``() =
    disasmMIPS16 "20006500" "beqz s0, 0x2"
    disasmMIPS16 "20016500" "beqz s0, 0x4"
    disasmMIPS16 "20026500" "beqz s0, 0x6"
    disasmMIPS16 "20036500" "beqz s0, 0x8"

  [<TestMethod>]
  member _.``MD00076 BNEZ``() =
    disasmMIPS16 "28006500" "bnez s0, 0x2"
    disasmMIPS16 "28016500" "bnez s0, 0x4"
    disasmMIPS16 "28026500" "bnez s0, 0x6"
    disasmMIPS16 "28036500" "bnez s0, 0x8"

  [<TestMethod>]
  member _.``MD00076 BREAK``() =
    disasmMIPS16 "e8056500" "break 0x0"
    disasmMIPS16 "e8256500" "break 0x1"
    disasmMIPS16 "e8456500" "break 0x2"
    disasmMIPS16 "e8656500" "break 0x3"

  [<TestMethod>]
  member _.``MD00076 BTEQZ``() =
    disasmMIPS16 "60006500" "bteqz 0x2"
    disasmMIPS16 "60016500" "bteqz 0x4"
    disasmMIPS16 "60026500" "bteqz 0x6"
    disasmMIPS16 "60036500" "bteqz 0x8"

  [<TestMethod>]
  member _.``MD00076 BTNEZ``() =
    disasmMIPS16 "61006500" "btnez 0x2"
    disasmMIPS16 "61016500" "btnez 0x4"
    disasmMIPS16 "61026500" "btnez 0x6"
    disasmMIPS16 "61036500" "btnez 0x8"

  [<TestMethod>]
  member _.``MD00076 CMP``() =
    disasmMIPS16 "e80a6500" "cmp s0, s0"
    disasmMIPS16 "e82a6500" "cmp s0, s1"
    disasmMIPS16 "e84a6500" "cmp s0, v0"
    disasmMIPS16 "e86a6500" "cmp s0, v1"

  [<TestMethod>]
  member _.``MD00076 CMPI``() =
    disasmMIPS16 "70006500" "cmpi s0, 0x0"
    disasmMIPS16 "70016500" "cmpi s0, 0x1"
    disasmMIPS16 "70026500" "cmpi s0, 0x2"
    disasmMIPS16 "70036500" "cmpi s0, 0x3"

  [<TestMethod>]
  member _.``MD00076 DIV``() =
    disasmMIPS16 "e81a6500" "div s0, s0"
    disasmMIPS16 "e83a6500" "div s0, s1"
    disasmMIPS16 "e85a6500" "div s0, v0"
    disasmMIPS16 "e87a6500" "div s0, v1"

  [<TestMethod>]
  member _.``MD00076 DIVU``() =
    disasmMIPS16 "e81b6500" "divu s0, s0"
    disasmMIPS16 "e83b6500" "divu s0, s1"
    disasmMIPS16 "e85b6500" "divu s0, v0"
    disasmMIPS16 "e87b6500" "divu s0, v1"

  [<TestMethod>]
  member _.``MD00076 JAL``() =
    disasmMIPS16 "18006500" "jal 0x19400"
    disasmMIPS16 "18016500" "jal 0x819400"
    disasmMIPS16 "18026500" "jal 0x1019400"
    disasmMIPS16 "18036500" "jal 0x1819400"

  [<TestMethod>]
  member _.``MD00076 JALR``() =
    disasmMIPS16 "e8406500" "jalr ra, s0"
    disasmMIPS16 "e9406500" "jalr ra, s1"
    disasmMIPS16 "ea406500" "jalr ra, v0"
    disasmMIPS16 "eb406500" "jalr ra, v1"

  [<TestMethod>]
  member _.``MD00076 JALRC``() =
    disasmMIPS16 "e8c06500" "jalrc ra, s0"
    disasmMIPS16 "e9c06500" "jalrc ra, s1"
    disasmMIPS16 "eac06500" "jalrc ra, v0"
    disasmMIPS16 "ebc06500" "jalrc ra, v1"

  [<TestMethod>]
  member _.``MD00076 JALX``() =
    disasmMIPS16 "1c006500" "jalx 0x19400"
    disasmMIPS16 "1c016500" "jalx 0x819400"
    disasmMIPS16 "1c026500" "jalx 0x1019400"
    disasmMIPS16 "1c036500" "jalx 0x1819400"

  [<TestMethod>]
  member _.``MD00076 JR``() =
    disasmMIPS16 "e8006500" "jr s0"
    disasmMIPS16 "e8206500" "jr ra"
    disasmMIPS16 "e9006500" "jr s1"
    disasmMIPS16 "ea006500" "jr v0"

  [<TestMethod>]
  member _.``MD00076 JRC``() =
    disasmMIPS16 "e8806500" "jrc s0"
    disasmMIPS16 "e8a06500" "jrc ra"
    disasmMIPS16 "e9806500" "jrc s1"
    disasmMIPS16 "ea806500" "jrc v0"

  [<TestMethod>]
  member _.``MD00076 LB``() =
    disasmMIPS16 "80006500" "lb s0, 0(s0)"
    disasmMIPS16 "80016500" "lb s0, 1(s0)"
    disasmMIPS16 "80026500" "lb s0, 2(s0)"
    disasmMIPS16 "80036500" "lb s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00076 LBU``() =
    disasmMIPS16 "a0006500" "lbu s0, 0(s0)"
    disasmMIPS16 "a0016500" "lbu s0, 1(s0)"
    disasmMIPS16 "a0026500" "lbu s0, 2(s0)"
    disasmMIPS16 "a0036500" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00076 LH``() =
    disasmMIPS16 "88006500" "lh s0, 0(s0)"
    disasmMIPS16 "88016500" "lh s0, 2(s0)"
    disasmMIPS16 "88026500" "lh s0, 4(s0)"
    disasmMIPS16 "88036500" "lh s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00076 LHU``() =
    disasmMIPS16 "a8006500" "lhu s0, 0(s0)"
    disasmMIPS16 "a8016500" "lhu s0, 2(s0)"
    disasmMIPS16 "a8026500" "lhu s0, 4(s0)"
    disasmMIPS16 "a8036500" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00076 LI``() =
    disasmMIPS16 "68006500" "li s0, 0x0"
    disasmMIPS16 "68016500" "li s0, 0x1"
    disasmMIPS16 "68026500" "li s0, 0x2"
    disasmMIPS16 "68036500" "li s0, 0x3"

  [<TestMethod>]
  member _.``MD00076 LW``() =
    disasmMIPS16 "90006500" "lw s0, 0(sp)"
    disasmMIPS16 "90016500" "lw s0, 4(sp)"
    disasmMIPS16 "90026500" "lw s0, 8(sp)"
    disasmMIPS16 "90036500" "lw s0, 12(sp)"

  [<TestMethod>]
  member _.``MD00076 MFHI``() =
    disasmMIPS16 "e8106500" "mfhi s0"
    disasmMIPS16 "e9106500" "mfhi s1"
    disasmMIPS16 "ea106500" "mfhi v0"
    disasmMIPS16 "eb106500" "mfhi v1"

  [<TestMethod>]
  member _.``MD00076 MFLO``() =
    disasmMIPS16 "e8126500" "mflo s0"
    disasmMIPS16 "e9126500" "mflo s1"
    disasmMIPS16 "ea126500" "mflo v0"
    disasmMIPS16 "eb126500" "mflo v1"

  [<TestMethod>]
  member _.``MD00076 MOVE``() =
    disasmMIPS16 "65016500" "move r0, s1"
    disasmMIPS16 "65026500" "move r0, v0"
    disasmMIPS16 "65036500" "move r0, v1"
    disasmMIPS16 "65046500" "move r0, a0"

  [<TestMethod>]
  member _.``MD00076 MULT``() =
    disasmMIPS16 "e8186500" "mult s0, s0"
    disasmMIPS16 "e8386500" "mult s0, s1"
    disasmMIPS16 "e8586500" "mult s0, v0"
    disasmMIPS16 "e8786500" "mult s0, v1"

  [<TestMethod>]
  member _.``MD00076 MULTU``() =
    disasmMIPS16 "e8196500" "multu s0, s0"
    disasmMIPS16 "e8396500" "multu s0, s1"
    disasmMIPS16 "e8596500" "multu s0, v0"
    disasmMIPS16 "e8796500" "multu s0, v1"

  [<TestMethod>]
  member _.``MD00076 NEG``() =
    disasmMIPS16 "e80b6500" "neg s0, s0"
    disasmMIPS16 "e82b6500" "neg s0, s1"
    disasmMIPS16 "e84b6500" "neg s0, v0"
    disasmMIPS16 "e86b6500" "neg s0, v1"

  [<TestMethod>]
  member _.``MD00076 NOP``() =
    disasmMIPS16 "65006500" "nop"

  [<TestMethod>]
  member _.``MD00076 NOT``() =
    disasmMIPS16 "e80f6500" "not s0, s0"
    disasmMIPS16 "e82f6500" "not s0, s1"
    disasmMIPS16 "e84f6500" "not s0, v0"
    disasmMIPS16 "e86f6500" "not s0, v1"

  [<TestMethod>]
  member _.``MD00076 OR``() =
    disasmMIPS16 "e80d6500" "or s0, s0, s0"
    disasmMIPS16 "e82d6500" "or s0, s0, s1"
    disasmMIPS16 "e84d6500" "or s0, s0, v0"
    disasmMIPS16 "e86d6500" "or s0, s0, v1"

  [<TestMethod>]
  member _.``MD00076 RESTORE``() =
    disasmMIPS16 "64006500" "restore 0x80"
    disasmMIPS16 "64016500" "restore 0x8"
    disasmMIPS16 "64026500" "restore 0x10"
    disasmMIPS16 "64036500" "restore 0x18"

  [<TestMethod>]
  member _.``MD00076 SAVE``() =
    disasmMIPS16 "64806500" "save 0x80"
    disasmMIPS16 "64816500" "save 0x8"
    disasmMIPS16 "64826500" "save 0x10"
    disasmMIPS16 "64836500" "save 0x18"

  [<TestMethod>]
  member _.``MD00076 SB``() =
    disasmMIPS16 "c0006500" "sb s0, 0(s0)"
    disasmMIPS16 "c0016500" "sb s0, 1(s0)"
    disasmMIPS16 "c0026500" "sb s0, 2(s0)"
    disasmMIPS16 "c0036500" "sb s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00076 SDBBP``() =
    disasmMIPS16 "e8016500" "sdbbp 0x0"
    disasmMIPS16 "e8216500" "sdbbp 0x1"
    disasmMIPS16 "e8416500" "sdbbp 0x2"
    disasmMIPS16 "e8616500" "sdbbp 0x3"

  [<TestMethod>]
  member _.``MD00076 SEB``() =
    disasmMIPS16 "e8916500" "seb s0, s0"
    disasmMIPS16 "e9916500" "seb s1, s1"
    disasmMIPS16 "ea916500" "seb v0, v0"
    disasmMIPS16 "eb916500" "seb v1, v1"

  [<TestMethod>]
  member _.``MD00076 SEH``() =
    disasmMIPS16 "e8b16500" "seh s0, s0"
    disasmMIPS16 "e9b16500" "seh s1, s1"
    disasmMIPS16 "eab16500" "seh v0, v0"
    disasmMIPS16 "ebb16500" "seh v1, v1"

  [<TestMethod>]
  member _.``MD00076 SH``() =
    disasmMIPS16 "c8006500" "sh s0, 0(s0)"
    disasmMIPS16 "c8016500" "sh s0, 2(s0)"
    disasmMIPS16 "c8026500" "sh s0, 4(s0)"
    disasmMIPS16 "c8036500" "sh s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00076 SLL``() =
    disasmMIPS16 "30006500" "sll s0, s0, 0x8"
    disasmMIPS16 "30046500" "sll s0, s0, 0x1"
    disasmMIPS16 "30086500" "sll s0, s0, 0x2"
    disasmMIPS16 "300c6500" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00076 SLLV``() =
    disasmMIPS16 "e8046500" "sllv s0, s0, s0"
    disasmMIPS16 "e8246500" "sllv s1, s1, s0"
    disasmMIPS16 "e8446500" "sllv v0, v0, s0"
    disasmMIPS16 "e8646500" "sllv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00076 SLT``() =
    disasmMIPS16 "e8026500" "slt s0, s0"
    disasmMIPS16 "e8226500" "slt s0, s1"
    disasmMIPS16 "e8426500" "slt s0, v0"
    disasmMIPS16 "e8626500" "slt s0, v1"

  [<TestMethod>]
  member _.``MD00076 SLTI``() =
    disasmMIPS16 "50006500" "slti s0, 0x0"
    disasmMIPS16 "50016500" "slti s0, 0x1"
    disasmMIPS16 "50026500" "slti s0, 0x2"
    disasmMIPS16 "50036500" "slti s0, 0x3"

  [<TestMethod>]
  member _.``MD00076 SLTIU``() =
    disasmMIPS16 "58006500" "sltiu s0, 0x0"
    disasmMIPS16 "58016500" "sltiu s0, 0x1"
    disasmMIPS16 "58026500" "sltiu s0, 0x2"
    disasmMIPS16 "58036500" "sltiu s0, 0x3"

  [<TestMethod>]
  member _.``MD00076 SLTU``() =
    disasmMIPS16 "e8036500" "sltu s0, s0"
    disasmMIPS16 "e8236500" "sltu s0, s1"
    disasmMIPS16 "e8436500" "sltu s0, v0"
    disasmMIPS16 "e8636500" "sltu s0, v1"

  [<TestMethod>]
  member _.``MD00076 SRA``() =
    disasmMIPS16 "30036500" "sra s0, s0, 0x8"
    disasmMIPS16 "30076500" "sra s0, s0, 0x1"
    disasmMIPS16 "300b6500" "sra s0, s0, 0x2"
    disasmMIPS16 "300f6500" "sra s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00076 SRAV``() =
    disasmMIPS16 "e8076500" "srav s0, s0, s0"
    disasmMIPS16 "e8276500" "srav s1, s1, s0"
    disasmMIPS16 "e8476500" "srav v0, v0, s0"
    disasmMIPS16 "e8676500" "srav v1, v1, s0"

  [<TestMethod>]
  member _.``MD00076 SRL``() =
    disasmMIPS16 "30026500" "srl s0, s0, 0x8"
    disasmMIPS16 "30066500" "srl s0, s0, 0x1"
    disasmMIPS16 "300a6500" "srl s0, s0, 0x2"
    disasmMIPS16 "300e6500" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00076 SRLV``() =
    disasmMIPS16 "e8066500" "srlv s0, s0, s0"
    disasmMIPS16 "e8266500" "srlv s1, s1, s0"
    disasmMIPS16 "e8466500" "srlv v0, v0, s0"
    disasmMIPS16 "e8666500" "srlv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00076 SUBU``() =
    disasmMIPS16 "e0036500" "subu s0, s0, s0"
    disasmMIPS16 "e0076500" "subu s1, s0, s0"
    disasmMIPS16 "e00b6500" "subu v0, s0, s0"
    disasmMIPS16 "e00f6500" "subu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00076 SW``() =
    disasmMIPS16 "62006500" "sw ra, 0(sp)"
    disasmMIPS16 "62016500" "sw ra, 4(sp)"
    disasmMIPS16 "62026500" "sw ra, 8(sp)"
    disasmMIPS16 "62036500" "sw ra, 12(sp)"

  [<TestMethod>]
  member _.``MD00076 XOR``() =
    disasmMIPS16 "e80e6500" "xor s0, s0, s0"
    disasmMIPS16 "e82e6500" "xor s0, s0, s1"
    disasmMIPS16 "e84e6500" "xor s0, s0, v0"
    disasmMIPS16 "e86e6500" "xor s0, s0, v1"

  [<TestMethod>]
  member _.``MD00076 ZEB``() =
    disasmMIPS16 "e8116500" "zeb s0, s0"
    disasmMIPS16 "e9116500" "zeb s1, s1"
    disasmMIPS16 "ea116500" "zeb v0, v0"
    disasmMIPS16 "eb116500" "zeb v1, v1"

  [<TestMethod>]
  member _.``MD00076 ZEH``() =
    disasmMIPS16 "e8316500" "zeh s0, s0"
    disasmMIPS16 "e9316500" "zeh s1, s1"
    disasmMIPS16 "ea316500" "zeh v0, v0"
    disasmMIPS16 "eb316500" "zeh v1, v1"

  (* One test for each MIPS16e instruction MD00077 describes, in the order of
     its sections. Each reads words of the instruction and checks the text, and
     each word is one binutils' objdump reads as the same instruction with the
     same operands, so what is asserted is a reading two decoders agree on. *)
  [<TestMethod>]
  member _.``MD00077 ADDIU``() =
    disasmMIPS16x64 "00006500" "addiu s0, sp, 0x0"
    disasmMIPS16x64 "00016500" "addiu s0, sp, 0x4"
    disasmMIPS16x64 "00026500" "addiu s0, sp, 0x8"
    disasmMIPS16x64 "00036500" "addiu s0, sp, 0xc"

  [<TestMethod>]
  member _.``MD00077 ADDU``() =
    disasmMIPS16x64 "e0016500" "addu s0, s0, s0"
    disasmMIPS16x64 "e0056500" "addu s1, s0, s0"
    disasmMIPS16x64 "e0096500" "addu v0, s0, s0"
    disasmMIPS16x64 "e00d6500" "addu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00077 AND``() =
    disasmMIPS16x64 "e80c6500" "and s0, s0, s0"
    disasmMIPS16x64 "e82c6500" "and s0, s0, s1"
    disasmMIPS16x64 "e84c6500" "and s0, s0, v0"
    disasmMIPS16x64 "e86c6500" "and s0, s0, v1"

  [<TestMethod>]
  member _.``MD00077 B``() =
    disasmMIPS16x64 "10006500" "b 0x2"
    disasmMIPS16x64 "10016500" "b 0x4"
    disasmMIPS16x64 "10026500" "b 0x6"
    disasmMIPS16x64 "10036500" "b 0x8"

  [<TestMethod>]
  member _.``MD00077 BEQZ``() =
    disasmMIPS16x64 "20006500" "beqz s0, 0x2"
    disasmMIPS16x64 "20016500" "beqz s0, 0x4"
    disasmMIPS16x64 "20026500" "beqz s0, 0x6"
    disasmMIPS16x64 "20036500" "beqz s0, 0x8"

  [<TestMethod>]
  member _.``MD00077 BNEZ``() =
    disasmMIPS16x64 "28006500" "bnez s0, 0x2"
    disasmMIPS16x64 "28016500" "bnez s0, 0x4"
    disasmMIPS16x64 "28026500" "bnez s0, 0x6"
    disasmMIPS16x64 "28036500" "bnez s0, 0x8"

  [<TestMethod>]
  member _.``MD00077 BREAK``() =
    disasmMIPS16x64 "e8056500" "break 0x0"
    disasmMIPS16x64 "e8256500" "break 0x1"
    disasmMIPS16x64 "e8456500" "break 0x2"
    disasmMIPS16x64 "e8656500" "break 0x3"

  [<TestMethod>]
  member _.``MD00077 BTEQZ``() =
    disasmMIPS16x64 "60006500" "bteqz 0x2"
    disasmMIPS16x64 "60016500" "bteqz 0x4"
    disasmMIPS16x64 "60026500" "bteqz 0x6"
    disasmMIPS16x64 "60036500" "bteqz 0x8"

  [<TestMethod>]
  member _.``MD00077 BTNEZ``() =
    disasmMIPS16x64 "61006500" "btnez 0x2"
    disasmMIPS16x64 "61016500" "btnez 0x4"
    disasmMIPS16x64 "61026500" "btnez 0x6"
    disasmMIPS16x64 "61036500" "btnez 0x8"

  [<TestMethod>]
  member _.``MD00077 CMP``() =
    disasmMIPS16x64 "e80a6500" "cmp s0, s0"
    disasmMIPS16x64 "e82a6500" "cmp s0, s1"
    disasmMIPS16x64 "e84a6500" "cmp s0, v0"
    disasmMIPS16x64 "e86a6500" "cmp s0, v1"

  [<TestMethod>]
  member _.``MD00077 CMPI``() =
    disasmMIPS16x64 "70006500" "cmpi s0, 0x0"
    disasmMIPS16x64 "70016500" "cmpi s0, 0x1"
    disasmMIPS16x64 "70026500" "cmpi s0, 0x2"
    disasmMIPS16x64 "70036500" "cmpi s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 DADDIU``() =
    disasmMIPS16x64 "40106500" "daddiu s0, s0, 0x0"
    disasmMIPS16x64 "40116500" "daddiu s0, s0, 0x1"
    disasmMIPS16x64 "40126500" "daddiu s0, s0, 0x2"
    disasmMIPS16x64 "40136500" "daddiu s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 DADDU``() =
    disasmMIPS16x64 "e0006500" "daddu s0, s0, s0"
    disasmMIPS16x64 "e0046500" "daddu s1, s0, s0"
    disasmMIPS16x64 "e0086500" "daddu v0, s0, s0"
    disasmMIPS16x64 "e00c6500" "daddu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00077 DDIV``() =
    disasmMIPS16x64 "e81e6500" "ddiv s0, s0"
    disasmMIPS16x64 "e83e6500" "ddiv s0, s1"
    disasmMIPS16x64 "e85e6500" "ddiv s0, v0"
    disasmMIPS16x64 "e87e6500" "ddiv s0, v1"

  [<TestMethod>]
  member _.``MD00077 DDIVU``() =
    disasmMIPS16x64 "e81f6500" "ddivu s0, s0"
    disasmMIPS16x64 "e83f6500" "ddivu s0, s1"
    disasmMIPS16x64 "e85f6500" "ddivu s0, v0"
    disasmMIPS16x64 "e87f6500" "ddivu s0, v1"

  [<TestMethod>]
  member _.``MD00077 DIV``() =
    disasmMIPS16x64 "e81a6500" "div s0, s0"
    disasmMIPS16x64 "e83a6500" "div s0, s1"
    disasmMIPS16x64 "e85a6500" "div s0, v0"
    disasmMIPS16x64 "e87a6500" "div s0, v1"

  [<TestMethod>]
  member _.``MD00077 DIVU``() =
    disasmMIPS16x64 "e81b6500" "divu s0, s0"
    disasmMIPS16x64 "e83b6500" "divu s0, s1"
    disasmMIPS16x64 "e85b6500" "divu s0, v0"
    disasmMIPS16x64 "e87b6500" "divu s0, v1"

  [<TestMethod>]
  member _.``MD00077 DMULT``() =
    disasmMIPS16x64 "e81c6500" "dmult s0, s0"
    disasmMIPS16x64 "e83c6500" "dmult s0, s1"
    disasmMIPS16x64 "e85c6500" "dmult s0, v0"
    disasmMIPS16x64 "e87c6500" "dmult s0, v1"

  [<TestMethod>]
  member _.``MD00077 DMULTU``() =
    disasmMIPS16x64 "e81d6500" "dmultu s0, s0"
    disasmMIPS16x64 "e83d6500" "dmultu s0, s1"
    disasmMIPS16x64 "e85d6500" "dmultu s0, v0"
    disasmMIPS16x64 "e87d6500" "dmultu s0, v1"

  [<TestMethod>]
  member _.``MD00077 DSLL``() =
    disasmMIPS16x64 "30016500" "dsll s0, s0, 0x8"
    disasmMIPS16x64 "30056500" "dsll s0, s0, 0x1"
    disasmMIPS16x64 "30096500" "dsll s0, s0, 0x2"
    disasmMIPS16x64 "300d6500" "dsll s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 DSLLV``() =
    disasmMIPS16x64 "e8146500" "dsllv s0, s0, s0"
    disasmMIPS16x64 "e8346500" "dsllv s1, s1, s0"
    disasmMIPS16x64 "e8546500" "dsllv v0, v0, s0"
    disasmMIPS16x64 "e8746500" "dsllv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 DSRA``() =
    disasmMIPS16x64 "e8136500" "dsra s0, s0, 0x8"
    disasmMIPS16x64 "e8336500" "dsra s1, s1, 0x8"
    disasmMIPS16x64 "e8536500" "dsra v0, v0, 0x8"
    disasmMIPS16x64 "e8736500" "dsra v1, v1, 0x8"

  [<TestMethod>]
  member _.``MD00077 DSRAV``() =
    disasmMIPS16x64 "e8176500" "dsrav s0, s0, s0"
    disasmMIPS16x64 "e8376500" "dsrav s1, s1, s0"
    disasmMIPS16x64 "e8576500" "dsrav v0, v0, s0"
    disasmMIPS16x64 "e8776500" "dsrav v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 DSRL``() =
    disasmMIPS16x64 "e8086500" "dsrl s0, s0, 0x8"
    disasmMIPS16x64 "e8286500" "dsrl s1, s1, 0x8"
    disasmMIPS16x64 "e8486500" "dsrl v0, v0, 0x8"
    disasmMIPS16x64 "e8686500" "dsrl v1, v1, 0x8"

  [<TestMethod>]
  member _.``MD00077 DSRLV``() =
    disasmMIPS16x64 "e8166500" "dsrlv s0, s0, s0"
    disasmMIPS16x64 "e8366500" "dsrlv s1, s1, s0"
    disasmMIPS16x64 "e8566500" "dsrlv v0, v0, s0"
    disasmMIPS16x64 "e8766500" "dsrlv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 DSUBU``() =
    disasmMIPS16x64 "e0026500" "dsubu s0, s0, s0"
    disasmMIPS16x64 "e0066500" "dsubu s1, s0, s0"
    disasmMIPS16x64 "e00a6500" "dsubu v0, s0, s0"
    disasmMIPS16x64 "e00e6500" "dsubu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00077 JAL``() =
    disasmMIPS16x64 "18006500" "jal 0x19400"
    disasmMIPS16x64 "18016500" "jal 0x819400"
    disasmMIPS16x64 "18026500" "jal 0x1019400"
    disasmMIPS16x64 "18036500" "jal 0x1819400"

  [<TestMethod>]
  member _.``MD00077 JALR``() =
    disasmMIPS16x64 "e8406500" "jalr ra, s0"
    disasmMIPS16x64 "e9406500" "jalr ra, s1"
    disasmMIPS16x64 "ea406500" "jalr ra, v0"
    disasmMIPS16x64 "eb406500" "jalr ra, v1"

  [<TestMethod>]
  member _.``MD00077 JALRC``() =
    disasmMIPS16x64 "e8c06500" "jalrc ra, s0"
    disasmMIPS16x64 "e9c06500" "jalrc ra, s1"
    disasmMIPS16x64 "eac06500" "jalrc ra, v0"
    disasmMIPS16x64 "ebc06500" "jalrc ra, v1"

  [<TestMethod>]
  member _.``MD00077 JALX``() =
    disasmMIPS16x64 "1c006500" "jalx 0x19400"
    disasmMIPS16x64 "1c016500" "jalx 0x819400"
    disasmMIPS16x64 "1c026500" "jalx 0x1019400"
    disasmMIPS16x64 "1c036500" "jalx 0x1819400"

  [<TestMethod>]
  member _.``MD00077 JR``() =
    disasmMIPS16x64 "e8006500" "jr s0"
    disasmMIPS16x64 "e8206500" "jr ra"
    disasmMIPS16x64 "e9006500" "jr s1"
    disasmMIPS16x64 "ea006500" "jr v0"

  [<TestMethod>]
  member _.``MD00077 JRC``() =
    disasmMIPS16x64 "e8806500" "jrc s0"
    disasmMIPS16x64 "e8a06500" "jrc ra"
    disasmMIPS16x64 "e9806500" "jrc s1"
    disasmMIPS16x64 "ea806500" "jrc v0"

  [<TestMethod>]
  member _.``MD00077 LB``() =
    disasmMIPS16x64 "80006500" "lb s0, 0(s0)"
    disasmMIPS16x64 "80016500" "lb s0, 1(s0)"
    disasmMIPS16x64 "80026500" "lb s0, 2(s0)"
    disasmMIPS16x64 "80036500" "lb s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00077 LBU``() =
    disasmMIPS16x64 "a0006500" "lbu s0, 0(s0)"
    disasmMIPS16x64 "a0016500" "lbu s0, 1(s0)"
    disasmMIPS16x64 "a0026500" "lbu s0, 2(s0)"
    disasmMIPS16x64 "a0036500" "lbu s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00077 LD``() =
    disasmMIPS16x64 "38006500" "ld s0, 0(s0)"
    disasmMIPS16x64 "38016500" "ld s0, 8(s0)"
    disasmMIPS16x64 "38026500" "ld s0, 16(s0)"
    disasmMIPS16x64 "38036500" "ld s0, 24(s0)"

  [<TestMethod>]
  member _.``MD00077 LH``() =
    disasmMIPS16x64 "88006500" "lh s0, 0(s0)"
    disasmMIPS16x64 "88016500" "lh s0, 2(s0)"
    disasmMIPS16x64 "88026500" "lh s0, 4(s0)"
    disasmMIPS16x64 "88036500" "lh s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00077 LHU``() =
    disasmMIPS16x64 "a8006500" "lhu s0, 0(s0)"
    disasmMIPS16x64 "a8016500" "lhu s0, 2(s0)"
    disasmMIPS16x64 "a8026500" "lhu s0, 4(s0)"
    disasmMIPS16x64 "a8036500" "lhu s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00077 LI``() =
    disasmMIPS16x64 "68006500" "li s0, 0x0"
    disasmMIPS16x64 "68016500" "li s0, 0x1"
    disasmMIPS16x64 "68026500" "li s0, 0x2"
    disasmMIPS16x64 "68036500" "li s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 LW``() =
    disasmMIPS16x64 "90006500" "lw s0, 0(sp)"
    disasmMIPS16x64 "90016500" "lw s0, 4(sp)"
    disasmMIPS16x64 "90026500" "lw s0, 8(sp)"
    disasmMIPS16x64 "90036500" "lw s0, 12(sp)"

  [<TestMethod>]
  member _.``MD00077 LWU``() =
    disasmMIPS16x64 "b8006500" "lwu s0, 0(s0)"
    disasmMIPS16x64 "b8016500" "lwu s0, 4(s0)"
    disasmMIPS16x64 "b8026500" "lwu s0, 8(s0)"
    disasmMIPS16x64 "b8036500" "lwu s0, 12(s0)"

  [<TestMethod>]
  member _.``MD00077 MFHI``() =
    disasmMIPS16x64 "e8106500" "mfhi s0"
    disasmMIPS16x64 "e9106500" "mfhi s1"
    disasmMIPS16x64 "ea106500" "mfhi v0"
    disasmMIPS16x64 "eb106500" "mfhi v1"

  [<TestMethod>]
  member _.``MD00077 MFLO``() =
    disasmMIPS16x64 "e8126500" "mflo s0"
    disasmMIPS16x64 "e9126500" "mflo s1"
    disasmMIPS16x64 "ea126500" "mflo v0"
    disasmMIPS16x64 "eb126500" "mflo v1"

  [<TestMethod>]
  member _.``MD00077 MOVE``() =
    disasmMIPS16x64 "65016500" "move r0, s1"
    disasmMIPS16x64 "65026500" "move r0, v0"
    disasmMIPS16x64 "65036500" "move r0, v1"
    disasmMIPS16x64 "65046500" "move r0, a0"

  [<TestMethod>]
  member _.``MD00077 MULT``() =
    disasmMIPS16x64 "e8186500" "mult s0, s0"
    disasmMIPS16x64 "e8386500" "mult s0, s1"
    disasmMIPS16x64 "e8586500" "mult s0, v0"
    disasmMIPS16x64 "e8786500" "mult s0, v1"

  [<TestMethod>]
  member _.``MD00077 MULTU``() =
    disasmMIPS16x64 "e8196500" "multu s0, s0"
    disasmMIPS16x64 "e8396500" "multu s0, s1"
    disasmMIPS16x64 "e8596500" "multu s0, v0"
    disasmMIPS16x64 "e8796500" "multu s0, v1"

  [<TestMethod>]
  member _.``MD00077 NEG``() =
    disasmMIPS16x64 "e80b6500" "neg s0, s0"
    disasmMIPS16x64 "e82b6500" "neg s0, s1"
    disasmMIPS16x64 "e84b6500" "neg s0, v0"
    disasmMIPS16x64 "e86b6500" "neg s0, v1"

  [<TestMethod>]
  member _.``MD00077 NOP``() =
    disasmMIPS16x64 "65006500" "nop"

  [<TestMethod>]
  member _.``MD00077 NOT``() =
    disasmMIPS16x64 "e80f6500" "not s0, s0"
    disasmMIPS16x64 "e82f6500" "not s0, s1"
    disasmMIPS16x64 "e84f6500" "not s0, v0"
    disasmMIPS16x64 "e86f6500" "not s0, v1"

  [<TestMethod>]
  member _.``MD00077 OR``() =
    disasmMIPS16x64 "e80d6500" "or s0, s0, s0"
    disasmMIPS16x64 "e82d6500" "or s0, s0, s1"
    disasmMIPS16x64 "e84d6500" "or s0, s0, v0"
    disasmMIPS16x64 "e86d6500" "or s0, s0, v1"

  [<TestMethod>]
  member _.``MD00077 RESTORE``() =
    disasmMIPS16x64 "64006500" "restore 0x80"
    disasmMIPS16x64 "64016500" "restore 0x8"
    disasmMIPS16x64 "64026500" "restore 0x10"
    disasmMIPS16x64 "64036500" "restore 0x18"

  [<TestMethod>]
  member _.``MD00077 SAVE``() =
    disasmMIPS16x64 "64806500" "save 0x80"
    disasmMIPS16x64 "64816500" "save 0x8"
    disasmMIPS16x64 "64826500" "save 0x10"
    disasmMIPS16x64 "64836500" "save 0x18"

  [<TestMethod>]
  member _.``MD00077 SB``() =
    disasmMIPS16x64 "c0006500" "sb s0, 0(s0)"
    disasmMIPS16x64 "c0016500" "sb s0, 1(s0)"
    disasmMIPS16x64 "c0026500" "sb s0, 2(s0)"
    disasmMIPS16x64 "c0036500" "sb s0, 3(s0)"

  [<TestMethod>]
  member _.``MD00077 SD``() =
    disasmMIPS16x64 "78006500" "sd s0, 0(s0)"
    disasmMIPS16x64 "78016500" "sd s0, 8(s0)"
    disasmMIPS16x64 "78026500" "sd s0, 16(s0)"
    disasmMIPS16x64 "78036500" "sd s0, 24(s0)"

  [<TestMethod>]
  member _.``MD00077 SDBBP``() =
    disasmMIPS16x64 "e8016500" "sdbbp 0x0"
    disasmMIPS16x64 "e8216500" "sdbbp 0x1"
    disasmMIPS16x64 "e8416500" "sdbbp 0x2"
    disasmMIPS16x64 "e8616500" "sdbbp 0x3"

  [<TestMethod>]
  member _.``MD00077 SEB``() =
    disasmMIPS16x64 "e8916500" "seb s0, s0"
    disasmMIPS16x64 "e9916500" "seb s1, s1"
    disasmMIPS16x64 "ea916500" "seb v0, v0"
    disasmMIPS16x64 "eb916500" "seb v1, v1"

  [<TestMethod>]
  member _.``MD00077 SEH``() =
    disasmMIPS16x64 "e8b16500" "seh s0, s0"
    disasmMIPS16x64 "e9b16500" "seh s1, s1"
    disasmMIPS16x64 "eab16500" "seh v0, v0"
    disasmMIPS16x64 "ebb16500" "seh v1, v1"

  [<TestMethod>]
  member _.``MD00077 SEW``() =
    disasmMIPS16x64 "e8d16500" "sew s0, s0"
    disasmMIPS16x64 "e9d16500" "sew s1, s1"
    disasmMIPS16x64 "ead16500" "sew v0, v0"
    disasmMIPS16x64 "ebd16500" "sew v1, v1"

  [<TestMethod>]
  member _.``MD00077 SH``() =
    disasmMIPS16x64 "c8006500" "sh s0, 0(s0)"
    disasmMIPS16x64 "c8016500" "sh s0, 2(s0)"
    disasmMIPS16x64 "c8026500" "sh s0, 4(s0)"
    disasmMIPS16x64 "c8036500" "sh s0, 6(s0)"

  [<TestMethod>]
  member _.``MD00077 SLL``() =
    disasmMIPS16x64 "30006500" "sll s0, s0, 0x8"
    disasmMIPS16x64 "30046500" "sll s0, s0, 0x1"
    disasmMIPS16x64 "30086500" "sll s0, s0, 0x2"
    disasmMIPS16x64 "300c6500" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SLLV``() =
    disasmMIPS16x64 "e8046500" "sllv s0, s0, s0"
    disasmMIPS16x64 "e8246500" "sllv s1, s1, s0"
    disasmMIPS16x64 "e8446500" "sllv v0, v0, s0"
    disasmMIPS16x64 "e8646500" "sllv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 SLT``() =
    disasmMIPS16x64 "e8026500" "slt s0, s0"
    disasmMIPS16x64 "e8226500" "slt s0, s1"
    disasmMIPS16x64 "e8426500" "slt s0, v0"
    disasmMIPS16x64 "e8626500" "slt s0, v1"

  [<TestMethod>]
  member _.``MD00077 SLTI``() =
    disasmMIPS16x64 "50006500" "slti s0, 0x0"
    disasmMIPS16x64 "50016500" "slti s0, 0x1"
    disasmMIPS16x64 "50026500" "slti s0, 0x2"
    disasmMIPS16x64 "50036500" "slti s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SLTIU``() =
    disasmMIPS16x64 "58006500" "sltiu s0, 0x0"
    disasmMIPS16x64 "58016500" "sltiu s0, 0x1"
    disasmMIPS16x64 "58026500" "sltiu s0, 0x2"
    disasmMIPS16x64 "58036500" "sltiu s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SLTU``() =
    disasmMIPS16x64 "e8036500" "sltu s0, s0"
    disasmMIPS16x64 "e8236500" "sltu s0, s1"
    disasmMIPS16x64 "e8436500" "sltu s0, v0"
    disasmMIPS16x64 "e8636500" "sltu s0, v1"

  [<TestMethod>]
  member _.``MD00077 SRA``() =
    disasmMIPS16x64 "30036500" "sra s0, s0, 0x8"
    disasmMIPS16x64 "30076500" "sra s0, s0, 0x1"
    disasmMIPS16x64 "300b6500" "sra s0, s0, 0x2"
    disasmMIPS16x64 "300f6500" "sra s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SRAV``() =
    disasmMIPS16x64 "e8076500" "srav s0, s0, s0"
    disasmMIPS16x64 "e8276500" "srav s1, s1, s0"
    disasmMIPS16x64 "e8476500" "srav v0, v0, s0"
    disasmMIPS16x64 "e8676500" "srav v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 SRL``() =
    disasmMIPS16x64 "30026500" "srl s0, s0, 0x8"
    disasmMIPS16x64 "30066500" "srl s0, s0, 0x1"
    disasmMIPS16x64 "300a6500" "srl s0, s0, 0x2"
    disasmMIPS16x64 "300e6500" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``MD00077 SRLV``() =
    disasmMIPS16x64 "e8066500" "srlv s0, s0, s0"
    disasmMIPS16x64 "e8266500" "srlv s1, s1, s0"
    disasmMIPS16x64 "e8466500" "srlv v0, v0, s0"
    disasmMIPS16x64 "e8666500" "srlv v1, v1, s0"

  [<TestMethod>]
  member _.``MD00077 SUBU``() =
    disasmMIPS16x64 "e0036500" "subu s0, s0, s0"
    disasmMIPS16x64 "e0076500" "subu s1, s0, s0"
    disasmMIPS16x64 "e00b6500" "subu v0, s0, s0"
    disasmMIPS16x64 "e00f6500" "subu v1, s0, s0"

  [<TestMethod>]
  member _.``MD00077 SW``() =
    disasmMIPS16x64 "62006500" "sw ra, 0(sp)"
    disasmMIPS16x64 "62016500" "sw ra, 4(sp)"
    disasmMIPS16x64 "62026500" "sw ra, 8(sp)"
    disasmMIPS16x64 "62036500" "sw ra, 12(sp)"

  [<TestMethod>]
  member _.``MD00077 XOR``() =
    disasmMIPS16x64 "e80e6500" "xor s0, s0, s0"
    disasmMIPS16x64 "e82e6500" "xor s0, s0, s1"
    disasmMIPS16x64 "e84e6500" "xor s0, s0, v0"
    disasmMIPS16x64 "e86e6500" "xor s0, s0, v1"

  [<TestMethod>]
  member _.``MD00077 ZEB``() =
    disasmMIPS16x64 "e8116500" "zeb s0, s0"
    disasmMIPS16x64 "e9116500" "zeb s1, s1"
    disasmMIPS16x64 "ea116500" "zeb v0, v0"
    disasmMIPS16x64 "eb116500" "zeb v1, v1"

  [<TestMethod>]
  member _.``MD00077 ZEH``() =
    disasmMIPS16x64 "e8316500" "zeh s0, s0"
    disasmMIPS16x64 "e9316500" "zeh s1, s1"
    disasmMIPS16x64 "ea316500" "zeh v0, v0"
    disasmMIPS16x64 "eb316500" "zeh v1, v1"

  [<TestMethod>]
  member _.``MD00077 ZEW``() =
    disasmMIPS16x64 "e8516500" "zew s0, s0"
    disasmMIPS16x64 "e9516500" "zew s1, s1"
    disasmMIPS16x64 "ea516500" "zew v0, v0"
    disasmMIPS16x64 "eb516500" "zew v1, v1"

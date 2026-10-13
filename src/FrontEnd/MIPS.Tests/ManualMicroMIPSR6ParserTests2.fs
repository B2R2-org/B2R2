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

namespace B2R2.FrontEnd.MIPS.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.MIPS

/// <summary>
/// One test for each instruction microMIPS64 6.01 describes, ORI to XORI. Each
/// reads words of the instruction and checks the text, and each word is one
/// binutils' objdump reads as the same instruction with the same operands, so
/// what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMicroMIPSR6ParserTests2() =
  let isa =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS ||| int MIPSRelease.R6)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  [<TestMethod>]
  member _.``microMIPS64 6.01 ORI``() =
    testDisasm "50030000" "ori r0, v1, 0x0"
    testDisasm "50030001" "ori r0, v1, 0x1"
    testDisasm "50037fff" "ori r0, v1, 0x7fff"
    testDisasm "50038000" "ori r0, v1, 0x8000"

  [<TestMethod>]
  member _.``microMIPS64 6.01 PAUSE``() =
    testDisasm "00002800" "pause"

  [<TestMethod>]
  member _.``microMIPS64 6.01 PREF``() =
    testDisasm "60002000" "pref 0x0, 0(r0)"
    testDisasm "60002001" "pref 0x0, 1(r0)"
    testDisasm "60002002" "pref 0x0, 2(r0)"
    testDisasm "60002003" "pref 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 PREFE``() =
    testDisasm "6000a400" "prefe 0x0, 0(r0)"
    testDisasm "6000a401" "prefe 0x0, 1(r0)"
    testDisasm "6000a402" "prefe 0x0, 2(r0)"
    testDisasm "6000a403" "prefe 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 RDHWR``() =
    testDisasm "00006b3c" "rdhwr r0, r0"
    testDisasm "00226b3c" "rdhwr at, v0"
    testDisasm "03fe6b3c" "rdhwr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 RDPGPR``() =
    testDisasm "0000e17c" "rdpgpr r0, r0"
    testDisasm "0022e17c" "rdpgpr at, v0"
    testDisasm "03fee17c" "rdpgpr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 RECIP.fmt``() =
    testDisasm "5400123b" "recip.s f0, f0"
    testDisasm "5400523b" "recip.d f0, f0"
    testDisasm "5422123b" "recip.s f1, f2"
    testDisasm "5422523b" "recip.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ROTR``() =
    testDisasm "000000c0" "rotr r0, r0, 0x0"
    testDisasm "000008c0" "rotr r0, r0, 0x1"
    testDisasm "000010c0" "rotr r0, r0, 0x2"
    testDisasm "000018c0" "rotr r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ROTRV``() =
    testDisasm "000000d0" "rotrv r0, r0, r0"
    testDisasm "000008d0" "rotrv at, r0, r0"
    testDisasm "000010d0" "rotrv v0, r0, r0"
    testDisasm "000018d0" "rotrv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ROUND.L.fmt``() =
    testDisasm "5400333b" "round.l.s f0, f0"
    testDisasm "5400733b" "round.l.d f0, f0"
    testDisasm "5422333b" "round.l.s f1, f2"
    testDisasm "5422733b" "round.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 ROUND.W.fmt``() =
    testDisasm "54003b3b" "round.w.s f0, f0"
    testDisasm "54007b3b" "round.w.d f0, f0"
    testDisasm "54223b3b" "round.w.s f1, f2"
    testDisasm "54227b3b" "round.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 RSQRT.fmt``() =
    testDisasm "5400023b" "rsqrt.s f0, f0"
    testDisasm "5400423b" "rsqrt.d f0, f0"
    testDisasm "5422023b" "rsqrt.s f1, f2"
    testDisasm "5422423b" "rsqrt.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SB``() =
    testDisasm "88000c00" "sb r0, 0(s0)"
    testDisasm "88010c00" "sb r0, 1(s0)"
    testDisasm "88020c00" "sb r0, 2(s0)"
    testDisasm "88030c00" "sb r0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SB16``() =
    testDisasm "88000c00" "sb r0, 0(s0)"
    testDisasm "88010c00" "sb r0, 1(s0)"
    testDisasm "88020c00" "sb r0, 2(s0)"
    testDisasm "88030c00" "sb r0, 3(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SBE``() =
    testDisasm "6000a800" "sbe r0, 0(r0)"
    testDisasm "6000a801" "sbe r0, 1(r0)"
    testDisasm "6000a802" "sbe r0, 2(r0)"
    testDisasm "6000a803" "sbe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SC``() =
    testDisasm "6000b000" "sc r0, 0(r0)"
    testDisasm "6000b001" "sc r0, 1(r0)"
    testDisasm "6000b002" "sc r0, 2(r0)"
    testDisasm "6000b003" "sc r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SCD``() =
    testDisasm "6000f000" "scd r0, 0(r0)"
    testDisasm "6000f001" "scd r0, 1(r0)"
    testDisasm "6000f002" "scd r0, 2(r0)"
    testDisasm "6000f003" "scd r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SCE``() =
    testDisasm "6000ac00" "sce r0, 0(r0)"
    testDisasm "6000ac01" "sce r0, 1(r0)"
    testDisasm "6000ac02" "sce r0, 2(r0)"
    testDisasm "6000ac03" "sce r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SD``() =
    testDisasm "d8030000" "sd r0, 0(v1)"
    testDisasm "d8600000" "sd v1, 0(r0)"
    testDisasm "d8030001" "sd r0, 1(v1)"
    testDisasm "d8600001" "sd v1, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SDC1``() =
    testDisasm "b8030000" "sdc1 f0, 0(v1)"
    testDisasm "b8600000" "sdc1 f3, 0(r0)"
    testDisasm "b8030001" "sdc1 f0, 1(v1)"
    testDisasm "b8600001" "sdc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SDC2``() =
    testDisasm "2000a000" "sdc2 0x0, 0(r0)"
    testDisasm "2000a001" "sdc2 0x0, 1(r0)"
    testDisasm "2000a002" "sdc2 0x0, 2(r0)"
    testDisasm "2000a003" "sdc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SDM``() =
    testDisasm "2022f000" "sdm s0, 0(v0)"
    testDisasm "2022f001" "sdm s0, 1(v0)"
    testDisasm "2022f002" "sdm s0, 2(v0)"
    testDisasm "2022f003" "sdm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SDP``() =
    testDisasm "2000c000" "sdp r0, at, 0(r0)"
    testDisasm "2000c001" "sdp r0, at, 1(r0)"
    testDisasm "2000c002" "sdp r0, at, 2(r0)"
    testDisasm "2000c003" "sdp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SEB``() =
    testDisasm "00002b3c" "seb r0, r0"
    testDisasm "00222b3c" "seb at, v0"
    testDisasm "03fe2b3c" "seb ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SEH``() =
    testDisasm "00003b3c" "seh r0, r0"
    testDisasm "00223b3c" "seh at, v0"
    testDisasm "03fe3b3c" "seh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SH``() =
    testDisasm "a8000c00" "sh r0, 0(s0)"
    testDisasm "a8010c00" "sh r0, 2(s0)"
    testDisasm "a8020c00" "sh r0, 4(s0)"
    testDisasm "a8030c00" "sh r0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SH16``() =
    testDisasm "a8000c00" "sh r0, 0(s0)"
    testDisasm "a8010c00" "sh r0, 2(s0)"
    testDisasm "a8020c00" "sh r0, 4(s0)"
    testDisasm "a8030c00" "sh r0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SHE``() =
    testDisasm "6000aa00" "she r0, 0(r0)"
    testDisasm "6000aa01" "she r0, 1(r0)"
    testDisasm "6000aa02" "she r0, 2(r0)"
    testDisasm "6000aa03" "she r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLL``() =
    testDisasm "24000c00" "sll s0, s0, 0x8"
    testDisasm "24020c00" "sll s0, s0, 0x1"
    testDisasm "24040c00" "sll s0, s0, 0x2"
    testDisasm "24060c00" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLL16``() =
    testDisasm "24000c00" "sll s0, s0, 0x8"
    testDisasm "24020c00" "sll s0, s0, 0x1"
    testDisasm "24040c00" "sll s0, s0, 0x2"
    testDisasm "24060c00" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLLV``() =
    testDisasm "00000010" "sllv r0, r0, r0"
    testDisasm "00000810" "sllv at, r0, r0"
    testDisasm "00001010" "sllv v0, r0, r0"
    testDisasm "00001810" "sllv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLT``() =
    testDisasm "00000350" "slt r0, r0, r0"
    testDisasm "00000b50" "slt at, r0, r0"
    testDisasm "00001350" "slt v0, r0, r0"
    testDisasm "00001b50" "slt v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLTI``() =
    testDisasm "90030000" "slti r0, v1, 0x0"
    testDisasm "90600000" "slti v1, r0, 0x0"
    testDisasm "90030001" "slti r0, v1, 0x1"
    testDisasm "90600001" "slti v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLTIU``() =
    testDisasm "b0030000" "sltiu r0, v1, 0x0"
    testDisasm "b0600000" "sltiu v1, r0, 0x0"
    testDisasm "b0030001" "sltiu r0, v1, 0x1"
    testDisasm "b0600001" "sltiu v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SLTU``() =
    testDisasm "00000390" "sltu r0, r0, r0"
    testDisasm "00000b90" "sltu at, r0, r0"
    testDisasm "00001390" "sltu v0, r0, r0"
    testDisasm "00001b90" "sltu v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SQRT.fmt``() =
    testDisasm "54000a3b" "sqrt.s f0, f0"
    testDisasm "54004a3b" "sqrt.d f0, f0"
    testDisasm "54220a3b" "sqrt.s f1, f2"
    testDisasm "54224a3b" "sqrt.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRA``() =
    testDisasm "00000080" "sra r0, r0, 0x0"
    testDisasm "00000880" "sra r0, r0, 0x1"
    testDisasm "00001080" "sra r0, r0, 0x2"
    testDisasm "00001880" "sra r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRAV``() =
    testDisasm "00000090" "srav r0, r0, r0"
    testDisasm "00000890" "srav at, r0, r0"
    testDisasm "00001090" "srav v0, r0, r0"
    testDisasm "00001890" "srav v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRL``() =
    testDisasm "24010c00" "srl s0, s0, 0x8"
    testDisasm "24030c00" "srl s0, s0, 0x1"
    testDisasm "24050c00" "srl s0, s0, 0x2"
    testDisasm "24070c00" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRL16``() =
    testDisasm "24010c00" "srl s0, s0, 0x8"
    testDisasm "24030c00" "srl s0, s0, 0x1"
    testDisasm "24050c00" "srl s0, s0, 0x2"
    testDisasm "24070c00" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SRLV``() =
    testDisasm "00000050" "srlv r0, r0, r0"
    testDisasm "00000850" "srlv at, r0, r0"
    testDisasm "00001050" "srlv v0, r0, r0"
    testDisasm "00001850" "srlv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SSNOP``() =
    testDisasm "00000800" "ssnop"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SUB``() =
    testDisasm "00220190" "sub r0, v0, at"
    testDisasm "00220990" "sub at, v0, at"
    testDisasm "00221190" "sub v0, v0, at"
    testDisasm "00221990" "sub v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SUB.fmt``() =
    testDisasm "54000070" "sub.s f0, f0, f0"
    testDisasm "54000170" "sub.d f0, f0, f0"
    testDisasm "54000270" "sub.ps f0, f0, f0"
    testDisasm "54000870" "sub.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SUBU``() =
    testDisasm "04010c00" "subu s0, s0, s0"
    testDisasm "04110c00" "subu s0, s0, s1"
    testDisasm "04210c00" "subu s0, s0, v0"
    testDisasm "04310c00" "subu s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SW``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SW16``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWC1``() =
    testDisasm "98030000" "swc1 f0, 0(v1)"
    testDisasm "98600000" "swc1 f3, 0(r0)"
    testDisasm "98030001" "swc1 f0, 1(v1)"
    testDisasm "98600001" "swc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWC2``() =
    testDisasm "20008000" "swc2 0x0, 0(r0)"
    testDisasm "20008001" "swc2 0x0, 1(r0)"
    testDisasm "20008002" "swc2 0x0, 2(r0)"
    testDisasm "20008003" "swc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWE``() =
    testDisasm "6000ae00" "swe r0, 0(r0)"
    testDisasm "6000ae01" "swe r0, 1(r0)"
    testDisasm "6000ae02" "swe r0, 2(r0)"
    testDisasm "6000ae03" "swe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWM32``() =
    testDisasm "2022d000" "swm s0, 0(v0)"
    testDisasm "2022d001" "swm s0, 1(v0)"
    testDisasm "2022d002" "swm s0, 2(v0)"
    testDisasm "2022d003" "swm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWP``() =
    testDisasm "20009000" "swp r0, at, 0(r0)"
    testDisasm "20009001" "swp r0, at, 1(r0)"
    testDisasm "20009002" "swp r0, at, 2(r0)"
    testDisasm "20009003" "swp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SWSP``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SYNC``() =
    testDisasm "00006b7c" "sync 0x0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 SYSCALL``() =
    testDisasm "00008b7c" "syscall 0x0"
    testDisasm "00228b7c" "syscall 0x22"
    testDisasm "03fe8b7c" "syscall 0x3fe"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TEQ``() =
    testDisasm "0000003c" "teq r0, r0"
    testDisasm "0022003c" "teq v0, at"
    testDisasm "03fe003c" "teq s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TGE``() =
    testDisasm "0000023c" "tge r0, r0"
    testDisasm "0022023c" "tge v0, at"
    testDisasm "03fe023c" "tge s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TGEU``() =
    testDisasm "0000043c" "tgeu r0, r0"
    testDisasm "0022043c" "tgeu v0, at"
    testDisasm "03fe043c" "tgeu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLBP``() =
    testDisasm "0000037c" "tlbp"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLBR``() =
    testDisasm "0000137c" "tlbr"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLBWI``() =
    testDisasm "0000237c" "tlbwi"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLBWR``() =
    testDisasm "0000337c" "tlbwr"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLT``() =
    testDisasm "0000083c" "tlt r0, r0"
    testDisasm "0022083c" "tlt v0, at"
    testDisasm "03fe083c" "tlt s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TLTU``() =
    testDisasm "00000a3c" "tltu r0, r0"
    testDisasm "00220a3c" "tltu v0, at"
    testDisasm "03fe0a3c" "tltu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TNE``() =
    testDisasm "00000c3c" "tne r0, r0"
    testDisasm "00220c3c" "tne v0, at"
    testDisasm "03fe0c3c" "tne s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TRUNC.L.fmt``() =
    testDisasm "5400233b" "trunc.l.s f0, f0"
    testDisasm "5400633b" "trunc.l.d f0, f0"
    testDisasm "5422233b" "trunc.l.s f1, f2"
    testDisasm "5422633b" "trunc.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 TRUNC.W.fmt``() =
    testDisasm "54002b3b" "trunc.w.s f0, f0"
    testDisasm "54006b3b" "trunc.w.d f0, f0"
    testDisasm "54222b3b" "trunc.w.s f1, f2"
    testDisasm "54226b3b" "trunc.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 6.01 WAIT``() =
    testDisasm "0000937c" "wait 0x0"
    testDisasm "0022937c" "wait 0x22"
    testDisasm "03fe937c" "wait 0x3fe"

  [<TestMethod>]
  member _.``microMIPS64 6.01 WRPGPR``() =
    testDisasm "0000f17c" "wrpgpr r0, r0"
    testDisasm "0022f17c" "wrpgpr at, v0"
    testDisasm "03fef17c" "wrpgpr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 WSBH``() =
    testDisasm "00007b3c" "wsbh r0, r0"
    testDisasm "00227b3c" "wsbh at, v0"
    testDisasm "03fe7b3c" "wsbh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 6.01 XOR``() =
    testDisasm "00000310" "xor r0, r0, r0"
    testDisasm "00000b10" "xor at, r0, r0"
    testDisasm "00001310" "xor v0, r0, r0"
    testDisasm "00001b10" "xor v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 6.01 XORI``() =
    testDisasm "70030000" "xori r0, v1, 0x0"
    testDisasm "70600000" "xori v1, r0, 0x0"
    testDisasm "70030001" "xori r0, v1, 0x1"
    testDisasm "70600001" "xori v1, r0, 0x1"

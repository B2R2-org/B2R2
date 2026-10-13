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
/// One test for each instruction microMIPS64 5.04 describes, SDR to XORI. Each
/// reads words of the instruction and checks the text, and each word is one
/// binutils' objdump reads as the same instruction with the same operands, so
/// what is asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMicroMIPSParserTests3() =
  let isa =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSISAMode.MicroMIPS)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDR``() =
    testDisasm "6000d000" "sdr r0, 0(r0)"
    testDisasm "6000d001" "sdr r0, 1(r0)"
    testDisasm "6000d002" "sdr r0, 2(r0)"
    testDisasm "6000d003" "sdr r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SDXC1``() =
    testDisasm "54000108" "sdxc1 f0, r0(r0)"
    testDisasm "54000908" "sdxc1 f1, r0(r0)"
    testDisasm "54001108" "sdxc1 f2, r0(r0)"
    testDisasm "54001908" "sdxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SEB``() =
    testDisasm "00002b3c" "seb r0, r0"
    testDisasm "00222b3c" "seb at, v0"
    testDisasm "03fe2b3c" "seb ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SEH``() =
    testDisasm "00003b3c" "seh r0, r0"
    testDisasm "00223b3c" "seh at, v0"
    testDisasm "03fe3b3c" "seh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SH``() =
    testDisasm "a8000c00" "sh r0, 0(s0)"
    testDisasm "a8010c00" "sh r0, 2(s0)"
    testDisasm "a8020c00" "sh r0, 4(s0)"
    testDisasm "a8030c00" "sh r0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SH16``() =
    testDisasm "a8000c00" "sh r0, 0(s0)"
    testDisasm "a8010c00" "sh r0, 2(s0)"
    testDisasm "a8020c00" "sh r0, 4(s0)"
    testDisasm "a8030c00" "sh r0, 6(s0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SHE``() =
    testDisasm "6000aa00" "she r0, 0(r0)"
    testDisasm "6000aa01" "she r0, 1(r0)"
    testDisasm "6000aa02" "she r0, 2(r0)"
    testDisasm "6000aa03" "she r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLL``() =
    testDisasm "24000c00" "sll s0, s0, 0x8"
    testDisasm "24020c00" "sll s0, s0, 0x1"
    testDisasm "24040c00" "sll s0, s0, 0x2"
    testDisasm "24060c00" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLL16``() =
    testDisasm "24000c00" "sll s0, s0, 0x8"
    testDisasm "24020c00" "sll s0, s0, 0x1"
    testDisasm "24040c00" "sll s0, s0, 0x2"
    testDisasm "24060c00" "sll s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLLV``() =
    testDisasm "00000010" "sllv r0, r0, r0"
    testDisasm "00000810" "sllv at, r0, r0"
    testDisasm "00001010" "sllv v0, r0, r0"
    testDisasm "00001810" "sllv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLT``() =
    testDisasm "00000350" "slt r0, r0, r0"
    testDisasm "00000b50" "slt at, r0, r0"
    testDisasm "00001350" "slt v0, r0, r0"
    testDisasm "00001b50" "slt v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTI``() =
    testDisasm "90030000" "slti r0, v1, 0x0"
    testDisasm "90600000" "slti v1, r0, 0x0"
    testDisasm "90030001" "slti r0, v1, 0x1"
    testDisasm "90600001" "slti v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTIU``() =
    testDisasm "b0030000" "sltiu r0, v1, 0x0"
    testDisasm "b0600000" "sltiu v1, r0, 0x0"
    testDisasm "b0030001" "sltiu r0, v1, 0x1"
    testDisasm "b0600001" "sltiu v1, r0, 0x1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SLTU``() =
    testDisasm "00000390" "sltu r0, r0, r0"
    testDisasm "00000b90" "sltu at, r0, r0"
    testDisasm "00001390" "sltu v0, r0, r0"
    testDisasm "00001b90" "sltu v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SQRT.fmt``() =
    testDisasm "54000a3b" "sqrt.s f0, f0"
    testDisasm "54004a3b" "sqrt.d f0, f0"
    testDisasm "54220a3b" "sqrt.s f1, f2"
    testDisasm "54224a3b" "sqrt.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRA``() =
    testDisasm "00000080" "sra r0, r0, 0x0"
    testDisasm "00000880" "sra r0, r0, 0x1"
    testDisasm "00001080" "sra r0, r0, 0x2"
    testDisasm "00001880" "sra r0, r0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRAV``() =
    testDisasm "00000090" "srav r0, r0, r0"
    testDisasm "00000890" "srav at, r0, r0"
    testDisasm "00001090" "srav v0, r0, r0"
    testDisasm "00001890" "srav v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRL``() =
    testDisasm "24010c00" "srl s0, s0, 0x8"
    testDisasm "24030c00" "srl s0, s0, 0x1"
    testDisasm "24050c00" "srl s0, s0, 0x2"
    testDisasm "24070c00" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRL16``() =
    testDisasm "24010c00" "srl s0, s0, 0x8"
    testDisasm "24030c00" "srl s0, s0, 0x1"
    testDisasm "24050c00" "srl s0, s0, 0x2"
    testDisasm "24070c00" "srl s0, s0, 0x3"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SRLV``() =
    testDisasm "00000050" "srlv r0, r0, r0"
    testDisasm "00000850" "srlv at, r0, r0"
    testDisasm "00001050" "srlv v0, r0, r0"
    testDisasm "00001850" "srlv v1, r0, r0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SSNOP``() =
    testDisasm "00000800" "ssnop"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUB``() =
    testDisasm "00220190" "sub r0, v0, at"
    testDisasm "00220990" "sub at, v0, at"
    testDisasm "00221190" "sub v0, v0, at"
    testDisasm "00221990" "sub v1, v0, at"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUB.fmt``() =
    testDisasm "54000070" "sub.s f0, f0, f0"
    testDisasm "54000170" "sub.d f0, f0, f0"
    testDisasm "54000270" "sub.ps f0, f0, f0"
    testDisasm "54000870" "sub.s f1, f0, f0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUBU``() =
    testDisasm "04010c00" "subu s0, s0, s0"
    testDisasm "04030c00" "subu s0, s1, s0"
    testDisasm "04050c00" "subu s0, v0, s0"
    testDisasm "04070c00" "subu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUBU16``() =
    testDisasm "04010c00" "subu s0, s0, s0"
    testDisasm "04030c00" "subu s0, s1, s0"
    testDisasm "04050c00" "subu s0, v0, s0"
    testDisasm "04070c00" "subu s0, v1, s0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SUXC1``() =
    testDisasm "54000188" "suxc1 f0, r0(r0)"
    testDisasm "54000988" "suxc1 f1, r0(r0)"
    testDisasm "54001188" "suxc1 f2, r0(r0)"
    testDisasm "54001988" "suxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SW``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SW16``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWC1``() =
    testDisasm "98030000" "swc1 f0, 0(v1)"
    testDisasm "98600000" "swc1 f3, 0(r0)"
    testDisasm "98030001" "swc1 f0, 1(v1)"
    testDisasm "98600001" "swc1 f3, 1(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWC2``() =
    testDisasm "20008000" "swc2 0x0, 0(r0)"
    testDisasm "20008001" "swc2 0x0, 1(r0)"
    testDisasm "20008002" "swc2 0x0, 2(r0)"
    testDisasm "20008003" "swc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWE``() =
    testDisasm "6000ae00" "swe r0, 0(r0)"
    testDisasm "6000ae01" "swe r0, 1(r0)"
    testDisasm "6000ae02" "swe r0, 2(r0)"
    testDisasm "6000ae03" "swe r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWL``() =
    testDisasm "60008000" "swl r0, 0(r0)"
    testDisasm "60008001" "swl r0, 1(r0)"
    testDisasm "60008002" "swl r0, 2(r0)"
    testDisasm "60008003" "swl r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWLE``() =
    testDisasm "6000a000" "swle r0, 0(r0)"
    testDisasm "6000a001" "swle r0, 1(r0)"
    testDisasm "6000a002" "swle r0, 2(r0)"
    testDisasm "6000a003" "swle r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWM16``() =
    testDisasm "45400c00" "swm s0, ra, 0(sp)"
    testDisasm "45410c00" "swm s0, ra, 4(sp)"
    testDisasm "45420c00" "swm s0, ra, 8(sp)"
    testDisasm "45430c00" "swm s0, ra, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWM32``() =
    testDisasm "2022d000" "swm s0, 0(v0)"
    testDisasm "2022d001" "swm s0, 1(v0)"
    testDisasm "2022d002" "swm s0, 2(v0)"
    testDisasm "2022d003" "swm s0, 3(v0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWP``() =
    testDisasm "20009000" "swp r0, at, 0(r0)"
    testDisasm "20009001" "swp r0, at, 1(r0)"
    testDisasm "20009002" "swp r0, at, 2(r0)"
    testDisasm "20009003" "swp r0, at, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWR``() =
    testDisasm "60009000" "swr r0, 0(r0)"
    testDisasm "60009001" "swr r0, 1(r0)"
    testDisasm "60009002" "swr r0, 2(r0)"
    testDisasm "60009003" "swr r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWRE``() =
    testDisasm "6000a200" "swre r0, 0(r0)"
    testDisasm "6000a201" "swre r0, 1(r0)"
    testDisasm "6000a202" "swre r0, 2(r0)"
    testDisasm "6000a203" "swre r0, 3(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWSP``() =
    testDisasm "c8000c00" "sw r0, 0(sp)"
    testDisasm "c8010c00" "sw r0, 4(sp)"
    testDisasm "c8020c00" "sw r0, 8(sp)"
    testDisasm "c8030c00" "sw r0, 12(sp)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SWXC1``() =
    testDisasm "54000088" "swxc1 f0, r0(r0)"
    testDisasm "54000888" "swxc1 f1, r0(r0)"
    testDisasm "54001088" "swxc1 f2, r0(r0)"
    testDisasm "54001888" "swxc1 f3, r0(r0)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SYNC``() =
    testDisasm "00006b7c" "sync 0x0"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SYNCI``() =
    testDisasm "42030000" "synci 0(v1)"
    testDisasm "42030001" "synci 1(v1)"
    testDisasm "42037fff" "synci 32767(v1)"
    testDisasm "42038000" "synci -32768(v1)"

  [<TestMethod>]
  member _.``microMIPS64 5.04 SYSCALL``() =
    testDisasm "00008b7c" "syscall 0x0"
    testDisasm "00228b7c" "syscall 0x22"
    testDisasm "03fe8b7c" "syscall 0x3fe"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TEQ``() =
    testDisasm "0000003c" "teq r0, r0"
    testDisasm "0022003c" "teq v0, at"
    testDisasm "03fe003c" "teq s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TEQI``() =
    testDisasm "41c30000" "teqi v1, 0x0"
    testDisasm "41c30001" "teqi v1, 0x1"
    testDisasm "41c37fff" "teqi v1, 0x7fff"
    testDisasm "41c38000" "teqi v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TGE``() =
    testDisasm "0000023c" "tge r0, r0"
    testDisasm "0022023c" "tge v0, at"
    testDisasm "03fe023c" "tge s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEI``() =
    testDisasm "41230000" "tgei v1, 0x0"
    testDisasm "41230001" "tgei v1, 0x1"
    testDisasm "41237fff" "tgei v1, 0x7fff"
    testDisasm "41238000" "tgei v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEIU``() =
    testDisasm "41630000" "tgeiu v1, 0x0"
    testDisasm "41630001" "tgeiu v1, 0x1"
    testDisasm "41637fff" "tgeiu v1, 0x7fff"
    testDisasm "41638000" "tgeiu v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TGEU``() =
    testDisasm "0000043c" "tgeu r0, r0"
    testDisasm "0022043c" "tgeu v0, at"
    testDisasm "03fe043c" "tgeu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBP``() =
    testDisasm "0000037c" "tlbp"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBR``() =
    testDisasm "0000137c" "tlbr"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBWI``() =
    testDisasm "0000237c" "tlbwi"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLBWR``() =
    testDisasm "0000337c" "tlbwr"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLT``() =
    testDisasm "0000083c" "tlt r0, r0"
    testDisasm "0022083c" "tlt v0, at"
    testDisasm "03fe083c" "tlt s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTI``() =
    testDisasm "41030000" "tlti v1, 0x0"
    testDisasm "41030001" "tlti v1, 0x1"
    testDisasm "41037fff" "tlti v1, 0x7fff"
    testDisasm "41038000" "tlti v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTIU``() =
    testDisasm "41430000" "tltiu v1, 0x0"
    testDisasm "41430001" "tltiu v1, 0x1"
    testDisasm "41437fff" "tltiu v1, 0x7fff"
    testDisasm "41438000" "tltiu v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TLTU``() =
    testDisasm "00000a3c" "tltu r0, r0"
    testDisasm "00220a3c" "tltu v0, at"
    testDisasm "03fe0a3c" "tltu s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TNE``() =
    testDisasm "00000c3c" "tne r0, r0"
    testDisasm "00220c3c" "tne v0, at"
    testDisasm "03fe0c3c" "tne s8, ra"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TNEI``() =
    testDisasm "41830000" "tnei v1, 0x0"
    testDisasm "41830001" "tnei v1, 0x1"
    testDisasm "41837fff" "tnei v1, 0x7fff"
    testDisasm "41838000" "tnei v1, 0xffffffffffff8000"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TRUNC.L.fmt``() =
    testDisasm "5400233b" "trunc.l.s f0, f0"
    testDisasm "5400633b" "trunc.l.d f0, f0"
    testDisasm "5422233b" "trunc.l.s f1, f2"
    testDisasm "5422633b" "trunc.l.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 TRUNC.W.fmt``() =
    testDisasm "54002b3b" "trunc.w.s f0, f0"
    testDisasm "54006b3b" "trunc.w.d f0, f0"
    testDisasm "54222b3b" "trunc.w.s f1, f2"
    testDisasm "54226b3b" "trunc.w.d f1, f2"

  [<TestMethod>]
  member _.``microMIPS64 5.04 WAIT``() =
    testDisasm "0000937c" "wait 0x0"
    testDisasm "0022937c" "wait 0x22"
    testDisasm "03fe937c" "wait 0x3fe"

  [<TestMethod>]
  member _.``microMIPS64 5.04 WRPGPR``() =
    testDisasm "0000f17c" "wrpgpr r0, r0"
    testDisasm "0022f17c" "wrpgpr at, v0"
    testDisasm "03fef17c" "wrpgpr ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 WSBH``() =
    testDisasm "00007b3c" "wsbh r0, r0"
    testDisasm "00227b3c" "wsbh at, v0"
    testDisasm "03fe7b3c" "wsbh ra, s8"

  [<TestMethod>]
  member _.``microMIPS64 5.04 XOR``() =
    testDisasm "44400c00" "xor s0, s0, s0"
    testDisasm "44410c00" "xor s0, s0, s1"
    testDisasm "44420c00" "xor s0, s0, v0"
    testDisasm "44430c00" "xor s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 XOR16``() =
    testDisasm "44400c00" "xor s0, s0, s0"
    testDisasm "44410c00" "xor s0, s0, s1"
    testDisasm "44420c00" "xor s0, s0, v0"
    testDisasm "44430c00" "xor s0, s0, v1"

  [<TestMethod>]
  member _.``microMIPS64 5.04 XORI``() =
    testDisasm "70030000" "xori r0, v1, 0x0"
    testDisasm "70600000" "xori v1, r0, 0x0"
    testDisasm "70030001" "xori r0, v1, 0x1"
    testDisasm "70600001" "xori v1, r0, 0x1"

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
/// One test for each instruction MD00087 describes, SLT to XORI. Each reads
/// words of the instruction and checks the text, and each word is one binutils'
/// objdump reads as the same instruction with the same operands, so what is
/// asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMIPSR6ParserTests3() =
  let isa =
    ISA(Architecture.MIPS,
        Endian.Big,
        WordSize.Bit64,
        int MIPSRelease.R6)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

  [<TestMethod>]
  member _.``MD00087 SLT``() =
    testDisasm "0000002a" "slt r0, r0, r0"
    testDisasm "0020002a" "slt r0, at, r0"
    testDisasm "0001002a" "slt r0, r0, at"
    testDisasm "0000082a" "slt at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SLTI``() =
    testDisasm "28000000" "slti r0, r0, 0x0"
    testDisasm "28200000" "slti r0, at, 0x0"
    testDisasm "28010000" "slti at, r0, 0x0"
    testDisasm "28400000" "slti r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLTIU``() =
    testDisasm "2c000000" "sltiu r0, r0, 0x0"
    testDisasm "2c200000" "sltiu r0, at, 0x0"
    testDisasm "2c010000" "sltiu at, r0, 0x0"
    testDisasm "2c400000" "sltiu r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SLTU``() =
    testDisasm "0000002b" "sltu r0, r0, r0"
    testDisasm "0020002b" "sltu r0, at, r0"
    testDisasm "0001002b" "sltu r0, r0, at"
    testDisasm "0000082b" "sltu at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SQRT.fmt``() =
    testDisasm "46000004" "sqrt.s f0, f0"
    testDisasm "46200004" "sqrt.d f0, f0"
    testDisasm "46001804" "sqrt.s f0, f3"
    testDisasm "46201804" "sqrt.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 SRA``() =
    testDisasm "00000003" "sra r0, r0, 0x0"
    testDisasm "00010003" "sra r0, at, 0x0"
    testDisasm "00000803" "sra at, r0, 0x0"
    testDisasm "00020003" "sra r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SRAV``() =
    testDisasm "00000007" "srav r0, r0, r0"
    testDisasm "00200007" "srav r0, r0, at"
    testDisasm "00010007" "srav r0, at, r0"
    testDisasm "00000807" "srav at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SRL``() =
    testDisasm "00000002" "srl r0, r0, 0x0"
    testDisasm "00010002" "srl r0, at, 0x0"
    testDisasm "00000802" "srl at, r0, 0x0"
    testDisasm "00020002" "srl r0, v0, 0x0"

  [<TestMethod>]
  member _.``MD00087 SRLV``() =
    testDisasm "00000006" "srlv r0, r0, r0"
    testDisasm "00200006" "srlv r0, r0, at"
    testDisasm "00010006" "srlv r0, at, r0"
    testDisasm "00000806" "srlv at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 SSNOP``() =
    testDisasm "00000040" "ssnop"

  [<TestMethod>]
  member _.``MD00087 SUB``() =
    testDisasm "00200022" "sub r0, at, r0"
    testDisasm "00400022" "sub r0, v0, r0"
    testDisasm "00600022" "sub r0, v1, r0"
    testDisasm "00800022" "sub r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 SUB.fmt``() =
    testDisasm "46000001" "sub.s f0, f0, f0"
    testDisasm "46200001" "sub.d f0, f0, f0"
    testDisasm "46021901" "sub.s f4, f3, f2"
    testDisasm "46221901" "sub.d f4, f3, f2"

  [<TestMethod>]
  member _.``MD00087 SUBU``() =
    testDisasm "00200023" "subu r0, at, r0"
    testDisasm "00400023" "subu r0, v0, r0"
    testDisasm "00600023" "subu r0, v1, r0"
    testDisasm "00800023" "subu r0, a0, r0"

  [<TestMethod>]
  member _.``MD00087 SW``() =
    testDisasm "ac000000" "sw r0, 0(r0)"
    testDisasm "ac010000" "sw at, 0(r0)"
    testDisasm "ac020000" "sw v0, 0(r0)"
    testDisasm "ac030000" "sw v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWC1``() =
    testDisasm "e4000000" "swc1 f0, 0(r0)"
    testDisasm "e4010000" "swc1 f1, 0(r0)"
    testDisasm "e4020000" "swc1 f2, 0(r0)"
    testDisasm "e4030000" "swc1 f3, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SWC2``() =
    testDisasm "49600000" "swc2 0x0, 0(r0)"
    testDisasm "49600001" "swc2 0x0, 1(r0)"
    testDisasm "49600002" "swc2 0x0, 2(r0)"
    testDisasm "49600003" "swc2 0x0, 3(r0)"

  [<TestMethod>]
  member _.``MD00087 SWE``() =
    testDisasm "7c00001f" "swe r0, 0(r0)"
    testDisasm "7c01001f" "swe at, 0(r0)"
    testDisasm "7c02001f" "swe v0, 0(r0)"
    testDisasm "7c03001f" "swe v1, 0(r0)"

  [<TestMethod>]
  member _.``MD00087 SYNC``() =
    testDisasm "0000000f" "sync 0x0"

  [<TestMethod>]
  member _.``MD00087 SYNCI``() =
    testDisasm "041f0000" "synci 0(r0)"
    testDisasm "041f0001" "synci 1(r0)"
    testDisasm "041f0002" "synci 2(r0)"
    testDisasm "041f0003" "synci 3(r0)"

  [<TestMethod>]
  member _.``MD00087 SYSCALL``() =
    testDisasm "0000000c" "syscall"

  [<TestMethod>]
  member _.``MD00087 TEQ``() =
    testDisasm "00000034" "teq r0, r0"
    testDisasm "00200034" "teq at, r0"
    testDisasm "00010034" "teq r0, at"
    testDisasm "00400034" "teq v0, r0"

  [<TestMethod>]
  member _.``MD00087 TGE``() =
    testDisasm "00000030" "tge r0, r0"
    testDisasm "00200030" "tge at, r0"
    testDisasm "00010030" "tge r0, at"
    testDisasm "00400030" "tge v0, r0"

  [<TestMethod>]
  member _.``MD00087 TGEU``() =
    testDisasm "00000031" "tgeu r0, r0"
    testDisasm "00200031" "tgeu at, r0"
    testDisasm "00010031" "tgeu r0, at"
    testDisasm "00400031" "tgeu v0, r0"

  [<TestMethod>]
  member _.``MD00087 TLBINV``() =
    testDisasm "42000003" "tlbinv"

  [<TestMethod>]
  member _.``MD00087 TLBINVF``() =
    testDisasm "42000004" "tlbinvf"

  [<TestMethod>]
  member _.``MD00087 TLBP``() =
    testDisasm "42000008" "tlbp"

  [<TestMethod>]
  member _.``MD00087 TLBR``() =
    testDisasm "42000001" "tlbr"

  [<TestMethod>]
  member _.``MD00087 TLBWI``() =
    testDisasm "42000002" "tlbwi"

  [<TestMethod>]
  member _.``MD00087 TLBWR``() =
    testDisasm "42000006" "tlbwr"

  [<TestMethod>]
  member _.``MD00087 TLT``() =
    testDisasm "00000032" "tlt r0, r0"
    testDisasm "00200032" "tlt at, r0"
    testDisasm "00010032" "tlt r0, at"
    testDisasm "00400032" "tlt v0, r0"

  [<TestMethod>]
  member _.``MD00087 TLTU``() =
    testDisasm "00000033" "tltu r0, r0"
    testDisasm "00200033" "tltu at, r0"
    testDisasm "00010033" "tltu r0, at"
    testDisasm "00400033" "tltu v0, r0"

  [<TestMethod>]
  member _.``MD00087 TNE``() =
    testDisasm "00000036" "tne r0, r0"
    testDisasm "00200036" "tne at, r0"
    testDisasm "00010036" "tne r0, at"
    testDisasm "00400036" "tne v0, r0"

  [<TestMethod>]
  member _.``MD00087 TRUNC.L.fmt``() =
    testDisasm "46000009" "trunc.l.s f0, f0"
    testDisasm "46200009" "trunc.l.d f0, f0"
    testDisasm "46001809" "trunc.l.s f0, f3"
    testDisasm "46201809" "trunc.l.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 TRUNC.W.fmt``() =
    testDisasm "4600000d" "trunc.w.s f0, f0"
    testDisasm "4620000d" "trunc.w.d f0, f0"
    testDisasm "4600180d" "trunc.w.s f0, f3"
    testDisasm "4620180d" "trunc.w.d f0, f3"

  [<TestMethod>]
  member _.``MD00087 WAIT``() =
    testDisasm "42000020" "wait"

  [<TestMethod>]
  member _.``MD00087 WRPGPR``() =
    testDisasm "41c00000" "wrpgpr r0, r0"

  [<TestMethod>]
  member _.``MD00087 WSBH``() =
    testDisasm "7c0000a0" "wsbh r0, r0"

  [<TestMethod>]
  member _.``MD00087 XOR``() =
    testDisasm "00000026" "xor r0, r0, r0"
    testDisasm "00200026" "xor r0, at, r0"
    testDisasm "00010026" "xor r0, r0, at"
    testDisasm "00000826" "xor at, r0, r0"

  [<TestMethod>]
  member _.``MD00087 XORI``() =
    testDisasm "38000000" "xori r0, r0, 0x0"
    testDisasm "38200000" "xori r0, at, 0x0"
    testDisasm "38010000" "xori at, r0, 0x0"
    testDisasm "38400000" "xori r0, v0, 0x0"

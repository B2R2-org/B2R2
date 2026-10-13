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
/// One test for each instruction MD00087 describes, SYNC to XORI. Each reads
/// words of the instruction and checks the text, and each word is one binutils'
/// objdump reads as the same instruction with the same operands, so what is
/// asserted is a reading two decoders agree on.
/// </summary>
[<TestClass>]
type ManualMIPSParserTests3() =
  let isa =
    ISA(Architecture.MIPS, Endian.Big, WordSize.Bit64)

  let testDisasm (byteString: string) (expected: string) =
    let bytes = ByteArray.ofHexString byteString
    let parser = Parser(isa, BinReader.Init isa.Endian) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    Assert.AreEqual<string>(expected, ins.Disasm())

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
  member _.``MD00087 TEQI``() =
    testDisasm "040c0000" "teqi r0, 0x0"
    testDisasm "040c0001" "teqi r0, 0x1"
    testDisasm "040c0002" "teqi r0, 0x2"
    testDisasm "040c0003" "teqi r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TGE``() =
    testDisasm "00000030" "tge r0, r0"
    testDisasm "00200030" "tge at, r0"
    testDisasm "00010030" "tge r0, at"
    testDisasm "00400030" "tge v0, r0"

  [<TestMethod>]
  member _.``MD00087 TGEI``() =
    testDisasm "04080000" "tgei r0, 0x0"
    testDisasm "04080001" "tgei r0, 0x1"
    testDisasm "04080002" "tgei r0, 0x2"
    testDisasm "04080003" "tgei r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TGEIU``() =
    testDisasm "04090000" "tgeiu r0, 0x0"
    testDisasm "04090001" "tgeiu r0, 0x1"
    testDisasm "04090002" "tgeiu r0, 0x2"
    testDisasm "04090003" "tgeiu r0, 0x3"

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
  member _.``MD00087 TLTI``() =
    testDisasm "040a0000" "tlti r0, 0x0"
    testDisasm "040a0001" "tlti r0, 0x1"
    testDisasm "040a0002" "tlti r0, 0x2"
    testDisasm "040a0003" "tlti r0, 0x3"

  [<TestMethod>]
  member _.``MD00087 TLTIU``() =
    testDisasm "040b0000" "tltiu r0, 0x0"
    testDisasm "040b0001" "tltiu r0, 0x1"
    testDisasm "040b0002" "tltiu r0, 0x2"
    testDisasm "040b0003" "tltiu r0, 0x3"

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
  member _.``MD00087 TNEI``() =
    testDisasm "040e0000" "tnei r0, 0x0"
    testDisasm "040e0001" "tnei r0, 0x1"
    testDisasm "040e0002" "tnei r0, 0x2"
    testDisasm "040e0003" "tnei r0, 0x3"

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

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
/// The microMIPS64 5.04 instructions binutils 2.42 cannot read back in a
/// microMIPS64 Release 2 object: the coprocessor 1 and 2 branches on a
/// condition code come out as ".short". These words are the manual's
/// encodings written out (POOL32I, then the branch's minor opcode, cc in
/// bits 20:18, 00, and the 16-bit offset), and the text is its Format,
/// "BC1F cc, offset", with the target PC + 4 + (offset shifted left once).
/// </summary>
[<TestClass>]
type ManualHandParserTests() =
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

  /// microMIPS64 5.04 pp.194, 196, 198 and 200.
  [<TestMethod>]
  member _.``microMIPS64 5.04 BC1F BC1T BC2F BC2T``() =
    testDisasm "43880008" "bc1f 0x2, 0x14"
    testDisasm "43a80008" "bc1t 0x2, 0x14"
    testDisasm "42880008" "bc2f 0x2, 0x14"
    testDisasm "42a80008" "bc2t 0x2, 0x14"

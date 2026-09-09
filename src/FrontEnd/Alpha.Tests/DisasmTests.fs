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

namespace B2R2.FrontEnd.BinLifter.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Alpha
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type DisasmTests() =
  static let isa = ISA Architecture.Alpha

  static let parser =
    AlphaParser(BinReader.Init isa.Endian) :> IInstructionParsable

  static let disasm hex =
    let bytes = ByteArray.ofHexString hex
    let ins = parser.Parse(ReadOnlySpan bytes, 0UL)
    let builder = StringDisasmBuilder(false, null, WordSize.Bit64)
    ins.Disasm builder

  [<TestMethod>]
  member _.``[Alpha] the operands are written after a comma test``() =
    Assert.AreEqual<string>("addq r1, r2, r3", disasm "03042240")
    Assert.AreEqual<string>("bis r31, r31, r31", disasm "1F04FF47")

  (* The trap-on-overflow forms of the arithmetic are instructions of their own
     rather than a qualifier, and the handbook writes them with a slash. *)
  [<TestMethod>]
  member _.``[Alpha] the overflow forms carry a slash test``() =
    Assert.AreEqual<string>("addl/v r1, r2, r3", disasm "03082240")
    Assert.AreEqual<string>("mulq/v r1, r2, r3", disasm "030C224C")

  (* The memory an instruction reaches is written the way an assembler for this
     architecture has always written it: a displacement and the register it is
     counted from, in parentheses. *)
  [<TestMethod>]
  member _.``[Alpha] memory is a displacement and a register test``() =
    Assert.AreEqual<string>("lda r1, 0x10(r30)", disasm "10003E20")
    Assert.AreEqual<string>("ldt f1, 0x20(r16)", disasm "2000308C")

  (* A displacement below zero is written as the bits of the word it was
     widened to, so that the assembler reading it back needs to know only how
     wide the field it lands in is. *)
  [<TestMethod>]
  member _.``[Alpha] a displacement below zero is written whole test``() =
    Assert.AreEqual<string>("stq r1, 0xfffffff8(r30)", disasm "F8FF3EB4")
    Assert.AreEqual<string>("beq r1, 0xfffffff8", disasm "FEFF3FE4")

  (* An instruction naming no register at all writes nothing after its name,
     and one naming memory without counting a distance to it writes only the
     register in parentheses. *)
  [<TestMethod>]
  member _.``[Alpha] an instruction may name nothing test``() =
    Assert.AreEqual<string>("mb", disasm "0040FF63")
    Assert.AreEqual<string>("fetch (r16)", disasm "0080F063")
    Assert.AreEqual<string>("rpcc r1", disasm "00C03F60")

  [<TestMethod>]
  member _.``[Alpha] a computed branch writes its hint test``() =
    Assert.AreEqual<string>("jsr r26, (r27), 0x0", disasm "00405B6B")
    Assert.AreEqual<string>("ret r31, (r26), 0x1", disasm "0180FA6B")

  (* A qualifier is written glued to the mnemonic by a slash, because how an
     instruction rounds and what it traps on are part of which instruction it
     is rather than something it works on. *)
  [<TestMethod>]
  member _.``[Alpha] a qualifier is glued to the mnemonic test``() =
    Assert.AreEqual<string>("adds f1, f2, f3", disasm "03102258")
    Assert.AreEqual<string>("adds/suid f1, f2, f3", disasm "03F82258")
    Assert.AreEqual<string>("cvttq/svc f2, f3", disasm "E3A5E25B")
    Assert.AreEqual<string>("addg/sc f1, f2, f3", disasm "03842254")
    Assert.AreEqual<string>("cvtst/s f2, f3", disasm "83D5E25B")

  [<TestMethod>]
  member _.``[Alpha] a trap to palcode writes its function code test``() =
    Assert.AreEqual<string>("call_pal 0x83", disasm "83000000")

// vim: set tw=80 sts=2 sw=2:

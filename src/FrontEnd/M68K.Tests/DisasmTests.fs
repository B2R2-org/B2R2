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
open B2R2.FrontEnd.M68K
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type DisasmTests() =
  static let isa = ISA Architecture.M68K

  static let parser =
    M68KParser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  static let disasmWith (isa: ISA) hex =
    let bytes = ByteArray.ofHexString hex
    let parser = M68KParser(isa, BinReader.Init isa.Endian)
    let ins = (parser :> IInstructionParsable).Parse(ReadOnlySpan bytes, 0UL)
    let builder = StringDisasmBuilder(false, null, WordSize.Bit32)
    ins.Disasm builder

  static let disasm hex = disasmWith isa hex

  (* The size an m68k mnemonic carries is a suffix on the mnemonic itself, so it
     belongs to the mnemonic word and not to an operand. *)
  [<TestMethod>]
  member _.``[M68K] the size is a mnemonic suffix test``() =
    Assert.AreEqual<string>("move.b d0, d1", disasm "1200")
    Assert.AreEqual<string>("move.w d0, d1", disasm "3200")
    Assert.AreEqual<string>("move.l d0, d1", disasm "2200")

  [<TestMethod>]
  member _.``[M68K] a move to an address register is a movea test``() =
    Assert.AreEqual<string>("movea.l a0, a1", disasm "2248")

  [<TestMethod>]
  member _.``[M68K] the register indirect modes test``() =
    Assert.AreEqual<string>("move.l (a0), d1", disasm "2210")
    Assert.AreEqual<string>("move.l (a0)+, -(a1)", disasm "2318")

  (* Every displacement is signed, so a negative one has to read as such rather
     than as the wide hex value its two's complement would print as. *)
  [<TestMethod>]
  member _.``[M68K] a displacement is signed test``() =
    Assert.AreEqual<string>("move.l (0x8,a0), d1", disasm "22280008")
    Assert.AreEqual<string>("move.l (-0x8,a0), d1", disasm "2228FFF8")
    Assert.AreEqual<string>("move.l (0x10,pc), d1", disasm "223A0010")

  [<TestMethod>]
  member _.``[M68K] the absolute and immediate modes test``() =
    Assert.AreEqual<string>("move.l 0x1234, d1", disasm "22381234")
    Assert.AreEqual<string>("move.l #0x12345678, d1", disasm "223C12345678")

  (* A scale of one is what every model reads where the scale bits are absent,
     so printing it would put something in the output that the encoding does not
     say. A larger one is written the way the manual does. *)
  [<TestMethod>]
  member _.``[M68K] an index writes its width and scale test``() =
    Assert.AreEqual<string>("move.l (0x10,a0,d1.w*2), d2", disasm "24301210")
    Assert.AreEqual<string>("move.l (0x10,a0,d1.w), d2", disasm "24301010")
    let full = disasm "2430AD3000001234"
    Assert.AreEqual<string>("move.l (0x1234,a0,a2.l*4), d2", full)

  (* Brackets enclose the values that form the intermediate address of a memory
     indirect mode, and where the index sits relative to the closing bracket is
     the whole of what tells preindexing from postindexing. *)
  [<TestMethod>]
  member _.``[M68K] the memory indirect modes test``() =
    let pre = disasm "2430112200100020"
    Assert.AreEqual<string>("move.l ([0x10,a0,d1.w],0x20), d2", pre)
    let post = disasm "2430112600100020"
    Assert.AreEqual<string>("move.l ([0x10,a0],d1.w,0x20), d2", post)

  [<TestMethod>]
  member _.``[M68K] a suppressed base or index test``() =
    let noIndex = disasm "243001610010"
    Assert.AreEqual<string>("move.l ([0x10,a0],0x0), d2", noIndex)
    let noBase = disasm "243011A00010"
    Assert.AreEqual<string>("move.l (0x10,d1.w), d2", noBase)

  (* The address marker precedes the mnemonic once disassembly is configured to
     show it, which is the only thing that puts the address in the string. *)
  [<TestMethod>]
  member _.``[M68K] the address marker test``() =
    let bytes = ByteArray.ofHexString "2200"
    let ins = parser.Parse(ReadOnlySpan bytes, 0x1000UL)
    let builder = StringDisasmBuilder(true, null, WordSize.Bit32)
    Assert.AreEqual<string>("00001000: move.l d0, d1", ins.Disasm builder)

  (* A relative branch prints the displacement the encoding carries and the
     address it reaches, the second as a comment, so that neither the bytes nor
     the target has to be worked out by hand. The base is the extension word,
     not the start of the instruction. *)
  [<TestMethod>]
  member _.``[M68K] a branch shows its target test``() =
    Assert.AreEqual<string>("bra.b +0x10 ; 0x12", disasm "6010")
    Assert.AreEqual<string>("bra.w +0x10 ; 0x12", disasm "60000010")
    Assert.AreEqual<string>("bra.b -0x10 ; 0xfffffff2", disasm "60f0")
    Assert.AreEqual<string>("bsr.b +0x10 ; 0x12", disasm "6110")
    Assert.AreEqual<string>("dbf.w d0, +0x10 ; 0x12", disasm "51c80010")

  (* MOVEM folds each run of consecutive registers into a range. A run may cross
     from the data registers into the address registers, the two being
     consecutive in the mask. *)
  [<TestMethod>]
  member _.``[M68K] a movem register list test``() =
    Assert.AreEqual<string>("movem.w a6-a7, -(a7)", disasm "48a70003")
    Assert.AreEqual<string>("movem.l (a7)+, d0-d1", disasm "4cdf0003")
    Assert.AreEqual<string>("movem.l d0-a7, -(a7)", disasm "48e7ffff")
    Assert.AreEqual<string>("movem.l (a7)+, d0/d2/a5", disasm "4cdf2005")

  (* A bit field is written inside braces after the address it sits in, and a
     width field of zero reads as the thirty-two bits it means rather than the
     zero it holds. *)
  [<TestMethod>]
  member _.``[M68K] a bit field operand test``() =
    Assert.AreEqual<string>("bftst d0{0x1f:0x20}", disasm "e8c007c0")
    Assert.AreEqual<string>("bfextu d0{d0:d0}, d0", disasm "e9c00820")
    Assert.AreEqual<string>("bfins d0, d0{0x0:0x8}", disasm "efc00008")

  [<TestMethod>]
  member _.``[M68K] the register pair operands test``() =
    let cas2 = disasm "0cfc00400040"
    Assert.AreEqual<string>("cas2.w d0:d0, d1:d1, (d0):(d0)", cas2)
    Assert.AreEqual<string>("divs.l d0, d0:d0", disasm "4c400c00")

  (* The status register and the stack pointers are named where the encoding
     implies them, there being no field for them to come from. *)
  [<TestMethod>]
  member _.``[M68K] the implied registers test``() =
    Assert.AreEqual<string>("move.w sr, d0", disasm "40c0")
    Assert.AreEqual<string>("move.w d0, ccr", disasm "44c0")
    Assert.AreEqual<string>("move.l a0, usp", disasm "4e60")
    Assert.AreEqual<string>("movec.l vbr, d0", disasm "4e7a0801")

  [<TestMethod>]
  member _.``[M68K] the operandless instructions test``() =
    Assert.AreEqual<string>("nop", disasm "4e71")
    Assert.AreEqual<string>("rts", disasm "4e75")
    Assert.AreEqual<string>("illegal", disasm "4afc")
    Assert.AreEqual<string>("traphi", disasm "52fc")

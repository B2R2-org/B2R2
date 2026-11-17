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

namespace B2R2.FrontEnd.PPC.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PPC
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins where control can go after an instruction, which is what a CFG is
/// built from. The 32-bit encodings come from gcc -O2 PIE builds of coreutils
/// ls and binutils objdump, and the 64-bit ones from the ELFv1 build of ls.
[<TestClass>]
type InstructionTests() =
  static let parserOf wordSize (category: Category) =
    Parser(wordSize, category, BinReader.Init Endian.Big)
    :> IInstructionParsable

  static let parser32 = parserOf WordSize.Bit32 Category.Server

  static let parser64 = parserOf WordSize.Bit64 Category.Server

  static let parserVLE = parserOf WordSize.Bit32 Category.VLE

  static let parseWith (parser: IInstructionParsable) addr hex =
    let bytes = ByteArray.ofHexString hex
    parser.Parse(ReadOnlySpan bytes, addr)

  static let parse32 addr hex = parseWith parser32 addr hex

  static let parse64 addr hex = parseWith parser64 addr hex

  static let parseVLE addr hex = parseWith parserVLE addr hex

  static let nexts (ins: IInstruction) = ins.GetNextInstrAddrs()

  [<TestMethod>]
  member _.``[PPC32] a conditional branch also falls through``() =
    let ins = parse32 0x4300UL "4182006c" (* beq 0x436c *)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x4304UL; 0x436cUL |], nexts ins)

  (* BO_1 takes a branch on a set CR bit, and BO_3 one that tests CTR alone
     when CTR reaches zero. *)
  [<TestMethod>]
  member _.``[PPC32] a branch on a clear bit jumps on false``() =
    let onTrue hex = (parse32 0x1000UL hex).IsCJmpOnTrue
    Assert.AreEqual<bool>(true, onTrue "4182006c") (* beq 0x106c *)
    Assert.AreEqual<bool>(false, onTrue "40810010") (* ble 0x1010 *)
    Assert.AreEqual<bool>(true, onTrue "42400044") (* bdz 0x1044 *)
    Assert.AreEqual<bool>(false, onTrue "4200ffe8") (* bdnz 0xfe8 *)

  [<TestMethod>]
  member _.``[PPC32] a branch backward wraps at 32 bits``() =
    let ins = parse32 0x7b80UL "4200ffe8" (* bdnz 0x7b68 *)
    CollectionAssert.AreEqual([| 0x7b84UL; 0x7b68UL |], nexts ins)
    let ins = parse32 0x10UL "4200ffe0" (* bdnz 0xfffffff0 *)
    CollectionAssert.AreEqual([| 0x14UL; 0xfffffff0UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC64] a branch backward wraps at 64 bits``() =
    let ins = parse64 0x10UL "4200ffe0" (* bdnz 0xfffffffffffffff0 *)
    CollectionAssert.AreEqual([| 0x14UL; 0xfffffffffffffff0UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC32] a branch that links nothing goes to its target only``() =
    let ins = parse32 0x40a8UL "48000028" (* b 0x40d0 *)
    Assert.AreEqual<bool>(false, ins.IsCall)
    CollectionAssert.AreEqual([| 0x40d0UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC32] a call returns to the next instruction``() =
    let ins = parse32 0x42f8UL "4800f3ad" (* bl 0x136a4 *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    CollectionAssert.AreEqual([| 0x42fcUL; 0x136a4UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC64] a call returns to the next instruction``() =
    let ins = parse64 0x86fcUL "4bffffc5" (* bl 0x86c0 *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    CollectionAssert.AreEqual([| 0x8700UL; 0x86c0UL |], nexts ins)

  (* PIC code reads where it is with bcl 20,31,$+4, which the ISA keeps off
     the link stack, as it calls nothing. *)
  [<TestMethod>]
  member _.``[PPC32] a branch that reads the PC calls nothing``() =
    let ins = parse32 0x41f0UL "429f0005" (* bcl 20,31,0x41f4 *)
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x41f4UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC32] an indirect call returns to the next instruction``() =
    let ins = parse32 0x40a4UL "4e800421" (* bctrl *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    CollectionAssert.AreEqual([| 0x40a8UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC32] a return has no static next address``() =
    let ins = parse32 0x3ce0UL "4e800020" (* blr *)
    Assert.AreEqual<bool>(true, ins.IsRET)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[PPC32] a conditional return falls through``() =
    let ins = parse32 0xfc08UL "4d820020" (* beqlr *)
    Assert.AreEqual<bool>(true, ins.IsRET)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0xfc0cUL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC32] an indirect jump has no static next address``() =
    let ins = parse32 0x4324UL "4e800420" (* bctr *)
    Assert.AreEqual<bool>(false, ins.IsRET)
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  (* A return pops nothing, so the BO of a return is no immediate that
     a summary would read as what the return takes off the stack. *)
  [<TestMethod>]
  member _.``[PPC32] a branch has no immediate``() =
    let ins = parse32 0x3ce0UL "4e800020" (* blr *)
    Assert.AreEqual<bool>(false, fst (ins.Immediate()))

  (* GCC puts a trap where __builtin_trap is, and a trap whose TO takes in
     every comparison traps whatever it compares. *)
  [<TestMethod>]
  member _.``[PPC32] a trap that always traps has no next address``() =
    let traps =
      [ "7fe00008" (* trap *)
        "7fe32008" (* tw 31,r3,r4 *)
        "7f832008" (* tw 28,r3,r4 *) ]
    for hex in traps do
      let ins = parse32 0x5bb80UL hex
      Assert.AreEqual<bool>(true, ins.IsTerminator null, hex)
      CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins, hex)

  [<TestMethod>]
  member _.``[PPC32] a trap on a condition falls through``() =
    let ins = parse32 0x1000UL "7c832008" (* tweq r3,r4 *)
    Assert.AreEqual<bool>(false, ins.IsExit)
    CollectionAssert.AreEqual([| 0x1004UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC32] a system call ends a block and falls through``() =
    let ins = parse32 0x1000UL "44000002" (* sc *)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    CollectionAssert.AreEqual([| 0x1004UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC32] a nop falls through``() =
    let ins = parse32 0x2555cUL "60000000" (* nop *)
    Assert.AreEqual<bool>(true, ins.IsNop)
    CollectionAssert.AreEqual([| 0x25560UL |], nexts ins)

  [<TestMethod>]
  member _.``[PPC VLE] a branch goes where the base encoding does``() =
    let cond = parseVLE 0x1000UL "e604" (* se_bc 1,2,0x1008 *)
    Assert.AreEqual<bool>(true, cond.IsCondBranch)
    Assert.AreEqual<bool>(true, cond.IsCJmpOnTrue)
    CollectionAssert.AreEqual([| 0x1002UL; 0x1008UL |], nexts cond)
    let call = parseVLE 0x1000UL "e904" (* se_bl 0x1008 *)
    Assert.AreEqual<bool>(true, call.IsCall)
    CollectionAssert.AreEqual([| 0x1002UL; 0x1008UL |], nexts call)
    let jump = parseVLE 0x1000UL "78000010" (* e_b 0x1010 *)
    Assert.AreEqual<bool>(false, jump.IsCondBranch)
    CollectionAssert.AreEqual([| 0x1010UL |], nexts jump)
    let ret = parseVLE 0x1000UL "0004" (* se_blr *)
    Assert.AreEqual<bool>(true, ret.IsRET)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ret)

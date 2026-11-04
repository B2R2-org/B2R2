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
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PPC

/// The control-flow queries of an instruction, which the middle end asks of
/// every instruction it lifts. Each word below is written as the Power ISA
/// draws it, decoded at 0x1000 on a 32-bit processor.
[<TestClass>]
type InstructionTests() =
  static let parser =
    Parser(WordSize.Bit32, BinReader.Init Endian.Big) :> IInstructionParsable

  static let parse hex =
    let bytes = ByteArray.ofHexString hex
    parser.Parse(ReadOnlySpan bytes, 0x1000UL)

  static let target (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, addr -> Some addr
    | false, _ -> None

  [<TestMethod>]
  member _.``[PPC] b Is An Unconditional Direct Branch Test``() =
    let b = parse "48000100" (* b 0x1100 *)
    Assert.IsTrue(b.IsBranch)
    Assert.IsTrue(b.IsDirectBranch)
    Assert.IsFalse(b.IsIndirectBranch)
    Assert.IsFalse(b.IsCondBranch)
    Assert.IsFalse(b.IsCall)
    Assert.IsTrue(b.IsTerminator null)
    Assert.AreEqual<Addr option>(Some 0x1100UL, target b)
    CollectionAssert.AreEqual([| 0x1100UL |], b.GetNextInstrAddrs())

  [<TestMethod>]
  member _.``[PPC] bl Is A Direct Call Test``() =
    let bl = parse "48000101" (* bl 0x1100 *)
    Assert.IsTrue(bl.IsBranch)
    Assert.IsTrue(bl.IsDirectBranch)
    Assert.IsTrue(bl.IsCall)
    Assert.IsFalse(bl.IsCondBranch)
    Assert.IsFalse(bl.IsRET)
    Assert.AreEqual<Addr option>(Some 0x1100UL, target bl)
    CollectionAssert.AreEqual([| 0x1100UL |], bl.GetNextInstrAddrs())

  [<TestMethod>]
  member _.``[PPC] bgt Is Taken When Its CR Bit Is Set Test``() =
    let bgt = parse "41810020" (* bc 12,1,+0x20: bgt cr0 *)
    Assert.IsTrue(bgt.IsCondBranch)
    Assert.IsTrue(bgt.IsCJmpOnTrue)
    Assert.IsFalse(bgt.IsCall)
    Assert.AreEqual<Addr option>(Some 0x1020UL, target bgt)
    CollectionAssert.AreEqual([| 0x1020UL; 0x1004UL |],
                              bgt.GetNextInstrAddrs())

  [<TestMethod>]
  member _.``[PPC] bne Is Taken When Its CR Bit Is Clear Test``() =
    let bne = parse "40820020" (* bc 4,2,+0x20: bne cr0 *)
    Assert.IsTrue(bne.IsCondBranch)
    Assert.IsFalse(bne.IsCJmpOnTrue)

  [<TestMethod>]
  member _.``[PPC] bdnz Counts Down And Branches Backwards Test``() =
    let bdnz = parse "4200fff8" (* bc 16,0,-8: bdnz *)
    Assert.IsTrue(bdnz.IsCondBranch)
    Assert.IsTrue(bdnz.IsCJmpOnTrue)
    Assert.AreEqual<Addr option>(Some 0xff8UL, target bdnz)

  [<TestMethod>]
  member _.``[PPC] bca Branches To An Absolute Address Test``() =
    let bca = parse "42800022" (* bca 20,0,0x20 *)
    Assert.IsFalse(bca.IsCondBranch)
    Assert.AreEqual<Addr option>(Some 0x20UL, target bca)

  [<TestMethod>]
  member _.``[PPC] blr Is A Return Test``() =
    let blr = parse "4e800020" (* bclr 20,0 *)
    Assert.IsTrue(blr.IsBranch)
    Assert.IsTrue(blr.IsIndirectBranch)
    Assert.IsFalse(blr.IsDirectBranch)
    Assert.IsTrue(blr.IsRET)
    Assert.IsFalse(blr.IsCondBranch)
    Assert.IsFalse(blr.IsCall)
    Assert.IsTrue(blr.IsTerminator null)
    Assert.AreEqual<Addr option>(None, target blr)
    CollectionAssert.AreEqual([||], blr.GetNextInstrAddrs())

  [<TestMethod>]
  member _.``[PPC] beqlr Is A Conditional Return Test``() =
    let beqlr = parse "4d820020" (* bclr 12,2 *)
    Assert.IsTrue(beqlr.IsRET)
    Assert.IsTrue(beqlr.IsCondBranch)
    CollectionAssert.AreEqual([| 0x1004UL |], beqlr.GetNextInstrAddrs())

  [<TestMethod>]
  member _.``[PPC] bctr Is An Indirect Jump Test``() =
    let bctr = parse "4e800420" (* bcctr 20,0 *)
    Assert.IsTrue(bctr.IsIndirectBranch)
    Assert.IsFalse(bctr.IsRET)
    Assert.IsFalse(bctr.IsCall)
    CollectionAssert.AreEqual([||], bctr.GetNextInstrAddrs())

  [<TestMethod>]
  member _.``[PPC] bctrl Is An Indirect Call Test``() =
    let bctrl = parse "4e800421" (* bcctrl 20,0 *)
    Assert.IsTrue(bctrl.IsIndirectBranch)
    Assert.IsTrue(bctrl.IsCall)
    Assert.IsFalse(bctrl.IsRET)
    Assert.AreEqual<Addr option>(None, target bctrl)
    CollectionAssert.AreEqual([||], bctrl.GetNextInstrAddrs())

  (* PIC code reads its own address into LR with a bcl that links to the next
     instruction. The lifter calls it a call, so the query does too, and the
     target tells the two apart. *)
  [<TestMethod>]
  member _.``[PPC] bcl To The Next Instruction Is A Call Test``() =
    let bcl = parse "429f0005" (* bcl 20,31,$+4 *)
    Assert.IsTrue(bcl.IsCall)
    Assert.IsFalse(bcl.IsCondBranch)
    Assert.AreEqual<Addr option>(Some 0x1004UL, target bcl)

  [<TestMethod>]
  member _.``[PPC] sc Is An Interrupt Test``() =
    let sc = parse "44000002"
    Assert.IsTrue(sc.IsInterrupt)
    Assert.IsFalse(sc.IsBranch)
    Assert.IsTrue(sc.IsTerminator null)
    CollectionAssert.AreEqual([| 0x1004UL |], sc.GetNextInstrAddrs())
    match sc.InterruptNum() with
    | true, n -> Assert.AreEqual<int64>(0L, n)
    | false, _ -> Assert.Fail "no interrupt number"

  [<TestMethod>]
  member _.``[PPC] rfi Is An Exit Test``() =
    let rfi = parse "4c000064"
    Assert.IsTrue(rfi.IsExit)
    Assert.IsTrue(rfi.IsTerminator null)
    CollectionAssert.AreEqual([||], rfi.GetNextInstrAddrs())

  [<TestMethod>]
  member _.``[PPC] trap Is An Exit Test``() =
    let trap = parse "7fe00008" (* tw 31,0,0 *)
    Assert.IsTrue(trap.IsExit)
    Assert.IsTrue(trap.IsTerminator null)

  [<TestMethod>]
  member _.``[PPC] nop Ends Nothing Test``() =
    let nop = parse "60000000" (* ori 0,0,0 *)
    Assert.IsTrue(nop.IsNop)
    Assert.IsFalse(nop.IsBranch)
    Assert.IsFalse(nop.IsTerminator null)
    CollectionAssert.AreEqual([| 0x1004UL |], nop.GetNextInstrAddrs())

  [<TestMethod>]
  member _.``[PPC] addi Carries Its Immediate Test``() =
    let addi = parse "38610008" (* addi r3,r1,8 *)
    Assert.IsFalse(addi.IsNop)
    Assert.IsFalse(addi.IsBranch)
    Assert.IsFalse(addi.IsInterrupt)
    Assert.IsFalse(addi.IsExit)
    Assert.IsFalse(addi.IsRET)
    Assert.IsFalse(addi.IsPush)
    Assert.IsFalse(addi.IsPop)
    Assert.AreEqual<Addr option>(None, target addi)
    match addi.Immediate() with
    | true, v -> Assert.AreEqual<int64>(8L, v)
    | false, _ -> Assert.Fail "no immediate"

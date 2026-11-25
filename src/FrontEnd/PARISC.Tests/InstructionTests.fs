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

namespace B2R2.FrontEnd.PARISC.Tests

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PARISC
open Microsoft.VisualStudio.TestTools.UnitTesting

/// The encodings come from a gcc -O2 PIE build of coreutils ls for PA-RISC,
/// at the addresses they have there, each transfer with the delay slot that
/// follows it.
[<TestClass>]
type InstructionTests() =
  static let isa = ISA(Architecture.PARISC, Endian.Big, WordSize.Bit32)

  static let parser = Parser(isa, BinReader.Init Endian.Big)

  static let parse addr hex =
    (parser :> IInstructionParsable).Parse(ByteArray.ofHexString hex, addr)

  static let nexts (ins: IInstruction) = ins.GetNextInstrAddrs()

  [<TestMethod>]
  member _.``[PARISC] A Call Returns Past Its Delay Slot Test``() =
    let ins = parse 0x5578UL "e8460b20341a0004" (* b,l 11b10,rp; ldi 2,r26 *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x5580UL; 0x11b10UL |], nexts ins)

  (* Millicode, such as the division routines, returns through GR31. *)
  [<TestMethod>]
  member _.``[PARISC] A Millicode Call Returns Past Its Delay Slot Test``() =
    let ins = parse 0x8f44UL "ebf0014808000240" (* b,l $$divU,r31; nop *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    CollectionAssert.AreEqual([| 0x8f4cUL; 0x28ff0UL |], nexts ins)

  [<TestMethod>]
  member _.``[PARISC] A Branch Past Its Delay Slot Reads The PC Test``() =
    (* b,l 5588,r20; depwi 0,31,2,r20 *)
    let ins = parse 0x5580UL "ea800000d6801c1e"
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsBranch)
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    CollectionAssert.AreEqual([| 0x5588UL |], nexts ins)

  [<TestMethod>]
  member _.``[PARISC] A Procedure Returns Through RP Test``() =
    let ins = parse 0x5004UL "e840c00037de3781" (* bv r0(rp); ldo -440(sp) *)
    Assert.AreEqual<bool>(true, ins.IsRET)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<int>(0, (nexts ins).Length)

  (* A jump table sits right past a jump that nullifies its slot. *)
  [<TestMethod>]
  member _.``[PARISC] A Jump Through A Table Is No Return Test``() =
    let ins = parse 0x5594UL "eaa0c002" (* bv,n r0(r21) *)
    Assert.AreEqual<bool>(false, ins.IsRET)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    Assert.AreEqual<int>(0, (nexts ins).Length)
    let ins = parse 0x28df4UL "ebe0c002" (* bv,n r0(r31) *)
    Assert.AreEqual<bool>(false, ins.IsRET)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)

  [<TestMethod>]
  member _.``[PARISC] A Conditional Branch Goes On Past Its Slot Test``() =
    (* cmpib,= -1,ret0,5a10; copy r4,r19 *)
    let ins = parse 0x5564UL "879f294808040253"
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    Assert.AreEqual<bool>(true, ins.IsCJmpOnTrue)
    CollectionAssert.AreEqual([| 0x556cUL; 0x5a10UL |], nexts ins)
    (* addib,>= -2,ret0,dd48; stb,ma r31,1(r21) *)
    let ins = parse 0xdd54UL "af9d5fdd0ebf1222"
    CollectionAssert.AreEqual([| 0xdd5cUL; 0xdd48UL |], nexts ins)

  (* The range check of a jump table nullifies the jump to the table when
     the index is out of range, so the code goes on past the jump, as the
     lifter has the compare branch there. *)
  [<TestMethod>]
  member _.``[PARISC] A Nullifying Compare Branches Past The Next Test``() =
    let ins = parse 0x5570UL "0b8b8880" (* cmpclr,<< r11,ret0,r0 *)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    Assert.AreEqual<bool>(true, ins.IsCJmpOnTrue)
    Assert.AreEqual<bool * Addr>((true, 0x5578UL), ins.DirectBranchTarget())
    CollectionAssert.AreEqual([| 0x5574UL; 0x5578UL |], nexts ins)
    let ins = parse 0x5574UL "e800000a" (* b,l,n 5580,r0 *)
    Assert.AreEqual<bool>(true, ins.IsBranch)
    CollectionAssert.AreEqual([| 0x5580UL |], nexts ins)
    let ins = parse 0x1000UL "b4001000" (* addi,tr 0,r0,r0 *)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x1008UL |], nexts ins)

  (* The division millicode negates a result in the delay slot of the branch
     to the negation, nullifying that where the result is not negative. *)
  [<TestMethod>]
  member _.``[PARISC] A Slot That Nullifies Passes Over The Target Test``() =
    (* b,l 152e84,r0; add,>= r0,r26,ret1 *)
    let ins = parse 0x153004UL "e81f1cf50b40561d"
    CollectionAssert.AreEqual([| 0x152e84UL; 0x152e88UL |], nexts ins)

  [<TestMethod>]
  member _.``[PARISC] An Instruction That Never Nullifies Goes On Test``() =
    let ins = parse 0x7af0UL "08000240" (* nop *)
    Assert.AreEqual<bool>(true, ins.IsNop)
    Assert.AreEqual<bool>(false, ins.IsTerminator null)
    CollectionAssert.AreEqual([| 0x7af4UL |], nexts ins)
    let ins = parse 0x1000UL "08002880" (* cmpclr,= r0,r0,r0 *)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    let ins = parse 0x1000UL "08000880" (* cmpclr r0,r0,r0 *)
    Assert.AreEqual<bool>(false, ins.IsTerminator null)

  (* GCC plants IITLBP for __builtin_trap. *)
  [<TestMethod>]
  member _.``[PARISC] A Privileged Instruction Traps Test``() =
    let ins = parse 0x7af4UL "04000000" (* iitlbp r0,(sr0,r0) *)
    Assert.AreEqual<bool>(true, ins.IsExit)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    Assert.AreEqual<int>(0, (nexts ins).Length)

  [<TestMethod>]
  member _.``[PARISC] A System Call Returns Past Its Delay Slot Test``() =
    (* be,l 100(sr2,r0),sr0,r31; ldi 1,r20 *)
    let ins = parse 0x1000UL "e400820034140002"
    Assert.AreEqual<bool>(true, ins.IsInterrupt)
    Assert.AreEqual<bool>(false, ins.IsBranch)
    Assert.AreEqual<bool>(false, ins.IsCall)
    CollectionAssert.AreEqual([| 0x1008UL |], nexts ins)

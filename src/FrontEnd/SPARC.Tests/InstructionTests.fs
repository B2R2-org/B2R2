(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.SPARC.Tests

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open Microsoft.VisualStudio.TestTools.UnitTesting

/// The encodings come from gcc and clang -O2 PIE builds of coreutils ls for
/// SPARC V9, at the addresses they have there, each transfer with the delay
/// slot that follows it.
[<TestClass>]
type InstructionTests() =
  static let parser = Parser(BinReader.Init Endian.Big) :> IInstructionParsable

  static let parse addr hex =
    parser.Parse(ByteArray.ofHexString hex, addr)

  static let nexts (ins: IInstruction) = ins.GetNextInstrAddrs()

  [<TestMethod>]
  member _.``[SPARC] A Call Returns Past Its Delay Slot Test``() =
    let ins = parse 0x6bd0UL "400000ccae15e030" (* call 0x6f00; or *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x6bd8UL; 0x6f00UL |], nexts ins)

  [<TestMethod>]
  member _.``[SPARC] An Indirect Call Returns Past Its Delay Slot Test``() =
    let ins = parse 0x4a3cUL "9fc0400001000000" (* call %g1; nop *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    CollectionAssert.AreEqual([| 0x4a44UL |], nexts ins)

  (* RESTORE in the slot turns the window back to the caller, whose %o7 the
     callee then returns through. *)
  [<TestMethod>]
  member _.``[SPARC] A Call That Restores The Window Never Returns Test``() =
    let ins = parse 0x6c7cUL "400039e581e80000" (* call 0x15410; restore *)
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsBranch)
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    CollectionAssert.AreEqual([| 0x15410UL |], nexts ins)

  (* A leaf keeps its return address in %g1 across the call and moves it back
     into %o7 in the slot, after the call has linked. *)
  [<TestMethod>]
  member _.``[SPARC] A Call That Moves Back The Link Never Returns Test``() =
    let ins = parse 0xab74UL "400489db9e100001" (* call free; mov %g1, %o7 *)
    Assert.AreEqual<bool>(false, ins.IsCall)
    CollectionAssert.AreEqual([| 0x12d2e0UL |], nexts ins)
    let ins = parse 0xab74UL "400489db82100001" (* call free; mov %g1, %g1 *)
    Assert.AreEqual<bool>(true, ins.IsCall)

  [<TestMethod>]
  member _.``[SPARC] A Function Returns 8 Past Its Link Test``() =
    for addr, hex in [| 0x6bf8UL, "81c7e00881e80000" (* ret; restore *)
                        0x6f00UL, "81c3e008ae03c017" (* retl; add *)
                        0x6f6cUL, "81cfe00801000000" (* return %i7+8 *) |] do
      let ins = parse addr hex
      Assert.AreEqual<bool>(true, ins.IsRET)
      Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
      Assert.AreEqual<bool>(false, ins.IsCall)
      Assert.AreEqual<int>(0, (nexts ins).Length)

  [<TestMethod>]
  member _.``[SPARC] A Jump Through A Table Is No Return Test``() =
    let ins = parse 0x51a0UL "81c7000101000000" (* jmp %i4 + %g1; nop *)
    Assert.AreEqual<bool>(false, ins.IsRET)
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    Assert.AreEqual<int>(0, (nexts ins).Length)

  [<TestMethod>]
  member _.``[SPARC] A Conditional Branch Goes On Past Its Slot Test``() =
    for addr, hex, target in
      [| 0x6cf8UL, "1248001125000002", 0x6d3cUL (* bne %icc; sethi *)
         0x517cUL, "2240002235000009", 0x5204UL (* be,a,pn %icc; sethi *)
         0x4964UL, "02ce4004c225c000", 0x4974UL (* brz %i1; st *)
         0x18818UL, "1d48005da2102016", 0x1898cUL (* fbule; mov *) |] do
      let ins = parse addr hex
      Assert.AreEqual<bool>(true, ins.IsCondBranch)
      Assert.AreEqual<bool>(true, ins.IsCJmpOnTrue)
      CollectionAssert.AreEqual([| addr + 8UL; target |], nexts ins)

  [<TestMethod>]
  member _.``[SPARC] A Branch Always Goes To Its Target Only Test``() =
    let b = parse 0x4994UL "1068000501000000" (* b %xcc, 0x49a8; nop *)
    Assert.AreEqual<bool>(false, b.IsCondBranch)
    CollectionAssert.AreEqual([| 0x49a8UL |], nexts b)
    let ba = parse 0x6f08UL "3068000601000000" (* b,a %xcc, 0x6f20 *)
    Assert.AreEqual<uint32>(4u, ba.Extent)
    CollectionAssert.AreEqual([| 0x6f20UL |], nexts ba)

  (* BN runs its delay slot and goes on, and BN,a skips it. *)
  [<TestMethod>]
  member _.``[SPARC] A Branch Never Goes On Past Its Slot Test``() =
    for hex in [| "0080000401000000"; "2080000401000000" |] do
      let ins = parse 0x1000UL hex
      Assert.AreEqual<bool>(false, ins.IsBranch)
      Assert.AreEqual<bool>(true, ins.IsTerminator null)
      CollectionAssert.AreEqual([| 0x1008UL |], nexts ins)

  [<TestMethod>]
  member _.``[SPARC] A Trap That GCC Plants Ends The Program Test``() =
    let ins = parse 0x14c938UL "91d02005" (* ta 5 *)
    Assert.AreEqual<bool>(true, ins.IsExit)
    Assert.AreEqual<bool>(false, ins.IsInterrupt)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    Assert.AreEqual<int>(0, (nexts ins).Length)
    let ins = parse 0x6ef8UL "00000000" (* illtrap 0 *)
    Assert.AreEqual<bool>(true, ins.IsExit)
    Assert.AreEqual<int>(0, (nexts ins).Length)

  [<TestMethod>]
  member _.``[SPARC] A System Call Goes On Past Itself Test``() =
    let ins = parse 0x1000UL "91d0206d" (* ta 0x6d *)
    Assert.AreEqual<bool>(true, ins.IsInterrupt)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    CollectionAssert.AreEqual([| 0x1004UL |], nexts ins)

  [<TestMethod>]
  member _.``[SPARC] An Immediate Comes From A Non Transfer Test``() =
    let mutable v = 0L
    let ins = parse 0x6bd4UL "ae15e030" (* or %l7, 0x30, %l7 *)
    Assert.AreEqual<bool>(true, ins.Immediate &v)
    Assert.AreEqual<int64>(0x30L, v)
    Assert.AreEqual<bool>(true, (parse 0x6becUL "01000000").IsNop)
    let ret = parse 0x6bf8UL "81c7e00881e80000" (* ret; restore *)
    Assert.AreEqual<bool>(false, ret.Immediate &v)

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

namespace B2R2.FrontEnd.CIL.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.CIL
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins what an instruction says about the control flow through it, which is
/// what a CFG is built from: which instructions end a block, where each goes,
/// and which of those places are written into the instruction itself.
[<TestClass>]
type InstructionTests() =
  static let parser =
    CILParser(BinReader.Init Endian.Little) :> IInstructionParsable

  static let parseAt addr hex =
    let bytes = ByteArray.ofHexString hex
    parser.Parse(ReadOnlySpan bytes, addr)

  static let parse hex = parseAt 0x1000UL hex

  static let nexts (ins: IInstruction) = ins.GetNextInstrAddrs()

  static let target (ins: IInstruction) =
    let mutable addr = 0UL
    if ins.DirectBranchTarget &addr then Some addr else None

  static let immediate (ins: IInstruction) =
    let mutable v = 0L
    if ins.Immediate &v then Some v else None

  [<TestMethod>]
  member _.``[CIL] an unconditional branch goes one place test``() =
    let ins = parse "2b05"
    Assert.AreEqual<bool>(true, ins.IsBranch)
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    Assert.AreEqual<bool>(false, ins.IsIndirectBranch)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    Assert.AreEqual(Some 0x1007UL, target ins)
    CollectionAssert.AreEqual([| 0x1007UL |], nexts ins)

  [<TestMethod>]
  member _.``[CIL] a leave is a branch like any other test``() =
    let ins = parse "dd00000000"
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x1005UL |], nexts ins)

  [<TestMethod>]
  member _.``[CIL] a conditional branch goes two places test``() =
    let ins = parse "2d05"
    Assert.AreEqual<bool>(true, ins.IsBranch)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    Assert.AreEqual(Some 0x1007UL, target ins)
    CollectionAssert.AreEqual([| 0x1002UL; 0x1007UL |], nexts ins)

  (* brfalse goes where the value is not, and bne.un where the two differ, so
     neither goes where the predicate its name states holds. *)
  [<TestMethod>]
  member _.``[CIL] which way a conditional branch goes test``() =
    Assert.AreEqual<bool>(true, (parse "2d05").IsCJmpOnTrue)
    Assert.AreEqual<bool>(true, (parse "2e05").IsCJmpOnTrue)
    Assert.AreEqual<bool>(true, (parse "3b00000000").IsCJmpOnTrue)
    Assert.AreEqual<bool>(false, (parse "2c05").IsCJmpOnTrue)
    Assert.AreEqual<bool>(false, (parse "3900000000").IsCJmpOnTrue)
    Assert.AreEqual<bool>(false, (parse "3305").IsCJmpOnTrue)
    Assert.AreEqual<bool>(false, (parse "4000000000").IsCJmpOnTrue)
    Assert.AreEqual<bool>(false, (parse "2b05").IsCJmpOnTrue)

  (* A switch goes to every entry of its table or falls through, and no single
     address stands for that. *)
  [<TestMethod>]
  member _.``[CIL] a switch goes everywhere its table says test``() =
    let ins = parse "450200000002000000fcffffff"
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    Assert.AreEqual(None, target ins)
    CollectionAssert.AreEqual([| 0x100dUL; 0x100fUL; 0x1009UL |], nexts ins)

  [<TestMethod>]
  member _.``[CIL] a switch table lists an address once test``() =
    let ins = parse "450200000000000000fbffffff"
    CollectionAssert.AreEqual([| 0x100dUL; 0x1008UL |], nexts ins)

  (* A call names a method by a token rather than by an address, so it is a
     branch with no target the instruction can say; only calli, which goes
     where a pointer on the stack says, is indirect. *)
  [<TestMethod>]
  member _.``[CIL] a call is a branch without an address test``() =
    for hex in [| "2801000006"; "6f0100000a"; "7301000006" |] do
      let ins = parse hex
      Assert.AreEqual<bool>(true, ins.IsCall)
      Assert.AreEqual<bool>(true, ins.IsBranch)
      Assert.AreEqual<bool>(false, ins.IsDirectBranch)
      Assert.AreEqual<bool>(false, ins.IsIndirectBranch)
      Assert.AreEqual(None, target ins)
      CollectionAssert.AreEqual([| 0x1005UL |], nexts ins)
    let calli = parse "2901000011"
    Assert.AreEqual<bool>(true, calli.IsCall)
    Assert.AreEqual<bool>(true, calli.IsIndirectBranch)

  (* A jmp hands the arguments on to another method and never comes back. *)
  [<TestMethod>]
  member _.``[CIL] a jmp never falls through test``() =
    let ins = parse "2701000006"
    Assert.AreEqual<bool>(true, ins.IsCall)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[CIL] a return has no next instruction test``() =
    for hex in [| "2a"; "dc"; "fe11" |] do
      let ins = parse hex
      Assert.AreEqual<bool>(true, ins.IsRET)
      Assert.AreEqual<bool>(true, ins.IsBranch)
      Assert.AreEqual<bool>(true, ins.IsTerminator null)
      CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[CIL] a throw exits test``() =
    for hex in [| "7a"; "fe1a" |] do
      let ins = parse hex
      Assert.AreEqual<bool>(true, ins.IsExit)
      Assert.AreEqual<bool>(false, ins.IsBranch)
      Assert.AreEqual<bool>(true, ins.IsTerminator null)
      CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[CIL] a break is a trap test``() =
    let ins = parse "01"
    Assert.AreEqual<bool>(true, ins.IsInterrupt)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    let mutable num = 0L
    Assert.AreEqual<bool>(false, ins.InterruptNum &num)

  [<TestMethod>]
  member _.``[CIL] an ordinary instruction falls through test``() =
    let ins = parse "58"
    Assert.AreEqual<bool>(false, ins.IsBranch)
    Assert.AreEqual<bool>(false, ins.IsTerminator null)
    CollectionAssert.AreEqual([| 0x1001UL |], nexts ins)
    Assert.AreEqual<bool>(true, (parse "00").IsNop)
    Assert.AreEqual<bool>(false, (parse "58").IsNop)

  (* An integer an instruction carries is its immediate; a token names a
     thing rather than a number, a float is not an integer, and an address is
     where a branch goes. *)
  [<TestMethod>]
  member _.``[CIL] the immediate is the integer carried test``() =
    Assert.AreEqual(Some -1L, immediate (parse "1fff"))
    Assert.AreEqual(Some 0x12345678L, immediate (parse "2078563412"))
    Assert.AreEqual(Some -1L, immediate (parse "21ffffffffffffffff"))
    Assert.AreEqual(Some 5L, immediate (parse "0e05"))
    Assert.AreEqual(Some 4L, immediate (parse "fe1204"))
    Assert.AreEqual(None, immediate (parse "2801000006"))
    Assert.AreEqual(None, immediate (parse "220000c03f"))
    Assert.AreEqual(None, immediate (parse "2b05"))
    Assert.AreEqual(None, immediate (parse "00"))

  (* Nothing is lifted yet, and the failure says so by the one exception a
     caller is told to expect. *)
  [<TestMethod>]
  member _.``[CIL] lifting says what is not implemented test``() =
    let isa = ISA Architecture.CIL
    let regFactory = RegisterFactory isa
    let builder = ILowUIRBuilder.Default(isa, regFactory, LowUIRStream())
    let ins = parse "58"
    let e =
      Assert.ThrowsExactly<NotImplementedIRException>(fun () ->
        ins.Translate builder |> ignore)
    Assert.AreEqual<string>("add", e.Data0)

// vim: set tw=80 sts=2 sw=2:

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
type InstructionTests() =
  static let parser =
    let isa = ISA Architecture.M68K
    M68KParser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  static let parse hex =
    let head = ByteArray.ofHexString hex
    let bytes = Array.append head (Array.zeroCreate 22)
    parser.Parse(ReadOnlySpan bytes, 0x1000UL)

  (* The address and length a parse reports are what a caller walks a section
     by, so a length that came from the opcode word alone rather than from where
     the extension words stopped would step into the middle of the next
     instruction. *)
  [<TestMethod>]
  member _.``[M68K] address and length test``() =
    let ins = parse "223C12345678"
    Assert.AreEqual<Addr>(0x1000UL, ins.Address)
    Assert.AreEqual<uint32>(6u, ins.Length)

  (* IsTerminator reads IsBranch, IsInterrupt, and IsExit, so leaving any of
     them unimplemented takes every block-level API down with it however valid
     the input was. A MOVE ends no block. *)
  [<TestMethod>]
  member _.``[M68K] a move ends no block test``() =
    let ins = parse "2200"
    Assert.AreEqual<bool>(false, ins.IsBranch)
    Assert.AreEqual<bool>(false, ins.IsInterrupt)
    Assert.AreEqual<bool>(false, ins.IsExit)
    Assert.AreEqual<bool>(false, ins.IsTerminator null)

  [<TestMethod>]
  member _.``[M68K] a move is neither a call nor a return test``() =
    let ins = parse "2200"
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<bool>(false, ins.IsRET)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    Assert.AreEqual<bool>(false, ins.IsNop)

  [<TestMethod>]
  member _.``[M68K] a move has no branch target test``() =
    let ins = parse "2200"
    let mutable target = 0UL
    Assert.AreEqual<bool>(false, ins.IsDirectBranch)
    Assert.AreEqual<bool>(false, ins.IsIndirectBranch)
    Assert.AreEqual<bool>(false, ins.DirectBranchTarget &target)

  (* The branch families are what IsTerminator turns on, and each of them has to
     answer for what kind of transfer it is: a Bcc of the always condition is a
     BRA and not conditional, a BSR is a call, and an RTS a return. *)
  [<TestMethod>]
  member _.``[M68K] the branch families test``() =
    let bra = parse "6010"
    Assert.AreEqual<bool>(true, bra.IsBranch)
    Assert.AreEqual<bool>(false, bra.IsCondBranch)
    Assert.AreEqual<bool>(true, bra.IsTerminator null)
    let bhi = parse "6210"
    Assert.AreEqual<bool>(true, bhi.IsCondBranch)
    let dbf = parse "51c80010"
    Assert.AreEqual<bool>(true, dbf.IsCondBranch)
    let bsr = parse "6110"
    Assert.AreEqual<bool>(true, bsr.IsCall)
    Assert.AreEqual<bool>(false, bsr.IsCondBranch)
    let rts = parse "4e75"
    Assert.AreEqual<bool>(true, rts.IsRET)
    Assert.AreEqual<bool>(true, rts.IsBranch)

  (* A JSR through a register reaches an address only the running program knows,
     which is what tells an indirect branch from a direct one. *)
  [<TestMethod>]
  member _.``[M68K] a jump is direct or indirect test``() =
    let indirect = parse "4e90"
    Assert.AreEqual<bool>(true, indirect.IsCall)
    Assert.AreEqual<bool>(true, indirect.IsIndirectBranch)
    Assert.AreEqual<bool>(false, indirect.IsDirectBranch)
    let direct = parse "4eb91234abcd"
    Assert.AreEqual<bool>(true, direct.IsDirectBranch)
    Assert.AreEqual<bool>(false, direct.IsIndirectBranch)

  (* A relative branch counts its displacement from the extension word holding
     it, so the target of a branch at 0x1000 displaced by 0x10 is 0x1012 rather
     than 0x1010. *)
  [<TestMethod>]
  member _.``[M68K] a branch target counts from the extension word test``() =
    let mutable target = 0UL
    let bra = parse "6010"
    Assert.AreEqual<bool>(true, bra.DirectBranchTarget &target)
    Assert.AreEqual<Addr>(0x1012UL, target)
    let dbf = parse "51c8fff0"
    Assert.AreEqual<bool>(true, dbf.DirectBranchTarget &target)
    Assert.AreEqual<Addr>(0xff2UL, target)
    let jsr = parse "4eb91234abcd"
    Assert.AreEqual<bool>(true, jsr.DirectBranchTarget &target)
    Assert.AreEqual<Addr>(0x1234abcdUL, target)

  (* Each of these enters an exception vector rather than the instruction after
     it, so a block ends there. *)
  [<TestMethod>]
  member _.``[M68K] the instructions that trap test``() =
    for hex in [| "4e40"; "4e76"; "4afc"; "484a"; "4180"; "52fc" |] do
      let ins = parse hex
      Assert.AreEqual<bool>(true, ins.IsInterrupt, hex)
      Assert.AreEqual<bool>(true, ins.IsTerminator null, hex)

  [<TestMethod>]
  member _.``[M68K] the instructions that leave test``() =
    for hex in [| "4e73"; "4e720000"; "4e70" |] do
      let ins = parse hex
      Assert.AreEqual<bool>(true, ins.IsExit, hex)
      Assert.AreEqual<bool>(true, ins.IsTerminator null, hex)

  [<TestMethod>]
  member _.``[M68K] a nop is a nop test``() =
    Assert.AreEqual<bool>(true, (parse "4e71").IsNop)
    Assert.AreEqual<bool>(false, (parse "4e71").IsTerminator null)

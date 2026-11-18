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
    Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  static let parse hex =
    let head = ByteArray.ofHexString hex
    let bytes = Array.append head (Array.zeroCreate 22)
    parser.Parse(ReadOnlySpan bytes, 0x1000UL)

  static let parseAt addr hex =
    let bytes = ByteArray.ofHexString hex
    parser.Parse(ReadOnlySpan bytes, addr)

  static let nexts (ins: IInstruction) = ins.GetNextInstrAddrs()

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

  [<TestMethod>]
  member _.``[M68K] a conditional branch also falls through test``() =
    let branches =
      [ 0x80002e6aUL, "67000284", 0x80002e6eUL, 0x800030f0UL (* beq.w *)
        0x4e52UL, "6608", 0x4e54UL, 0x4e5cUL (* bne.s *)
        0x5c88UL, "f2931094", 0x5c8cUL, 0x6d1eUL (* fbge *)
        0x35b3eUL, "51cfffa2", 0x35b42UL, 0x35ae2UL (* dbf d7 *) ]
    for addr, hex, next, target in branches do
      let ins = parseAt addr hex
      Assert.AreEqual<bool>(true, ins.IsCondBranch, hex)
      CollectionAssert.AreEqual([| next; target |], nexts ins, hex)

  (* A DBcc branches where its condition fails, and so does an FDBcc. *)
  [<TestMethod>]
  member _.``[M68K] a decrementing branch jumps on false test``() =
    let onTrue hex = (parseAt 0x1000UL hex).IsCJmpOnTrue
    Assert.AreEqual<bool>(true, onTrue "67000284") (* beq.w *)
    Assert.AreEqual<bool>(true, onTrue "f2931094") (* fbge *)
    Assert.AreEqual<bool>(false, onTrue "51cfffa2") (* dbf d7 *)

  [<TestMethod>]
  member _.``[M68K] a branch goes to its target only test``() =
    let ins = parseAt 0x4ee8UL "600e" (* bra.s 0x4ef8 *)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x4ef8UL |], nexts ins)

  [<TestMethod>]
  member _.``[M68K] a call returns to the next instruction test``() =
    let calls =
      [ 0x4e46UL, "61fffffffc60", 0x4e4cUL, 0x4aa8UL (* bsr.l *)
        0x80002dd0UL, "4eb9800165a0", 0x80002dd6UL, 0x800165a0UL (* jsr *)
        0x800034f4UL, "4ebaff9e", 0x800034f8UL, 0x80003494UL (* jsr (d,pc) *) ]
    for addr, hex, next, target in calls do
      let ins = parseAt addr hex
      Assert.AreEqual<bool>(true, ins.IsCall, hex)
      Assert.AreEqual<bool>(true, ins.IsDirectBranch, hex)
      CollectionAssert.AreEqual([| next; target |], nexts ins, hex)

  [<TestMethod>]
  member _.``[M68K] an indirect call returns to the next instruction test``() =
    let ins = parseAt 0x80002e60UL "4e94" (* jsr (a4) *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    CollectionAssert.AreEqual([| 0x80002e62UL |], nexts ins)

  [<TestMethod>]
  member _.``[M68K] a jump through a table has no static next address test``() =
    let ins = parseAt 0x80002e82UL "4efb0002" (* jmp (2,pc,d0.w) *)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    Assert.AreEqual<bool>(false, ins.IsDirectBranch)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[M68K] a return has no static next address test``() =
    let ins = parseAt 0x4e84UL "4e75" (* rts *)
    Assert.AreEqual<bool>(true, ins.IsRET)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  (* What an RTD drops off the stack is what a caller of it has to know. *)
  [<TestMethod>]
  member _.``[M68K] a return that drops arguments tells how many test``() =
    let ins = parseAt 0x1000UL "4e740008" (* rtd #8 *)
    let mutable v = 0L
    Assert.AreEqual<bool>(true, ins.IsRET)
    Assert.AreEqual<bool>(true, ins.Immediate &v)
    Assert.AreEqual<int64>(8L, v)

  (* Linux takes TRAP #0 as a system call, which comes back, and sends a
     signal for any other vector: GCC puts TRAP #7 where __builtin_trap is,
     right before the next function. ILLEGAL comes back, if at all, to
     itself, as after the call to __libc_start_main in _start. *)
  [<TestMethod>]
  member _.``[M68K] only a system call comes back from a trap test``() =
    let syscall = parseAt 0x1000UL "4e40" (* trap #0 *)
    Assert.AreEqual<bool>(false, syscall.IsExit)
    CollectionAssert.AreEqual([| 0x1002UL |], nexts syscall)
    let traps =
      [ "4e47" (* trap #7 *)
        "4afc" (* illegal *) ]
    for hex in traps do
      let ins = parseAt 0x56744UL hex
      Assert.AreEqual<bool>(true, ins.IsExit, hex)
      Assert.AreEqual<bool>(true, ins.IsTerminator null, hex)
      CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins, hex)

  [<TestMethod>]
  member _.``[M68K] a nop falls through test``() =
    let ins = parseAt 0x32702UL "4e71"
    Assert.AreEqual<bool>(true, ins.IsNop)
    CollectionAssert.AreEqual([| 0x32704UL |], nexts ins)

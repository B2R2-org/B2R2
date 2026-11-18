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

namespace B2R2.FrontEnd.BinLifter.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type InstructionTests() =
  static let parser =
    let isa = ISA(Architecture.S390, endian = Endian.Big)
    Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  static let parse hex =
    let head = ByteArray.ofHexString hex
    let bytes = Array.append head (Array.zeroCreate 8)
    parser.Parse(ReadOnlySpan bytes, 0x1000UL)

  static let parserOf wordSize =
    let isa = ISA(Architecture.S390, Endian.Big, wordSize)
    Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable

  static let parser31 = parserOf WordSize.Bit32

  static let parser64 = parserOf WordSize.Bit64

  static let parseWith (parser: IInstructionParsable) addr hex =
    let bytes = ByteArray.ofHexString hex
    parser.Parse(ReadOnlySpan bytes, addr)

  static let parse31 addr hex = parseWith parser31 addr hex

  static let parse64 addr hex = parseWith parser64 addr hex

  static let nexts (ins: IInstruction) = ins.GetNextInstrAddrs()

  (* IsTerminator reads IsInterrupt and IsExit, both of which used to be
     unimplemented, so asking whether any S390 instruction ended a block raised
     NotImplementedException and took every block-level API with it. *)
  [<TestMethod>]
  member _.``[S390] Supervisor Call Is An Interrupt Test``() =
    let svc = parse "0a00"
    Assert.AreEqual<bool>(true, svc.IsInterrupt)
    Assert.AreEqual<bool>(true, svc.IsTerminator null)

  [<TestMethod>]
  member _.``[S390] Monitor Call Is An Interrupt Test``() =
    Assert.AreEqual<bool>(true, (parse "af001000").IsInterrupt)

  (* Program Return leaves the service routine a Program Call entered, and
     Load PSW replaces the whole program status word, which is how S390 returns
     from an interruption. Both end execution of the current stream. *)
  [<TestMethod>]
  member _.``[S390] Program Return Is An Exit Test``() =
    let pr = parse "0101"
    Assert.AreEqual<bool>(true, pr.IsExit)
    Assert.AreEqual<bool>(true, pr.IsTerminator null)

  [<TestMethod>]
  member _.``[S390] Load PSW Is An Exit Test``() =
    Assert.AreEqual<bool>(true, (parse "82001000").IsExit)

  [<TestMethod>]
  member _.``[S390] A Plain Load Ends Nothing Test``() =
    let lr = parse "1812"
    Assert.AreEqual<bool>(false, lr.IsInterrupt)
    Assert.AreEqual<bool>(false, lr.IsExit)
    Assert.AreEqual<bool>(false, lr.IsTerminator null)

  (* A branch already ended a block, which must stay true now that the two
     other tests of IsTerminator answer instead of raising. *)
  [<TestMethod>]
  member _.``[S390] A Branch Ends A Block Test``() =
    Assert.AreEqual<bool>(true, (parse "07fe").IsTerminator null)

  (* Bytes with no opcode used to parse into an InvalOp instruction, so every
     address looked like code to a linear sweep and TryParseInstruction never
     reported a failure on this architecture. *)
  [<TestMethod>]
  member _.``[S390] Undecodable Bytes Do Not Parse Test``() =
    for hex in [| "ffff"; "ffffffff"; "ffffffffffff" |] do
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parse hex |> ignore) |> ignore

  (* The encodings from here on come from gcc and clang -O2 PIE builds of
     coreutils printf and ls, at the addresses they have there. *)
  [<TestMethod>]
  member _.``[S390] A Call Returns To The Next Instruction Test``() =
    let ins = parse64 0x22b2UL "c0e5fffffec7" (* brasl %r14,0x2040 *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsDirectBranch)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x22b8UL; 0x2040UL |], nexts ins)

  [<TestMethod>]
  member _.``[S390] An Indirect Call Returns To The Next Instruction Test``() =
    let ins = parse64 0x2444UL "0de2" (* basr %r14,%r2 *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    CollectionAssert.AreEqual([| 0x2446UL |], nexts ins)

  (* The PLT reads where it is with BASR to R0, which saves the address that
     follows and branches nowhere. *)
  [<TestMethod>]
  member _.``[S390] A Branch To R0 Reads The PC Test``() =
    let ins = parse64 0x1c0eUL "0d10" (* basr %r1,%r0 *)
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<bool>(false, ins.IsBranch)
    Assert.AreEqual<bool>(false, ins.IsTerminator null)
    CollectionAssert.AreEqual([| 0x1c10UL |], nexts ins)

  [<TestMethod>]
  member _.``[S390] A Conditional Branch Also Falls Through Test``() =
    let ins = parse64 0x22bcUL "a7740005" (* jne 0x22c6 *)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    Assert.AreEqual<bool>(true, ins.IsCJmpOnTrue)
    CollectionAssert.AreEqual([| 0x22c0UL; 0x22c6UL |], nexts ins)

  [<TestMethod>]
  member _.``[S390] A Branch On Every Code Goes To Its Target Only Test``() =
    let j = parse64 0x2376UL "a7f40009" (* j 0x2388 *)
    Assert.AreEqual<bool>(false, j.IsCondBranch)
    CollectionAssert.AreEqual([| 0x2388UL |], nexts j)
    let jg = parse64 0x23f6UL "c0f4fffffd05" (* jg 0x1e00 *)
    Assert.AreEqual<bool>(false, jg.IsCall)
    CollectionAssert.AreEqual([| 0x1e00UL |], nexts jg)

  (* A compare and branch picks equal, low and high with its mask. *)
  [<TestMethod>]
  member _.``[S390] A Compare And Branch Is Conditional Test``() =
    let ins = parse64 0x2556UL "ec4200e7297f" (* clijh %r4,41,0x2724 *)
    Assert.AreEqual<bool>(true, ins.IsBranch)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x255cUL; 0x2724UL |], nexts ins)

  [<TestMethod>]
  member _.``[S390] A Branch On Count Is Conditional Test``() =
    let ins = parse64 0x66c8UL "a776ff86" (* brct %r7,0x65d4 *)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x66ccUL; 0x65d4UL |], nexts ins)

  (* GCC returns through the register it reloads the saved R14 into, and jumps
     through a table by way of R14, so no branch tells a return by itself. *)
  [<TestMethod>]
  member _.``[S390] No Branch Tells A Return By Itself Test``() =
    let br = parse64 0x4a37cUL "07fe" (* br %r14 *)
    Assert.AreEqual<bool>(false, br.IsRET)
    Assert.AreEqual<bool>(true, br.IsIndirectBranch)
    Assert.AreEqual<int>(0, (nexts br).Length)
    let ber = parse64 0x8170UL "078e" (* ber %r14 *)
    Assert.AreEqual<bool>(true, ber.IsCondBranch)
    CollectionAssert.AreEqual([| 0x8172UL |], nexts ber)
    Assert.AreEqual<bool>(false, (parse64 0x22f4UL "07f4").IsRET) (* br %r4 *)

  [<TestMethod>]
  member _.``[S390] A Jump Through A Table Is Indirect Test``() =
    let ins = parse64 0x2efcUL "47f52000" (* b 0(%r5,%r2) *)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    Assert.AreEqual<bool>(false, ins.IsCondBranch)
    Assert.AreEqual<int>(0, (nexts ins).Length)

  (* GCC pads between functions with nopr %r7, a branch on no code. *)
  [<TestMethod>]
  member _.``[S390] A Branch On No Code Is A Nop Test``() =
    for hex in [| "0707"; "a7040000"; "47000000"; "07f0" |] do
      let ins = parse64 0x22f6UL hex
      Assert.AreEqual<bool>(true, ins.IsNop)
      Assert.AreEqual<bool>(false, ins.IsBranch)
      CollectionAssert.AreEqual([| 0x22f6UL + uint64 ins.Length |], nexts ins)

  (* GCC plants j .+2 where __builtin_trap is, a branch into its own second
     halfword, which holds no valid opcode. *)
  [<TestMethod>]
  member _.``[S390] A Branch Into Its Own Second Halfword Traps Test``() =
    let ins = parse64 0x3f818UL "a7f40001" (* j 0x3f81a *)
    Assert.AreEqual<bool>(true, ins.IsExit)
    Assert.AreEqual<bool>(false, ins.IsBranch)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    Assert.AreEqual<int>(0, (nexts ins).Length)

  [<TestMethod>]
  member _.``[S390] A Branch Target Wraps At 31 Bits Test``() =
    let ins = parse31 0x23e6UL "c0e500002b05" (* brasl %r14,0x79f0 *)
    CollectionAssert.AreEqual([| 0x23ecUL; 0x79f0UL |], nexts ins)
    let ins = parse31 0x1000UL "a7f48000" (* j 0x7fff1000 *)
    CollectionAssert.AreEqual([| 0x7fff1000UL |], nexts ins)
    let ins = parse64 0x1000UL "a7f48000" (* j 0xffffffffffff1000 *)
    CollectionAssert.AreEqual([| 0xffffffffffff1000UL |], nexts ins)

  [<TestMethod>]
  member _.``[S390] An Immediate Comes From A Non Branch Test``() =
    let mutable v = 0L
    let lghi = parse64 0x22aaUL "a7490400" (* lghi %r4,1024 *)
    Assert.AreEqual<bool>(true, lghi.Immediate &v)
    Assert.AreEqual<int64>(1024L, v)
    let aghi = parse64 0x22a6UL "a7fbfb60" (* aghi %r15,-1184 *)
    Assert.AreEqual<bool>(true, aghi.Immediate &v)
    Assert.AreEqual<int64>(-1184L, v)
    let j = parse64 0x2376UL "a7f40009" (* j 0x2388 *)
    Assert.AreEqual<bool>(false, j.Immediate &v)

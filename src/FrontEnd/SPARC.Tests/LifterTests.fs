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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open type Register

[<TestClass>]
type LifterTests() =
  let num (v: int64) = BitVector(v, 64<rt>) |> AST.num

  let t64 id = AST.tmpvar 64<rt> id

  let isa = ISA(Architecture.SPARC, Endian.Little)

  let reader = BinReader.Init Endian.Little

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let ( !. ) reg = Register.toRegID reg |> regFactory.GetRegVar

  let unwrapStmts stmts = Array.sub stmts 1 (Array.length stmts - 2)

  let parse (hex: string) =
    let parser = Parser(reader) :> IInstructionParsable
    parser.Parse(ByteArray.ofHexString hex, 0UL)

  /// The statements the instruction at the start of the given bytes lifts
  /// to, marks and all.
  let lifted hex =
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    (parse hex).Translate builder

  let test (bytes: byte[], givenStmts) =
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let parser = Parser(reader) :> IInstructionParsable
    let ins = parser.Parse(bytes, 0UL)
    CollectionAssert.AreEqual(givenStmts, unwrapStmts <| ins.Translate builder)

  (* A transfer carries its delay slot: the slot runs after the transfer has
     read what decides it and before control leaves, so it is lifted between
     the two, with no marks of its own, and the transfer ends the statements
     rather than an IEMark. *)
  let testDelaySlot branch slot (givenStmts: Stmt[]) =
    CollectionAssert.AreEqual(givenStmts, Array.tail (lifted (branch + slot)))

  /// The statements an instruction lifts to alone, without its marks.
  let slotOf hex = lifted hex |> unwrapStmts

  /// BNE on icc, to 8 bytes past itself.
  let bne = "02008012"

  /// BNE,a on icc, to 8 bytes past itself.
  let bneA = "02008032"

  /// What BNE on icc reads: icc.Z clear.
  let iccNotZero () = (!.CCZI == AST.num0 32<rt>) == AST.b0

  /// The target of a branch 8 bytes past the branch.
  let branchTarget () = !.PC .+ AST.zext 64<rt> (num 8L)

  /// ADD %o2, %o5, %o7.
  let addO7 = "0d80029e"

  let ( ++ ) byteString givenStmts =
    ByteArray.ofHexString byteString, givenStmts

  /// <summary>
  /// A conditional branch reads its condition before its delay slot runs,
  /// since the slot may change what it reads, then goes where the value it
  /// read says. Branch and slot are one instruction of the branch's length,
  /// and nothing in it is left in nPC.
  /// </summary>
  [<TestMethod>]
  member _.``[SPARC] BNE runs its delay slot then branches``() =
    let taken = AST.tmpvar 1<rt> 1
    Assert.AreEqual<uint32>(4u, (parse (bne + addO7)).Length)
    testDelaySlot bne addO7
    <| Array.concat
         [ [| taken := iccNotZero () |]
           [| t64 2 := !.O2 .+ !.O5
              !.O7 := t64 2 |]
           [| AST.intercjmp taken (branchTarget ()) (!.PC .+ num 8L) |] ]

  /// An annulling branch runs its delay slot only when it is taken: the
  /// taken path runs the slot and goes to the target, the other goes past
  /// the slot without running it.
  [<TestMethod>]
  member _.``[SPARC] BNE,a runs its delay slot only when taken``() =
    let stream = LowUIRStream()
    let lblTaken = stream.NewLabel "Taken"
    let lblNotTaken = stream.NewLabel "NotTaken"
    let taken, notTaken = AST.jmpDest lblTaken, AST.jmpDest lblNotTaken
    testDelaySlot bneA addO7
    <| Array.concat
         [ [| AST.cjmp (iccNotZero ()) taken notTaken
              AST.lmark lblTaken |]
           slotOf addO7
           [| AST.interjmp (branchTarget ()) InterJmpKind.Base
              AST.lmark lblNotTaken
              AST.interjmp (!.PC .+ num 8L) InterJmpKind.Base |] ]

  /// BA,a and BN,a annul their delay slot whatever happens, so they never
  /// read it: they lift alone, on bytes that end with them.
  [<TestMethod>]
  member _.``[SPARC] BA,a and BN,a lift without their delay slot``() =
    let baA = [| AST.interjmp (branchTarget ()) InterJmpKind.Base |]
    let bnA = [| AST.interjmp (!.PC .+ num 8L) InterJmpKind.Base |]
    CollectionAssert.AreEqual(baA, Array.tail (lifted "02008030"))
    CollectionAssert.AreEqual(bnA, Array.tail (lifted "02008020"))

  /// <summary>
  /// CALL links into %o7 before its delay slot runs, so the slot reads the
  /// link; but %o7 itself is written only once the slot is done, the slot
  /// working on a copy of it, so a slot that faults leaves %o7 as it was.
  /// </summary>
  [<TestMethod>]
  member _.``[SPARC] CALL's slot sees the link committed after it``() =
    let link = t64 1
    (* call .+8 ; add %o7, 8, %o0 *)
    testDelaySlot "02000040" "08e00390"
    <| [| link := !.PC
          t64 2 := link .+ num 8L
          !.O0 := t64 2
          !.O7 := link
          AST.interjmp (!.PC .+ num 8L) InterJmpKind.IsCall |]

  /// A slot that writes %o7 writes the copy CALL committed, so its value is
  /// the one %o7 is left with.
  [<TestMethod>]
  member _.``[SPARC] CALL's slot writes %o7 over the link``() =
    let link = t64 1
    (* call .+8 ; add %o2, %o5, %o7 *)
    testDelaySlot "02000040" addO7
    <| [| link := !.PC
          t64 2 := !.O2 .+ !.O5
          link := t64 2
          !.O7 := link
          AST.interjmp (!.PC .+ num 8L) InterJmpKind.IsCall |]

  /// A slot that turns the register window, as RESTORE does in a tail call,
  /// moves %o7 out from under any copy, so CALL links before it.
  [<TestMethod>]
  member _.``[SPARC] CALL links before a slot that turns the window``() =
    (* call .+8 ; restore *)
    testDelaySlot "02000040" "0000e881"
    <| [| !.O7 := !.PC
          t64 1 := num 0L
          !.O0 := !.I0
          !.O1 := !.I1
          !.O2 := !.I2
          !.O3 := !.I3
          !.O4 := !.I4
          !.O5 := !.I5
          !.O6 := !.I6
          !.O7 := !.I7
          AST.sideEffect RestoreWindow
          !.G0 := !.G0
          AST.interjmp (!.PC .+ num 8L) InterJmpKind.IsCall |]

  /// <summary>
  /// JMPL whose rd is its rs1 reads its target before the link and its slot,
  /// and writes rd only after the slot: a slot that faults leaves rd as it
  /// was, so running the JMPL again goes where it went the first time.
  /// </summary>
  [<TestMethod>]
  member _.``[SPARC] JMPL into its own rs1 writes it after its slot``() =
    let target, link = t64 1, t64 2
    (* jmpl %g1 + 8, %g1 ; add %g1, 8, %o0 *)
    testDelaySlot "0860c083" "08600090"
    <| [| target := !.G1 .+ num 8L
          link := !.PC
          t64 3 := link .+ num 8L
          !.O0 := t64 3
          !.G1 := link
          AST.interjmp target InterJmpKind.Base |]

  /// JMPL into %g0, which is what RET is, links nowhere.
  [<TestMethod>]
  member _.``[SPARC] JMPL to %g0 discards the link (ret) lift Test``() =
    (* ret ; nop *)
    testDelaySlot "08e0c781" "00000001"
    <| [| t64 1 := !.I7 .+ num 8L
          AST.interjmp (t64 1) InterJmpKind.Base |]

  /// <summary>
  /// RETURN runs its delay slot in the window it restores, before restoring
  /// it: the slot's %oN is the caller's %oN, which is the callee's %iN, so
  /// the slot works on %iN and the window turns after it. A slot that faults
  /// leaves the window where it was.
  /// </summary>
  [<TestMethod>]
  member _.``[SPARC] RETURN runs its slot on the window it restores``() =
    (* return %i7 + 8 ; add %o2, %o5, %o7 *)
    testDelaySlot "08e0cf81" addO7
    <| [| t64 1 := !.I7 .+ num 8L
          t64 2 := !.I2 .+ !.I5
          !.I7 := t64 2
          !.O0 := !.I0
          !.O1 := !.I1
          !.O2 := !.I2
          !.O3 := !.I3
          !.O4 := !.I4
          !.O5 := !.I5
          !.O6 := !.I6
          !.O7 := !.I7
          AST.sideEffect RestoreWindow
          AST.interjmp (t64 1) InterJmpKind.IsRet |]

  /// A RETURN slot that reads the restored window's %l or %i cannot run in
  /// the old window, so the window is restored first.
  [<TestMethod>]
  member _.``[SPARC] RETURN restores first for a slot reading %l``() =
    (* return %i7 + 8 ; add %l0, 8, %o0 *)
    testDelaySlot "08e0cf81" "08200490"
    <| [| t64 1 := !.I7 .+ num 8L
          !.O0 := !.I0
          !.O1 := !.I1
          !.O2 := !.I2
          !.O3 := !.I3
          !.O4 := !.I4
          !.O5 := !.I5
          !.O6 := !.I6
          !.O7 := !.I7
          AST.sideEffect RestoreWindow
          t64 2 := !.L0 .+ num 8L
          !.O0 := t64 2
          AST.interjmp (t64 1) InterJmpKind.IsRet |]

  /// A transfer in a delay slot (a DCTI couple) is not lifted: the slot
  /// raises an undefined instruction, and nothing of the transfer in it is
  /// taken.
  [<TestMethod>]
  member _.``[SPARC] a transfer in a delay slot is undefined``() =
    let taken = AST.tmpvar 1<rt> 1
    (* bne .+8 ; ba .+8 *)
    testDelaySlot bne "02008010"
    <| [| taken := iccNotZero ()
          AST.sideEffect UndefinedInstruction
          AST.intercjmp taken (branchTarget ()) (!.PC .+ num 8L) |]

  /// A branch whose bytes end before its delay slot still parses, but is not
  /// lifted: alone it would transfer without running the slot.
  [<TestMethod>]
  member _.``[SPARC] a branch without its delay slot is not lifted``() =
    Assert.AreEqual<uint32>(4u, (parse bne).Length)
    Assert.ThrowsExactly<MissingDelaySlotException>(fun () ->
      lifted bne |> ignore) |> ignore

  /// An instruction lifts the same after a branch as anywhere else: the
  /// branch carries its slot and leaves nothing behind for the instruction
  /// that sits there.
  [<TestMethod>]
  member _.``[SPARC] a delay slot lifts alone as it does anywhere``() =
    let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let parser = Parser(reader) :> IInstructionParsable
    (* bne .+8 ; sethi %hi(0x1000), %o0 *)
    let sethi = "04000011"
    let bytes = ByteArray.ofHexString (bne + sethi)
    parser.Parse(bytes, 0UL).Translate builder |> ignore
    let slot = parser.Parse(System.ReadOnlySpan(bytes, 4, 4), 4UL)
    let fresh = LowUIRBuilder(isa, regFactory, LowUIRStream())
    let alone = parser.Parse(ByteArray.ofHexString sethi, 4UL)
    CollectionAssert.AreEqual(alone.Translate fresh, slot.Translate builder)

  /// RD %pc in a delay slot reads the slot's own address, not the branch's.
  [<TestMethod>]
  member _.``[SPARC] RD %pc in a delay slot reads the slot address``() =
    let taken = AST.tmpvar 1<rt> 1
    (* bne .+8 ; rd %pc, %o0 *)
    testDelaySlot bne "00404191"
    <| [| taken := iccNotZero ()
          !.O0 := num 4L
          AST.intercjmp taken (branchTarget ()) (!.PC .+ num 8L) |]

  /// An instruction and the delay slot it carries depend on the bytes of
  /// both; one that annuls its slot whatever happens, and one that has none,
  /// on their own.
  [<TestMethod>]
  member _.``[SPARC] the extent of a branch covers its delay slot``() =
    Assert.AreEqual<uint32>(8u, (parse (bne + addO7)).Extent)
    Assert.AreEqual<uint32>(4u, (parse ("02008030" + addO7)).Extent)
    Assert.AreEqual<uint32>(4u, (parse addO7).Extent)

  /// DONE and RETRY resume at a trap's saved PC alone: there is no nPC to
  /// write.
  [<TestMethod>]
  member _.``[SPARC] DONE and RETRY write the PC alone``() =
    "0000f081" ++ [| !.PC := !.TNPC |] |> test
    "0000f083" ++ [| !.PC := !.TPC |] |> test

  [<TestMethod>]
  member _.``[SPARC] ADD (three reg operands) lift Test``() =
    "0d80029e"
    ++ [| t64 1 := !.O2 .+ !.O5
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] ADD (two reg op, one imm op) lift Test``() =
    "8ab6029e"
    ++ [| t64 1 := !.O2 .+ num 0xfffffffffffff68aL
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] ADD (with carry) lift Test``() =
    "0d80429e"
    ++ [| t64 1 := !.O2 .+ !.O5 .+ AST.zext 64<rt> (AST.extract !.CCC 1<rt> 31)
          !.O7 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] ADD (with carry and modify icc) lift Test``() =
    "0d80429e"
    ++ [| t64 1 := !.O2 .+ !.O5 .+ AST.zext 64<rt> (AST.extract !.CCC 1<rt> 31)
          !.O7 := t64 1 |]
    |> test

  /// SUBcc keeps the condition codes in the registers apart from CCR: the
  /// result, whose bits 63 and 31 are the N flags and whose being zero is the
  /// Z flags, and the overflow and borrow vectors, whose bits 63 and 31 are
  /// the V and C flags.
  [<TestMethod>]
  member _.``[SPARC] SUBcc keeps the condition codes apart lift Test``() =
    "0a40a280"
    ++ [| t64 1 := !.O1 .- !.O2
          !.CCN := t64 1
          !.CCZI := AST.xtlo 32<rt> (t64 1)
          !.CCZX := t64 1
          !.CCV := (!.O1 <+> !.O2) .& (!.O1 <+> t64 1)
          !.CCC := (AST.not !.O1 .& !.O2) .| (t64 1 .& (AST.not !.O1 .| !.O2))
          !.G0 := !.G0 |]
    |> test

  /// RDCCR and WRCCR move CCR as a byte of the eight flags, which the
  /// registers apart from it keep, so neither touches CCR itself.
  [<TestMethod>]
  member _.``[SPARC] RD and WR of CCR go through the flags lift Test``() =
    let lifted hex =
      let builder = LowUIRBuilder(isa, regFactory, LowUIRStream())
      let parser = Parser(reader) :> IInstructionParsable
      (parser.Parse(ByteArray.ofHexString hex, 0UL)).Translate builder
    let touchesCCR hex =
      lifted hex |> Array.exists (fun s -> s.ToString().Contains "CCR")
    Assert.AreEqual(false, touchesCCR "00804097")
    Assert.AreEqual(false, touchesCCR "00208385")

  /// %g0 reads as the zero it always holds, so CLR, which is a store of it,
  /// stores the constant to the address the register names alone.
  [<TestMethod>]
  member _.``[SPARC] %g0 reads as zero lift Test``() =
    "000022c0"
    ++ [| AST.store Endian.Big !.O0 (BitVector(0u, 32<rt>) |> AST.num) |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] SAVE rotates the window in lift Test``() =
    "0240e091"
    ++ [| t64 1 := !.G1 .+ !.G2
          AST.sideEffect SaveWindow
          !.I0 := !.O0
          !.I1 := !.O1
          !.I2 := !.O2
          !.I3 := !.O3
          !.I4 := !.O4
          !.I5 := !.O5
          !.I6 := !.O6
          !.I7 := !.O7
          !.O0 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] RESTORE rotates the window out lift Test``() =
    "0240e891"
    ++ [| t64 1 := !.G1 .+ !.G2
          !.O0 := !.I0
          !.O1 := !.I1
          !.O2 := !.I2
          !.O3 := !.I3
          !.O4 := !.I4
          !.O5 := !.I5
          !.O6 := !.I6
          !.O7 := !.I7
          AST.sideEffect RestoreWindow
          !.O0 := t64 1 |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] FLUSHW flushes the windows lift Test``() =
    "00005881"
    ++ [| AST.sideEffect FlushWindows |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] TA to the syscall trap becomes a SysCall lift Test``() =
    "6d20d091"
    ++ [| AST.sideEffect SysCall |]
    |> test

  [<TestMethod>]
  member _.``[SPARC] TA to another trap number is a no-op lift Test``() =
    "0520d091"
    ++ [||]
    |> test



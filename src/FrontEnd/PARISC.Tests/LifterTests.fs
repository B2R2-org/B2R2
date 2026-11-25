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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PARISC
open type Register

/// Pins how a transfer of control lifts: it carries the instruction in its
/// delay slot, which runs after the transfer has read what decides it and
/// before control leaves, so the two lift as one instruction ending with the
/// transfer. What the transfer writes the slot reads, yet the registers take
/// it only once the slot has run, so a slot that faults leaves them as they
/// were.
[<TestClass>]
type LifterTests() =
  let isa = ISA(Architecture.PARISC, Endian.Big, WordSize.Bit32)

  let reader = BinReader.Init Endian.Big

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let ( !. ) reg = Register.toRegID reg |> regFactory.GetRegVar

  let num (v: uint32) = AST.num (BitVector(u32 = v, bitLen = 32<rt>))

  let tmp i = AST.tmpvar 32<rt> i

  let bit i = AST.tmpvar 1<rt> i

  let parse (hex: string) =
    let parser = Parser(isa, reader) :> IInstructionParsable
    parser.Parse(ByteArray.ofHexString hex, 0UL)

  let newBuilder () = LowUIRBuilder(isa, regFactory, LowUIRStream())

  /// The statements the instruction at the start of the given bytes lifts
  /// to, past its opening mark: a transfer writes no closing one.
  let lifted hex = (parse hex).Translate(newBuilder ()) |> Array.tail

  /// The index of the first statement writing the given register.
  let writeOf reg (stmts: Stmt[]) =
    let rid = Register.toRegID reg
    stmts
    |> Array.findIndex (fun stmt ->
      match stmt with
      | Put(Dst = Var(RegisterID = r)) -> r = rid
      | _ -> false)

  /// How many statements write the given register.
  let writesOf reg (stmts: Stmt[]) =
    let rid = Register.toRegID reg
    stmts
    |> Array.filter (fun stmt ->
      match stmt with
      | Put(Dst = Var(RegisterID = r)) -> r = rid
      | _ -> false)
    |> Array.length

  /// The condition on which a branch jumps over its slot.
  let skipsSlot stmt =
    match stmt with
    | CJmp(Cond = c) -> c
    | _ -> failwith $"no jump over a slot: {stmt}"

  let hasSideEffect eff (stmts: Stmt[]) =
    stmts
    |> Array.exists (fun stmt ->
      match stmt with
      | SideEffect(Effect = e) -> e = eff
      | _ -> false)

  /// Where an instruction may go, in the order its jumps appear.
  let exits (stmts: Stmt[]) =
    stmts
    |> Array.choose (fun stmt ->
      match stmt with
      | InterJmp(Target = t) -> Some t
      | _ -> None)

  /// BV to the address in RP.
  let bvRp = "e840c000"

  /// LDW -20(SP), RP, which reloads the return address as an epilogue does.
  let ldwRp = "4bc23fd9"

  /// LDO 5(R0), R1, which reads and writes nothing the transfers do.
  let ldoR1 = "3401000a"

  /// BL to 0x18 linking RP.
  let blRp = "e8400020"

  [<TestMethod>]
  member _.``[PARISC] BV reads its register before its delay slot``() =
    let ins = parse (bvRp + ldwRp)
    Assert.AreEqual<uint32>(4u, ins.Length)
    Assert.AreEqual<uint32>(8u, ins.Extent)
    let stmts = lifted (bvRp + ldwRp)
    let target = !.GR2 .& num 0xfffffffcu
    Assert.AreEqual<Stmt>((tmp 1 := target), stmts[0])
    Assert.IsLessThan(stmts.Length - 1, writeOf GR2 stmts)
    let last = AST.interjmp (tmp 1) InterJmpKind.Base
    Assert.AreEqual<Stmt>(last, Array.last stmts)

  /// BV goes eight bytes further for each step of its index, as through a
  /// table of two-instruction entries, and an index of GR0 adds nothing.
  [<TestMethod>]
  member _.``[PARISC] BV scales its index by eight``() =
    (* bv r3(rp) ; nop *)
    let stmts = lifted ("e843c000" + "08000240")
    let target = (!.GR2 .+ (!.GR3 << num 3u)) .& num 0xfffffffcu
    Assert.AreEqual<Stmt>((tmp 1 := target), stmts[0])

  /// The slot reads the link the branch leaves, but RP takes it only after
  /// the slot has run.
  [<TestMethod>]
  member _.``[PARISC] BL links after its delay slot``() =
    (* b,l .+0x18, rp ; ldo 0(rp), r1 *)
    let stmts = lifted (blRp + "34410000")
    let expected =
      [| tmp 1 := num 0xbu
         tmp 2 := tmp 1 .+ num 0u
         !.GR1 := tmp 2
         !.GR2 := tmp 1
         AST.interjmp (num 0x18u) InterJmpKind.IsCall |]
    CollectionAssert.AreEqual(expected, stmts)

  /// The slot reads the sum, but R5 takes it only after the slot has run, so
  /// a slot that faults leaves R5 as it was and running the pair again adds
  /// once.
  [<TestMethod>]
  member _.``[PARISC] ADDB writes its sum after its delay slot``() =
    (* addb,= r4, r5, .+0x10 ; ldw 0(r5), r1 *)
    let stmts = lifted ("a0a42010" + "48a10000")
    let load = writeOf GR1 stmts
    Assert.AreEqual<Stmt>((!.GR5 := tmp 4), stmts[writeOf GR5 stmts])
    Assert.IsGreaterThan(load, writeOf GR5 stmts)
    Assert.AreEqual<Stmt>((tmp 5 := tmp 4 .+ num 0u), stmts[load - 1])
    let last = AST.intercjmp (bit 3) (num 0x10u) (num 8u)
    Assert.AreEqual<Stmt>(last, Array.last stmts)

  [<TestMethod>]
  member _.``[PARISC] MOVB writes its copy after its delay slot``() =
    (* movb,= r4, r5, .+0x10 ; ldo 5(r0), r1 *)
    let stmts = lifted ("c8a42010" + ldoR1)
    Assert.IsGreaterThan(writeOf GR1 stmts, writeOf GR5 stmts)

  /// CMPB reads its operands before its slot runs, so a slot that writes one
  /// leaves the branch where the comparison sent it.
  [<TestMethod>]
  member _.``[PARISC] CMPB reads its condition before its delay slot``() =
    (* cmpb,= r4, r5, .+0x10 ; ldo 0(r0), r4 *)
    let stmts = lifted ("80a42010" + "34040000")
    let expected =
      [| tmp 1 := !.GR4 .- !.GR5
         bit 2 := (!.GR4 == !.GR5)
         tmp 3 := !.GR0 .+ num 0u
         !.GR4 := tmp 3
         AST.intercjmp (bit 2) (num 0x10u) (num 8u) |]
    CollectionAssert.AreEqual(expected, stmts)

  /// BLR links as BL does: the slot reads the link, RP takes it after.
  [<TestMethod>]
  member _.``[PARISC] BLR links after its delay slot``() =
    (* blr r3, rp ; ldo 0(rp), r1 *)
    let stmts = lifted ("e8434000" + "34410000")
    Assert.AreEqual<Stmt>((tmp 3 := tmp 2 .+ num 0u), stmts[2])
    Assert.IsGreaterThan(writeOf GR1 stmts, writeOf GR2 stmts)

  /// A branch that links and goes right past its slot reads where it runs,
  /// as PIC code does to find a jump table, rather than calls.
  [<TestMethod>]
  member _.``[PARISC] BL past its delay slot reads the PC``() =
    (* b,l .+8, r20 ; depwi 0, 31, 2, r20 *)
    let stmts = lifted ("ea800000" + "d6801c1e")
    Assert.AreEqual<Stmt>((!.GR20 := tmp 1), stmts[stmts.Length - 2])
    let last = AST.interjmp (num 8u) InterJmpKind.Base
    Assert.AreEqual<Stmt>(last, Array.last stmts)

  /// A branch that links GR0 keeps no link, so there is nothing to hold.
  [<TestMethod>]
  member _.``[PARISC] B without a link writes nothing``() =
    (* b .+0x18 ; ldo 5(r0), r1 *)
    let stmts = lifted ("e8000020" + ldoR1)
    let expected =
      [| tmp 1 := !.GR0 .+ num 5u
         !.GR1 := tmp 1
         AST.interjmp (num 0x18u) InterJmpKind.Base |]
    CollectionAssert.AreEqual(expected, stmts)

  /// A lift that threw midway leaves the writes it held behind in the
  /// builder; the next transfer makes only its own.
  [<TestMethod>]
  member _.``[PARISC] a transfer makes only its own writes``() =
    let bld = newBuilder ()
    bld.Defer(Register.toRegID GR1, AST.tmpvar 32<rt> 9)
    let hex = blRp + ldoR1
    let expected = (parse hex).Translate(newBuilder ())
    CollectionAssert.AreEqual(expected, (parse hex).Translate bld)

  /// An unconditional transfer that nullifies never runs the instruction
  /// after it, which may be data: it goes at once, needing no slot.
  [<TestMethod>]
  member _.``[PARISC] a nullifying jump goes without a slot``() =
    let ins = parse "e840c002"
    Assert.AreEqual<uint32>(4u, ins.Extent)
    let last = AST.interjmp (tmp 1) InterJmpKind.Base
    Assert.AreEqual<Stmt>(last, Array.last (lifted "e840c002"))

  /// An instruction that nullifies the next one branches past it where its
  /// condition holds, which it reads before it writes its target: COMCLR
  /// clears the very register it compares here.
  [<TestMethod>]
  member _.``[PARISC] a nullifying compare branches past the next``() =
    (* cmpclr,= r4, r3, r3 *)
    let stmts = lifted "08642883"
    let skip = bit 2
    Assert.AreEqual<Stmt>((skip := (!.GR4 == !.GR3)), stmts[1])
    Assert.IsGreaterThan(1, writeOf GR3 stmts)
    let last = AST.intercjmp skip (num 8u) (num 4u)
    Assert.AreEqual<Stmt>(last, Array.last stmts)
    Assert.AreEqual<int>(0, writesOf PSW_N stmts)

  /// The condition that always holds leaves no way on to the next one.
  [<TestMethod>]
  member _.``[PARISC] an always nullifying instruction jumps past the next``() =
    (* addi,tr 0, r0, r0 *)
    let last = AST.interjmp (num 8u) InterJmpKind.Base
    Assert.AreEqual<Stmt>(last, Array.last (lifted "b4001000"))

  /// Whatever instruction is lifted next, the builder knows nothing of what
  /// came before: the one lifted after a nullifying one is lifted as alone.
  [<TestMethod>]
  member _.``[PARISC] what follows a nullifying instruction lifts alone``() =
    let builder = newBuilder ()
    let parser = Parser(isa, reader) :> IInstructionParsable
    let bytes = ByteArray.ofHexString ("08642883" + ldoR1)
    parser.Parse(bytes, 0UL).Translate builder |> ignore
    let next = parser.Parse(System.ReadOnlySpan(bytes, 4, 4), 4UL)
    let expected = next.Translate(newBuilder ())
    Assert.AreEqual<int>(expected.Length, (next.Translate builder).Length)

  /// With the "n" completer a taken forward branch nullifies its slot: the
  /// branch jumps over the slot where it is taken, and writes no nullify bit.
  [<TestMethod>]
  member _.``[PARISC] a forward nullifying branch skips its slot taken``() =
    (* cmpb,=,n r4, r5, .+0x10 ; ldo 5(r0), r1 *)
    let stmts = lifted ("80a42012" + ldoR1)
    Assert.AreEqual<Expr>(bit 2, skipsSlot stmts[2])
    Assert.AreEqual<int>(0, writesOf PSW_N stmts)
    let last = AST.intercjmp (bit 2) (num 0x10u) (num 8u)
    Assert.AreEqual<Stmt>(last, Array.last stmts)

  /// And an untaken backward one nullifies it.
  [<TestMethod>]
  member _.``[PARISC] a backward nullifying branch skips its slot untaken``() =
    (* addib,=,n -1, r3, .-4 ; ldo 5(r0), r1 *)
    let stmts = lifted ("a47f3fef" + ldoR1)
    Assert.AreEqual<Expr>(AST.not (bit 3), skipsSlot stmts[4])
    Assert.AreEqual<int>(0, writesOf PSW_N stmts)
    let last = AST.intercjmp (bit 3) (num 0xfffffffcu) (num 8u)
    Assert.AreEqual<Stmt>(last, Array.last stmts)

  /// A slot that nullifies the next instruction nullifies the one the
  /// transfer goes on to, so the transfer goes past it where the slot says,
  /// as the millicode for division does to negate only a negative result.
  [<TestMethod>]
  member _.``[PARISC] a slot that nullifies passes over the target``() =
    (* b .+0x18 ; addi,= 0, r3, r3 *)
    let stmts = lifted ("e8000020" + "b4632000")
    CollectionAssert.AreEqual([| num 0x1cu; num 0x18u |], exits stmts)
    (* b,l .+0x18, rp ; addi,= 0, r3, r3: the call returns where it would. *)
    let stmts = lifted (blRp + "b4632000")
    Assert.IsLessThan(writeOf GR2 stmts, writeOf GR3 stmts)
    let last = AST.interjmp (num 0x18u) InterJmpKind.IsCall
    Assert.AreEqual<Stmt>(last, Array.last stmts)

  /// A slot that runs on one side of a branch only nullifies on that side.
  [<TestMethod>]
  member _.``[PARISC] a slot that runs on one side passes over there``() =
    (* cmpb,=,n r4, r5, .+0x10 ; addi,= 0, r3, r3 *)
    let stmts = lifted ("80a42012" + "b4632000")
    let isJump stmt =
      match stmt with
      | InterCJmp _ -> true
      | _ -> false
    let jumps = stmts |> Array.filter isJump
    let expected =
      [| AST.intercjmp (bit 2) (num 0x14u) (num 0xcu)
         AST.intercjmp (bit 2) (num 0x10u) (num 8u)
         AST.intercjmp (bit 2) (num 0x10u) (num 8u) |]
    CollectionAssert.AreEqual(expected, jumps)

  /// A branch into the gateway page asks for the kernel's service once its
  /// slot has placed the argument, and returns past the slot.
  [<TestMethod>]
  member _.``[PARISC] a system call runs after its delay slot``() =
    (* ble 0x100(sr2, r0) ; ldi 21, r20 *)
    let stmts = lifted ("e4008200" + "3414002a")
    let expected =
      [| tmp 1 := num 0xbu
         tmp 2 := !.GR0 .+ num 0x15u
         !.GR20 := tmp 2
         !.GR31 := tmp 1
         AST.sideEffect SysCall
         AST.interjmp (num 8u) InterJmpKind.Base |]
    CollectionAssert.AreEqual(expected, stmts)

  /// The light-weight call and the thread-pointer write run after the slot
  /// as the system call does, and return past it.
  [<TestMethod>]
  member _.``[PARISC] the other gateway services run after the slot``() =
    (* ble 0xb0(sr2, r0) ; ldo 5(r0), r1 *)
    let lws = lifted ("e4008160" + ldoR1)
    Assert.AreEqual<bool>(true, hasSideEffect AtomicBegin lws)
    Assert.IsGreaterThan(writeOf GR1 lws, writeOf GR28 lws)
    let last = AST.interjmp (num 8u) InterJmpKind.Base
    Assert.AreEqual<Stmt>(last, Array.last lws)
    (* ble 0xe0(sr2, r0) ; ldo 5(r0), r1 *)
    let tp = lifted ("e40081c0" + ldoR1)
    Assert.AreEqual<Stmt>((!.CR27 := !.GR26), tp[writeOf CR27 tp])
    Assert.IsGreaterThan(writeOf GR1 tp, writeOf CR27 tp)
    Assert.AreEqual<Stmt>(last, Array.last tp)

  /// A transfer in the delay slot of a taken transfer runs after the first
  /// target, which one program counter cannot follow.
  [<TestMethod>]
  member _.``[PARISC] a transfer in a taken branch's slot is unsupported``() =
    (* b .+0x18 ; bv r0(rp) *)
    let stmts = lifted ("e8000020" + bvRp)
    Assert.AreEqual<bool>(true, hasSideEffect UnsupportedInstruction stmts)
    Assert.AreEqual<int>(0, (exits stmts).Length)
    (* addib,=,n -1, r3, .-4 ; bv r0(rp): taken backward runs the slot. *)
    let stmts = lifted ("a47f3fef" + bvRp)
    Assert.AreEqual<bool>(true, hasSideEffect UnsupportedInstruction stmts)
    CollectionAssert.AreEqual([| num 8u |], exits stmts)

  /// Where the slot runs only with the branch untaken, it is an ordinary
  /// transfer at its own address, and the taken side nullifies it.
  [<TestMethod>]
  member _.``[PARISC] a transfer in an untaken branch's slot runs alone``() =
    (* cmpb,=,n r4, r5, .+0x10 ; bv r0(rp) *)
    let stmts = lifted ("80a42012" + bvRp)
    Assert.AreEqual<bool>(false, hasSideEffect UnsupportedInstruction stmts)
    let last = AST.intercjmp (bit 2) (num 0x10u) (num 4u)
    Assert.AreEqual<Stmt>(last, Array.last stmts)

  /// A transfer whose bytes end before its delay slot still parses, but is
  /// not lifted: alone it would go without running the slot.
  [<TestMethod>]
  member _.``[PARISC] a transfer without its delay slot is not lifted``() =
    let ins = parse bvRp
    Assert.AreEqual<uint32>(4u, ins.Extent)
    Assert.ThrowsExactly<MissingDelaySlotException>(fun () ->
      lifted bvRp |> ignore) |> ignore

  /// An instruction lifted after a transfer with the same builder lifts as it
  /// does anywhere: the transfer leaves no jump behind for it to make.
  [<TestMethod>]
  member _.``[PARISC] a delay slot lifted alone does not jump``() =
    let builder = newBuilder ()
    let parser = Parser(isa, reader) :> IInstructionParsable
    let bytes = ByteArray.ofHexString (bvRp + ldoR1)
    parser.Parse(bytes, 0UL).Translate builder |> ignore
    let slot = parser.Parse(System.ReadOnlySpan(bytes, 4, 4), 4UL)
    Assert.AreEqual<int>(0, (exits (slot.Translate builder)).Length)

  /// Every transfer of control ends a block, as does an instruction that
  /// nullifies the next one, and nothing else does.
  [<TestMethod>]
  member _.``[PARISC] transfers are terminators``() =
    let nop = parse "08000240"
    let ends hex = (parse hex).IsTerminator nop
    let transfers =
      [| bvRp + ldoR1
         "e840c002"
         blRp + ldoR1
         "a0a42010" + ldoR1
         "e4008200" + ldoR1
         "08642883" |]
    let others = [| "08000240"; ldoR1; ldwRp |]
    CollectionAssert.AreEqual(Array.map (fun _ -> true) transfers,
                              Array.map ends transfers)
    CollectionAssert.AreEqual(Array.map (fun _ -> false) others,
                              Array.map ends others)

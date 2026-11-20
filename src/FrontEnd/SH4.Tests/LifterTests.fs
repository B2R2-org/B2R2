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

namespace B2R2.FrontEnd.SH4.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SH4
open type Register

/// Pins how a delayed branch lifts: it carries the instruction in its delay
/// slot, which runs after the branch has read what decides it and before
/// control leaves, so the two lift as one instruction ending with the branch.
[<TestClass>]
type LifterTests() =
  let isa = ISA(Architecture.SH4, Endian.Little)

  let reader = BinReader.Init Endian.Little

  let regFactory = RegisterFactory isa :> IRegisterFactory

  let ( !. ) reg = Register.toRegID reg |> regFactory.GetRegVar

  let num (v: uint32) = AST.num (BitVector(u32 = v, bitLen = 32<rt>))

  let parse (hex: string) =
    let parser = Parser(reader) :> IInstructionParsable
    parser.Parse(ByteArray.ofHexString hex, 0UL)

  let newBuilder () = LowUIRBuilder(isa, regFactory, LowUIRStream())

  /// The statements the instruction at the start of the given bytes lifts
  /// to, marks and all.
  let lifted hex = (parse hex).Translate(newBuilder ())

  /// The statements a branch and its slot lift to, past the opening mark:
  /// the slot writes no marks of its own, and the branch ends them.
  let testDelaySlot branch slot (givenStmts: Stmt[]) =
    CollectionAssert.AreEqual(givenStmts, Array.tail (lifted (branch + slot)))

  /// The statements an instruction lifts to alone, without its marks.
  let slotOf hex =
    let stmts = lifted hex
    Array.sub stmts 1 (Array.length stmts - 2)

  /// BRA to six bytes past itself.
  let bra = "01a0"

  /// MOV R3, R4, which reads and writes no temporary.
  let movR3R4 = "3364"

  /// MOV #5, R1.
  let movImmR1 = "05e1"

  /// DT R1, which writes T.
  let dtR1 = "1041"

  let undefined = [| AST.sideEffect UndefinedInstruction |]

  [<TestMethod>]
  member _.``[SH4] BRA runs its delay slot then branches``() =
    let ins = parse (bra + movR3R4)
    Assert.AreEqual<uint32>(2u, ins.Length)
    Assert.AreEqual<uint32>(4u, ins.Extent)
    testDelaySlot bra movR3R4
    <| Array.append
         (slotOf movR3R4)
         [| AST.interjmp (num 6u) InterJmpKind.Base |]

  /// BT/S reads T before its slot runs, so a slot that writes T, as DT does,
  /// leaves the branch where T sent it; untaken, it goes past the slot.
  [<TestMethod>]
  member _.``[SH4] BT/S reads T before its delay slot``() =
    let taken = AST.tmpvar 1<rt> 1
    testDelaySlot "018d" dtR1
    <| Array.concat
         [ [| taken := !.T |]
           slotOf dtR1
           [| AST.intercjmp taken (num 6u) (num 4u) |] ]

  [<TestMethod>]
  member _.``[SH4] BF/S reads T before its delay slot``() =
    let taken = AST.tmpvar 1<rt> 1
    testDelaySlot "018f" dtR1
    <| Array.concat
         [ [| taken := AST.not !.T |]
           slotOf dtR1
           [| AST.intercjmp taken (num 6u) (num 4u) |] ]

  /// JMP reads the register it goes through before its slot runs, so a slot
  /// that writes that register leaves the target as it was.
  [<TestMethod>]
  member _.``[SH4] JMP reads its register before its delay slot``() =
    let target = AST.tmpvar 32<rt> 1
    testDelaySlot "2b41" movImmR1
    <| Array.concat
         [ [| target := !.R1 |]
           slotOf movImmR1
           [| AST.interjmp target InterJmpKind.Base |] ]

  /// JSR writes PR, the address past its slot, before the slot runs, as the
  /// manual's description of it does, so the slot sees the new PR.
  [<TestMethod>]
  member _.``[SH4] JSR links and reads its register before its slot``() =
    let target = AST.tmpvar 32<rt> 1
    testDelaySlot "0b41" movImmR1
    <| Array.concat
         [ [| target := !.R1
              !.PR := num 4u |]
           slotOf movImmR1
           [| AST.interjmp target InterJmpKind.IsCall |] ]

  [<TestMethod>]
  member _.``[SH4] BRAF adds its register before its delay slot``() =
    let target = AST.tmpvar 32<rt> 1
    testDelaySlot "2301" movImmR1
    <| Array.concat
         [ [| target := num 4u .+ !.R1 |]
           slotOf movImmR1
           [| AST.interjmp target InterJmpKind.Base |] ]

  [<TestMethod>]
  member _.``[SH4] BSRF links and adds its register before its slot``() =
    let target = AST.tmpvar 32<rt> 1
    testDelaySlot "0301" movImmR1
    <| Array.concat
         [ [| target := num 4u .+ !.R1
              !.PR := num 4u |]
           slotOf movImmR1
           [| AST.interjmp target InterJmpKind.IsCall |] ]

  [<TestMethod>]
  member _.``[SH4] BSR links before its delay slot``() =
    testDelaySlot "01b0" movR3R4
    <| Array.concat
         [ [| !.PR := num 4u |]
           slotOf movR3R4
           [| AST.interjmp (num 6u) InterJmpKind.IsCall |] ]

  /// RTS reads PR before its slot runs, so a slot that pops PR, as a
  /// function's epilogue does, leaves the return where PR said.
  [<TestMethod>]
  member _.``[SH4] RTS reads PR before its delay slot``() =
    let target = AST.tmpvar 32<rt> 1
    (* rts ; lds.l @r15+, pr *)
    let stmts = Array.tail (lifted ("0b00" + "264f"))
    let first = target := !.PR
    let last = AST.interjmp target InterJmpKind.IsRet
    Assert.AreEqual<Stmt>(first, stmts[0])
    Assert.AreEqual<Stmt>(last, Array.last stmts)
    Assert.IsGreaterThan(2, stmts.Length)

  /// An instruction that changes the PC may not sit in a delay slot: the
  /// processor raises a slot illegal instruction exception on it, so the
  /// branch lifts as an undefined instruction, nothing of it done.
  [<TestMethod>]
  member _.``[SH4] a PC-changing delay slot is undefined``() =
    let slots =
      [| "01a0" (* bra *)
         "018b" (* bf *)
         "0189" (* bt *)
         "018d" (* bt/s *)
         "018f" (* bf/s *)
         "2b41" (* jmp @r1 *)
         "0b41" (* jsr @r1 *)
         "2301" (* braf r1 *)
         "0301" (* bsrf r1 *)
         "01b0" (* bsr *)
         "0b00" (* rts *)
         "2b00" (* rte *)
         "01c3" (* trapa #1 *)
         "0e41" (* ldc r1, sr *)
         "0741" (* ldc.l @r1+, sr *) |]
    for slot in slots do
      testDelaySlot bra slot undefined

  /// A PC-relative MOV or MOVA may not sit in a delay slot either.
  [<TestMethod>]
  member _.``[SH4] a PC-relative delay slot is undefined``() =
    let slots =
      [| "01c7" (* mova *)
         "0191" (* mov.w *)
         "01d1" (* mov.l *) |]
    for slot in slots do
      testDelaySlot bra slot undefined

  /// A branch whose bytes end before its delay slot still parses, but is not
  /// lifted: alone it would branch without running the slot.
  [<TestMethod>]
  member _.``[SH4] a branch without its delay slot is not lifted``() =
    let ins = parse bra
    Assert.AreEqual<uint32>(2u, ins.Extent)
    Assert.ThrowsExactly<MissingDelaySlotException>(fun () ->
      lifted bra |> ignore) |> ignore

  /// An instruction lifts the same after a branch as anywhere else: the
  /// branch carries its slot and leaves nothing behind for the instruction
  /// that sits there.
  [<TestMethod>]
  member _.``[SH4] a delay slot lifts alone as it does anywhere``() =
    let builder = newBuilder ()
    let parser = Parser(reader) :> IInstructionParsable
    let bytes = ByteArray.ofHexString (bra + movR3R4)
    parser.Parse(bytes, 0UL).Translate builder |> ignore
    let slot = parser.Parse(System.ReadOnlySpan(bytes, 2, 2), 2UL)
    let alone = parser.Parse(ByteArray.ofHexString movR3R4, 2UL)
    let expected = alone.Translate(newBuilder ())
    CollectionAssert.AreEqual(expected, slot.Translate builder)

  /// Every control transfer ends a block, and nothing else does.
  [<TestMethod>]
  member _.``[SH4] control transfers are terminators``() =
    let nop = parse "0900"
    let ends hex = (parse hex).IsTerminator nop
    let transfers =
      [| bra + movR3R4; "018b"; "0189"; "2b00"; "01c3"; "0b00" + movR3R4 |]
    let others = [| "0900"; movR3R4; movImmR1 |]
    CollectionAssert.AreEqual(Array.map (fun _ -> true) transfers,
                              Array.map ends transfers)
    CollectionAssert.AreEqual(Array.map (fun _ -> false) others,
                              Array.map ends others)

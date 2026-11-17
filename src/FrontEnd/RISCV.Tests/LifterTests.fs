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


namespace B2R2.FrontEnd.RISCV.Tests

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.RISCV
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins the lifting the CFG recovery leans on: it tells calls, returns and the
/// jumps through tables apart by the kind of jump they leave by, and it lifts
/// every instruction of a block it reaches. The jump encodings are those of
/// InstructionTests.
[<TestClass>]
type LifterTests() =
  static let lift wordSize addr hex =
    let isa = ISA(Architecture.RISCV, Endian.Little, wordSize)
    let reader = BinReader.Init Endian.Little
    let parser = Parser(isa, reader) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, addr)
    let regs = RegisterFactory isa
    ins.Translate(ILowUIRBuilder.Default(isa, regs, LowUIRStream()))

  /// Finds where a word read at an address jumps to, if it names the place, and
  /// the kind of the jump.
  static let jumpOf wordSize addr hex =
    lift wordSize addr hex
    |> Array.pick (function
      | InterJmp(Target = Num(Value = bv); Kind = kind) ->
        Some(Some(bv.ToUInt64()), kind)
      | InterJmp(Kind = kind) ->
        Some(None, kind)
      | _ ->
        None)

  static let kindOf wordSize addr hex = snd (jumpOf wordSize addr hex)

  [<TestMethod>]
  member _.``[RISCV64] a call lifts as a call``() =
    let calls =
      [ "eff03fea" (* jal ra, 0x4e10 *)
        "8297" (* c.jalr a5 *) ]
    for hex in calls do
      let kind = kindOf WordSize.Bit64 0x4f6eUL hex
      Assert.AreEqual<InterJmpKind>(InterJmpKind.IsCall, kind, hex)

  [<TestMethod>]
  member _.``[RISCV32] a compressed call lifts as a call to its target``() =
    let target, kind = jumpOf WordSize.Bit32 0x11fbeUL "493f" (* c.jal *)
    Assert.AreEqual<uint64 option>(Some 0x11f50UL, target)
    Assert.AreEqual<InterJmpKind>(InterJmpKind.IsCall, kind)

  (* x5 is a link as much as x1 is: LLVM calls its outlined functions through
     t0, and they return through it. *)
  [<TestMethod>]
  member _.``[RISCV32] a call through t0 lifts as a call``() =
    let call = kindOf WordSize.Bit32 0x12258UL "ef22b20d" (* jal t0 *)
    Assert.AreEqual<InterJmpKind>(InterJmpKind.IsCall, call)
    let ret = kindOf WordSize.Bit32 0x18dbeUL "8282" (* c.jr t0 *)
    Assert.AreEqual<InterJmpKind>(InterJmpKind.IsRet, ret)

  [<TestMethod>]
  member _.``[RISCV64] a return lifts as a return``() =
    let kind = kindOf WordSize.Bit64 0x4f9eUL "8280" (* c.jr ra *)
    Assert.AreEqual<InterJmpKind>(InterJmpKind.IsRet, kind)

  (* A jump through a table is no return, and neither is a PLT entry, which
     keeps the address after its jump in t1 for the lazy resolver. *)
  [<TestMethod>]
  member _.``[RISCV64] a jump that links nothing lifts as a plain jump``() =
    let jumps =
      [ "6f10e014" (* jal zero, 0x63b6 *)
        "39a0" (* c.j 0x4ff8 *)
        "8287" (* c.jr a5 *)
        "67030e00" (* jalr t1, 0(t3) *) ]
    for hex in jumps do
      let kind = kindOf WordSize.Bit64 0x5268UL hex
      Assert.AreEqual<InterJmpKind>(InterJmpKind.Base, kind, hex)

  (* The CFG recovery reads the last statement of a block for the jump that
     ends it, so a jump ends its instruction with no mark after it. *)
  [<TestMethod>]
  member _.``[RISCV64] a jump is the last statement of its instruction``() =
    let jumps =
      [ "eff03fea" (* jal ra, 0x4e10 *)
        "8287" (* c.jr a5 *)
        "639bd700" (* bne a5, a3, 0x510a *)
        "11c1" (* c.beqz a0, 0x4f7e *) ]
    for hex in jumps do
      match Array.last (lift WordSize.Bit64 0x4f6eUL hex) with
      | InterJmp _ | InterCJmp _ -> ()
      | stmt -> Assert.Fail $"{hex} ends with {stmt}"

  [<TestMethod>]
  member _.``[RISCV64] the illegal halfword lifts as an undefined one``() =
    let effects =
      lift WordSize.Bit64 0x6750UL "0000"
      |> Array.choose (function
        | SideEffect(Effect = e) -> Some e
        | _ -> None)
    CollectionAssert.AreEqual([| UndefinedInstruction |], effects)

  (* RV32 alone has the compressed loads and stores of single floats, as RV64
     spends their encodings on doublewords. They do what their full forms do,
     so only the marks that hold the length of an instruction tell them
     apart. *)
  [<TestMethod>]
  member _.``[RISCV32] a compressed float access lifts as its full form``() =
    let bodyOf hex =
      lift WordSize.Bit32 0x381b2UL hex
      |> Array.filter (function
        | ISMark _ | IEMark _ -> false
        | _ -> true)
      |> Array.map string
    let pairs =
      [ "1c62", "87270600" (* flw fa5, 0(a2) *)
        "3267", "0727c100" (* flw fa4, 12(sp) *)
        "9ce7", "27a4f700" (* fsw fa5, 8(a5) *)
        "3ae6", "2726e100" (* fsw fa4, 12(sp) *) ]
    for short, full in pairs do
      CollectionAssert.AreEqual(bodyOf full, bodyOf short, short)

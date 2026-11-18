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

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins the lifting the CFG recovery leans on: it reads the jump that ends a
/// block from the last statement of the block, follows a jump out of an
/// instruction to one of two targets only to numbers, and tells calls apart by
/// the kind of jump they leave by. The encodings are those of
/// InstructionTests.
[<TestClass>]
type LifterTests() =
  static let lift addr hex =
    let isa = ISA(Architecture.S390, Endian.Big, WordSize.Bit64)
    let parser = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, addr)
    let regs = RegisterFactory isa
    ins.Translate(ILowUIRBuilder.Default(isa, regs, LowUIRStream()))

  static let kindsOf stmts =
    stmts
    |> Array.choose (function
      | InterJmp(Kind = k) -> Some k
      | _ -> None)

  [<TestMethod>]
  member _.``[S390] A Jump Is The Last Statement Of Its Instruction Test``() =
    let jumps =
      [ 0x22b2UL, "c0e5fffffec7" (* brasl %r14,0x2040 *)
        0x2444UL, "0de2" (* basr %r14,%r2 *)
        0x22bcUL, "a7740005" (* jne 0x22c6 *)
        0x2376UL, "a7f40009" (* j 0x2388 *)
        0x2556UL, "ec4200e7297f" (* clijh %r4,41,0x2724 *)
        0x66c8UL, "a776ff86" (* brct %r7,0x65d4 *)
        0x22f4UL, "07f4" (* br %r4 *)
        0x2efcUL, "47f52000" (* b 0(%r5,%r2) *) ]
    for addr, hex in jumps do
      match Array.last (lift addr hex) with
      | InterJmp _ | InterCJmp _ -> ()
      | stmt -> Assert.Fail $"{hex} ends with {stmt}"

  [<TestMethod>]
  member _.``[S390] A Conditional Branch Jumps To Two Numbers Test``() =
    match Array.last (lift 0x22bcUL "a7740005") (* jne 0x22c6 *) with
    | InterCJmp(TrueTarget = Num(Value = t); FalseTarget = Num(Value = f)) ->
      Assert.AreEqual<uint64>(0x22c6UL, t.ToUInt64())
      Assert.AreEqual<uint64>(0x22c0UL, f.ToUInt64())
    | stmt ->
      Assert.Fail $"jne ends with {stmt}"

  (* Whether a jump through a register returns, only the data flow tells: GCC
     returns through the register it reloads the saved R14 into, and jumps
     through a table by way of R14. *)
  [<TestMethod>]
  member _.``[S390] Only A Call Leaves By A Kind Of Its Own Test``() =
    for addr, hex, kind in
      [ 0x22b2UL, "c0e5fffffec7", InterJmpKind.IsCall (* brasl *)
        0x2444UL, "0de2", InterJmpKind.IsCall (* basr %r14,%r2 *)
        0x4a37cUL, "07fe", InterJmpKind.Base (* br %r14 *)
        0x22f4UL, "07f4", InterJmpKind.Base (* br %r4 *) ] do
      CollectionAssert.AreEqual([| kind |], kindsOf (lift addr hex), hex)

  (* A branch through a register on a condition jumps from within the
     instruction, as a jump out of it to one of two targets is followed only to
     numbers, and goes on to the next instruction where it does not jump. *)
  [<TestMethod>]
  member _.``[S390] A Conditional Branch To A Register Jumps Within Test``() =
    let stmts = lift 0x8170UL "078e" (* ber %r14 *)
    CollectionAssert.AreEqual([| InterJmpKind.Base |], kindsOf stmts)
    Assert.AreEqual<bool>(true, Array.exists (function
      | CJmp _ -> true
      | _ -> false) stmts)
    match Array.last stmts with
    | IEMark _ -> ()
    | stmt -> Assert.Fail $"ber ends with {stmt}"

  (* The PLT reads where it is with BASR to R0, which jumps nowhere. *)
  [<TestMethod>]
  member _.``[S390] A Branch To R0 Jumps Nowhere Test``() =
    let stmts = lift 0x1c0eUL "0d10" (* basr %r1,%r0 *)
    Assert.AreEqual<int>(0, (kindsOf stmts).Length)
    match Array.last stmts with
    | IEMark _ -> ()
    | stmt -> Assert.Fail $"basr ends with {stmt}"

  [<TestMethod>]
  member _.``[S390] A Branch Into Its Own Second Halfword Traps Test``() =
    let effects =
      lift 0x3f818UL "a7f40001" (* j 0x3f81a *)
      |> Array.choose (function
        | SideEffect(Effect = e) -> Some e
        | _ -> None)
    CollectionAssert.AreEqual([| UndefinedInstruction |], effects)

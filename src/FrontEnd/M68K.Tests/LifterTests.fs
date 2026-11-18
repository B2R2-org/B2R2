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
open B2R2.FrontEnd.M68K
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins the lifting the CFG recovery leans on: it reads a call to a number as
/// a call to that address, and a call to anything else as an indirect one.
/// The encodings come from a GCC build of coreutils ls for the 68020 without
/// PIE, whose calls are JSR to an absolute address or to one the program
/// counter displaces.
[<TestClass>]
type LifterTests() =
  static let lift addr hex =
    let isa = ISA Architecture.M68K
    let parser = Parser(isa, BinReader.Init Endian.Big) :> IInstructionParsable
    let ins = parser.Parse(ByteArray.ofHexString hex, addr)
    let regs = RegisterFactory isa
    ins.Translate(ILowUIRBuilder.Default(isa, regs, LowUIRStream()))

  /// Finds where an instruction at an address jumps to, if it names the
  /// place, and the kind of the jump.
  static let jumpOf addr hex =
    lift addr hex
    |> Array.pick (function
      | InterJmp(Target = Num(Value = bv); Kind = kind) ->
        Some(Some(bv.ToUInt64()), kind)
      | InterJmp(Kind = kind) ->
        Some(None, kind)
      | _ ->
        None)

  [<TestMethod>]
  member _.``[M68K] a call to an address lifts as a call to it``() =
    let calls =
      [ 0x80002dd0UL, "4eb9800165a0", 0x800165a0UL (* jsr 0x800165a0 *)
        0x800034f4UL, "4ebaff9e", 0x80003494UL (* jsr (-0x62,pc) *)
        0x4e46UL, "61fffffffc60", 0x4aa8UL (* bsr.l 0x4aa8 *) ]
    for addr, hex, target in calls do
      let lifted, kind = jumpOf addr hex
      Assert.AreEqual<uint64 option>(Some target, lifted, hex)
      Assert.AreEqual<InterJmpKind>(InterJmpKind.IsCall, kind, hex)

  [<TestMethod>]
  member _.``[M68K] a call through a register lifts as an indirect call``() =
    let target, kind = jumpOf 0x80002e60UL "4e94" (* jsr (a4) *)
    Assert.AreEqual<uint64 option>(None, target)
    Assert.AreEqual<InterJmpKind>(InterJmpKind.IsCall, kind)

  [<TestMethod>]
  member _.``[M68K] a jump through a table lifts as an indirect jump``() =
    let target, kind = jumpOf 0x80002e82UL "4efb0002" (* jmp (2,pc,d0.w) *)
    Assert.AreEqual<uint64 option>(None, target)
    Assert.AreEqual<InterJmpKind>(InterJmpKind.Base, kind)

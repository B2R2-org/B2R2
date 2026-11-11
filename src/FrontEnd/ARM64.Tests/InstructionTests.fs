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

namespace B2R2.FrontEnd.ARM64.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins where control can go after an instruction, which is what a CFG is
/// built from. The encodings come from a gcc -O2 aarch64 build of coreutils
/// pinky, where they sit right before a switch dispatch.
[<TestClass>]
type InstructionTests() =
  static let parser =
    Parser(BinReader.Init Endian.Little) :> IInstructionParsable

  static let parseAt addr hex =
    let bytes = ByteArray.ofHexString hex
    parser.Parse(ReadOnlySpan bytes, addr)

  static let parse hex = parseAt 0x1000UL hex

  static let nexts (ins: IInstruction) = ins.GetNextInstrAddrs()

  [<TestMethod>]
  member _.``[ARM64] a conditional branch also falls through test``() =
    let ins = parseAt 0x52b4UL "80010054" (* b.eq 0x52e4 *)
    CollectionAssert.AreEqual([| 0x52b8UL; 0x52e4UL |], nexts ins)

  [<TestMethod>]
  member _.``[ARM64] a test-and-branch also falls through test``() =
    let ins = parseAt 0x52b8UL "1a020036" (* tbz w26, #0x0, 0x52f8 *)
    CollectionAssert.AreEqual([| 0x52bcUL; 0x52f8UL |], nexts ins)

  [<TestMethod>]
  member _.``[ARM64] a compare-and-branch also falls through test``() =
    let ins = parse "400000b4" (* cbz x0, 0x1008 *)
    CollectionAssert.AreEqual([| 0x1004UL; 0x1008UL |], nexts ins)

  [<TestMethod>]
  member _.``[ARM64] an unconditional branch goes to its target only test``() =
    let ins = parse "04000014" (* b 0x1010 *)
    CollectionAssert.AreEqual([| 0x1010UL |], nexts ins)

  (* B.cond with AL or NV is taken whatever the flags say, so it is a branch
     that never falls through, like B. *)
  [<TestMethod>]
  member _.``[ARM64] a branch on AL goes to its target only test``() =
    let ins = parse "8e000054" (* b.al 0x1010 *)
    CollectionAssert.AreEqual([| 0x1010UL |], nexts ins)

  [<TestMethod>]
  member _.``[ARM64] a branch on NV goes to its target only test``() =
    let ins = parse "8f000054" (* b.nv 0x1010 *)
    CollectionAssert.AreEqual([| 0x1010UL |], nexts ins)

  [<TestMethod>]
  member _.``[ARM64] a call returns to the next instruction test``() =
    let ins = parse "04000094" (* bl 0x1010 *)
    CollectionAssert.AreEqual([| 0x1004UL; 0x1010UL |], nexts ins)

  [<TestMethod>]
  member _.``[ARM64] an indirect branch has no static next address test``() =
    let ins = parseAt 0x52e0UL "00001fd6" (* br x0 *)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[ARM64] a return has no static next address test``() =
    let ins = parse "c0035fd6" (* ret *)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[ARM64] a halt has no next address test``() =
    let ins = parse "000040d4" (* hlt #0x0 *)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  (* BRK and UDF raise an exception that returns to the trapping instruction
     itself, so control never reaches the next one, which compilers fill with
     whatever follows, as they do after a UD2 of Intel. A block ends there. *)
  [<TestMethod>]
  member _.``[ARM64] a trap has no next address test``() =
    let traps =
      [ "007d20d4" (* brk #0x3e8 *)
        "00000000" (* udf #0 *) ]
    for hex in traps do
      let ins = parse hex
      Assert.AreEqual<bool>(true, ins.IsTerminator null, hex)
      CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[ARM64] a supervisor call falls through test``() =
    let ins = parse "010000d4" (* svc #0x0 *)
    CollectionAssert.AreEqual([| 0x1004UL |], nexts ins)

  [<TestMethod>]
  member _.``[ARM64] any other instruction falls through test``() =
    let ins = parse "1f2003d5" (* nop *)
    CollectionAssert.AreEqual([| 0x1004UL |], nexts ins)

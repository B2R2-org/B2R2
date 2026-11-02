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
namespace B2R2.MiddleEnd.Tests
namespace B2R2.MiddleEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

[<TestClass>]
type BBLOverlapTests() =
  /// Represents a raw x86 binary of `mov eax, 0x90909090; nop; ret`. Read from
  /// its second byte, the immediate of the `mov` decodes as four `nop`s that
  /// run into the same `nop; ret`, so a BBL started there overlaps the one
  /// started at the `mov` without sharing an instruction boundary before 0x5.
  let binary = [| 0xb8uy; 0x90uy; 0x90uy; 0x90uy; 0x90uy; 0x90uy; 0xc3uy |]

  let isa = ISA(Architecture.Intel, WordSize.Bit32)
  let hdl = BinHandle.LoadRawImage(binary, isa)
  let instrs = InstructionCollection(LinearSweepInstructionCollector hdl)

  let edge src dst = ProgramPoint(src, 0), ProgramPoint(dst, 0)

  (* A new leader does not only cut the BBL of the leader right before it. The
     misaligned leader 0x1 sits between 0x0 and the new leader 0x5, yet the BBL
     at 0x0 still covers 0x5 and has to be cut there as well. *)
  [<TestMethod>]
  member _.``New Leader Cuts Every BBL Covering It``() =
    let bblFactory = BBLFactory(hdl, instrs)
    scanBBLs bblFactory [| 0x0UL |]
    scanBBLs bblFactory [| 0x1UL |]
    match bblFactory.ScanBBLs [| 0x5UL |] with
    | Ok dividedEdges ->
      let expected = [| edge 0x0UL 0x5UL; edge 0x1UL 0x5UL |]
      CollectionAssert.AreEqual(expected, dividedEdges.ToArray())
    | Error e ->
      Assert.Fail $"Unexpected failure: {e}"
    let range = extractBBLRange bblFactory (ProgramPoint(0x0UL, 0))
    Assert.AreEqual<Addr * Addr>((0x0UL, 0x4UL), range)

  (* Once committed, a cut is not reported again by a later scan, and a BBL
     parsed after a leader exists stops right before it. *)
  [<TestMethod>]
  member _.``Later Scan Does Not Repeat A Cut``() =
    let bblFactory = BBLFactory(hdl, instrs)
    scanBBLs bblFactory [| 0x0UL |]
    scanBBLs bblFactory [| 0x5UL |]
    match bblFactory.ScanBBLs [| 0x1UL |] with
    | Ok dividedEdges ->
      Assert.AreEqual<int>(0, dividedEdges.Count)
    | Error e ->
      Assert.Fail $"Unexpected failure: {e}"

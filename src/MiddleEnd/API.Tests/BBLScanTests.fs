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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

[<TestClass>]
type BBLScanTests() =
  /// Represents a raw x86 binary of `nop; ret`, which is two instructions
  /// that always parse, so that the only way a scan of it can fail is the one
  /// this fixture arranges.
  let binary = [| 0x90uy; 0xc3uy |]

  let isa = ISA(Architecture.Intel, WordSize.Bit32)
  let hdl = BinHandle.LoadRawImage(binary, isa)
  let instrs = InstructionCollection(LinearSweepInstructionCollector hdl)

  (* A scan walks its entry points in order, so an entry point that cannot be
     parsed is reached with earlier ones already collected. Those are lifted
     and kept: the factory is shared across the scans of one function, and
     throwing away what parsed would lose blocks that a later scan then has no
     way to ask for again. The scan still reports the failure. *)
  [<TestMethod>]
  member _.``Scan Keeps What Parsed When A Later Entry Point Fails``() =
    let bblFactory = BBLFactory(hdl, instrs)
    let outOfRange = 0x1000UL
    match bblFactory.ScanBBLs [| 0x0UL; outOfRange |] with
    | Ok _ -> Assert.Fail "Expected the scan of an unmapped address to fail"
    | Error e -> Assert.AreEqual<ErrorCase>(ErrorCase.ParsingFailure, e)
    Assert.AreEqual<bool>(true, bblFactory.Contains(ProgramPoint(0x0UL, 0)))
    Assert.AreEqual<int>(1, bblFactory.Count)

  [<TestMethod>]
  member _.``Scan Of Only Parsable Entry Points Succeeds``() =
    let bblFactory = BBLFactory(hdl, instrs)
    match bblFactory.ScanBBLs [| 0x0UL |] with
    | Ok _ -> Assert.AreEqual<int>(1, bblFactory.Count)
    | Error e -> Assert.Fail $"Unexpected failure: {e}"

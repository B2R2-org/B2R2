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
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

[<TestClass>]
type BBLCutTests() =
  /// Represents a raw x86 binary of `nop; fptan; ret`. Lifting `fptan` yields
  /// intra-instruction control flow, and unlike the `rep`-prefixed ones, it
  /// never jumps to itself, so it does not start a BBL of its own. A BBL can
  /// thus end at `fptan` while starting from the `nop` before it, which is the
  /// only shape that carries a label map into a cut.
  let binary = [| 0x90uy; 0xd9uy; 0xf2uy; 0xc3uy |]

  let isa = ISA(Architecture.Intel, WordSize.Bit32)
  let hdl = BinHandle.LoadRawImage(binary, isa)
  let instrs = InstructionCollection(LinearSweepInstructionCollector hdl)

  (* Labels only ever come from the terminator of the last instruction of a
     BBL, and a cut keeps that instruction in the latter block, so the latter
     block takes the whole label map and the former one is left with none. *)
  [<TestMethod>]
  member _.``BBL Cut Label Map Test``() =
    let bblFactory = BBLFactory(hdl, instrs)
    scanBBLs bblFactory [| 0x0UL; 0x1UL |]
    let former = bblFactory.Find(ProgramPoint(0x0UL, 0))
    let latter = bblFactory.Find(ProgramPoint(0x1UL, 0))
    Assert.AreEqual<int>(1, former.Internals.LiftedInstructions.Length)
    Assert.AreEqual<int>(0, former.LabelMap.Count)
    Assert.AreEqual<int>(2, latter.LabelMap.Count)
    let latterInss = latter.Internals.LiftedInstructions
    Assert.AreEqual<int>(1, latterInss.Length)
    Assert.AreEqual<uint64>(0x1UL, latterInss[0].BBLAddr)
    let labelAddrs =
      latter.LabelMap.Values |> Seq.map (fun pp -> pp.Address) |> Seq.distinct
    Assert.AreEqual<uint64>(0x1UL, Seq.exactlyOne labelAddrs)
    match latter.Internals.Terminator with
    | CJmp(_, JmpDest(tLbl, _), JmpDest(fLbl, _), _) ->
      Assert.AreEqual<bool>(true, latter.LabelMap.ContainsKey tLbl)
      Assert.AreEqual<bool>(true, latter.LabelMap.ContainsKey fLbl)
    | terminator ->
      Assert.Fail $"Unexpected terminator: {terminator}"

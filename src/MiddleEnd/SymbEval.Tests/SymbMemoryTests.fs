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

namespace B2R2.MiddleEnd.SymbEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor
open B2R2.MiddleEnd.SymbEval

[<TestClass>]
type SymbMemoryTests() =
  let addr = 0x1000UL

  let value = Const(BitVector(0x11223344UL, 32<rt>))

  let imageAddr = 0x3000UL

  let imageByte = 0x90uy

  let unwrittenAddr = 0x2000UL

  let newHandle () =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let bytes = Array.create 16 imageByte
    BinHandle.LoadRawImage(bytes, isa, imageAddr, OS.Linux)

  let sectionMemory () =
    BinSectionSymbMemory(newHandle ()) :> IMemory<SymbExpr>

  let assertRoundTrip endian =
    let mem = DictionaryMemory() :> IMemory<SymbExpr>
    SymbMemoryOperation.store addr value endian mem
    match SymbMemoryOperation.load addr endian 32<rt> mem with
    | Ok loaded -> Assert.AreEqual<SymbExpr>(value, loaded)
    | Error e -> Assert.Fail $"Failed to load back the value: {e}"

  [<TestMethod>]
  member _.``A little-endian constant loads back as itself``() =
    assertRoundTrip Endian.Little

  [<TestMethod>]
  member _.``A big-endian constant loads back as itself``() =
    assertRoundTrip Endian.Big

  [<TestMethod>]
  member _.``Loading an unwritten address names the failing address``() =
    let mem = DictionaryMemory() :> IMemory<SymbExpr>
    match SymbMemoryOperation.load addr Endian.Little 32<rt> mem with
    | Ok loaded -> Assert.Fail $"Loaded {loaded} from an unwritten address."
    | Error e -> Assert.AreEqual<SymbEvalError>(InvalidMemoryRead addr, e)

  [<TestMethod>]
  member _.``A section-backed memory reads a section byte``() =
    let expected = ValueSome(SymbExpr.ofByte imageByte)
    let read = (sectionMemory ()).ByteRead imageAddr
    Assert.AreEqual<SymbExpr voption>(expected, read)

  [<TestMethod>]
  member _.``Clearing a section-backed memory keeps its backing``() =
    let mem = sectionMemory ()
    mem.ByteWrite(imageAddr, SymbExpr.zero 8<rt>)
    mem.Clear()
    let expected = ValueSome(SymbExpr.ofByte imageByte)
    Assert.AreEqual<SymbExpr voption>(expected, mem.ByteRead imageAddr)

  [<TestMethod>]
  member _.``Clearing a section-backed memory discards its writes``() =
    let mem = sectionMemory ()
    mem.ByteWrite(unwrittenAddr, SymbExpr.zero 8<rt>)
    mem.Clear()
    let read = mem.ByteRead unwrittenAddr
    Assert.AreEqual<SymbExpr voption>(ValueNone, read)

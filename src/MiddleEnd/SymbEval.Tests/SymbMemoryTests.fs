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

  let sectionMemory () = BinSectionSymbMemory(newHandle ()) :> ISymbMemory

  let assertRoundTrip endian =
    let mem = SymbMemory() :> ISymbMemory
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
  member _.``Clearing a section-backed memory keeps its backing``() =
    let mem = sectionMemory ()
    mem.ByteWrite(imageAddr, SymbExpr.zero 8<rt>)
    mem.Clear()
    match mem.ByteRead imageAddr with
    | Ok(Const bv) ->
      Assert.AreEqual<uint64>(uint64 imageByte, bv.ToUInt64())
    | Ok value ->
      Assert.Fail $"Read a non-constant byte {value}."
    | Error e ->
      Assert.Fail $"Lost the section backing: {e}"

  [<TestMethod>]
  member _.``Clearing a section-backed memory discards its writes``() =
    let mem = sectionMemory ()
    mem.ByteWrite(unwrittenAddr, SymbExpr.zero 8<rt>)
    mem.Clear()
    match mem.ByteRead unwrittenAddr with
    | Ok value ->
      Assert.Fail $"Kept a written byte {value} after Clear()."
    | Error e ->
      Assert.AreEqual<SymbEvalError>(InvalidMemoryRead unwrittenAddr, e)

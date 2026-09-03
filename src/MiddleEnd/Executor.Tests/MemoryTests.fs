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

namespace B2R2.MiddleEnd.Executor.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.MiddleEnd.Executor

[<TestClass>]
type MemoryTests() =
  let addr = 0x1000UL

  let backedAddr = 0x3000UL

  let backedValue = 0x90uy

  let backing addr =
    if addr = backedAddr then ValueSome backedValue else ValueNone

  let backedMemory () = BackedMemory(backing, DictionaryMemory())

  let assertReads expected (mem: IMemory<byte>) addr =
    Assert.AreEqual<byte voption>(expected, mem.ByteRead addr)

  [<TestMethod>]
  member _.``A written value reads back as itself``() =
    let mem = DictionaryMemory() :> IMemory<byte>
    mem.ByteWrite(addr, 0x42uy)
    assertReads (ValueSome 0x42uy) mem addr

  [<TestMethod>]
  member _.``An unwritten address reads as ValueNone``() =
    assertReads ValueNone (DictionaryMemory()) addr

  [<TestMethod>]
  member _.``A sharable memory reads back what it wrote``() =
    let mem = SharableMemory() :> IMemory<byte>
    mem.ByteWrite(addr, 0x42uy)
    assertReads (ValueSome 0x42uy) mem addr

  [<TestMethod>]
  member _.``Clearing a memory discards its contents``() =
    let mem = DictionaryMemory() :> IMemory<byte>
    mem.ByteWrite(addr, 0x42uy)
    mem.Clear()
    assertReads ValueNone mem addr

  [<TestMethod>]
  member _.``A cloned memory keeps the contents of its origin``() =
    let mem = DictionaryMemory() :> IMemory<byte>
    mem.ByteWrite(addr, 0x42uy)
    assertReads (ValueSome 0x42uy) (mem.Clone()) addr

  [<TestMethod>]
  member _.``A cloned memory does not share later writes``() =
    let mem = DictionaryMemory() :> IMemory<byte>
    let clone = mem.Clone()
    clone.ByteWrite(addr, 0x42uy)
    mem.ByteWrite(addr + 1UL, 0x43uy)
    assertReads ValueNone mem addr
    assertReads ValueNone clone (addr + 1UL)

  [<TestMethod>]
  member _.``A cloned sharable memory does not share later writes``() =
    let mem = SharableMemory() :> IMemory<byte>
    let clone = mem.Clone()
    clone.ByteWrite(addr, 0x42uy)
    assertReads ValueNone mem addr

  [<TestMethod>]
  member _.``A backed memory reads what its backing holds``() =
    assertReads (ValueSome backedValue) (backedMemory ()) backedAddr

  [<TestMethod>]
  member _.``A written value shadows the backing``() =
    let mem = backedMemory () :> IMemory<byte>
    mem.ByteWrite(backedAddr, 0x42uy)
    assertReads (ValueSome 0x42uy) mem backedAddr

  [<TestMethod>]
  member _.``Clearing a backed memory keeps its backing``() =
    let mem = backedMemory () :> IMemory<byte>
    mem.ByteWrite(backedAddr, 0x42uy)
    mem.Clear()
    assertReads (ValueSome backedValue) mem backedAddr

  [<TestMethod>]
  member _.``Clearing a backed memory discards its writes``() =
    let mem = backedMemory () :> IMemory<byte>
    mem.ByteWrite(addr, 0x42uy)
    mem.Clear()
    assertReads ValueNone mem addr

  [<TestMethod>]
  member _.``A cloned backed memory keeps its backing``() =
    let mem = backedMemory () :> IMemory<byte>
    assertReads (ValueSome backedValue) (mem.Clone()) backedAddr

  [<TestMethod>]
  member _.``A cloned backed memory does not share later writes``() =
    let mem = backedMemory () :> IMemory<byte>
    let clone = mem.Clone()
    clone.ByteWrite(addr, 0x42uy)
    assertReads ValueNone mem addr

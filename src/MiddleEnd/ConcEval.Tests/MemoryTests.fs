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

namespace B2R2.MiddleEnd.ConcEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type MemoryTests() =
  let addr = 0x1000UL

  let value = BitVector(0x11223344UL, 32<rt>)

  let imageAddr = 0x3000UL

  let imageByte = 0x90uy

  let newHandle () =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let bytes = Array.create 16 imageByte
    BinHandle.LoadRawImage(bytes, isa, imageAddr, OS.Linux)

  let sectionMemory () = BinSectionMemory(newHandle ())

  let assertRoundTrip endian (mem: IMemory) =
    Memory.write addr value endian mem
    match Memory.read addr endian 32<rt> mem with
    | Ok v -> Assert.AreEqual<BitVector>(value, v)
    | Error e -> Assert.Fail $"Failed to read back the value: {e}"

  let assertByteOrder endian expected (mem: IMemory) =
    Memory.write addr value endian mem
    let bytes =
      Array.init 4 (fun idx ->
        match mem.ByteRead(addr + uint64 idx) with
        | Ok b -> b
        | Error e -> Assert.Fail $"Failed to read a byte: {e}"; 0uy)
    CollectionAssert.AreEqual(expected, bytes)

  let assertUnwritten (mem: IMemory) addr =
    let expected = Error ErrorCase.InvalidMemoryRead
    Assert.AreEqual<Result<byte, ErrorCase>>(expected, mem.ByteRead addr)

  [<TestMethod>]
  member _.``A little-endian value reads back as itself``() =
    assertRoundTrip Endian.Little (NonsharableMemory())

  [<TestMethod>]
  member _.``A big-endian value reads back as itself``() =
    assertRoundTrip Endian.Big (NonsharableMemory())

  [<TestMethod>]
  member _.``A sharable memory composes multi-byte accesses, too``() =
    assertRoundTrip Endian.Little (SharableMemory())

  [<TestMethod>]
  member _.``A little-endian write stores the low byte first``() =
    let expected = [| 0x44uy; 0x33uy; 0x22uy; 0x11uy |]
    assertByteOrder Endian.Little expected (NonsharableMemory())

  [<TestMethod>]
  member _.``A big-endian write stores the high byte first``() =
    let expected = [| 0x11uy; 0x22uy; 0x33uy; 0x44uy |]
    assertByteOrder Endian.Big expected (NonsharableMemory())

  [<TestMethod>]
  member _.``Reading an unwritten address fails``() =
    let mem = NonsharableMemory() :> IMemory
    match Memory.read addr Endian.Little 32<rt> mem with
    | Ok v -> Assert.Fail $"Read {v} from an unwritten address."
    | Error e -> Assert.AreEqual<ErrorCase>(ErrorCase.InvalidMemoryRead, e)

  [<TestMethod>]
  member _.``Clearing a section-backed memory keeps its backing``() =
    let mem = sectionMemory () :> IMemory
    mem.ByteWrite(imageAddr, 0uy)
    mem.Clear()
    match mem.ByteRead imageAddr with
    | Ok b -> Assert.AreEqual<byte>(imageByte, b)
    | Error e -> Assert.Fail $"Lost the section backing: {e}"

  [<TestMethod>]
  member _.``Clearing a section-backed memory discards its writes``() =
    let mem = sectionMemory () :> IMemory
    mem.ByteWrite(0x2000UL, 0x42uy)
    mem.Clear()
    match mem.ByteRead 0x2000UL with
    | Ok b -> Assert.Fail $"Kept a written byte {b} after Clear()."
    | Error e -> Assert.AreEqual<ErrorCase>(ErrorCase.InvalidMemoryRead, e)

  [<TestMethod>]
  member _.``An unbacked section memory reads no section byte``() =
    let mem = BinSectionMemory(newHandle (), false) :> IMemory
    match mem.ByteRead imageAddr with
    | Ok b -> Assert.Fail $"Read a section byte {b} without a backing."
    | Error e -> Assert.AreEqual<ErrorCase>(ErrorCase.InvalidMemoryRead, e)

  [<TestMethod>]
  member _.``A cloned memory keeps the contents of its origin``() =
    let mem = NonsharableMemory() :> IMemory
    mem.ByteWrite(addr, 0x42uy)
    match mem.Clone().ByteRead addr with
    | Ok b -> Assert.AreEqual<byte>(0x42uy, b)
    | Error e -> Assert.Fail $"Lost the cloned contents: {e}"

  [<TestMethod>]
  member _.``A cloned memory does not share later writes``() =
    let mem = NonsharableMemory() :> IMemory
    let clone = mem.Clone()
    clone.ByteWrite(addr, 0x42uy)
    mem.ByteWrite(addr + 1UL, 0x43uy)
    assertUnwritten mem addr
    assertUnwritten clone (addr + 1UL)

  [<TestMethod>]
  member _.``A cloned sharable memory does not share later writes``() =
    let mem = SharableMemory() :> IMemory
    let clone = mem.Clone()
    clone.ByteWrite(addr, 0x42uy)
    assertUnwritten mem addr

  [<TestMethod>]
  member _.``A cloned section memory keeps its backing``() =
    let mem = sectionMemory () :> IMemory
    match mem.Clone().ByteRead imageAddr with
    | Ok b -> Assert.AreEqual<byte>(imageByte, b)
    | Error e -> Assert.Fail $"Lost the section backing: {e}"

  [<TestMethod>]
  member _.``A cloned EvalState owns its memory``() =
    let st = EvalState()
    let clone = st.Clone()
    clone.Memory.ByteWrite(addr, 0x42uy)
    assertUnwritten st.Memory addr

  [<TestMethod>]
  member _.``A cloned EvalState can share a given memory``() =
    let st = EvalState()
    let clone = st.Clone st.Memory
    clone.Memory.ByteWrite(addr, 0x42uy)
    match st.Memory.ByteRead addr with
    | Ok b -> Assert.AreEqual<byte>(0x42uy, b)
    | Error e -> Assert.Fail $"Failed to share the memory: {e}"

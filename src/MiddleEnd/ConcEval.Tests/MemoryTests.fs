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
open B2R2.MiddleEnd.Executor
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

  let sectionMemory () = BinSectionMemory(newHandle ()) :> IMemory<byte>

  let assertRoundTrip endian (mem: IMemory<byte>) =
    Memory.write addr value endian mem
    match Memory.read addr endian 32<rt> mem with
    | Ok v -> Assert.AreEqual<BitVector>(value, v)
    | Error e -> Assert.Fail $"Failed to read back the value: {e}"

  let assertByteOrder endian expected (mem: IMemory<byte>) =
    Memory.write addr value endian mem
    let bytes =
      Array.init 4 (fun idx ->
        match mem.ByteRead(addr + uint64 idx) with
        | ValueSome b -> b
        | ValueNone -> Assert.Fail $"Failed to read a byte at {idx}."; 0uy)
    CollectionAssert.AreEqual(expected, bytes)

  let assertReads expected (mem: IMemory<byte>) addr =
    Assert.AreEqual<byte voption>(expected, mem.ByteRead addr)

  [<TestMethod>]
  member _.``A little-endian value reads back as itself``() =
    assertRoundTrip Endian.Little (DictionaryMemory())

  [<TestMethod>]
  member _.``A big-endian value reads back as itself``() =
    assertRoundTrip Endian.Big (DictionaryMemory())

  [<TestMethod>]
  member _.``A sharable memory composes multi-byte accesses, too``() =
    assertRoundTrip Endian.Little (SharableMemory())

  [<TestMethod>]
  member _.``A little-endian write stores the low byte first``() =
    let expected = [| 0x44uy; 0x33uy; 0x22uy; 0x11uy |]
    assertByteOrder Endian.Little expected (DictionaryMemory())

  [<TestMethod>]
  member _.``A big-endian write stores the high byte first``() =
    let expected = [| 0x11uy; 0x22uy; 0x33uy; 0x44uy |]
    assertByteOrder Endian.Big expected (DictionaryMemory())

  [<TestMethod>]
  member _.``Reading an unwritten address fails``() =
    let mem = DictionaryMemory() :> IMemory<byte>
    match Memory.read addr Endian.Little 32<rt> mem with
    | Ok v -> Assert.Fail $"Read {v} from an unwritten address."
    | Error e -> Assert.AreEqual<ErrorCase>(ErrorCase.InvalidMemoryRead, e)

  [<TestMethod>]
  member _.``A section-backed memory reads a section byte``() =
    assertReads (ValueSome imageByte) (sectionMemory ()) imageAddr

  [<TestMethod>]
  member _.``Clearing a section-backed memory keeps its backing``() =
    let mem = sectionMemory ()
    mem.ByteWrite(imageAddr, 0uy)
    mem.Clear()
    assertReads (ValueSome imageByte) mem imageAddr

  [<TestMethod>]
  member _.``Clearing a section-backed memory discards its writes``() =
    let mem = sectionMemory ()
    mem.ByteWrite(0x2000UL, 0x42uy)
    mem.Clear()
    assertReads ValueNone mem 0x2000UL

  [<TestMethod>]
  member _.``A cloned section memory keeps its backing``() =
    let mem = sectionMemory ()
    assertReads (ValueSome imageByte) (mem.Clone()) imageAddr

  [<TestMethod>]
  member _.``A cloned EvalState owns its memory``() =
    let st = EvalState()
    let clone = st.Clone()
    clone.Memory.ByteWrite(addr, 0x42uy)
    assertReads ValueNone st.Memory addr

  [<TestMethod>]
  member _.``A cloned EvalState can share a given memory``() =
    let st = EvalState()
    let clone = st.Clone st.Memory
    clone.Memory.ByteWrite(addr, 0x42uy)
    assertReads (ValueSome 0x42uy) st.Memory addr

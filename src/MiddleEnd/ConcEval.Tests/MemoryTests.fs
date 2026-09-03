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
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type MemoryTests() =
  let addr = 0x1000UL

  let value = BitVector(0x11223344UL, 32<rt>)

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

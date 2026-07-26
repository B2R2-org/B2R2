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

namespace B2R2.FrontEnd.Tests

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type BinHandleTests() =
  static let isa = ISA(Architecture.Intel, WordSize.Bit64)

  /// A 16-byte raw image whose byte at each address equals the address.
  static let hdl = BinHandle([| for i in 0 .. 15 -> byte i |], isa)

  /// An image with no content at all, which cannot serve any read.
  static let emptyHdl = BinHandle isa

  /// An address outside the image, for which the file hands out a null pointer.
  static let unmapped = 0x9999UL

  /// A pointer whose address range (33 bytes) outruns its file offset range
  /// (11 bytes). Reads through it must never report success with a truncated
  /// result.
  static let skewed = BinFilePointer.CreateFileBacked(0UL, 0x20UL, 0, 10)

  /// A pointer to a region mapped to VM only, as in a .bss section.
  static let vmOnly = BinFilePointer.CreateVirtual(0x1000UL, 0x1fffUL)

  /// An image holding "hi", a NUL, and then an unterminated "ab".
  static let strHdl =
    BinHandle([| 0x68uy; 0x69uy; 0x00uy; 0x61uy; 0x62uy |], isa)

  [<TestMethod>]
  member _.``[BinHandle] raw image ISA and OS test``() =
    Assert.AreEqual<Architecture>(Architecture.Intel, hdl.File.ISA.Arch)
    Assert.AreEqual<OS>(OS.UnknownOS, hdl.OS)

  [<TestMethod>]
  member _.``[BinHandle] OS injected into a raw image test``() =
    let hdl = BinHandle([| 0x90uy |], isa, OS.Linux)
    Assert.AreEqual<OS>(OS.Linux, hdl.OS)

  [<TestMethod>]
  member _.``[BinHandle] read bytes within the image test``() =
    CollectionAssert.AreEqual([| 4uy; 5uy; 6uy; 7uy |], hdl.ReadBytes(4UL, 4))
    Assert.AreEqual<int>(16, hdl.ReadBytes(0UL, 16).Length)

  [<TestMethod>]
  member _.``[BinHandle] try read bytes within the image test``() =
    Assert.AreEqual(Ok [| 4uy; 5uy; 6uy; 7uy |], hdl.TryReadBytes(4UL, 4))
    let whole = hdl.TryReadBytes(0UL, 16) |> Result.map Array.length
    Assert.AreEqual(Ok 16, whole)

  [<TestMethod>]
  member _.``[BinHandle] try read bytes past the end test``() =
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadBytes(12UL, 8))

  (* A null pointer used to slip through the size-1 check, which turned this
     into a span-level exception instead of an error. *)
  [<TestMethod>]
  member _.``[BinHandle] try read bytes at an unmapped address test``() =
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadBytes(unmapped, 4))
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadBytes(unmapped, 1))
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    emptyHdl.TryReadBytes(0UL, 4))

  [<TestMethod>]
  member _.``[BinHandle] try read bytes of a non-positive size test``() =
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadBytes(0UL, 0))

  [<TestMethod>]
  member _.``[BinHandle] try read bytes through a skewed pointer test``() =
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadBytes(skewed, 32))

  [<TestMethod>]
  member _.``[BinHandle] try read bytes of a VM-only region test``() =
    let expected: Result<byte[], ErrorCase> = Ok(Array.zeroCreate 8)
    Assert.AreEqual(expected, hdl.TryReadBytes(vmOnly, 8))

  [<TestMethod>]
  member _.``[BinHandle] read integers within the image test``() =
    Assert.AreEqual<int64>(0x0706050403020100L, hdl.ReadInt(0UL, 8))
    Assert.AreEqual<uint64>(0x0706050403020100UL, hdl.ReadUInt(0UL, 8))
    Assert.AreEqual<int64>(0x03020100L, hdl.ReadInt(0UL, 4))

  [<TestMethod>]
  member _.``[BinHandle] try read integers at an unmapped address test``() =
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadInt(unmapped, 4))
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadUInt(unmapped, 4))

  [<TestMethod>]
  member _.``[BinHandle] try read an integer of an unsupported size test``() =
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadInt(0UL, 3))

  [<TestMethod>]
  member _.``[BinHandle] read a NUL-terminated string test``() =
    Assert.AreEqual<string>("hi", strHdl.ReadASCII 0UL)
    Assert.AreEqual<string>("i", strHdl.ReadASCII 1UL)
    Assert.AreEqual<string>("", strHdl.ReadASCII 2UL)
    Assert.AreEqual(Ok "hi", strHdl.TryReadASCII 0UL)

  (* A string that runs to the end of the pointed region without a NUL yields
     what was read; only an unreadable start is an error. *)
  [<TestMethod>]
  member _.``[BinHandle] read an unterminated string test``() =
    Assert.AreEqual<string>("ab", strHdl.ReadASCII 3UL)
    Assert.AreEqual(Ok "ab", strHdl.TryReadASCII 3UL)

  (* This used to hand back an empty string, making an unmapped address
     indistinguishable from a genuinely empty one. *)
  [<TestMethod>]
  member _.``[BinHandle] try read a string at a bad pointer test``() =
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadASCII unmapped)
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadASCII BinFilePointer.Null)
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    hdl.TryReadASCII vmOnly)
    Assert.AreEqual(Error ErrorCase.InvalidMemoryRead,
                    emptyHdl.TryReadASCII 0UL)

  (* Every failing read must surface the same exception type. A span-level
     ArgumentOutOfRangeException would fail these, since it derives from
     ArgumentException and ThrowsExactly rejects derived types. *)
  [<TestMethod>]
  member _.``[BinHandle] read bytes past the end raises test``() =
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      hdl.ReadBytes(12UL, 8) |> ignore) |> ignore

  [<TestMethod>]
  member _.``[BinHandle] read bytes at an unmapped address raises test``() =
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      hdl.ReadBytes(unmapped, 4) |> ignore) |> ignore

  [<TestMethod>]
  member _.``[BinHandle] read bytes through a skewed pointer raises test``() =
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      hdl.ReadBytes(skewed, 32) |> ignore) |> ignore

  [<TestMethod>]
  member _.``[BinHandle] read an integer of a bad size raises test``() =
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      hdl.ReadInt(0UL, 3) |> ignore) |> ignore

  [<TestMethod>]
  member _.``[BinHandle] read a string at a bad pointer raises test``() =
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      hdl.ReadASCII unmapped |> ignore) |> ignore
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      hdl.ReadASCII BinFilePointer.Null |> ignore) |> ignore
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      hdl.ReadASCII vmOnly |> ignore) |> ignore

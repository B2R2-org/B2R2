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

  (* The handle must report the ISA the file settled on, not a copy of the one
     it was constructed with, since format detection can resolve a different
     one. Holding the same instance is what pins that. *)
  [<TestMethod>]
  member _.``[BinHandle] raw image ISA and OS test``() =
    Assert.AreEqual<Architecture>(Architecture.Intel, hdl.ISA.Arch)
    Assert.AreSame(hdl.File.ISA, hdl.ISA)
    Assert.AreEqual<OS>(OS.UnknownOS, hdl.OS)

  [<TestMethod>]
  member _.``[BinHandle] OS injected into a raw image test``() =
    let hdl = BinHandle([| 0x90uy |], isa, OS.Linux)
    Assert.AreEqual<OS>(OS.Linux, hdl.OS)

  (* Shellcode at a non-zero base on a known OS had no construction path: the
     base-address overload pinned the OS to None and the OS overload pinned the
     base to None, so such an image always fell back to UnknownOS. *)
  [<TestMethod>]
  member _.``[BinHandle] raw image with a base address and an OS test``() =
    let hdl = BinHandle([| 0x90uy; 0xc3uy |], isa, 0x400000UL, OS.Linux)
    Assert.AreEqual<OS>(OS.Linux, hdl.OS)
    Assert.AreEqual<Addr>(0x400000UL, hdl.File.BaseAddress)
    let read = hdl.ReadBytes(0x400000UL, 2)
    CollectionAssert.AreEqual([| 0x90uy; 0xc3uy |], read)

  (* The byte-array constructors take the array as a raw image; LoadFileBytes is
     the path that runs format detection over it. Hex text is the one format
     needing no fixture, so it is what pins the difference. The detection is not
     visible through Format, since a hex image still loads as a RawBinFile and
     so reports RawBinary; the parsed content is what tells the two apart. *)
  [<TestMethod>]
  member _.``[BinHandle] LoadFileBytes detects the format test``() =
    let hexText = System.Text.Encoding.ASCII.GetBytes "90c3"
    let raw = BinHandle(hexText, isa)
    Assert.AreEqual<int>(4, raw.File.Length)
    CollectionAssert.AreEqual(hexText, raw.ReadBytes(0UL, 4))
    let detected = BinHandle.LoadFileBytes(hexText, isa)
    Assert.AreEqual<int>(2, detected.File.Length)
    CollectionAssert.AreEqual([| 0x90uy; 0xc3uy |], detected.ReadBytes(0UL, 2))

  (* A hex image is decoded on load, so the handle already holds decoded bytes
     and hex is spent as an input notation. MakeNew used to reuse the detected
     format rather than the one the loaded file reports, and so fed those
     decoded bytes back through the hex parser, which threw. *)
  [<TestMethod>]
  member _.``[BinHandle] MakeNew on a decoded hex image test``() =
    let hexText = System.Text.Encoding.ASCII.GetBytes "90c3"
    let hdl = BinHandle.LoadFileBytes(hexText, isa)
    let again = hdl.MakeNew(hdl.File.RawBytes.ToArray())
    Assert.AreEqual<int>(2, again.File.Length)
    CollectionAssert.AreEqual([| 0x90uy; 0xc3uy |], again.ReadBytes(0UL, 2))

  (* MakeNew is the only other path that feeds an OS back into construction, so
     an injected one has to survive it. *)
  [<TestMethod>]
  member _.``[BinHandle] OS survives MakeNew test``() =
    let hdl = BinHandle([| 0x90uy |], isa, OS.Linux)
    Assert.AreEqual<OS>(OS.Linux, hdl.MakeNew([| 0x90uy; 0x90uy |]).OS)
    Assert.AreEqual<OS>(OS.Linux, hdl.MakeNew([| 0x90uy |], 0x1000UL).OS)

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

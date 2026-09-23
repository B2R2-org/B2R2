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

namespace B2R2.FrontEnd.BinFile.Tests

open B2R2.FrontEnd.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type BinRegionTableTests() =
  /// Two regions in the shape a loader maps: a 0x100-byte one wholly kept in
  /// the file, and a 0x200-byte one whose last 0x100 bytes are zero at run
  /// time and nowhere on disk, as the tail of a data segment is.
  static let regions =
    [| { Address = 0x1000UL
         VMSize = 0x100UL
         Offset = 0UL
         FileSize = 0x100UL }
       { Address = 0x2000UL
         VMSize = 0x200UL
         Offset = 0x100UL
         FileSize = 0x100UL } |]

  static let table = BinRegionTable regions

  [<TestMethod>]
  member _.``[BinRegionTable] file-backed lookup test``() =
    let ptr = table.GetBoundedPointer 0x1040UL
    Assert.AreEqual<bool>(true, ptr.CanReadFileBytes)
    Assert.AreEqual<int>(0x40, ptr.Offset)
    Assert.AreEqual<int>(0xff, ptr.MaxOffset)
    Assert.AreEqual<uint64>(0x10ffUL, ptr.MaxAddr)

  (* An address a region gives room to but the file keeps no bytes for names
     no file offset, so it must give a virtual pointer bounded by the whole of
     what the region maps, not by what the file holds. *)
  [<TestMethod>]
  member _.``[BinRegionTable] virtual lookup test``() =
    let ptr = table.GetBoundedPointer 0x2100UL
    Assert.AreEqual<bool>(true, ptr.IsVirtual)
    Assert.AreEqual<bool>(false, ptr.CanReadFileBytes)
    Assert.AreEqual<uint64>(0x21ffUL, ptr.MaxAddr)

  (* The bounds are inclusive on the last byte a region maps and exclusive one
     past it, which is where an off-by-one would show. *)
  [<TestMethod>]
  member _.``[BinRegionTable] region boundary test``() =
    Assert.AreEqual<int>(0, (table.GetBoundedPointer 0x1000UL).Offset)
    Assert.AreEqual<int>(0xff, (table.GetBoundedPointer 0x10ffUL).Offset)
    Assert.AreEqual<bool>(true, (table.GetBoundedPointer 0x1100UL).IsNull)
    Assert.AreEqual<bool>(true, (table.GetBoundedPointer 0x1fffUL).IsNull)
    Assert.AreEqual<bool>(true, (table.GetBoundedPointer 0x21ffUL).IsVirtual)
    Assert.AreEqual<bool>(true, (table.GetBoundedPointer 0x2200UL).IsNull)

  [<TestMethod>]
  member _.``[BinRegionTable] unmapped lookup test``() =
    Assert.AreEqual<bool>(true, (table.GetBoundedPointer 0UL).IsNull)
    Assert.AreEqual<bool>(true, (table.GetBoundedPointer 0xffffUL).IsNull)

  [<TestMethod>]
  member _.``[BinRegionTable] empty table test``() =
    let empty = BinRegionTable [||]
    Assert.AreEqual<bool>(true, (empty.GetBoundedPointer 0x1000UL).IsNull)

  (* A region that maps nothing must match no address at all, rather than let
     the one at its start through. *)
  [<TestMethod>]
  member _.``[BinRegionTable] empty region test``() =
    let r = { Address = 0x1000UL; VMSize = 0UL; Offset = 0UL; FileSize = 0UL }
    let table = BinRegionTable [| r |]
    Assert.AreEqual<bool>(true, (table.GetBoundedPointer 0x1000UL).IsNull)

  (* The hint each table keeps must be its own, so that two tables read in
     turn, as two open files are, neither knock each other's hint out nor
     answer from an index into the other's regions. The two tables below map
     the same address at different indices, which is where the latter would
     show. *)
  [<TestMethod>]
  member _.``[BinRegionTable] per-table hint test``() =
    let other =
      [| { Address = 0UL; VMSize = 0x10UL; Offset = 0UL; FileSize = 0x10UL }
         { Address = 0x1000UL
           VMSize = 0x100UL
           Offset = 0x10UL
           FileSize = 0x100UL } |]
      |> BinRegionTable
    for _ in 1 .. 4 do
      Assert.AreEqual<int>(0x40, (table.GetBoundedPointer 0x1040UL).Offset)
      Assert.AreEqual<int>(0x50, (other.GetBoundedPointer 0x1040UL).Offset)

  (* Where two regions map the same address, the first of them must win, which
     is what a scan from the top of the table does. *)
  [<TestMethod>]
  member _.``[BinRegionTable] overlapping regions test``() =
    let table =
      [| { Address = 0x1000UL
           VMSize = 0x100UL
           Offset = 0UL
           FileSize = 0x100UL }
         { Address = 0x1000UL
           VMSize = 0x100UL
           Offset = 0x100UL
           FileSize = 0x100UL } |]
      |> BinRegionTable
    Assert.AreEqual<int>(0, (table.GetBoundedPointer 0x1000UL).Offset)

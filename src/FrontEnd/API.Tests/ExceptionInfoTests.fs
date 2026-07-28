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

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.FrontEnd
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type ExceptionInfoTests() =
  static let isa = ISA(Architecture.Intel, WordSize.Bit64)

  /// A raw image, which carries no section structure and therefore no code
  /// section for the coverage ratio to measure against.
  static let rawHdl = BinHandle([| 0x90uy; 0x90uy; 0xc3uy; 0x90uy |], isa)

  /// A window of 0x1000 addresses, used to keep the expected ratios exact.
  static let winLo, winHi = 0x1000UL, 0x1fffUL

  /// Builds the range table the production code keeps, which is keyed by the
  /// range start so that duplicate starts collapse.
  static let ranges pairs =
    let tbl = Dictionary<Addr, Addr>()
    for startAddr, endAddr in pairs do tbl[startAddr] <- endAddr
    tbl

  /// Coverage of the standard window by the ranges built from the given pairs.
  static let coverage pairs =
    ExceptionCoverage.compute winLo winHi (ranges pairs)

  /// Builds a handler table from (blockStart, blockEnd, landingPad) triples.
  static let handlers triples =
    triples
    |> List.fold (fun tbl (blkStart, blkEnd, pad) ->
      HandlerTable.add (AddrRange.create blkStart blkEnd) pad tbl)
      IntervalMap.empty

  (* The ratio used to divide by a zero-sized window and yield NaN, which no
     threshold check can catch: both "> 0.9" and "< 0.1" are false for NaN. *)
  [<TestMethod>]
  member _.``[ExceptionInfo] coverage without a code section test``() =
    let coverage = ExceptionInfo(rawHdl).ExceptionCoverage
    Assert.AreEqual<bool>(false, System.Double.IsNaN coverage)
    Assert.AreEqual<float>(0.0, coverage)

  (* The covered amount added one to each range length while the window size did
     not, so a fully covered section reported more than 100%. *)
  [<TestMethod>]
  member _.``[ExceptionInfo] full coverage is exactly one test``() =
    Assert.AreEqual<float>(1.0, coverage [ winLo, winHi ])

  (* Only the start of a range was tested against the window, so a range
     running past the end contributed its whole length, while one starting
     before the window was dropped altogether. *)
  [<TestMethod>]
  member _.``[ExceptionInfo] ranges are clamped to the window test``() =
    Assert.AreEqual<float>(0.5, coverage [ 0x1800UL, 0xffffUL ])
    Assert.AreEqual<float>(0.5, coverage [ 0x0UL, 0x17ffUL ])
    Assert.AreEqual<float>(0.0, coverage [ 0x8000UL, 0x9000UL ])

  (* A try block inside another try block yields a range contained in an outer
     one. The table used to forbid that, so building it raised
     RangeOverlapException for ordinary C++ binaries. *)
  [<TestMethod>]
  member _.``[ExceptionInfo] nested handler blocks are kept test``() =
    let tbl =
      handlers
        [ 0x1000UL, 0x2000UL, 0xaaUL
          0x1500UL, 0x1600UL, 0xbbUL ]
    Assert.AreEqual<int>(2, (HandlerTable.toArray tbl).Length)

  (* At run time the innermost block catches first, so the narrowest range
     covering the address is the one that decides the landing pad. *)
  [<TestMethod>]
  member _.``[ExceptionInfo] innermost handler block wins test``() =
    let tbl =
      handlers
        [ 0x1000UL, 0x2000UL, 0xaaUL
          0x1500UL, 0x1600UL, 0xbbUL ]
    Assert.AreEqual(Some 0xbbUL, HandlerTable.tryFindTarget 0x1550UL tbl)
    Assert.AreEqual(Some 0xaaUL, HandlerTable.tryFindTarget 0x1100UL tbl)
    Assert.AreEqual(Some 0xaaUL, HandlerTable.tryFindTarget 0x2000UL tbl)
    Assert.AreEqual(None, HandlerTable.tryFindTarget 0x2001UL tbl)

  (* Nesting also shows up as two blocks sharing a start address, which no
     comparison on the start alone can resolve. *)
  [<TestMethod>]
  member _.``[ExceptionInfo] handler blocks sharing a start test``() =
    let tbl =
      handlers
        [ 0x1000UL, 0x9000UL, 0xaaUL
          0x1000UL, 0x1010UL, 0xbbUL ]
    Assert.AreEqual(Some 0xbbUL, HandlerTable.tryFindTarget 0x1005UL tbl)
    Assert.AreEqual(Some 0xaaUL, HandlerTable.tryFindTarget 0x1011UL tbl)

  (* An exact duplicate range must not raise either; the last pad wins. *)
  [<TestMethod>]
  member _.``[ExceptionInfo] duplicate handler blocks collapse test``() =
    let tbl =
      handlers
        [ 0x1000UL, 0x2000UL, 0xaaUL
          0x1000UL, 0x2000UL, 0xbbUL ]
    Assert.AreEqual<int>(1, (HandlerTable.toArray tbl).Length)
    Assert.AreEqual(Some 0xbbUL, HandlerTable.tryFindTarget 0x1500UL tbl)

  [<TestMethod>]
  member _.``[ExceptionInfo] handler ranges are ordered by start test``() =
    let tbl =
      handlers
        [ 0x3000UL, 0x4000UL, 0xccUL
          0x1000UL, 0x2000UL, 0xaaUL
          0x1500UL, 0x1600UL, 0xbbUL ]
    let starts =
      HandlerTable.toArray tbl
      |> Array.map (fun (r: AddrRange, _) -> $"{r.Min:x}")
      |> String.concat ","
    Assert.AreEqual<string>("1000,1500,3000", starts)

  [<TestMethod>]
  member _.``[ExceptionInfo] empty handler table test``() =
    let tbl = handlers []
    Assert.AreEqual<int>(0, (HandlerTable.toArray tbl).Length)
    Assert.AreEqual(None, HandlerTable.tryFindTarget 0x1000UL tbl)

  [<TestMethod>]
  member _.``[ExceptionInfo] degenerate coverage inputs test``() =
    Assert.AreEqual<float>(0.0, coverage [])
    let reversed = ExceptionCoverage.compute 0x2000UL 0x1fffUL (ranges [])
    Assert.AreEqual<float>(0.0, reversed)
    let single = ranges [ winLo, winLo ]
    let oneAddr = ExceptionCoverage.compute winLo winLo single
    Assert.AreEqual<float>(1.0, oneAddr)

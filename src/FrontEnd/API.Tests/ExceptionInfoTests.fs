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

  [<TestMethod>]
  member _.``[ExceptionInfo] degenerate coverage inputs test``() =
    Assert.AreEqual<float>(0.0, coverage [])
    let reversed = ExceptionCoverage.compute 0x2000UL 0x1fffUL (ranges [])
    Assert.AreEqual<float>(0.0, reversed)
    let single = ranges [ winLo, winLo ]
    let oneAddr = ExceptionCoverage.compute winLo winLo single
    Assert.AreEqual<float>(1.0, oneAddr)

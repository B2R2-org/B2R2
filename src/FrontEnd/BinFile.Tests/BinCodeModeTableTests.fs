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

open B2R2
open B2R2.FrontEnd.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Tests for the table that answers where each marked region of a binary
/// begins and ends, which is what lets a reader skip a data region rather than
/// decode it.
[<TestClass>]
type BinCodeModeTableTests() =
  /// A word of ARM code, a word of data embedded in it, and code again, given
  /// out of order so that the table cannot rely on the order it is built from.
  static let markers =
    [| { Address = 0x110UL; Mode = ArmMode }
       { Address = 0x100UL; Mode = ArmMode }
       { Address = 0x108UL; Mode = DataMode } |]

  static let table = BinCodeModeTable markers

  [<TestMethod>]
  member _.``[BinCodeModeTable] a marked address reads its own mode``() =
    let data = table.TryFindMode 0x108UL
    Assert.AreEqual<BinCodeMode option>(Some DataMode, data)
    Assert.AreEqual<BinCodeMode option>(Some ArmMode, table.TryFindMode 0x110UL)

  [<TestMethod>]
  member _.``[BinCodeModeTable] an unmarked address reads no mode``() =
    Assert.AreEqual<BinCodeMode option>(None, table.TryFindMode 0x104UL)

  [<TestMethod>]
  member _.``[BinCodeModeTable] a region ends at the next marker``() =
    Assert.AreEqual<Addr option>(Some 0x110UL, table.TryFindRegionEnd 0x108UL)

  [<TestMethod>]
  member _.``[BinCodeModeTable] an address inside a region ends with it``() =
    Assert.AreEqual<Addr option>(Some 0x108UL, table.TryFindRegionEnd 0x104UL)

  [<TestMethod>]
  member _.``[BinCodeModeTable] the last region has no end``() =
    Assert.AreEqual<Addr option>(None, table.TryFindRegionEnd 0x110UL)

  [<TestMethod>]
  member _.``[BinCodeModeTable] two markers at one address mark one region``() =
    (* The region would otherwise be empty, which a reader walking it in
       address order cannot step over. *)
    let doubled =
      [| { Address = 0x100UL; Mode = DataMode }
         { Address = 0x100UL; Mode = ArmMode } |]
    let table = BinCodeModeTable doubled
    Assert.AreEqual<BinCodeMode option>(Some ArmMode, table.TryFindMode 0x100UL)
    Assert.AreEqual<Addr option>(None, table.TryFindRegionEnd 0x100UL)

  [<TestMethod>]
  member _.``[BinCodeModeTable] a file without markers is empty``() =
    let table = BinCodeModeTable [||]
    Assert.AreEqual<bool>(true, table.IsEmpty)
    Assert.AreEqual<Addr option>(None, table.TryFindRegionEnd 0x100UL)

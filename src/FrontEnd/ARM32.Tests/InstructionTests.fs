(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.FrontEnd.ARM32.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM32

[<TestClass>]
type InstructionTests() =
  static let parse isThumb hex =
    let reader = BinReader.Init Endian.Big
    let parser = Parser(ISA "armv7", isThumb, reader) :> IInstructionParsable
    parser.Parse(ByteArray.ofHexString hex, 0UL)

  (* A function returns by branching to the link register as much as by popping
     the PC, and a BX to any other register is a jump that the CFG has to
     follow, not a return. *)
  [<TestMethod>]
  member _.``[ARMv7] returns test``() =
    let isRET isThumb hex = (parse isThumb hex).IsRET
    Assert.AreEqual<bool>(true, isRET false "e12fff1e") (* bx lr *)
    Assert.AreEqual<bool>(true, isRET true "4770") (* bx lr *)
    Assert.AreEqual<bool>(true, isRET false "e8bd8010") (* pop {r4, pc} *)
    Assert.AreEqual<bool>(true, isRET false "e49df004") (* pop {pc} *)
    Assert.AreEqual<bool>(false, isRET false "e12fff13") (* bx r3 *)

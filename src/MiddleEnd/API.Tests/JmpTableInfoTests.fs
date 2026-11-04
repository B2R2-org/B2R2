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

namespace B2R2.MiddleEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Tests how the entries of a jump table are read out of the binary.
[<TestClass>]
type JmpTableInfoTests() =
  /// Represents a raw x64 image that holds nothing but one entry, the address
  /// 0x10, so that the slot after it lies past the end of the image.
  let binary = [| 0x10uy; 0x0uy; 0x0uy; 0x0uy; 0x0uy; 0x0uy; 0x0uy; 0x0uy |]

  let isa = ISA(Architecture.Intel, WordSize.Bit64)
  let hdl = BinHandle.LoadRawImage(binary, isa)

  let jmptbl =
    { InsAddr = 0x0UL
      JumpBase = 0x0UL
      TableAddress = 0x0UL
      EntrySize = 8
      EntryShift = 0
      IsSignedEntry = true
      NumEntries = 0
      WaitingInstructions = []
      IsSingleEntry = false
      OwnRangeEntries = None
      IsFunctionPointerTable = false }

  (* A table can end right where the bytes of the file do, and the slot after
     its last entry then holds nothing to read, which is no entry rather than
     a failure. *)
  [<TestMethod>]
  member _.``JmpTableInfo reads no entry past the end of the image``() =
    let read = JmpTableInfo.tryReadTarget hdl jmptbl
    Assert.AreEqual<Addr option>(Some 0x10UL, read 0)
    Assert.AreEqual<Addr option>(None, read 1)

  (* GCC for ARM counts the entries of a table in words and reads a byte entry
     with ldrb or ldrsb, so the same byte sends one table 0xe0 words past its
     base and another 0x20 words before it. *)
  [<TestMethod>]
  member _.``JmpTableInfo extends an entry as its load does and scales it``() =
    let hdl = BinHandle.LoadRawImage([| 0xe0uy |], ISA "armv7")
    let unsigned =
      { jmptbl with
          JumpBase = 0x1000UL
          EntrySize = 1
          EntryShift = 2
          IsSignedEntry = false }
    let signed = { unsigned with IsSignedEntry = true }
    let read tbl = JmpTableInfo.tryReadTarget hdl tbl 0
    Assert.AreEqual<Addr option>(Some 0x1380UL, read unsigned)
    Assert.AreEqual<Addr option>(Some 0xf80UL, read signed)

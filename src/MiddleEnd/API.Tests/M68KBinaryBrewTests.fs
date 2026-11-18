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
open B2R2.MiddleEnd

/// Tests the recovery of m68k binaries.
[<TestClass>]
type M68KBinaryBrewTests() =
  /// Recovers the functions of the given code, which starts at address zero
  /// with the entry of the binary. A raw image has no section to hold a table,
  /// so a test on one reads its tables as ones of labels, which have to point
  /// into their function, before the next one: the code starts by calling a
  /// function that lies past its tables.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    BinaryBrew(BinHandle.LoadRawImage(bytes, ISA Architecture.M68K)).Functions

  /// Returns how many entries each jump table of the entry function has.
  static let countEntries code =
    let fns = recoverCode code
    fns[0UL].JumpTables |> Array.map _.NumEntries

  (* GCC loads an entry of a table right after its jump with move.w, which
     fills the low word of a data register and keeps the rest, and the jump
     reads that low word back. *)
  [<TestMethod>]
  member _.``A table is read through the low word that a move fills``() =
    let code =
      [ "61000022" (* bsr.w 0x24 *)
        "0c8000000001" (* cmpi.l #1,d0 *)
        "62000016" (* bhi.w 0x22 *)
        "303b0a06" (* move.w (6,pc,d0.l*2),d0 *)
        "4efb0002" (* jmp (2,pc,d0.w) *)
        "0004" (* 0x16: .word 0x1a - 0x16 *)
        "0008" (* .word 0x1e - 0x16 *)
        "7000" (* 0x1a: moveq #0,d0 *)
        "4e75" (* rts *)
        "7001" (* 0x1e: moveq #1,d0 *)
        "4e75" (* rts *)
        "4e75" (* 0x22: rts *)
        "4e75" (* 0x24: rts *) ]
    CollectionAssert.AreEqual([| 2 |], countEntries code)

  (* GCC doubles an index by adding it to itself and loads the entry with a
     scale of one. *)
  [<TestMethod>]
  member _.``A table is read through an index that the code doubles``() =
    let code =
      [ "61000024" (* bsr.w 0x26 *)
        "0c8000000001" (* cmpi.l #1,d0 *)
        "62000018" (* bhi.w 0x24 *)
        "d080" (* add.l d0,d0 *)
        "303b0806" (* move.w (6,pc,d0.l),d0 *)
        "4efb0002" (* jmp (2,pc,d0.w) *)
        "0004" (* 0x18: .word 0x1c - 0x18 *)
        "0008" (* .word 0x20 - 0x18 *)
        "7000" (* 0x1c: moveq #0,d0 *)
        "4e75" (* rts *)
        "7001" (* 0x20: moveq #1,d0 *)
        "4e75" (* rts *)
        "4e75" (* 0x24: rts *)
        "4e75" (* 0x26: rts *) ]
    CollectionAssert.AreEqual([| 2 |], countEntries code)

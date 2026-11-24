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

/// Tests the recovery of Alpha binaries.
[<TestClass>]
type AlphaBinaryBrewTests() =
  /// Recovers the functions of the given Alpha code, which starts at address
  /// zero with the entry of the binary.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    BinaryBrew(BinHandle.LoadRawImage(bytes, ISA "alpha")).Functions

  (* A jump clears the low two bits of its target, which the address of code
     has clear anyway, so a table is read through the jump as if it did not.
     A raw image has no section to hold a table, so the table is one of
     labels, which point into its function, before the next one: the code
     starts by calling a function that lies past its table. *)
  [<TestMethod>]
  member _.``A table is read through the mask of its jump``() =
    let code =
      [ "0e0040d3" (* 0x00: bsr ra,0x3c *)
        "a1370042" (* cmpule a0,1,t0 *)
        "0b0020e4" (* beq t0,0x38 *)
        "20005f20" (* lda t1,0x20 *)
        "50040242" (* s4addq a0,t1,a0 *)
        "000030a0" (* ldl t0,0(a0) *)
        "01044140" (* addq t1,t0,t0 *)
        "0000e16b" (* jmp (t0) *)
        "08000000" (* 0x20: .long 0x28 - 0x20 *)
        "10000000" (* .long 0x30 - 0x20 *)
        "00001f20" (* 0x28: lda v0,0 *)
        "0080fa6b" (* ret *)
        "01001f20" (* 0x30: lda v0,1 *)
        "0080fa6b" (* ret *)
        "0080fa6b" (* 0x38: ret *)
        "0080fa6b" (* 0x3c: ret *) ]
    let fns = recoverCode code
    let entries = fns[0UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

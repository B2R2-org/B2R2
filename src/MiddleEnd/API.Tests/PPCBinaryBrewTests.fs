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

/// Tests the recovery of PowerPC binaries.
[<TestClass>]
type PPCBinaryBrewTests() =
  /// Recovers the functions of the given big-endian code for the given word
  /// size, which starts at address zero with the entry of the binary. A raw
  /// image has no section to hold a table, so a test on one reads its tables
  /// as ones of labels, which have to point into their function, before the
  /// next one: the code starts by calling a function that lies past its
  /// tables.
  static let recoverCode wordSize (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    let isa = ISA(Architecture.PPC, Endian.Big, wordSize)
    BinaryBrew(BinHandle.LoadRawImage(bytes, isa)).Functions

  /// Returns how many entries each jump table of the entry function has.
  static let countEntries wordSize code =
    let fns = recoverCode wordSize code
    fns[0UL].JumpTables |> Array.map _.NumEntries

  /// Returns the code of a function that jumps through a table of two entries
  /// right after its jump, which counts the entries from itself as GCC does,
  /// once the given instructions turn the index in r3 into the offset of its
  /// entry and load the entry into r3 from the table in r9.
  static let tableOfTwo (scaleAndLoad: string list) =
    [ "48000041" (* bl 0x40 *)
      "28030001" (* cmplwi r3,1 *)
      "4181002c" (* bgt 0x34 *)
      "3d200000" (* lis r9,0 *)
      "39290028" (* addi r9,r9,0x28 *)
      yield! scaleAndLoad
      "7d234a14" (* add r9,r3,r9 *)
      "7d2903a6" (* mtctr r9 *)
      "4e800420" (* bctr *)
      "00000008" (* 0x28: .long 0x30 - 0x28 *)
      "00000010" (* .long 0x38 - 0x28 *)
      "38600000" (* 0x30: li r3,0 *)
      "4e800020" (* blr *)
      "38600001" (* 0x38: li r3,1 *)
      "4e800020" (* blr *)
      "4e800020" (* 0x40: blr *) ]

  (* A branch to CTR clears the low two bits of its target, which the address
     of code has clear anyway, so a table is read through the branch as if it
     did not. *)
  [<TestMethod>]
  member _.``A table is read through the mask of its branch``() =
    let code =
      tableOfTwo
        [ "1c630004" (* mulli r3,r3,4 *)
          "7c69182e" (* lwzx r3,r9,r3 *) ]
    CollectionAssert.AreEqual([| 2 |], countEntries WordSize.Bit32 code)

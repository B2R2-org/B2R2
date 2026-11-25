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

/// Tests the recovery of PA-RISC binaries.
[<TestClass>]
type PARISCBinaryBrewTests() =
  /// Recovers the functions of the given PA-RISC code, which starts at
  /// address zero with the entry of the binary.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    let isa = ISA(Architecture.PARISC, Endian.Big, WordSize.Bit32)
    BinaryBrew(BinHandle.LoadRawImage(bytes, isa)).Functions

  (* A transfer through a register clears the low two bits of its target,
     which hold the privilege level there and which the address of code has
     clear anyway, so a table is read through the transfer as if it did not.
     A raw image has no section to hold a table, so the table is one of
     labels, which point into its function, before the next one: the code
     starts by calling a function that lies past its table. *)
  [<TestMethod>]
  member _.``A table is read through the mask of its jump``() =
    let code =
      [ "e8400060" (* 0x00: b,l 0x38,rp *)
        "08000240" (* nop *)
        "93408002" (* cmpiclr,<< 1,r26,r0 *)
        "e8000002" (* b,n 0x14 *)
        "e840c002" (* bv,n r0(rp) *)
        "34130040" (* 0x14: ldi 0x20,r19 *)
        "0e7a2093" (* ldw,s r26(r19),r19 *)
        "ea60c002" (* bv,n r0(r19) *)
        "00000028" (* 0x20: .word 0x28 *)
        "00000030" (* .word 0x30 *)
        "e840c000" (* 0x28: bv r0(rp) *)
        "341c0000" (* ldi 0,ret0 *)
        "e840c000" (* 0x30: bv r0(rp) *)
        "341c0002" (* ldi 1,ret0 *)
        "e840c002" (* 0x38: bv,n r0(rp) *) ]
    let fns = recoverCode code
    let entries = fns[0UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

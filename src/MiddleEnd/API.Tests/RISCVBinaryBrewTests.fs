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

/// Tests the recovery of RISCV binaries.
[<TestClass>]
type RISCVBinaryBrewTests() =
  /// Recovers the functions of elf_riscv64 once _start, at 0x650 with room
  /// for thirty-four bytes before load_gp, becomes the given code, and
  /// .rodata, at 0x768 with room for eight bytes before a string, starts with
  /// the given bytes. A table grows past its first entry only within a
  /// function that another follows, which main, the last one, is not.
  static let recoverPatched (code: string list) (rodata: string) =
    let bytes = readZippedBinary "elf_riscv64"
    let patch (offset: int) (hex: string) =
      (ByteArray.ofHexString hex).CopyTo(bytes, offset)
    patch 0x650 (String.concat "" code)
    patch 0x768 rodata
    let isa = ISA(Architecture.RISCV, Endian.Little, WordSize.Bit64)
    BinaryBrew(BinHandle.LoadFileBytes(bytes, isa)).Functions

  (* Every JALR clears the lowest bit of its target, which the address of
     code has clear anyway, so a table is read through the jump as if it did
     not: here the table of GCC PIC code, whose entries count from the table
     itself. *)
  [<TestMethod>]
  member _.``A table is read through the mask of its jump``() =
    let code =
      [ "97070000" (* auipc a5, 0x0 *)
        "93878711" (* addi a5, a5, 280 *)
        "0a05" (* c.slli a0, 0x2 *)
        "3e95" (* c.add a0, a5 *)
        "0841" (* c.lw a0, 0(a0) *)
        "3e95" (* c.add a0, a5 *)
        "0285" (* c.jr a0 *)
        "0145" (* c.li a0, 0 *)
        "8280" (* c.jr ra *)
        "0545" (* c.li a0, 1 *)
        "8280" (* c.jr ra *) ]
    let rodata = "fafefffffefeffff" (* .word 0x662 - 0x768, 0x666 - 0x768 *)
    let fns = recoverPatched code rodata
    let entries = fns[0x650UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

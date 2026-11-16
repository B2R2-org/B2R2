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

  /// Recovers the functions of the given RV64 code, which starts at address
  /// zero with the entry of the binary. A raw image has no section to hold a
  /// table, so a test on one reads its tables as ones of labels, which have to
  /// point into their function, before the next one: the code starts by
  /// calling a function that lies past its tables.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    let isa = ISA(Architecture.RISCV, Endian.Little, WordSize.Bit64)
    BinaryBrew(BinHandle.LoadRawImage(bytes, isa)).Functions

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

  (* GCC for RV64 takes the low word of an index and scales it at once, by
     shifting it to the top of the register and back by two less. *)
  [<TestMethod>]
  member _.``A table is read through an index that shifts there and back``() =
    let code =
      [ "97070000" (* auipc a5, 0x0 *)
        "93878711" (* addi a5, a5, 280 *)
        "13170502" (* slli a4, a0, 32 *)
        "1355e701" (* srli a0, a4, 30 *)
        "3e95" (* c.add a0, a5 *)
        "0841" (* c.lw a0, 0(a0) *)
        "3e95" (* c.add a0, a5 *)
        "0285" (* c.jr a0 *)
        "0145" (* c.li a0, 0 *)
        "8280" (* c.jr ra *)
        "0545" (* c.li a0, 1 *)
        "8280" (* c.jr ra *) ]
    let rodata = "00ffffff04ffffff" (* .word 0x668 - 0x768, 0x66c - 0x768 *)
    let fns = recoverPatched code rodata
    let entries = fns[0x650UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* A table that nothing bounds reads on into the next one, counting its
     entries from its own base. Here the second entry of A, the first of B,
     sends the jump of A right before the jump of B, ahead of the case of T
     that dispatches B. The jump of B then reads A through the registers that
     A left, against another base, and two jumps that count one table from
     different bases do not share it, so the entry is wrong. *)
  [<TestMethod>]
  member _.``An entry into another dispatch is past its table``() =
    let code =
      [ "ef008006" (* jal ra, 0x68 *)
        "31a8" (* c.j 0x20 *)
        "0100" (* c.nop *)
        "2c000000" (* 0x08, A: .word 0x34 - 0x08 *)
        "54000000" (* 0x0c, B: .word 0x60 - 0x0c *)
        "58000000" (* .word 0x64 - 0x0c *)
        "34000000" (* 0x14, T: .word 0x48 - 0x14 *)
        "38000000" (* .word 0x4c - 0x14 *)
        "00000100" (* .word past the code *)
        "17070000" (* 0x20: auipc a4, 0x0 *)
        "130787fe" (* addi a4, a4, -24: A *)
        "93172500" (* slli a5, a0, 2 *)
        "ba97" (* c.add a5, a4 *)
        "9c43" (* c.lw a5, 0(a5) *)
        "ba97" (* c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "17070000" (* 0x34: auipc a4, 0x0 *)
        "130707fe" (* addi a4, a4, -32: T *)
        "93972500" (* slli a5, a1, 2 *)
        "ba97" (* c.add a5, a4 *)
        "9c43" (* c.lw a5, 0(a5) *)
        "ba97" (* c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "0145" (* 0x48: c.li a0, 0 *)
        "8280" (* c.jr ra *)
        "17070000" (* 0x4c: auipc a4, 0x0 *)
        "130707fc" (* addi a4, a4, -64: B *)
        "93172600" (* slli a5, a2, 2 *)
        "ba97" (* c.add a5, a4 *)
        "9c43" (* c.lw a5, 0(a5) *)
        "ba97" (* 0x5c: c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "0545" (* 0x60: c.li a0, 1 *)
        "8280" (* c.jr ra *)
        "0945" (* 0x64: c.li a0, 2 *)
        "8280" (* c.jr ra *)
        "8280" (* 0x68: c.jr ra *) ]
    let fns = recoverCode code
    let tables =
      fns[0UL].JumpTables
      |> Array.map (fun t -> t.TableAddress, t.NumEntries)
      |> Array.sort
    let expected = [| 0x08UL, 1; 0x0cUL, 2; 0x14UL, 2 |]
    CollectionAssert.AreEqual(expected, tables)

  (* Here the third entry of A, the first of B, sends the jump of A to the
     load of B, which reads through a register that A never sets, so along
     that way the jump of B reads no table. The last entry of T, which the
     recovery reaches after that one, leads to the dispatch of B, and the phis
     that join the two ways hide the table of B from the jump. Read along each
     way on its own, the jump reads B, which then ends A. *)
  [<TestMethod>]
  member _.``A jump reads its table along the way through its dispatch``() =
    let code =
      [ "ef008007" (* jal ra, 0x78 *)
        "25a0" (* c.j 0x2c *)
        "0100" (* c.nop *)
        "38000000" (* 0x08, A: .word 0x40 - 0x08 *)
        "4c000000" (* .word 0x54 - 0x08 *)
        "62000000" (* 0x10, B: .word 0x72 - 0x10 *)
        "64000000" (* .word 0x74 - 0x10 *)
        "40000000" (* 0x18, T: .word 0x58 - 0x18 *)
        "40000000" (* .word 0x58 - 0x18 *)
        "40000000" (* .word 0x58 - 0x18 *)
        "44000000" (* .word 0x5c - 0x18 *)
        "00000100" (* .word past the code *)
        "17070000" (* 0x2c: auipc a4, 0x0 *)
        "1307c7fd" (* addi a4, a4, -36: A *)
        "93172500" (* slli a5, a0, 2 *)
        "ba97" (* c.add a5, a4 *)
        "9c43" (* c.lw a5, 0(a5) *)
        "ba97" (* c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "17070000" (* 0x40: auipc a4, 0x0 *)
        "130787fd" (* addi a4, a4, -40: T *)
        "93972500" (* slli a5, a1, 2 *)
        "ba97" (* c.add a5, a4 *)
        "9c43" (* c.lw a5, 0(a5) *)
        "ba97" (* c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "0d45" (* 0x54: c.li a0, 3 *)
        "8280" (* c.jr ra *)
        "0145" (* 0x58: c.li a0, 0 *)
        "8280" (* c.jr ra *)
        "17070000" (* 0x5c: auipc a4, 0x0 *)
        "130747fb" (* addi a4, a4, -76: B *)
        "13182600" (* slli a6, a2, 2 *)
        "3a98" (* c.add a6, a4 *)
        "83270800" (* 0x6a: lw a5, 0(a6) *)
        "ba97" (* c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "8280" (* 0x72: c.jr ra *)
        "0945" (* 0x74: c.li a0, 2 *)
        "8280" (* c.jr ra *)
        "8280" (* 0x78: c.jr ra *) ]
    let fns = recoverCode code
    let tables =
      fns[0UL].JumpTables
      |> Array.map (fun t -> t.TableAddress, t.NumEntries)
      |> Array.sort
    let expected = [| 0x08UL, 2; 0x10UL, 2; 0x18UL, 4 |]
    CollectionAssert.AreEqual(expected, tables)

  (* Here the third entry of A, the first of B, sends the jump of A to the
     load of B, where the registers hold what A left: the address of that
     entry and the base of A. Along that way, the jump of B reads A with the
     index of A, so it reads that very entry again and comes back to the load,
     running nothing but the code that dispatches it. No case starts there, so
     the entry is wrong, though the two jumps read one table from one base,
     as the copies of a computed goto share theirs. *)
  [<TestMethod>]
  member _.``An entry read again where it leads is past its table``() =
    let code =
      [ "ef008007" (* jal ra, 0x78 *)
        "25a0" (* c.j 0x2c *)
        "0100" (* c.nop *)
        "38000000" (* 0x08, A: .word 0x40 - 0x08 *)
        "4c000000" (* .word 0x54 - 0x08 *)
        "62000000" (* 0x10, B: .word 0x72 - 0x10 *)
        "64000000" (* .word 0x74 - 0x10 *)
        "40000000" (* 0x18, T: .word 0x58 - 0x18 *)
        "40000000" (* .word 0x58 - 0x18 *)
        "40000000" (* .word 0x58 - 0x18 *)
        "44000000" (* .word 0x5c - 0x18 *)
        "00000100" (* .word past the code *)
        "17070000" (* 0x2c: auipc a4, 0x0 *)
        "1307c7fd" (* addi a4, a4, -36: A *)
        "93162500" (* slli a3, a0, 2 *)
        "ba96" (* c.add a3, a4 *)
        "9c42" (* c.lw a5, 0(a3) *)
        "ba97" (* c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "17070000" (* 0x40: auipc a4, 0x0 *)
        "130787fd" (* addi a4, a4, -40: T *)
        "93972500" (* slli a5, a1, 2 *)
        "ba97" (* c.add a5, a4 *)
        "9c43" (* c.lw a5, 0(a5) *)
        "ba97" (* c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "0d45" (* 0x54: c.li a0, 3 *)
        "8280" (* c.jr ra *)
        "0145" (* 0x58: c.li a0, 0 *)
        "8280" (* c.jr ra *)
        "17070000" (* 0x5c: auipc a4, 0x0 *)
        "130747fb" (* addi a4, a4, -76: B *)
        "93162600" (* slli a3, a2, 2 *)
        "ba96" (* c.add a3, a4 *)
        "83a70600" (* 0x6a: lw a5, 0(a3) *)
        "ba97" (* c.add a5, a4 *)
        "8287" (* c.jr a5 *)
        "8280" (* 0x72: c.jr ra *)
        "0945" (* 0x74: c.li a0, 2 *)
        "8280" (* c.jr ra *)
        "8280" (* 0x78: c.jr ra *) ]
    let fns = recoverCode code
    let tables =
      fns[0UL].JumpTables
      |> Array.map (fun t -> t.TableAddress, t.NumEntries)
      |> Array.sort
    let expected = [| 0x08UL, 2; 0x10UL, 2; 0x18UL, 4 |]
    CollectionAssert.AreEqual(expected, tables)

  (* Clang folds the smallest value of a switch into the displacement of the
     load, which reads below the base by the entries of the values that the
     switch never takes. Here the jump of Q reads its first entry for one, so
     Q starts at its base, while the word below the base is the last entry of
     P. *)
  [<TestMethod>]
  member _.``A table starts at the base that its load reads below``() =
    let code =
      [ "ef006005" (* jal ra, 0x56 *)
        "21a8" (* c.j 0x1c *)
        "0100" (* c.nop *)
        "30000000" (* 0x08, P: .word 0x30 *)
        "34000000" (* .word 0x34 *)
        "4e000000" (* 0x10, Q: .word 0x4e *)
        "52000000" (* .word 0x52 *)
        "00000100" (* .word past the code *)
        "11ce" (* 0x1c: c.beqz a2, 0x38 *)
        "17070000" (* auipc a4, 0x0 *)
        "1307a7fe" (* addi a4, a4, -22: P *)
        "93172500" (* slli a5, a0, 2 *)
        "ba97" (* c.add a5, a4 *)
        "9c43" (* c.lw a5, 0(a5) *)
        "8287" (* c.jr a5 *)
        "0145" (* 0x30: c.li a0, 0 *)
        "8280" (* c.jr ra *)
        "0545" (* 0x34: c.li a0, 1 *)
        "8280" (* c.jr ra *)
        "17070000" (* 0x38: auipc a4, 0x0 *)
        "130787fd" (* addi a4, a4, -40: Q *)
        "93f7f50f" (* andi a5, a1, 255 *)
        "8a07" (* c.slli a5, 2 *)
        "ba97" (* c.add a5, a4 *)
        "83a7c7ff" (* lw a5, -4(a5) *)
        "8287" (* c.jr a5 *)
        "0945" (* 0x4e: c.li a0, 2 *)
        "8280" (* c.jr ra *)
        "0d45" (* 0x52: c.li a0, 3 *)
        "8280" (* c.jr ra *)
        "8280" (* 0x56: c.jr ra *) ]
    let fns = recoverCode code
    let tables =
      fns[0UL].JumpTables
      |> Array.map (fun t -> t.TableAddress, t.NumEntries)
      |> Array.sort
    CollectionAssert.AreEqual([| 0x08UL, 2; 0x10UL, 2 |], tables)

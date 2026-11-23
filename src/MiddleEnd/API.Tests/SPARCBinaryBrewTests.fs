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

namespace B2R2.MiddleEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Tests the recovery of SPARC binaries.
[<TestClass>]
type SPARCBinaryBrewTests() =
  /// Recovers the functions of the given SPARC V9 code, which starts at
  /// address zero with the entry of the binary.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    BinaryBrew(BinHandle.LoadRawImage(bytes, ISA "sparc64")).Functions

  /// Recovers the functions of elf_sparc64_so with get, at 0x6a8, made the
  /// given code, which has room for 23 words before .text ends.
  static let recoverPatchedGet (code: string list) =
    let bytes = readZippedBinary "elf_sparc64_so"
    (ByteArray.ofHexString(String.concat "" code)).CopyTo(bytes, 0x6a8)
    BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "sparc64")).Functions

  /// Recovers the functions of elf_sparc64_so with its symbol table hidden,
  /// whose type in the section header at 0x2e98 becomes SHT_NULL, so that
  /// only the dynamic symbols tell where functions start, as in a stripped
  /// binary, with get, at 0x6a8, made the given code, which has room for 23
  /// words, and the relocation that writes the address of pa at 0x3e40, the
  /// third of .rela.dyn, made to write the given address.
  static let recoverStrippedSoPointingTo (code: string list) (addr: uint64) =
    let bytes = readZippedBinary "elf_sparc64_so"
    (Array.zeroCreate<byte> 4).CopyTo(bytes, 0x2e9c)
    (ByteArray.ofHexString(String.concat "" code)).CopyTo(bytes, 0x6a8)
    let addend = System.BitConverter.GetBytes addr |> Array.rev
    addend.CopyTo(bytes, 0x410)
    BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "sparc64")).Functions

  /// Returns the entries of the given functions, in order.
  static let entriesOf (fns: FunctionCollection) =
    fns.Sequence |> Seq.map _.EntryPoint |> Seq.sort |> Seq.toArray

  /// Returns the addresses of the blocks of the function, in order.
  static let blocksOf (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.map (fun v -> v.VData.Internals.BlockAddress)
    |> Array.sort

  (* The delay slot of a call runs before the callee does, so the callee
     returns past it, to the instruction after the slot. *)
  [<TestMethod>]
  member _.``A call returns past its delay slot``() =
    let fns =
      recoverCode
        [ "40000004" (* call 0x10 *)
          "90102001" (* mov 1, %o0 *)
          "81c3e008" (* retl *)
          "01000000" (* nop *)
          "81c3e008" (* retl *)
          "01000000" (* nop *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0x8UL |], blocksOf fns[0x0UL])

  (* PIC code finds its GOT with a thunk that adds the address of the call,
     which the call links into %o7, to what the code puts in %l7 around the
     call. A table that the code addresses from the GOT is found only once the
     GOT is: here %l7 is 0x1ff8 + 0x8, and the table lies 0x1fa4 below it. *)
  [<TestMethod>]
  member _.``A thunk reads the PC that a table is addressed from``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "2f000007" (* 0x04: sethi %hi(0x1c00), %l7 *)
          "40000018" (* 0x08: call 0x68 *)
          "ae15e3f8" (* 0x0c: or %l7, 0x3f8, %l7 *)
          "80a62002" (* 0x10: cmp %i0, 2 *)
          "18400010" (* 0x14: bgu,pn %icc, 0x54 *)
          "01000000" (* 0x18: nop *)
          "03000007" (* 0x1c: sethi %hi(0x1c00), %g1 *)
          "821063a4" (* 0x20: or %g1, 0x3a4, %g1 *)
          "8225c001" (* 0x24: sub %l7, %g1, %g1 *)
          "b1362000" (* 0x28: srl %i0, 0, %i0 *)
          "b12e3002" (* 0x2c: sllx %i0, 2, %i0 *)
          "f0404018" (* 0x30: ldsw [%g1 + %i0], %i0 *)
          "81c04018" (* 0x34: jmp %g1 + %i0 *)
          "01000000" (* 0x38: nop *)
          "81c7e008" (* 0x3c: ret *)
          "91e8200a" (* 0x40: restore %g0, 10, %o0 *)
          "81c7e008" (* 0x44: ret *)
          "91e8200b" (* 0x48: restore %g0, 11, %o0 *)
          "81c7e008" (* 0x4c: ret *)
          "91e8200c" (* 0x50: restore %g0, 12, %o0 *)
          "81c7e008" (* 0x54: ret *)
          "91e82000" (* 0x58: restore %g0, 0, %o0 *)
          "ffffffe0" (* 0x5c: .word 0x3c - 0x5c *)
          "ffffffe8" (* 0x60: .word 0x44 - 0x5c *)
          "fffffff0" (* 0x64: .word 0x4c - 0x5c *)
          "81c3e008" (* 0x68: retl *)
          "ae03c017" (* 0x6c: add %o7, %l7, %l7 *) ]
    let tables =
      fns[0x0UL].JumpTables |> Array.map (fun t -> t.TableAddress, t.NumEntries)
    CollectionAssert.AreEqual([| (0x5cUL, 3) |], tables)

  (* A table whose entries a jump adds to their base, after extending them,
     may lie at a base that the code computes in more steps than the jump
     table analysis expands: here the code keeps the address that it computes
     from the GOT in its frame across a call, reloads it, and jumps to that
     base plus a sign-extended entry. *)
  [<TestMethod>]
  member _.``A table is read off a base that the data flow computes``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "2f000007" (* 0x04: sethi %hi(0x1c00), %l7 *)
          "4000001e" (* 0x08: call 0x80 *)
          "ae15e3f8" (* 0x0c: or %l7, 0x3f8, %l7 *)
          "05000007" (* 0x10: sethi %hi(0x1c00), %g2 *)
          "8418a394" (* 0x14: xor %g2, 0x394, %g2 *)
          "8225c002" (* 0x18: sub %l7, %g2, %g1 *)
          "c277a7f7" (* 0x1c: stx %g1, [%fp + 2039] *)
          "40000016" (* 0x20: call 0x78 *)
          "01000000" (* 0x24: nop *)
          "80a62002" (* 0x28: cmp %i0, 2 *)
          "1840000e" (* 0x2c: bgu,pn %icc, 0x64 *)
          "01000000" (* 0x30: nop *)
          "c85fa7f7" (* 0x34: ldx [%fp + 2039], %g4 *)
          "83362000" (* 0x38: srl %i0, 0, %g1 *)
          "83287002" (* 0x3c: sllx %g1, 2, %g1 *)
          "c2410001" (* 0x40: ldsw [%g4 + %g1], %g1 *)
          "81c10001" (* 0x44: jmp %g4 + %g1 *)
          "01000000" (* 0x48: nop *)
          "81c7e008" (* 0x4c: ret *)
          "91e8200a" (* 0x50: restore %g0, 10, %o0 *)
          "81c7e008" (* 0x54: ret *)
          "91e8200b" (* 0x58: restore %g0, 11, %o0 *)
          "81c7e008" (* 0x5c: ret *)
          "91e8200c" (* 0x60: restore %g0, 12, %o0 *)
          "81c7e008" (* 0x64: ret *)
          "91e82000" (* 0x68: restore %g0, 0, %o0 *)
          "ffffffe0" (* 0x6c: .word 0x4c - 0x6c *)
          "ffffffe8" (* 0x70: .word 0x54 - 0x6c *)
          "fffffff0" (* 0x74: .word 0x5c - 0x6c *)
          "81c3e008" (* 0x78: retl *)
          "01000000" (* 0x7c: nop *)
          "81c3e008" (* 0x80: retl *)
          "ae03c017" (* 0x84: add %o7, %l7, %l7 *) ]
    let tables =
      fns[0x0UL].JumpTables |> Array.map (fun t -> t.TableAddress, t.NumEntries)
    CollectionAssert.AreEqual([| (0x6cUL, 3) |], tables)

  (* A slot deep in a large frame lies at an offset too wide for an
     instruction, which the code builds with SETHI and XOR before it adds the
     offset to the frame pointer, so the code keeps a base there all the same
     as in any other slot. *)
  [<TestMethod>]
  member _.``A table is read off a base kept deep in a large frame``() =
    let fns =
      recoverCode
        [ "03000200" (* 0x00: sethi %hi(0x80000), %g1 *)
          "82187ee0" (* 0x04: xor %g1, -288, %g1 *)
          "9de38001" (* 0x08: save %sp, %g1, %sp *)
          "03000000" (* 0x0c: sethi %hi(0), %g1 *)
          "82106078" (* 0x10: or %g1, 0x78, %g1 *)
          "050001fe" (* 0x14: sethi %hi(0x7f800), %g2 *)
          "8418bfb7" (* 0x18: xor %g2, -73, %g2 *)
          "8400801e" (* 0x1c: add %g2, %fp, %g2 *)
          "c2708000" (* 0x20: stx %g1, [%g2] *)
          "40000018" (* 0x24: call 0x84 *)
          "01000000" (* 0x28: nop *)
          "80a62002" (* 0x2c: cmp %i0, 2 *)
          "18400010" (* 0x30: bgu,pn %icc, 0x70 *)
          "050001fe" (* 0x34: sethi %hi(0x7f800), %g2 *)
          "8418bfb7" (* 0x38: xor %g2, -73, %g2 *)
          "8400801e" (* 0x3c: add %g2, %fp, %g2 *)
          "c2588000" (* 0x40: ldx [%g2], %g1 *)
          "b1362000" (* 0x44: srl %i0, 0, %i0 *)
          "b12e3002" (* 0x48: sllx %i0, 2, %i0 *)
          "c2004018" (* 0x4c: ld [%g1 + %i0], %g1 *)
          "81c04000" (* 0x50: jmp %g1 *)
          "01000000" (* 0x54: nop *)
          "81c7e008" (* 0x58: ret *)
          "91e8200a" (* 0x5c: restore %g0, 10, %o0 *)
          "81c7e008" (* 0x60: ret *)
          "91e8200b" (* 0x64: restore %g0, 11, %o0 *)
          "81c7e008" (* 0x68: ret *)
          "91e8200c" (* 0x6c: restore %g0, 12, %o0 *)
          "81c7e008" (* 0x70: ret *)
          "91e82000" (* 0x74: restore %g0, 0, %o0 *)
          "00000058" (* 0x78: .word 0x58 *)
          "00000060" (* 0x7c: .word 0x60 *)
          "00000068" (* 0x80: .word 0x68 *)
          "81c3e008" (* 0x84: retl *)
          "01000000" (* 0x88: nop *) ]
    let tables =
      fns[0x0UL].JumpTables |> Array.map (fun t -> t.TableAddress, t.NumEntries)
    CollectionAssert.AreEqual([| (0x78UL, 3) |], tables)

  (* GCC writes the base of a table to a slot of the frame before a loop, and
     code that it shares reaches the loop along a way that skips the write,
     which never reaches the read of the slot as the code runs. A slot of the
     frame holds nothing on entry, so the slot holds the base at the read. *)
  [<TestMethod>]
  member _.``A table is read off a base that a way skips``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "4000001b" (* 0x04: call 0x70 *)
          "01000000" (* 0x08: nop *)
          "02ce4005" (* 0x0c: brz %i1, 0x20 *)
          "01000000" (* 0x10: nop *)
          "03000000" (* 0x14: sethi %hi(0), %g1 *)
          "82106064" (* 0x18: or %g1, 0x64, %g1 *)
          "c277a7f7" (* 0x1c: stx %g1, [%fp + 2039] *)
          "80a62002" (* 0x20: cmp %i0, 2 *)
          "1840000e" (* 0x24: bgu,pn %icc, 0x5c *)
          "01000000" (* 0x28: nop *)
          "c25fa7f7" (* 0x2c: ldx [%fp + 2039], %g1 *)
          "b1362000" (* 0x30: srl %i0, 0, %i0 *)
          "b12e3002" (* 0x34: sllx %i0, 2, %i0 *)
          "c2004018" (* 0x38: ld [%g1 + %i0], %g1 *)
          "81c04000" (* 0x3c: jmp %g1 *)
          "01000000" (* 0x40: nop *)
          "81c7e008" (* 0x44: ret *)
          "91e8200a" (* 0x48: restore %g0, 10, %o0 *)
          "81c7e008" (* 0x4c: ret *)
          "91e8200b" (* 0x50: restore %g0, 11, %o0 *)
          "81c7e008" (* 0x54: ret *)
          "91e8200c" (* 0x58: restore %g0, 12, %o0 *)
          "81c7e008" (* 0x5c: ret *)
          "91e82000" (* 0x60: restore %g0, 0, %o0 *)
          "00000044" (* 0x64: .word 0x44 *)
          "0000004c" (* 0x68: .word 0x4c *)
          "00000054" (* 0x6c: .word 0x54 *)
          "81c3e008" (* 0x70: retl *)
          "01000000" (* 0x74: nop *) ]
    let tables =
      fns[0x0UL].JumpTables |> Array.map (fun t -> t.TableAddress, t.NumEntries)
    CollectionAssert.AreEqual([| (0x64UL, 3) |], tables)

  (* GCC lays the tables of a translation unit next to each other, so the
     words past a table read as more of its entries, which send its jump into
     the code of the function all the same. The range check right before the
     jump says where the table ends. *)
  [<TestMethod>]
  member _.``A table ends where its range check says``() =
    let fns =
      recoverPatchedGet
        [ "80a22001" (* 0x6a8: cmp %o0, 1 *)
          "1840000e" (* 0x6ac: bgu,pn %icc, 0x6e4 *)
          "01000000" (* 0x6b0: nop *)
          "03000001" (* 0x6b4: sethi %hi(0x400), %g1 *)
          "821062cc" (* 0x6b8: or %g1, 0x2cc, %g1 *)
          "912a3002" (* 0x6bc: sllx %o0, 2, %o0 *)
          "d0404008" (* 0x6c0: ldsw [%g1 + %o0], %o0 *)
          "81c04008" (* 0x6c4: jmp %g1 + %o0 *)
          "01000000" (* 0x6c8: nop *)
          "00000010" (* 0x6cc: .word 0x6dc - 0x6cc *)
          "00000018" (* 0x6d0: .word 0x6e4 - 0x6cc *)
          "00000010" (* 0x6d4: an entry of the next table, 0x6dc here *)
          "ffff0000" (* 0x6d8: no entry *)
          "81c3e008" (* 0x6dc: retl *)
          "90102000" (* 0x6e0: clr %o0 *)
          "81c3e008" (* 0x6e4: retl *)
          "90102001" (* 0x6e8: mov 1, %o0 *) ]
    let entries = fns[0x6a8UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* GCC fills the delay slot of the branch of a range check with the last
     step of the index, so the check compares a value that the code computes
     the same way in another register, which bounds the index all the same. *)
  [<TestMethod>]
  member _.``A range check on a copy of the index ends its table``() =
    let fns =
      recoverPatchedGet
        [ "82023fff" (* 0x6a8: add %o0, -1, %g1 *)
          "840860ff" (* 0x6ac: and %g1, 0xff, %g2 *)
          "80a0a001" (* 0x6b0: cmp %g2, 1 *)
          "1840000e" (* 0x6b4: bgu,pn %icc, 0x6ec *)
          "820860ff" (* 0x6b8: and %g1, 0xff, %g1 *)
          "05000001" (* 0x6bc: sethi %hi(0x400), %g2 *)
          "8410a2d4" (* 0x6c0: or %g2, 0x2d4, %g2 *)
          "83287002" (* 0x6c4: sllx %g1, 2, %g1 *)
          "c2408001" (* 0x6c8: ldsw [%g2 + %g1], %g1 *)
          "81c08001" (* 0x6cc: jmp %g2 + %g1 *)
          "01000000" (* 0x6d0: nop *)
          "00000010" (* 0x6d4: .word 0x6e4 - 0x6d4 *)
          "00000018" (* 0x6d8: .word 0x6ec - 0x6d4 *)
          "00000010" (* 0x6dc: an entry of the next table, 0x6e4 here *)
          "ffff0000" (* 0x6e0: no entry *)
          "81c3e008" (* 0x6e4: retl *)
          "90102000" (* 0x6e8: clr %o0 *)
          "81c3e008" (* 0x6ec: retl *)
          "90102001" (* 0x6f0: mov 1, %o0 *) ]
    let entries = fns[0x6a8UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* The delay slot may also take the low word of the index past the check,
     which SRL does with a shift by zero, and the check bounds the value that
     the code adjusts before the check all the same. *)
  [<TestMethod>]
  member _.``A range check before the low word of the index ends its table``() =
    let fns =
      recoverPatchedGet
        [ "90023fff" (* 0x6a8: add %o0, -1, %o0 *)
          "80a22001" (* 0x6ac: cmp %o0, 1 *)
          "1840000e" (* 0x6b0: bgu,pn %icc, 0x6e8 *)
          "91322000" (* 0x6b4: srl %o0, 0, %o0 *)
          "03000001" (* 0x6b8: sethi %hi(0x400), %g1 *)
          "821062d0" (* 0x6bc: or %g1, 0x2d0, %g1 *)
          "912a3002" (* 0x6c0: sllx %o0, 2, %o0 *)
          "d0404008" (* 0x6c4: ldsw [%g1 + %o0], %o0 *)
          "81c04008" (* 0x6c8: jmp %g1 + %o0 *)
          "01000000" (* 0x6cc: nop *)
          "00000010" (* 0x6d0: .word 0x6e0 - 0x6d0 *)
          "00000018" (* 0x6d4: .word 0x6e8 - 0x6d0 *)
          "00000010" (* 0x6d8: an entry of the next table, 0x6e0 here *)
          "ffff0000" (* 0x6dc: no entry *)
          "81c3e008" (* 0x6e0: retl *)
          "90102000" (* 0x6e4: clr %o0 *)
          "81c3e008" (* 0x6e8: retl *)
          "90102001" (* 0x6ec: mov 1, %o0 *) ]
    let entries = fns[0x6a8UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* A jump that restores the window in its delay slot, as GCC calls a
     function as its tail, and a call that does, as clang does, hand the code
     they go to the return address of their caller, so a function starts
     there even where nothing else tells so, rather than more of main. *)
  [<TestMethod>]
  member _.``A transfer that restores the window calls its tail``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "80a62000" (* 0x04: cmp %i0, 0 *)
          "02480004" (* 0x08: be %icc, 0x18 *)
          "01000000" (* 0x0c: nop *)
          "10800004" (* 0x10: b 0x20 *)
          "81e80000" (* 0x14: restore *)
          "40000004" (* 0x18: call 0x28 *)
          "81e80000" (* 0x1c: restore *)
          "81c3e008" (* 0x20: retl *)
          "90102001" (* 0x24: mov 1, %o0 *)
          "81c3e008" (* 0x28: retl *)
          "90102002" (* 0x2c: mov 2, %o0 *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0x20UL; 0x28UL |], entriesOf fns)
    CollectionAssert.AreEqual([| 0x0UL; 0x10UL; 0x18UL |], blocksOf fns[0x0UL])

  (* A leaf f calls g as its tail with a call that moves a copy of %o7 back
     into %o7 in its delay slot, which GNU ld relaxes into a branch with a nop
     there, leaving the copy right above, so g returns to the caller of f,
     past h, which lies between them, and main goes on past its call to f. *)
  [<TestMethod>]
  member _.``A branch past a copy of the return address calls its tail``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "4000000a" (* 0x04: call 0x2c *)
          "01000000" (* 0x08: nop *)
          "40000004" (* 0x0c: call 0x1c *)
          "01000000" (* 0x10: nop *)
          "81c7e008" (* 0x14: ret *)
          "91e82001" (* 0x18: restore %g0, 1, %o0 *)
          "90102010" (* 0x1c: mov 16, %o0 *)
          "8213c000" (* 0x20: mov %o7, %g1 *)
          "10800004" (* 0x24: b 0x34 *)
          "01000000" (* 0x28: nop *)
          "81c3e008" (* 0x2c: retl *)
          "01000000" (* 0x30: nop *)
          "9de3bf50" (* 0x34: save %sp, -176, %sp *)
          "81c7e008" (* 0x38: ret *)
          "81e80000" (* 0x3c: restore *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0xcUL; 0x14UL |], blocksOf fns[0x0UL])

  (* Only a word of data leads to the function past get, which the loader
     writes, and the function turns the window first, as a function does. *)
  [<TestMethod>]
  member _.``Functions start where data points to``() =
    let fns =
      recoverStrippedSoPointingTo
        [ "81c3e008" (* 0x6a8: retl *)
          "01000000" (* 0x6ac: nop *)
          "9de3bf50" (* 0x6b0: save %sp, -176, %sp *)
          "81c7e008" (* 0x6b4: ret *)
          "81e80000" (* 0x6b8: restore *) ] 0x6b0UL
    CollectionAssert.Contains(entriesOf fns, 0x6b0UL)

  (* A word of data may name code that starts no function by chance, here
     code that get skips with a branch, right past which it jumps, as one way
     of an if-else, which the code above does not end. *)
  [<TestMethod>]
  member _.``No function starts where code above jumps right past``() =
    let fns =
      recoverStrippedSoPointingTo
        [ "10800003" (* 0x6a8: b 0x6b4 *)
          "90102001" (* 0x6ac: mov 1, %o0 *)
          "90102002" (* 0x6b0: mov 2, %o0 *)
          "81c3e008" (* 0x6b4: retl *)
          "01000000" (* 0x6b8: nop *) ] 0x6b0UL
    CollectionAssert.DoesNotContain(entriesOf fns, 0x6b0UL)

  (* clang gives back the room that it takes on the stack for a call to a
     function that never returns right past the call, where nothing runs, and
     no function starts by giving back room that it never took, though a
     word of data may name such code by chance. *)
  [<TestMethod>]
  member _.``No function starts by giving back stack it never took``() =
    let fns =
      recoverStrippedSoPointingTo
        [ "81c3e008" (* 0x6a8: retl *)
          "01000000" (* 0x6ac: nop *)
          "9c03a030" (* 0x6b0: add %sp, 0x30, %sp *)
          "81c3e008" (* 0x6b4: retl *)
          "01000000" (* 0x6b8: nop *) ] 0x6b0UL
    CollectionAssert.DoesNotContain(entriesOf fns, 0x6b0UL)

  (* Nothing leads to h, which lies past g, past two words of a jump table
     that GCC lays before the function that uses it, which read as ILLTRAP. *)
  [<TestMethod>]
  member _.``A function starts past another and what fills space``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "40000004" (* 0x04: call 0x14 *)
          "01000000" (* 0x08: nop *)
          "81c7e008" (* 0x0c: ret *)
          "81e80000" (* 0x10: restore *)
          "81c3e008" (* 0x14: retl *)
          "01000000" (* 0x18: nop *)
          "0000002c" (* 0x1c: .word 0x2c *)
          "00000034" (* 0x20: .word 0x34 *)
          "9de3bf50" (* 0x24: save %sp, -176, %sp *)
          "81c7e008" (* 0x28: ret *)
          "91e82001" (* 0x2c: restore %g0, 1, %o0 *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0x14UL; 0x24UL |], entriesOf fns)

  (* Nothing leads to h either, which converts a number first, rounding it as
     the floating-point state register that it receives tells. *)
  [<TestMethod>]
  member _.``A function starts past another where it rounds first``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "40000004" (* 0x04: call 0x14 *)
          "01000000" (* 0x08: nop *)
          "81c7e008" (* 0x0c: ret *)
          "81e80000" (* 0x10: restore *)
          "81c3e008" (* 0x14: retl *)
          "01000000" (* 0x18: nop *)
          "81a01100" (* 0x1c: fxtod %f0, %f0 *)
          "81c3e008" (* 0x20: retl *)
          "01000000" (* 0x24: nop *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0x14UL; 0x1cUL |], entriesOf fns)

  (* Nothing leads to h either, whose way past the call to k, which never
     returns, reads %l0 that only the other way writes, as no code above
     leaves anything in a local of the window that h turns to. *)
  [<TestMethod>]
  member _.``A function starts past another where a dead way reads a local``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "40000004" (* 0x04: call 0x14 *)
          "01000000" (* 0x08: nop *)
          "81c7e008" (* 0x0c: ret *)
          "81e80000" (* 0x10: restore *)
          "81c3e008" (* 0x14: retl *)
          "01000000" (* 0x18: nop *)
          "9de3bf50" (* 0x1c: save %sp, -176, %sp *)
          "02ce0004" (* 0x20: brz %i0, 0x30 *)
          "01000000" (* 0x24: nop *)
          "10800004" (* 0x28: b 0x38 *)
          "a0100000" (* 0x2c: clr %l0 *)
          "40000005" (* 0x30: call 0x44 *)
          "01000000" (* 0x34: nop *)
          "80a42000" (* 0x38: cmp %l0, 0 *)
          "81c7e008" (* 0x3c: ret *)
          "81e80000" (* 0x40: restore *)
          "91d02005" (* 0x44: ta 5 *) ]
    let expected = [| 0x0UL; 0x14UL; 0x1cUL; 0x44UL |]
    CollectionAssert.AreEqual(expected, entriesOf fns)

  (* Nothing leads to g either, which lies right past the call of f to k, a
     function of the binary that never returns, as clang lays a function that
     nothing calls past one that ends calling xalloc_die. *)
  [<TestMethod>]
  member _.``A function starts past a call that never returns``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "40000004" (* 0x04: call 0x14 *)
          "01000000" (* 0x08: nop *)
          "81c7e008" (* 0x0c: ret *)
          "81e80000" (* 0x10: restore *)
          "9de3bf50" (* 0x14: save %sp, -176, %sp *)
          "40000004" (* 0x18: call 0x28 *)
          "01000000" (* 0x1c: nop *)
          "81c3e008" (* 0x20: retl *)
          "90102001" (* 0x24: mov 1, %o0 *)
          "91d02005" (* 0x28: ta 5 *) ]
    let expected = [| 0x0UL; 0x14UL; 0x20UL; 0x28UL |]
    CollectionAssert.AreEqual(expected, entriesOf fns)

  (* Nothing leads to g and h either, which lie past code of f and g that
     nothing reaches, as GCC leaves a block that jumps back into a function,
     or a return, past the rest of it. *)
  [<TestMethod>]
  member _.``A function starts past dead code of another``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "40000004" (* 0x04: call 0x14 *)
          "01000000" (* 0x08: nop *)
          "81c7e008" (* 0x0c: ret *)
          "81e80000" (* 0x10: restore *)
          "9de3bf50" (* 0x14: save %sp, -176, %sp *)
          "81c7e008" (* 0x18: ret *)
          "91e82001" (* 0x1c: restore %g0, 1, %o0 *)
          "10bffffe" (* 0x20: b 0x18 *)
          "b0102002" (* 0x24: mov 2, %i0 *)
          "9de3bf50" (* 0x28: save %sp, -176, %sp *)
          "81c7e008" (* 0x2c: ret *)
          "81e80000" (* 0x30: restore *)
          "81cfe008" (* 0x34: return %i7 + 8 *)
          "01000000" (* 0x38: nop *)
          "9de3bf50" (* 0x3c: save %sp, -176, %sp *)
          "81c7e008" (* 0x40: ret *)
          "81e80000" (* 0x44: restore *) ]
    let expected = [| 0x0UL; 0x14UL; 0x28UL; 0x3cUL |]
    CollectionAssert.AreEqual(expected, entriesOf fns)

  (* GNU as pads a long way to an alignment with BA,a over the nops that fill
     it, which starts no function. *)
  [<TestMethod>]
  member _.``A branch over padding starts no function``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "40000004" (* 0x04: call 0x14 *)
          "01000000" (* 0x08: nop *)
          "81c7e008" (* 0x0c: ret *)
          "81e80000" (* 0x10: restore *)
          "81c3e008" (* 0x14: retl *)
          "01000000" (* 0x18: nop *)
          "30800003" (* 0x1c: b,a 0x28 *)
          "01000000" (* 0x20: nop *)
          "01000000" (* 0x24: nop *)
          "9de3bf50" (* 0x28: save %sp, -176, %sp *)
          "81c7e008" (* 0x2c: ret *)
          "91e82001" (* 0x30: restore %g0, 1, %o0 *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0x14UL; 0x28UL |], entriesOf fns)

  (* Code that a compiler leaves past the rest of a function, which nothing
     reaches, jumps back into the function, rather than starts another. *)
  [<TestMethod>]
  member _.``Code that jumps back into a function starts none``() =
    let fns =
      recoverCode
        [ "80a22000" (* 0x00: cmp %o0, 0 *)
          "02480004" (* 0x04: be %icc, 0x14 *)
          "01000000" (* 0x08: nop *)
          "81c3e008" (* 0x0c: retl *)
          "90102001" (* 0x10: mov 1, %o0 *)
          "81c3e008" (* 0x14: retl *)
          "90102002" (* 0x18: mov 2, %o0 *)
          "10bffffe" (* 0x1c: b 0x14 *)
          "90102003" (* 0x20: mov 3, %o0 *) ]
    CollectionAssert.AreEqual([| 0x0UL |], entriesOf fns)

  (* main passes the address of f to g, which is all that leads to f, and f
     turns the window, as a function does. The word right above f decodes as
     nothing, so no code runs into f, nor does f lie past what code fills. *)
  [<TestMethod>]
  member _.``A function starts where code passes its address``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "11000000" (* 0x04: sethi %hi(0x24), %o0 *)
          "40000004" (* 0x08: call 0x18 *)
          "90122024" (* 0x0c: or %o0, 0x24, %o0 *)
          "81c7e008" (* 0x10: ret *)
          "81e80000" (* 0x14: restore *)
          "81c3e008" (* 0x18: retl *)
          "01000000" (* 0x1c: nop *)
          "ffffffff" (* 0x20: no instruction *)
          "9de3bf50" (* 0x24: save %sp, -176, %sp *)
          "81c7e008" (* 0x28: ret *)
          "81e80000" (* 0x2c: restore *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0x18UL; 0x24UL |], entriesOf fns)

  (* main passes g two addresses of code that reads nothing and returns at
     once, as a leaf function does: a block that g jumps to, which starts no
     function, and h, which nothing else leads to. A number may name code by
     chance in a binary that stays where it is linked, so such an address
     starts a function only once the recovery has built every function that
     anything else leads to, and only where none of them jumps. *)
  [<TestMethod>]
  member _.``A leaf starts where code passes its address at last``() =
    let fns =
      recoverCode
        [ "9de3bf50" (* 0x00: save %sp, -176, %sp *)
          "11000000" (* 0x04: sethi %hi(0x34), %o0 *)
          "90122034" (* 0x08: or %o0, 0x34, %o0 *)
          "13000000" (* 0x0c: sethi %hi(0x48), %o1 *)
          "40000004" (* 0x10: call 0x20 *)
          "92126048" (* 0x14: or %o1, 0x48, %o1 *)
          "81c7e008" (* 0x18: ret *)
          "81e80000" (* 0x1c: restore *)
          "80a22000" (* 0x20: cmp %o0, 0 *)
          "02480004" (* 0x24: be %icc, 0x34 *)
          "01000000" (* 0x28: nop *)
          "81c3e008" (* 0x2c: retl *)
          "01000000" (* 0x30: nop *)
          "81c3e008" (* 0x34: retl *)
          "90102001" (* 0x38: mov 1, %o0 *)
          "ffffffff" (* 0x3c: no instruction *)
          "81c3e008" (* 0x40: retl *)
          "01000000" (* 0x44: nop *)
          "81c3e008" (* 0x48: retl *)
          "90102002" (* 0x4c: mov 2, %o0 *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0x20UL; 0x48UL |], entriesOf fns)

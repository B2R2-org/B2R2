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

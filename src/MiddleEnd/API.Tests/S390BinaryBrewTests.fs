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
open B2R2.ABI
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowGraph

/// Tests the recovery of S390 binaries.
[<TestClass>]
type S390BinaryBrewTests() =
  /// Recovers the functions of the given z/Architecture code, which starts at
  /// address zero with the entry of the binary.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    let isa = ISA(Architecture.S390, Endian.Big, WordSize.Bit64)
    BinaryBrew(BinHandle.LoadRawImage(bytes, isa)).Functions

  /// Recovers the functions of elf_s390x with main, at 0x810, made the given
  /// code, which has room for 44 halfwords before .text ends.
  static let recoverPatchedMain (code: string list) =
    let bytes = readZippedBinary "elf_s390x"
    (ByteArray.ofHexString(String.concat "" code)).CopyTo(bytes, 0x810)
    let isa = ISA(Architecture.S390, Endian.Big, WordSize.Bit64)
    BinaryBrew(BinHandle.LoadFileBytes(bytes, isa)).Functions

  /// Returns where the functions that the recovery finds in elf_s390x start,
  /// once each of the given hex strings is written at its offset. Its symbol
  /// table is hidden, so that only its call frame information, its entry and
  /// its data tell of functions, and frame_dummy returns right away, so that
  /// nothing leads to register_tm_clones, at 0x760.
  static let findEntries (patches: (int * string) list) =
    let bytes = readZippedBinary "elf_s390x"
    let patch (offset: int, hex: string) =
      (ByteArray.ofHexString hex).CopyTo(bytes, offset)
    patch (0x1f64, "00000000") (* the type of .symtab: SHT_NULL *)
    patch (0x800, "07fe") (* frame_dummy: br %r14 *)
    List.iter patch patches
    let isa = ISA(Architecture.S390, Endian.Big, WordSize.Bit64)
    let hdl = BinHandle.LoadFileBytes(bytes, isa)
    Seq.toArray (BinaryBrew hdl).Functions.Addresses

  /// Returns the patches that make the word of .data that a relocation sets,
  /// at 0x2008, point to the given address: the addend of the relocation and
  /// the word itself.
  static let relocatedPointerTo (addr: uint64) =
    let hex = addr.ToString("x16")
    [ 0x518, hex; 0x1008, hex ]

  /// Returns the patches that make the binary an executable that stays where
  /// it is linked, whose .rodata holds the given words, one after another, as
  /// it takes in the bytes of .eh_frame_hdr past its own.
  static let readOnlyWords (words: uint64 list) =
    let wordPatch i (w: uint64) = 0x898 + 8 * i, w.ToString("x16")
    [ 0x10, "0002" (* e_type: ET_EXEC *)
      0x1d00, "0000000000000024" (* the size of .rodata *) ]
    @ List.mapi wordPatch words

  (* gnulib's error exits unless its status is zero, and GCC returns from it
     through R4, which it reloads the saved R14 into, as no S390 instruction
     returns by itself. *)
  [<TestMethod>]
  member _.``A return through the reloaded link returns conditionally``() =
    let fns =
      recoverCode
        [ "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
          "a7fbff60" (* aghi %r15,-160 *)
          "ec280006007c" (* 0x0a: cgije %r2,0,0x16 *)
          "c0e50000000a" (* 0x10: brasl %r14,0x24 *)
          "e340f1100004" (* 0x16: lg %r4,272(%r15) *)
          "ebeff1100004" (* lmg %r14,%r15,272(%r15) *)
          "07f4" (* 0x22: br %r4 *)
          "a7f40000" (* 0x24: j 0x24 *) ]
    let r2 = S390.Register.toRegID S390.Register.R2
    let expected = ConditionalNoRet(ArgLocation.Reg r2)
    Assert.AreEqual<NonReturningStatus>(expected, fns[0x0UL].NoRet)

  (* A jump through a pointer that memory holds is no return, even where the
     function reloads its saved R14 as it leaves, as the caller left no such
     address there. *)
  [<TestMethod>]
  member _.``A jump through a loaded pointer returns to nobody``() =
    let fns =
      recoverCode
        [ "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
          "a7fbff60" (* aghi %r15,-160 *)
          "ec280006007c" (* 0x0a: cgije %r2,0,0x16 *)
          "c0e50000000a" (* 0x10: brasl %r14,0x24 *)
          "e34030000004" (* 0x16: lg %r4,0(%r3) *)
          "ebeff1100004" (* lmg %r14,%r15,272(%r15) *)
          "07f4" (* 0x22: br %r4 *)
          "a7f40000" (* 0x24: j 0x24 *) ]
    Assert.AreEqual<NonReturningStatus>(NotNoRet, fns[0x0UL].NoRet)

  (* gnulib's error_tail tests its status with LTGR, which sets the condition
     code to zero where the status is, and JE takes that code. *)
  [<TestMethod>]
  member _.``A status that the condition code tests decides the return``() =
    let fns =
      recoverCode
        [ "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
          "a7fbff60" (* aghi %r15,-160 *)
          "b9020022" (* ltgr %r2,%r2 *)
          "a7840005" (* 0x0e: je 0x18 *)
          "c0e50000000a" (* 0x12: brasl %r14,0x26 *)
          "e340f1100004" (* 0x18: lg %r4,272(%r15) *)
          "ebeff1100004" (* lmg %r14,%r15,272(%r15) *)
          "07f4" (* 0x24: br %r4 *)
          "a7f40000" (* 0x26: j 0x26 *) ]
    let r2 = S390.Register.toRegID S390.Register.R2
    let expected = ConditionalNoRet(ArgLocation.Reg r2)
    Assert.AreEqual<NonReturningStatus>(expected, fns[0x0UL].NoRet)

  (* Compilers lay the tables of a function next to each other, so the words
     past a table read as more of its entries, which send its jump into the
     code of the function all the same. The range check right before the jump
     says where the table ends. *)
  [<TestMethod>]
  member _.``A table ends where its range check says``() =
    let fns =
      recoverPatchedMain
        [ "ec220023017d" (* clgijh %r2,1,0x856 *)
          "eb120003000d" (* sllg %r1,%r2,3 *)
          "c0300000000a" (* larl %r3,0x830 *)
          "e31130000004" (* lg %r1,0(%r1,%r3) *)
          "47f13000" (* b 0(%r1,%r3) *)
          "07070707" (* nopr %r7; nopr %r7 *)
          "0000000000000020" (* 0x830: .quad 0x850 - 0x830 *)
          "0000000000000026" (* .quad 0x856 - 0x830 *)
          "0000000000000020" (* an entry of the next table, 0x850 here *)
          "ffff0000ffff0000" (* no entry *)
          "a729000007fe" (* 0x850: lghi %r2,0; br %r14 *)
          "a729000107fe" (* 0x856: lghi %r2,1; br %r14 *) ]
    let entries = fns[0x810UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* The first entry sends the jump below main, to the return of
     __do_global_dtors_aux, where no switch of main lays a case, as clang
     indexes a table of callbacks that way to call one as its tail. *)
  [<TestMethod>]
  member _.``A table whose first entry leads below its function is none``() =
    let fns =
      recoverPatchedMain
        [ "ec220023017d" (* clgijh %r2,1,0x856 *)
          "eb120003000d" (* sllg %r1,%r2,3 *)
          "c0300000000a" (* larl %r3,0x830 *)
          "e31130000004" (* lg %r1,0(%r1,%r3) *)
          "47f13000" (* b 0(%r1,%r3) *)
          "07070707" (* nopr %r7; nopr %r7 *)
          "ffffffffffffffc0" (* 0x830: .quad 0x7f0 - 0x830 *)
          "0000000000000026" (* .quad 0x856 - 0x830 *)
          "ffff0000ffff0000" (* no entry *)
          "ffff0000ffff0000" (* no entry *)
          "a729000007fe" (* 0x850: lghi %r2,0; br %r14 *)
          "a729000107fe" (* 0x856: lghi %r2,1; br %r14 *) ]
    Assert.AreEqual<int>(0, fns[0x810UL].JumpTables.Length)

  (* Only the relocated word of .data leads to register_tm_clones, which no
     code runs into, as nops pad the code above up to it. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A relocated pointer to code below padding is a function``() =
    let entries = findEntries (relocatedPointerTo 0x760UL)
    CollectionAssert.Contains(entries, 0x760UL)

  (* The pointer names the middle of register_tm_clones, which saves registers
     first this time, as a function sets up its frame. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A relocated pointer to code saving registers is a function``() =
    let code = 0x786, "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
    let entries = findEntries (code :: relocatedPointerTo 0x786UL)
    CollectionAssert.Contains(entries, 0x786UL)

  (* The code that the pointer names, past the return of deregister_tm_clones,
     copies R1, which holds nothing as a function starts. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to code reading what code above left is no function``() =
    let code = 0x752, "b904002107fe" (* lgr %r2,%r1; br %r14 *)
    let entries = findEntries (code :: relocatedPointerTo 0x752UL)
    CollectionAssert.DoesNotContain(entries, 0x752UL)

  (* The code past the return of deregister_tm_clones changes R12 this time,
     which a function saves first, for its caller. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to code changing an unsaved register is no function``() =
    let code = 0x752, "b90400c207fe" (* lgr %r12,%r2; br %r14 *)
    let entries = findEntries (code :: relocatedPointerTo 0x752UL)
    CollectionAssert.DoesNotContain(entries, 0x752UL)

  (* The pointer names the middle of register_tm_clones, which the shift above
     runs into, with no frame set up. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to code that code above runs into is no function``() =
    let entries = findEntries (relocatedPointerTo 0x786UL)
    CollectionAssert.DoesNotContain(entries, 0x786UL)

  (* As an executable that stays where it is linked, the binary relocates
     nothing, and .data holds the address of register_tm_clones as it is. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A code address in fixed-base data is a pointer``() =
    let entries = findEntries [ 0x10, "0002"; 0x1008, "0000000000000760" ]
    CollectionAssert.Contains(entries, 0x760UL)

  (* .rodata holds the addresses of register_tm_clones and
     __do_global_dtors_aux, one after the other, as a table of callbacks
     does. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A table of callbacks in read-only data holds functions``() =
    let entries = findEntries (readOnlyWords [ 0x760UL; 0x7b0UL ])
    CollectionAssert.Contains(entries, 0x760UL)

  (* The second word names code that copies R1 this time, as the entry of a
     jump table names code that the code before the jump leads into, and the
     words of such a table name no functions. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A jump table in read-only data holds no functions``() =
    let code = 0x752, "b904002107fe" (* lgr %r2,%r1; br %r14 *)
    let entries = findEntries (code :: readOnlyWords [ 0x760UL; 0x752UL ])
    CollectionAssert.DoesNotContain(entries, 0x760UL)

  (* The pointer names code in main that returns right below a call, as the
     return of a case does that a jump table of GCC names, while the call
     frame information gives main the code from 0x810 to 0x862. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer into a function that a frame covers is no function``() =
    let code = 0x84e, "a729000007fe" (* lghi %r2,0; br %r14 *)
    let entries = findEntries (code :: relocatedPointerTo 0x84eUL)
    CollectionAssert.DoesNotContain(entries, 0x84eUL)

  (* main loads the address of register_tm_clones with LARL this time, rather
     than that of its string, as code does that passes a callback. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A code address that recovered code takes is a function``() =
    let code = 0x824, "c030ffffff9e" (* larl %r3,0x760 *)
    let entries = findEntries [ code ]
    CollectionAssert.Contains(entries, 0x760UL)

  (* The address that main takes lies in the middle of register_tm_clones,
     which the shift above runs into. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A taken address that code above runs into is no function``() =
    let code = 0x824, "c030ffffffb1" (* larl %r3,0x786 *)
    let entries = findEntries [ code ]
    CollectionAssert.DoesNotContain(entries, 0x786UL)

  (* frame_dummy jumps back to register_tm_clones, as it calls that as its
     tail, and only that jump leads there. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A function that a jump leaves for is a function``() =
    let code = 0x800, "c0f4ffffffb0" (* jg 0x760 *)
    let entries = findEntries [ code ]
    CollectionAssert.Contains(entries, 0x760UL)

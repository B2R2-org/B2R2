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

  /// Returns where the indirect jumps of the function go, in order.
  static let indirectJumpTargetsOf (fn: Function) =
    fn.CFG.Edges
    |> Array.filter (fun e -> e.Label = IndirectJmpEdge)
    |> Array.map (fun e -> e.Second.VData.Internals.BlockAddress)
    |> Array.sort

  /// Recovers the functions of elf_s390x once each of the given hex strings is
  /// written at its offset. Its symbol table is hidden, so that only its call
  /// frame information, its entry and its data tell of functions, frame_dummy
  /// returns right away, and __do_global_dtors_aux calls nothing, so that
  /// nothing leads to register_tm_clones, at 0x760, nor to
  /// deregister_tm_clones, at 0x730, past which code resumes there.
  static let recoverPatched (patches: (int * string) list) =
    let bytes = readZippedBinary "elf_s390x"
    let patch (offset: int, hex: string) =
      (ByteArray.ofHexString hex).CopyTo(bytes, offset)
    patch (0x1f64, "00000000") (* the type of .symtab: SHT_NULL *)
    patch (0x800, "07fe") (* frame_dummy: br %r14 *)
    patch (0x7e6, "c00400000000") (* brasl %r14,0x730 -> brcl 0,0x7e6 *)
    List.iter patch patches
    let isa = ISA(Architecture.S390, Endian.Big, WordSize.Bit64)
    BinaryBrew(BinHandle.LoadFileBytes(bytes, isa)).Functions

  /// Returns where the functions that the recovery finds in elf_s390x start,
  /// once each of the given hex strings is written at its offset, as
  /// recoverPatched recovers them.
  static let findEntries patches =
    Seq.toArray (recoverPatched patches).Addresses

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

  (* clang's error_tail branches to exit where a compare finds its status low
     or high, which is where it is not zero. *)
  [<TestMethod>]
  member _.``A status that a compare finds low or high decides the return``() =
    let fns =
      recoverCode
        [ "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
          "a7fbff60" (* aghi %r15,-160 *)
          "ec26000a007e" (* 0x0a: cijlh %r2,0,0x1e *)
          "e340f1100004" (* 0x10: lg %r4,272(%r15) *)
          "ebeff1100004" (* lmg %r14,%r15,272(%r15) *)
          "07f4" (* 0x1c: br %r4 *)
          "c0e500000003" (* 0x1e: brasl %r14,0x24 *)
          "a7f40000" (* 0x24: j 0x24 *) ]
    let r2 = S390.Register.toRegID S390.Register.R2
    let expected = ConditionalNoRet(ArgLocation.Reg r2)
    Assert.AreEqual<NonReturningStatus>(expected, fns[0x0UL].NoRet)

  (* The function passes error_tail a status that it reads, and a function that
     saves R14 lies right past the call, which tells that the call never
     returns there, as the call leaves in R14 what it returns to. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A call right before code that saves the link never returns``() =
    let fns =
      recoverCode
        [ "e32030000014" (* lgf %r2,0(%r3) *)
          "c0e50000000d" (* brasl %r14,0x20 *)
          "ebeff0700024" (* 0x0c: stmg %r14,%r15,112(%r15) *)
          "a7290000" (* lghi %r2,0 *)
          "ebeff0700004" (* lmg %r14,%r15,112(%r15) *)
          "07fe" (* br %r14 *)
          "0707" (* nopr %r7 *)
          "ebeff0700024" (* 0x20: stmg %r14,%r15,112(%r15) *)
          "a7fbff60" (* aghi %r15,-160 *)
          "ec26000a007e" (* cijlh %r2,0,0x3e *)
          "e340f1100004" (* lg %r4,272(%r15) *)
          "ebeff1100004" (* lmg %r14,%r15,272(%r15) *)
          "07f4" (* br %r4 *)
          "c0e500000003" (* 0x3e: brasl %r14,0x44 *)
          "a7f40000" (* 0x44: j 0x44 *) ]
    Assert.AreEqual<NonReturningStatus>(NoRet, fns[0x0UL].NoRet)
    CollectionAssert.Contains(Seq.toArray fns.Addresses, 0xcUL)

  (* The function branches past the function that it calls, which it learns
     starts there only once it has taken in the code past it, as a function
     does that takes in the code of the next one before that one is known. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A function leaves out code past the function it calls``() =
    let fns =
      recoverCode
        [ "ec280008007c" (* cgije %r2,0,0x10 *)
          "c0e500000004" (* 0x06: brasl %r14,0x0e *)
          "07fe" (* 0x0c: br %r14 *)
          "07fe" (* 0x0e: br %r14 *)
          "07f3" (* 0x10: br %r3 *) ]
    let blocks =
      fns[0x0UL].CFG.Vertices
      |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
      |> Array.map _.VData.Internals.BlockAddress
      |> Array.sort
    CollectionAssert.AreEqual([| 0x0UL; 0x6UL; 0xcUL |], blocks)

  (* _init and _fini of 31-bit glibc branch over a pool of literals with
     BRAS, which leaves the address of the pool in R13 rather than an address
     to return to in R14, the link register of the calling convention. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A branch over literals that saves their address calls nothing``() =
    let fns =
      recoverCode
        [ "a7d50004" (* bras %r13,0x08 *)
          "00048800" (* .long 0x00048800 *)
          "58c0d000" (* 0x08: l %r12,0(%r13) *)
          "1acd" (* ar %r12,%r13 *)
          "07fe" (* br %r14 *) ]
    CollectionAssert.AreEqual([| 0x0UL |], Seq.toArray fns.Addresses)

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

  (* The second entry sends the jump to the next function, which the function
     takes in as its own code until the case that the third entry sends the
     jump to calls it, as clang lays the label of an unreachable default where
     the next function starts. The code taken in then lies past the next
     function, which tells nothing wrong of the entry. *)
  [<TestMethod>]
  member _.``A table to a function found later keeps its entries``() =
    let fns =
      recoverPatchedMain
        [ "ec22001c027d" (* clgijh %r2,2,0x848 *)
          "eb120003000d" (* sllg %r1,%r2,3 *)
          "c0300000000a" (* larl %r3,0x830 *)
          "e31130000004" (* lg %r1,0(%r1,%r3) *)
          "47f13000" (* b 0(%r1,%r3) *)
          "07070707" (* nopr %r7; nopr %r7 *)
          "0000000000000018" (* 0x830: .quad 0x848 - 0x830 *)
          "0000000000000030" (* .quad 0x860 - 0x830 *)
          "000000000000001e" (* .quad 0x84e - 0x830 *)
          "a729000007fe" (* 0x848: lghi %r2,0; br %r14 *)
          "c0e500000009" (* 0x84e: brasl %r14,0x860 *)
          "a729000107fe" (* lghi %r2,1; br %r14 *)
          String.replicate 3 "0707" (* nopr %r7 *)
          "a729000207fe" (* 0x860: lghi %r2,2; br %r14 *) ]
    let entries = fns[0x810UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 3 |], entries)

  (* The first entry sends the jump to code that jumps to the next function,
     which the function takes in as its own code until the case that the third
     entry sends the jump to calls it, as clang lays a function that only a
     jump leads to right past the one that jumps to it. The code taken in then
     lies past the next function, which tells nothing wrong of the entry. *)
  [<TestMethod>]
  member _.``A table to a jump to a function found later keeps its entries``() =
    let fns =
      recoverPatchedMain
        [ "ec22001e027d" (* clgijh %r2,2,0x84c *)
          "eb120003000d" (* sllg %r1,%r2,3 *)
          "c0300000000a" (* larl %r3,0x830 *)
          "e31130000004" (* lg %r1,0(%r1,%r3) *)
          "47f13000" (* b 0(%r1,%r3) *)
          "07070707" (* nopr %r7; nopr %r7 *)
          "0000000000000018" (* 0x830: .quad 0x848 - 0x830 *)
          "000000000000001c" (* .quad 0x84c - 0x830 *)
          "0000000000000022" (* .quad 0x852 - 0x830 *)
          "a7f4000c" (* 0x848: j 0x860 *)
          "a729000007fe" (* 0x84c: lghi %r2,0; br %r14 *)
          "c0e500000007" (* 0x852: brasl %r14,0x860 *)
          "a729000107fe" (* lghi %r2,1; br %r14 *)
          "0707" (* nopr %r7 *)
          "a729000207fe" (* 0x860: lghi %r2,2; br %r14 *) ]
    let entries = fns[0x810UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 3 |], entries)

  (* The range check bounds the value before the shift that takes its top
     bits as the index, as ESA/390 code switches over the top bits of a byte,
     so it admits two entries, while the next table follows right after. *)
  [<TestMethod>]
  member _.``A range check before a shift of the index ends a table``() =
    let fns =
      recoverPatchedMain
        [ "ec2200277f7d" (* clgijh %r2,127,0x85e *)
          "eb120006000c" (* srlg %r1,%r2,6 *)
          "eb110003000d" (* sllg %r1,%r1,3 *)
          "c0300000000b" (* larl %r3,0x838 *)
          "e31130000004" (* lg %r1,0(%r1,%r3) *)
          "47f13000" (* b 0(%r1,%r3) *)
          "070707070707" (* nopr %r7; nopr %r7; nopr %r7 *)
          "0000000000000020" (* 0x838: .quad 0x858 - 0x838 *)
          "0000000000000026" (* .quad 0x85e - 0x838 *)
          "0000000000000020" (* an entry of the next table, 0x858 here *)
          "ffff0000ffff0000" (* no entry *)
          "a729000007fe" (* 0x858: lghi %r2,0; br %r14 *)
          "a729000107fe" (* 0x85e: lghi %r2,1; br %r14 *) ]
    let entries = fns[0x810UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* The mask that takes a field of a value as the index scales it as well,
     as ESA/390 code adds (x >> 20) & 12 to a table of words, so it lets the
     index select four entries, while the next table follows right after. *)
  [<TestMethod>]
  member _.``A mask that scales the index ends a table``() =
    let fns =
      recoverPatchedMain
        [ "eb120004000c" (* srlg %r1,%r2,4 *)
          "a7390018" (* lghi %r3,24 *)
          "b9800013" (* ngr %r1,%r3 *)
          "c03000000009" (* larl %r3,0x830 *)
          "e31130000004" (* lg %r1,0(%r1,%r3) *)
          "47f13000" (* b 0(%r1,%r3) *)
          "0707" (* nopr %r7 *)
          "0000000000000028" (* 0x830: .quad 0x858 - 0x830 *)
          "000000000000002e" (* .quad 0x85e - 0x830 *)
          "0000000000000028" (* .quad 0x858 - 0x830 *)
          "000000000000002e" (* .quad 0x85e - 0x830 *)
          "0000000000000028" (* an entry of the next table, 0x858 here *)
          "a729000007fe" (* 0x858: lghi %r2,0; br %r14 *)
          "a729000107fe" (* 0x85e: lghi %r2,1; br %r14 *) ]
    let entries = fns[0x810UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 4 |], entries)

  (* clang lays the template that EXRL runs past the code of its function,
     where the label of an unreachable default lands, so the entries of the
     cases that never come send the jump to the template. They are holes. *)
  [<TestMethod>]
  member _.``A table entry to a template that EXRL runs is a hole``() =
    let fns =
      recoverPatchedMain
        [ "c64000000028" (* exrl %r4,0x860 *)
          "ec220021037d" (* clgijh %r2,3,0x858 *)
          "eb120003000d" (* sllg %r1,%r2,3 *)
          "c0300000000b" (* larl %r3,0x838 *)
          "e31130000004" (* lg %r1,0(%r1,%r3) *)
          "47f13000" (* b 0(%r1,%r3) *)
          "070707070707" (* nopr %r7; nopr %r7; nopr %r7 *)
          "0000000000000020" (* 0x838: .quad 0x858 - 0x838 *)
          "0000000000000028" (* .quad 0x860 - 0x838, a hole *)
          "0000000000000022" (* .quad 0x85a - 0x838 *)
          "0000000000000028" (* .quad 0x860 - 0x838, a hole *)
          "07fe" (* 0x858: br %r14 *)
          "a729000107fe" (* 0x85a: lghi %r2,1; br %r14 *)
          "d20020003000" (* 0x860: mvc 0(1,%r2),0(%r3) *) ]
    let entries = fns[0x810UL].JumpTables |> Array.map _.NumEntries
    let targets = indirectJumpTargetsOf fns[0x810UL]
    CollectionAssert.AreEqual([| 4 |], entries)
    CollectionAssert.AreEqual([| 0x858UL; 0x85aUL |], targets)

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

  (* register_tm_clones calls a function that never returns this time, which
     no name tells, as it calls abort as its tail, and past the call lies a
     template that EXRL runs, which reads what no code sets, as clang lays the
     templates of a function past the code of the next one. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A template past a call that never returns reads nothing``() =
    let code =
      [ 0x760, "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
        0x766, "c0e500000006" (* brasl %r14,0x772 *)
        0x76c, "d2002000c000" (* mvc 0(1,%r2),0(%r12) *)
        0x772, "c0f4ffffffa3" (* jg 0x6b8: abort@plt *) ]
    let entries = findEntries (code @ relocatedPointerTo 0x760UL)
    CollectionAssert.Contains(entries, 0x760UL)

  (* register_tm_clones calls abort on one way this time, past which lies a
     block that reads R13, which the other way sets before it jumps there, as
     a compiler lays a block that a branch leads to past a call that never
     returns. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A block past a call to abort reads what its branch sets``() =
    let code =
      [ 0x760, "ebdff0680024" (* stmg %r13,%r15,104(%r15) *)
        0x766, "a7fbff60" (* aghi %r15,-160 *)
        0x76a, "ec260007007e" (* cijne %r2,0,0x778 *)
        0x770, "b90400d3" (* lgr %r13,%r3 *)
        0x774, "a7f40005" (* j 0x77e *)
        0x778, "c0e5ffffffa0" (* brasl %r14,0x6b8: abort@plt *)
        0x77e, "b904002d" (* lgr %r2,%r13 *)
        0x782, "ebdff1080004" (* lmg %r13,%r15,264(%r15) *)
        0x788, "07fe" (* br %r14 *) ]
    let entries = findEntries (code @ relocatedPointerTo 0x760UL)
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

  (* The code that the pointer names, past the return of deregister_tm_clones,
     tests its argument and inserts the condition code into R1 with IPM,
     which keeps the rest of R1 as it is, as clang does to turn a comparison
     into a value. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to code inserting the condition code is a function``() =
    let hex =
      "b9020022" (* ltgr %r2,%r2 *)
      + "b2220010" (* ipm %r1 *)
      + "b9140021" (* lgfr %r2,%r1 *)
      + "07fe" (* br %r14 *)
    let entries = findEntries ((0x752, hex) :: relocatedPointerTo 0x752UL)
    CollectionAssert.Contains(entries, 0x752UL)

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

  (* The pointer names the nops that pad the code above up to
     register_tm_clones, as halfwords of data next to each other do that read
     as a word. No function starts with the nops that pad functions apart. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to the padding between functions is no function``() =
    let entries = findEntries (relocatedPointerTo 0x75cUL)
    CollectionAssert.DoesNotContain(entries, 0x75cUL)

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

  (* deregister_tm_clones jumps ahead to register_tm_clones this time, which
     starts by saving R14 and R15, before the next function that the recovery
     knows, as clang lays a function that only jumps lead to right past the one
     that jumps to it. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code saving the link that a jump leads to is a function``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x730, "c0f400000018" (* jg 0x760 *)
          0x760, "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
          0x766, "ebeff0700004" (* lmg %r14,%r15,112(%r15) *)
          0x76c, "07fe" (* br %r14 *) ]
    CollectionAssert.Contains(entries, 0x760UL)

  (* deregister_tm_clones branches to the same code on a condition before it
     jumps there, so the code is its own. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code saving the link that a branch reaches too is no function``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x730, "ec280018007c" (* cgije %r2,0,0x760 *)
          0x736, "c0f400000015" (* jg 0x760 *)
          0x760, "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
          0x766, "ebeff0700004" (* lmg %r14,%r15,112(%r15) *)
          0x76c, "07fe" (* br %r14 *) ]
    CollectionAssert.DoesNotContain(entries, 0x760UL)

  (* deregister_tm_clones saves R14 and R15 past a return on a condition this
     time, which runs into the saving otherwise, and jumps back there from
     below, as GCC does that saves them only once it has to. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code saving the link that code above runs into is no function``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x730, "b9020022" (* ltgr %r2,%r2 *)
          0x734, "a784000a" (* je 0x748 *)
          0x738, "077e" (* bner %r14 *)
          0x73a, "ebeff0700024" (* stmg %r14,%r15,112(%r15) *)
          0x740, "ebeff0700004" (* lmg %r14,%r15,112(%r15) *)
          0x746, "07fe" (* br %r14 *)
          0x748, "a7f4fff9" (* j 0x73a *)
          0x74c, "07070707" (* nopr %r7; nopr %r7 *) ]
    CollectionAssert.DoesNotContain(entries, 0x73aUL)

  (* __do_global_dtors_aux calls deregister_tm_clones this time, as it does in
     the binary, and nops pad the code past its return up to
     register_tm_clones, which nothing calls or points to. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code past the padding of a function is a function``() =
    let code = 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
    let entries = findEntries [ code ]
    CollectionAssert.Contains(entries, 0x760UL)

  (* Templates that EXRL runs lie right above register_tm_clones this time, past
     the return of deregister_tm_clones and a nop, as clang lays them past the
     functions of a source file. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code past templates below a function is a function``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x754, "d20020004000" (* mvc 0(1,%r2),0(%r4) *)
          0x75a, "d70020002000" (* xc 0(1,%r2),0(%r2) *) ]
    CollectionAssert.Contains(entries, 0x760UL)

  (* deregister_tm_clones calls frame_dummy where it returns this time, which
     calls abort as its tail, and code that sets up no frame lies right past
     the call, which starts a function on the guess that the call never
     returns, as the recovery finds of frame_dummy. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Frameless code right past a call that never returns is one``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x800, "c0f4ffffff5c" (* jg 0x6b8: abort@plt *)
          0x750, "c0e500000058" (* brasl %r14,0x800 *)
          0x756, "a729000007fe" (* lghi %r2,0; br %r14 *) ]
    CollectionAssert.Contains(entries, 0x756UL)

  (* deregister_tm_clones calls code right below register_tm_clones this time,
     which jumps past __do_global_dtors_aux to code right past frame_dummy, so
     that it returns nowhere until the recovery finds that a function starts
     there, and the code right past the call is the rest of
     deregister_tm_clones after all. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code past a call that turns out to return is no function``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x730, "c0e500000010" (* brasl %r14,0x750 *)
          0x736, "a729000007fe" (* lghi %r2,0; br %r14 *)
          0x73c, String.replicate 10 "0707" (* nopr %r7 *)
          0x750, "c0f40000005c" (* jg 0x808 *)
          0x756, String.replicate 5 "0707" (* nopr %r7 *)
          0x802, String.replicate 2 "0707" (* nopr %r7 *)
          0x808, "a729000107fe" (* lghi %r2,1; br %r14 *) ]
    CollectionAssert.DoesNotContain(entries, 0x736UL)

  (* deregister_tm_clones calls the code right below register_tm_clones as
     above and then abort, which starts a function on a guess right past the
     first call until the recovery finds that call to return, and main calls
     deregister_tm_clones and then returns, which it never does. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A caller of code that runs into a guess never returns``() =
    let fns =
      recoverPatched
        [ 0x730, "c0e500000010" (* brasl %r14,0x750 *)
          0x736, "c0e5ffffffc1" (* brasl %r14,0x6b8: abort@plt *)
          0x73c, String.replicate 10 "0707" (* nopr %r7 *)
          0x750, "c0f40000005c" (* jg 0x808 *)
          0x756, String.replicate 5 "0707" (* nopr %r7 *)
          0x802, String.replicate 2 "0707" (* nopr %r7 *)
          0x808, "a729000107fe" (* lghi %r2,1; br %r14 *)
          0x810, "c0e5ffffff90" (* brasl %r14,0x730 *)
          0x816, "a729000007fe" (* lghi %r2,0; br %r14 *) ]
    Assert.AreEqual<NonReturningStatus>(NoRet, fns[0x810UL].NoRet)

  (* deregister_tm_clones calls abort where it returns this time, which its name
     tells never to return, and code that sets up no frame lies right past the
     call, as clang lays a function right past one that ends with such a call,
     without padding. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code right past a call to abort is a function``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x750, "c0e5ffffffb4" (* brasl %r14,0x6b8: abort@plt *)
          0x756, "a729000007fe" (* lghi %r2,0; br %r14 *) ]
    CollectionAssert.Contains(entries, 0x756UL)

  (* deregister_tm_clones calls abort this time and jumps past its return to
     code of its own, as a function does to a block that it lays past the rest
     of its code, which the recovery builds only once it finds that the callee
     returns. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code that the function above jumps to is no function``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x742, "c0e5ffffffbb" (* brasl %r14,0x6b8: abort@plt *)
          0x748, "a7f400050707" (* j 0x752; nopr %r7 *)
          0x752, "a729000007fe" (* lghi %r2,0; br %r14 *) ]
    CollectionAssert.DoesNotContain(entries, 0x752UL)

  (* deregister_tm_clones jumps to its return this time, over a function that
     calls register_tm_clones as its tail, which nothing calls or points to,
     as code past the function above may be one that another jumps to. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Code that a function inside the one above jumps to is one``() =
    let entries =
      findEntries
        [ 0x7e6, "c0e5ffffffa5" (* brasl %r14,0x730 *)
          0x730, "a7f40010" (* j 0x750 *)
          0x734, "c0f400000016" (* jg 0x760 *)
          0x73a, String.replicate 11 "0707" (* nopr %r7 *) ]
    CollectionAssert.Contains(entries, 0x760UL)

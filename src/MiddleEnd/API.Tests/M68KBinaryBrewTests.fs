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
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowGraph

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

  /// Returns the kinds of the edges that leave the block that ends with the
  /// instruction at the given address.
  static let edgeKindsFrom (fn: Function) insAddr =
    let v =
      fn.CFG.FindVertexBy(fun v ->
        not v.VData.Internals.IsAbstract
        && v.VData.Internals.LastInstruction.Address = insAddr)
    fn.CFG.GetSuccEdges v |> Array.map _.Label

  /// Returns how many entries each jump table of the entry function has.
  static let countEntries code =
    let fns = recoverCode code
    fns[0UL].JumpTables |> Array.map _.NumEntries

  /// Returns where the functions that the recovery finds in the shared object
  /// of m68k start, once each of the given hex strings is written at its
  /// offset. Its symbol table is hidden, so that only its dynamic symbols and
  /// its data tell of functions, and frame_dummy returns right away, so that
  /// nothing leads to register_tm_clones, at 0x408.
  static let findEntriesInSo (patches: (int * string) list) =
    let bytes = readZippedBinary "elf_m68k_so"
    let patch (offset: int, hex: string) =
      (ByteArray.ofHexString hex).CopyTo(bytes, offset)
    patch (0x28e4, "00000000") (* the type of .symtab: SHT_NULL *)
    patch (0x494, "4e754e714e71") (* frame_dummy: rts; nop; nop *)
    List.iter patch patches
    let hdl = BinHandle.LoadFileBytes(bytes, ISA Architecture.M68K)
    Seq.toArray (BinaryBrew hdl).Functions.Addresses

  /// Returns the patches that make the first word of .data.rel.ro, which a
  /// relocation sets, point to the given address: the addend of the
  /// relocation and the word itself.
  static let relocatedPointerTo (addr: uint32) =
    let hex = addr.ToString("x8")
    [ 0x2a4, hex; 0x1f30, hex ]

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

  (* GCC loads the address of a function that it calls more than once into an
     address register, through which a call takes two bytes rather than the
     six that JSR to an absolute address takes. *)
  [<TestMethod>]
  member _.``A call through a register reaches the function it holds``() =
    let code =
      [ "45f90000000c" (* lea 0xc,a2 *)
        "4e92" (* jsr (a2) *)
        "4e92" (* jsr (a2) *)
        "4e75" (* rts *)
        "4e75" (* 0xc: rts *) ]
    let fns = recoverCode code
    let callee = fns[0UL].Callees[LeafCallSite 0x6UL]
    Assert.AreEqual<CalleeKind>(RegularCallee 0xcUL, callee)
    Assert.AreEqual<bool>(true, Seq.contains 0xcUL fns.Addresses)

  (* A switch over every value of an enum has no range check, and the code of
     its first case follows the table, whose first word reads as an entry that
     sends the jump to an odd address, where no instruction starts. *)
  [<TestMethod>]
  member _.``A table ends before an entry that points to an odd address``() =
    let code =
      [ "6100005e" (* bsr.w 0x60 *)
        "303b0a06" (* move.w (6,pc,d0.l*2),d0 *)
        "4efb0002" (* jmp (2,pc,d0.w) *)
        "0004" (* 0xc: .word 0x10 - 0xc *)
        "000a" (* .word 0x16 - 0xc *)
        "00410001" (* 0x10: ori.w #1,d1 *)
        "4e75" (* rts *)
        "7002" (* 0x16: moveq #2,d0 *)
        "4e75" (* rts *)
        String.replicate 25 "4e71" (* 0x1a: nop *)
        "004e7500" (* 0x4c: data that reads as rts at 0x4d *)
        String.replicate 8 "4e71" (* 0x50: nop *)
        "4e75" (* 0x60: rts *) ]
    CollectionAssert.AreEqual([| 2 |], countEntries code)

  (* A switch over every value of an enum has no range check, and the code of
     its first case follows the table, whose first word reads as an entry
     that points into the function. *)
  [<TestMethod>]
  member _.``A table right after its jump ends where its code starts``() =
    let code =
      [ "6100005e" (* bsr.w 0x60 *)
        "303b0a06" (* move.w (6,pc,d0.l*2),d0 *)
        "4efb0002" (* jmp (2,pc,d0.w) *)
        "0004" (* 0xc: .word 0x10 - 0xc *)
        "000a" (* .word 0x16 - 0xc *)
        "00400001" (* 0x10: ori.w #1,d0 *)
        "4e75" (* rts *)
        "7002" (* 0x16: moveq #2,d0 *)
        "4e75" (* rts *)
        String.replicate 35 "4e71" (* 0x1a: nop *)
        "4e75" (* 0x60: rts *) ]
    CollectionAssert.AreEqual([| 2 |], countEntries code)

  (* f jumps to x before anything tells that x is a function, so its building
     leaves out the code there as lying past h, which main has called. g,
     which main calls next, calls x and so makes it a function, after which f
     is built again to call x as its tail. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A jump to a function that a later call proves calls it``() =
    let fns =
      recoverCode
        [ "61000016" (* main: bsr.w h *)
          "61000008" (* bsr.w f *)
          "61000010" (* bsr.w g *)
          "4e75" (* rts *)
          "4a80" (* 0xe: f: tst.l d0 *)
          "6704" (* beq.s 0x16 *)
          "6000000c" (* bra.w x *)
          "4e75" (* 0x16: rts *)
          "4e75" (* 0x18: h: rts *)
          "61000004" (* 0x1a: g: bsr.w x *)
          "4e75" (* rts *)
          "5280" (* 0x20: x: addq.l #1,d0 *)
          "4e75" (* rts *) ]
    let kinds = edgeKindsFrom fns[0xeUL] 0x12UL
    CollectionAssert.AreEqual([| TailCallEdge |], kinds)

  (* Only a relocated word of .data.rel.ro leads to register_tm_clones, which
     saves a5 first. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A relocated pointer to code saving registers is a function``() =
    let entries = findEntriesInSo (relocatedPointerTo 0x408u)
    CollectionAssert.Contains(entries, 0x408UL)

  (* The pointer names the code past the return of frame_dummy, which returns
     one with no frame, where no code runs into it. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A relocated pointer to code below a return is a function``() =
    let code = 0x494, "4e7570014e75" (* rts; moveq #1,d0; rts *)
    let entries = findEntriesInSo (code :: relocatedPointerTo 0x496u)
    CollectionAssert.Contains(entries, 0x496UL)

  (* The code past the return of frame_dummy copies d0 this time, which holds
     nothing as a function starts, as every argument comes on the stack. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to code reading what code above left is no function``() =
    let code = 0x494, "4e7522004e75" (* rts; move.l d0,d1; rts *)
    let entries = findEntriesInSo (code :: relocatedPointerTo 0x496u)
    CollectionAssert.DoesNotContain(entries, 0x496UL)

  (* The pointer names where register_tm_clones restores d2, which the code
     above runs into, with no frame set up. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to code that code above runs into is no function``() =
    let entries = findEntriesInSo (relocatedPointerTo 0x44au)
    CollectionAssert.DoesNotContain(entries, 0x44aUL)

  (* As an executable that stays where it is linked, the binary relocates
     nothing, and .data.rel.ro holds the address of register_tm_clones as it
     is, right past .fini_array, which holds that of __do_global_dtors_aux. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A code address next to other pointers is a pointer``() =
    let entries = findEntriesInSo [ 0x10, "0002"; 0x1f30, "00000408" ]
    CollectionAssert.Contains(entries, 0x408UL)

  (* .data holds the address of register_tm_clones this time, among small
     numbers and data addresses, as a number that happens to look like a code
     address sits. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A lone code address in fixed-base data is no pointer``() =
    let entries = findEntriesInSo [ 0x10, "0002"; 0x2044, "00000408" ]
    CollectionAssert.DoesNotContain(entries, 0x408UL)

  (* frame_dummy jumps through a table right past it this time, which the
     pointer names, as PIE code loads the address of such a table from the
     GOT, where a relocation sets it. The first entry of the table reads as a
     branch below a jump. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A pointer to a table right past its jump is no function``() =
    let code = 0x494, "4efb00026002" (* jmp (2,pc,d0.w); .word 0x6002 *)
    let entries = findEntriesInSo (code :: relocatedPointerTo 0x498u)
    CollectionAssert.DoesNotContain(entries, 0x498UL)

  (* main passes f to g, as qsort takes its comparison, by pushing the address
     of f that it computes from the PC, and nothing calls f. *)
  [<TestMethod>]
  member _.``Code that passes the address of code passes a function``() =
    let code =
      [ "487a000a" (* pea (0xa,pc) *)
        "61000008" (* bsr.w g *)
        "588f" (* addq.l #4,sp *)
        "4e75" (* rts *)
        "4e75" (* 0xc: f: rts *)
        "4e75" (* 0xe: g: rts *) ]
    CollectionAssert.Contains(Seq.toArray (recoverCode code).Addresses, 0xcUL)

  (* Code that stays where it is linked pushes the address of f as it is. *)
  [<TestMethod>]
  member _.``Fixed-base code that pushes the address of code passes one``() =
    let code =
      [ "2f3c0000000e" (* move.l #0xe,-(sp) *)
        "61000008" (* bsr.w g *)
        "588f" (* addq.l #4,sp *)
        "4e75" (* rts *)
        "4e75" (* 0xe: f: rts *)
        "4e75" (* 0x10: g: rts *) ]
    CollectionAssert.Contains(Seq.toArray (recoverCode code).Addresses, 0xeUL)

  (* frame_dummy pushes a number that names register_tm_clones this time, but
     the loader may place the library anywhere, so its code holds no address
     as an immediate. *)
  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``An immediate of relocated code names no function``() =
    let code = 0x494, "2f3c000004084e75" (* move.l #0x408,-(sp); rts *)
    let entries = findEntriesInSo [ code ]
    CollectionAssert.DoesNotContain(entries, 0x408UL)

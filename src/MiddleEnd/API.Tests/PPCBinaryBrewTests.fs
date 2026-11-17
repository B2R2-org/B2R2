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

  /// Writes the big-endian word at the given offset.
  static let writeWord (bytes: byte[]) offset (v: uint32) =
    for i in 0 .. 3 do bytes[offset + i] <- byte (v >>> (24 - 8 * i))

  /// Reads the big-endian word at the given offset.
  static let readWord (bytes: byte[]) offset =
    Array.sub bytes offset 4
    |> Array.fold (fun v b -> (v <<< 8) ||| uint32 b) 0u

  /// Recovers the functions of elf_ppc32_so once the given patch has changed
  /// its bytes, which has get, at 0x4d4, room for 28 instructions.
  static let recoverPatchedSO patch =
    let bytes = readZippedBinary "elf_ppc32_so"
    patch bytes
    let isa = ISA(Architecture.PPC, Endian.Big, WordSize.Bit32)
    BinaryBrew(BinHandle.LoadFileBytes(bytes, isa)).Functions

  /// Makes get the given code.
  static let patchGet (code: string list) (bytes: byte[]) =
    (ByteArray.ofHexString(String.concat "" code)).CopyTo(bytes, 0x4d4)

  /// Makes the PLT of elf_ppc32_so the classic one, which the dynamic linker
  /// writes: .plt, section 17, turns NOBITS and executable, the relocations of
  /// .rela.plt, section 6, fill three entries two words apart from 0x20048,
  /// and the data segment, the second, takes them in, executable, past the
  /// bytes that the file holds of it.
  static let patchClassicPLT (bytes: byte[]) =
    let shdr idx = int (readWord bytes 0x20) + idx * 40
    let phdr idx = int (readWord bytes 0x1c) + idx * 32
    writeWord bytes (shdr 17 + 4) 8u (* SHT_NOBITS *)
    writeWord bytes (shdr 17 + 8) 7u (* SHF_WRITE|SHF_ALLOC|SHF_EXECINSTR *)
    let relocs = int (readWord bytes (shdr 6 + 16))
    for i in 0 .. 2 do
      writeWord bytes (relocs + 12 * i) (0x20048u + 8u * uint32 i)
    writeWord bytes (phdr 1 + 20) 0x170u (* p_memsz *)
    writeWord bytes (phdr 1 + 24) 7u (* PF_R|PF_W|PF_X *)

  /// Returns the code of get in elf_ppc64_so, at 0x7b4, as a function that
  /// first calls the stub at 0x640 the given number of times, up to three,
  /// reloading r2 from its frame after each call as the ABI has it, and then
  /// jumps through a table of two entries at 0x7fc, right after the jump,
  /// whose address it takes from r2, the TOC pointer, 0x27f00.
  static let tocTableOfTwo calls =
    let call target =
      [ $"{0x48000001u ||| (target &&& 0x3fffffcu):x8}" (* bl 0x640 *)
        "e8410028" (* ld r2,40(r1) *) ]
    [ "7c0802a6" (* mflr r0 *)
      "f8010010" (* std r0,16(r1) *)
      "f821ff81" (* stdu r1,-128(r1) *)
      for i in 0u .. 2u do
        if i < calls then yield! call (0x640u - 0x7c0u - 8u * i)
        else yield! [ "60000000"; "60000000" ] (* nop; nop *)
      "28030001" (* 0x7d8: cmplwi r3,1 *)
      "41810034" (* bgt 0x810 *)
      "3d42fffe" (* addis r10,r2,-2 *)
      "394a88fc" (* addi r10,r10,-30468: 0x7fc *)
      "78631788" (* rldic r3,r3,2,30 *)
      "7c6a1aaa" (* lwax r3,r10,r3 *)
      "7d435214" (* add r10,r3,r10 *)
      "7d4903a6" (* mtctr r10 *)
      "4e800420" (* bctr *)
      "00000008" (* 0x7fc: .long 0x804 - 0x7fc *)
      "00000010" (* .long 0x80c - 0x7fc *)
      "38600000" (* 0x804: li r3,0 *)
      "48000008" (* b 0x810 *)
      "38600001" (* 0x80c: li r3,1 *)
      "38210080" (* 0x810: addi r1,r1,128 *)
      "e8010010" (* ld r0,16(r1) *)
      "7c0803a6" (* mtlr r0 *)
      "4e800020" (* blr *) ]

  /// Returns how many entries each jump table of get in elf_ppc64_so has, once
  /// get becomes the given code.
  static let countEntriesInGet64 (code: string list) =
    let bytes = readZippedBinary "elf_ppc64_so"
    (ByteArray.ofHexString(String.concat "" code)).CopyTo(bytes, 0x7b4)
    let isa = ISA(Architecture.PPC, Endian.Big, WordSize.Bit64)
    let fns = BinaryBrew(BinHandle.LoadFileBytes(bytes, isa)).Functions
    fns[0x7b4UL].JumpTables |> Array.map _.NumEntries

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

  (* slwi rotates the index and masks off the bits that the rotation brings
     around, which leaves the index shifted. *)
  [<TestMethod>]
  member _.``A table is read through an index that rotates a word``() =
    let code =
      tableOfTwo
        [ "5463103a" (* slwi r3,r3,2 *)
          "7c69182e" (* lwzx r3,r9,r3 *) ]
    CollectionAssert.AreEqual([| 2 |], countEntries WordSize.Bit32 code)

  (* GCC for PPC64 scales the low word of an index with rldic, which rotates
     the doubleword and masks off the high word along with what the rotation
     brings around, and loads the entry with its sign. *)
  [<TestMethod>]
  member _.``A table is read through an index that rotates a doubleword``() =
    let code =
      tableOfTwo
        [ "78631788" (* rldic r3,r3,2,30 *)
          "7c691aaa" (* lwax r3,r9,r3 *) ]
    CollectionAssert.AreEqual([| 2 |], countEntries WordSize.Bit64 code)

  (* The file holds no bytes of the classic PLT, which the dynamic linker
     writes, so a jump into it calls the import as its tail with no code there
     to read. *)
  [<TestMethod>]
  member _.``A jump into a PLT that the file lacks calls an import``() =
    let code =
      [ "2c030000" (* cmpwi r3,0 *)
        "4d820020" (* beqlr *)
        "4801fb6c" (* b 0x20048 <ext@plt> *) ]
    let fns = recoverPatchedSO (fun bytes -> patchClassicPLT bytes
                                             patchGet code bytes)
    let callee = fns[0x4d4UL].Callees[LeafCallSite 0x4dcUL]
    Assert.AreEqual<CalleeKind>(RegularCallee 0x20048UL, callee)

  (* GCC lays the tables of a function next to each other, so the words past
     a table read as more of its entries, counted from its own base, which
     send its jump into the code of the function all the same. The range
     check right before the jump says where the table ends. *)
  [<TestMethod>]
  member _.``A table ends where its range check says``() =
    let code =
      [ "28030001" (* cmplwi r3,1 *)
        "41810034" (* bgt 0x50c *)
        "3d200000" (* lis r9,0 *)
        "392904f8" (* addi r9,r9,0x4f8 *)
        "5463103a" (* slwi r3,r3,2 *)
        "7c69182e" (* lwzx r3,r9,r3 *)
        "7d234a14" (* add r9,r3,r9 *)
        "7d2903a6" (* mtctr r9 *)
        "4e800420" (* bctr *)
        "00000010" (* 0x4f8: .long 0x508 - 0x4f8 *)
        "00000018" (* .long 0x510 - 0x4f8 *)
        "00000010" (* 0x500: an entry of the next table, 0x508 if read here *)
        "7fff0000" (* 0x504: no entry *)
        "38600000" (* 0x508: li r3,0 *)
        "4e800020" (* blr *)
        "38600001" (* 0x510: li r3,1 *)
        "4e800020" (* blr *) ]
    let fns = recoverPatchedSO (patchGet code)
    let entries = fns[0x4d4UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* 32-bit PIC reads the offset of .got2 that lies right before the code that
     reads it, through the address that bcl 20,31,$+4 leaves in LR, and then
     the address of a table from a slot of .got2, which the loader rebases.
     The relocation of the slot at 0x1ff20 here points to the table, which
     lies right after the jump. *)
  [<TestMethod>]
  member _.``A table is read through the slot of .got2 that holds it``() =
    let code =
      [ "48000008" (* b 0x4dc *)
        "00027a20" (* 0x4d8: .long 0x27f04 - 0x4e4 *)
        "7d8802a6" (* mflr r12 *)
        "429f0005" (* bcl 20,31,0x4e4 *)
        "7fc802a6" (* 0x4e4: mflr r30 *)
        "7d8803a6" (* mtlr r12 *)
        "801efff4" (* lwz r0,-12(r30) *)
        "7fc0f214" (* add r30,r0,r30 *)
        "28030001" (* cmplwi r3,1 *)
        "41810030" (* bgt 0x528 *)
        "813e801c" (* lwz r9,-32740(r30) *)
        "5463103a" (* slwi r3,r3,2 *)
        "7c69182e" (* lwzx r3,r9,r3 *)
        "7d234a14" (* add r9,r3,r9 *)
        "7d2903a6" (* mtctr r9 *)
        "4e800420" (* bctr *)
        "00000008" (* 0x514: .long 0x51c - 0x514 *)
        "00000010" (* .long 0x524 - 0x514 *)
        "38600000" (* 0x51c: li r3,0 *)
        "4e800020" (* blr *)
        "38600001" (* 0x524: li r3,1 *)
        "4e800020" (* blr *) ]
    let patch bytes =
      writeWord bytes (0x268 + 6 * 12 + 8) 0x514u (* r_addend of 0x1ff20 *)
      patchGet code bytes
    let fns = recoverPatchedSO patch
    let entries = fns[0x4d4UL].JumpTables |> Array.map _.NumEntries
    CollectionAssert.AreEqual([| 2 |], entries)

  (* 64-bit code finds data through r2, which holds the TOC pointer on entry
     to every function, 0x8000 bytes past the start of .got. *)
  [<TestMethod>]
  member _.``A table is read through the TOC pointer``() =
    CollectionAssert.AreEqual([| 2 |], countEntriesInGet64 (tocTableOfTwo 0u))

  (* A call to another module goes through a stub that saves r2 in the frame
     of the caller, from where the caller reloads it after the call. *)
  [<TestMethod>]
  member _.``A table is read through the TOC pointer reloaded after a call``() =
    CollectionAssert.AreEqual([| 2 |], countEntriesInGet64 (tocTableOfTwo 1u))

  (* r2 goes through the frame at every call, a copy each way, which costs the
     expansion of the jump target no step. *)
  [<TestMethod>]
  member _.``A table is read through a TOC pointer reloaded many times``() =
    CollectionAssert.AreEqual([| 2 |], countEntriesInGet64 (tocTableOfTwo 3u))

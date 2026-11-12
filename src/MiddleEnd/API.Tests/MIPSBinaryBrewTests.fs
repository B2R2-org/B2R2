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

/// Tests the recovery of MIPS binaries.
[<TestClass>]
type MIPSBinaryBrewTests() =
  /// Recovers the functions of the given big-endian MIPS32 code, which starts
  /// at address zero with the entry of the binary.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    BinaryBrew(BinHandle.LoadRawImage(bytes, ISA "mips32")).Functions

  /// Recovers the functions of the given fixture once main becomes the given
  /// code and .rodata starts with the given bytes. The fixture gives its name,
  /// its ISA, the offset of main in the file, and that of .rodata.
  static let recoverPatched fixture code rodata =
    let name, (isa: string), mainOffset, rodataOffset = fixture
    let bytes = readZippedBinary name
    let patch (offset: int) (hex: string) =
      (ByteArray.ofHexString hex).CopyTo(bytes, offset)
    patch mainOffset (String.concat "" code)
    patch rodataOffset rodata
    BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA isa)).Functions

  /// The fixture whose main is at 0x400520 with room for sixteen
  /// instructions, and whose .rodata is at 0x4006f4 with room for eight bytes.
  static let mips32 = "elf_mips32", "mips32", 0x520, 0x6f4

  /// The fixture whose main is at 0x1200008b0 with room for twenty
  /// instructions, and whose .rodata is at 0x120000ac8 with room for sixteen
  /// bytes.
  static let mips64 = "elf_mips64", "mips64", 0x8b0, 0xac8

  /// Returns how many entries each jump table of main has, once main becomes
  /// the given code and .rodata starts with the given bytes.
  static let countEntriesInPatchedMain code rodata =
    let fns = recoverPatched mips32 code rodata
    fns[0x400520UL].JumpTables |> Array.map _.NumEntries

  /// Returns how many entries each jump table of main has in elf_mips64, once
  /// main becomes the given code and .rodata starts with the given bytes.
  static let countEntriesInPatchedMain64 code rodata =
    let fns = recoverPatched mips64 code rodata
    fns[0x1200008b0UL].JumpTables |> Array.map _.NumEntries

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
        [ "04110003" (* bal 0x10 *)
          "24040001" (* addiu a0, zero, 1 *)
          "03e00008" (* jr ra *)
          "00000000" (* nop *)
          "03e00008" (* jr ra *)
          "00000000" (* nop *) ]
    CollectionAssert.AreEqual([| 0x0UL; 0x8UL |], blocksOf fns[0x0UL])

  (* A table may run up to other data whose address the code computes on its
     own: here the code past the first case returns the address of the word
     right past the table, which holds an address in main. No range check
     bounds the table, and its section goes on, so nothing else ends it. *)
  [<TestMethod>]
  member _.``A table ends at data that the code addresses``() =
    let code =
      [ "3c010040" (* lui at, 0x40 *)
        "00041080" (* sll v0, a0, 2 *)
        "00220821" (* addu at, at, v0 *)
        "8c2106f4" (* lw at, 0x6f4(at) *)
        "00200008" (* jr at *)
        "00000000" (* nop *)
        "03e00008" (* jr ra *)
        "24020000" (* addiu v0, zero, 0 *)
        "3c020040" (* lui v0, 0x40 *)
        "03e00008" (* jr ra *)
        "244206f8" (* addiu v0, v0, 0x6f8 *) ]
    let rodata = "0040053800400540" (* .word 0x400538, 0x400540 *)
    CollectionAssert.AreEqual([| 1 |], countEntriesInPatchedMain code rodata)

  (* MIPS code checks the index of a table right before it jumps, and the
     table ends where the check says, though the word past it reads as an
     entry too. *)
  [<TestMethod>]
  member _.``A table ends at its range check``() =
    let code =
      [ "2c810001" (* sltiu at, a0, 1 *)
        "10200008" (* beqz at, 0x400548 *)
        "00041080" (* sll v0, a0, 2 *)
        "3c010040" (* lui at, 0x40 *)
        "00220821" (* addu at, at, v0 *)
        "8c2106f4" (* lw at, 0x6f4(at) *)
        "00200008" (* jr at *)
        "00000000" (* nop *)
        "03e00008" (* jr ra *)
        "24020000" (* addiu v0, zero, 0 *)
        "03e00008" (* jr ra *)
        "24020001" (* addiu v0, zero, 1 *) ]
    let rodata = "0040054000400548" (* .word 0x400540, 0x400548 *)
    CollectionAssert.AreEqual([| 1 |], countEntriesInPatchedMain code rodata)

  (* MIPS64 code checks a 32-bit index, then takes its low word with DEXT,
     which the IR masks, before it scales the index. *)
  [<TestMethod>]
  member _.``A table ends at the range check of a 32-bit index``() =
    let code =
      [ "2482ffff" (* addiu v0, a0, -1 *)
        "2c430001" (* sltiu v1, v0, 1 *)
        "1060000a" (* beqz v1, 0x1200008e4 *)
        "3c011200" (* lui at, 0x1200 *)
        "00010938" (* dsll at, at, 4 *)
        "7c42f803" (* dext v0, v0, 0, 32 *)
        "000210f8" (* dsll v0, v0, 3 *)
        "0022082d" (* daddu at, at, v0 *)
        "dc210ac8" (* ld at, 0xac8(at) *)
        "00200008" (* jr at *)
        "00000000" (* nop *)
        "03e00008" (* jr ra *)
        "64020000" (* daddiu v0, zero, 0 *)
        "03e00008" (* jr ra *)
        "64020001" (* daddiu v0, zero, 1 *) ]
    let rodata = "00000001200008dc00000001200008e4"
    CollectionAssert.AreEqual([| 1 |], countEntriesInPatchedMain64 code rodata)

  (* A mask on the index bounds a table as a range check does, when the code
     masks rather than checks it. *)
  [<TestMethod>]
  member _.``A table ends where a mask on its index says``() =
    let code =
      [ "30820000" (* andi v0, a0, 0 *)
        "00021080" (* sll v0, v0, 2 *)
        "3c010040" (* lui at, 0x40 *)
        "00220821" (* addu at, at, v0 *)
        "8c2106f4" (* lw at, 0x6f4(at) *)
        "00200008" (* jr at *)
        "00000000" (* nop *)
        "03e00008" (* jr ra *)
        "24020000" (* addiu v0, zero, 0 *)
        "03e00008" (* jr ra *)
        "24020001" (* addiu v0, zero, 1 *) ]
    let rodata = "0040053c00400544" (* .word 0x40053c, 0x400544 *)
    CollectionAssert.AreEqual([| 1 |], countEntriesInPatchedMain code rodata)

  (* PIC code reads the address of a table from the local GOT and adds each
     entry to gp, which it reloads from the stack, as GCC builds a switch. *)
  [<TestMethod>]
  member _.``A table is read through the GOT``() =
    let code =
      [ "3c1c0043" (* lui gp, 0x43 *)
        "279c8010" (* addiu gp, gp, -0x7ff0 *)
        "27bdfff8" (* addiu sp, sp, -8 *)
        "afbc0000" (* sw gp, 0(sp) *)
        "8f828018" (* lw v0, -0x7fe8(gp) *)
        "00042080" (* sll a0, a0, 2 *)
        "00441021" (* addu v0, v0, a0 *)
        "8c4201d4" (* lw v0, 0x1d4(v0) *)
        "8fbc0000" (* lw gp, 0(sp) *)
        "005c1021" (* addu v0, v0, gp *)
        "00400008" (* jr v0 *)
        "27bd0008" (* addiu sp, sp, 8 *)
        "03e00008" (* jr ra *)
        "24020000" (* addiu v0, zero, 0 *)
        "03e00008" (* jr ra *)
        "24020001" (* addiu v0, zero, 1 *) ]
    let rodata = "fffd8540fffd8548" (* .word 0x400550 - gp, 0x400558 - gp *)
    CollectionAssert.AreEqual([| 2 |], countEntriesInPatchedMain code rodata)

  (* PIC code finds gp from t9, which holds the address of its function on
     entry, so the constant that it adds to t9 is _gp, 0x428010 here, less
     that address. That tells where a function starts that nothing calls, but
     not where the constant would have t9 point past the code that adds it. *)
  [<TestMethod>]
  member _.``A function starts where its code finds gp from t9``() =
    let code =
      [ "03e00008" (* jr ra *)
        "00000000" (* nop *)
        "3c020002" (* lui v0, 0x2 *)
        "24427ae8" (* addiu v0, v0, 0x7ae8 *)
        "0059e021" (* addu gp, v0, t9 *)
        "03e00008" (* jr ra *)
        "00000000" (* nop *)
        "3c020002" (* lui v0, 0x2 *)
        "24427ad0" (* addiu v0, v0, 0x7ad0 *)
        "0059e021" (* addu gp, v0, t9 *)
        "03e00008" (* jr ra *)
        "00000000" (* nop *) ]
    let addrs = (recoverPatched mips32 code "").Addresses |> Set.ofSeq
    let found =
      [| 0x400528UL; 0x40053cUL; 0x400540UL |]
      |> Array.filter (fun addr -> Set.contains addr addrs)
    CollectionAssert.AreEqual([| 0x400528UL |], found)

  (* A callee may change t9, so the code that a call returns to never finds
     gp from it: code that does right after a call starts a function, which
     the call never returns to. *)
  [<TestMethod>]
  member _.``A function starts right after a call``() =
    let code =
      [ "0320f809" (* jalr t9 *)
        "00002021" (* move a0, zero *)
        "3c020002" (* lui v0, 0x2 *)
        "24427ae8" (* addiu v0, v0, 0x7ae8 *)
        "0059e021" (* addu gp, v0, t9 *)
        "03e00008" (* jr ra *)
        "00000000" (* nop *) ]
    let addrs = (recoverPatched mips32 code "").Addresses |> Set.ofSeq
    Assert.AreEqual<bool>(true, Set.contains 0x400528UL addrs)

  (* A prologue may add t9 in the delay slot of a branch, which runs it
     whether or not the branch is taken. A likely branch runs it only when
     taken, so an add there tells nothing of where the function starts. *)
  [<TestMethod>]
  member _.``A function finds gp in the delay slot of a branch``() =
    let code =
      [ "03e00008" (* jr ra *)
        "00000000" (* nop *)
        "3c020002" (* lui v0, 0x2 *)
        "24427ae8" (* addiu v0, v0, 0x7ae8 *)
        "10800001" (* beq a0, zero, 0x400538 *)
        "0059e021" (* addu gp, v0, t9 *)
        "03e00008" (* jr ra *)
        "00000000" (* nop *)
        "3c020002" (* lui v0, 0x2 *)
        "24427ad0" (* addiu v0, v0, 0x7ad0 *)
        "50800001" (* beql a0, zero, 0x400550 *)
        "0059e021" (* addu gp, v0, t9 *)
        "03e00008" (* jr ra *)
        "00000000" (* nop *) ]
    let addrs = (recoverPatched mips32 code "").Addresses |> Set.ofSeq
    let found =
      [| 0x400528UL; 0x400540UL |]
      |> Array.filter (fun addr -> Set.contains addr addrs)
    CollectionAssert.AreEqual([| 0x400528UL |], found)

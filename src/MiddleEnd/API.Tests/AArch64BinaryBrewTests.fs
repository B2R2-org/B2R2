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
open B2R2.MiddleEnd.ControlFlowGraph

/// Tests the recovery of AArch64 binaries.
[<TestClass>]
type AArch64BinaryBrewTests() =
  /// Recovers the functions of the given AArch64 code, which starts at address
  /// zero with the entry of the binary. A raw image has no section to hold a
  /// table, so a test on one reads its table as one of labels, which has to
  /// point into its function, before the next one: the code starts by calling
  /// a function that lies past its table.
  static let recoverCode (code: string list) =
    let bytes = code |> String.concat "" |> ByteArray.ofHexString
    BinaryBrew(BinHandle.LoadRawImage(bytes, ISA "aarch64")).Functions

  /// Returns where the indirect jumps of the function go, in order.
  static let indirectJumpTargetsOf (fn: Function) =
    fn.CFG.Edges
    |> Array.filter (fun e -> e.Label = IndirectJmpEdge)
    |> Array.map (fun e -> e.Second.VData.Internals.BlockAddress)
    |> Array.sort

  /// Returns how many entries each jump table of main has, once main becomes
  /// the given code and .rodata starts with the given bytes. Main is at
  /// 0x400580 with room for sixteen instructions, and .rodata at 0x400710 with
  /// room for twelve bytes. Unlike a raw image, the binary has a section for
  /// tables, within which a range check can end one.
  static let countEntriesInPatchedMain code rodata =
    let bytes = readZippedBinary "elf_aarch64"
    let patch (offset: int) (hex: string) =
      (ByteArray.ofHexString hex).CopyTo(bytes, offset)
    patch 0x580 (String.concat "" code)
    patch 0x710 rodata
    let hdl = BinHandle.LoadFileBytes(bytes, ISA "aarch64")
    BinaryBrew(hdl).Functions[0x400580UL].JumpTables
    |> Array.map _.NumEntries

  (* Clang adds a byte of the table, shifted, to the address of the first case.
     LDRB writes the byte to W11, which X11 holds zero-extended, so the byte is
     extended twice before the shift. *)
  [<TestMethod>]
  member _.``A clang table of bytes is shifted by the add to a case``() =
    let fns =
      recoverCode
        [ "13000094" (* bl 0x4c *)
          "1f0c0071" (* cmp w0, #3 *)
          "c8010054" (* b.hi 0x40 *)
          "e803002a" (* mov w8, w0 *)
          "09000090" (* adrp x9, 0x0 *)
          "29210191" (* add x9, x9, #0x48 *)
          "8a000010" (* adr x10, 0x28 *)
          "2b696838" (* ldrb w11, [x9, x8] *)
          "4a090b8b" (* add x10, x10, x11, lsl #2 *)
          "40011fd6" (* br x10 *)
          "00008052" (* mov w0, #0 *)
          "c0035fd6" (* ret *)
          "20008052" (* mov w0, #1 *)
          "c0035fd6" (* ret *)
          "40008052" (* mov w0, #2 *)
          "c0035fd6" (* ret *)
          "60008052" (* mov w0, #3 *)
          "c0035fd6" (* ret *)
          "00020406" (* .byte 0, 2, 4, 6 *)
          "c0035fd6" (* ret *) ]
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 0x28UL; 0x30UL; 0x38UL; 0x40UL |], targets)

  (* GCC extends a byte of the table by its sign as it adds it, shifted, to the
     address past the jump, so a case can lie before the jump: here the last
     entry, -8, goes back to the case at 0x10. The byte that SXTB extends is
     the low one of W0, to which LDRB wrote it zero-extended, twice. *)
  [<TestMethod>]
  member _.``A GCC table of bytes reads its entries as signed``() =
    let fns =
      recoverCode
        [ "13000094" (* bl 0x4c *)
          "1f0c0071" (* cmp w0, #3 *)
          "c8010054" (* b.hi 0x40 *)
          "03000014" (* b 0x18 *)
          "20018052" (* mov w0, #9 *)
          "c0035fd6" (* ret *)
          "01000090" (* adrp x1, 0x0 *)
          "21200191" (* add x1, x1, #0x48 *)
          "20486038" (* ldrb w0, [x1, w0, uxtw] *)
          "61000010" (* adr x1, 0x30 *)
          "2088208b" (* add x0, x1, w0, sxtb #2 *)
          "00001fd6" (* br x0 *)
          "00008052" (* mov w0, #0 *)
          "c0035fd6" (* ret *)
          "20008052" (* mov w0, #1 *)
          "c0035fd6" (* ret *)
          "40008052" (* mov w0, #2 *)
          "c0035fd6" (* ret *)
          "000204f8" (* .byte 0, 2, 4, -8 *)
          "c0035fd6" (* ret *) ]
    let targets = indirectJumpTargetsOf fns[0x0UL]
    CollectionAssert.AreEqual([| 0x10UL; 0x30UL; 0x38UL; 0x40UL |], targets)

  (* As on ARM, GCC may switch on a halfword that a callee has written into a
     structure on the stack, a slot that the function itself never writes.
     LDRH copies the slot into a temporary, which X2 then holds extended, so
     the range check has to bound X2 rather than the slot, whose width the
     data flow does not know. Here main switches on a halfword that helper
     is to write, and the bytes past the table, 1 and 3, would send the jump
     to the RET of each case. *)
  [<TestMethod>]
  member _.``A GCC switch on a stack halfword ends at its range check``() =
    let code =
      [ "e0430091" (* add x0, sp, #16 *)
        "5b000094" (* bl helper *)
        "e2234079" (* ldrh w2, [sp, #16] *)
        "5f080071" (* cmp w2, #2 *)
        "68010054" (* b.hi 0x4005bc *)
        "00000090" (* adrp x0, 0x400000 *)
        "00401c91" (* add x0, x0, #0x710 *)
        "00486238" (* ldrb w0, [x0, w2, uxtw] *)
        "61000010" (* adr x1, 0x4005ac *)
        "2088208b" (* add x0, x1, w0, sxtb #2 *)
        "00001fd6" (* br x0 *)
        "00008052" (* mov w0, #0 *)
        "c0035fd6" (* ret *)
        "20008052" (* mov w0, #1 *)
        "c0035fd6" (* ret *)
        "c0035fd6" (* ret *) ]
    let rodata = "0002040103" (* .byte 0, 2, 4, then 1, 3 *)
    let actual = countEntriesInPatchedMain code rodata
    CollectionAssert.AreEqual([| 3 |], actual)

  (* Clang at -Oz outlines the allocation of a variable-length array into a
     function that lowers SP by a size its caller passes in X9, so SP is
     unknown where the function returns. RET returns through X30, which the
     function leaves alone, so the function still returns, and the code after
     the call to it belongs to main. *)
  [<TestMethod>]
  member _.``A function that moves SP returns through X30``() =
    let fns =
      recoverCode
        [ "e903002a" (* mov w9, w0 *)
          "03000094" (* bl 0x10 *)
          "20008052" (* mov w0, #1 *)
          "c0035fd6" (* ret *)
          "ea030091" (* mov x10, sp *)
          "29f17dd3" (* lsl x9, x9, #3 *)
          "293d0091" (* add x9, x9, #0xf *)
          "29ed7c92" (* and x9, x9, #0xfffffffffffffff0 *)
          "490109cb" (* sub x9, x10, x9 *)
          "3f010091" (* mov sp, x9 *)
          "c0035fd6" (* ret *) ]
    let afterCall =
      fns[0x0UL].CFG.TryFindVertexBy(fun v ->
        v.VData.Internals.BlockAddress = 0x8UL)
    let actual = fns[0x10UL].NoRet, Option.isSome afterCall
    Assert.AreEqual<NonReturningStatus * bool>((NotNoRet, true), actual)

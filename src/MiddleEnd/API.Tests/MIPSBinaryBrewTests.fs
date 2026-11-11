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

  /// Returns how many entries each jump table of main has, once main becomes
  /// the given code and .rodata starts with the given bytes. Main is at
  /// 0x400520 with room for sixteen instructions, and .rodata at 0x4006f4
  /// with room for eight bytes.
  static let countEntriesInPatchedMain code rodata =
    let bytes = readZippedBinary "elf_mips32"
    let patch (offset: int) (hex: string) =
      (ByteArray.ofHexString hex).CopyTo(bytes, offset)
    patch 0x520 (String.concat "" code)
    patch 0x6f4 rodata
    let hdl = BinHandle.LoadFileBytes(bytes, ISA "mips32")
    BinaryBrew(hdl).Functions[0x400520UL].JumpTables
    |> Array.map _.NumEntries

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

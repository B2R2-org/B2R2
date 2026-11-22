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

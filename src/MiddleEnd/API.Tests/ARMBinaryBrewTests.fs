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

/// Tests the recovery of 32-bit ARM binaries, whose functions each start in
/// one of two instruction sets.
[<TestClass>]
type ARMBinaryBrewTests() =
  /// GCC links the Thumb start-up code of glibc in front of a program it
  /// builds in ARM, so this binary holds functions of both instruction sets.
  static let mixedFunctions =
    let hdl = BinHandle.LoadFileBytes(readZippedBinary "elf_arm32", ISA "armv7")
    BinaryBrew(hdl).Functions

  /// Returns which instruction sets the instructions of the function are in,
  /// telling Thumb by true.
  static let instructionSetsOf (fn: Function) =
    fn.CFG.Vertices
    |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
    |> Array.collect (fun v -> v.VData.Internals.Instructions)
    |> Array.map (fun ins -> (ins :?> ARM32.Instruction).IsThumb)
    |> Array.distinct

  [<TestMethod>]
  member _.``An ARM function is read in ARM``() =
    let main = mixedFunctions[0x10330UL]
    CollectionAssert.AreEqual([| false |], instructionSetsOf main)

  (* The file says _start is in Thumb by setting the lowest bit of the address
     it gives, while the function itself starts at the even address below. *)
  [<TestMethod>]
  member _.``A Thumb function is read in Thumb at its even address``() =
    let start = mixedFunctions[0x10354UL]
    CollectionAssert.AreEqual([| true |], instructionSetsOf start)

  (* A BLX with an immediate always switches instruction sets, so the function
     it calls starts in the other one: here an ARM function calls a Thumb one
     that only returns. *)
  [<TestMethod>]
  member _.``A BLX makes its callee start in the other instruction set``() =
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "010000fa" (* blx 0x10 *)
        "1080bde8" (* pop {r4, pc} *)
        "00f020e3" (* nop *)
        "7047" (* bx lr, in Thumb *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let fns = BinaryBrew(BinHandle.LoadRawImage(code, ISA "armv7")).Functions
    CollectionAssert.AreEqual([| false |], instructionSetsOf fns[0x0UL])
    CollectionAssert.AreEqual([| true |], instructionSetsOf fns[0x10UL])

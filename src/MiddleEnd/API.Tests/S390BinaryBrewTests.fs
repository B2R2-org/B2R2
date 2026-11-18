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

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

namespace B2R2.FrontEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// Provides the assignment operator that an architecture adopting the
/// assignment DSL defines for itself, so that the tests below exercise the
/// same shape a lifter does.
[<AutoOpen>]
module private AssignDSLTestHelper =
  let inline (:=) target src =
    match target with
    | AssignTarget.Direct dst -> AST.assign dst src
    | AssignTarget.Sized(size, dst) -> assignSized size dst src

[<TestClass>]
type AssignDSLTests() =
  let reg64 = AST.var 64<rt> (RegisterID.create 0) "R"

  let num bitLen v = BitVector(u64 = v, bitLen = bitLen) |> AST.num

  /// Bytes the given assignment allocates, measured after a warm-up long
  /// enough for the loop to have settled.
  let allocatedBy count (assign: int -> Stmt) =
    for i in 1 .. count do assign i |> ignore
    let before = System.GC.GetAllocatedBytesForCurrentThread()
    for i in 1 .. count do assign i |> ignore
    System.GC.GetAllocatedBytesForCurrentThread() - before

  (* The wrapper is a struct and every constructor of it is inlined, so it
     never reaches the heap. Drop the `inline` or the `[<Struct>]` and this is
     what says so. *)
  [<TestMethod>]
  member _.``[AssignDSL] The target wrapper allocates nothing``() =
    let count = 10000
    let plain = allocatedBy count (fun _ -> AST.assign reg64 (num 64<rt> 1UL))
    let wrapped = allocatedBy count (fun _ -> direct reg64 := num 64<rt> 1UL)
    Assert.AreEqual<bool>(true, wrapped <= plain, $"{wrapped} > {plain}")

  [<TestMethod>]
  member _.``[AssignDSL] A sized write of 32 bits zero-extends``() =
    let src = num 32<rt> 1UL
    let expected = AST.assign reg64 (AST.zext 64<rt> src)
    Assert.AreEqual<Stmt>(expected, (sized 32<rt> reg64 := src))

  [<TestMethod>]
  member _.``[AssignDSL] A sized write of the whole register extends not``() =
    let src = num 64<rt> 1UL
    Assert.AreEqual<Stmt>(AST.assign reg64 src,
                          (sized 64<rt> reg64 := src))

  (* An 8- or 16-bit operand leaves the upper bits of its register alone, so
     the write goes to the extract as it stands. *)
  [<TestMethod>]
  member _.``[AssignDSL] A sized write of 8 bits keeps the upper bits``() =
    let dst = AST.extract reg64 8<rt> 0
    let src = num 8<rt> 1UL
    Assert.AreEqual<Stmt>(AST.assign dst src, (sized 8<rt> dst := src))

  (* A direct write to an extract is the write the lifter wrote, not a write
     of the register the extract reads: `AST.unwrap` walks through an extract,
     so deriving the size from the source would widen this one silently. *)
  [<TestMethod>]
  member _.``[AssignDSL] A direct write to an extract stays partial``() =
    let dst = AST.extract reg64 32<rt> 0
    let src = num 32<rt> 1UL
    Assert.AreEqual<Stmt>(AST.assign dst src, (direct dst := src))
    Assert.AreNotEqual<Stmt>(AST.assign reg64 (AST.zext 64<rt> src),
                             (direct dst := src))

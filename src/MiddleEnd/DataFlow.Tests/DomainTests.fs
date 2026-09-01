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


namespace B2R2.MiddleEnd.DataFlow.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.Intel
open B2R2.MiddleEnd.DataFlow

[<TestClass>]
type DomainTests() =
  let c (v: uint32) = ConstantDomain.Const(BitVector(v, 32<rt>))

  let c64 (v: uint64) = ConstantDomain.Const(BitVector(v, 64<rt>))

  let sp (v: uint32) = StackPointerDomain.ConstSP(BitVector(v, 32<rt>))

  let untouched r =
    Regular(Register.toRegID r)
    |> UntouchedValueDomain.RegisterTag
    |> UntouchedValueDomain.Untouched

  let eqC (expected: ConstantDomain.Lattice) actual =
    Assert.AreEqual<ConstantDomain.Lattice>(expected, actual)

  let eqU (expected: UntouchedValueDomain.Lattice) actual =
    Assert.AreEqual<UntouchedValueDomain.Lattice>(expected, actual)

  (* Each of these domains is a three-level lattice, so the same laws hold of
     all of them: join is a least upper bound, and subsume is its order. *)
  let checkLatticeLaws (join: 'a -> 'a -> 'a) subsume bottom top elems =
    for a in elems do
      Assert.AreEqual<'a>(a, join a a, "join is idempotent")
      Assert.AreEqual<'a>(a, join bottom a, "bottom is the unit of join")
      Assert.AreEqual<'a>(top, join top a, "top absorbs everything")
      for b in elems do
        Assert.AreEqual<'a>(join a b, join b a, "join commutes")
        Assert.AreEqual<bool>(join a b = a,
                              subsume a b,
                              "subsume is the order that join induces")
        for d in elems do
          Assert.AreEqual<'a>(join (join a b) d,
                              join a (join b d),
                              "join associates")

  [<TestMethod>]
  member _.``Constant domain lattice laws``() =
    [ ConstantDomain.Undef; c 0u; c 1u; c 42u; ConstantDomain.NotAConst ]
    |> checkLatticeLaws ConstantDomain.join
                        ConstantDomain.subsume
                        ConstantDomain.Undef
                        ConstantDomain.NotAConst

  [<TestMethod>]
  member _.``Stack pointer domain lattice laws``() =
    [ StackPointerDomain.Undef
      sp 0x80000000u
      sp 0x7ffffff8u
      StackPointerDomain.NotConstSP ]
    |> checkLatticeLaws StackPointerDomain.join
                        StackPointerDomain.subsume
                        StackPointerDomain.Undef
                        StackPointerDomain.NotConstSP

  [<TestMethod>]
  member _.``Untouched value domain lattice laws``() =
    [ UntouchedValueDomain.Undef
      untouched Register.EAX
      untouched Register.EBX
      UntouchedValueDomain.Untouched(UntouchedValueDomain.MemoryTag 0x100UL)
      UntouchedValueDomain.Touched ]
    |> checkLatticeLaws UntouchedValueDomain.join
                        UntouchedValueDomain.subsume
                        UntouchedValueDomain.Undef
                        UntouchedValueDomain.Touched

  [<TestMethod>]
  member _.``Constant domain binary operator propagation``() =
    (* Undef wins over NotAConst here: an operand we know nothing about yet
       leaves the result unknown too, rather than raising it to the top. *)
    let undef = ConstantDomain.Undef
    let notAConst = ConstantDomain.NotAConst
    let ops =
      [ ConstantDomain.add
        ConstantDomain.sub
        ConstantDomain.mul
        ConstantDomain.``and``
        ConstantDomain.``or``
        ConstantDomain.xor ]
    for op in ops do
      eqC undef (op undef (c 1u))
      eqC undef (op (c 1u) undef)
      eqC undef (op undef notAConst)
      eqC notAConst (op notAConst (c 1u))
      eqC notAConst (op (c 1u) notAConst)

  [<TestMethod>]
  member _.``Constant domain folds constant operands``() =
    eqC (c 5u) (ConstantDomain.add (c 2u) (c 3u))
    eqC (c 1u) (ConstantDomain.sub (c 3u) (c 2u))
    eqC (c 6u) (ConstantDomain.mul (c 2u) (c 3u))
    eqC (c 2u) (ConstantDomain.``and`` (c 6u) (c 3u))
    eqC (c 7u) (ConstantDomain.``or`` (c 6u) (c 3u))
    eqC (c 5u) (ConstantDomain.xor (c 6u) (c 3u))

  [<TestMethod>]
  member _.``Constant domain gives up on a division by zero``() =
    let divs =
      [ ConstantDomain.div
        ConstantDomain.sdiv
        ConstantDomain.``mod``
        ConstantDomain.smod ]
    for d in divs do
      eqC ConstantDomain.NotAConst (d (c 8u) (c 0u))
      eqC ConstantDomain.Undef (d ConstantDomain.Undef (c 0u))
    eqC (c 4u) (ConstantDomain.div (c 8u) (c 2u))
    eqC (c 2u) (ConstantDomain.``mod`` (c 8u) (c 3u))

  [<TestMethod>]
  member _.``Constant domain gives up on an oversized shift amount``() =
    let one = c64 1UL
    eqC (c64 4UL) (ConstantDomain.shl one (c64 2UL))
    eqC (c64 0UL) (ConstantDomain.shr one (c64 2UL))
    eqC ConstantDomain.NotAConst (ConstantDomain.shl one (c64 0x100000000UL))
    eqC ConstantDomain.NotAConst (ConstantDomain.shr one (c64 0x100000000UL))

  [<TestMethod>]
  member _.``Constant domain resolves an ite by its condition``() =
    eqC (c 1u) (ConstantDomain.ite (c 7u) (c 1u) (c 2u))
    eqC (c 2u) (ConstantDomain.ite (c 0u) (c 1u) (c 2u))
    let undef = ConstantDomain.Undef
    eqC undef (ConstantDomain.ite undef (c 1u) (c 2u))
    (* An unknown condition takes both branches, so a shared answer survives. *)
    let notAConst = ConstantDomain.NotAConst
    eqC notAConst (ConstantDomain.ite notAConst (c 1u) (c 2u))
    eqC (c 1u) (ConstantDomain.ite notAConst (c 1u) (c 1u))

  [<TestMethod>]
  member _.``Untouched value domain keeps only a shared origin``() =
    let eax = untouched Register.EAX
    let ebx = untouched Register.EBX
    eqU eax (UntouchedValueDomain.join eax eax)
    eqU UntouchedValueDomain.Touched (UntouchedValueDomain.join eax ebx)
    eqU eax (UntouchedValueDomain.join UntouchedValueDomain.Undef eax)
    eqU UntouchedValueDomain.Touched
        (UntouchedValueDomain.join eax UntouchedValueDomain.Touched)

  [<TestMethod>]
  member _.``Variable definition domain unions the definitions``() =
    let vp addr =
      { ProgramPoint = ProgramPoint(addr, 0)
        VarKind = Regular(Register.toRegID Register.EAX) }
    let addr = Some 0x10UL
    let m1 = VarDefDomain.store addr (vp 0x1UL) VarDefDomain.empty
    let m2 = VarDefDomain.store addr (vp 0x2UL) VarDefDomain.empty
    let joined = VarDefDomain.join m1 m2
    Assert.AreEqual<int>(2, VarDefDomain.load addr joined |> Set.count)
    Assert.AreEqual<int>(0, VarDefDomain.load (Some 0x20UL) joined |> Set.count)

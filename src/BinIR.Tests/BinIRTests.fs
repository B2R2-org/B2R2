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

namespace B2R2.BinIR.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

[<TestClass>]
type BinIRTests() =

  [<TestMethod>]
  member _.``Inline Optimization Test``() =
    let n1 = AST.num <| BitVector(1, 32<rt>)
    let n2 = AST.num <| BitVector(2, 32<rt>)
    let n3 = AST.num <| BitVector(3, 32<rt>)
    let e1 = AST.add (AST.mul n1 n2) n3
    let e2 = AST.sub (AST.mul n2 n3) n1
    Assert.AreEqual<Expr>(e1, e2)

  [<TestMethod>]
  member _.``Expr Commutative Equivalence Test 1``() =
    let n1 = AST.tmpvar 32<rt> 0
    let n2 = AST.tmpvar 32<rt> 1
    let e1 = AST.add n1 n2
    let e2 = AST.add n2 n1
    Assert.AreNotEqual(e1, e2)

  [<TestMethod>]
  member _.``Expr Commutative Equivalence Test 2``() =
    let n1 = AST.tmpvar 32<rt> 0
    let n2 = AST.tmpvar 32<rt> 1
    let n3 = AST.tmpvar 32<rt> 2
    let e1 = AST.mul n3 (AST.div n1 n2)
    let e2 = AST.mul (AST.div n1 n2) n3
    Assert.AreNotEqual(e1, e2)

  [<TestMethod>]
  member _.``Operand Order Test``() =
    (* Lifters take an operation apart by position -- the base register of an
       address is the left of its sum -- and which of two NaNs a float sum
       gives back depends on the order, so no commutative operation may have
       its operands reordered; one of the two orders here would be. *)
    let a = AST.tmpvar 64<rt> 0
    let b = AST.tmpvar 64<rt> 1
    let leftOf e =
      match e with
      | BinOp(Left = l)
      | RelOp(Left = l) -> l
      | _ -> Terminator.impossible ()
    [ AST.add
      AST.mul
      AST.``or``
      AST.xor
      AST.fadd
      AST.fmul
      AST.eq
      AST.neq ]
    |> List.iter (fun op ->
      Assert.AreEqual<bool>(true, obj.ReferenceEquals(a, leftOf (op a b)))
      Assert.AreEqual<bool>(true, obj.ReferenceEquals(b, leftOf (op b a))))

  [<TestMethod>]
  member _.``Raw Constructor Test``() =
    (* Each of these the AST would simplify away: an operation on constants
       folded, a cast to the type its operand has dropped, the arm a constant
       condition names taken. A pass that rebuilds a node around new operands
       needs the node it names. *)
    let n1 = AST.num <| BitVector(1, 32<rt>)
    let n2 = AST.num <| BitVector(2, 32<rt>)
    let x = AST.tmpvar 32<rt> 0
    let mode = AST.roundingMode RoundingMode.TowardZero
    let kindOf e =
      match e with
      | UnOp _ -> "UnOp"
      | BinOp _ -> "BinOp"
      | RelOp _ -> "RelOp"
      | Ite _ -> "Ite"
      | Cast _ -> "Cast"
      | Extract _ -> "Extract"
      | RoundCtrl _ -> "RoundCtrl"
      | _ -> "simplified"
    [ "UnOp", AST.Raw.unop UnOpType.NEG n1
      "BinOp", AST.Raw.binop BinOpType.ADD 32<rt> n1 n2
      "RelOp", AST.Raw.relop RelOpType.EQ n1 n2
      "Ite", AST.Raw.ite AST.b1 x n2
      "Cast", AST.Raw.cast CastKind.ZeroExt 32<rt> x
      "Extract", AST.Raw.extract n1 8<rt> 0
      "RoundCtrl", AST.Raw.roundCtrl mode n1 ]
    |> List.iter (fun (kind, e) -> Assert.AreEqual<string>(kind, kindOf e))

#if HASHCONS
  [<TestMethod>]
  member _.``Raw Constructor Sharing Test``() =
    (* A node built raw is the very node the AST builds where the AST
       simplifies nothing: one table holds both. *)
    let x = AST.tmpvar 32<rt> 0
    let y = AST.tmpvar 32<rt> 1
    let c = AST.lt x y
    [ AST.neg x, AST.Raw.unop UnOpType.NEG x
      AST.add x y, AST.Raw.binop BinOpType.ADD 32<rt> x y
      c, AST.Raw.relop RelOpType.LT x y
      AST.ite c x y, AST.Raw.ite c x y
      AST.zext 64<rt> x, AST.Raw.cast CastKind.ZeroExt 64<rt> x
      AST.extract x 8<rt> 8, AST.Raw.extract x 8<rt> 8 ]
    |> List.iter (fun (e, raw) ->
      Assert.AreEqual<bool>(true, obj.ReferenceEquals(e, raw)))

  [<TestMethod>]
  member _.``Hash Consing Hash Test``() =
    (* A node is interned under the hash its operands give, the one its own
       GetHashCode works out; any other would put nodes over different
       operands under one hash. *)
    let x = AST.tmpvar 32<rt> 0
    let y = AST.tmpvar 32<rt> 1
    [ AST.zext 64<rt> x
      AST.zext 64<rt> y
      AST.neg x
      AST.neg y
      AST.extract (AST.extract x 16<rt> 8) 8<rt> 4
      AST.extract (AST.extract y 16<rt> 8) 8<rt> 4 ]
    |> List.iter (fun e -> Assert.AreEqual<int>(e.GetHashCode(), e.Hash))
#endif

  [<TestMethod>]
  member _.``Side Effect Register Clobbering Test``() =
    let check expected eff =
      let msg = SideEffect.toString eff
      Assert.AreEqual<bool>(expected, SideEffect.mayClobberRegisters eff, msg)
    [ Fence; Delay; AtomicBegin; AtomicEnd; SaveWindow; FlushWindows ]
    |> List.iter (check false)
    [ SysCall
      Interrupt 0x80
      RestoreWindow
      ProcessorInfoRead
      Breakpoint
      ClockCounterRead None
      UndefinedInstruction
      UnsupportedInstruction
      Terminate ]
    |> List.iter (check true)

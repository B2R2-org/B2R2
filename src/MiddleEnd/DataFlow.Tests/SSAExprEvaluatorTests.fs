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
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd.Intel
open B2R2.MiddleEnd.DataFlow

[<TestClass>]
type SSAExprEvaluatorTests() =
  let var rt r id =
    { Kind = RegVar(rt, Register.toRegID r, Register.toString r)
      Identifier = id }

  let num (v: uint64) = Num(BitVector(v, 32<rt>))

  let binop op e1 e2 = BinOp(op, 32<rt>, e1, e2)

  let relop op e1 e2 = RelOp(op, 32<rt>, e1, e2)

  let findDefIn defs v =
    defs |> List.tryFind (function Def(d, _) -> d = v | _ -> false)

  /// Evaluates the given condition with the root holding each of the given
  /// values, telling for each whether the condition holds, if that is known.
  let evaluateAll defs root cond values =
    let evaluate value =
      SSAExprEvaluator.evaluate (findDefIn defs) root (Some value) 10 cond
    values
    |> List.map (fun value ->
      match evaluate value with
      | ConstantDomain.Const bv -> Some bv.IsTrue
      | _ -> None)

  [<TestMethod>]
  member _.``SSAExprEvaluator follows definitions to the root``() =
    (* lea eax, [edi-4]; cmp eax, 5; jbe takes its branch when edi is 4 to 9,
       as edi - 4 wraps around below 4. *)
    let edi, eax = var 32<rt> Register.EDI 1, var 32<rt> Register.EAX 2
    let cf, zf = var 1<rt> Register.CF 3, var 1<rt> Register.ZF 4
    let diff = binop BinOpType.SUB (Var eax) (num 5UL)
    let defs =
      [ Def(eax, binop BinOpType.ADD (Var edi) (num 0xfffffffcUL))
        Def(cf, relop RelOpType.LT (Var eax) (num 5UL))
        Def(zf, relop RelOpType.EQ diff (num 0UL)) ]
    let cond = BinOp(BinOpType.OR, 1<rt>, Var cf, Var zf)
    let actual = evaluateAll defs edi cond [ 3L; 4L; 9L; 10L ]
    let expected = [ Some false; Some true; Some true; Some false ]
    Assert.AreEqual<bool option list>(expected, actual)

  [<TestMethod>]
  member _.``SSAExprEvaluator evaluates a signed comparison``() =
    (* cmp edi, 4; jl takes its branch when SF differs from OF, which happens
       for 3 and for every negative value. *)
    let edi = var 32<rt> Register.EDI 1
    let sf, ofl = var 1<rt> Register.SF 2, var 1<rt> Register.OF 3
    let diff = binop BinOpType.SUB (Var edi) (num 4UL)
    let xorEdi e = binop BinOpType.XOR (Var edi) e
    let overflow = binop BinOpType.AND (xorEdi (num 4UL)) (xorEdi diff)
    let defs =
      [ Def(sf, Extract(diff, 1<rt>, 31))
        Def(ofl, Extract(overflow, 1<rt>, 31)) ]
    let cond = RelOp(RelOpType.NEQ, 1<rt>, Var sf, Var ofl)
    let actual = evaluateAll defs edi cond [ 3L; 4L; 0x80000000L ]
    let expected = [ Some true; Some false; Some true ]
    Assert.AreEqual<bool option list>(expected, actual)

  [<TestMethod>]
  member _.``SSAExprEvaluator takes a missing width from the reader``() =
    (* The IR data flow gives a stack slot no width. A copy into eax tells it,
       but a cast tells only the width it casts to. *)
    let slot = { Kind = StackVar(0<rt>, 4); Identifier = 1 }
    let eax = var 32<rt> Register.EAX 2
    let defs = [ Def(eax, Var slot) ]
    let copied = relop RelOpType.LT (Var eax) (num 4UL)
    let cast = Cast(CastKind.ZeroExt, 32<rt>, Var slot)
    let actual =
      evaluateAll defs slot copied [ 3L; 4L ]
      @ evaluateAll defs slot (relop RelOpType.LT cast (num 4UL)) [ 3L ]
    let expected = [ Some true; Some false; None ]
    Assert.AreEqual<bool option list>(expected, actual)

  [<TestMethod>]
  member _.``SSAExprEvaluator knows no slot read at another width``() =
    (* mov [rsp+0x70], rax spills eight bytes, and cmp dword [rsp+0x70], 9
       reads back four of them, which four depending on the byte order. *)
    let rax = var 64<rt> Register.RAX 1
    let slot = { Kind = StackVar(0<rt>, 0x70); Identifier = 2 }
    let temp = { Kind = TempVar(0<rt>, 1); Identifier = 3 }
    let defs = [ Def(slot, Var rax); Def(temp, Var slot) ]
    let compared = relop RelOpType.LT (Var temp) (num 9UL)
    let extended = Cast(CastKind.ZeroExt, 64<rt>, Var slot)
    let widened = RelOp(RelOpType.LT, 64<rt>, extended, Var rax)
    let actual =
      evaluateAll defs rax compared [ 5L ]
      @ evaluateAll defs rax widened [ 5L ]
    let expected = [ None; None ]
    Assert.AreEqual<bool option list>(expected, actual)

  [<TestMethod>]
  member _.``SSAExprEvaluator knows no result resting on an unknown``() =
    (* A comparison with a variable that has no definition, or with the root
       while it holds no value, is not a constant. *)
    let edi, ecx = var 32<rt> Register.EDI 1, var 32<rt> Register.ECX 2
    let withEcx = relop RelOpType.LT (Var edi) (Var ecx)
    let noValue =
      relop RelOpType.LT (Var edi) (num 4UL)
      |> SSAExprEvaluator.evaluate (findDefIn []) edi None 10
    let actual = evaluateAll [] edi withEcx [ 3L ], noValue
    let expected = [ None ], ConstantDomain.NotAConst
    Assert.AreEqual<bool option list * ConstantDomain.Lattice>(expected, actual)

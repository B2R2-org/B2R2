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

namespace B2R2.MiddleEnd.SymbEval.Tests

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.SymbEval

[<TestClass>]
type SMTLibPipelineTests() =
  let x8 = SymbExpr.Var("x", 8<rt>)

  let tmp8 = AST.tmpvar 8<rt> 0

  let num8 value = AST.num (BitVector(uint64 value, 8<rt>))

  let newState () =
    let state = SymbState()
    state.SetTmp(0, x8)
    state

  let normalize (s: string) =
    s.Replace("\r\n", "\n")

  let solverValue name (values: SolverValue list) =
    values
    |> List.find (fun v -> v.Name = name)
    |> fun v -> v.Value

  let translateLowUIR state expr =
    match SymbExprTranslator.translate state expr with
    | Ok expr -> expr
    | Error err -> Assert.Fail $"Failed to translate LowUIR: {err}"; failwith ""

  let translateAllLowUIR exprs =
    let state = newState ()
    exprs |> List.map (translateLowUIR state)

  let assertStatus expected text =
    match SolverOutputParser.parseStatus text with
    | Ok status -> Assert.AreEqual<SolverStatus>(expected, status)
    | Error err -> Assert.Fail $"Failed to parse status: {err}"

  [<TestMethod>]
  member _.``Serialize command-free assertion script``() =
    let state = newState ()
    let lowuirCond = AST.eq (AST.add tmp8 (num8 3)) (num8 10)
    let pathCondition = [ translateLowUIR state lowuirCond ]
    let values = [ translateLowUIR state tmp8 ]
    let actual =
      SMTLibSerializer.serializeAssertions pathCondition values |> normalize
    let expected =
      [ "(set-logic QF_BV)"
        "(declare-fun |x| () (_ BitVec 8))"
        "(assert (= (bvadd |x| (_ bv3 8)) (_ bv10 8)))"
        "" ]
      |> String.concat "\n"
    Assert.AreEqual<string>(expected, actual)

  [<TestMethod>]
  member _.``Serialize LowUIR bit-vector expression operators``() =
    let state = newState ()
    let concat = AST.concat (num8 0x12) tmp8
    let extract = translateLowUIR state (AST.extract concat 8<rt> 0)
    let extended = translateLowUIR state (AST.zext 16<rt> tmp8)
    let ite =
      AST.ite (AST.eq tmp8 (num8 7)) (num8 1) (num8 0)
      |> translateLowUIR state
    Assert.AreEqual<string>("((_ extract 7 0) (concat (_ bv18 8) |x|))",
                            SMTLibSerializer.serializeExpr extract)
    Assert.AreEqual<string>("((_ zero_extend 8) |x|)",
                            SMTLibSerializer.serializeExpr extended)
    Assert.AreEqual<string>("(ite (= |x| (_ bv7 8)) (_ bv1 8) (_ bv0 8))",
                            SMTLibSerializer.serializeExpr ite)

  [<TestMethod>]
  member _.``Parse raw solver status text``() =
    assertStatus Sat "sat\n"
    assertStatus Unsat " unsat \r\n"
    assertStatus Unknown "unknown"
    assertStatus Sat "SATISFIABLE"
    assertStatus Unsat "UNSATISFIABLE\n"
    assertStatus Unknown " UNKNOWN "

  [<TestMethod>]
  member _.``Reject model query for non-variable expression``() =
    let one = SymbExpr.Const(BitVector.One 8<rt>)
    let value = SymbExpr.binop BinOpType.ADD 8<rt> x8 one
    match SolverOutputParser.extract [ value ] "" with
    | Error(SolverFailure(SolverSerializationFailure _)) -> ()
    | Ok output -> Assert.Fail $"Unexpected model extraction: {output}"
    | Error err -> Assert.Fail $"Unexpected error kind: {err}"

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

module B2R2.FrontEnd.Tests.Optimizer

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp

[<AutoOpen>]
module TestHelper =
  let num v = BitVector.OfUInt32 v 32<rt> |> AST.num

  let t32 id = AST.tmpvar 32<rt> id

  let ismark = AST.ismark 1u

  let iemark = AST.iemark 1u

  let varA = AST.var 32<rt> (RegisterID.create 0) "A"

  let varB = AST.var 32<rt> (RegisterID.create 1) "B"

  let varC = AST.var 32<rt> (RegisterID.create 2) "C"

  let wrapStmts stmts = [| ismark; yield! stmts; iemark |]

  let test optimizeFn (expectedStmts, givenStmts) =
    let optimizedStmts = optimizeFn <| wrapStmts givenStmts
    CollectionAssert.AreEqual (wrapStmts expectedStmts, optimizedStmts)

[<TestClass>]
type ConstantFoldingTest () =
  [<TestMethod>]
  member __.``[ConstantFolding] Binary operator replacement test`` () =
    ([ varA := num 30u
       varB := num 3u
       varC := num 12u ],
     [ varA := num 30u
       varB := num 9u .- (varA ./ num 5u)
       varC := varB .* num 4u ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member __.``[ConstantFolding] ite replacement test`` () =
    ([ varC := num 12u
       varC := num 2u ],
     [ varC := num 12u
       varC := AST.ite (varC .> num 10u) (varC .- num 10u) varC ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member __.``[ConstantFolding] Tempvar replacement test`` () =
    ([ t32 1 := num 6u
       varA := varA .- num 4u
       AST.loadLE 32<rt> varA := varB
       AST.loadLE 32<rt> varA := varB
       varA := varA .- num 0x6u ],
     [ t32 1 := num 6u
       varA := varA .- num 4u
       AST.loadLE 32<rt> varA := varB
       AST.loadLE 32<rt> varA := varB
       varA := varA .- t32 1 ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member __.``[ConstantFolding] Condition jump replacement test`` () =
    let ir = IRBuilder 42
    let lblTarget = !%ir "Target"
    let lblImpossible = !%ir "Impossible"
    let lblEnd = !%ir "End"
    ([ varA := num 1u
       AST.jmp (AST.name lblTarget)
       AST.lmark lblImpossible
       varB := num 0u
       AST.lmark lblTarget
       varB := num 1u
       AST.lmark lblEnd ],
     [ varA := num 1u
       AST.cjmp (varA == varA) (AST.name lblTarget) (AST.name lblImpossible)
       AST.lmark lblImpossible
       varB := num 0u
       AST.lmark lblTarget
       varB := num 1u
       AST.lmark lblEnd ])
    |> test ConstantFolding.optimize

[<TestClass>]
type DeadCodeEliminationTest () =
  [<TestMethod>]
  member __.``[DeadCodeElimination] Dead code removal test (1)`` () =
    ([ t32 1 := num 1u
       t32 2 := num 2u
       varA := t32 1 .+ t32 2 ],
     [ t32 1 := num 1u
       t32 2 := num 2u
       t32 3 := num 3u
       varA := t32 1 .+ t32 2 ])
    |> test DeadCodeElimination.optimize

  [<TestMethod>]
  member __.``[DeadCodeElimination] Dead code removal test (2)`` () =
    ([ varB := num 3u
       varA := t32 1 .+ t32 2 ],
     [ varB := num 1u
       varB := num 2u
       varB := num 3u
       varA := t32 1 .+ t32 2 ])
    |> test DeadCodeElimination.optimize

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

namespace B2R2.FrontEnd.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp

[<TestClass>]
type OptimizerTests() =
  let num v = BitVector(u32 = v, bitLen = 32<rt>) |> AST.num

  let t32 id = AST.tmpvar 32<rt> id

  let ismark = AST.ismark 1u

  let iemark = AST.iemark 1u

  let varA = AST.var 32<rt> (RegisterID.create 0) "A"

  let varB = AST.var 32<rt> (RegisterID.create 1) "B"

  let varC = AST.var 32<rt> (RegisterID.create 2) "C"

  let wrapStmts stmts = [| ismark; yield! stmts; iemark |]

  let test optimizeFn (expectedStmts, givenStmts) =
    let optimizedStmts = optimizeFn <| wrapStmts givenStmts
    CollectionAssert.AreEqual(wrapStmts expectedStmts, optimizedStmts)

  [<TestMethod>]
  member _.``[ConstantFolding] Binary operator replacement test``() =
    ([ varA := num 30u
       varB := num 3u
       varC := num 12u ],
     [ varA := num 30u
       varB := num 9u .- (varA ./ num 5u)
       varC := varB .* num 4u ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member _.``[ConstantFolding] ite replacement test``() =
    ([ varC := num 12u
       varC := num 2u ],
     [ varC := num 12u
       varC := AST.ite (varC .> num 10u) (varC .- num 10u) varC ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member _.``[ConstantFolding] ite false branch replacement test``() =
    ([ varA := num 5u
       varB := num 5u .+ varB ],
     [ varA := num 5u
       varB := AST.ite (varA .> num 10u) (num 1u) (varA .+ varB) ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member _.``[ConstantFolding] Redefined variable replacement test``() =
    ([ varA := num 1u
       varA := num 2u
       varB := num 2u ],
     [ varA := num 1u
       varA := num 2u
       varB := varA ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member _.``[ConstantFolding] Redefined tempvar replacement test``() =
    ([ t32 1 := num 1u
       t32 1 := num 2u
       varB := num 2u ],
     [ t32 1 := num 1u
       t32 1 := num 2u
       varB := t32 1 ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member _.``[ConstantFolding] Tempvar replacement test``() =
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
  member _.``[ConstantFolding] Condition jump replacement test``() =
    let stream = LowUIRStream()
    let lblTarget = stream.NewLabel "Target"
    let lblImpossible = stream.NewLabel "Impossible"
    let lblEnd = stream.NewLabel "End"
    ([ varA := num 1u
       AST.jmp (AST.jmpDest lblTarget)
       AST.lmark lblImpossible
       varB := num 0u
       AST.lmark lblTarget
       varB := num 1u
       AST.lmark lblEnd ],
     [ varA := num 1u
       AST.cjmp (varA == varA)
                (AST.jmpDest lblTarget)
                (AST.jmpDest lblImpossible)
       AST.lmark lblImpossible
       varB := num 0u
       AST.lmark lblTarget
       varB := num 1u
       AST.lmark lblEnd ])
    |> test ConstantFolding.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Plain copy replacement test``() =
    ([ t32 1 := varB
       varA := varB ],
     [ t32 1 := varB
       varA := t32 1 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Copy chain replacement test``() =
    ([ t32 1 := varB
       t32 2 := varB
       varA := varB ],
     [ t32 1 := varB
       t32 2 := t32 1
       varA := t32 2 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Redefined source kill test``() =
    ([ t32 1 := varB
       varB := varC
       varA := t32 1 ],
     [ t32 1 := varB
       varB := varC
       varA := t32 1 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Redefined destination kill test``() =
    ([ t32 1 := varB
       t32 1 := varC
       varA := varC ],
     [ t32 1 := varB
       t32 1 := varC
       varA := t32 1 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Self-referencing definition test``() =
    ([ varA := varA .+ num 1u
       varB := varA ],
     [ varA := varA .+ num 1u
       varB := varA ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Memory load is not propagated test``() =
    ([ t32 1 := AST.loadLE 32<rt> varB
       varA := t32 1 ],
     [ t32 1 := AST.loadLE 32<rt> varB
       varA := t32 1 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Small expression replacement test``() =
    ([ t32 1 := varB .+ num 8u
       varA := varB .+ num 8u ],
     [ t32 1 := varB .+ num 8u
       varA := t32 1 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Two-variable expression is kept test``() =
    ([ t32 1 := varB .+ varC
       varA := t32 1 ],
     [ t32 1 := varB .+ varC
       varA := t32 1 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] External call clears the map test``() =
    ([ t32 1 := varB
       AST.extCall (AST.app "f" [] 32<rt>)
       varA := t32 1 ],
     [ t32 1 := varB
       AST.extCall (AST.app "f" [] 32<rt>)
       varA := t32 1 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Clobbering side effect clears the map test``() =
    ([ t32 1 := varB
       AST.sideEffect SysCall
       varA := t32 1 ],
     [ t32 1 := varB
       AST.sideEffect SysCall
       varA := t32 1 ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Marker side effect keeps the map test``() =
    ([ t32 1 := varB
       AST.sideEffect AtomicBegin
       varA := varB
       AST.sideEffect AtomicEnd ],
     [ t32 1 := varB
       AST.sideEffect AtomicBegin
       varA := t32 1
       AST.sideEffect AtomicEnd ])
    |> test CopyPropagation.optimize

  [<TestMethod>]
  member _.``[CopyPropagation] Dead copy removal test``() =
    ([ varA := varB ],
     [ t32 1 := varB
       varA := t32 1 ])
    |> test (fun stmts ->
               CopyPropagation.optimize stmts |> DeadCodeElimination.optimize)

  [<TestMethod>]
  member _.``[DeadCodeElimination] Dead code removal test (1)``() =
    ([ t32 1 := num 1u
       t32 2 := num 2u
       varA := t32 1 .+ t32 2 ],
     [ t32 1 := num 1u
       t32 2 := num 2u
       t32 3 := num 3u
       varA := t32 1 .+ t32 2 ])
    |> test DeadCodeElimination.optimize

  [<TestMethod>]
  member _.``[DeadCodeElimination] Dead code removal test (2)``() =
    ([ varB := num 3u
       varA := t32 1 .+ t32 2 ],
     [ varB := num 1u
       varB := num 2u
       varB := num 3u
       varA := t32 1 .+ t32 2 ])
    |> test DeadCodeElimination.optimize

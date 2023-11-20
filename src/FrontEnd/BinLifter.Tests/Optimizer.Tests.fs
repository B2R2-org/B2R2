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
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open type Register

[<AutoOpen>]
type Expr =
  static member Num (integer: uint32) =
    BitVector.OfUInt32 integer 32<rt> |> AST.num

  static member T32 (id: int) =
    AST.tmpvar 32<rt> id

[<AutoOpen>]
type Optimization =
  static member DeadCodeElimination =
    DeadCodeElimination.optimize

  static member ConstantFolding =
    ConstantFolding.optimize

[<AutoOpen>]
module TestHelper =
  let isa = ISA.Init Architecture.IntelX86 Endian.Little

  let ctxt = IntelTranslationContext isa

  let appendImarkToStmts stmts =
    stmts
    |> List.insertAt 0 (AST.ismark 1u)
    |> List.insertAt (stmts.Length + 1) (AST.iemark 1u)

  let inline ( ++ ) (optStmts: list<Stmt>) baseStmts =
    appendImarkToStmts optStmts, Array.ofList <| appendImarkToStmts baseStmts

  let inline ( !. ) name = Register.toRegID name |> ctxt.GetRegVar

  let rec breakByMark acc (stmts: Stmt []) idx =
    if idx < stmts.Length then
      match stmts[idx].S with
      | ISMark (_)
      | LMark (_) ->
        let left, right = Array.splitAt idx stmts
        breakByMark (left :: acc) right 1
      | _ ->
        breakByMark acc stmts (idx + 1)
    else List.rev (stmts :: acc) |> List.toArray

  let breakIntoBlocks (stmts: Stmt []) =
    if Array.isEmpty stmts then [| stmts |]
    else breakByMark [] stmts 1

  let trimIEMark (stmts: Stmt []) =
    let last = stmts[stmts.Length - 1].S
    let secondLast = stmts[stmts.Length - 2].S
    match secondLast, last with
    | InterJmp _, IEMark _
    | InterCJmp _, IEMark _ ->
      Array.sub stmts 0 (stmts.Length - 1)
    | _ -> stmts

  let test optimizeKind (expectedStmts, actualStmts: Stmt[]) =
    let optimizedStmts =
      actualStmts
      |> trimIEMark
      |> breakIntoBlocks
      |> Array.collect (optimizeKind)
      |> List.ofArray
    Assert.AreEqual (expectedStmts, optimizedStmts)

[<TestClass>]
type ConstantFoldingTest () =
  [<TestMethod>]
  member __.``[ConstantFolding] Binary operator replace test`` () =
    [ !.EAX := Num 0x1eu
      !.EBX := Num 0x3u
      !.ECX := Num 0xcu ]
    ++ [ !.EAX := Num 0x1eu
         !.EBX := Num 0x9u .- (!.EAX ./ Num 0x5u)
         !.ECX := !.EBX .* Num 0x4u ]
    |> test ConstantFolding

  [<TestMethod>]
  member __.``[ConstantFolding] ite replace test`` () =
    [ !.ECX := Num 0xcu
      !.ECX := Num 0x2u ]
    ++ [ !.ECX := Num 0xcu
         !.ECX := AST.ite (!.ECX .> Num 0xau) (!.ECX .- Num 0xau) !.ECX ]
    |> test ConstantFolding

  [<TestMethod>]
  member __.``[ConstantFolding] Tempvar replace test`` () =
    [ T32 1 := Num 0x6u
      !.ESP := !.ESP .- Num 0x4u
      AST.loadLE 32<rt> !.ESP := !.EBP
      AST.loadLE 32<rt> !.ESP := !.EBP
      !.ESP := !.ESP .- Num 0x6u ]
    ++ [ T32 1 := Num 0x6u
         !.ESP := !.ESP .- Num 0x4u
         AST.loadLE 32<rt> !.ESP := !.EBP
         AST.loadLE 32<rt> !.ESP := !.EBP
         !.ESP := !.ESP .- T32 1 ]
    |> test ConstantFolding

  [<TestMethod>]
  member __.``[ConstantFolding] Condition jump replace test`` () =
    let ir = !*ctxt
    let lblTarget = !%ir "Target"
    let lblImpossible = !%ir "Impossible"
    let lblEnd = !%ir "End"
    [ !.EAX := Num 0x1u
      AST.jmp (AST.name lblTarget)
      AST.lmark lblImpossible
      !.EBX := Num 0x0u
      AST.lmark lblTarget
      !.EBX := Num 0x1u
      AST.lmark lblEnd ]
    ++ [ !.EAX := Num 0x1u
         AST.cjmp (!.EAX == !.EAX) (AST.name lblTarget) (AST.name lblImpossible)
         AST.lmark lblImpossible
         !.EBX := Num 0x0u
         AST.lmark lblTarget
         !.EBX := Num 0x1u
         AST.lmark lblEnd ]
    |> test ConstantFolding

[<TestClass>]
type DeadCodeEliminationTest () =
  [<TestMethod>]
  member __.``[DeadCodeElimination] Dead code remove test (1)`` () =
    [ T32 1 := Num 0x1u
      T32 2 := Num 0x2u
      !.EAX := T32 1 .+ T32 2 ]
    ++ [ T32 1 := Num 0x1u
         T32 2 := Num 0x2u
         T32 3 := Num 0x3u
         !.EAX := T32 1 .+ T32 2 ]
    |> test DeadCodeElimination

  [<TestMethod>]
  member __.``[DeadCodeElimination] Dead code remove test (2)`` () =
    [ !.EBX := Num 0x3u
      !.EAX := T32 1 .+ T32 2 ]
    ++ [ !.EBX := Num 0x1u
         !.EBX := Num 0x2u
         !.EBX := Num 0x3u
         !.EAX := T32 1 .+ T32 2 ]
    |> test DeadCodeElimination

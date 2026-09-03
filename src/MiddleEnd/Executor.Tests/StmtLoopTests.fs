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

namespace B2R2.MiddleEnd.Executor.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.Executor

/// Stands in for an evaluation state, holding only what the loop reads.
type private FakeCursor() =
  let mutable stmtIdx = 0
  let mutable isInstrTerminated = false

  member _.Idx with get() = stmtIdx and set i = stmtIdx <- i

  member _.Terminate() = isInstrTerminated <- true

  interface IStmtCursor with

    member _.StmtIdx = stmtIdx

    member _.IsInstrTerminated = isInstrTerminated

[<TestClass>]
type StmtLoopTests() =
  let stmts = Array.init 3 (fun _ -> AST.ismark 4u)

  [<TestMethod>]
  member _.``Every statement of the instruction reaches the step``() =
    let seen = ResizeArray()
    let step (st: FakeCursor) _ =
      seen.Add st.Idx
      st.Idx <- st.Idx + 1
    StmtLoop.run step StmtLoop.carryOn (FakeCursor()) stmts |> ignore
    CollectionAssert.AreEqual([| 0; 1; 2 |], seen.ToArray())

  [<TestMethod>]
  member _.``The loop reads the statement the cursor names``() =
    let seen = ResizeArray()
    let step (st: FakeCursor) _ =
      seen.Add st.Idx
      st.Idx <- st.Idx + 2
    StmtLoop.run step StmtLoop.carryOn (FakeCursor()) stmts |> ignore
    CollectionAssert.AreEqual([| 0; 2 |], seen.ToArray())

  [<TestMethod>]
  member _.``A statement that ends the instruction ends the loop``() =
    let step (st: FakeCursor) _ =
      st.Idx <- st.Idx + 1
      st.Terminate()
    match StmtLoop.run step StmtLoop.carryOn (FakeCursor()) stmts with
    | Completed st -> Assert.AreEqual<int>(1, st.Idx)
    | Interrupted _ -> Assert.Fail "The loop reported an interruption."

  [<TestMethod>]
  member _.``The loop hands back the outcome that interrupted it``() =
    let step (st: FakeCursor) _ =
      st.Idx <- st.Idx + 1
      if st.Idx = 2 then Error "stopped" else Ok()
    match StmtLoop.run step StmtLoop.whileOk (FakeCursor()) stmts with
    | Interrupted outcome ->
      Assert.AreEqual<Result<unit, string>>(Error "stopped", outcome)
    | Completed _ ->
      Assert.Fail "The loop ran to the end of the instruction."

  [<TestMethod>]
  member _.``The loop carries on with the state the outcome names``() =
    let switched = FakeCursor()
    let step (st: FakeCursor) _ =
      switched.Idx <- st.Idx + 1
      switched
    let next _ (st: FakeCursor) = ValueSome st
    match StmtLoop.run step next (FakeCursor()) stmts with
    | Completed st -> Assert.AreSame(switched, st)
    | Interrupted _ -> Assert.Fail "The loop reported an interruption."

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

namespace B2R2.MiddleEnd.SymEval.Tests

open System
open System.ComponentModel
open System.Diagnostics
open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.SymEval

[<TestClass>]
type SMTLibPipelineTests() =
  let x8 = SymExpr.Var("x", 8<rt>)

  let tmp8 = AST.tmpvar 8<rt> 0

  let num8 value = AST.num (BitVector(uint64 value, 8<rt>))

  let newState () =
    let state = SymState()
    state.SetTmp(0, x8)
    state

  let normalize (s: string) =
    s.Replace("\r\n", "\n")

  let parseZ3 stdout =
    match Z3OutputParser.parse stdout with
    | Ok output -> output
    | Error err -> Assert.Fail $"Failed to parse z3 output: {err}"; failwith ""

  let solverValue name (values: SolverValue list) =
    values
    |> List.find (fun v -> v.Name = name)
    |> fun v -> v.Value

  let translateLowUIR state expr =
    match SymExprTranslator.translate state expr with
    | Ok expr -> expr
    | Error err -> Assert.Fail $"Failed to translate LowUIR: {err}"; failwith ""

  let translateAllLowUIR exprs =
    let state = newState ()
    exprs |> List.map (translateLowUIR state)

  let tryRunZ3 (smtlib: string) =
    let z3Path =
      match Environment.GetEnvironmentVariable "Z3_PATH" with
      | null | "" -> "z3"
      | path -> path
    let fileName = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.smt2")
    File.WriteAllText(fileName, smtlib)
    try
      let startInfo = ProcessStartInfo()
      startInfo.FileName <- z3Path
      startInfo.Arguments <- $"\"{fileName}\""
      startInfo.UseShellExecute <- false
      startInfo.RedirectStandardOutput <- true
      startInfo.RedirectStandardError <- true
      startInfo.CreateNoWindow <- true
      try
        use proc = Process.Start startInfo
        if isNull proc then None
        else
          if proc.WaitForExit 5000 then
            Some(proc.ExitCode, proc.StandardOutput.ReadToEnd(),
                 proc.StandardError.ReadToEnd())
          else
            proc.Kill true
            Assert.Fail "z3 did not finish within 5 seconds."
            None
      with
      | :? Win32Exception -> None
    finally
      if File.Exists fileName then File.Delete fileName

  let runZ3OrInconclusive smtlib =
    match tryRunZ3 smtlib with
    | Some result -> result
    | None ->
      Assert.Inconclusive "z3 was not found. Set Z3_PATH or add z3 to PATH."
      failwith ""

  [<TestMethod>]
  member _.``Serialize LowUIR path condition``() =
    let lowuirCond = AST.eq (AST.add tmp8 (num8 3)) (num8 10)
    let pathCondition = translateAllLowUIR [ lowuirCond ]
    let actual =
      SMTLibSerializer.serializePathCondition pathCondition |> normalize
    let expected =
      [ "(set-logic QF_BV)"
        "(declare-fun |x| () (_ BitVec 8))"
        "(assert (= (bvadd |x| (_ bv3 8)) (_ bv10 8)))"
        "(check-sat)"
        "(get-model)"
        "" ]
      |> String.concat "\n"
    Assert.AreEqual<string>(expected, actual)

  [<TestMethod>]
  member _.``Serialize LowUIR get-value query``() =
    let state = newState ()
    let lowuirCond = AST.eq (AST.add tmp8 (num8 3)) (num8 10)
    let pathCondition = [ translateLowUIR state lowuirCond ]
    let values = [ translateLowUIR state tmp8 ]
    let actual =
      SMTLibSerializer.serializeValueQuery pathCondition values |> normalize
    let expected =
      [ "(set-logic QF_BV)"
        "(declare-fun |x| () (_ BitVec 8))"
        "(assert (= (bvadd |x| (_ bv3 8)) (_ bv10 8)))"
        "(check-sat)"
        "(get-value (|x|))"
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
  member _.``Z3 returns sat for LowUIR path condition``() =
    let state = newState ()
    let lowuirCond = AST.eq (AST.add tmp8 (num8 3)) (num8 10)
    let pathCondition = [ translateLowUIR state lowuirCond ]
    let values = [ translateLowUIR state tmp8 ]
    let smtlib = SMTLibSerializer.serializeValueQuery pathCondition values
    let exitCode, stdout, stderr = runZ3OrInconclusive smtlib
    Assert.AreEqual<int>(0, exitCode, stderr)
    let output = parseZ3 stdout
    Assert.AreEqual<SolverStatus>(Sat, output.Status)
    Assert.AreEqual<uint64>(7UL,
                            solverValue "x" output.Values
                            |> BitVector.ToUInt64)

  [<TestMethod>]
  member _.``Z3 returns unsat for contradictory LowUIR path condition``() =
    let state = newState ()
    let pathCondition =
      [ AST.eq tmp8 (num8 7)
        AST.eq tmp8 (num8 8) ]
      |> List.map (translateLowUIR state)
    let values = [ translateLowUIR state tmp8 ]
    let smtlib = SMTLibSerializer.serializeValueQuery pathCondition values
    let _, stdout, _ = runZ3OrInconclusive smtlib
    let output = parseZ3 stdout
    Assert.AreEqual<SolverStatus>(Unsat, output.Status)
    Assert.AreEqual<int>(0, output.Values.Length)

  [<TestMethod>]
  member _.``Z3 accepts serialized LowUIR path condition``() =
    let pathCondition =
      [ AST.eq (AST.add tmp8 (num8 3)) (num8 10)
        AST.lt tmp8 (num8 20)
        AST.eq (AST.extract (AST.zext 16<rt> tmp8) 8<rt> 0) tmp8 ]
      |> translateAllLowUIR
    let smtlib = SMTLibSerializer.serializePathCondition pathCondition
    let exitCode, stdout, stderr = runZ3OrInconclusive smtlib
    Assert.AreEqual<int>(0, exitCode, stderr)
    Assert.IsTrue(stdout.StartsWith("sat", StringComparison.Ordinal),
                  $"Unexpected z3 output: {stdout}{stderr}")

  [<TestMethod>]
  member _.``Reject malformed get-value output``() =
    match Z3OutputParser.parse "sat\n((|x| true))\n" with
    | Ok output -> Assert.Fail $"Unexpected parse success: {output}"
    | Error(SolverFailure _) -> ()
    | Error err -> Assert.Fail $"Unexpected error kind: {err}"

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

namespace B2R2.RearEnd.Repl

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ConcEval

type ParserState =
  | LowUIRParser
  | BinParser of Architecture

type ReplState(isa: ISA, regFactory: IRegisterFactory, doFiltering) =
  let rstate = EvalState()
  let mutable parser = BinParser isa.Arch
  do
    rstate.SideEffectEventHandler <-
      (fun e st -> printfn $"[*] Unhandled side-effect ({e}) encountered"
                   st.IsInstrTerminated <- true)
    regFactory.GetAllRegVars()
    |> Array.map (fun r ->
      (regFactory.GetRegisterID r, BitVector(0, Expr.TypeOf r)))
    |> fun regs -> rstate.InitializeContext(0UL, regs)
  let mutable prevReg =
    rstate.Registers.ToArray()
    |> Array.map (fun (i, v) -> RegisterID.create i, v)
  let mutable prevTmp = rstate.Temporaries.ToArray()
  let generalRegs =
    regFactory.GetGeneralRegVars()
    |> Array.map regFactory.GetRegisterID
    |> Set.ofArray

  let tryEvaluate stmt st =
    try Evaluator.evalStmt st stmt
    with _ ->
      if st.IgnoreUndef then st.NextStmt()
      else failwith "Undefined expression encountered."

  /// Evaluates a sequence of statements, assuming that the statements are
  /// lifted from a single instruction.
  let rec evalStmts stmts (st: EvalState) =
    let idx = st.StmtIdx
    let numStmts = Array.length stmts
    if numStmts > idx then
      if st.IsInstrTerminated then
        if st.NeedToEvaluateIEMark then
          let stmt = stmts[numStmts - 1]
          tryEvaluate stmt st
        else ()
      else
        let stmt = stmts[idx]
        tryEvaluate stmt st
        evalStmts stmts st
    else ()

  member private _.EvaluateStmts(stmts: Stmt[]) =
    rstate.PrepareInstrEval stmts
    evalStmts stmts rstate

  member private _.ComputeDelta(prev, curr) =
    Array.fold2 (fun acc t1 t2 ->
      if t1 <> t2 then fst t1 :: acc else acc
    ) [] prev curr

  /// Update the state and return deltas.
  member this.Update stmts =
    try this.EvaluateStmts stmts
    with exc -> printfn "%s" exc.Message
    let currReg =
      rstate.Registers.ToArray()
      |> Array.map (fun (i, v) -> RegisterID.create i, v)
    let currTmp = rstate.Temporaries.ToArray()
    let regdelta = this.ComputeDelta(prevReg, currReg)
    prevReg <- currReg
    prevTmp <- currTmp
    regdelta

  member private _.Filter regPairs =
    if doFiltering then
      regPairs
      |> List.filter (fun (r, _) -> Set.contains r generalRegs)
    else regPairs

  member this.GetAllRegValString delta =
    let set = Set.ofList delta
    prevReg
    |> Seq.toList
    |> this.Filter
    |> List.map (fun (r, v) ->
      let regStr = regFactory.GetRegisterName r
      let regVal = v.ToString()
      regStr + ": " + regVal, Set.contains r set)

  /// Gets a temporary register name and EvalValue string representation.
  member private _.TempRegString(n: int, v) =
    $"T_{n}: {v.ToString()}"

  member this.GetAllTempValString delta =
    let set = Set.ofList delta
    prevTmp
    |> Seq.toList
    |> List.map (fun (id, v) -> this.TempRegString(id, v), Set.contains id set)

  member _.SwitchParser() =
    match parser with
    | BinParser _ -> parser <- LowUIRParser
    | LowUIRParser -> parser <- BinParser isa.Arch

  member _.CurrentParser with get() = parser

  member _.ConsolePrompt with get() =
    match parser with
    | BinParser arch -> arch.ToString() + "> "
    | LowUIRParser -> "LowUIR> "

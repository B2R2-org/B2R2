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

namespace B2R2.Utilities.Repl

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.ConcEval

type ReplState (regbay: RegisterBay, doFiltering) =
  let mutable state =
    regbay.GetAllRegExprs ()
    |> List.map (fun r ->
      (regbay.RegIDFromRegExpr r, BitVector.ofInt32 0 (LowUIR.AST.typeOf r)))
    |> List.map (fun (x, y) -> (x, Def y))
    |> EvalState.PrepareContext (EvalState ()) 0 0UL
  let mutable prevReg =
    (EvalState.GetCurrentContext state).Registers.ToSeq () |> Seq.toArray
  let mutable prevTmp =
    (EvalState.GetCurrentContext state).Temporaries.ToSeq () |> Seq.toArray
  let generalRegs =
    regbay.GetGeneralRegExprs ()
    |> List.map regbay.RegIDFromRegExpr
    |> Set.ofList

  member private __.EvaluateStmts (stmts: LowUIR.Stmt []) =
    stmts
    |> Array.fold (fun state stmt -> Evaluator.evalStmt state stmt) state

  member private __.ComputeDelta prev curr =
    Array.fold2 (fun acc t1 t2 ->
      if t1 <> t2 then fst t1 :: acc else acc
    ) [] prev curr

  /// Update the state and return deltas.
  member __.Update stmts =
    try state <- __.EvaluateStmts stmts
    with exc -> printfn "%s" exc.Message
    let currContext = EvalState.GetCurrentContext state
    let currReg = currContext.Registers.ToSeq () |> Seq.toArray
    let currTmp = currContext.Temporaries.ToSeq () |> Seq.toArray
    let regdelta = __.ComputeDelta prevReg currReg
    prevReg <- currReg
    prevTmp <- currTmp
    regdelta

  member private __.EvalValueToString v =
    match v with
    | Def bv -> bv.ToString ()
    | Undef -> "undef"

  member private __.Filter regPairs =
    if doFiltering then
      regPairs
      |> List.filter (fun (r, _) -> Set.contains r generalRegs)
    else regPairs

  member __.GetAllRegValString delta =
    let set = Set.ofList delta
    prevReg
    |> Seq.toList
    |> __.Filter
    |> List.map (fun (r, v) ->
      let regStr = regbay.RegIDToString r
      let regVal = __.EvalValueToString v
      regStr + ": " + regVal, Set.contains r set)

  /// Gets a temporary register name and EvalValue string representation.
  member private __.TempRegString (n: int) v =
    "T_" + string (n) + ": " + (__.EvalValueToString v)

  member __.GetAllTempValString delta =
    let set = Set.ofList delta
    prevTmp
    |> Seq.toList
    |> List.map (fun (id, v) -> __.TempRegString id v, Set.contains id set)

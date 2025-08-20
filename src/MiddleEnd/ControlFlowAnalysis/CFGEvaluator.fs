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

module B2R2.MiddleEnd.ControlFlowAnalysis.CFGEvaluator

open System
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.DataFlow.Constants

let private memoryReader (hdl: BinHandle) _pc addr typ _e =
  let len = RegType.toByteWidth typ
  let file = hdl.File
  if addr < UInt64.MaxValue && file.IsValidAddr addr then
    let ptr = hdl.File.GetBoundedPointer addr
    match hdl.TryReadBytes(ptr, len) with
    | Ok v -> Ok(BitVector v)
    | Error e -> Error e
  else Error ErrorCase.InvalidMemoryRead

let private stackAddr t = BitVector(InitialStackPointer, t)

let private obtainStackDef (hdl: BinHandle) =
  match hdl.RegisterFactory.StackPointer with
  | Some r -> [| r, hdl.File.ISA.WordSize |> WordSize.toRegType |> stackAddr |]
  | None -> [||]

let private obtainFramePointerDef (hdl: BinHandle) =
  match hdl.RegisterFactory.FramePointer with
  | Some r ->
    [| r, hdl.File.ISA.WordSize |> WordSize.toRegType |> BitVector.Zero |]
  | None -> [||]

let private initState hdl pc =
  let st = EvalState true
  st.LoadFailureEventHandler <- memoryReader hdl
  [| obtainStackDef hdl; obtainFramePointerDef hdl |]
  |> Array.concat
  |> fun regs -> st.InitializeContext(pc, regs)
  st

let private tryEvaluate stmt st =
  match SafeEvaluator.evalStmt st stmt with
  | Ok() -> Ok st
  | Error e ->
    if st.IgnoreUndef then st.NextStmt(); Ok st
    else Error e

/// Evaluate a sequence of statements, which is lifted from a single
/// instruction.
let rec private evalStmts stmts result =
  match result with
  | Ok(st: EvalState) ->
    let idx = st.StmtIdx
    let numStmts = Array.length stmts
    if numStmts > idx then
      if st.IsInstrTerminated then
        if st.NeedToEvaluateIEMark then tryEvaluate stmts[numStmts - 1] st
        else Ok st
      else
        let stmt = stmts[idx]
        evalStmts stmts (tryEvaluate stmt st)
    else Ok st
  | Error _ -> result

let rec private evalBlockLoop idx (blk: Stmt[][]) result =
  match result with
  | Ok(st: EvalState) ->
    if idx < blk.Length then
      let stmts = blk[idx]
      st.PrepareInstrEval stmts
      evalStmts stmts (Ok st)
      |> evalBlockLoop (idx + 1) blk
    else result
  | Error e -> Error e

/// Evaluates a series of statement arrays, assuming that each array is obtained
/// from a single machine instruction.
let private evalBlock (st: EvalState) pc blk =
  st.PC <- pc
  evalBlockLoop 0 blk (Ok st)
  |> function
    | Ok st -> Ok st
    | Error e -> Error e

/// Concretely evaluate a basic block from an arbitrarily generated state.
let evalBlockFromScratch hdl (blk: IVertex<LowUIRBasicBlock>) =
  let pc = blk.VData.Internals.PPoint.Address
  let st = initState hdl pc
  st.SideEffectEventHandler <- fun _ st -> st.AbortInstr()
  let stmts =
    blk.VData.Internals.LiftedInstructions |> Array.map (fun arr -> arr.Stmts)
  match evalBlock st pc stmts with
  | Ok st -> st
  | Error _ -> Terminator.impossible ()

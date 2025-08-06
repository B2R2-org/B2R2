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
    | Ok v -> Ok(BitVector.OfArr v)
    | Error e -> Error e
  else Error ErrorCase.InvalidMemoryRead

let private stackAddr t = BitVector.OfUInt64(InitialStackPointer, t)

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

/// Concretely evaluate a basic block from an arbitrarily generated state.
let evalBlockFromScratch hdl (blk: IVertex<LowUIRBasicBlock>) =
  let pc = blk.VData.Internals.PPoint.Address
  let st = initState hdl pc
  st.SideEffectEventHandler <- fun _ st -> st.AbortInstr()
  let stmts =
    blk.VData.Internals.LiftedInstructions |> Array.map (fun arr -> arr.Stmts)
  match SafeEvaluator.evalBlock st pc stmts with
  | Ok st -> st
  | Error _ -> Terminator.impossible ()

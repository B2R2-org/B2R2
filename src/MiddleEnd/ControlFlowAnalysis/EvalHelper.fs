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

module B2R2.MiddleEnd.ControlFlowAnalysis.EvalHelper

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ConcEval

let private memoryReader hdl _pc addr =
  let fileInfo = hdl.FileInfo
  if addr < System.UInt64.MaxValue && fileInfo.IsValidAddr addr then
    match BinHandle.TryReadBytes (hdl, addr, 1) with
    | Ok v -> Ok v.[0]
    | Error e -> Error e
  else Error ErrorCase.InvalidMemoryRead

let private stackAddr t = BitVector.ofInt32 0x1000000 t

let private obtainStackDef hdl =
  match hdl.RegisterBay.StackPointer with
  | Some r -> Some (r, hdl.ISA.WordSize |> WordSize.toRegType |> stackAddr)
  | None -> None

let private obtainFramePointerDef hdl =
  match hdl.RegisterBay.FramePointer with
  | Some r -> Some (r, hdl.ISA.WordSize |> WordSize.toRegType |> BitVector.zero)
  | None -> None

let private initState hdl pc =
  let st = EvalState (memoryReader hdl, true)
  [ obtainStackDef hdl; obtainFramePointerDef hdl ]
  |> List.choose id
  |> st.PrepareContext 0 pc
  st

let evalBlock hdl (blk: Vertex<IRBasicBlock>) =
  let pc = blk.VData.PPoint.Address
  let st = initState hdl pc
  st.Callbacks.SideEffectEventHandler <- fun _ st -> st.AbortInstr ()
  match blk.VData.IRStatements |> SafeEvaluator.evalBlock st pc 0 with
  | Ok st -> st
  | Error _ -> Utils.impossible ()

let evalFunctionUntilStopFn hdl (fn: RegularFunction) stopFn =
  let visited = HashSet<ProgramPoint> ()
  let rec evalLoop (blk: Vertex<IRBasicBlock>) st stopFn =
    let pp = blk.VData.PPoint
    if visited.Contains pp then None
    else
      visited.Add pp |> ignore
      let result =
        blk.VData.IRStatements
        |> SafeEvaluator.evalBlock st pp.Address 0
      match result with
      | Ok st' ->
        if stopFn blk then Some st'
        else
          match fn.TryFindVertex (ProgramPoint (st'.PC, 0)) with
          | Some v -> evalLoop v st' stopFn
          | None -> None
      | Error _ -> None
  let pc = fn.Entry
  let st = initState hdl pc
  let root = fn.FindVertex (ProgramPoint (pc, 0))
  evalLoop root st stopFn

let readReg (st: EvalState) regID =
  match st.TryGetReg regID with
  | Def v -> Some v
  | Undef -> None

let readMem (st: EvalState) addr endian size =
  let addr = BitVector.toUInt64 addr
  match st.Memory.Read st.PC addr endian size with
  | Ok bs -> BitVector.toUInt64 bs |> Some
  | Error _ -> None

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

module B2R2.MiddleEnd.EmulationHelper

open B2R2
open B2R2.FrontEnd
open B2R2.ConcEval
open B2R2.BinGraph
open B2R2.BinEssence
open System.Collections.Generic

let defZero t = Def (BitVector.zero t)
let stackAddr t = Def (BitVector.ofInt32 0x1000000 t)

let obtainStackDef hdl =
  match hdl.RegisterBay.StackPointer with
  | Some r -> Some (r, hdl.ISA.WordSize |> WordSize.toRegType |> stackAddr)
  | None -> None

let obtainFramePointerDef hdl =
  match hdl.RegisterBay.FramePointer with
  | Some r -> Some (r, hdl.ISA.WordSize |> WordSize.toRegType |> defZero)
  | None -> None

let initRegs hdl =
  [ obtainStackDef hdl; obtainFramePointerDef hdl ]
  |> List.choose id

let memoryReader hdl _pc addr =
  let fileInfo = hdl.FileInfo
  if addr < System.UInt64.MaxValue && fileInfo.IsValidAddr addr then
    match BinHandler.TryReadBytes (hdl, addr, 1) with
    | Some v -> Some v.[0]
    | None -> None
  else None

let eval (ess: BinEssence) (blk: Vertex<IRBasicBlock>) st stopFn =
  let visited = HashSet<ProgramPoint> ()
  let rec evalLoop (blk: Vertex<IRBasicBlock>) st stopFn =
    if visited.Contains blk.VData.PPoint then None
    else
      visited.Add blk.VData.PPoint |> ignore
      let st' =
        blk.VData.GetIRStatements ()
        |> Array.concat
        |> Evaluator.evalBlock st 0
      if stopFn blk.VData.LastInstruction then Some st'
      else
        match ess.FindVertex st'.PC with
        | None -> None
        | Some v -> evalLoop v st' stopFn
  evalLoop blk st stopFn

let readMem (st: EvalState) addr endian size =
  let addr = BitVector.toUInt64 addr
  match st.Memory.Read st.PC addr endian size with
  | Ok bs -> BitVector.toUInt64 bs |> Some
  | Error _ -> None

let readReg st regID =
  match EvalState.GetReg st regID with
  | Def v -> Some v
  | Undef -> None

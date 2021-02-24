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

module B2R2.MiddleEnd.Reclaimer.EmulationHelper

open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open System.Collections.Generic

let stackAddr t = BitVector.ofInt32 0x1000000 t

let obtainStackDef hdl =
  match hdl.RegisterBay.StackPointer with
  | Some r -> Some (r, hdl.ISA.WordSize |> WordSize.toRegType |> stackAddr)
  | None -> None

let obtainFramePointerDef hdl =
  match hdl.RegisterBay.FramePointer with
  | Some r -> Some (r, hdl.ISA.WordSize |> WordSize.toRegType |>BitVector.zero)
  | None -> None

let initRegs hdl =
  [ obtainStackDef hdl; obtainFramePointerDef hdl ]
  |> List.choose id

let memoryReader hdl _pc addr =
  let fileInfo = hdl.FileInfo
  if addr < System.UInt64.MaxValue && fileInfo.IsValidAddr addr then
    match BinHandle.TryReadBytes (hdl, addr, 1) with
    | Ok v -> Ok v.[0]
    | Error e -> Error e
  else Error ErrorCase.InvalidMemoryRead

let emptyMemoryReader _ _ _ = Error ErrorCase.InvalidMemoryRead

let eval (ess: BinEssence) (blk: Vertex<IRBasicBlock>) st stopFn =
  let visited = HashSet<ProgramPoint> ()
  let rec evalLoop (blk: Vertex<IRBasicBlock>) st stopFn =
    let pp = blk.VData.PPoint
    if visited.Contains pp then None
    else
      visited.Add pp |> ignore
      let result =
        blk.VData.GetIRStatements ()
        |> SafeEvaluator.evalBlock st pp.Address 0
      match result with
      | Ok st' ->
        if stopFn blk then Some st'
        else
          match ess.FindVertex st'.PC with
          | None -> None
          | Some v -> evalLoop v st' stopFn
      | Error _ -> None
  evalLoop blk st stopFn

let readMem (st: EvalState) addr endian size =
  let addr = BitVector.toUInt64 addr
  match st.Memory.Read st.PC addr endian size with
  | Ok bs -> BitVector.toUInt64 bs |> Some
  | Error _ -> None

let readReg (st: EvalState) regID =
  match st.TryGetReg regID with
  | Def v -> Some v
  | Undef -> None

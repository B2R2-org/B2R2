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

module B2R2.BinGraph.EmulationHelper

open B2R2
open B2R2.FrontEnd
open B2R2.ConcEval
open System.Collections.Generic

let defZero t = Def (BitVector.zero t)
let stackAddr t = Def (BitVector.ofInt32 0x1000000 t)

let initRegs hdl =
  match hdl.ISA.Arch with
  | Arch.IntelX86 ->
    [ (Intel.Register.ESP |> Intel.Register.toRegID, stackAddr 32<rt>)
      (Intel.Register.EBP |> Intel.Register.toRegID, defZero 32<rt>) ]
  | Arch.IntelX64 ->
    [ (Intel.Register.RSP |> Intel.Register.toRegID, stackAddr 64<rt>)
      (Intel.Register.RBP |> Intel.Register.toRegID, defZero 64<rt>) ]
  | Arch.AARCH32
  | Arch.ARMv7 ->
    [ (ARM32.Register.SP |> ARM32.Register.toRegID, stackAddr 32<rt>) ]
  | Arch.AARCH64 ->
    [ (ARM64.Register.SP |> ARM64.Register.toRegID, stackAddr 64<rt>) ]
  | _ -> []

let memoryReader hdl _pc addr =
  let fileInfo = hdl.FileInfo
  if fileInfo.IsValidAddr addr then
    let v = BinHandler.ReadBytes (hdl, addr, 1)
    Some <| v.[0]
  else None

let eval (scfg: SCFG) (blk: Vertex<IRBasicBlock>) st stopFn =
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
        match scfg.FindVertex st'.PC with
        | None -> None
        | Some v -> evalLoop v st' stopFn
  evalLoop blk st stopFn

let readMem (st: EvalState) addr endian size =
  let addr = BitVector.toUInt64 addr
  try st.Memory.Read st.PC addr endian size |> BitVector.toUInt64 |> Some
  with InvalidMemException -> None

let readReg st regID =
  match EvalState.GetReg st regID with
  | Def v -> Some v
  | Undef -> None

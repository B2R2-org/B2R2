(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Jaeseung Choi <jschoi17@kaist.ac.kr>

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

module B2R2.BinGraph.DisasHeuristic

open B2R2
open B2R2.FrontEnd
open B2R2.ConcEval

let private defZero t = Def (BitVector.zero t)
let private stackAddr t = Def (BitVector.ofInt32 0x1000000 t)

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

let rec eval (scfg: SCFG) (blk: Vertex<IRBasicBlock>) st callerAddr =
  let st' =
    blk.VData.GetIRStatements ()
    |> Array.concat
    |> Evaluator.evalBlock st 0
  if blk.VData.LastInstruction.Address = callerAddr then Some st'
  else
    match scfg.FindVertex st'.PC with
    | None -> None
    | Some v -> eval scfg v st' callerAddr

let readMem (st: EvalState) addr endian size =
  let addr = BitVector.toUInt64 addr
  try st.Memory.Read st.PC addr endian size |> BitVector.toUInt64 |> Some
  with InvalidMemException -> None

let readReg st regID =
  match EvalState.GetReg st regID with
  | Def v -> Some v
  | Undef -> None

let retrieveAddrsForx86 hdl app st =
  match EvalState.GetReg st (Intel.Register.ESP |> Intel.Register.toRegID) with
  | Def sp ->
    let p1 = BitVector.add (BitVector.ofInt32 4 32<rt>) sp
    let p4 = BitVector.add (BitVector.ofInt32 16 32<rt>) sp
    let p5 = BitVector.add (BitVector.ofInt32 20 32<rt>) sp
    let p6 = BitVector.add (BitVector.ofInt32 24 32<rt>) sp
    [ readMem st p1 Endian.Little 32<rt>
      readMem st p4 Endian.Little 32<rt>
      readMem st p5 Endian.Little 32<rt>
      readMem st p6 Endian.Little 32<rt> ]
    |> List.choose id
    |> List.filter (fun addr -> app.InstrMap.ContainsKey addr |> not)
    |> function
      | [] -> app
      | addrs -> BinaryApparatus.update hdl app addrs
  | Undef -> app

let retrieveAddrsForx64 hdl app st =
  [ readReg st (Intel.Register.RDI |> Intel.Register.toRegID)
    readReg st (Intel.Register.RCX |> Intel.Register.toRegID)
    readReg st (Intel.Register.R8 |> Intel.Register.toRegID)
    readReg st (Intel.Register.R9 |> Intel.Register.toRegID) ]
  |> List.choose id
  |> List.map (BitVector.toUInt64)
  |> List.filter (fun addr -> app.InstrMap.ContainsKey addr |> not)
  |> function
    | [] -> app
    | addrs -> BinaryApparatus.update hdl app addrs

let retrieveLibcStartAddresses hdl app = function
  | None -> app
  | Some st ->
    match hdl.ISA.Arch with
    | Arch.IntelX86 -> retrieveAddrsForx86 hdl app st
    | Arch.IntelX64 -> retrieveAddrsForx64 hdl app st
    | _ -> app

let analyzeLibcStartMain hdl (scfg: SCFG) app callerAddr =
  let st = EvalState (memoryReader hdl, true)
  let st = initRegs hdl |> EvalState.PrepareContext st 0 callerAddr
  match scfg.FindFunctionVertex callerAddr with
  | None -> app
  | Some root ->
    eval scfg root st callerAddr
    |> retrieveLibcStartAddresses hdl app

let recoverAddrsFromLibcStartMain hdl scfg app =
  match app.CalleeMap.Find "__libc_start_main" with
  | Some callee ->
    match List.tryExactlyOne callee.Callers with
    | None -> app
    | Some caller -> analyzeLibcStartMain hdl scfg app caller
  | None -> app

let recoverLibcEntries hdl scfg app =
  match hdl.FileInfo.FileFormat with
  | FileFormat.ELFBinary -> recoverAddrsFromLibcStartMain hdl scfg app
  | _ -> app

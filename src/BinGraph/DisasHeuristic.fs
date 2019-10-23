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

namespace B2R2.BinGraph

open B2R2
open B2R2.FrontEnd
open B2R2.ConcEval
open B2R2.BinGraph.EmulationHelper

module private LibcAnalysisHelper =

  let retrieveAddrsForx86 hdl app st =
    let esp = (Intel.Register.ESP |> Intel.Register.toRegID)
    match EvalState.GetReg st esp with
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
        | addrs ->
          addrs
          |> List.map (fun addr -> LeaderInfo.Init (hdl, addr))
          |> BinaryApparatus.update hdl app
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
      | addrs ->
        addrs
        |> List.map (fun addr -> LeaderInfo.Init (hdl, addr))
        |> BinaryApparatus.update hdl app

  let retrieveLibcStartAddresses hdl app = function
    | None -> app
    | Some st ->
      match hdl.ISA.Arch with
      | Arch.IntelX86 -> retrieveAddrsForx86 hdl app st
      | Arch.IntelX64 -> retrieveAddrsForx64 hdl app st
      | _ -> app

  let analyzeLibcStartMain hdl (scfg: SCFG) app callerAddr =
    match scfg.FindFunctionVertex callerAddr with
    | None -> app
    | Some root ->
      let st = EvalState (memoryReader hdl, true)
      let rootAddr = root.VData.PPoint.Address
      let st = initRegs hdl |> EvalState.PrepareContext st 0 rootAddr
      try
        eval scfg root st (fun last -> last.Address = callerAddr)
        |> retrieveLibcStartAddresses hdl app
      with _ -> app

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

type LibcAnalysis () =
  interface IPostAnalysis with
    member __.Run hdl scfg app =
      LibcAnalysisHelper.recoverLibcEntries hdl scfg app

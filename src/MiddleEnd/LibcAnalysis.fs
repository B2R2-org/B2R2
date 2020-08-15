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

namespace B2R2.MiddleEnd

open B2R2
open B2R2.FrontEnd
open B2R2.BinEssence
open B2R2.ConcEval
open B2R2.MiddleEnd.EmulationHelper

module private LibcAnalysisHelper =
  let retrieveAddrsForx86 (ess: BinEssence) st =
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
      |> List.filter (fun addr ->
        ess.InstrMap.ContainsKey addr |> not)
      |> function
        | [] -> ess
        | addrs ->
          let ctxt = ess.BinHandler.DefaultParsingContext
          let entries = addrs |> List.map (fun addr -> addr, ctxt)
          match BinEssence.addEntries ess entries with
          | Ok ess -> ess
          | _ -> Utils.impossible ()
    | Undef -> ess

  let retrieveAddrsForx64 (ess: BinEssence) st =
    [ readReg st (Intel.Register.RDI |> Intel.Register.toRegID)
      readReg st (Intel.Register.RCX |> Intel.Register.toRegID)
      readReg st (Intel.Register.R8 |> Intel.Register.toRegID)
      readReg st (Intel.Register.R9 |> Intel.Register.toRegID) ]
    |> List.choose id
    |> List.map BitVector.toUInt64
    |> List.filter (fun addr ->
      ess.InstrMap.ContainsKey addr |> not)
    |> function
      | [] -> ess
      | addrs ->
        let ctxt = ess.BinHandler.DefaultParsingContext
        let entries = addrs |> List.map (fun addr -> addr, ctxt)
        match BinEssence.addEntries ess entries with
        | Ok ess -> ess
        | _ -> Utils.impossible ()

  let retrieveLibcStartAddresses ess = function
    | None -> ess
    | Some st ->
      match ess.BinHandler.ISA.Arch with
      | Arch.IntelX86 -> retrieveAddrsForx86 ess st
      | Arch.IntelX64 -> retrieveAddrsForx64 ess st
      | _ -> ess

  let analyzeLibcStartMain (ess: BinEssence) callerAddr =
    match ess.FindFunctionVertex callerAddr with
    | None -> ess
    | Some root ->
      let hdl = ess.BinHandler
      let st = EvalState (memoryReader hdl, true)
      let rootAddr = root.VData.PPoint.Address
      let st = initRegs hdl |> EvalState.PrepareContext st 0 rootAddr
      eval ess root st (fun last -> last.Address = callerAddr)
      |> retrieveLibcStartAddresses ess

  let recoverAddrsFromLibcStartMain ess =
    match ess.CalleeMap.Find "__libc_start_main" with
    | Some callee ->
      match List.tryExactlyOne <| Set.toList callee.Callers with
      | None -> ess
      | Some caller -> analyzeLibcStartMain ess caller
    | None -> ess

  let recoverLibcEntries ess =
    match ess.BinHandler.FileInfo.FileFormat with
    | FileFormat.ELFBinary -> recoverAddrsFromLibcStartMain ess
    | _ -> ess

type LibcAnalysis () =
  interface IAnalysis with
    member __.Name = "LibC Analysis"

    member __.Run ess =
      LibcAnalysisHelper.recoverLibcEntries ess

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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.ControlFlowAnalysis.EvalHelper

module private LibcAnalysisHelper =
  let retrieveAddrsForx86 (builder: CFGBuilder) codeMgr st =
    let esp = (Intel.Register.ESP |> Intel.Register.toRegID)
    match (st: EvalState).TryGetReg esp with
    | Def sp ->
      let p1 = BitVector.Add (BitVector.OfInt32 4 32<rt>, sp)
      let p4 = BitVector.Add (BitVector.OfInt32 16 32<rt>, sp)
      let p5 = BitVector.Add (BitVector.OfInt32 20 32<rt>, sp)
      let p6 = BitVector.Add (BitVector.OfInt32 24 32<rt>, sp)
      [ readMem st p1 Endian.Little 32<rt>
        readMem st p4 Endian.Little 32<rt>
        readMem st p5 Endian.Little 32<rt>
        readMem st p6 Endian.Little 32<rt> ]
      |> List.choose id
      |> List.filter (fun addr ->
        addr <> 0UL && ((codeMgr: CodeManager).HasInstruction addr |> not))
      |> function
        | [] -> false
        | addrs ->
          let mode = ArchOperationMode.NoMode
          let entries = addrs |> List.map (fun addr -> addr, mode)
          match builder.AddNewFunctions entries with
          | Ok () -> true
          | _ -> Utils.impossible ()
    | Undef -> false

  let retrieveAddrsForx64 (builder: CFGBuilder) codeMgr st =
    [ readReg st (Intel.Register.RDI |> Intel.Register.toRegID)
      readReg st (Intel.Register.RCX |> Intel.Register.toRegID)
      readReg st (Intel.Register.R8 |> Intel.Register.toRegID)
      readReg st (Intel.Register.R9 |> Intel.Register.toRegID) ]
    |> List.choose id
    |> List.map BitVector.ToUInt64
    |> List.filter (fun addr ->
      addr <> 0UL && ((codeMgr: CodeManager).HasInstruction addr |> not))
    |> function
      | [] -> false
      | addrs ->
        let mode = ArchOperationMode.NoMode
        let entries = addrs |> List.map (fun addr -> addr, mode)
        match builder.AddNewFunctions entries with
        | Ok () -> true
        | _ -> Utils.impossible ()

  let retrieveLibcStartAddresses builder hdl codeMgr = function
    | None -> false
    | Some st ->
      match hdl.BinFile.ISA.Arch with
      | Arch.IntelX86 -> retrieveAddrsForx86 builder codeMgr st
      | Arch.IntelX64 -> retrieveAddrsForx64 builder codeMgr st
      | _ -> false

  let tryFindFunction (codeMgr: CodeManager) entry =
    match codeMgr.TryGetBBL entry with
    | Some bblInfo ->
      if bblInfo.FunctionEntry = entry then
        codeMgr.FunctionMaintainer.TryFindRegular entry
      else None
    | None -> None

  let analyzeLibcStartMain builder hdl codeMgr entry callSite =
    match tryFindFunction codeMgr entry with
    | None -> false
    | Some fn ->
      evalFunctionUntilStopFn hdl fn
        (fun blk -> blk.VData.Range.IsIncluding callSite)
      |> retrieveLibcStartAddresses builder hdl codeMgr

  let recoverAddrsFromLibcStartMain builder hdl (codeMgr: CodeManager) =
    match codeMgr.FunctionMaintainer.TryFind "__libc_start_main" with
    | Some func when func.FunctionKind = FunctionKind.External ->
      let _, trampoline = (func :?> ExternalFunction).TrampolineAddr ()
      let isLibcStartMain addr = addr = func.EntryPoint || addr = trampoline
      match List.tryExactlyOne <| Seq.toList func.Callers with
      | None -> false
      | Some caller ->
        let start = codeMgr.FunctionMaintainer.FindRegular (addr=caller)
        let callSite =
          start.CallEdges
          |> Array.find (fun (_, callee) ->
            match callee with
            | RegularCallee target -> isLibcStartMain target
            | IndirectCallees addrs -> Set.exists isLibcStartMain addrs
            | UnresolvedIndirectCallees (_) | NullCallee -> false)
          |> fst
        analyzeLibcStartMain builder hdl codeMgr start.EntryPoint callSite
    | _ -> false
    |> function
    | true -> PluggableAnalysisOk
    | false -> PluggableAnalysisError

  let recoverLibcEntries builder hdl codeMgr =
    match hdl.BinFile.FileFormat with
    | FileFormat.ELFBinary ->
      recoverAddrsFromLibcStartMain builder hdl codeMgr
    | _ -> PluggableAnalysisError

type LibcAnalysis () =
  interface IPluggableAnalysis with

    member __.Name = "LibC Analysis"

    member __.Run builder hdl codeMgr _dataMgr =
      LibcAnalysisHelper.recoverLibcEntries builder hdl codeMgr

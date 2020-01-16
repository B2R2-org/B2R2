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
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.ConcEval
open B2R2.BinGraph.EmulationHelper

module private LibcAnalysisHelper =

  let retrieveAddrsForx86 hdl corpus st =
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
      |> List.filter (fun addr -> corpus.InstrMap.ContainsKey addr |> not)
      |> function
        | [] -> corpus
        | addrs ->
          addrs
          |> List.map (fun addr -> LeaderInfo.Init (hdl, addr))
          |> BinCorpus.update hdl corpus
    | Undef -> corpus

  let retrieveAddrsForx64 hdl corpus st =
    [ readReg st (Intel.Register.RDI |> Intel.Register.toRegID)
      readReg st (Intel.Register.RCX |> Intel.Register.toRegID)
      readReg st (Intel.Register.R8 |> Intel.Register.toRegID)
      readReg st (Intel.Register.R9 |> Intel.Register.toRegID) ]
    |> List.choose id
    |> List.map (BitVector.toUInt64)
    |> List.filter (fun addr -> corpus.InstrMap.ContainsKey addr |> not)
    |> function
      | [] -> corpus
      | addrs ->
        addrs
        |> List.map (fun addr -> LeaderInfo.Init (hdl, addr))
        |> BinCorpus.update hdl corpus

  let retrieveLibcStartAddresses hdl corpus = function
    | None -> corpus
    | Some st ->
      match hdl.ISA.Arch with
      | Arch.IntelX86 -> retrieveAddrsForx86 hdl corpus st
      | Arch.IntelX64 -> retrieveAddrsForx64 hdl corpus st
      | _ -> corpus

  let analyzeLibcStartMain hdl (scfg: SCFG) corpus callerAddr =
    match scfg.FindFunctionVertex callerAddr with
    | None -> corpus
    | Some root ->
      let st = EvalState (memoryReader hdl, true)
      let rootAddr = root.VData.PPoint.Address
      let st = initRegs hdl |> EvalState.PrepareContext st 0 rootAddr
      try
        eval scfg root st (fun last -> last.Address = callerAddr)
        |> retrieveLibcStartAddresses hdl corpus
      with _ -> corpus

  let recoverAddrsFromLibcStartMain hdl scfg corpus =
    match corpus.CalleeMap.Find "__libc_start_main" with
    | Some callee ->
      match List.tryExactlyOne callee.Callers with
      | None -> corpus
      | Some caller -> analyzeLibcStartMain hdl scfg corpus caller
    | None -> corpus

  let recoverLibcEntries hdl scfg corpus =
    match hdl.FileInfo.FileFormat with
    | FileFormat.ELFBinary -> recoverAddrsFromLibcStartMain hdl scfg corpus
    | _ -> corpus

type LibcAnalysis () =
  interface IPostAnalysis with
    member __.Run hdl scfg corpus =
      LibcAnalysisHelper.recoverLibcEntries hdl scfg corpus

type EVMCodeCopyAnalysis () =
  let findCodeCopy stmts =
    stmts
    |> Array.tryPick (fun stmt ->
      match stmt with
      | Store (_, Num dst,
                  BinOp (BinOpType.APP, _len,
                         FuncName "code",
                         BinOp (BinOpType.CONS, _, Num src, _, _, _), _, _)) ->
        let dstAddr = BitVector.toUInt64 dst
        let srcAddr = BitVector.toUInt64 src
        let offset = srcAddr - dstAddr
        let pp = ProgramPoint (srcAddr, 0)
        LeaderInfo.Init (pp, ArchOperationMode.NoMode, offset) |> Some
      | _ -> None)

  let recoverCopiedCode hdl corpus =
    corpus.InstrMap
    |> Seq.fold (fun corpus (KeyValue (_, ins)) ->
      match ins.Stmts |> findCodeCopy with
      | None -> corpus
      | Some leader ->
        match corpus.CalleeMap.Find leader.Point.Address with
        | None -> BinCorpus.update hdl corpus [leader]
        | Some _ -> corpus) corpus

  interface IPostAnalysis with
    member __.Run hdl _scfg corpus =
      match hdl.FileInfo.ISA.Arch with
      | Architecture.EVM -> recoverCopiedCode hdl corpus
      | _ -> corpus


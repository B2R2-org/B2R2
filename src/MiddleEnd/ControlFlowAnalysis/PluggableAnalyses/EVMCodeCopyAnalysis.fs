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
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow

type EVMCodeCopyAnalysis () =
  let accumulateCodeCopyInfo (cpState: CPState<SCPValue>) (stmt: SSA.Stmt) acc =
    match stmt with
    | ExternalCall (
        BinOp (BinOpType.APP, _, FuncName "codecopy",
          BinOp (BinOpType.CONS, _, tmpVarDst,
            BinOp (BinOpType.CONS, _, tmpVarSrc,
              BinOp (BinOpType.CONS, _, tmpVarLen, _)))), _, _) ->
      let dst = tmpVarDst |> IRHelper.tryResolveExprToUInt64 cpState
      let src = tmpVarSrc |> IRHelper.tryResolveExprToUInt64 cpState
      let len = tmpVarLen |> IRHelper.tryResolveExprToUInt64 cpState
      (dst, src, len) :: acc
    | _ -> acc

  let rec pickValidCopyInfo (hdl: BinHandle) = function
    | (Some 0UL, Some src, Some len) :: restCopyInfos ->
      let binLen = uint64 hdl.File.Length
      let bin = hdl.File.Slice (offset=int src, size=int len)
      let srcEnd = src + len - 1UL
      if srcEnd < binLen then
        let newHdl = BinHandle (bin.ToArray (), hdl.File.ISA, None, false)
        PluggableAnalysisNewBinary newHdl
      else pickValidCopyInfo hdl restCopyInfos
    | _ :: restCopyInfos -> pickValidCopyInfo hdl restCopyInfos
    | _ -> failwith "Failed to find codecopy"

  let recoverCopiedCode hdl codeMgr =
    (codeMgr: CodeManager).FunctionMaintainer.RegularFunctions
    |> Seq.fold (fun acc fn ->
      let struct (cpState, ssaCFG) = PerFunctionAnalysis.runCP hdl fn None
      ssaCFG.FoldVertex (fun acc v ->
        v.VData.LiftedSSAStmts
        |> Array.fold (fun acc (_, stmt) ->
          accumulateCodeCopyInfo cpState stmt acc
        ) acc
      ) acc) []
    |> pickValidCopyInfo hdl

  interface IPluggableAnalysis with

    member __.Name = "EVM Code Copy Analysis"

    member __.Run _builder (hdl: BinHandle) codeMgr _jmpTbls =
      match hdl.File.ISA.Arch with
      | Architecture.EVM -> recoverCopiedCode hdl codeMgr
      | _ -> PluggableAnalysisOk

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
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.ControlFlowAnalysis

type EVMCodeCopyAnalysis () =
  let findCodeCopy hdl stmts =
    stmts
    |> Array.tryPick (fun stmt ->
      match stmt.S with
      | Store (_, { E = Num dst },
                  { E = BinOp (BinOpType.APP, _len,
                               { E = FuncName "code" },
                               { E = BinOp (BinOpType.CONS, _,
                                            { E = Num src }, _, _) }, _) }) ->
        let dstAddr = BitVector.toUInt64 dst
        let srcAddr = BitVector.toUInt64 src
        let offset = srcAddr - dstAddr
        (hdl.Parser :?> EVM.EVMParser).CodeOffset <- offset
        (srcAddr, ArchOperationMode.NoMode) |> Some
      | _ -> None)

  let recoverCopiedCode (builder: CFGBuilder) hdl codeMgr =
    (codeMgr: CodeManager).FoldInstructions (fun cont (KeyValue (_, ins)) ->
      match ins.Stmts |> findCodeCopy hdl with
      | None -> cont
      | Some (addr, mode) ->
        match codeMgr.FunctionMaintainer.TryFind addr with
        | None ->
          match builder.AddNewFunctions [(addr, mode)] with
          | Ok () -> true
          | Error _ -> Utils.impossible ()
        | Some _ -> cont) false

  interface IPluggableAnalysis with

    member __.Name = "EVM Code Copy Analysis"

    member __.Run builder hdl codeMgr _dataMgr =
      match hdl.FileInfo.ISA.Arch with
      | Architecture.EVM -> recoverCopiedCode builder hdl codeMgr
      | _ -> false

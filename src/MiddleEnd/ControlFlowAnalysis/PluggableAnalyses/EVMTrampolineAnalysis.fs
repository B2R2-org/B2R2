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

open FSharp.Data
open FSharp.Data.JsonExtensions
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface

[<AutoOpen>]
module private EVMTrampolineAnalysis =
  let computeKeccak256 (keccak: SHA3Core.Keccak.Keccak) (str: string) =
    let hashStr = (keccak.Hash str)[ 0 .. 7 ]
    System.UInt32.Parse (hashStr, System.Globalization.NumberStyles.HexNumber)

  // Parse function information and update signature to name mapping.
  let parseFunc keccak accMap (funcJson: JsonValue) =
    let name = funcJson?name.AsString ()
    let argTypes = [ for v in funcJson?inputs -> v?``type``.AsString () ]
    let argStr = String.concat "," argTypes
    let signature = sprintf "%s(%s)" name argStr |> computeKeccak256 keccak
    Map.add signature name accMap

  // Returns a mapping from a function signature to its name.
  let parseABI abiFile =
    let keccak = SHA3Core.Keccak.Keccak (SHA3Core.Enums.KeccakBitType.K256)
    let abiStr = System.IO.File.ReadAllText (abiFile)
    let abiJson = JsonValue.Parse (abiStr)
    let isFunc (json: JsonValue) = json?``type``.AsString () = "function"
    let funcJsons = [ for v in abiJson -> v ] |> List.filter isFunc
    List.fold (parseFunc keccak) Map.empty funcJsons

  let tryGetTrampolineInfo cpState = function
    (* It's based on heuristics. *)
    | SSA.Jmp (SSA.InterCJmp (cond, tExpr, _)) ->
      let cond = cond |> IRHelper.resolveExpr cpState true
      let tAddr = tExpr |> IRHelper.tryResolveExprToUInt64 cpState
      match cond, tAddr with
      | SSA.RelOp (RelOpType.EQ, _, v1, v2), Some tAddr ->
        let v1 = v1 |> IRHelper.tryResolveExprToUInt32 cpState
        let v2 = v2 |> IRHelper.tryResolveExprToUInt32 cpState
        match v1, v2 with
        (* One is variable, and the other one is a constant which represents a
           signature of a function. Note that it's common for constants to come
           first while EVM handles function signatures. *)
        | Some v, None ->
          let sign = v
          let addr = tAddr
          Some (sign, addr)
        | _ -> None
      | _ -> None
    | _ -> None

  // Iterate trampolines in the entry function.
  let iterateTrampoline hdl codeMgr fn =
    let entryOffset = 0UL
    (codeMgr: CodeManager).FunctionMaintainer.TryFindRegular entryOffset
    |> function
      | Some func ->
        let struct (cpState, ssaCFG) = PerFunctionAnalysis.runCP hdl func None
        ssaCFG.IterVertex (fun v ->
          Array.iter (fun (_, stmt) ->
            match tryGetTrampolineInfo cpState stmt with
            | Some (sign, addr) -> fn sign addr
            | _ -> ()) v.VData.SSAStmtInfos)
      | _ -> failwith "Could not find its entry function at 0x0"

type EVMTrampolineAnalysis (abiFile) =
  member private __.MakeSymbol name addr =
    { Address = addr
      Name = name
      Kind = SymFunctionType
      Visibility = SymbolVisibility.StaticSymbol
      LibraryName = ""
      ArchOperationMode = ArchOperationMode.NoMode }

  member private __.UpdateSymbols (file: BinFile) addr name =
    file.AddSymbol addr (__.MakeSymbol name addr)

  member private __.AnalyzeTrampoline hdl codeMgr =
    let bytes = hdl.BinFile.Span.ToArray ()
    let isa = hdl.BinFile.ISA
    let newHdl = BinHandle.Init (isa, bytes)
    let newFi = newHdl.BinFile
    let sigToName = if abiFile <> "" then parseABI abiFile else Map.empty
    let fn sign addr =
      let name =
        match Map.tryFind sign sigToName with
        | Some name -> name
        | _ -> sprintf "func_%x" addr
      __.UpdateSymbols newFi addr name
    iterateTrampoline hdl codeMgr fn
    PluggableAnalysisNewBinary newHdl

  interface IPluggableAnalysis with
    member __.Name = "EVM Trampoline Analysis"

    member __.Run _builder hdl codeMgr _dataMgr =
      match hdl.BinFile.ISA.Arch with
      | Architecture.EVM -> __.AnalyzeTrampoline hdl codeMgr
      | _ -> PluggableAnalysisOk

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

namespace B2R2.MiddleEnd.BinEssence

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.ControlFlowAnalysis

/// <summary>
///   BinEssence represents essential information about the binary at all
///   levels: a low-level interface for binary code and data, parsed
///   instructions, and recovered control-flow information including CFG itself.
///   Note that every field of BinEssence is *mutable*.
/// </summary>
type BinEssence = {
  /// Low-level access to binary code and data.
  BinHandle: BinHandle
  /// Higher-level access to the code. It handles parsed instructions, lifted
  /// IRs, basic blocks, functions, exception handlers, etc.
  CodeManager: CodeManager
  /// Higher-level access to the data.
  DataManager: DataManager
}

[<RequireQualifiedAccess>]
module BinEssence =

  /// Retrieve the IR-level CFG at the given address (addr) from the BinEssence.
  let getFunctionCFG ess (addr: Addr) =
    match ess.CodeManager.FunctionMaintainer.TryFindRegular addr with
    | Some func ->
      let root = func.FindVertex (ProgramPoint (addr, 0))
      Ok (func.IRCFG, root)
    | None -> Error ()

  let private getFunctionOperationMode hdl entry =
    match hdl.ISA.Arch with
    | Arch.ARMv7 ->
      if entry &&& 1UL = 1UL then
        entry - 1UL, ArchOperationMode.ThumbMode
      else entry, ArchOperationMode.ARMMode
    | _ -> entry, ArchOperationMode.NoMode

  let private addEntriesFromExceptionTable (codeMgr: CodeManager) entries =
    codeMgr.ExceptionTable.Fold (fun entries (KeyValue (entry, _)) ->
      if codeMgr.ExceptionTable.IsNoEntryFDE entry then entries
      else Set.add entry entries) entries

  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the other analyses.
  let private getInitialEntryPoints ess =
    let fi = ess.BinHandle.FileInfo
    let entries =
      fi.GetFunctionAddresses ()
      |> Set.ofSeq
      |> addEntriesFromExceptionTable ess.CodeManager
    fi.EntryPoint
    |> Option.fold (fun acc addr ->
      if fi.FileType = FileType.LibFile && addr = 0UL then acc
      else Set.add addr acc) entries
    |> Set.toList
    |> List.map (getFunctionOperationMode ess.BinHandle)

  let private initialize hdl =
    { BinHandle = hdl
      CodeManager = CodeManager (hdl)
      DataManager = DataManager (hdl) }

  let private initialBuild ess (builder: CFGBuilder) =
    let entries = getInitialEntryPoints ess
    match builder.AddNewFunctions entries with
    | Ok () -> Ok ess
    | Error err -> Error err

  let private handlePluggableAnalysisResult ess name = function
    | PluggableAnalysisOk ->
      Ok ess
    | PluggableAnalysisError ->
      printfn "[*] %s failed." name
      Ok ess
    | PluggableAnalysisNewBinary hdl ->
      let ess = initialize hdl
      let builder = CFGBuilder (hdl, ess.CodeManager, ess.DataManager)
      initialBuild ess builder

  let private runAnalyses builder analyses (ess: BinEssence) =
    analyses
    |> List.fold (fun ess (analysis: IPluggableAnalysis) ->
  #if DEBUG
      printfn "[*] %s started." analysis.Name
  #endif
      let ess =
        analysis.Run builder ess.BinHandle ess.CodeManager ess.DataManager
        |> handlePluggableAnalysisResult ess analysis.Name
      match ess with
      | Ok ess -> ess
      | Error e ->
        eprintfn "[*] Fatal error with %s" (CFGError.toString e)
        Utils.impossible ()) ess

  let private analyzeAll preAnalyses mainAnalyses postAnalyses builder ess =
    ess
    |> runAnalyses builder preAnalyses
    |> runAnalyses builder mainAnalyses
    |> runAnalyses builder postAnalyses

  [<CompiledName("Init")>]
  let init hdl preAnalyses mainAnalyses postAnalyses =
#if DEBUG
    let startTime = System.DateTime.Now
#endif
    let ess = initialize hdl
    let builder = CFGBuilder (hdl, ess.CodeManager, ess.DataManager)
    match initialBuild ess builder with
    | Ok ess ->
      let ess = ess |> analyzeAll preAnalyses mainAnalyses postAnalyses builder
#if DEBUG
      let endTime = System.DateTime.Now
      endTime.Subtract(startTime).TotalSeconds
      |> printfn "[*] All done in %f sec."
#endif
      ess
    | Error e ->
      eprintfn "[*] Fatal error with %s" (CFGError.toString e)
      Utils.impossible ()

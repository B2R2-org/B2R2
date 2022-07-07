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

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface

[<AutoOpen>]
module private FunctionMaintainer =
  /// These are some functions that sometimes get linked without the use of PLT.
  let knownNoPLTFuncs =
    [| "__libc_start_main"; "__gmon_start__" |]

  let findInternalFuncReloc (elf: ELF.ELF) (symb: ELF.ELFSymbol) =
    let reloc = elf.RelocInfo.RelocByAddr[symb.Addr]
    match reloc.RelSymbol with
    | Some relSym ->
      if relSym.SymType = ELF.SymbolType.STTFunc then
        match relSym.ParentSection with
        | Some parent ->
          if parent.SecName = ".text" then Ok relSym
          else Error ErrorCase.SymbolNotFound
        | _ -> Error ErrorCase.SymbolNotFound
      else Error ErrorCase.SymbolNotFound
    | _ -> Error ErrorCase.SymbolNotFound

/// Maintains functions in the binary.
type FunctionMaintainer private (hdl, histMgr: HistoryManager) =
  let addrMap = SortedList<Addr, Function> ()
  let regularMap = Dictionary<Addr, RegularFunction> ()
  let nameMap = Dictionary<string, Addr> ()
  let internalRefs = Dictionary<Addr, Addr> ()

  /// The current number of functions.
  member __.Count with get() = addrMap.Count

  /// Return the sequence of functions.
  member __.Functions
    with get () = addrMap |> Seq.map (fun (KeyValue (_, f)) -> f)

  /// Return the sequence of function entry addresses.
  member __.Entries
    with get () = addrMap |> Seq.map (fun (KeyValue (a, _)) -> a)

  /// Check if the given address belongs to a known function entry address.
  member __.Contains (addr) = addrMap.ContainsKey addr

  /// Check if there is a function with the given name.
  member __.Contains (name) = nameMap.ContainsKey name

  /// Try to obtain a function by the given function entry address.
  member __.TryFind (addr) = addrMap.TryGetValue addr |> Utils.tupleToOpt

  /// Try to obtain a function by the given function name.
  member __.TryFind (name) =
    match nameMap.TryGetValue name with
    | true, addr -> __.TryFind addr
    | _ -> None

  /// Obtain a function by the given function entry address.
  member __.Find (addr) = addrMap[addr]

  /// Obtain a function by the given function name.
  member __.Find (name) = addrMap[nameMap[name]]

  /// Obtain a regular function by the given function entry address.
  member __.TryFindRegular (addr) =
    regularMap.TryGetValue addr |> Utils.tupleToOpt

  /// Obtain a regular function by the given function entry address.
  member __.FindRegular (addr) = regularMap[addr]

  /// Returns an array of regualr functions.
  member __.RegularFunctions with get () = regularMap.Values |> Seq.toArray

  /// Return the next function address relative to the given function (fn).
  member __.FindNextFunctionAddr (fn: RegularFunction) =
    match SortedList.findLeastUpperBoundKey (fn.Entry + 1UL) addrMap with
    | Some ubAddr -> ubAddr
    | None -> System.UInt64.MaxValue

  /// Remove the given function.
  member __.RemoveFunction (addr) =
    let fnName = addrMap[addr].FunctionName
    regularMap.Remove addr |> ignore
    addrMap.Remove addr |> ignore
    nameMap.Remove fnName |> ignore

  /// Add an external function. This function should not be called outside.
  member private __.AddFunction (func: ExternalFunction) =
    nameMap[func.FunctionID] <- func.Entry
    nameMap[func.FunctionName] <- func.Entry
    addrMap[func.Entry] <- func
    match func.TrampolineAddr () with
    | true, addr -> addrMap[addr] <- func
    | _ -> ()

  /// Add a new regular function
  member __.AddFunction (func: RegularFunction) =
    let entry = func.Entry
    nameMap[func.FunctionID] <- entry
    nameMap[func.FunctionName] <- entry
    addrMap[entry] <- func
    regularMap[entry] <- func

  /// Get a regular function at the entry. If the entry does not contain any
  /// function, create a new one and return it.
  member __.GetOrAddFunction entry =
    match regularMap.TryGetValue entry with
    | true, f -> f
    | false, _ ->
      histMgr.Record <| CreatedFunction entry
      let f = RegularFunction (histMgr, hdl, entry)
      __.AddFunction f
      f

  member private __.CollectXRefs () =
    regularMap.Values
    |> Seq.fold (fun xrefs func ->
      func.AccumulateXRefs xrefs) Map.empty

  /// Update callers' cross references.
  member __.UpdateCallerCrossReferences () =
    __.CollectXRefs ()
    |> Map.iter (fun callee callers ->
      addrMap[callee].RegisterCallers callers)

  /// This is a mapping from a PLT address to an internal function address. Some
  /// static binaries have a PLT entry for an internal function.
  member __.InternalRefs with get() = internalRefs

  /// If the given address belongs to a special PLT entry, then we convert it to
  /// the address of the corresponding internal function.
  member __.ConvertPLTToInternalRef (addr: Addr) =
    match internalRefs.TryGetValue addr with
    | true, addr' -> addr'
    | false, _ -> addr

  static member private InitELFExterns hdl (fnMaintainer: FunctionMaintainer) =
    let elf = (hdl.FileInfo :?> ELFFileInfo).ELF
    elf.PLT
    |> ARMap.iter (fun range symb ->
      match findInternalFuncReloc elf symb with
      | Ok relSym -> fnMaintainer.InternalRefs[range.Min] <- relSym.Addr
      | Error _ ->
        let func = ExternalFunction.Init symb.Addr symb.SymName range.Min
        fnMaintainer.AddFunction func)
    elf.RelocInfo.RelocByAddr.Values
    |> Seq.iter (fun reloc ->
      match reloc.RelSymbol with
      | Some symb ->
        let sec = elf.SecInfo.SecByNum[reloc.RelSecNumber]
        if (sec.SecName = ".rela.dyn" || sec.SecName = ".rel.dyn")
          && Array.contains symb.SymName knownNoPLTFuncs
        then
          let func = ExternalFunction.Init reloc.RelOffset symb.SymName 0UL
          fnMaintainer.AddFunction func
        else ()
      | None -> ())

  static member Init hdl histMgr =
    let fnMaintainer = FunctionMaintainer (hdl, histMgr)
    match hdl.FileInfo.FileFormat with
    | FileFormat.ELFBinary -> FunctionMaintainer.InitELFExterns hdl fnMaintainer
    | _ -> ()
    fnMaintainer

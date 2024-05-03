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
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader

type FunctionBuilderTable<'V,
                          'E,
                          'FnCtx,
                          'GlCtx when 'V :> IRBasicBlock
                                  and 'V: equality
                                  and 'E: equality
                                  and 'FnCtx :> IResettable
                                  and 'FnCtx: (new: unit -> 'FnCtx)
                                  and 'GlCtx: (new: unit -> 'GlCtx)>
  public (hdl, instrs, cfgConstructor, strategy) =

  let builders =
    Dictionary<Addr, IFunctionBuildable<'V,'E, 'FnCtx, 'GlCtx>> ()

  let getOrCreateInternalBuilder manager addr mode =
    match builders.TryGetValue addr with
    | true, builder -> builder
    | false, _ ->
      let builder =
        InternalFunctionBuilder (hdl, instrs, addr, mode,
                                 cfgConstructor, manager, strategy)
      builders[addr] <- builder
      builder

  let loadFromPLT manager (elf: ELFBinFile) =
    elf.PLT
    |> ARMap.iter (fun range entry ->
      match ELF.findInternalFuncReloc elf entry with
      | Ok fnAddr ->
        (* We create a mapping from a PLT address to an internal function
           address because some static binaries have a PLT entry for an internal
           function. *)
        let mode = ArchOperationMode.NoMode
        let builder = getOrCreateInternalBuilder manager fnAddr mode
        builders[range.Min] <- builder
      | Error _ ->
        let addr, name = entry.TableAddress, entry.FuncName
        let isNoRet = ELF.isKnownNoReturnFunc name
        let builder = ExternalFunctionBuilder (hdl, addr, name, isNoRet)
        builders[range.Min] <- builder
    )

  let loadFromReloc (elf: ELFBinFile) =
    elf.RelocationInfo.RelocByAddr.Values
    |> Seq.iter (fun reloc ->
      match reloc.RelSymbol with
      | Some symb ->
        let sec = elf.FindSection reloc.RelSecNumber
        if ELF.isDynamicReloc sec && ELF.isKnownNoPLTFunc symb.SymName then
          let addr, name = reloc.RelOffset, symb.SymName
          let builder = ExternalFunctionBuilder (hdl, addr, name, NotNoRet)
          builders[reloc.RelOffset] <- builder
        else ()
      | None -> ()
    )

  let loadELF manager (elf: ELFBinFile) =
    loadFromPLT manager elf
    loadFromReloc elf

  member _.Load manager =
    match hdl.File.Format with
    | FileFormat.ELFBinary ->
      hdl.File :?> ELFBinFile |> loadELF manager
    | _ -> ()

  /// Retrieve a function builder by its address.
  member _.Item with get(addr:Addr) = builders[addr]

  member _.Values with get() = builders.Values

  /// Get or create a function builder by its address and operation mode.
  member _.GetOrCreateBuilder manager addr mode =
    getOrCreateInternalBuilder manager addr mode

  /// Try to retrieve a function builder by its address.
  member _.TryGetBuilder (addr: Addr) =
    match builders.TryGetValue addr with
    | true, builder -> Ok builder
    | false, _ -> Error ErrorCase.ItemNotFound

  /// Convert the table to an array.
  member _.ToArray () =
    builders.Values |> Seq.toArray

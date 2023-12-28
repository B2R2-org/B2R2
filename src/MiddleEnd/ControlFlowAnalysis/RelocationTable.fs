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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

type RelocationTable (hdl: BinHandle) =
  let offset =
    match hdl.File.ISA.Arch with
    | Architecture.IntelX86
    | Architecture.IntelX64 -> 1UL
    | _ -> Utils.futureFeature ()

  let lookup addr =
    match hdl.File with
    | :? ELFBinFile as elf ->
      match elf.RelocationInfo.RelocByAddr.TryGetValue addr with
      | true, rel ->
        rel.RelSymbol
        |> Option.bind (fun sym ->
          if sym.SymType = ELF.SymbolType.STT_FUNC then Some sym.SymName
          else None)
      | false, _ -> None
    | :? RawBinFile -> None
    | _ -> Utils.futureFeature ()

  /// Check if the given call instruction has a relocatable target, and if so,
  /// return the function symbol name.
  member __.CallTargetFunctionName (callAddr: Addr) =
    let targetAddr = callAddr + offset
    lookup targetAddr

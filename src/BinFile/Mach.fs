(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinFile

open System
open B2R2
open B2R2.BinFile.Mach
open B2R2.BinFile.Mach.Helper

/// <summary>
///   This class represents a Mach-O binary file.
/// </summary>
type MachFileInfo (bytes, path) =
  inherit FileInfo ()

  let mach = initMach bytes

  override __.FileFormat = FileFormat.MachBinary

  override __.FilePath = path

  override __.EntryPoint = mach.EntryPoint

  override __.IsStripped =
    getAllStaticSymbols mach
    |> Array.exists (fun s -> s.Kind = SymbolKind.FunctionType)
    |> not

  override __.FileType = transFileType mach.MachHdr.FileType

  override __.WordSize = mach.MachHdr.Class

  override __.NXEnabled =
    not (mach.MachHdr.Flags.HasFlag MachFlag.MHAllowStackExecution)
    || mach.MachHdr.Flags.HasFlag MachFlag.MHNoHeapExecution

  override __.IsValidAddr addr =
    match ARMap.tryFindByAddr addr mach.Sections.SecByAddr with
    | Some _ -> true
    | None -> false

  override __.TranslateAddress addr =
    match ARMap.tryFindByAddr addr mach.Sections.SecByAddr with
    | Some s -> Convert.ToInt32 (addr - s.SecAddr + uint64 s.SecOffset)
    | None -> raise InvalidAddrReadException

  override __.TryFindFunctionSymbolName (addr, name: byref<string>) =
    match tryFindFunctionSymb mach addr with
    | Some n -> name <- n; true
    | None -> false

  override __.FindSymbolChunkStartAddress _addr = Utils.futureFeature ()

  override __.GetSymbols () =
    let s = getAllStaticSymbols mach
    let d = getAllDynamicSymbols mach
    Array.append s d |> Array.toSeq

  override __.GetStaticSymbols () = getAllStaticSymbols mach |> Array.toSeq

  override __.GetDynamicSymbols (?defined) =
    getAllDynamicSymbols mach |> Array.toSeq

  override __.GetRelocationSymbols () = Utils.futureFeature ()

  override __.GetSections () =
    mach.Sections.SecByNum
    |> Array.map (machSectionToSection mach.SegmentMap)
    |> Array.toSeq

  override __.GetSections (addr) =
    match ARMap.tryFindByAddr addr mach.Sections.SecByAddr with
    | Some s -> Seq.singleton (machSectionToSection mach.SegmentMap s)
    | None -> Seq.empty

  override __.GetSectionsByName (name) =
    match Map.tryFind name mach.Sections.SecByName with
    | Some s -> Seq.singleton (machSectionToSection mach.SegmentMap s)
    | None -> Seq.empty

  override __.GetSegments () = Segment.getAll mach

  override __.GetLinkageTableEntries () =
    mach.SymInfo.LinkageTable
    |> List.sortBy (fun entry -> entry.TrampolineAddress)
    |> List.toSeq

  override __.TextStartAddr =
    (Map.find "__text" mach.Sections.SecByName).SecAddr

// vim: set tw=80 sts=2 sw=2:

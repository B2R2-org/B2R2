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

open B2R2
open B2R2.BinFile.ELF
open B2R2.BinFile.ELF.Helper

/// <summary>
///   This class represents an ELF binary file.
/// </summary>
type ELFFileInfo (bytes, path) =
  inherit FileInfo ()

  let elf = initELF bytes

  override __.FileFormat = FileFormat.ELFBinary

  override __.BinReader = elf.BinReader

  override __.ISA = ISA.Init elf.ELFHdr.MachineType elf.ELFHdr.Endian

  override __.FilePath = path

  override __.EntryPoint = elf.ELFHdr.EntryPoint

  override __.IsStripped =
    not (Map.containsKey ".symtab" elf.SecInfo.SecByName)

  override __.FileType =
    match elf.ELFHdr.ELFFileType with
    | ELFFileType.Executable -> FileType.ExecutableFile
    | ELFFileType.SharedObject -> FileType.LibFile
    | ELFFileType.Core -> FileType.CoreFile
    | _ -> FileType.UnknownFile

  override __.WordSize = elf.ELFHdr.Class

  override __.IsNXEnabled =
    let predicate e = e.PHType = ProgramHeaderType.PTGNUStack
    match List.tryFind predicate elf.ProgHeaders with
    | Some s -> s.PHFlags.HasFlag Permission.Executable |> not
    | _ -> false

  override __.IsRelocatable =
    let pred (e: DynamicSectionEntry) = e.DTag = DynamicSectionTag.DTDebug
    __.FileType = FileType.LibFile
    && Section.getDynamicSectionEntries elf.BinReader elf.SecInfo
       |> List.exists pred

  override __.TextStartAddr =
    (Map.find secTEXT elf.SecInfo.SecByName).SecAddr

  override __.TranslateAddress addr =
    translateAddr addr elf.LoadableSegments

  override __.TryFindFunctionSymbolName (addr, name: byref<string>) =
    match tryFindFuncSymb elf addr with
    | Some n -> name <- n; true
    | None -> false

  override __.GetSymbols () =
    let s = __.GetStaticSymbols ()
    let d = __.GetDynamicSymbols ()
    Seq.append s d

  override __.GetStaticSymbols () =
    Symbol.getStaticSymArray elf
    |> Array.map (Symbol.toB2R2Symbol TargetKind.StaticSymbol)
    |> Array.toSeq

  override __.GetDynamicSymbols (?defined: bool) =
    let onlyDef = defaultArg defined false
    let alwaysTrue = fun _ -> true
    let filter =
      if onlyDef then (fun s -> s.SecHeaderIndex <> SHNUndef) else alwaysTrue
    Symbol.getDynamicSymArray elf
    |> Array.filter filter
    |> Array.map (Symbol.toB2R2Symbol TargetKind.DynamicSymbol)
    |> Array.toSeq

  override __.GetSections () =
    elf.SecInfo.SecByNum
    |> Array.map (elfSectionToSection)
    |> Array.toSeq

  override __.GetSections (addr) =
    match ARMap.tryFindByAddr addr elf.SecInfo.SecByAddr with
    | Some s -> Seq.singleton (elfSectionToSection s)
    | None -> Seq.empty

  override __.GetSectionsByName (name) =
    match Map.tryFind name elf.SecInfo.SecByName with
    | Some s -> Seq.singleton (elfSectionToSection s)
    | None -> Seq.empty

  override __.GetSegments () =
    elf.LoadableSegments
    |> List.map ProgHeader.toSegment
    |> List.toSeq

  override __.GetLinkageTableEntries () =
    let create pltAddr (symb: ELFSymbol) =
      { FuncName = symb.SymName
        LibraryName = Symbol.versionToLibName symb.VerInfo
        TrampolineAddress = pltAddr
        TableAddress = symb.Addr }
    elf.PLT
    |> ARMap.fold (fun acc addrRange s -> create addrRange.Min s :: acc) []
    |> List.sortBy (fun entry -> entry.TrampolineAddress)
    |> List.toSeq

  override __.GetRelocationSymbols () =
    let translate (_, reloc) =
      reloc.RelSymbol
      |> Option.bind (fun s ->
           { s with Addr = reloc.RelOffset }
           |> Symbol.toB2R2Symbol TargetKind.DynamicSymbol
           |> Some)
    elf.RelocInfo.RelocByName
    |> Map.toSeq
    |> Seq.choose translate

  override __.IsValidAddr addr =
    isValid addr elf.LoadableSegments

  override __.IsValidRange range =
    IntervalSet.findAll range elf.InvalidAddrRanges |> List.isEmpty

  override __.IsInFileAddr addr =
    isInFile addr elf.LoadableSegments

  override __.IsInFileRange range =
    IntervalSet.findAll range elf.NotInFileRanges |> List.isEmpty

  override __.GetNotInFileIntervals range =
    IntervalSet.findAll range elf.NotInFileRanges
    |> List.map (FileHelper.trimByRange range)
    |> List.toSeq

// vim: set tw=80 sts=2 sw=2:

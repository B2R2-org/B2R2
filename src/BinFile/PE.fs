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
open B2R2.BinFile.PE.Helper
open System.Reflection.PortableExecutable

/// <summary>
///   This class represents a PE binary file.
/// </summary>
type PEFileInfo (bytes, path, ?rawpdb) =
  inherit FileInfo ()
  let pe = initPE bytes path rawpdb

  override __.FileFormat = FileFormat.PEBinary

  override __.BinReader = pe.BinReader

  override __.ISA =
    let arch = machineToArch pe.PEHeaders.CoffHeader.Machine
    ISA.Init arch Endian.Little

  override __.FilePath = path

  override __.EntryPoint =
    let entry = pe.PEHeaders.PEHeader.AddressOfEntryPoint
    if entry = 0 then 0UL
    else uint64 entry + pe.PEHeaders.PEHeader.ImageBase

  override __.IsStripped =
    Array.length pe.PDB.SymbolArray = 0

  override __.FileType =
    let c = pe.PEHeaders.CoffHeader.Characteristics
    if c.HasFlag Characteristics.Dll then FileType.LibFile
    elif c.HasFlag Characteristics.ExecutableImage then FileType.ExecutableFile
    else FileType.UnknownFile

  override __.WordSize =
    match pe.PEHeaders.PEHeader.Magic with
    | PEMagic.PE32 -> WordSize.Bit32
    | PEMagic.PE32Plus -> WordSize.Bit64
    | _ -> raise InvalidWordSizeException

  override __.IsNXEnabled =
    pe.PEHeaders.PEHeader.DllCharacteristics.HasFlag
      (DllCharacteristics.NxCompatible)

  override __.IsRelocatable =
    pe.PEHeaders.PEHeader.DllCharacteristics.HasFlag
      (DllCharacteristics.DynamicBase)

  override __.TranslateAddress addr =
    let rva = int (addr - pe.PEHeaders.PEHeader.ImageBase)
    match pe.PEHeaders.GetContainingSectionIndex rva with
    | -1 -> raise InvalidAddrReadException
    | idx ->
      let sHdr = pe.PEHeaders.SectionHeaders.[idx]
      rva + sHdr.PointerToRawData - sHdr.VirtualAddress

  override __.TryFindFunctionSymbolName (addr, name: byref<string>) =
    match tryFindFunctionSymbolName pe addr with
    | Some n -> name <- n; true
    | None -> false

  override __.GetSymbols () =
    let s = __.GetStaticSymbols ()
    let d = __.GetDynamicSymbols ()
    Seq.append s d

  override __.GetStaticSymbols () =
    pe.PDB.SymbolArray
    |> Array.map pdbSymbolToSymbol
    |> Array.toSeq

  override __.GetDynamicSymbols (?defined) =
    let onlyDef = defaultArg defined false
    if onlyDef then getExportSymbols pe else getAllDynamicSymbols pe
    |> List.toSeq

  override __.GetRelocationSymbols () =
    pe.RelocBlocks
    |> Seq.collect (fun block ->
      block.Entries |> Seq.map(fun entry -> (block, entry)))
    |> Seq.map (fun (block, entry) -> {
      Address = uint64 (block.PageRVA + uint32 entry.Offset)
      Name = String.Empty
      Kind = SymbolKind.NoType
      Target = TargetKind.DynamicSymbol
      LibraryName = String.Empty
    })

  override __.GetSections () =
    pe.SectionHeaders
    |> Array.map (secHdrToSection pe)
    |> Array.toSeq

  override __.GetSections (addr) =
    let rva = int (addr - pe.PEHeaders.PEHeader.ImageBase)
    match pe.PEHeaders.GetContainingSectionIndex rva with
    | -1 -> Seq.empty
    | idx ->
      pe.PEHeaders.SectionHeaders.[idx] |> secHdrToSection pe |> Seq.singleton

  override __.GetSectionsByName (name) =
    let headers = pe.PEHeaders.SectionHeaders
    match headers |> Seq.tryFind (fun sec -> sec.Name = name) with
    | None -> Seq.empty
    | Some sec -> secHdrToSection pe sec |> Seq.singleton

  override __.GetSegments () =
    let getSecPermission (chr: SectionCharacteristics) =
      let x = if chr.HasFlag SectionCharacteristics.MemExecute then 1 else 0
      let w = if chr.HasFlag SectionCharacteristics.MemWrite then 2 else 0
      let r = if chr.HasFlag SectionCharacteristics.MemRead then 4 else 0
      r + w + x |> LanguagePrimitives.EnumOfValue
    let secToSegment (sec: SectionHeader) =
      let baseaddr = pe.PEHeaders.PEHeader.ImageBase
      { Address = uint64 sec.VirtualAddress + baseaddr
        Size = uint64 sec.VirtualSize
        Permission = getSecPermission sec.SectionCharacteristics }
    pe.PEHeaders.SectionHeaders
    |> Seq.map secToSegment

  override __.GetLinkageTableEntries () =
    pe.ImportMap
    |> Map.fold (fun acc addr info ->
         match info with
         | PE.ImportByOrdinal (_, dllname) ->
           { FuncName = ""
             LibraryName = dllname
             TrampolineAddress = 0UL
             TableAddress = addrFromRVA pe.PEHeaders addr } :: acc
         | PE.ImportByName (_, fname, dllname) ->
           { FuncName = fname
             LibraryName = dllname
             TrampolineAddress = 0UL
             TableAddress = addrFromRVA pe.PEHeaders addr } :: acc) []
    |> List.sortBy (fun entry -> entry.TableAddress)
    |> List.toSeq

  override __.TextStartAddr =
    match __.GetSectionsByName ".text" |> Seq.tryHead with
    | None -> 0UL
    | Some sec -> sec.Address

  override __.IsValidAddr addr =
    IntervalSet.containsAddr addr pe.InvalidAddrRanges |> not

  override __.IsValidRange range =
    IntervalSet.findAll range pe.InvalidAddrRanges |> List.isEmpty

  override __.IsInFileAddr addr =
    IntervalSet.containsAddr addr pe.NotInFileRanges |> not

  override __.IsInFileRange range =
    IntervalSet.findAll range pe.NotInFileRanges |> List.isEmpty

  override __.GetNotInFileIntervals range =
    IntervalSet.findAll range pe.NotInFileRanges
    |> List.map (FileHelper.trimByRange range)
    |> List.toSeq

// vim: set tw=80 sts=2 sw=2:

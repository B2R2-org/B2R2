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

/// <summary>
///   This class represents an ELF binary file.
/// </summary>
type ELFFileInfo (bytes, path) =
    inherit FileInfo ()

    let elf = initELF bytes

    override __.FileFormat = FileFormat.ELFBinary

    override __.FilePath = path

    override __.EntryPoint = elf.ELFHdr.EntryPoint

    override __.IsStripped =
        not (Map.containsKey ".symtab" elf.Sections.SecByName)

    override __.FileType =
        match elf.ELFHdr.ELFFileType with
        | Executable -> FileType.ExecutableFile
        | SharedObject -> FileType.LibFile
        | Core -> FileType.CoreFile
        | _ -> FileType.UnknownFile

    override __.WordSize = elf.ELFHdr.Class

    override __.NXEnabled =
        match List.tryFind (fun e -> e.PHType = PHTGNUStack) elf.Segments with
        | Some s -> s.PHFlags &&& 0x1 <> 0
        | _ -> false

    override __.TextStartAddr =
        getTextSectionStartAddr elf

    override __.TranslateAddress addr =
        translateAddr addr elf.LoadableSegments

    override __.TryFindFunctionSymbolName (addr, name: byref<string>) =
        match tryFindFuncSymb elf addr with
        | Some n -> name <- n; true
        | None -> false

    override __.FindSymbolChunkStartAddress addr =
        match tryFindELFSymbolChunkRange elf addr with
        | Some range -> range.Min
        | None -> 0UL

    override __.GetSymbols () =
        let s = getAllStaticSymbols elf
        let d = getAllDynamicSymbols elf
        Array.append s d |> Array.toSeq

    override __.GetStaticSymbols () = getAllStaticSymbols elf |> Array.toSeq

    override __.GetDynamicSymbols () = getAllDynamicSymbols elf |> Array.toSeq

    override __.GetSections () =
        getAllSections elf

    override __.GetSections (addr) =
        getSectionsByAddr elf addr

    override __.GetSectionsByName (name) =
        getSectionsByName elf name

    override __.GetSegments () =
        getAllSegments elf

    override __.GetLinkageTableEntries () =
        getLinkageTableEntries elf

    override __.IsValidAddr addr = isValid addr elf.LoadableSegments

// vim: set tw=80 sts=2 sw=2:

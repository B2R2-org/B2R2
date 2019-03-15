(*
  B2R2 - the Next-Generation Reversing Platform

  Author: DongYeop Oh <oh51dy@kaist.ac.kr>

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
open B2R2.BinFile.PE

/// <summary>
///   This class represents a PE binary file.
/// </summary>
type PEFileInfo (bytes, path, ?rawpdb) =
  inherit FileInfo ()
  let pe = initPE bytes
  let pdb = initPDB path rawpdb |> parsePdbSymbols pe

  override __.FileFormat = FileFormat.PEBinary

  override __.FilePath = path

  override __.EntryPoint =
    pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.AddressOfEntryPoint
    + pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.ImageBase |> uint64

  override __.IsStripped = false

  override __.FileType =
    transFileType pe.PEHdr.ImageNTHdrs.ImageFileHeader.Characteristics

  override __.WordSize =
    getBitTypeFromMagic pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.Magic

  override __.NXEnabled =
    let dllCharacteristics =
      pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.DllCharacteristics
    dllCharacteristics &&& 0x0100s <> 0s

  override __.IsValidAddr addr = isValidAddr pe addr

  override __.TranslateAddress addr = translateAddr pe addr

  override __.TryFindFunctionSymbolName (addr, name: byref<string>) =
    match tryFindFunctionSymbolName pe pdb addr with
    | Some n -> name <- n; true
    | None -> false

  override __.FindSymbolChunkStartAddress _addr = Utils.futureFeature ()

  override __.GetSymbols () =
    let s = getAllStaticSymbols pdb
    let d = getAllDynamicSymbols pe
    Array.append s d |> Array.toSeq

  override __.GetStaticSymbols () = getAllStaticSymbols pdb |> Array.toSeq

  override __.GetDynamicSymbols () = getAllDynamicSymbols pe |> Array.toSeq

  override __.GetRelocationSymbols () = Utils.futureFeature ()

  override __.GetSections () = getAllSections pe

  override __.GetSections (addr) = getSectionsByAddr pe addr

  override __.GetSectionsByName (name) = getSectionsByName pe name

  override __.GetSegments () = getAllSegments pe

  override __.GetLinkageTableEntries () = getLinkageTableEntries pe

  override __.TextStartAddr =
    (Map.find ".text" pe.ImageSecHdrs.SecNameMap).VirtualAddr
    + pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.ImageBase |> uint64

// vim: set tw=80 sts=2 sw=2:

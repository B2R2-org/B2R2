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

namespace B2R2.FrontEnd.BinFile.ELF

open System
open System.IO
open System.Collections.Generic
open B2R2
open B2R2.Monads.Maybe
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// A symbol's binding determines the linkage visibility and behavior.
type SymbolBind =
  /// Local symbols are not visible outside. Local symbols of the same name may
  /// exist in multiple files without interfering with each other.
  | STB_LOCAL = 0uy
  /// Global symbols are visible to all object files being combined.
  | STB_GLOBAL = 1uy
  /// Weak symbols resemble global symbols, but their definitions have lower
  /// precedence.
  | STB_WEAK = 2uy
  /// The lower bound of OS-specific binding type.
  | STB_LOOS = 10uy
  /// The upper bound of OS-specific binding type.
  | STB_HIOS = 12uy
  /// The lower bound of processor-specific binding type.
  | STB_LOPROC = 13uy
  /// The upper bound of processor-specific binding type.
  | STB_HIPROC = 15uy

/// A symbol's type provides a general classification for the associated entity.
type SymbolType =
  /// Symbol's type is not specified.
  | STT_NOTYPE = 0uy
  /// This symbol is associated with a data object, such as variable and an
  /// array.
  | STT_OBJECT = 1uy
  /// This symbol is associated with a function.
  | STT_FUNC = 2uy
  /// This symbol is associated with a section. Symbol table entries of this
  /// type exist primarily for relocation and normally have STBLocal binding.
  | STT_SECTION = 3uy
  /// This symbol represents the name of the source file associated with the
  /// object file.
  | STT_FILE = 4uy
  /// This symbol labels an uninitialized common block.
  | STT_COMMON = 5uy
  /// The symbol specifies a Thread-Local Storage entity.
  | STT_TLS = 6uy
  /// The lower bound of OS-specific symbol type.
  | STT_LOOS = 10uy
  /// A symbol with type STT_GNU_IFUNC is a function, but the symbol does not
  /// provide the address of the function as usual. Instead, the symbol provides
  /// the address of a function which returns a pointer to the actual function.
  | STT_GNU_IFUNC = 10uy
  /// The upper bound of OS-specific binding type.
  | STT_HIOS = 12uy
  /// The lower bound of processor-specific symbol type.
  | STT_LOPROC = 13uy
  /// The upper bound of processor-specific symbol type.
  | STT_HIPROC = 15uy

/// This member currently specifies a symbol's visibility
type SymbolVisibility =
  /// Use the visibility specified by the symbol's binding type (SymbolBind).
  | STV_DEFAULT = 0x0uy
  /// This visibility attribute is currently reserved.
  | STV_INTERNAL = 0x01uy
  /// A symbol defined in the current component is hidden if its name is not
  /// visible to other components. Such a symbol is necessarily protected. This
  /// attribute is used to control the external interface of a component. An
  /// object named by such a symbol may still be referenced from another
  /// component if its address is passed outside.
  | STV_HIDDEN = 0x02uy
  /// A symbol defined in the current component is protected if it is visible in
  /// other components but cannot be preempted. Any reference to such a symbol
  /// from within the defining component must be resolved to the definition in
  /// that component, even if there is a definition in another component that
  /// would interpose by the default rules.
  | STV_PROTECTED = 0x03uy

/// Symbol version information.
type SymVerInfo = {
  /// Is this a hidden symbol? This is a GNU-specific extension indicated as
  /// VERSYM_HIDDEN.
  IsHidden: bool
  /// Version string.
  VerName: string
}

type ELFSymbol = {
  /// Address of the symbol.
  Addr: Addr
  /// Symbol's name.
  SymName: string
  /// Size of the symbol (e.g., size of the data object).
  Size: uint64
  /// Symbol binding.
  Bind: SymbolBind
  /// Symbol type.
  SymType: SymbolType
  /// Symbol visibility.
  Vis: SymbolVisibility
  /// The index of the relevant section with regard to this symbol.
  SecHeaderIndex: SectionHeaderIdx
  /// Parent section of this section.
  ParentSection: ELFSection option
  /// Version information.
  VerInfo: SymVerInfo option
  /// ArchOperationMode.
  ArchOperationMode: ArchOperationMode
}

/// Main data structure for storing symbol information.
type ELFSymbolInfo = {
  /// Linux-specific symbol version table containing versions required to link.
  VersionTable: Dictionary<uint16, string>
  /// A mapping from a section number to the corresponding symbol table.
  SecNumToSymbTbls: Dictionary<int, ELFSymbol[]>
  /// Address to symbol mapping.
  AddrToSymbTable: Dictionary<Addr, ELFSymbol>
}

module internal Symbol =
  let getSymbKind ndx = function
    | SymbolType.STT_OBJECT -> SymObjectType
    | SymbolType.STT_GNU_IFUNC
    | SymbolType.STT_FUNC ->
      if ndx = SHN_UNDEF then SymNoType
      else SymFunctionType
    | SymbolType.STT_SECTION -> SymSectionType
    | SymbolType.STT_FILE ->SymFileType
    | _ -> SymNoType

  let versionToLibName version =
    match version with
    | Some version -> version.VerName
    | None -> ""

  let toB2R2Symbol vis (symb: ELFSymbol) =
    { Address = symb.Addr
      Name = symb.SymName
      Kind = getSymbKind symb.SecHeaderIndex symb.SymType
      Visibility = vis
      LibraryName = versionToLibName symb.VerInfo
      ArchOperationMode = symb.ArchOperationMode }

  let verName (strTab: ByteSpan) vnaNameOffset =
    if vnaNameOffset >= strTab.Length then ""
    else ByteArray.extractCStringFromSpan strTab vnaNameOffset

  let rec parseNeededVerFromSecAux span (reader: IBinReader) verTbl strTbl pos =
    let idx = reader.ReadUInt16 (span=span, offset=pos + 6) (* vna_other *)
    let nameOffset = reader.ReadInt32 (span, pos + 8)
    (verTbl: Dictionary<_, _>)[idx] <- verName strTbl nameOffset
    let next = reader.ReadInt32 (span, pos + 12)
    if next = 0 then ()
    else parseNeededVerFromSecAux span reader verTbl strTbl (pos + next)

  let rec parseNeededVerFromSec span reader verTbl strTbl offset =
    let auxOffset = (* vn_aux + current file offset *)
      (reader: IBinReader).ReadInt32 (span=span, offset=offset + 8) + offset
    parseNeededVerFromSecAux span reader verTbl strTbl auxOffset
    let next = reader.ReadInt32 (span, offset + 12) (* vn_next *)
    if next = 0 then ()
    else parseNeededVerFromSec span reader verTbl strTbl (offset + next)

  let parseNeededVersionTable (stream: Stream) reader verTbl strTbl = function
    | None -> ()
    | Some { SecOffset = offset; SecSize = size } ->
      let buf = readChunk stream offset (int size)
      let span = ReadOnlySpan buf
      parseNeededVerFromSec span reader verTbl strTbl 0

  let rec parseDefinedVerFromSec span (reader: IBinReader) verTbl strTbl offset =
    let auxOffset = (* vd_aux + current file offset *)
      reader.ReadInt32 (span=span, offset=offset + 12) + offset
    let idx = reader.ReadUInt16 (span, offset + 4) (* vd_ndx *)
    let nameOffset = reader.ReadInt32 (span, auxOffset) (* vda_name *)
    (verTbl: Dictionary<_, _>)[idx] <- verName strTbl nameOffset
    let next = reader.ReadInt32 (span, offset + 16) (* vd_next *)
    if next = 0 then ()
    else parseDefinedVerFromSec span reader verTbl strTbl (offset + next)

  let parseDefinedVersionTable (stream: Stream) reader verTbl strTbl = function
    | None -> ()
    | Some { SecOffset = offset; SecSize = size } ->
      let buf = readChunk stream offset (int size)
      let span = ReadOnlySpan buf
      parseDefinedVerFromSec span reader verTbl strTbl 0

  let findVerNeedSection shdrs =
    shdrs
    |> Array.tryFind (fun s -> s.SecType = SectionType.SHT_GNU_verneed)

  let findVerDefSection shdrs =
    shdrs
    |> Array.tryFind (fun s -> s.SecType = SectionType.SHT_GNU_verdef)

  let getStaticSymbolSectionNumbers shdrs =
    shdrs
    |> Array.choose (fun s ->
      if s.SecType = SectionType.SHT_SYMTAB then Some s.SecNum else None)

  let getDynamicSymbolSectionNumbers shdrs =
    shdrs
    |> Array.choose (fun s ->
      if s.SecType = SectionType.SHT_DYNSYM then Some s.SecNum else None)

  let parseVersionTable { Stream = stream; Reader = reader } shdrs =
    let verTbl = Dictionary ()
    let verNeedSec = findVerNeedSection shdrs
    let verDefSec = findVerDefSection shdrs
    for n in getDynamicSymbolSectionNumbers shdrs do
      let symSection = shdrs[n]
      let strSection = shdrs[Convert.ToInt32 symSection.SecLink]
      let size = Convert.ToInt32 strSection.SecSize
      let strTbl = ReadOnlySpan (readChunk stream strSection.SecOffset size)
      parseNeededVersionTable stream reader verTbl strTbl verNeedSec
      parseDefinedVersionTable stream reader verTbl strTbl verDefSec
    verTbl

  let retrieveVer (verTbl: Dictionary<_, _>) verData =
    let isHidden = verData &&& 0x8000us <> 0us
    match verTbl.TryGetValue (verData &&& 0x7fffus) with
    | true, verStr -> Some { IsHidden = isHidden; VerName = verStr }
    | false, _ -> None

  let adjustSymAddr baseAddr addr =
    if addr = 0UL then 0UL
    else addr + baseAddr

  let readSymAddr baseAddr span reader cls parent txtOffset =
    let symAddr = readUIntOfType span reader cls (pickNum cls 4 8)
    match (parent: ELFSection option) with
    | None -> symAddr
    | Some sec ->
      (* This is to give a meaningful address to static symbols in a relocatable
         object. We let .text section's address to be zero, and assume that the
         .text section always precedes the other sections. See
         https://github.com/B2R2-org/B2R2/issues/25 for more details. *)
      if sec.SecAddr = baseAddr && sec.SecOffset > txtOffset then
        sec.SecOffset - txtOffset + symAddr
      else symAddr
    |> adjustSymAddr baseAddr

  let computeArchOpMode hdr symbolName =
    if hdr.MachineType = Architecture.ARMv7
      || hdr.MachineType = Architecture.AARCH32
    then
      if symbolName = "$a" then ArchOperationMode.ARMMode
      elif symbolName = "$t" then ArchOperationMode.ThumbMode
      else ArchOperationMode.NoMode
    else ArchOperationMode.NoMode

  let parseVersData (reader: IBinReader) symIdx verInfoTbl =
    let pos = symIdx * 2
    let versData = reader.ReadUInt16 (bs=verInfoTbl, offset=pos)
    if versData > 1us then Some versData
    else None

  let getVerInfo reader verTbl verInfoTblOpt symIdx =
    match verInfoTblOpt with
    | Some verInfoTbl ->
      parseVersData reader symIdx verInfoTbl >>= retrieveVer verTbl
    | None -> None

  let getSymbol toolBox shdrs strTbl verTbl symTbl verInfoTbl txtOffset symIdx =
    let cls = toolBox.Header.Class
    let reader = toolBox.Reader
    let nameIdx = reader.ReadUInt32 (span=symTbl, offset=0)
    let sname = ByteArray.extractCStringFromSpan strTbl (int nameIdx)
    let info = symTbl[pickNum cls 12 4]
    let other = symTbl[pickNum cls 13 5]
    let ndx =  reader.ReadUInt16 (symTbl, pickNum cls 14 6) |> int
    let parent = Array.tryItem ndx shdrs
    let secIdx = SectionHeaderIdx.IndexFromInt ndx
    let verInfo = getVerInfo reader verTbl verInfoTbl symIdx
    { Addr = readSymAddr toolBox.BaseAddress symTbl reader cls parent txtOffset
      SymName = sname
      Size = readUIntOfType symTbl reader cls (pickNum cls 8 16)
      Bind = info >>> 4 |> LanguagePrimitives.EnumOfValue
      SymType = info &&& 0xfuy |> LanguagePrimitives.EnumOfValue
      Vis = other &&& 0x3uy |> LanguagePrimitives.EnumOfValue
      SecHeaderIndex = secIdx
      ParentSection = parent
      VerInfo = verInfo
      ArchOperationMode = computeArchOpMode toolBox.Header sname }

  let nextSymOffset cls offset =
    offset + pickNum cls 16 24

  let getTextSectionOffset shdrs =
    match shdrs |> Array.tryFind (fun s -> s.SecName = Section.SecText) with
    | None -> 0UL
    | Some sec -> sec.SecOffset

  let parseSymbols toolBox shdrs verTbl verInfoTbl symTblSec =
    let cls = toolBox.Header.Class
    let txt = getTextSectionOffset shdrs
    let ssec = shdrs[Convert.ToInt32 symTblSec.SecLink] (* Get the string sec. *)
    let offset = ssec.SecOffset
    let size = Convert.ToInt32 ssec.SecSize
    let stringBuf = readChunk toolBox.Stream offset size
    let offset = symTblSec.SecOffset
    let size = Convert.ToInt32 symTblSec.SecSize
    let verInfoTbl = (* symbol versioning is only valid for dynamic symbols. *)
      if symTblSec.SecType = SectionType.SHT_DYNSYM then verInfoTbl else None
    let symTblBuf = readChunk toolBox.Stream offset size
    let numEntries = int symTblSec.SecSize / (pickNum cls 16 24)
    let symbols = Array.zeroCreate numEntries
    let rec parseLoop i offset =
      if i = numEntries then symbols
      else
        let strTbl = ReadOnlySpan stringBuf
        let symTbl = (ReadOnlySpan symTblBuf).Slice offset
        let sym = getSymbol toolBox shdrs strTbl verTbl symTbl verInfoTbl txt i
        symbols[i] <- sym
        parseLoop (i + 1) (nextSymOffset cls offset)
    parseLoop 0 0

  let getVerInfoTable (stream: Stream) shdrs =
    shdrs
    |> Array.tryFind (fun s -> s.SecType = SectionType.SHT_GNU_versym)
    |> function
      | Some sec ->
        let buf = Array.zeroCreate (int sec.SecSize)
        stream.Seek (int64 sec.SecOffset, SeekOrigin.Begin) |> ignore
        readOrDie stream buf
        Some buf
      | None -> None

  let parseSymTabs toolBox symTbl shdrs verTbl symSecs =
    let verInfoTbl = getVerInfoTable toolBox.Stream shdrs
    for (n, symTblSec) in symSecs do
      let symbols = parseSymbols toolBox shdrs verTbl verInfoTbl symTblSec
      (symTbl: Dictionary<int, ELFSymbol[]>)[n] <- symbols

  let getSymbolSections shdrs =
    shdrs
    |> Array.choose (fun s ->
      if s.SecType = SectionType.SHT_SYMTAB
        || s.SecType = SectionType.SHT_DYNSYM
      then Some s.SecNum
      else None)
    |> Array.map (fun n -> n, shdrs[n])

  let getMergedSymbolTbl (symTbls: Dictionary<_, _>) numbers =
    numbers
    |> Array.fold (fun acc n -> Array.append (symTbls[n]) acc) [||]

  let getStaticSymArray shdrs symTbl =
    getStaticSymbolSectionNumbers shdrs
    |> getMergedSymbolTbl symTbl

  let getDynamicSymArray shdrs symTbl =
    getDynamicSymbolSectionNumbers shdrs
    |> getMergedSymbolTbl symTbl

  let buildSymbolMap staticSymArr dynamicSymArr =
    let map = Dictionary<Addr, ELFSymbol> ()
    let iterator sym =
      if sym.Addr > 0UL then map[sym.Addr] <- sym
      else ()
    staticSymArr |> Array.iter iterator
    dynamicSymArr |> Array.iter iterator
    map

  let parse toolBox shdrs =
    let verTbl = parseVersionTable toolBox shdrs
    let symSecs = getSymbolSections shdrs
    let symTbl = Dictionary ()
    parseSymTabs toolBox symTbl shdrs verTbl symSecs
    let staticSymArr = getStaticSymArray shdrs symTbl
    let dynamicSymArr = getDynamicSymArray shdrs symTbl
    { VersionTable = verTbl
      SecNumToSymbTbls = symTbl
      AddrToSymbTable = buildSymbolMap staticSymArr dynamicSymArr }

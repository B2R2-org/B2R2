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
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents a DWARF compilation/type unit, which contains a list of DIEs.
type internal DWUnitInfo =
  { UnitOffset: int
    UnitLength: int
    Version: uint16
    UnitType: DWUnitType
    AddrSize: int
    AbbrevOffset: uint64
    AbbrevTable: DWAbbrevTable
    OffsetSize: int
    BodyOffset: uint64 }

/// Represents a DWARF abbreviation table keyed by abbreviation code.
and internal DWAbbrevTable = Map<uint64, DWAbbrevEntry>

/// Represents a single abbreviation entry in the DWARF abbreviation table.
and internal DWAbbrevEntry =
  { Code: uint64
    Tag: DWTag
    HasChildren: bool
    AttributeSpecs: DWAbbrevAttributeSpec list }

/// Represents an attribute specification in a DWARF abbreviation entry.
and internal DWAbbrevAttributeSpec =
  { Attribute: DWAttribute
    Form: DWForm
    ImplicitConst: int64 option }

[<RequireQualifiedAccess>]
module internal DWAbbrevTable =
  let rec private parseAttributeSpecs span offset acc =
    let attr, offset = readULEB128 span offset
    let form, offset = readULEB128 span offset
    if attr = 0UL && form = 0UL then
      List.rev acc, offset
    else
      let form = DWForm.parse (uint16 form)
      let implicitConst, offset =
        if form = DWForm.DW_FORM_implicit_const then
          let value, offset = readSLEB128 span offset
          Some value, offset
        else None, offset
      let spec =
        { Attribute = DWAttribute.parse (uint16 attr)
          Form = form
          ImplicitConst = implicitConst }
      parseAttributeSpecs span offset (spec :: acc)

  let rec private parseEntries (reader: IBinReader) span offset table =
    let code, offset = readULEB128 span offset
    if code = 0UL then
      table
    else
      let tag, offset = readULEB128 span offset
      let hasChildren = reader.ReadUInt8(span, offset) <> 0uy
      let specs, offset = parseAttributeSpecs span (offset + 1) []
      let entry =
        { Code = code
          Tag = DWTag.parse (uint16 tag)
          HasChildren = hasChildren
          AttributeSpecs = specs }
      parseEntries reader span offset (Map.add code entry table)

  let parse toolBox (shdr: SectionHeader option) (offset: uint64) =
    let offset = Convert.ToInt32 offset
    match shdr with
    | Some shdr ->
      let shOffset, shSize = shdr.SecOffset, shdr.SecSize
      let span = ReadOnlySpan(toolBox.Bytes, int shOffset, int shSize)
      assert (offset < span.Length)
      parseEntries toolBox.Reader span offset Map.empty
    | None ->
      Map.empty

[<RequireQualifiedAccess>]
module internal DebugInformation =
  let findMainSections (shdrs: SectionHeader[]) =
    let mutable infoSec, abbrevSec = None, None
    for shdr in shdrs do
      match shdr.SecName with
      | Section.DebugInfo -> infoSec <- Some shdr
      | Section.DebugAbbrev -> abbrevSec <- Some shdr
      | _ -> ()
    struct (infoSec, abbrevSec)

  let assertSupportedUnitType = function
    | DWUnitType.DW_UT_compile
    | DWUnitType.DW_UT_partial ->
      ()
    | t ->
      eprintsn $"Unsupported DWARF unit type: {t}"
      Terminator.futureFeature ()

  let readUInt24 (reader: IBinReader) (span: ByteSpan) offset =
    let b0 = uint64 span[offset]
    let b1 = uint64 span[offset + 1]
    let b2 = uint64 span[offset + 2]
    match reader.Endianness with
    | Endian.Little -> b0 ||| (b1 <<< 8) ||| (b2 <<< 16)
    | _ -> (b0 <<< 16) ||| (b1 <<< 8) ||| b2

  let readUIntBySize (reader: IBinReader) (span: ByteSpan) size offset =
    match size with
    | 1 -> uint64 (reader.ReadUInt8(span, offset))
    | 2 -> uint64 (reader.ReadUInt16(span, offset))
    | 3 -> readUInt24 reader span offset
    | 4 -> uint64 (reader.ReadUInt32(span, offset))
    | 8 -> reader.ReadUInt64(span, offset)
    | n ->
      eprintsn $"Unsupported DWARF value size: {n}"
      Terminator.impossible ()

  let readBytes (span: ByteSpan) count offset =
    span.Slice(offset, count).ToArray(), offset + count

  let rec findNull (span: ByteSpan) i =
    if span[i] = 0uy then i + 1 else findNull span (i + 1)

  let readCStringValue (span: ByteSpan) offset =
    let s = readCString span offset
    DWString s, findNull span offset

  let readBlock (span: ByteSpan) len offset ctor =
    let bytes, offset = readBytes span len offset
    ctor bytes, offset

  let readOffsetValue reader span offsetSize offset ctor =
    ctor (readUIntBySize reader span offsetSize offset), offset + offsetSize

  let rec readFormValue reader span unit spec offsetSize offset =
    match spec.Form with
    | DWForm.DW_FORM_addr ->
      let addrSize = unit.AddrSize
      DWAddr(readUIntBySize reader span addrSize offset), offset + addrSize
    | DWForm.DW_FORM_block2 ->
      let len = int (reader.ReadUInt16(span, offset))
      readBlock span len (offset + 2) DWBlock
    | DWForm.DW_FORM_block4 ->
      let len = int (reader.ReadUInt32(span, offset))
      readBlock span len (offset + 4) DWBlock
    | DWForm.DW_FORM_data2 ->
      DWUInt(uint64 (reader.ReadUInt16(span, offset))), offset + 2
    | DWForm.DW_FORM_data4 ->
      DWUInt(uint64 (reader.ReadUInt32(span, offset))), offset + 4
    | DWForm.DW_FORM_data8 ->
      DWUInt(reader.ReadUInt64(span, offset)), offset + 8
    | DWForm.DW_FORM_string ->
      readCStringValue span offset
    | DWForm.DW_FORM_block ->
      let len, offset = readULEB128 span offset
      readBlock span (int len) offset DWBlock
    | DWForm.DW_FORM_block1 ->
      let len = int (reader.ReadUInt8(span, offset))
      readBlock span len (offset + 1) DWBlock
    | DWForm.DW_FORM_data1 ->
      DWUInt(uint64 (reader.ReadUInt8(span, offset))), offset + 1
    | DWForm.DW_FORM_flag ->
      DWBool(reader.ReadUInt8(span, offset) <> 0uy), offset + 1
    | DWForm.DW_FORM_sdata ->
      let v, offset = readSLEB128 span offset
      DWSInt v, offset
    | DWForm.DW_FORM_strp
    | DWForm.DW_FORM_strp_sup
    | DWForm.DW_FORM_GNU_strp_alt ->
      readOffsetValue reader span offsetSize offset DWStringOffset
    | DWForm.DW_FORM_udata ->
      let v, offset = readULEB128 span offset
      DWUInt v, offset
    | DWForm.DW_FORM_ref_addr ->
      readOffsetValue reader span offsetSize offset DWDebugInfoRef
    | DWForm.DW_FORM_ref1 ->
      DWUnitRef(uint64 (reader.ReadUInt8(span, offset))), offset + 1
    | DWForm.DW_FORM_ref2 ->
      DWUnitRef(uint64 (reader.ReadUInt16(span, offset))), offset + 2
    | DWForm.DW_FORM_ref4 ->
      DWUnitRef(uint64 (reader.ReadUInt32(span, offset))), offset + 4
    | DWForm.DW_FORM_ref8 ->
      DWUnitRef(reader.ReadUInt64(span, offset)), offset + 8
    | DWForm.DW_FORM_ref_udata ->
      let v, offset = readULEB128 span offset
      DWUnitRef v, offset
    | DWForm.DW_FORM_indirect ->
      let form, offset = readULEB128 span offset
      let form = DWForm.parse (uint16 form)
      let spec = { spec with Form = form; ImplicitConst = None }
      let value, offset = readFormValue reader span unit spec offsetSize offset
      DWIndirect(form, value), offset
    | DWForm.DW_FORM_sec_offset ->
      readOffsetValue reader span offsetSize offset DWSectionOffset
    | DWForm.DW_FORM_exprloc ->
      let len, offset = readULEB128 span offset
      readBlock span (int len) offset DWExprLoc
    | DWForm.DW_FORM_flag_present ->
      DWBool true, offset
    | DWForm.DW_FORM_ref_sig8 ->
      DWTypeSignature(reader.ReadUInt64(span, offset)), offset + 8
    | DWForm.DW_FORM_strx ->
      let v, offset = readULEB128 span offset
      DWStringIndex v, offset
    | DWForm.DW_FORM_addrx ->
      let v, offset = readULEB128 span offset
      DWAddrIndex v, offset
    | DWForm.DW_FORM_ref_sup4 ->
      DWSupRef(uint64 (reader.ReadUInt32(span, offset))), offset + 4
    | DWForm.DW_FORM_ref_sup8 ->
      DWSupRef(reader.ReadUInt64(span, offset)), offset + 8
    | DWForm.DW_FORM_data16 ->
      let bytes, offset = readBytes span 16 offset
      DWBytes bytes, offset
    | DWForm.DW_FORM_line_strp ->
      readOffsetValue reader span offsetSize offset DWLineStringOffset
    | DWForm.DW_FORM_implicit_const ->
      match spec.ImplicitConst with
      | Some value -> DWImplicitConst value, offset
      | None ->
        eprintsn "DW_FORM_implicit_const requires abbrev-side constant support."
        Terminator.impossible ()
    | DWForm.DW_FORM_loclistx ->
      let v, offset = readULEB128 span offset
      DWLocListIndex v, offset
    | DWForm.DW_FORM_rnglistx ->
      let v, offset = readULEB128 span offset
      DWRangeListIndex v, offset
    | DWForm.DW_FORM_strx1 ->
      DWStringIndex(uint64 (reader.ReadUInt8(span, offset))), offset + 1
    | DWForm.DW_FORM_strx2 ->
      DWStringIndex(uint64 (reader.ReadUInt16(span, offset))), offset + 2
    | DWForm.DW_FORM_strx3 ->
      DWStringIndex(readUInt24 reader span offset), offset + 3
    | DWForm.DW_FORM_strx4 ->
      DWStringIndex(uint64 (reader.ReadUInt32(span, offset))), offset + 4
    | DWForm.DW_FORM_addrx1 ->
      DWAddrIndex(uint64 (reader.ReadUInt8(span, offset))), offset + 1
    | DWForm.DW_FORM_addrx2 ->
      DWAddrIndex(uint64 (reader.ReadUInt16(span, offset))), offset + 2
    | DWForm.DW_FORM_addrx3 ->
      DWAddrIndex(readUInt24 reader span offset), offset + 3
    | DWForm.DW_FORM_addrx4 ->
      DWAddrIndex(uint64 (reader.ReadUInt32(span, offset))), offset + 4
    | DWForm.DW_FORM_GNU_addr_index ->
      readOffsetValue reader span offsetSize offset DWAddrIndex
    | DWForm.DW_FORM_GNU_str_index ->
      readOffsetValue reader span offsetSize offset DWStringIndex
    | DWForm.DW_FORM_GNU_ref_alt ->
      readOffsetValue reader span offsetSize offset DWSupRef
    | _ ->
      Terminator.impossible ()

  let rec readAttributeValuesLoop reader span unit offsetSize offset acc =
    function
    | [] -> List.rev acc, offset
    | spec :: rest ->
      let value, offset = readFormValue reader span unit spec offsetSize offset
      let attr =
        { Attribute = spec.Attribute
          Form = spec.Form
          Value = value }
      let acc = attr :: acc
      readAttributeValuesLoop reader span unit offsetSize offset acc rest

  let readAttributeValues toolBox unit (span: ByteSpan) offset specs =
    let reader = toolBox.Reader
    readAttributeValuesLoop reader span unit unit.OffsetSize offset [] specs

  let rec parseUnitDIEs toolBox (span: ByteSpan) unit offset level dies =
    if offset = span.Length then
      if level = 0 then List.rev dies |> List.toArray
      else eprintsn "Unexpected end of DIE list"; Terminator.impossible ()
    else
      let dieOffset = uint64 offset + unit.BodyOffset
      let abbrevNumber, offset = readULEB128 span offset
      if abbrevNumber = 0UL then
        if level > 0 then
          parseUnitDIEs toolBox span unit offset (level - 1) dies
        elif
          offset = span.Length then List.rev dies |> List.toArray
        else
          eprintsn "Unexpected null DIE at top level"; Terminator.impossible ()
      else
        match Map.tryFind abbrevNumber unit.AbbrevTable with
        | Some abbrev ->
          let attrs, offset =
            readAttributeValues toolBox unit span offset abbrev.AttributeSpecs
          let die =
            { Offset = dieOffset
              Tag = abbrev.Tag
              HasChildren = abbrev.HasChildren
              Attributes = attrs }
          let nextLevel = if abbrev.HasChildren then level + 1 else level
          parseUnitDIEs toolBox span unit offset nextLevel (die :: dies)
        | None ->
          eprintsn $"Abbreviation code {abbrevNumber} not found."
          Terminator.impossible ()

  let rec scanCompilationUnits toolBox abbrevSec (span: ByteSpan) offset acc =
    let reader = toolBox.Reader
    if offset < span.Length then
      let unitOffset = offset
      let len = reader.ReadInt32(span = span, offset = offset)
      let len, initialLengthSize, cls =
        if len <> 0xffffffff then len, 4, WordSize.Bit32
        else int (reader.ReadInt64(span, offset + 4)), 12, WordSize.Bit64
      let unitEnd = unitOffset + initialLengthSize + len
      assert (unitEnd <= span.Length)
      let version = reader.ReadUInt16(span, offset + initialLengthSize)
      if version < 5us then
        Terminator.futureFeature ()
      else
        let headerOffset = unitOffset + initialLengthSize + 2
        let unitType = reader.ReadUInt8(span, headerOffset) |> DWUnitType.parse
        let ptrSize = reader.ReadUInt8(span, headerOffset + 1) |> int
        let abbrevOffset = readUIntByWordSize span reader cls (headerOffset + 2)
        let offsetSize = selectByWordSize cls 4 8
        let bodyOffset = headerOffset + 2 + offsetSize
        assertSupportedUnitType unitType
        let abbrevTable = DWAbbrevTable.parse toolBox abbrevSec abbrevOffset
        let unit =
          { UnitOffset = unitOffset
            UnitLength = len
            Version = version
            UnitType = unitType
            AddrSize = ptrSize
            AbbrevOffset = abbrevOffset
            AbbrevTable = abbrevTable
            OffsetSize = offsetSize
            BodyOffset = uint64 bodyOffset }
        let bodySpan = span.Slice(bodyOffset, unitEnd - bodyOffset)
        let dies = parseUnitDIEs toolBox bodySpan unit 0 0 []
        scanCompilationUnits toolBox abbrevSec span unitEnd (dies :: acc)
    else
      List.rev acc
      |> Array.concat

  let parse toolBox (shdrs: SectionHeader[]) =
    let struct (infoSec, abbrevSec) = findMainSections shdrs
    match infoSec with
    | Some shdr ->
      let shOffset, shSize = shdr.SecOffset, shdr.SecSize
      let span = ReadOnlySpan(toolBox.Bytes, int shOffset, int shSize)
      scanCompilationUnits toolBox abbrevSec span 0 []
    | None ->
      [||]

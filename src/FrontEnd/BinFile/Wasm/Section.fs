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

module internal B2R2.FrontEnd.BinFile.Wasm.Section

open System
open System.Text
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Wasm.Expression

let [<Literal>] CustomName = "name"

let peekVectorLen (bs: byte[]) (reader: IBinReader) offset =
  reader.ReadUInt32LEB128(bs, offset)

let peekVector bs (reader: IBinReader) offset pe =
  let vecLen, len = peekVectorLen bs reader offset
  let rec loop (acc: _[]) (count: uint32) (nOff: int) =
    if count = 0u then
      acc, uint32 (nOff - offset)
    else
      let e, no = pe bs reader nOff
      loop (Array.append acc [| e |]) (count - 1u) no
  let elems, size = loop [||] vecLen (offset + len)
  { Length = vecLen
    Elements = elems
    Size = size }

let peekByteVector (bs: byte[]) reader offset =
  let pb (bs: byte[]) (_: IBinReader) (o: int) = bs[o], o + 1
  peekVector bs reader offset pb

/// Reads one index out of a vector of them, in the shape a vector's element
/// reader takes: the second half of the pair is where the next element
/// starts, not how many bytes this one spans.
let peekIdx (bs: byte[]) (reader: IBinReader) offset =
  let idx, len = reader.ReadUInt32LEB128(bs, offset)
  idx, offset + len

let peekName bs reader offset =
  let vec = peekByteVector bs reader offset
  vec.Elements
  |> Encoding.UTF8.GetString, vec.Size

let peekSectionId (bs: byte[]) reader offset =
  (reader: IBinReader).ReadUInt8(bs, offset)
  |> LanguagePrimitives.EnumOfValue

let peekSectionHeader bs reader offset =
  let secId: SectionId = peekSectionId bs reader offset
  let secContSize, len = reader.ReadUInt32LEB128(bs, offset + 1)
  secId, secContSize, len

let parseSection bs reader offset (pc: byte[] -> IBinReader -> int -> 'TC) =
  let id, contSize, len = peekSectionHeader bs reader offset
  let headerSize = len + 1
  let contOff = offset + headerSize
  let contents = if contSize = 0u then None else Some(pc bs reader contOff)
  { Id = id
    Size = contSize
    Offset = offset
    Contents = contents }

let peekNameAssoc (bs: byte[]) (reader: IBinReader) offset =
  let idx, len = reader.ReadUInt32LEB128(bs, offset)
  let name, nameLen = peekName bs reader (offset + len)
  { Index = idx; Name = name }, offset + len + int nameLen

let parseNameSection (bs: byte[]) (reader: IBinReader) startOff endOff =
  let rec loop funcNames modName off =
    if off >= endOff then
      { ModuleName = modName; FunctionNames = funcNames }
    else
      let subId: NameSubsectionId =
        reader.ReadUInt8(bs, off) |> LanguagePrimitives.EnumOfValue
      let subSize, lenLen = reader.ReadUInt32LEB128(bs, off + 1)
      let payloadOff = off + 1 + lenLen
      let next = payloadOff + int subSize
      match subId with
      | NameSubsectionId.Module ->
        let name, _ = peekName bs reader payloadOff
        loop funcNames (Some name) next
      | NameSubsectionId.Function ->
        let vec = peekVector bs reader payloadOff peekNameAssoc
        loop vec.Elements modName next
      | _ ->
        loop funcNames modName next
  loop [||] None startOff

let parseCustomSec bs (reader: IBinReader) offset =
  let _, contSize, len = peekSectionHeader bs reader offset
  let contOff = offset + len + 1
  let contents =
    if contSize = 0u then
      None
    else
      let name, rawLen = peekName bs reader contOff
      let payloadOff = contOff + int rawLen
      let payloadEnd = contOff + int contSize
      let nameSec =
        if name = CustomName then
          Some(parseNameSection bs reader payloadOff payloadEnd)
        else
          None
      Some { Name = name; Size = contSize; NameSection = nameSec }
  { Id = SectionId.Custom
    Size = contSize
    Offset = offset
    Contents = contents }

let peekValTypeVec bs reader offset =
  let pvt (bs: byte[]) (r: IBinReader) (o: int) =
    let b = bs[o]
    let valt: Wasm.ValueType = b |> LanguagePrimitives.EnumOfValue
    valt, o + 1
  peekVector bs reader offset pvt

let peekFuncType bs reader offset =
  let offset' = offset + 1
  let paramTypes = peekValTypeVec bs reader offset'
  let rtOffset = offset' + int paramTypes.Size
  let resultTypes = peekValTypeVec bs reader rtOffset
  { ParameterTypes = paramTypes
    ResultTypes = resultTypes }, rtOffset + int resultTypes.Size

let peekTypeSecContents bs reader offset =
  peekVector bs reader offset peekFuncType

let parseTypeSec bs reader offset =
  parseSection bs reader offset peekTypeSecContents

let peekLimits (bs: byte[]) (reader: IBinReader) offset =
  let limitsKind =
    reader.ReadUInt8(bs, offset)
    |> LanguagePrimitives.EnumOfValue
  let offset' = offset + 1
  match limitsKind with
  | LimitsKind.Min ->
    let mn, len = reader.ReadUInt32LEB128(bs, offset')
    Min mn, (offset' + len)
  | LimitsKind.MinMax ->
    let mn, mnLen = reader.ReadUInt32LEB128(bs, offset')
    let mx, mxLen = reader.ReadUInt32LEB128(bs, offset' + mnLen)
    MinMax(mn, mx), (offset' + mnLen + mxLen)
  | _ ->
    raise InvalidFileFormatException

let peekTableType (bs: byte[]) (reader: IBinReader) offset =
  let elemType =
    reader.ReadUInt8(bs, offset)
    |> LanguagePrimitives.EnumOfValue
  let offset' = offset + 1
  let limits, no = peekLimits bs reader (offset')
  { ElemType = elemType
    Limits = limits }, no

let peekGlobalType (bs: byte[]) (reader: IBinReader) offset =
  let valType =
    reader.ReadUInt8(bs, offset)
    |> LanguagePrimitives.EnumOfValue
  let mut =
    reader.ReadUInt8(bs, offset + 1)
    |> LanguagePrimitives.EnumOfValue
  { ValueType = valType; Mutable = mut }, offset + 2

let peekImportDesc (bs: byte[]) (reader: IBinReader) offset =
  let descKind =
    reader.ReadUInt8(bs, offset)
    |> LanguagePrimitives.EnumOfValue
  match descKind with
  | ImportDescKind.Func ->
    let typeIdx, len = reader.ReadUInt32LEB128(bs, offset + 1)
    ImpFunc(typeIdx), (offset + 1 + len)
  | ImportDescKind.Table ->
    let tableType, size = peekTableType bs reader (offset + 1)
    ImpTable(tableType), (offset + 1 + size)
  | ImportDescKind.Mem ->
    let mem, size = peekLimits bs reader (offset + 1)
    ImpMem(mem), (offset + 1 + size)
  | ImportDescKind.Global ->
    let glob, size = peekGlobalType bs reader (offset + 1)
    ImpGlobal(glob), (offset + 1 + size)
  | _ ->
    raise InvalidFileFormatException

let peekImportEntry bs reader offset =
  let modName, rawLen = peekName bs reader offset
  let offset' = (offset + int rawLen)
  let impName, rawLen = peekName bs reader offset'
  let impDesc, nOff = peekImportDesc bs reader (offset' + int rawLen)
  { Offset = offset
    ModuleName = modName
    Name = impName
    Desc = impDesc }, nOff

let peekImportSecContents bs reader offset =
  peekVector bs reader offset peekImportEntry

let parseImportSec bs reader offset =
  parseSection bs reader offset peekImportSecContents

let peekFunctionSecContents bs reader offset =
  peekVector bs reader offset peekIdx

let parseFunctionSec bs reader offset =
  parseSection bs reader offset peekFunctionSecContents

let peekTableSecContents bs reader offset =
  peekVector bs reader offset peekTableType

let parseTableSec bs reader offset =
  parseSection bs reader offset peekTableSecContents

let peekMemorySecContents bs reader offset =
  peekVector bs reader offset peekLimits

let parseMemorySec bs reader offset =
  parseSection bs reader offset peekMemorySecContents

let peekGlobalVar bs reader offset =
  let gt, no = peekGlobalType bs reader offset
  let expr, no' = peekConstExpr (ReadOnlySpan bs) reader no
  { Type = gt; InitExpr = expr }, no'

let peekGlobalSecContents bs reader offset =
  peekVector bs reader offset peekGlobalVar

let parseGlobalSec bs reader offset =
  parseSection bs reader offset peekGlobalSecContents

let peekExportDesc (bs: byte[]) (reader: IBinReader) offset =
  let descKind =
    reader.ReadUInt8(bs, offset)
    |> LanguagePrimitives.EnumOfValue
  match descKind with
  | ExportDescKind.Func ->
    let typeIdx, len = reader.ReadUInt32LEB128(bs, offset + 1)
    ExpFunc(typeIdx), offset + 1 + len
  | ExportDescKind.Table ->
    let tableIdx, len = reader.ReadUInt32LEB128(bs, offset + 1)
    ExpTable(tableIdx), offset + 1 + len
  | ExportDescKind.Mem ->
    let memIdx, len = reader.ReadUInt32LEB128(bs, offset + 1)
    ExpMem(memIdx), offset + 1 + len
  | ExportDescKind.Global ->
    let globalIdx, len = reader.ReadUInt32LEB128(bs, offset + 1)
    ExpGlobal(globalIdx), offset + 1 + len
  | _ ->
    raise InvalidFileFormatException

let peekExportEntry bs reader offset =
  let name, rawLen = peekName bs reader offset
  let offset' = (offset + int rawLen)
  let exportDesc, nOff = peekExportDesc bs reader offset'
  { Offset = offset
    Name = name
    Desc = exportDesc }, nOff

let peekExportSecContents bs reader offset =
  peekVector bs reader offset peekExportEntry

let parseExportSec bs reader offset =
  parseSection bs reader offset peekExportSecContents

let peekStartFunc (bs: byte[]) (reader: IBinReader) offset =
  let funcIdx, _ = reader.ReadUInt32LEB128(bs, offset)
  funcIdx

let parseStartSec bs reader offset = parseSection bs reader offset peekStartFunc

let private peekElemExpr (bs: byte[]) reader offset =
  peekConstExpr (ReadOnlySpan bs) reader offset

/// Reads the entries of an element segment, which bit 2 of the mode spells
/// out as expressions rather than as function indices.
let private peekElemInit bs reader mode offset =
  if mode &&& 4u = 0u then
    let funcs = peekVector bs reader offset peekIdx
    ElemFuncs funcs, offset + int funcs.Size
  else
    let exprs = peekVector bs reader offset peekElemExpr
    ElemExprs exprs, offset + int exprs.Size

/// Reads the table an element segment fills and the offset it fills from,
/// which only an active segment has. Bit 0 of the mode marks the segment
/// passive or declarative, and bit 1 gives an active one an explicit table
/// and the others a single byte naming the type of their entries.
let private peekElemTarget (bs: byte[]) (reader: IBinReader) mode offset =
  match mode &&& 3u with
  | 0u ->
    let expr, no = peekConstExpr (ReadOnlySpan bs) reader offset
    0u, Some expr, no
  | 2u ->
    let tableIdx, len = reader.ReadUInt32LEB128(bs, offset)
    let expr, no = peekConstExpr (ReadOnlySpan bs) reader (offset + len)
    tableIdx, Some expr, no + 1
  | _ ->
    0u, None, offset + 1

let peekElemSeg (bs: byte[]) (reader: IBinReader) offset =
  let mode, len = reader.ReadUInt32LEB128(bs, offset)
  let tableIdx, expr, no = peekElemTarget bs reader mode (offset + len)
  let init, offset' = peekElemInit bs reader mode no
  { Mode = mode
    TableIndex = tableIdx
    OffsetExpr = expr
    Init = init }, offset'

let peekElementSecContents bs reader offset =
  peekVector bs reader offset peekElemSeg

let parseElementSec bs reader offset =
  parseSection bs reader offset peekElementSecContents

let rec parseLocalDecls (bs: byte[]) (reader: IBinReader) locals len pos =
  if len = 0 then
    locals
  else
    let localDeclCnt, rawLen = reader.ReadUInt32LEB128(bs, pos)
    let localDeclType = bs[pos + rawLen]
    let local =
      { LocalDeclCount = localDeclCnt
        LocalDeclType = localDeclType
        LocalDeclLen = rawLen + 1 }
    let locals = locals @ [ local ]
    parseLocalDecls bs reader locals (len - 1) (pos + rawLen + 1)

let peekCodeEntry (bs: byte[]) (reader: IBinReader) offset =
  let codeSize, len = reader.ReadUInt32LEB128(bs, offset)
  let pos = offset + len
  let localsCnt, rawLen = reader.ReadUInt32LEB128(bs, pos)
  let locals = parseLocalDecls bs reader [] (int localsCnt) (pos + rawLen)
  { Offset = offset
    LenFieldSize = len
    CodeSize = codeSize
    LocalsSize = rawLen + List.sumBy (fun l -> l.LocalDeclLen) locals
    Locals = locals }, offset + len + int codeSize

let peekCodeSecContents bs reader offset =
  peekVector bs reader offset peekCodeEntry

let parseCodeSec bs reader offset =
  parseSection bs reader offset peekCodeSecContents

/// Reads the memory a data segment fills and the offset it fills from. Mode
/// 1 is a passive segment, which has neither; mode 2 names its memory where
/// mode 0 takes the first one.
let private peekDataTarget (bs: byte[]) (reader: IBinReader) mode offset =
  match mode with
  | 0u ->
    let expr, no = peekConstExpr (ReadOnlySpan bs) reader offset
    0u, Some expr, no
  | 2u ->
    let memIdx, len = reader.ReadUInt32LEB128(bs, offset)
    let expr, no = peekConstExpr (ReadOnlySpan bs) reader (offset + len)
    memIdx, Some expr, no
  | _ ->
    0u, None, offset

let peekDataSeg (bs: byte[]) (reader: IBinReader) offset =
  let mode, len = reader.ReadUInt32LEB128(bs, offset)
  let memIdx, expr, no = peekDataTarget bs reader mode (offset + len)
  let byteVec = peekByteVector bs reader no
  { Mode = mode
    MemoryIndex = memIdx
    OffsetExpr = expr
    InitBytes = byteVec }, no + int byteVec.Size

let peekDataSecContents bs reader offset =
  peekVector bs reader offset peekDataSeg

let parseDataSec bs reader offset =
  parseSection bs reader offset peekDataSecContents

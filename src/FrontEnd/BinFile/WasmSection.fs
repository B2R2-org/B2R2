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
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Wasm.Expression

let peekVectorLen (bs: byte[]) (reader: IBinReader) offset =
  reader.ReadUInt32LEB128 (bs, offset)

let peekVector bs (reader: IBinReader) offset pe =
  let vecLen, len = peekVectorLen bs reader offset
  let rec loop (acc: _ []) (count: uint32) (nOff: int) =
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
  let pb (bs: byte[]) (r: IBinReader) (o: int) =
    r.ReadByte (bs, o), o + 1
  peekVector bs reader offset pb

let peekName bs reader offset =
  let vec = peekByteVector bs reader offset
  vec.Elements
  |> Encoding.UTF8.GetString, vec.Size

let peekSectionId (bs: byte[]) reader offset =
  (reader: IBinReader).ReadUInt8 (bs, offset)
  |> LanguagePrimitives.EnumOfValue

let peekSectionHeader bs reader offset =
  let secId: SectionId = peekSectionId bs reader offset
  let secContSize, len = reader.ReadUInt32LEB128 (bs, offset + 1)
  secId, secContSize, len

let parseSection bs reader offset (pc: byte[] -> IBinReader -> int -> 'TC) =
  let id, contSize, len = peekSectionHeader bs reader offset
  let headerSize = len + 1
  let contOff = offset + headerSize
  let contents =
    if contSize = 0u then None
    else Some (pc bs reader contOff)
  { Id = id
    Size = contSize
    Offset = offset
    Contents = contents }

let peekCustomSecContents bs reader offset =
  let name, rawLen = peekName bs reader offset
  { Name = name; Size = rawLen }

let parseCustomSec bs reader offset =
  let sec = parseSection bs reader offset peekCustomSecContents
  let conts' =
    match sec.Contents with
    | Some conts ->
      Some { conts with Size = sec.Size }
    | None -> sec.Contents
  { sec with Contents = conts' }

let peekValTypeVec bs reader offset =
  let pvt (bs: byte[]) (r: IBinReader) (o: int) =
    let b = bs[o]
    let valt: Wasm.ValueType =
      b |> LanguagePrimitives.EnumOfValue
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
    reader.ReadUInt8 (bs, offset)
    |> LanguagePrimitives.EnumOfValue
  let offset' = offset + 1
  match limitsKind with
    | LimitsKind.Min ->
      let mn, len = reader.ReadUInt32LEB128 (bs, offset')
      Min mn, (offset' + len)
    | LimitsKind.MinMax ->
      let mn, mnLen = reader.ReadUInt32LEB128 (bs, offset')
      let mx, mxLen = reader.ReadUInt32LEB128 (bs, offset' + mnLen)
      MinMax (mn, mx), (offset' + mnLen + mxLen)
    | _ -> raise InvalidFileTypeException

let peekTableType (bs: byte[]) (reader: IBinReader) offset =
  let elemType =
    reader.ReadUInt8 (bs, offset)
    |> LanguagePrimitives.EnumOfValue
  let offset' = offset + 1
  let limits, no = peekLimits bs reader (offset')
  { ElemType = elemType
    Limits = limits }, no

let peekGlobalType (bs: byte[]) (reader: IBinReader) offset =
  let valType =
    reader.ReadUInt8 (bs, offset)
    |> LanguagePrimitives.EnumOfValue
  let mut =
    reader.ReadUInt8 (bs, offset + 1)
    |> LanguagePrimitives.EnumOfValue
  { ValueType = valType; Mutable = mut }, offset + 2

let peekImportDesc (bs: byte[]) (reader: IBinReader) offset =
  let descKind =
    reader.ReadUInt8 (bs, offset)
    |> LanguagePrimitives.EnumOfValue
  match descKind with
    | ImportDescKind.Func ->
      let typeIdx, len = reader.ReadUInt32LEB128 (bs, offset + 1)
      ImpFunc (typeIdx), (offset + 1 + len)
    | ImportDescKind.Table ->
      let tableType, size = peekTableType bs reader (offset + 1)
      ImpTable (tableType), (offset + 1 + size)
    | ImportDescKind.Mem ->
      let mem, size = peekLimits bs reader (offset + 1)
      ImpMem (mem), (offset + 1 + size)
    | ImportDescKind.Global ->
      let glob, size = peekGlobalType bs reader (offset + 1)
      ImpGlobal (glob), (offset + 1 + size)
    | _ -> raise InvalidFileTypeException

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
  let pti (bs: byte[]) (r: IBinReader) o =
    r.ReadUInt32LEB128 (bs, o)
  peekVector bs reader offset pti

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
    reader.ReadUInt8 (bs, offset)
    |> LanguagePrimitives.EnumOfValue
  match descKind with
    | ExportDescKind.Func ->
      let typeIdx, len = reader.ReadUInt32LEB128 (bs, offset + 1)
      ExpFunc (typeIdx), offset + 1 + len
    | ExportDescKind.Table ->
      let tableIdx, len = reader.ReadUInt32LEB128 (bs, offset + 1)
      ExpTable (tableIdx), offset + 1 + len
    | ExportDescKind.Mem ->
      let memIdx, len = reader.ReadUInt32LEB128 (bs, offset + 1)
      ExpMem (memIdx), offset + 1 + len
    | ExportDescKind.Global ->
      let globalIdx, len = reader.ReadUInt32LEB128 (bs, offset + 1)
      ExpGlobal (globalIdx), offset + 1 + len
    | _ -> raise InvalidFileTypeException

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
  let funcIdx, _ = reader.ReadUInt32LEB128 (bs, offset)
  funcIdx

let parseStartSec bs reader offset =
  parseSection bs reader offset peekStartFunc

let peekElemSeg (bs: byte[]) (reader: IBinReader) offset =
  let pti (bs: byte[]) (r: IBinReader) (o: int) =
    r.ReadUInt32LEB128 (bs, o)
  let tableIdx, len = reader.ReadUInt32LEB128 (bs, offset)
  let expr, no = peekConstExpr (ReadOnlySpan bs) reader (offset + len)
  let initFuncs = peekVector bs reader no pti
  let offset' = no + int initFuncs.Size
  { TableIndex = tableIdx
    OffsetExpr = expr
    InitFuncs = initFuncs }, offset'

let peekElementSecContents bs reader offset =
  peekVector bs reader offset peekElemSeg

let parseElementSec bs reader offset =
  parseSection bs reader offset peekElementSecContents

let peekCodeEntry (bs: byte[]) (reader: IBinReader) offset =
  let codeSize, len = reader.ReadUInt32LEB128 (bs, offset)
  { Offset = offset
    LenFieldSize = len
    CodeSize = codeSize }, offset + len + int codeSize

let peekCodeSecContents bs reader offset =
  peekVector bs reader offset peekCodeEntry

let parseCodeSec bs reader offset =
  parseSection bs reader offset peekCodeSecContents

let peekDataSeg (bs: byte[]) (reader: IBinReader) offset =
  let memIdx, len = reader.ReadUInt32LEB128 (bs, offset)
  let expr, no = peekConstExpr (ReadOnlySpan bs) reader (offset + len)
  let byteVec = peekByteVector bs reader no
  { MemoryIndex = memIdx
    OffsetExpr = expr
    InitBytes = byteVec }, no + int byteVec.Size

let peekDataSecContents bs reader offset =
  peekVector bs reader offset peekDataSeg

let parseDataSec bs reader offset =
  parseSection bs reader offset peekDataSecContents
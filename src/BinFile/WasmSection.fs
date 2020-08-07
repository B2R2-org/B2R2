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

module internal B2R2.BinFile.Wasm.Section

open B2R2
open B2R2.BinFile
open B2R2.BinFile.Wasm.Expression
open System.Text

let peekVectorLen (reader: BinReader) offset =
  reader.PeekUInt32LEB128 offset

let peekVector (reader: BinReader) offset pe =
  let vecLen, len = peekVectorLen reader offset
  let rec loop (acc: _ []) (count: uint32) (nOff: int) =
    if count = 0u then
      acc, uint32 (nOff - offset)
    else
      let e, no = pe reader nOff
      loop (Array.append acc [| e |]) (count - 1u) no
  let elems, size = loop [||] vecLen (offset + len)
  {
    Length = vecLen
    Elements = elems
    Size = size
  }

let peekByteVector (reader: BinReader) offset =
  let pb (r: BinReader) (o: int) =
    let struct(b, no) = r.ReadByte o
    b, no
  peekVector reader offset pb

let peekName (reader: BinReader) offset =
  let vec = peekByteVector reader offset
  vec.Elements
  |> Encoding.UTF8.GetString, vec.Size

let peekSectionId (reader: BinReader) offset: SectionId =
  reader.PeekUInt8(offset)
  |> LanguagePrimitives.EnumOfValue

let peekSectionHeader reader offset =
  let secId = peekSectionId reader offset
  let secContSize, len = reader.PeekUInt32LEB128 (offset + 1)
  secId, secContSize, len

let parseSection (reader: BinReader) offset (pc: BinReader -> int -> 'TC) =
  let id, contSize, len = peekSectionHeader reader offset
  let headerSize = len + 1
  let contOff = offset + headerSize
  let contents =
    if contSize = 0u then None
    else Some (pc reader contOff)
  {
    Id = id
    Size = contSize
    Offset = offset
    Contents = contents
  }

let peekCustomSecContents reader offset =
  let name, rawLen = peekName reader offset
  { Name = name; Size = rawLen }

let parseCustomSec (reader: BinReader) offset =
  let sec = parseSection reader offset peekCustomSecContents
  let size' =
    match sec.Contents with
    | Some conts ->
      sec.Size - conts.Size
    | None -> sec.Size
  {
    sec with
      Size = size'
  }

let peekValTypeVec (reader: BinReader) offset =
  let pvt (r: BinReader) (o: int) =
    let struct(b, no) = r.ReadByte o
    let valt: ValueType =
      b |> LanguagePrimitives.EnumOfValue
    valt, no
  peekVector reader offset pvt

let peekFuncType (reader: BinReader) offset =
  let offset' = offset + 1
  let paramTypes = peekValTypeVec reader offset'
  let rtOffset = offset' + int paramTypes.Size
  let resultTypes = peekValTypeVec reader rtOffset
  {
    ParameterTypes = paramTypes
    ResultTypes = resultTypes
  }, rtOffset + int resultTypes.Size

let peekTypeSecContents reader offset =
  peekVector reader offset peekFuncType

let parseTypeSec (reader: BinReader) offset =
  parseSection reader offset peekTypeSecContents

let peekLimits (reader: BinReader) offset =
  let limitsKind =
    reader.PeekUInt8 offset
    |> LanguagePrimitives.EnumOfValue
  let offset' = offset + 1
  match limitsKind with
    | LimitsKind.Min ->
      let mn, len = reader.PeekUInt32LEB128 (offset')
      Min mn, (offset' + len)
    | LimitsKind.MinMax ->
      let mn, mnLen = reader.PeekUInt32LEB128 (offset')
      let mx, mxLen = reader.PeekUInt32LEB128 (offset' + mnLen)
      MinMax (mn, mx), (offset' + mnLen + mxLen)
    | _ -> raise InvalidFileTypeException

let peekTableType (reader: BinReader) offset =
  let elemType =
    reader.PeekUInt8 offset
    |> LanguagePrimitives.EnumOfValue
  let offset' = offset + 1
  let limits, no = peekLimits reader (offset')
  {
    ElemType = elemType
    Limits = limits
  }, no

let peekGlobalType (reader: BinReader) offset =
  let valType =
    reader.PeekUInt8 offset
    |> LanguagePrimitives.EnumOfValue
  let mut =
    reader.PeekUInt8 (offset + 1)
    |> LanguagePrimitives.EnumOfValue
  { ValueType = valType; Mutable = mut }, offset + 2

let peekImportDesc (reader: BinReader) offset =
  let descKind =
    reader.PeekUInt8 offset
    |> LanguagePrimitives.EnumOfValue
  match descKind with
    | ImportDescKind.Func ->
      let typeIdx, len = reader.PeekUInt32LEB128 (offset + 1)
      ImpFunc (typeIdx), (offset + 1 + len)
    | ImportDescKind.Table ->
      let tableType, size = peekTableType reader (offset + 1)
      ImpTable (tableType), (offset + 1 + size)
    | ImportDescKind.Mem ->
      let mem, size = peekLimits reader (offset + 1)
      ImpMem (mem), (offset + 1 + size)
    | ImportDescKind.Global ->
      let glob, size = peekGlobalType reader (offset + 1)
      ImpGlobal (glob), (offset + 1 + size)
    | _ -> raise InvalidFileTypeException

let peekImportEntry (reader: BinReader) offset =
  let modName, rawLen = peekName reader offset
  let offset' = (offset + int rawLen)
  let impName, rawLen = peekName reader offset'
  let impDesc, nOff = peekImportDesc reader (offset' + int rawLen)
  {
    Offset = offset
    ModuleName = modName
    Name = impName
    Desc = impDesc
  }, nOff

let peekImportSecContents (reader: BinReader) offset =
  peekVector reader offset peekImportEntry

let parseImportSec (reader: BinReader) offset =
  parseSection reader offset peekImportSecContents

let peekFunctionSecContents (reader: BinReader) offset =
  let pti (r: BinReader) o =
    let struct(idx, no) = r.ReadUInt32LEB128 o
    idx, no
  peekVector reader offset pti

let parseFunctionSec (reader: BinReader) offset =
  parseSection reader offset peekFunctionSecContents

let peekTableSecContents (reader: BinReader) offset =
  peekVector reader offset peekTableType

let parseTableSec (reader: BinReader) offset =
  parseSection reader offset peekTableSecContents

let peekMemorySecContents (reader: BinReader) offset =
  peekVector reader offset peekLimits

let parseMemorySec (reader: BinReader) offset =
  parseSection reader offset peekMemorySecContents

let peekGlobalVar (reader: BinReader) offset =
  let gt, no = peekGlobalType reader offset
  let expr, no' = peekConstExpr reader no
  { Type = gt; InitExpr = expr }, no'

let peekGlobalSecContents (reader: BinReader) offset =
  peekVector reader offset peekGlobalVar

let parseGlobalSec (reader: BinReader) offset =
  parseSection reader offset peekGlobalSecContents

let peekExportDesc (reader: BinReader) offset =
  let descKind =
    reader.PeekUInt8 offset
    |> LanguagePrimitives.EnumOfValue
  match descKind with
    | ExportDescKind.Func ->
      let typeIdx, len = reader.PeekUInt32LEB128 (offset + 1)
      ExpFunc (typeIdx), offset + 1 + len
    | ExportDescKind.Table ->
      let tableIdx, len = reader.PeekUInt32LEB128 (offset + 1)
      ExpTable (tableIdx), offset + 1 + len
    | ExportDescKind.Mem ->
      let memIdx, len = reader.PeekUInt32LEB128 (offset + 1)
      ExpMem (memIdx), offset + 1 + len
    | ExportDescKind.Global ->
      let globalIdx, len = reader.PeekUInt32LEB128 (offset + 1)
      ExpGlobal (globalIdx), offset + 1 + len
    | _ -> raise InvalidFileTypeException

let peekExportEntry (reader: BinReader) offset =
  let name, rawLen = peekName reader offset
  let offset' = (offset + int rawLen)
  let exportDesc, nOff = peekExportDesc reader offset'
  {
    Offset = offset
    Name = name
    Desc = exportDesc
  }, nOff

let peekExportSecContents (reader: BinReader) offset =
  peekVector reader offset peekExportEntry

let parseExportSec (reader: BinReader) offset =
  parseSection reader offset peekExportSecContents

let peekStartFunc (reader: BinReader) offset =
  let funcIdx, _ = reader.PeekUInt32LEB128 offset
  funcIdx

let parseStartSec (reader: BinReader) offset =
  parseSection reader offset peekStartFunc

let peekElemSeg (reader: BinReader) offset =
  let pti (r: BinReader) (o: int) =
    let struct(i, no) = r.ReadUInt32LEB128 o
    i, no
  let tableIdx, len = reader.PeekUInt32LEB128 offset
  let expr, no = peekConstExpr reader (offset + len)
  let initFuncs = peekVector reader no pti
  let offset' = no + int initFuncs.Size
  {
    TableIndex = tableIdx
    OffsetExpr = expr
    InitFuncs = initFuncs
  }, offset'

let peekElementSecContents (reader: BinReader) offset =
  peekVector reader offset peekElemSeg

let parseElementSec (reader: BinReader) offset =
  parseSection reader offset peekElementSecContents

let peekCodeEntry (reader: BinReader) offset =
  let codeSize, len = reader.PeekUInt32LEB128 offset
  {
    Offset = offset
    LenFieldSize = len
    CodeSize = codeSize
  }, offset + len + int codeSize

let peekCodeSecContents (reader: BinReader) offset =
  peekVector reader offset peekCodeEntry

let parseCodeSec (reader: BinReader) offset =
  parseSection reader offset peekCodeSecContents

let peekDataSeg (reader: BinReader) offset =
  let memIdx, len = reader.PeekUInt32LEB128 offset
  let expr, no = peekConstExpr reader (offset + len)
  let byteVec = peekByteVector reader no
  {
    MemoryIndex = memIdx
    OffsetExpr = expr
    InitBytes = byteVec
  }, no + int byteVec.Size

let peekDataSecContents (reader: BinReader) offset =
  peekVector reader offset peekDataSeg

let parseDataSec (reader: BinReader) offset =
  parseSection reader offset peekDataSecContents
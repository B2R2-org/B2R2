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

module internal B2R2.BinFile.ELF.ExceptionFrames

open System
open B2R2
open B2R2.BinFile

/// Raised when an unhandled eh_frame version is encountered.
exception UnhandledExceptionHandlingFrameVersion

/// Raised when an unhandled augment string is encountered.
exception UnhandledAugString

/// Raised when an unhandled encoding is encountered.
exception UnhandledEncoding

let [<Literal>] ehframe = ".eh_frame"

let inline readInt (reader: BinReader) offset =
  reader.ReadInt32 offset

let inline readUInt64 (reader: BinReader) offset =
  reader.ReadUInt64 offset

let computeNextOffset len (reader: BinReader) offset =
  if len = -1 then
    let struct (len, offset) = readUInt64 reader offset
    int len + offset, offset
  else len + offset, offset

let parseULEB128 (reader: BinReader) offset =
  let span = reader.PeekSpan (offset)
  let v, cnt = LEB128.DecodeUInt64 span
  v, offset + cnt

let parseSLEB128 (reader: BinReader) offset =
  let span = reader.PeekSpan (offset)
  let v, cnt = LEB128.DecodeSInt64 span
  v, offset + cnt

let parseReturnRegister (reader: BinReader) version offset =
  if version = 1uy then reader.PeekByte offset |> uint64, offset + 1
  else parseULEB128 reader offset

let parseAugmentationData (reader: BinReader) offset augstr =
  if (augstr: string).StartsWith ('z') then
    let len, offset = parseULEB128 reader offset
    let span = reader.PeekSpan (int len, offset)
    let arr = span.ToArray ()
    Some arr, offset + int len
  else None, offset

let personalityRoutinePointerSize addrSize = function
  | 2uy -> 2
  | 3uy -> 4
  | 4uy -> 8
  | _ -> addrSize

let rec parseEncodingLoop addrSize (data: byte []) offset = function
  | 'L' :: rest -> parseEncodingLoop addrSize data (offset + 1) rest
  | 'P' :: rest ->
    let psz = data.[offset] &&& 7uy |> personalityRoutinePointerSize addrSize
    parseEncodingLoop addrSize data (offset + psz + 1) rest
  | 'R' :: _ ->
    let d = data.[offset]
    let v =
      int (d &&& 0x0Fuy)
      |> LanguagePrimitives.EnumOfValue<int, ExceptionHeaderValue>
    let app =
      int (d &&& 0xF0uy)
      |> LanguagePrimitives.EnumOfValue<int, ExceptionHeaderApplication>
    v, app
  | _ -> raise UnhandledAugString

let parseEncodingAndApp addrSize (augstr: string) augdata =
  match augdata with
  | None ->
    ExceptionHeaderValue.DW_EH_PE_absptr,
    ExceptionHeaderApplication.DW_EH_PE_absptr
  | Some (data: byte []) ->
    augstr.[1..]
    |> Seq.toList
    |> parseEncodingLoop addrSize data 0

let parseCIE cls (reader: BinReader) offset =
  let struct (version, offset) = reader.ReadByte offset
  if version = 1uy || version = 3uy then
    let span = reader.PeekSpan offset
    let augstr = ByteArray.extractCStringFromSpan span 0
    let addrSize = WordSize.toByteWidth cls
    let offset = offset + augstr.Length + 1
    let offset = if augstr.Contains "eh" then offset + addrSize else offset
    let codeAlignmentFactor, offset = parseULEB128 reader offset
    let dataAlignmentFactor, offset = parseSLEB128 reader offset
    let retReg, offset = parseReturnRegister reader version offset
    let augdata, _ = parseAugmentationData reader offset augstr
    let enc, app = parseEncodingAndApp addrSize augstr augdata
    { Version = version
      AugmentationString = augstr
      CodeAlignmentFactor = codeAlignmentFactor
      DataAlignmentFactor = dataAlignmentFactor
      ReturnAddressRegister = retReg
      AugmentationData = augdata
      FDEEncoding = enc
      FDEApplication = app }
  else
    raise UnhandledExceptionHandlingFrameVersion

let computePCInfo cls (reader: BinReader) cie offset =
  match cie.FDEEncoding with
  | ExceptionHeaderValue.DW_EH_PE_absptr ->
    let struct (addr, offset) = FileHelper.readUIntOfType reader cls offset
    let struct (len, _) = FileHelper.readUIntOfType reader cls offset
    addr, len
  | ExceptionHeaderValue.DW_EH_PE_uleb128 ->
    let addr, offset = parseULEB128 reader offset
    let len, _ = parseULEB128 reader offset
    addr, len
  | ExceptionHeaderValue.DW_EH_PE_udata2 ->
    let struct (addr, offset) = reader.ReadUInt16 offset
    let struct (len, _) = reader.ReadUInt16 offset
    uint64 addr, uint64 len
  | ExceptionHeaderValue.DW_EH_PE_sdata2 ->
    let struct (addr, offset) = reader.ReadInt16 offset
    let struct (len, _) = reader.ReadInt16 offset
    uint64 addr, uint64 len
  | ExceptionHeaderValue.DW_EH_PE_udata4 ->
    let struct (addr, offset) = reader.ReadUInt32 offset
    let struct (len, _) = reader.ReadUInt32 offset
    uint64 addr, uint64 len
  | ExceptionHeaderValue.DW_EH_PE_sdata4 ->
    let struct (addr, offset) = reader.ReadInt32 offset
    let struct (len, _) = reader.ReadInt32 offset
    uint64 addr, uint64 len
  | ExceptionHeaderValue.DW_EH_PE_udata8 ->
    let struct (addr, offset) = reader.ReadUInt64 offset
    let struct (len, _) = reader.ReadUInt64 offset
    addr, len
  | ExceptionHeaderValue.DW_EH_PE_sdata8 ->
    let struct (addr, offset) = reader.ReadInt64 offset
    let struct (len, _) = reader.ReadInt64 offset
    uint64 addr, uint64 len
  | _ -> raise UnhandledEncoding

let adjustPCAddr cie myAddr addr =
  match cie.FDEApplication with
  | ExceptionHeaderApplication.DW_EH_PE_pcrel -> addr + myAddr
  | _ -> addr

let parseFDE cls (reader: BinReader) sAddr cie offset =
  let myAddr = sAddr + uint64 offset
  let addr, len = computePCInfo cls reader cie offset
  let addr = adjustPCAddr cie myAddr addr
  { PCBegin = addr; PCEnd = addr + len }

let accumulateCFIs cfis cie fdes =
  match cie with
  | Some cie ->
    { CIERecord = cie
      FDERecord = List.rev fdes |> List.toArray } :: cfis
  | None -> cfis

let rec parseCallFrameInformation cls reader sAddr cie fdes offset cfis =
  if offset >= ((reader: BinReader).Length ()) then accumulateCFIs cfis cie fdes
  else
    let struct (len, offset) = readInt reader offset
    if len = 0 then accumulateCFIs cfis cie fdes
    else
      let nextOffset, offset = computeNextOffset len reader offset
      let struct (id, offset) = readInt reader offset
      if id = 0 then
        let cfis = accumulateCFIs cfis cie fdes
        let cie = parseCIE cls reader offset
        parseCallFrameInformation cls reader sAddr (Some cie) [] nextOffset cfis
      else
        match cie with
        | Some c ->
          let fde = parseFDE cls reader sAddr c offset
          let fdes = fde :: fdes
          parseCallFrameInformation cls reader sAddr cie fdes nextOffset cfis
        | None -> invalidArg "parseCallFrameInformation" "CIE not present"

let parse (reader: BinReader) cls (secs: SectionInfo) =
  match Map.tryFind ehframe secs.SecByName with
  | Some sec ->
    let size = Convert.ToInt32 sec.SecSize
    let offset = Convert.ToInt32 sec.SecOffset
    let reader = reader.SubReader offset size
    parseCallFrameInformation cls reader sec.SecAddr None [] 0 []
  | None -> []

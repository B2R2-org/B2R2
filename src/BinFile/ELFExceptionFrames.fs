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

[<RequireQualifiedAccess>]
module internal B2R2.BinFile.ELF.ExceptionFrames

open System
open B2R2
open B2R2.BinFile.ELF.ExceptionHeaderEncoding

/// Raised when an unhandled eh_frame version is encountered.
exception UnhandledExceptionHandlingFrameVersion

/// Raised when an unhandled augment string is encountered.
exception UnhandledAugString

/// Raised when CIE is not found by FDE
exception CIENotFoundByFDE

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

let parseReturnRegister (reader: BinReader) version offset =
  if version = 1uy then reader.PeekByte offset |> uint64, offset + 1
  else parseULEB128 reader offset

let personalityRoutinePointerSize addrSize = function
  | 2uy -> 2
  | 3uy -> 4
  | 4uy -> 8
  | _ -> addrSize

let obtainAugData addrSize (arr: byte []) data offset = function
  | 'L' ->
    let v, app = parseEncoding arr.[offset]
    { Format = 'L'
      ValueEncoding = v
      ApplicationEncoding = app
      PersonalityRoutionPointer = [||] } :: data, offset + 1
  | 'P' ->
    let v, app = parseEncoding arr.[offset]
    let psz = arr.[offset] &&& 7uy |> personalityRoutinePointerSize addrSize
    let prp = arr.[ offset + 1 .. offset + psz ]
    { Format = 'P'
      ValueEncoding = v
      ApplicationEncoding = app
      PersonalityRoutionPointer = prp } :: data, offset + psz + 1
  | 'R' ->
    let v, app = parseEncoding arr.[offset]
    { Format = 'R'
      ValueEncoding = v
      ApplicationEncoding = app
      PersonalityRoutionPointer = [||] } :: data, offset + 1
  | _ -> raise UnhandledAugString

let parseAugmentationData (reader: BinReader) offset addrSize augstr =
  if (augstr: string).StartsWith ('z') then
    let len, offset = parseULEB128 reader offset
    let span = reader.PeekSpan (int len, offset)
    let arr = span.ToArray ()
    augstr.[ 1.. ]
    |> Seq.fold (fun (data, idx) ch ->
      obtainAugData addrSize arr data idx ch) ([], 0)
    |> fst |> List.rev, offset + int len
  else [], offset

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
    let augs, _ = parseAugmentationData reader offset addrSize augstr
    { Version = version
      AugmentationString = augstr
      CodeAlignmentFactor = codeAlignmentFactor
      DataAlignmentFactor = dataAlignmentFactor
      ReturnAddressRegister = retReg
      Augmentations = augs }
  else
    raise UnhandledExceptionHandlingFrameVersion

let tryFindAugmentation cie format =
  cie.Augmentations |> List.tryFind (fun aug -> aug.Format = format)

let adjustAddr app myAddr addr =
  match app with
  | ExceptionHeaderApplication.DW_EH_PE_pcrel -> addr + myAddr
  | _ -> addr

let parsePCInfo cls reader sAddr venc aenc offset =
  let myAddr = sAddr + uint64 offset
  let struct (addr, offset) = computeValue cls reader venc offset
  let struct (range, offset) = computeValue cls reader venc offset
  let beginAddr = adjustAddr aenc myAddr addr
  let endAddr = beginAddr + range
  beginAddr, endAddr, offset

let parseLSDA cls reader sAddr aug offset =
  let _, offset = parseULEB128 reader offset
  let myAddr = sAddr + uint64 offset
  let struct (addr, _) = computeValue cls reader aug.ValueEncoding offset
  Some (adjustAddr aug.ApplicationEncoding myAddr addr)

let parseFDE cls reader sAddr cie offset =
  match cie with
  | Some cie ->
    let venc, aenc =
      match tryFindAugmentation cie 'R' with
      | Some aug -> aug.ValueEncoding, aug.ApplicationEncoding
      | None -> ExceptionHeaderValue.DW_EH_PE_absptr,
                ExceptionHeaderApplication.DW_EH_PE_absptr
    let beginAddr, endAddr, offset =
      parsePCInfo cls reader sAddr venc aenc offset
    let lsdaPointer =
      match tryFindAugmentation cie 'L' with
      | Some aug -> parseLSDA cls reader sAddr aug offset
      | None -> None
    { PCBegin = beginAddr; PCEnd = endAddr; LSDAPointer = lsdaPointer }
  | None -> raise CIENotFoundByFDE

let accumulateCFIs cfis cie fdes =
  match cie with
  | Some cie ->
    { CIERecord = cie
      FDERecord = List.rev fdes |> List.toArray } :: cfis
  | None -> cfis

let rec parseCFI cls reader sAddr cie cies fdes offset cfis =
  if offset >= ((reader: BinReader).Length ()) then accumulateCFIs cfis cie fdes
  else
    let originalOffset = offset
    let struct (len, offset) = readInt reader offset
    if len = 0 then accumulateCFIs cfis cie fdes
    else
      let nextOffset, offset = computeNextOffset len reader offset
      let mybase = offset
      let struct (id, offset) = readInt reader offset
      if id = 0 then
        let cfis = accumulateCFIs cfis cie fdes
        let cie = parseCIE cls reader offset
        let cies = Map.add originalOffset cie cies
        parseCFI cls reader sAddr (Some cie) cies [] nextOffset cfis
      else
        let cieOffset = mybase - id (* id = a CIE pointer, when id <> 0 *)
        let fde = parseFDE cls reader sAddr (Map.tryFind cieOffset cies) offset
        let fdes = fde :: fdes
        parseCFI cls reader sAddr cie cies fdes nextOffset cfis

let parse (reader: BinReader) cls (secs: SectionInfo) =
  match Map.tryFind ehframe secs.SecByName with
  | Some sec ->
    let size = Convert.ToInt32 sec.SecSize
    let offset = Convert.ToInt32 sec.SecOffset
    let reader = reader.SubReader offset size
    parseCFI cls reader sec.SecAddr None Map.empty [] 0 []
    |> List.rev
  | None -> []

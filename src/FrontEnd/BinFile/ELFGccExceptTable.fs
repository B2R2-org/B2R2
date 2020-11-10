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
module internal B2R2.FrontEnd.BinFile.ELF.ELFGccExceptTable

open System
open B2R2
open B2R2.FrontEnd.BinFile.ELF.ExceptionHeaderEncoding

/// Raised when types table end address not found.
exception TTEndNotFoundException

let [<Literal>] gccExceptTable = ".gcc_except_table"

let parseHeader cls (reader: BinReader) sAddr offset =
  let struct (b, offset) = reader.ReadByte offset
  let lpv, lpapp = parseEncoding b
  let struct (lpstart, offset) =
    if lpv = ExceptionHeaderValue.DW_EH_PE_omit then struct (None, offset)
    else
      let struct (cv, offset) = computeValue cls reader lpv offset
      struct (Some (sAddr + uint64 (offset - 1) + cv), offset)
  let struct (b, offset) = reader.ReadByte offset
  let ttv, ttapp = parseEncoding b
  let struct (ttend, offset) =
    if ttv = ExceptionHeaderValue.DW_EH_PE_omit then struct (None, offset)
    else
      let cv, offset = parseULEB128 reader offset
      struct (Some (sAddr + uint64 (offset - 1) + cv), offset)
  let struct (b, offset) = reader.ReadByte offset
  let csv, csapp = parseEncoding b
  let cstsz, offset = parseULEB128 reader offset
  { LPFormat = lpv, lpapp
    LPStart = lpstart
    TTFormat = ttv, ttapp
    TTEnd = ttend
    CallSiteFormat = csv, csapp
    CallSiteTableSize = cstsz }, offset

let rec parseCallSiteTable acc cls (reader: BinReader) offset csformat =
  if offset >= (reader.Length ()) then List.rev acc
  else
    let csv, _ = csformat
    let struct (start, offset) = computeValue cls reader csv offset
    let struct (length, offset) = computeValue cls reader csv offset
    let struct (landingPad, offset) = computeValue cls reader csv offset
    let action, offset = parseULEB128 reader offset
    let acc = { Position = start
                Length = length
                LandingPad = landingPad
                Action = action } :: acc
    parseCallSiteTable acc cls reader offset csformat

let validAction lastIdx curIdx =
  if curIdx > 0uy then
    lastIdx + 1uy = curIdx
  else
    lastIdx - 1uy = curIdx

let rec parseActionTable acc (reader: BinReader) lastIdx offset =
  let curIdx = reader.PeekByte offset
  if curIdx = 0uy then
    acc, offset
  else
    if validAction lastIdx curIdx then
      let filter, offset = parseSLEB128 reader offset
      let next, offset = parseSLEB128 reader offset
      let acc =
        { TypeFilter = filter
          NextAction = next } :: acc
      parseActionTable acc reader curIdx offset
    else acc, offset

let rec parseTypeTable acc cls reader sAddr header offset =
  let ttv, _ = header.TTFormat
  match header.TTEnd with
  | Some ttend ->
    if ttend = sAddr + uint64 (offset - 1) then
      acc, offset
    else
      let struct (t, offset) = computeValue cls reader ttv offset
      parseTypeTable (t :: acc) cls reader sAddr header offset
  | None -> raise TTEndNotFoundException

let rec removePadding (reader: BinReader) offset =
  if offset >= (reader.Length ()) then offset
  else
    let byte = reader.PeekByte offset
    if byte = 0uy then removePadding reader (offset + 1)
    else offset

/// Parse language-specific data area.
let rec parseLSDA cls (reader: BinReader) sAddr offset lsdas =
  if offset >= (reader.Length ()) then List.rev lsdas
  else
    let lsdaAddr = sAddr + uint64 offset
    let header, offset = parseHeader cls reader sAddr offset
    let subrdr = reader.SubReader offset (int header.CallSiteTableSize)
    let callsites =
      parseCallSiteTable [] cls subrdr 0 header.CallSiteFormat
    let offset = offset + int header.CallSiteTableSize
    let actions, offset =
      if List.forall (fun record -> record.Action = uint64 0) callsites then
        [], offset
      else
        parseActionTable [] reader 0uy offset
    let types, offset =
      if fst header.TTFormat = ExceptionHeaderValue.DW_EH_PE_omit then
        [], offset
      else
        let offset =
          if offset % 4 = 0 then offset
          else offset + 4 - offset % 4
        parseTypeTable [] cls reader sAddr header offset
    let offset = removePadding reader offset
    let lsdas = { LSDAAddr = lsdaAddr
                  Header = header
                  CallSiteTable = callsites
                  ActionTable = actions
                  TypeTable = types } :: lsdas
    parseLSDA cls reader sAddr offset lsdas

let parse (reader: BinReader) cls (secs: SectionInfo) =
  match Map.tryFind gccExceptTable secs.SecByName with
  | Some sec ->
    let size = Convert.ToInt32 sec.SecSize
    let offset = Convert.ToInt32 sec.SecOffset
    let reader = reader.SubReader offset size
    parseLSDA cls reader sec.SecAddr 0 []
  | None -> []

﻿(*
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

let [<Literal>] GccExceptTable = ".gcc_except_table"

let parseLSDAHeader cls (span: ByteSpan) reader sAddr offset =
  let b = span[offset]
  let offset = offset + 1
  let struct (lpv, lpapp) = parseEncoding b
  let struct (lpstart, offset) =
    if lpv = ExceptionHeaderValue.DW_EH_PE_omit then struct (None, offset)
    else
      let struct (cv, offset) = computeValue cls span reader lpv offset
      struct (Some (sAddr + uint64 offset + cv), offset)
  let b = span[offset]
  let offset = offset + 1
  let struct (ttv, ttapp) = parseEncoding b
  let struct (ttbase, offset) =
    if ttv = ExceptionHeaderValue.DW_EH_PE_omit then struct (None, offset)
    else
      let cv, offset = parseULEB128 span offset
      struct (Some (sAddr + uint64 offset + cv), offset)
  let b = span[offset]
  let offset = offset + 1
  let struct (csv, csapp) = parseEncoding b
  let cstsz, offset = parseULEB128 span offset
  { LPValueEncoding = lpv
    LPAppEncoding = lpapp
    LPStart = lpstart
    TTValueEncoding = ttv
    TTAppEncoding = ttapp
    TTBase = ttbase
    CallSiteValueEncoding = csv
    CallSiteAppEncoding = csapp
    CallSiteTableSize = cstsz }, offset

let rec parseCallSiteTable acc cls span reader offset csv hasAction =
  (* We found that GCC sometimes produces a wrong callsite table length, and the
     length can be off by one. So we minus one here. This is conservative
     anyways, because callsite entry can only be larger than three bytes. *)
  if offset >= (span: ByteSpan).Length - 3 then
    List.rev acc, hasAction
  else
    let struct (start, offset) = computeValue cls span reader csv offset
    let struct (length, offset) = computeValue cls span reader csv offset
    let struct (landingPad, offset) = computeValue cls span reader csv offset
    let actionOffset, offset = parseULEB128 span offset
    let acc =
      if start = 0UL && length = 0UL && landingPad = 0UL && actionOffset = 0UL
      then acc (* This can appear due to the miscalculation issue above. *)
      else { Position = start
             Length = length
             LandingPad = landingPad
             ActionOffset = int actionOffset
             ActionTypeFilters = [] } :: acc
    let hasAction = if actionOffset > 0UL then true else hasAction
    parseCallSiteTable acc cls span reader offset csv hasAction

let rec parseActionEntries acc span offset actOffset =
  if actOffset > 0 then
    let tfilter, offset = parseSLEB128 span (actOffset - 1 + offset)
    let next, offset = parseSLEB128 span offset
    let acc = tfilter :: acc
    parseActionEntries acc span offset (int next)
  else List.rev acc

let rec parseActionTable acc span offset callsites =
  match callsites with
  | csEntry :: tl ->
    let filters = parseActionEntries [] span offset csEntry.ActionOffset
    let acc = { csEntry with ActionTypeFilters = filters } :: acc
    parseActionTable acc span offset tl
  | [] -> List.rev acc

let findMinOrZero lst =
  match lst with
  | [] -> 0L
  | _ -> List.min lst

let findMinFilter callsites =
  if List.isEmpty callsites then 0L
  else
    callsites
    |> List.map (fun cs -> cs.ActionTypeFilters |> findMinOrZero)
    |> List.min

let rec readUntilNull (span: ByteSpan) offset =
  if span[offset] = 0uy then (offset + 1)
  else readUntilNull span (offset + 1)

/// We currently just skip the type table by picking up the minimum filter value
/// as we don't use the type table.
let skipTypeTable span ttbase callsites =
  let minFilter = findMinFilter callsites
  if minFilter < 0L then
    let offset = ttbase - int minFilter - 1
    readUntilNull span offset (* Consume exception spec table. *)
  else ttbase

/// Sometimes, we observe dummy zero bytes inserted by the compiler (icc); this
/// is nothing to do with the alignment. This is likely to be the compiler
/// error, but we should safely ignore those dummy bytes.
let rec skipDummyAlign (span: ByteSpan) offset =
  if offset >= span.Length then offset
  else
    let b = span[offset]
    if b = 0uy then skipDummyAlign span (offset + 1)
    else offset

/// Parse language-specific data area.
let rec parseLSDA cls (span: ByteSpan) reader sAddr offset lsdas =
  if offset >= span.Length then lsdas
  else
    let lsdaAddr = sAddr + uint64 offset
    let header, offset = parseLSDAHeader cls span reader sAddr offset
    let subspn = span.Slice (offset, int header.CallSiteTableSize)
    let encoding = header.CallSiteValueEncoding
    let callsites, hasAction =
      parseCallSiteTable [] cls subspn reader 0 encoding false
    let offset = offset + int header.CallSiteTableSize
    let callsites =
      if hasAction then parseActionTable [] span offset callsites
      else callsites
    let offset =
      match header.TTBase with
      | Some ttbase -> int (ttbase - sAddr)
      | None -> offset
    let offset = skipTypeTable span offset callsites
    let offset = skipDummyAlign span offset
    let lsda = { Header = header; CallSiteTable = callsites }
    let lsdas = Map.add lsdaAddr lsda lsdas
    parseLSDA cls span reader sAddr offset lsdas

let parse (span: ByteSpan) reader cls (secs: SectionInfo) =
  match Map.tryFind GccExceptTable secs.SecByName with
  | Some sec ->
    let size = Convert.ToInt32 sec.SecSize
    let offset = Convert.ToInt32 sec.SecOffset
    let span = span.Slice (offset, size)
    parseLSDA cls span reader sec.SecAddr 0 Map.empty
  | None -> Map.empty

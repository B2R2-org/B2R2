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

open B2R2

/// Represents the LSDA (Language Specific Data Area), which consists of a list
/// of callsite records.
type LSDA = {
  /// This is the value encoding of the landing pad pointer.
  LPValueEncoding: ExceptionHeaderValue
  /// This is the application encoding of the landing pad pointer.
  LPAppEncoding: ExceptionHeaderApplication
  /// The base of the landing pad pointers.
  LPStart: Addr option
  /// This is the value encoding of type table (TT).
  TTValueEncoding: ExceptionHeaderValue
  /// This is the application encoding of type table (TT).
  TTAppEncoding: ExceptionHeaderApplication
  /// The base of types table.
  TTBase: Addr option
  // This is the value encoding of the call site table.
  CallSiteValueEncoding: ExceptionHeaderValue
  // This is the application encoding of the call site table.
  CallSiteAppEncoding: ExceptionHeaderApplication
  // The size of call site table.
  CallSiteTableSize: uint64
  /// The callsite table, which is a list of callsite records.
  CallSiteTable: CallSiteRecord list
}

/// Represents a callsite record in the LSDA. Each callsite record contains
/// information about a callsite, including its position, length, landing pad,
/// etc.
and CallSiteRecord = {
  /// Offset of the callsite relative to the previous call site.
  Position: uint64
  /// Size of the callsite instruction(s).
  Length: uint64
  /// Offset of the landing pad.
  LandingPad: uint64
  /// Offset to the action table. Zero means no action entry.
  ActionOffset: int
  /// Parsed list of type filters from the action table.
  ActionTypeFilters: int64 list
}

module internal LSDA =
  open B2R2.FrontEnd.BinLifter
  open B2R2.FrontEnd.BinFile

  let parseLSDAHeader cls (span: ByteSpan) reader sAddr offset =
    let b = span[offset]
    let offset = offset + 1
    let struct (lpv, lpapp) = ExceptionHeader.parseEncoding b
    let struct (lpstart, offset) =
      if lpv = ExceptionHeaderValue.DW_EH_PE_omit then struct (None, offset)
      else
        let struct (cv, offset) =
          ExceptionHeaderValue.read cls span reader lpv offset
        struct (Some (sAddr + uint64 offset + cv), offset)
    let b = span[offset]
    let offset = offset + 1
    let struct (ttv, ttapp) = ExceptionHeader.parseEncoding b
    let struct (ttbase, offset) =
      if ttv = ExceptionHeaderValue.DW_EH_PE_omit then struct (None, offset)
      else
        let cv, offset = FileHelper.readULEB128 span offset
        struct (Some (sAddr + uint64 offset + cv), offset)
    let b = span[offset]
    let offset = offset + 1
    let struct (csv, csapp) = ExceptionHeader.parseEncoding b
    let cstsz, offset = FileHelper.readULEB128 span offset
    struct (lpv, lpapp, lpstart, ttv, ttapp, ttbase, csv, csapp, cstsz, offset)

  let rec parseCallSiteTable acc cls span reader offset csv hasAction =
    (* We found that GCC sometimes produces a wrong callsite table length, and
       the length can be off by one. So we minus one here. This is conservative
       anyways, because callsite entry can only be larger than three bytes. *)
    if offset >= (span: ByteSpan).Length - 3 then
      List.rev acc, hasAction
    else
      let struct (start, offset) =
        ExceptionHeaderValue.read cls span reader csv offset
      let struct (length, offset) =
        ExceptionHeaderValue.read cls span reader csv offset
      let struct (landingPad, offset) =
        ExceptionHeaderValue.read cls span reader csv offset
      let actionOffset, offset = FileHelper.readULEB128 span offset
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
      let tfilter, offset = FileHelper.readSLEB128 span (actOffset - 1 + offset)
      let next, offset = FileHelper.readSLEB128 span offset
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

  /// Parses one LSDA entry.
  let parse cls (span: ByteSpan) reader sAddr offset =
    let struct (lpv, lpapp, lpstart, ttv, tta, ttb, csv, csapp, cstsz, offset) =
      parseLSDAHeader cls span reader sAddr offset
    let subspn = span.Slice (offset, int cstsz)
    let callsites, hasAction =
      parseCallSiteTable [] cls subspn reader 0 csv false
    let offset = offset + int cstsz
    let callsites =
      if hasAction then parseActionTable [] span offset callsites
      else callsites
    let lsda =
      { LPValueEncoding = lpv
        LPAppEncoding = lpapp
        LPStart = lpstart
        TTValueEncoding = ttv
        TTAppEncoding = tta
        TTBase = ttb
        CallSiteValueEncoding = csv
        CallSiteAppEncoding = csapp
        CallSiteTableSize = uint64 cstsz
        CallSiteTable = callsites }
    struct (lsda, offset)

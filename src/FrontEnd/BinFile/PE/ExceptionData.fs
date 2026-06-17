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

/// Parses the x64 table-based exception data: the RUNTIME_FUNCTION array in
/// `.pdata` (located via the exception data directory) and the UNWIND_INFO it
/// references in `.xdata`. We recover per-function ranges and the personality
/// (exception handler) routine; the compact register-restore unwind codes are
/// intentionally ignored. 32-bit x86 PEs have no such table (they use runtime
/// stack-based SEH), so this yields no frames for them.
module internal B2R2.FrontEnd.BinFile.PE.ExceptionData

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.PE.Helper
open B2R2.FrontEnd.BinFile.PE.PEUtils

/// UNWIND_INFO has an exception handler (UNW_FLAG_EHANDLER).
let [<Literal>] private EHandler = 0x1uy

/// UNWIND_INFO has a termination handler (UNW_FLAG_UHANDLER).
let [<Literal>] private UHandler = 0x2uy

/// UNWIND_INFO chains to another RUNTIME_FUNCTION (UNW_FLAG_CHAININFO).
let [<Literal>] private ChainInfo = 0x4uy

/// Low-29-bit mask for the classic (FH3) C++ FuncInfo magic number.
let [<Literal>] private MagicMask = 0x1FFFFFFF

/// FH3 FuncInfo magic numbers (pre-VS2015, VS2015, and VS2017+ variants).
let private fh3Magics = [| 0x19930520; 0x19930521; 0x19930522 |]

/// The invariant reading context shared by the parse helpers: the binary
/// reader, the section headers (for RVA-to-file-offset mapping), and the image
/// base. The section byte span is threaded separately because it is a ref
/// struct and cannot live in a record.
type private Ctx =
  { Reader: IBinReader
    Secs: SectionHeader[]
    BaseAddr: Addr }

/// Returns whether the RVA maps into one of the file's sections.
let private isValidRva ctx rva =
  rva > 0 && findMappedSectionIndex ctx.Secs rva <> -1

/// A per-function exception frame descriptor recovered from `.pdata`/`.xdata`.
type internal FrameInfo =
  { /// Start address of the function (inclusive).
    FuncStart: Addr
    /// End address of the function (exclusive).
    FuncEnd: Addr
    /// Address of the personality (exception/termination handler) routine, if
    /// the UNWIND_INFO declares one.
    Personality: Addr option
    /// Guarded regions and their handlers (populated by later phases).
    Handlers: (Addr * Addr * Addr option) list }

/// Resolves the file offset of the handler data area (the ExceptionHandler RVA
/// followed by handler-specific data) for the UNWIND_INFO at the given RVA,
/// following CHAININFO chains up to a small depth bound. Returns None when no
/// handler is present.
let rec private resolveHandlerData ctx (span: ByteSpan) unwindRva depth =
  if depth > 8 || unwindRva = 0 then None
  else
    let off = getRawOffset ctx.Secs unwindRva
    let flags = span[off] >>> 3
    let codeCount = int span[off + 2]
    let dataOff = off + 4 + ((codeCount + 1) &&& ~~~1) * 2
    if (flags &&& ChainInfo) <> 0uy then
      let chainedUnwind = ctx.Reader.ReadInt32(span, dataOff + 8)
      resolveHandlerData ctx span chainedUnwind (depth + 1)
    elif (flags &&& (EHandler ||| UHandler)) <> 0uy then Some dataOff
    else None

/// Parses a C scope table (used by __C_specific_handler and the SEH GS handler
/// for `__try`/`__except`/`__finally`) at the given handler-data offset. Each
/// record guards [Begin, End) and, for `__except`, jumps to a target on an
/// exception (`__finally` has a zero target and is cleanup-only). We accept the
/// table only when every guarded region lies within the function, which cleanly
/// rejects the C++ FuncInfo pointer or GS data carried by other personalities.
let private parseScopeTable ctx (span: ByteSpan) off funcBeginRva funcEndRva =
  let count = ctx.Reader.ReadInt32(span, off)
  if count <= 0 || count > 0xFFFF || off + 4 + count * 16 > span.Length then []
  else
    let records = ResizeArray<Addr * Addr * Addr option>()
    let mutable valid = true
    let mutable i = 0
    while valid && i < count do
      let e = off + 4 + i * 16
      let blockBegin = ctx.Reader.ReadInt32(span, e)
      let blockEnd = ctx.Reader.ReadInt32(span, e + 4)
      let target = ctx.Reader.ReadInt32(span, e + 12)
      if blockBegin >= funcBeginRva && blockEnd <= funcEndRva
         && blockBegin < blockEnd then
        let handler =
          if target = 0 then None else Some(addrFromRVA ctx.BaseAddr target)
        records.Add(addrFromRVA ctx.BaseAddr blockBegin,
                    addrFromRVA ctx.BaseAddr blockEnd - 1UL,
                    handler)
      else valid <- false
      i <- i + 1
    if valid then List.ofSeq records else []

/// Derives the guarded code range [begin, end) of a try block from the
/// IP-to-state map, spanning the IPs whose state lies in [low, high]. Returns
/// None when the map is absent or no IP falls in the range.
let private deriveTryRange ctx (span: ByteSpan) funcEndRva mapRva nIP low high =
  if nIP <= 0 || not (isValidRva ctx mapRva) then None
  else
    let mapOff = getRawOffset ctx.Secs mapRva
    let mutable beginRva = Int32.MaxValue
    let mutable endRva = 0
    let mutable i = 0
    while i < nIP do
      let e = mapOff + i * 8
      let ip = ctx.Reader.ReadInt32(span, e)
      let state = ctx.Reader.ReadInt32(span, e + 4)
      if state >= low && state <= high then
        let next =
          if i + 1 < nIP then ctx.Reader.ReadInt32(span, mapOff + (i + 1) * 8)
          else funcEndRva
        if ip < beginRva then beginRva <- ip else ()
        if next > endRva then endRva <- next else ()
      else ()
      i <- i + 1
    if beginRva = Int32.MaxValue then None else Some(beginRva, endRva)

/// Reads the catch-handler code addresses (dispOfHandler) of a HandlerType
/// array, one record (20 bytes on x64) per catch clause.
let private readCatchHandlers ctx (span: ByteSpan) handlerArrayRva nCatch =
  let handlers = ResizeArray<Addr option>()
  if nCatch > 0 && nCatch <= 0xFFFF && isValidRva ctx handlerArrayRva then
    let arrOff = getRawOffset ctx.Secs handlerArrayRva
    let mutable k = 0
    while k < nCatch do
      let dispOfHandler = ctx.Reader.ReadInt32(span, arrOff + k * 20 + 12)
      handlers.Add(
        if dispOfHandler = 0 then None
        else Some(addrFromRVA ctx.BaseAddr dispOfHandler))
      k <- k + 1
  else ()
  handlers

/// Parses a classic (FH3) C++ FuncInfo, yielding one handler record per catch
/// clause: the try block's guarded range and the catch handler address. Returns
/// [] when the data is not an FH3 FuncInfo (e.g., FH4 or a GS-only handler).
let private parseFuncInfo ctx span funcBeginRva funcEndRva funcInfoRva =
  if not (isValidRva ctx funcInfoRva) then []
  else
    let fi = getRawOffset ctx.Secs funcInfoRva
    let magic = ctx.Reader.ReadInt32(span = span, offset = fi) &&& MagicMask
    if not (Array.contains magic fh3Magics) then []
    else
      let nTry = ctx.Reader.ReadInt32(span, fi + 12)
      let dispTryMap = ctx.Reader.ReadInt32(span, fi + 16)
      let nIP = ctx.Reader.ReadInt32(span, fi + 20)
      let dispIP2State = ctx.Reader.ReadInt32(span, fi + 24)
      if nTry <= 0 || nTry > 0xFFFF || not (isValidRva ctx dispTryMap) then []
      else
        let records = ResizeArray<Addr * Addr * Addr option>()
        let tryMapOff = getRawOffset ctx.Secs dispTryMap
        let mutable t = 0
        while t < nTry do
          let tb = tryMapOff + t * 20
          let tryLow = ctx.Reader.ReadInt32(span, tb)
          let tryHigh = ctx.Reader.ReadInt32(span, tb + 4)
          let nCatch = ctx.Reader.ReadInt32(span, tb + 12)
          let dispHandler = ctx.Reader.ReadInt32(span, tb + 16)
          let bStart, bEnd =
            match deriveTryRange ctx span funcEndRva dispIP2State nIP tryLow
                    tryHigh with
            | Some(b, e) ->
              addrFromRVA ctx.BaseAddr b, addrFromRVA ctx.BaseAddr e - 1UL
            | None ->
              addrFromRVA ctx.BaseAddr funcBeginRva,
              addrFromRVA ctx.BaseAddr funcEndRva - 1UL
          for handler in readCatchHandlers ctx span dispHandler nCatch do
            records.Add(bStart, bEnd, handler)
          t <- t + 1
        List.ofSeq records

let parse (pe: PE) (bytes: byte[]) =
  let frames = ResizeArray<FrameInfo>()
  let hdrs = pe.PEHeaders
  if hdrs.IsCoffOnly || hdrs.PEHeader.ExceptionTableDirectory.Size = 0 then
    frames
  else
    let dir = hdrs.PEHeader.ExceptionTableDirectory
    let ctx =
      { Reader = pe.BinReader
        Secs = pe.SectionHeaders
        BaseAddr = pe.BaseAddr }
    let span = ReadOnlySpan bytes
    let pdataOff = getRawOffset ctx.Secs dir.RelativeVirtualAddress
    let count = dir.Size / 12
    let mutable i = 0
    while i < count do
      let entryOff = pdataOff + i * 12
      let beginRva = ctx.Reader.ReadInt32(span, entryOff)
      if beginRva <> 0 then
        let endRva = ctx.Reader.ReadInt32(span, entryOff + 4)
        let unwindRva = ctx.Reader.ReadInt32(span, entryOff + 8)
        let personality, handlers =
          match resolveHandlerData ctx span unwindRva 0 with
          | Some dataOff ->
            let p =
              addrFromRVA ctx.BaseAddr (ctx.Reader.ReadInt32(span, dataOff))
            let scope = parseScopeTable ctx span (dataOff + 4) beginRva endRva
            let h =
              if List.isEmpty scope then
                parseFuncInfo ctx span beginRva endRva
                  (ctx.Reader.ReadInt32(span, dataOff + 4))
              else scope
            Some p, h
          | None -> None, []
        frames.Add
          { FuncStart = addrFromRVA ctx.BaseAddr beginRva
            FuncEnd = addrFromRVA ctx.BaseAddr endRva
            Personality = personality
            Handlers = handlers }
      else ()
      i <- i + 1
    frames

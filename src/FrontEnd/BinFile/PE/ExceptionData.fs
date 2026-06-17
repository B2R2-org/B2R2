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

/// Resolves the personality routine for the UNWIND_INFO at the given RVA,
/// following CHAININFO chains up to a small depth bound.
let rec private getPersonality (reader: IBinReader) (span: ByteSpan) secs
                               baseAddr unwindRva depth =
  if depth > 8 || unwindRva = 0 then None
  else
    let off = getRawOffset secs unwindRva
    let flags = span[off] >>> 3
    let codeCount = int span[off + 2]
    let dataOff = off + 4 + ((codeCount + 1) &&& ~~~1) * 2
    if (flags &&& ChainInfo) <> 0uy then
      let chainedUnwind = reader.ReadInt32(span, dataOff + 8)
      getPersonality reader span secs baseAddr chainedUnwind (depth + 1)
    elif (flags &&& (EHandler ||| UHandler)) <> 0uy then
      Some(addrFromRVA baseAddr (reader.ReadInt32(span, dataOff)))
    else None

let parse (pe: PE) (bytes: byte[]) =
  let frames = ResizeArray<FrameInfo>()
  let hdrs = pe.PEHeaders
  if hdrs.IsCoffOnly || hdrs.PEHeader.ExceptionTableDirectory.Size = 0 then
    frames
  else
    let dir = hdrs.PEHeader.ExceptionTableDirectory
    let reader = pe.BinReader
    let secs = pe.SectionHeaders
    let baseAddr = pe.BaseAddr
    let span = ReadOnlySpan bytes
    let pdataOff = getRawOffset secs dir.RelativeVirtualAddress
    let count = dir.Size / 12
    let mutable i = 0
    while i < count do
      let entryOff = pdataOff + i * 12
      let beginRva = reader.ReadInt32(span, entryOff)
      if beginRva <> 0 then
        let endRva = reader.ReadInt32(span, entryOff + 4)
        let unwindRva = reader.ReadInt32(span, entryOff + 8)
        frames.Add
          { FuncStart = addrFromRVA baseAddr beginRva
            FuncEnd = addrFromRVA baseAddr endRva
            Personality = getPersonality reader span secs baseAddr unwindRva 0
            Handlers = [] }
      else ()
      i <- i + 1
    frames

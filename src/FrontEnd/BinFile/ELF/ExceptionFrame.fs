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

open System
open B2R2.FrontEnd.BinLifter

/// Represents the exception frame, which is a list of CFI records.
type ExceptionFrame = CFI list

/// Represents the Call Frame Information (CFI), which is the main information
/// block of .eh_frame. This exists roughly for every object file, although one
/// object file may have multiple CFIs. Each CFI record contains a CIE record
/// followed by 1 or more FDE records.
and CFI =
  { /// CIE record.
    CIE: CIE
    /// FDE records.
    FDEs: FDE[] }

[<RequireQualifiedAccess>]
module internal ExceptionFrame =
  let [<Literal>] Name = ".eh_frame"

  let computeNextOffset (span: ByteSpan) (reader: IBinReader) offset len =
    if len = -1 then
      let len = reader.ReadUInt64(span, offset)
      let offset = offset + 8
      int len + offset, offset
    else len + offset, offset

  let accumulateCFIs cfis cie fdes =
    match cie with
    | Some cie ->
      { CIE = cie
        FDEs = List.rev fdes |> List.toArray } :: cfis
    | None -> cfis

  let private parseCFI toolBox cls isa reloc regs sec =
    let secAddr, secOffset, secSize = sec.SecAddr, sec.SecOffset, sec.SecSize
    let reader = toolBox.Reader
    let rec parseLoop cie cies fdes offset cfis =
      let secChunk = ReadOnlySpan(toolBox.Bytes, int secOffset, int secSize)
      if offset >= secChunk.Length then
        accumulateCFIs cfis cie fdes
      else
        let originalOffset = offset
        let len, offset = reader.ReadInt32(secChunk, offset), offset + 4
        if len = 0 then accumulateCFIs cfis cie fdes
        else
          let nextOfs, offset = computeNextOffset secChunk reader offset len
          let mybase = offset
          let id, offset = reader.ReadInt32(secChunk, offset), offset + 4
          if id = 0 then
            let cfis = accumulateCFIs cfis cie fdes
            let cie = CIE.parse toolBox secChunk cls isa regs offset nextOfs
            let cies = Map.add originalOffset cie cies
            let cie = Some cie
            parseLoop cie cies [] nextOfs cfis
          else
            let cieOffset = mybase - id (* id = a CIE pointer, when id <> 0 *)
            let fde =
              FDE.parse
                cls isa regs secChunk reader secAddr offset nextOfs reloc
                (Map.tryFind cieOffset cies)
            let fdes = fde :: fdes
            parseLoop cie cies fdes nextOfs cfis
    parseLoop None Map.empty [] 0 []

  let parse toolBox cls shdrs isa regFactoryOpt reloc =
    match Array.tryFind (fun s -> s.SecName = Name) shdrs, regFactoryOpt with
    | Some sec, Some registerFactory ->
      parseCFI toolBox cls isa reloc registerFactory sec
      |> List.rev
    | _ -> []
